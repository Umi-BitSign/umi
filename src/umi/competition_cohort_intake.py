"""Owned intake of explicit consent for configured recoverable cohorts.

The intake records native registration evidence and a proposed admission. It
has no wallet: a receipt is pending independent attestation, never a quorum
certificate or a promise of rewards. Publication and consent retention share
one lock so closing intake cannot race a new receipt.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
import time
from collections.abc import Awaitable, Callable
from contextlib import closing, contextmanager
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain import RegistrationCapture
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake_records import (
    RetainedCohortParticipation,
    read_participation,
    replay_participation,
)
from .competition_cohort_intake_seal import (
    CohortIntakeSeal,
    build_intake_seal,
    verify_intake_closure,
)
from .competition_cohort_participation import (
    CohortParticipationReceipt,
    CohortParticipationRequest,
    admit_recovery_participant,
)
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_execution import execution_boundary
from .competition_store import AdmissionCapacity, AdmissionCapacityError
from .concurrency import run_owned_thread
from .open_competition import CompetitionPolicy, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortIntakeBinding(StrictProtocolModel):
    cohort_sha256: Hex32
    authority_sha256: Hex32


class CohortIntakeConfig(StrictProtocolModel):
    directory: Annotated[str, Field(min_length=1, max_length=4096)]
    cohorts: Annotated[tuple[CohortIntakeBinding, ...], Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def ordered(self):
        path = Path(self.directory)
        if not path.is_absolute() or path == Path(path.anchor) or ".." in path.parts:
            raise ValueError("cohort intake requires a dedicated absolute state directory")
        ids = tuple(item.cohort_sha256 for item in self.cohorts)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("cohort intake bindings must be unique and sorted")
        return self


class CohortIntakeFenced(OSError):
    """This generation is frozen while its certified closure is being published."""


def history_tip(history: CohortRecoveryHistory) -> str:
    return digest(history.transitions[-1].transition if history.transitions else history.genesis)


def cohort_intake_bytes(db) -> int:
    """Count consent and optional admission evidence under one shared allowance."""
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    return sum(
        db.execute(f"SELECT COALESCE(SUM(length(body)),0) FROM {name}").fetchone()[0]
        for name in (
            "cohort_consents",
            "cohort_admission_artifacts",
            "cohort_admission_votes",
            "cohort_admission_certificates",
        )
        if name in tables
    )


class CohortIntakePublisher:
    """Native publication port; the service owns capture-provider lifecycle."""

    def __init__(
        self,
        intake: CohortIntake,
        capture: Callable[[], Awaitable[RegistrationCapture]],
        decision_source: Callable[[str, str], Awaitable[CohortDecisionInput]] | None = None,
    ):
        self.intake, self.capture, self.decision_source = intake, capture, decision_source

    async def __call__(self, history: CohortRecoveryHistory) -> None:
        capture = await self.capture()
        if self.decision_source is not None:
            inputs = tuple(
                [
                    await self.decision_source(digest(history.plan), s.transition.evidence_sha256)
                    for s in history.transitions
                    if s.transition.operation != "revoke"
                ]
            )
            await run_owned_thread(
                partial(self.intake.publish, history, capture, decision_inputs=inputs)
            )
            return
        closure = next(
            (
                s.transition
                for s in history.transitions
                if s.transition.phase == "intake" and s.transition.operation == "close_phase"
            ),
            None,
        )
        if closure is not None:
            raise ValueError("intake closure publication requires retained decision evidence")
        await run_owned_thread(self.intake.publish, history, capture)


class CohortIntake:
    def __init__(
        self,
        config: CohortIntakeConfig,
        policy: CompetitionPolicy,
        *,
        eligible_tracks: tuple[Literal["endpoint", "model"], ...] = ("endpoint",),
        capacity: AdmissionCapacity | None = None,
        initialize: bool = False,
    ):
        self.config = CohortIntakeConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if not eligible_tracks or not set(eligible_tracks) <= {"endpoint", "model"}:
            raise ValueError("invalid recoverable cohort intake tracks")
        self.tracks = eligible_tracks
        self.capacity = capacity or AdmissionCapacity()
        self._initialize = initialize
        self.directory = Path(config.directory)
        self.bindings = {item.cohort_sha256: item.authority_sha256 for item in config.cohorts}
        if self.directory.resolve() != self.directory:
            raise ValueError("cohort intake state must not traverse symlinks")
        if initialize:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._connection():
            pass
        self._initialize = False

    def _directory(self):
        info = self.directory.lstat()
        if (
            self.directory.resolve() != self.directory
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("cohort intake directory must be private and operator-owned")

    def _file(self, name):
        fd = os.open(
            self.directory / name,
            os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_CREAT if self._initialize else 0),
            0o600,
        )
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            os.close(fd)
            raise ValueError("cohort intake file is not private and singly linked")
        return fd

    @contextmanager
    def _connection(self):
        self._directory()
        lease = self._file("intake.lock")
        try:
            lock_until = time.monotonic() + 10
            while True:
                try:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= lock_until:
                        raise TimeoutError("cohort intake busy; retry unchanged") from None
                    time.sleep(0.02)
            descriptor = self._file("intake.sqlite3")
            try:
                # Keep the checked inode open for the entire database operation.
                with closing(
                    sqlite3.connect(self.directory / "intake.sqlite3", isolation_level=None)
                ) as db:
                    current = (self.directory / "intake.sqlite3").lstat()
                    held = os.fstat(descriptor)
                    if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                        raise ValueError("cohort intake database changed while opening")
                    raw = canonical_json_bytes(
                        {
                            "policy_sha256": digest(self.policy),
                            "config": self.config.model_dump(mode="json", by_alias=True),
                            "tracks": list(self.tracks),
                        }
                    )
                    tables = {
                        row[0]
                        for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    }
                    prior = (
                        db.execute("SELECT id,body FROM intake_binding").fetchall()
                        if "intake_binding" in tables
                        else []
                    )
                    if not prior and (not self._initialize or tables):
                        raise ValueError("cohort intake requires explicitly initialized state")
                    if prior and prior != [(1, raw)]:
                        raise ValueError("cohort intake state belongs to another configuration")
                    db.execute("PRAGMA journal_mode=DELETE")
                    db.execute("PRAGMA synchronous=FULL")
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS intake_binding "
                        "(id INTEGER PRIMARY KEY, body BLOB NOT NULL)"
                    )
                    db.execute("INSERT OR IGNORE INTO intake_binding VALUES (1,?)", (raw,))
                    db.execute("""CREATE TABLE IF NOT EXISTS cohort_consents (
                        consent TEXT PRIMARY KEY, cohort TEXT NOT NULL, hotkey TEXT NOT NULL,
                        track TEXT NOT NULL, sequence INTEGER NOT NULL, observed INTEGER NOT NULL,
                        recovery_tip TEXT NOT NULL,
                        body BLOB NOT NULL, UNIQUE(cohort,hotkey,track,sequence))""")
                    db.execute("""CREATE TABLE IF NOT EXISTS cohort_intake_seals (
                        cohort TEXT NOT NULL, tip TEXT NOT NULL, body BLOB NOT NULL,
                        PRIMARY KEY(cohort,tip))""")
                    store = CohortRecoveryStore(db)
                    parent = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(parent)
                    finally:
                        os.close(parent)
                    yield db, store
                    for name, fd in (("intake.lock", lease), ("intake.sqlite3", descriptor)):
                        path_info, held_info = (self.directory / name).lstat(), os.fstat(fd)
                        if (path_info.st_dev, path_info.st_ino) != (
                            held_info.st_dev,
                            held_info.st_ino,
                        ):
                            raise ValueError("cohort intake file changed during the operation")
            finally:
                os.close(descriptor)
        finally:
            os.close(lease)

    def _allowed(self, cohort: str):
        if cohort not in self.bindings:
            raise ValueError("cohort is not configured for recoverable intake")

    def publish(
        self,
        history: CohortRecoveryHistory,
        capture: RegistrationCapture,
        *,
        closure_input: CohortDecisionInput | None = None,
        decision_inputs: tuple[CohortDecisionInput, ...] | None = None,
    ):
        cohort = digest(history.plan)
        self._allowed(cohort)
        observation = execution_boundary(capture)
        if digest(history.authority.authority) != self.bindings[cohort]:
            raise ValueError("cohort history has another configured authority")
        if decision_inputs is not None:
            sources = {digest(e): e for e in decision_inputs}
            required = {
                s.transition.evidence_sha256
                for s in history.transitions
                if s.transition.operation != "revoke"
            }
            if sources.keys() != required or len(sources) != len(decision_inputs):
                raise ValueError("published decision evidence is incomplete or repeated")
            replay_cohort_decisions(history, self.policy, sources.__getitem__)
        with self._connection() as (db, store):
            tips = [digest(history.genesis), *(digest(s.transition) for s in history.transitions)]
            for tip, observed in db.execute(
                "SELECT recovery_tip,MAX(observed) FROM cohort_consents "
                "WHERE cohort=? GROUP BY recovery_tip",
                (cohort,),
            ):
                if tip not in tips:
                    raise ValueError(
                        "published history removes a retained participation observation"
                    )
                index = tips.index(tip)
                if (
                    index < len(history.transitions)
                    and observed > history.transitions[index].transition.observed_at_block
                ):
                    raise ValueError(
                        "published history predates retained participation; "
                        "fence intake before closing"
                    )
            for signed in history.transitions:
                closing = signed.transition
                if closing.phase == "intake" and closing.operation == "close_phase":
                    if decision_inputs is not None:
                        closure_input = sources[closing.evidence_sha256]
                    seal = self._seal(db, history, closing.predecessor_sha256)
                    if seal is None or closure_input is None:
                        raise ValueError(
                            "intake closure requires a retained seal and decision evidence"
                        )
                    verify_intake_closure(seal, closing, closure_input, self.policy)
                    # Retain the closure input before publishing its referencing history.
                    store.retain_source(cohort, closure_input)
            state = store.publish_history(history, self.policy, current_block=observation.block)
            # Retried publication fills any inputs lost after history adoption.
            # Native phase observation refuses missing inputs in the meantime.
            for evidence in decision_inputs or ():
                store.retain_source(cohort, evidence)
            return state

    def history(self, cohort: str) -> CohortRecoveryHistory:
        self._allowed(cohort)
        with self._connection() as (_, store):
            return store.published_history(cohort)

    def _receipt(self, raw: bytes, store: CohortRecoveryStore, request: CohortParticipationRequest):
        retained = read_participation(raw)
        proposed = retained.proposed_admission
        if digest(retained.request.consent.consent) != digest(request.consent.consent) or digest(
            retained.request.signed_submission.submission
        ) != digest(request.signed_submission.submission):
            raise ValueError("retained cohort participation belongs to another request")
        replay_participation(retained, store.published_history(proposed.cohort_sha256), self.policy)
        return CohortParticipationReceipt(
            schema="umi-cohort-participation-receipt/1",
            status="pending_attestation",
            proposed_admission=proposed,
            record_sha256=digest(retained),
            certified=False,
            rewards_active=False,
            chain_submission_authorized=False,
        ).model_dump(mode="json", by_alias=True)

    def receipt(self, request: CohortParticipationRequest):
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        cohort = request.consent.consent.cohort_sha256
        self._allowed(cohort)
        with self._connection() as (db, store):
            prior = db.execute(
                "SELECT substr(body,1,4194305) FROM cohort_consents WHERE consent=?",
                (digest(request.consent.consent),),
            ).fetchone()
            return None if prior is None else self._receipt(prior[0], store, request)

    def retain(self, request: CohortParticipationRequest, capture: RegistrationCapture):
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        cohort = request.consent.consent.cohort_sha256
        self._allowed(cohort)
        observation = execution_boundary(capture)
        sub = request.signed_submission.submission
        if sub.track not in self.tracks:
            raise ValueError("submission track is not open for recoverable intake")
        with self._connection() as (db, store):
            key = digest(request.consent.consent)
            prior = db.execute(
                "SELECT substr(body,1,4194305) FROM cohort_consents WHERE consent=?", (key,)
            ).fetchone()
            if prior is not None:
                return self._receipt(prior[0], store, request)
            history = store.published_history(cohort)
            if (
                db.execute(
                    "SELECT 1 FROM cohort_intake_seals WHERE cohort=? AND tip=?",
                    (cohort, history_tip(history)),
                ).fetchone()
                is not None
            ):
                raise CohortIntakeFenced("cohort intake is sealed; retry the same request")
            proposed = admit_recovery_participant(
                request.signed_submission,
                request.consent,
                history,
                self.policy,
                capture.snapshot,
                expected_tip_sha256=history_tip(history),
                current_block=observation.block,
            )
            previous = db.execute(
                "SELECT sequence,observed FROM cohort_consents "
                "WHERE cohort=? AND hotkey=? AND track=? ORDER BY sequence DESC LIMIT 1",
                (cohort, identity(sub.hotkey), sub.track),
            ).fetchone()
            if previous is not None and (
                sub.sequence <= previous[0]
                or observation.block - previous[1] < self.policy.minimum_submission_interval_blocks
            ):
                raise ValueError("cohort submission sequence or registration interval regressed")
            retained = RetainedCohortParticipation(
                schema="umi-retained-cohort-participation/1",
                request=request,
                proposed_admission=proposed,
                snapshot=capture.snapshot,
                observation=observation,
            )
            raw = canonical_json_bytes(retained)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("cohort participation exceeds its byte bound")
            records = db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone()[0]
            size = cohort_intake_bytes(db)
            if (
                records >= self.capacity.maximum_records
                or size + len(raw) > self.capacity.maximum_bytes
            ):
                raise AdmissionCapacityError("cohort intake needs additional durable capacity")
            db.execute(
                "INSERT INTO cohort_consents VALUES (?,?,?,?,?,?,?,?)",
                (
                    key,
                    cohort,
                    identity(sub.hotkey),
                    sub.track,
                    sub.sequence,
                    observation.block,
                    proposed.recovery_tip_sha256,
                    raw,
                ),
            )
            return self._receipt(raw, store, request)

    def _records(self, db, history):
        tips = {digest(history.genesis), *(digest(s.transition) for s in history.transitions)}
        for consent, tip, raw in db.execute(
            "SELECT consent,recovery_tip,substr(body,1,4194305) FROM cohort_consents "
            "WHERE cohort=? ORDER BY consent",
            (digest(history.plan),),
        ):
            retained = read_participation(raw)
            if (
                retained.proposed_admission.recovery_tip_sha256 != tip
                or retained.proposed_admission.cohort_sha256 != digest(history.plan)
            ):
                raise ValueError("retained consent index differs from its body")
            if tip in tips:
                yield consent, raw

    def _seal(self, db, history, tip):
        row = db.execute(
            "SELECT substr(body,1,4194305) FROM cohort_intake_seals WHERE cohort=? AND tip=?",
            (digest(history.plan), tip),
        ).fetchone()
        if row is None:
            return None
        raw = row[0]
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("retained intake seal exceeds its byte bound")
        seal = CohortIntakeSeal.model_validate_json(raw)
        if canonical_json_bytes(seal) != raw:
            raise ValueError("retained intake seal is not canonical")
        tips = [digest(history.genesis), *(digest(s.transition) for s in history.transitions)]
        if tip not in tips:
            raise ValueError("sealed intake does not belong to the current history")
        prefix = history.model_copy(update={"transitions": history.transitions[: tips.index(tip)]})
        expected = build_intake_seal(
            prefix,
            self.policy,
            seal.observation,
            seal.snapshot,
            self._records(db, prefix),
            expected_tip_sha256=tip,
        )
        if seal != expected:
            raise ValueError("retained intake seal differs from its original records")
        return seal

    def sealed(self, cohort: str, tip: str | None = None) -> CohortIntakeSeal | None:
        self._allowed(cohort)
        with self._connection() as (db, store):
            history = store.published_history(cohort)
            return self._seal(db, history, history_tip(history) if tip is None else tip)

    def seal(
        self,
        cohort: str,
        capture: RegistrationCapture,
        *,
        expected_tip_sha256: str,
    ) -> CohortIntakeSeal:
        """Atomically freeze this generation; completion still requires quorum review.

        Call only after the native availability observer has restored the intake
        window. A certified extension can admit more work at a new tip; a closed
        phase cannot reopen. Retry returns the same seal after an outage.
        """
        self._allowed(cohort)
        observation = execution_boundary(capture)
        with self._connection() as (db, store):
            history = store.published_history(cohort)
            prior = self._seal(db, history, expected_tip_sha256)
            if prior is not None:
                return prior
            if history_tip(history) != expected_tip_sha256:
                raise ValueError("intake history changed before sealing; retry current generation")
            result = build_intake_seal(
                history,
                self.policy,
                observation,
                capture.snapshot,
                self._records(db, history),
                expected_tip_sha256=expected_tip_sha256,
            )
            raw = canonical_json_bytes(result)
            if len(raw) > 4 * 1024 * 1024:
                raise AdmissionCapacityError("intake seal needs additional durable capacity")
            # The process lock serializes this commit with retain() and publish().
            db.execute(
                "INSERT INTO cohort_intake_seals VALUES (?,?,?)", (cohort, expected_tip_sha256, raw)
            )
            return result

    def retained_registration_blocks(self) -> frozenset[int]:
        with self._connection() as (db, _):
            return frozenset(
                [row[0] for row in db.execute("SELECT DISTINCT observed FROM cohort_consents")]
                + [
                    CohortIntakeSeal.model_validate_json(row[0]).observation.block
                    for row in db.execute("SELECT substr(body,1,4194305) FROM cohort_intake_seals")
                ]
            )
