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
from threading import Lock
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .canonical_reuse import canonical_json_reuse
from .competition_chain import RegistrationCapture
from .competition_cohort_admission_deadline import (
    OperatorAdmissionDeadline,
    PendingReservedAdmissions,
    reservation_precedes_deadline,
    retain_deadline,
    retained_deadline,
)
from .competition_cohort_capacity import MAX_AGGREGATE_EVIDENCE_BYTES
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake_records import (
    RetainedCohortParticipation,
    read_participation,
    replay_participation,
)
from .competition_cohort_intake_seal import (
    CohortIntakeSeal,
    verify_intake_closure,
)
from .competition_cohort_participation import (
    CohortParticipationReceipt,
    CohortParticipationRequest,
    admit_recovery_participant,
)
from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_cohort_seal_reuse import (
    IntakeSealRepairRequired,
    IntakeSealReuse,
    retained_metadata_bytes,
)
from .competition_cohort_seal_reuse import (
    transaction as seal_reuse_transaction,
)
from .competition_execution import execution_boundary
from .competition_model_certification_progress import ModelCertificationProgress
from .competition_store import AdmissionCapacity, AdmissionCapacityError
from .concurrency import run_owned_thread
from .host_memory_request_bounds import check_stage_json, stage_count
from .open_competition import CompetitionPolicy, digest, identity
from .private_files import PrivateStateBusyError
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .thread_gate import ThreadGate


class CohortIntakeBinding(StrictProtocolModel):
    cohort_sha256: Hex32
    authority_sha256: Hex32


class CohortIntakeConfig(StrictProtocolModel):
    directory: Annotated[str, Field(min_length=1, max_length=4096)]
    cohorts: Annotated[tuple[CohortIntakeBinding, ...], Field(min_length=1, max_length=512)]

    admission_deadlines: Annotated[
        tuple[OperatorAdmissionDeadline, ...], Field(max_length=512)
    ] = ()

    @model_serializer(mode="wrap")
    def preserve_original_config(self, handler):
        value = handler(self)
        if not self.admission_deadlines:
            value.pop("admission_deadlines", None)
        return value

    @model_validator(mode="after")
    def ordered(self):
        path = Path(self.directory)
        if not path.is_absolute() or path == Path(path.anchor) or ".." in path.parts:
            raise ValueError("cohort intake requires a dedicated absolute state directory")
        ids = tuple(item.cohort_sha256 for item in self.cohorts)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("cohort intake bindings must be unique and sorted")
        deadlines = tuple(v.cohort_sha256 for v in self.admission_deadlines)
        if deadlines != tuple(sorted(set(deadlines))) or not set(deadlines) <= set(ids):
            raise ValueError("admission deadlines require unique configured cohorts")
        return self


class CohortIntakeFenced(OSError):
    """This generation is frozen while its certified closure is being published."""


class CohortAdmissionClosed(CohortIntakeFenced):
    """The local operator cutoff permanently rejects new participation."""


def history_tip(history: CohortRecoveryHistory) -> str:
    return digest(history.transitions[-1].transition if history.transitions else history.genesis)


def cohort_intake_bytes(db) -> int:
    """Count consent and optional admission evidence under one shared allowance."""
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    reservation_bytes = (
        144 * db.execute("SELECT COUNT(*) FROM cohort_admission_reservations").fetchone()[0]
        if "cohort_admission_reservations" in tables
        else 0
    )
    return (
        reservation_bytes
        + retained_metadata_bytes(db)
        + sum(
            db.execute(f"SELECT COALESCE(SUM(length(body)),0) FROM {name}").fetchone()[0]
            for name in (
                "cohort_consents",
                "cohort_admission_deadlines",
                "cohort_admission_drain_snapshots",
                "cohort_admission_artifacts",
                "cohort_admission_votes",
                "cohort_admission_certificates",
                "cohort_prepared_rounds",
                "cohort_preparation_progress",
                "cohort_model_acceptance_intents",
                "cohort_model_acceptance_votes",
                "cohort_model_acceptances",
                "cohort_model_batch_records",
                "cohort_model_transport_qualifications",
                "cohort_model_transport_markers",
            )
            if name in tables
        )
    )


class CohortIntakePublisher:
    """Native publication port; the service owns capture-provider lifecycle."""

    def __init__(
        self,
        intake: CohortIntake,
        capture: Callable[[], Awaitable[RegistrationCapture]],
        decision_source: Callable[[str, str], Awaitable[CohortDecisionInput]] | None = None,
        *,
        current_block: Callable[[], Awaitable[int]] | None = None,
    ):
        self.intake, self.capture, self.decision_source = intake, capture, decision_source
        self.current_block = current_block

    async def __call__(self, history: CohortRecoveryHistory) -> None:
        if self.current_block is None:
            observation, publish = await self.capture(), self.intake.publish
        else:
            observation, publish = await self.current_block(), self.intake.publish_at_block
        if self.decision_source is not None:
            inputs = tuple(
                [
                    await self.decision_source(digest(history.plan), s.transition.evidence_sha256)
                    for s in history.transitions
                    if s.transition.requires_progress_evidence
                ]
            )
            await run_owned_thread(partial(publish, history, observation, decision_inputs=inputs))
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
        await run_owned_thread(publish, history, observation)


class CohortIntake:
    retained_bytes = staticmethod(cohort_intake_bytes)

    def __init__(
        self,
        config: CohortIntakeConfig,
        policy: CompetitionPolicy,
        *,
        eligible_tracks: tuple[Literal["endpoint", "model"], ...] = ("endpoint",),
        capacity: AdmissionCapacity | None = None,
        initialize: bool = False,
        read_only: bool = False,
    ):
        if initialize and read_only:
            raise ValueError("read-only cohort intake cannot initialize or migrate state")
        self._admission_drain_progress = {}
        self._admission_deadlines = {}
        self.pending_admission_uploads = None
        self._model_delivery_states = {}
        self._model_delivery_state_lock = Lock()
        self._read_only = read_only
        self.config = CohortIntakeConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if not eligible_tracks or not set(eligible_tracks) <= {"endpoint", "model"}:
            raise ValueError("invalid recoverable cohort intake tracks")
        self.tracks = eligible_tracks
        self.capacity = capacity or AdmissionCapacity()
        self._initialize = initialize
        self.directory = Path(config.directory)
        # File locks serialize this ledger across processes. Queue callers from
        # this process first so concurrent API, lifecycle and review threads do
        # not consume the external-lock timeout while one sibling owns it.
        self._process_lock = ThreadGate()
        self.model_certification_progress = ModelCertificationProgress()
        self.bindings = {item.cohort_sha256: item.authority_sha256 for item in config.cohorts}
        if self.directory.resolve() != self.directory:
            raise ValueError("cohort intake state must not traverse symlinks")
        fresh_state = initialize and not (self.directory / "intake.sqlite3").exists()
        if initialize:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._connection(prefer_history=read_only) as (db, store):
            if not read_only and not fresh_state:
                for selection in self.config.admission_deadlines:
                    retain_deadline(db, selection, store.published_history(selection.cohort_sha256))
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='cohort_admission_deadlines'"
            ).fetchone():
                for cohort, raw in db.execute("SELECT cohort,body FROM cohort_admission_deadlines"):
                    self._admission_deadlines[cohort] = (
                        OperatorAdmissionDeadline.model_validate_json(raw)
                    )
        self._initialize = False

    def admission_status(self, cohort):
        """Cached scheduling metadata only: no RPC, payload or database reads."""
        deadline = self._admission_deadlines.get(cohort)
        if deadline is None:
            return None
        now = time.time_ns() // 1_000_000
        closed = now >= deadline.close_new_admissions_at_unix_ms
        return {
            "stage": "new_submissions_closed" if closed else "accepting_new_submissions",
            "new_admissions_open": not closed,
            "close_new_admissions_at_unix_ms": deadline.close_new_admissions_at_unix_ms,
            "accepted_uploads_may_finish": True,
            "accepted_uploads": self._admission_drain_progress.get(cohort),
            "completed": int(closed),
            "total": 1,
            "percent": 100 if closed else 0,
            "elapsed_seconds": max(0, now - deadline.close_new_admissions_at_unix_ms) / 1000,
            "eta_seconds": max(0, deadline.close_new_admissions_at_unix_ms - now) / 1000,
            "eta_basis": "retained_operator_wallclock_deadline",
            "eta_scope": "new_admissions_only",
            "stalled_or_retrying": False,
        }

    def _remember_model_delivery_state(self, state):
        """Remember already authenticated state after its native fence succeeds."""
        cohort = state.cohort_sha256
        self._allowed(cohort)
        if state.authority_sha256 != self.bindings[cohort]:
            raise ValueError("model delivery phase has another cohort authority")
        selected = (state.sequence, state.tip_sha256, state.phase)
        with self._model_delivery_state_lock:
            old = self._model_delivery_states.get(cohort)
            if old is not None:
                if old[0] > selected[0]:
                    return
                if old[0] == selected[0] and old != selected:
                    raise ValueError("model delivery phase conflicts with its authenticated tip")
            self._model_delivery_states[cohort] = selected

    def model_delivery_phase(self, cohort):
        """Scheduling hint only: no database, history replay, RPC or deadline gate."""
        with self._model_delivery_state_lock:
            state = self._model_delivery_states.get(cohort)
            return None if state is None else state[2]

    @contextmanager
    def direct_upload_selection_context(self, cohort):
        """Reuse retained admission authority with the owner's next snapshot.

        No history replay or source verification. The native intake fence keeps
        new authorization from racing the direct owner's bounded projection.
        Permits are append-only and committed before the owner retains an
        authorized request or issues its reservation. Later new permits cannot
        affect a projected upload without advancing the owner's request/issued
        counters; deadlines are checked independently by their exact identity.
        """
        self._allowed(cohort)
        with self.fenced_read_snapshot() as (db, _):
            deadline = retained_deadline(db, cohort)
            permitted = (
                frozenset()
                if deadline is None
                else frozenset(
                    row[0]
                    for row in db.execute(
                        "SELECT request FROM cohort_admission_reservations "
                        "WHERE cohort=? AND admitted_ms<? LIMIT ?",
                        (
                            cohort,
                            deadline.close_new_admissions_at_unix_ms,
                            self.capacity.maximum_records + 1,
                        ),
                    )
                )
            )
            if len(permitted) > self.capacity.maximum_records:
                raise ValueError("admission authorization selection exceeds its metadata bound")
            yield deadline, permitted

    def direct_upload_selection_authority(self, cohort):
        """Bounded authority identity, without roster/payload reads or replay."""
        self._allowed(cohort)
        with self._history_connection() as (db, _):
            deadline = retained_deadline(db, cohort)
            return None if deadline is None else digest(deadline)

    def _directory(self):
        info = self.directory.lstat()
        if (
            self.directory.resolve() != self.directory
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("cohort intake directory must be private and operator-owned")

    def _file(self, name, *, read_only=False):
        if self._read_only and not read_only:
            raise ValueError("read-only cohort intake cannot open writable state")
        fd = os.open(
            self.directory / name,
            (os.O_RDONLY if read_only else os.O_RDWR)
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | (os.O_CREAT if self._initialize and not read_only else 0),
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
    def _connection(self, *, prefer_history: bool = False):
        if prefer_history:
            with self._history_connection() as value:
                yield value
            return
        # Replaying a whole accepted roster repeats identical canonical inputs.
        # Reuse serialization only while this operation owns the current state;
        # every schema, signature and authority check still runs on each read.
        with (
            self._process_lock.hold(preferred=prefer_history),
            canonical_json_reuse(),
            self._exclusive_connection() as value,
        ):
            yield value

    def _binding_bytes(self):
        return canonical_json_bytes(
            {
                "policy_sha256": digest(self.policy),
                "config": self.config.model_dump(
                    mode="json", by_alias=True, exclude={"admission_deadlines"}
                ),
                "tracks": list(self.tracks),
            }
        )

    @contextmanager
    def fenced_read_snapshot(self):
        """Owned metadata export under the native fence, without schema writes.

        The ordinary history reader remains available to other consumers. This
        bounded export also holds the writer fence so it can take the upload
        journal next and observe both original ledgers at one boundary.
        """
        with self._process_lock.hold():
            self._directory()
            lease = self._file("intake.lock", read_only=True)
            try:
                until = time.monotonic() + 10
                while True:
                    try:
                        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= until:
                            raise TimeoutError("cohort intake busy; retry unchanged") from None
                        time.sleep(0.02)
                with self._history_connection() as value:
                    yield value
                    path, held = (self.directory / "intake.lock").lstat(), os.fstat(lease)
                    if (path.st_dev, path.st_ino) != (held.st_dev, held.st_ino):
                        raise ValueError("cohort intake fence changed during metadata export")
            finally:
                os.close(lease)

    @contextmanager
    def _history_connection(self, *, wait=True):
        # Owner-authenticated history must remain readable while admission,
        # model preservation or another history caller owns the write gate.
        # SQLite's snapshot keeps the selected history and its inputs together.
        self._directory()
        descriptor = self._file("intake.sqlite3", read_only=True)
        path = self.directory / "intake.sqlite3"
        try:
            with (
                canonical_json_reuse(),
                closing(
                    sqlite3.connect(
                        path.as_uri() + "?mode=ro",
                        uri=True,
                        isolation_level=None,
                        timeout=5 if wait else 0,
                    )
                ) as db,
            ):
                current, held = path.lstat(), os.fstat(descriptor)
                if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                    raise ValueError("cohort intake database changed while opening")
                db.execute("PRAGMA query_only=ON")
                store = CohortRecoveryStore(db)
                with store.read_snapshot():
                    if db.execute("SELECT id,body FROM intake_binding").fetchall() != [
                        (1, self._binding_bytes())
                    ]:
                        raise ValueError("cohort intake state belongs to another configuration")
                    yield db, store
                    self._directory()
                    current = path.lstat()
                    if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                        raise ValueError("cohort intake file changed during the operation")
        except sqlite3.OperationalError as error:
            if not wait and getattr(error, "sqlite_errorcode", None) in (
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            ):
                raise PrivateStateBusyError(
                    "cohort_intake_snapshot", digest(str(self.directory)), error.sqlite_errorcode
                ) from error
            raise
        finally:
            os.close(descriptor)

    @contextmanager
    def _exclusive_connection(self):
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
                    raw = self._binding_bytes()
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
                    # A verified existing binding is immutable. Reissuing this
                    # no-op INSERT turns every history/model read into a write
                    # transaction that waits for unrelated SQLite readers.
                    if not prior:
                        db.execute("INSERT INTO intake_binding VALUES (1,?)", (raw,))
                    db.execute("""CREATE TABLE IF NOT EXISTS cohort_consents (
                        consent TEXT PRIMARY KEY, cohort TEXT NOT NULL, hotkey TEXT NOT NULL,
                        track TEXT NOT NULL, sequence INTEGER NOT NULL, observed INTEGER NOT NULL,
                        recovery_tip TEXT NOT NULL,
                        body BLOB NOT NULL, UNIQUE(cohort,hotkey,track,sequence))""")
                    db.execute("""CREATE TABLE IF NOT EXISTS cohort_intake_seals (
                        cohort TEXT NOT NULL, tip TEXT NOT NULL, body BLOB NOT NULL,
                        PRIMARY KEY(cohort,tip))""")
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS cohort_admission_deadlines "
                        "(cohort TEXT PRIMARY KEY, body BLOB NOT NULL)"
                    )
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS cohort_admission_reservations "
                        "(request TEXT PRIMARY KEY, cohort TEXT NOT NULL, "
                        "admitted_ms INTEGER NOT NULL)"
                    )
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
        return self.publish_at_block(
            history,
            execution_boundary(capture).block,
            closure_input=closure_input,
            decision_inputs=decision_inputs,
        )

    def publish_at_block(
        self,
        history: CohortRecoveryHistory,
        current_block: int,
        *,
        closure_input: CohortDecisionInput | None = None,
        decision_inputs: tuple[CohortDecisionInput, ...] | None = None,
    ):
        """Publish using an owned verified height; this is not membership evidence."""
        if type(current_block) is not int or not 0 <= current_block <= 2**53 - 1:
            raise ValueError("intake publication owned block is invalid")
        cohort = digest(history.plan)
        self._allowed(cohort)
        if digest(history.authority.authority) != self.bindings[cohort]:
            raise ValueError("cohort history has another configured authority")
        if decision_inputs is not None:
            sources = {digest(e): e for e in decision_inputs}
            required = {
                s.transition.evidence_sha256
                for s in history.transitions
                if s.transition.requires_progress_evidence
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
            state = store.publish_history(history, self.policy, current_block=current_block)
            for selection in self.config.admission_deadlines:
                if selection.cohort_sha256 == cohort:
                    retain_deadline(db, selection, history)
                    self._admission_deadlines[cohort] = selection
            # Retried publication fills any inputs lost after history adoption.
            # Native phase observation refuses missing inputs in the meantime.
            for evidence in decision_inputs or ():
                store.retain_source(cohort, evidence)
        self._remember_model_delivery_state(state)
        return state

    def pending_policy_adoption(self, cohort: str) -> CohortRecoveryTransition | None:
        """Recover either native policy reservation without inventing new bytes."""
        self._allowed(cohort)
        with self._connection(prefer_history=True) as (_, store):
            _, pending = store.status(cohort)
            return pending if pending is not None and pending.is_policy_adoption else None

    def pending_request_tail_adoption(self, cohort: str) -> CohortRecoveryTransition | None:
        """Read authenticated pending bytes for lifecycle reservation recovery."""
        self._allowed(cohort)
        with self._connection(prefer_history=True) as (_, store):
            _, pending = store.status(cohort)
            return (
                pending
                if pending is not None and pending.operation == "adopt_request_tail_rule"
                else None
            )

    def reserve_request_tail_adoption(
        self, proposal: CohortRecoveryTransition
    ) -> CohortRecoveryTransition:
        """Fence fresh receipts before the lifecycle owner reserves this exact tip.

        The durable pending transition shares the existing intake journal. A
        crash between intake and control reservation retries these same bytes;
        ordinary signed history publication releases the fence after commit.
        """
        return self._reserve_policy_adoption(proposal, "adopt_request_tail_rule")

    def reserve_evaluation_suite_adoption(self, proposal):
        """Fence the same original intake while the exact suite intent is pending."""
        return self._reserve_policy_adoption(proposal, "adopt_evaluation_suite")

    def _reserve_policy_adoption(self, proposal, operation):
        proposal = CohortRecoveryTransition.model_validate_json(canonical_json_bytes(proposal))
        if proposal.operation != operation:
            raise ValueError("intake reservation requires its exact adoption operation")
        cohort = proposal.cohort_sha256
        self._allowed(cohort)
        with self._connection() as (db, store):
            history = store.published_history(cohort)
            if any(item.transition == proposal for item in history.transitions):
                return store.reserve_exact(proposal)
            if history_tip(history) != proposal.predecessor_sha256:
                raise ValueError("intake rule reservation lost its selected predecessor")
            state, pending = store.status(cohort)
            if pending == proposal:
                return store.reserve_exact(proposal)
            if state.phase == "intake" and self._seal(db, history, state.tip_sha256) is not None:
                raise ValueError("request-rule adoption cannot reopen sealed intake")
            for _, _, retained in self._parsed_records(db, history):
                admission = replay_participation(retained, history, self.policy)
                if admission.admitted_at_block > proposal.observed_at_block:
                    raise ValueError("request-rule adoption predates retained participation")
            return store.reserve_exact(proposal)

    def history(self, cohort: str) -> CohortRecoveryHistory:
        self._allowed(cohort)
        with self._connection(prefer_history=True) as (_, store):
            return store.published_history(cohort)

    def export_records(
        self, cohort: str, *, maximum_bytes: int, maximum_records: int
    ) -> tuple[tuple[str, bytes], ...]:
        """Copy the complete inventory under the owner's lock, including superseded consent.

        Consumers must replay this inventory against their selected certified seal.
        No connection or lazy iterator escapes the owner's transaction.
        """
        self._allowed(cohort)
        if (
            type(maximum_bytes) is not int
            or not 1 <= maximum_bytes <= MAX_AGGREGATE_EVIDENCE_BYTES
            or type(maximum_records) is not int
            or not 1 <= maximum_records <= 65536
        ):
            raise ValueError("invalid cohort intake export bound")
        with self._connection() as (db, store):
            history = store.published_history(cohort)
            records, size = [], 0
            for key, raw in self._records(db, history):
                size += len(raw)
                if len(records) >= maximum_records or size > maximum_bytes:
                    raise AdmissionCapacityError("complete intake export exceeds its capacity")
                records.append((key, raw))
            return tuple(records)

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

    def require_new_admission(self, db, history, request):
        """Authorize a new delivery, or finish the exact retained authorization."""
        cohort = digest(history.plan)
        deadline = retained_deadline(db, cohort)
        now = time.time_ns() // 1_000_000
        key = digest(request)
        prior = db.execute(
            "SELECT cohort,admitted_ms FROM cohort_admission_reservations WHERE request=?", (key,)
        ).fetchone()
        if prior is not None:
            if prior[0] != cohort or (
                deadline is not None and prior[1] >= deadline.close_new_admissions_at_unix_ms
            ):
                raise CohortAdmissionClosed(
                    "retained admission authorization differs from the operator deadline"
                )
            return
        if deadline is not None and now >= deadline.close_new_admissions_at_unix_ms:
            raise CohortAdmissionClosed("new cohort admissions are closed by the operator deadline")
        if (
            db.execute("SELECT COUNT(*) FROM cohort_admission_reservations").fetchone()[0]
            >= self.capacity.maximum_records
            or cohort_intake_bytes(db) + 144 > self.capacity.maximum_bytes
        ):
            raise AdmissionCapacityError("admission reservation metadata capacity exhausted")
        db.execute("INSERT INTO cohort_admission_reservations VALUES (?,?,?)", (key, cohort, now))

    def _admission_reservation_deadline(self, db, cohort, request):
        """Return the current cutoff only when an original reservation is needed."""
        deadline = retained_deadline(db, cohort)
        if (
            deadline is None
            or time.time_ns() // 1_000_000 < deadline.close_new_admissions_at_unix_ms
        ):
            return None
        prior = db.execute(
            "SELECT cohort,admitted_ms FROM cohort_admission_reservations WHERE request=?",
            (digest(request),),
        ).fetchone()
        if (
            prior is not None
            and prior[0] == cohort
            and prior[1] < deadline.close_new_admissions_at_unix_ms
        ):
            return None
        return deadline

    def _require_retained_admission(
        self, db, history, request, reservation, *, defer_reservation=False
    ):
        deadline = self._admission_reservation_deadline(db, digest(history.plan), request)
        if deadline is None:
            return True
        if reservation is None:
            if defer_reservation:
                return False
            raise CohortAdmissionClosed("new cohort admissions are closed by the operator deadline")
        reservation_precedes_deadline(reservation, request, deadline, self.policy)
        return True

    def retain(
        self,
        request: CohortParticipationRequest,
        capture: RegistrationCapture,
        *,
        reservation=None,
        reservation_provider=None,
    ):
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        cohort = request.consent.consent.cohort_sha256
        self._allowed(cohort)
        observation = execution_boundary(capture)
        sub = request.signed_submission.submission
        if sub.track not in self.tracks:
            raise ValueError("submission track is not open for recoverable intake")
        receipt = self._retain_attempt(
            request,
            capture,
            observation,
            reservation,
            defer_reservation=reservation_provider is not None,
        )
        if receipt is not None:
            return receipt
        # The production payload router reads and qualifies acceptance intents
        # through this same intake owner. Resolve only the needed original
        # reservation after releasing intake.lock; the caller's issuance fence
        # remains held. The final attempt rechecks current native authority.
        reservation = reservation_provider(request)
        return self._retain_attempt(request, capture, observation, reservation)

    def _retain_attempt(
        self, request, capture, observation, reservation, *, defer_reservation=False
    ):
        """Return a receipt, or None solely to resolve a reservation outside the lock."""
        cohort = request.consent.consent.cohort_sha256
        sub = request.signed_submission.submission
        with self._connection() as (db, store):
            key = digest(request.consent.consent)
            prior = db.execute(
                "SELECT substr(body,1,4194305) FROM cohort_consents WHERE consent=?", (key,)
            ).fetchone()
            if prior is not None:
                return self._receipt(prior[0], store, request)
            if (
                defer_reservation
                and reservation is None
                and self._admission_reservation_deadline(db, cohort, request) is not None
            ):
                # This first pass is metadata-only. Do not replay signed
                # history just to discover the original-reservation lookup.
                return None
            history = store.published_history(cohort)
            if not self._require_retained_admission(
                db, history, request, reservation, defer_reservation=defer_reservation
            ):
                # The cutoff may have crossed during history authentication.
                # Defer through the same unlocked path, never call the router
                # while this transaction owns intake.lock.
                return None
            _, pending = store.status(cohort)
            if pending is not None and pending.is_policy_adoption:
                kind = (
                    "model-delivery"
                    if pending.operation == "adopt_model_delivery"
                    else "request-rule"
                )
                raise OSError(f"cohort intake awaits its reserved {kind} adoption")
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

    def _records(self, db, history, *, track: str | None = None, hotkey: str | None = None):
        for consent, raw, _ in self._parsed_records(db, history, track=track, hotkey=hotkey):
            yield consent, raw

    def _parsed_records(self, db, history, *, track: str | None = None, hotkey: str | None = None):
        tips = {digest(history.genesis), *(digest(s.transition) for s in history.transitions)}
        clauses = ["cohort=?"]
        cohort = digest(history.plan)
        parameters = [cohort]
        if track is not None:
            clauses.append("track=?")
            parameters.append(track)
        if hotkey is not None:
            clauses.append("hotkey=?")
            parameters.append(identity(hotkey))
        stage_bytes = 0
        records = db.execute(
            "SELECT consent,recovery_tip,substr(body,1,4194305) FROM cohort_consents "
            "WHERE " + " AND ".join(clauses) + " ORDER BY consent",
            parameters,
        )
        for stage_records, (consent, tip, raw) in enumerate(records, 1):
            stage_bytes += len(raw)
            stage_count("maximum_records", stage_records)
            stage_count("maximum_input_bytes", stage_bytes)
            retained = read_participation(raw)
            if (
                retained.proposed_admission.recovery_tip_sha256 != tip
                or retained.proposed_admission.cohort_sha256 != cohort
                or (
                    track is not None
                    and retained.request.signed_submission.submission.track != track
                )
                or (
                    hotkey is not None
                    and identity(retained.request.signed_submission.submission.hotkey)
                    != identity(hotkey)
                )
            ):
                raise ValueError("retained consent index differs from its body")
            if tip in tips:
                yield consent, raw, retained

    def _seal(self, db, history, tip):
        row = db.execute(
            "SELECT substr(body,1,4194305) FROM cohort_intake_seals WHERE cohort=? AND tip=?",
            (digest(history.plan), tip),
        ).fetchone()
        if row is None:
            if (
                db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='intake_seal_reuse_sources'"
                ).fetchone()
                and db.execute(
                    "SELECT 1 FROM intake_seal_reuse_sources "
                    "WHERE kind='seal' AND cohort=? AND id=?",
                    (digest(history.plan), tip),
                ).fetchone()
            ):
                raise IntakeSealRepairRequired("verified original intake seal is missing")
            return None
        raw = row[0]
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("retained intake seal exceeds its byte bound")
        check_stage_json(raw, kind="object")
        seal = CohortIntakeSeal.model_validate_json(raw)
        if canonical_json_bytes(seal) != raw:
            raise ValueError("retained intake seal is not canonical")
        tips = [digest(history.genesis), *(digest(s.transition) for s in history.transitions)]
        if tip not in tips:
            raise ValueError("sealed intake does not belong to the current history")
        prefix = history.model_copy(update={"transitions": history.transitions[: tips.index(tip)]})
        return IntakeSealReuse(self, db).verify(prefix, tip, seal)

    def sealed(self, cohort: str, tip: str | None = None) -> CohortIntakeSeal | None:
        self._allowed(cohort)
        with self._connection() as (db, store):
            history = store.published_history(cohort)
            return self._seal(db, history, history_tip(history) if tip is None else tip)

    def require_admission_uploads_drained(self, db, history):
        """The payload owner resolves accepted reservations before roster freeze."""
        cohort = digest(history.plan)
        deadline = self._admission_deadlines.get(cohort)
        if deadline is None or "model" not in self.tracks:
            return
        if time.time_ns() // 1_000_000 < deadline.close_new_admissions_at_unix_ms:
            raise PendingReservedAdmissions({"completed": 0, "total": 1, "pending": 1})
        inventory = (
            {
                "completed": 0,
                "total": 1,
                "pending": 1,
                "reason_code": "admission_upload_owner_unavailable",
            }
            if self.pending_admission_uploads is None
            else self.pending_admission_uploads(cohort, db, deadline)
        )
        self._admission_drain_progress[cohort] = dict(inventory)
        if inventory["pending"]:
            raise PendingReservedAdmissions(inventory)

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
            self.require_admission_uploads_drained(db, history)
            reuse = IntakeSealReuse(self, db)
            result = reuse.build(history, observation, capture.snapshot, expected_tip_sha256)
            raw = canonical_json_bytes(result)
            if len(raw) > 4 * 1024 * 1024:
                raise AdmissionCapacityError("intake seal needs additional durable capacity")
            # The process lock serializes this commit with retain() and publish().
            with seal_reuse_transaction(db):
                db.execute(
                    "INSERT INTO cohort_intake_seals VALUES (?,?,?)",
                    (cohort, expected_tip_sha256, raw),
                )
                reuse.record_created(history, expected_tip_sha256, result)
            return result

    def repair_seal_reuse(self, cohort, tip, *, reason):
        """Repair derived results for one retained seal; preserve signed originals."""
        self._allowed(cohort)
        with self._connection() as (db, store):
            history = store.published_history(cohort)
            tips = [digest(history.genesis), *(digest(s.transition) for s in history.transitions)]
            if tip not in tips:
                raise ValueError("seal repair requires a retained history tip")
            prefix = history.model_copy(
                update={"transitions": history.transitions[: tips.index(tip)]}
            )
            row = db.execute(
                "SELECT body FROM cohort_intake_seals WHERE cohort=? AND tip=?", (cohort, tip)
            ).fetchone()
            if row is None:
                raise ValueError("seal repair requires an original retained seal")
            seal = CohortIntakeSeal.model_validate_json(row[0])
            if canonical_json_bytes(seal) != row[0]:
                raise ValueError("retained intake seal is not canonical")
            reuse = IntakeSealReuse(self, db, repair_reason=reason)
            return reuse.verify(prefix, tip, seal, repair=True)

    def retained_registration_blocks(self) -> frozenset[int]:
        # Pin metadata has no writer work. A published-history/acceptance writer
        # must not make a verified registration capture wait at its ThreadGate.
        # Real snapshot contention defers pruning, never the capture itself.
        with self._history_connection(wait=False) as (db, _):
            prepared = []
            for table in ("cohort_prepared_rounds", "cohort_preparation_progress"):
                if db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
                ).fetchone():
                    prepared.extend(
                        r[0] for r in db.execute(f"SELECT DISTINCT observed FROM {table}")
                    )
            return frozenset(
                [row[0] for row in db.execute("SELECT DISTINCT observed FROM cohort_consents")]
                + [
                    CohortIntakeSeal.model_validate_json(row[0]).observation.block
                    for row in db.execute("SELECT substr(body,1,4194305) FROM cohort_intake_seals")
                ]
                + prepared
            )
