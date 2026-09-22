"""Continuous, journaled evaluation and peer agreement for both reward tracks.

Orders require an independent policy quorum. Execution uses the existing CPU
runner; only the evaluator hotkey signs fixed evidence types after reveal.
Private inbox/outbox delivery is external. This worker never submits weights.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import sqlite3
import stat
from contextlib import contextmanager, suppress
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from . import competition_evaluator_capacity as evaluator_capacity
from .competition_authorization import (
    EndpointAuthorizationPublication,
    validate_publication,
    validate_publication_body,
)
from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_endpoint_execution import (
    RetainedRevealPulse,
    assemble_endpoint_observations,
)
from .competition_evaluator_orders import EvaluationOrder, SignedEvaluationOrder
from .competition_evidence import (
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    independent_evidence_digest,
    replay_independent_evaluation,
    sign_evaluator_run,
    verify_evaluator_run,
)
from .competition_execution import (
    EndpointIncumbentJob,
    ExecutionBoundary,
    ExecutionCase,
    ExecutionJournal,
    ModelEvaluationJob,
    common_execution_result,
    execution_boundary,
    execution_key,
    execution_slot,
    run_endpoint_incumbent,
    run_model_evaluation,
    run_record_from_execution,
    validate_incumbent_job,
    validate_job,
)
from .competition_observations import (
    ExecutionAnnouncement,
    SignedExecutionAnnouncement,
    execution_observations,
)
from .competition_publication import PublicationReplayLimits
from .competition_scheduling import AssignmentPublicationJournal, SchedulingCapacity
from .competition_void import (
    AttestedEvaluationVoid,
    EvaluationVoidVote,
    ScorableObservations,
    VoidEvaluationEvidence,
    propose_evaluation_void,
    validate_own_void,
    verify_evaluation_void,
    void_evidence_digest,
)
from .concurrency import run_owned_thread
from .drand import QuicknetClient
from .open_competition import (
    AttestedResult,
    CompetitionPolicy,
    EvaluationResult,
    EvaluationSuite,
    Hotkey,
    Signature,
    SignedSubmission,
    digest,
    identity,
    sign_object,
    verify_signature,
)
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import MAX_PRIVATE_BYTES as MAX_BYTES
from .private_files import Directory as Directory
from .private_files import _publish_locked as _publish_locked
from .private_files import ensure_private_directory as _private
from .private_files import lock_private_file as _lock_file
from .private_files import private_path as _path
from .private_files import publish_private_model as _publish
from .private_files import read_private_model as _read
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_work_plans import WorkPlan


class EvaluationVote(StrictProtocolModel):
    schema_: Literal["umi-evaluation-vote/1"] = Field(alias="schema")
    order_sha256: Hex32
    result: EvaluationResult
    result_signature: Signature
    run: SignedEvaluatorRunRecord


class IndependentEvidenceObservation(StrictProtocolModel):
    """Local first-retention receipt, never a remote proof of receipt timing."""

    schema_: Literal["umi-independent-evidence-observation/1"] = Field(alias="schema")
    evaluator_hotkey: Hotkey
    policy_sha256: Hex32
    round_sha256: Hex32
    order_sha256: Hex32
    submission_sha256: Hex32
    evidence_sha256: Hex32
    observed: ExecutionBoundary
    chain_submission_authorized: Literal[False] = False


class VoidEvidenceObservation(IndependentEvidenceObservation):
    schema_: Literal["umi-void-evidence-observation/1"] = Field(alias="schema")


def validate_evidence_observation(receipt, order, evidence, hotkey, *, cutoff_block=None):
    return _validate_observation(
        receipt,
        order,
        independent_evidence_digest(evidence),
        hotkey,
        model=IndependentEvidenceObservation,
        cutoff_block=cutoff_block,
    )


def validate_void_observation(receipt, order, evidence, hotkey, *, cutoff_block=None):
    return _validate_observation(
        receipt,
        order,
        void_evidence_digest(evidence),
        hotkey,
        model=VoidEvidenceObservation,
        cutoff_block=cutoff_block,
    )


def _validate_observation(receipt, order, evidence_sha256, hotkey, *, model, cutoff_block):
    receipt = model.model_validate_json(canonical_json_bytes(receipt))
    if (
        identity(receipt.evaluator_hotkey) != identity(hotkey)
        or receipt.policy_sha256 != order.round.policy_sha256
        or receipt.round_sha256 != digest(order.round)
        or receipt.order_sha256 != digest(order)
        or receipt.submission_sha256 != digest(order.submission.submission)
        or receipt.evidence_sha256 != evidence_sha256
        or receipt.observed.block < order.round.reveal_block
    ):
        raise ValueError("local independent-evidence observation binding mismatch")
    if cutoff_block is not None and (
        type(cutoff_block) is not int
        or not order.round.reveal_block <= cutoff_block <= order.round.valid_through_block
        or receipt.observed.block > cutoff_block
    ):
        raise ValueError("independent evidence was not locally observed by cutoff")
    return receipt


class EvaluatorJournalLimits(StrictProtocolModel):
    """Optional per-store ceilings; omitted values use maximum_journal_bytes."""

    execution: Annotated[int, Field(ge=1024, le=16 * 1024**3)] | None = None
    round_signing: Annotated[int, Field(ge=1024, le=16 * 1024**3)] | None = None
    work_signing: Annotated[int, Field(ge=1024, le=16 * 1024**3)] | None = None
    work_admission: Annotated[int, Field(ge=1024, le=16 * 1024**3)] | None = None


class EvaluatorConfig(StrictProtocolModel):
    schema_: Literal["umi-evaluator-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    chain: CompetitionChainConfig
    evaluator_hotkey: Hotkey
    wallet_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    hotkey_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    wallet_path: Directory
    state_directory: Directory
    order_directory: Directory
    reveal_directory: Directory
    peer_directory: Directory
    outbox_directory: Directory
    archive_directory: Directory
    video_directory: Directory
    dispatch_directory: Directory | None = None
    legacy_policy_sha256: Hex32 | None = None
    exchange_origin: str | None = None
    round_coordinator_origin: str | None = None
    work_signing_chain: CompetitionChainConfig | None = None
    work_minimum_issue_ms: Annotated[int, Field(ge=1, le=300_000)] | None = None
    settlement_review_directory: Directory | None = None
    settlement_replay_limits: PublicationReplayLimits | None = None
    # Explicit local-only settlement connection; the public coordinator remains
    # the logical source for every role. Configure before initializing journals.
    settlement_loopback_port: Annotated[int, Field(ge=1, le=65535)] | None = None
    assignment_directory: Directory | None = None
    poll_seconds: Annotated[int, Field(ge=1, le=30)] = 5
    maximum_orders: Annotated[int, Field(ge=1, le=65536)] = 1024
    page_size: Annotated[int, Field(ge=1, le=16)] = 4
    maximum_parallel_jobs: Annotated[int, Field(ge=1, le=4)] = 1
    maximum_journal_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    journal_limits: EvaluatorJournalLimits = Field(default_factory=EvaluatorJournalLimits)
    scheduling_capacity: SchedulingCapacity = Field(default_factory=SchedulingCapacity)
    no_weight: Literal[True] = True

    @model_serializer(mode="wrap")
    def serialize_legacy_config(self, handler):
        value = handler(self)
        if self.settlement_loopback_port is None:
            value.pop("settlement_loopback_port", None)
        return value

    def journal_limit(
        self, name: Literal["execution", "round_signing", "work_signing", "work_admission"]
    ) -> int:
        value = getattr(self.journal_limits, name)
        return self.maximum_journal_bytes if value is None else value

    @model_validator(mode="after")
    def bindings(self):
        if self.settlement_loopback_port is not None and self.settlement_review_directory is None:
            raise ValueError(
                "settlement loopback requires configured independent settlement signing"
            )
        if (self.settlement_review_directory is None) != (
            self.settlement_replay_limits is None
        ) or (
            self.settlement_review_directory is not None and self.round_coordinator_origin is None
        ):
            raise ValueError(
                "settlement signing requires local reviews, replay limits and the round service"
            )
        if self.round_coordinator_origin is not None:
            from .competition_client import validate_intake_origin

            validate_intake_origin(self.round_coordinator_origin)
        if (self.work_signing_chain is None) != (self.work_minimum_issue_ms is None):
            raise ValueError("work signing needs both owned transport and an explicit issue margin")
        if self.work_signing_chain is not None and (
            self.round_coordinator_origin is None
            or self.legacy_policy_sha256 is None
            or self.work_signing_chain.policy_sha256 != self.policy_sha256
            or self.work_signing_chain.collection_timeout_seconds > 15
        ):
            raise ValueError(
                "work signing requires the round service and matching bounded transport"
            )
        if self.exchange_origin is not None:
            from .competition_client import validate_intake_origin

            validate_intake_origin(self.exchange_origin)
        if self.assignment_directory is not None and (
            self.exchange_origin is None or self.legacy_policy_sha256 is None
        ):
            raise ValueError("assignment delivery requires an exchange and transport policy")
        paths = [
            Path(v).resolve()
            for k, v in self.model_dump().items()
            if (k.endswith("_directory") or k == "wallet_path") and v is not None
        ] + [Path(_path(self.chain.state_directory)).resolve()]
        if self.work_signing_chain is not None:
            paths.append(Path(_path(self.work_signing_chain.state_directory)).resolve())
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("evaluator data, wallet and verifier directories must not overlap")
        if (
            self.chain.policy_sha256 != self.policy_sha256
            or self.chain.collection_timeout_seconds > 15
        ):
            raise ValueError("evaluator requires a matching bounded owned-finality provider")
        if (self.dispatch_directory is None) != (self.legacy_policy_sha256 is None):
            raise ValueError("endpoint dispatch journal and transport policy must be paired")
        return self


def _job_from_order_inputs(fields, evaluator, policy, publication, legacy):
    """Derive a job from fixed order fields, without granting execution authority."""
    if fields["submission"].submission.track == "model":
        if publication is not None:
            raise ValueError("model order must not contain endpoint authorization")
        return validate_job(
            ModelEvaluationJob(
                schema="umi-model-evaluation-job/1", evaluator_hotkey=evaluator, **fields
            ),
            policy,
        )
    if publication is None or legacy is None:
        raise ValueError("endpoint order requires its transport authorization")
    # Both entry points have already validated this unsigned body. The signed
    # path additionally verifies its publication quorum before deriving a job.
    body = publication
    submission_sha = digest(fields["submission"].submission)
    submissions = [s for s in body.submissions if digest(s.submission) == submission_sha]
    if len(submissions) != 1:
        raise ValueError("endpoint submission is absent from the publication")
    job = validate_incumbent_job(
        EndpointIncumbentJob(
            schema="umi-endpoint-incumbent-job/1",
            round=body.round,
            submission=submissions[0],
            incumbent=fields["incumbent"],
            runtime=fields["runtime"],
            evaluator_hotkey=evaluator,
            cases=tuple(
                ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
                for c in body.cases
            ),
        ),
        policy,
    )
    assigned = {
        a.case_sha256
        for a in body.assignments
        if a.submission_sha256 == submission_sha
        and identity(a.evaluator_hotkey) == identity(evaluator)
    }
    if assigned != {digest(c) for c in body.cases}:
        raise ValueError("endpoint evaluator does not have all paired assignments")
    if any(getattr(job, k) != v for k, v in fields.items()):
        raise ValueError("endpoint order differs from signed transport assignments")
    return job


def order_job(order, evaluator, policy, legacy=None):
    """Validate the same reference-free assignment for each nominated evaluator."""
    fields = {
        k: getattr(order, k) for k in ("round", "submission", "incumbent", "runtime", "cases")
    }
    publication = order.publication
    if publication is not None and order.submission.submission.track == "endpoint":
        if legacy is None:
            raise ValueError("endpoint order requires its signed transport authorization")
        publication = validate_publication(publication, policy, legacy).publication
    return _job_from_order_inputs(fields, evaluator, policy, publication, legacy)


def _validate_order_evaluators(evaluators, policy):
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    keys = [identity(k) for k in evaluators]
    if keys != sorted(set(keys)) or any(k not in groups for k in keys):
        raise ValueError("order evaluators must be canonical authorized identities")
    if len({groups[k] for k in keys}) != len(keys) or len(keys) < policy.required_evaluator_groups:
        raise ValueError("order requires distinct independent evaluator groups")


def order_from_unsigned_inputs(
    *,
    plan: WorkPlan,
    submission: SignedSubmission,
    policy: CompetitionPolicy,
    evaluator_hotkey: Hotkey,
    endpoint_publication: EndpointAuthorizationPublication | None = None,
    legacy_policy: ScoringPolicy | None = None,
) -> tuple[dict[str, object], ModelEvaluationJob]:
    """Return signature-independent order fields and a validated local job.

    The caller authenticates the frozen cutoff with ``validate_work_plan``.
    These fields are a capacity binding, not an EvaluationOrder or permission
    to execute. Their digest equals ``order_binding`` once signatures arrive.
    """
    if submission not in plan.submissions:
        raise ValueError("order submission is absent from its frozen plan")
    _validate_order_evaluators(plan.evaluators, policy)
    if identity(evaluator_hotkey) not in {identity(k) for k in plan.evaluators}:
        raise ValueError("order job evaluator is not nominated by its frozen plan")
    fields = {k: getattr(plan, k) for k in ("incumbent", "runtime", "cases")}
    fields.update(round=plan.cutoff.publication.round, submission=submission)
    publication = endpoint_publication
    if publication is not None:
        publication = validate_publication_body(publication, policy, legacy_policy)
        if publication.submissions != (submission,) or {
            identity(a.evaluator_hotkey) for a in publication.assignments
        } != {identity(k) for k in plan.evaluators}:
            raise ValueError("order authorization differs from its frozen plan")
    job = _job_from_order_inputs(fields, evaluator_hotkey, policy, publication, legacy_policy)
    encoded = job.model_dump(mode="json", by_alias=True, exclude={"evaluator_hotkey"})
    encoded.update(
        schema="umi-evaluation-order/1",
        evaluators=list(plan.evaluators),
        publication=(
            None if publication is None else publication.model_dump(mode="json", by_alias=True)
        ),
        no_weight=True,
    )
    return encoded, job


def validate_order(signed, policy, legacy=None):
    signed = SignedEvaluationOrder.model_validate_json(canonical_json_bytes(signed))
    order = validate_order_body(signed.order, policy, legacy)
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    signers = set()
    signer_groups = set()
    for signature in signed.signatures:
        key = identity(signature.hotkey)
        if key not in groups or key in signers or groups[key] in signer_groups:
            raise ValueError("order signature is unauthorized or repeats a control group")
        verify_signature(order, signature)
        signers.add(key)
        signer_groups.add(groups[key])
    if len(signer_groups) < policy.required_evaluator_groups:
        raise ValueError("order lacks independent quorum signatures")
    return signed


def validate_order_body(order, policy, legacy=None):
    """Check a reference-free proposal without authorizing execution."""
    order = EvaluationOrder.model_validate_json(canonical_json_bytes(order))
    _validate_order_evaluators(order.evaluators, policy)
    for evaluator in order.evaluators:
        order_job(order, evaluator, policy, legacy)
    return order


class EvaluatorJournal:
    """Bounded immutable orders/artifacts, including the pre-sign result intent."""

    def __init__(self, config):
        self.config = config
        root = Path(config.state_directory)
        _private(root)
        self.path = root / "evaluator.sqlite3"
        for suffix in ("", "-journal", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.is_symlink():
                raise ValueError("evaluator database must not be a symlink")
            if p.exists():
                info = p.stat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                ):
                    raise ValueError("evaluator database must be an owned private regular file")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (body BLOB NOT NULL)")
            old = db.execute("SELECT body FROM binding").fetchall()
            # Bind all configured paths and identity; an existing journal cannot
            # be used with another archive, transport policy or wallet.
            binding = canonical_json_bytes(
                config.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude={
                        "maximum_orders",
                        "maximum_journal_bytes",
                        "journal_limits",
                        "scheduling_capacity",
                        "maximum_parallel_jobs",
                        "page_size",
                        "poll_seconds",
                        *(
                            k
                            for k in (
                                "exchange_origin",
                                "assignment_directory",
                                "round_coordinator_origin",
                                "work_signing_chain",
                                "work_minimum_issue_ms",
                                "settlement_review_directory",
                                "settlement_replay_limits",
                            )
                            if getattr(config, k) is None
                        ),
                    },
                )
            )
            if old and len(old) != 1:
                raise ValueError("evaluator journal configuration changed")
            if old:
                from .competition_evaluator_rpc_migration import validate_rpc_binding

                validate_rpc_binding(db, bytes(old[0][0]), binding)
            if not old:
                db.execute("INSERT INTO binding VALUES (?)", (binding,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS orders (slot TEXT PRIMARY KEY, "
                "body BLOB NOT NULL, conflict INTEGER NOT NULL DEFAULT 0)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS artifacts (slot TEXT NOT NULL, kind TEXT NOT NULL, "
                "body BLOB NOT NULL, PRIMARY KEY(slot,kind))"
            )
            if evaluator_capacity.generation(db):
                self._capacity(db, 0)
                if self._order_count(db) > config.maximum_orders:
                    raise ValueError("evaluator reserved order capacity exhausted")

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        try:
            evaluator_capacity.connect(db)
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            evaluator_capacity.generation(db)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _order_count(self, db):
        return (
            db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
            + evaluator_capacity.usage(db)[1]
        )

    def _capacity(self, db, size, *, credit=0):
        used = sum(
            db.execute(f"SELECT COALESCE(SUM(LENGTH(body)),0) FROM {table}").fetchone()[0]
            for table in ("orders", "artifacts")
        )
        used += evaluator_capacity.usage(db)[0]
        if size > MAX_BYTES or used + size - credit > self.config.maximum_journal_bytes:
            raise ValueError("evaluator journal capacity exhausted; preserve its history")

    def reserve_orders(self, batch_id, specs):
        """Reserve a complete private order/artifact inventory without admitting work."""
        with self.transaction() as db:
            return evaluator_capacity.reserve(
                db,
                batch_id,
                specs,
                path=self.path,
                config=self.config,
                check_capacity=self._capacity,
            )

    def reservation(self, batch_id):
        with self.transaction() as db:
            if not evaluator_capacity.generation(db):
                return None
            size = db.execute(
                "SELECT length(body) FROM capacity_batches WHERE id=?", (batch_id,)
            ).fetchone()
            if size is None:
                return None
            if not 0 < size[0] <= MAX_BYTES:
                raise ValueError("evaluator reservation receipt exceeds its byte bound")
            row = db.execute("SELECT body FROM capacity_batches WHERE id=?", (batch_id,)).fetchone()
            receipt = evaluator_capacity.parse_receipt(bytes(row[0]))
            if (
                canonical_json_bytes(receipt) != bytes(row[0])
                or receipt["batch_id"] != batch_id
                or receipt["journal_path"] != str(self.path.resolve())
                or receipt["binding_sha256"]
                != hashlib.sha256(
                    bytes(db.execute("SELECT body FROM binding").fetchone()[0])
                ).hexdigest()
            ):
                raise ValueError("evaluator capacity receipt binding changed")
            evaluator_capacity.verify(db, receipt)
            self._capacity(db, 0)
            if self._order_count(db) > self.config.maximum_orders:
                raise ValueError("evaluator reserved order capacity exhausted")
            return receipt

    def admit(self, signed, slot):
        raw = canonical_json_bytes(signed)
        conflict = False
        with self.transaction() as db:
            old = db.execute("SELECT body FROM orders WHERE slot=?", (slot,)).fetchone()
            if old:
                saved = SignedEvaluationOrder.model_validate_json(old[0])
                conflict = saved.order != signed.order
                if conflict:
                    db.execute("UPDATE orders SET conflict=1 WHERE slot=?", (slot,))
                    # The hold survives even if there is no room for extra bytes.
                    try:
                        self._capacity(db, len(raw))
                    except ValueError:
                        pass
                    else:
                        db.execute(
                            "INSERT OR IGNORE INTO artifacts VALUES (?,?,?)",
                            (slot, "conflict:" + digest(signed.order), raw),
                        )
            else:
                try:
                    credit = evaluator_capacity.credit(
                        db, slot, None, raw, binding=evaluator_capacity.order_binding(signed.order)
                    )
                except evaluator_capacity.ReservedOrderConflict:
                    db.execute("UPDATE capacity_orders SET conflict=1 WHERE slot=?", (slot,))
                    conflict = True
                else:
                    if self._order_count(db) - int(credit > 0) >= self.config.maximum_orders:
                        raise ValueError("evaluator order capacity exhausted")
                    self._capacity(db, len(raw), credit=credit)
                    db.execute("INSERT INTO orders(slot,body) VALUES (?,?)", (slot, raw))
                    evaluator_capacity.consume(db, slot, None)
        if conflict:
            raise ValueError("conflicting signed evaluation order retained")

    def orders(self, *, after="", limit=4):
        if type(limit) is not int or not 1 <= limit <= 16:
            raise ValueError("invalid evaluator order page size")
        with self.transaction() as db:
            rows = db.execute(
                "SELECT slot,body,conflict FROM orders WHERE slot>? ORDER BY slot LIMIT ?",
                (after, limit),
            ).fetchall()
            if not rows and after:
                rows = db.execute(
                    "SELECT slot,body,conflict FROM orders ORDER BY slot LIMIT ?", (limit,)
                ).fetchall()
        return [
            (slot, SignedEvaluationOrder.model_validate_json(raw), bool(conflict))
            for slot, raw, conflict in rows
        ]

    def get(self, slot, kind, model):
        with self.transaction() as db:
            row = db.execute(
                "SELECT body FROM artifacts WHERE slot=? AND kind=?", (slot, kind)
            ).fetchone()
        return None if row is None else model.model_validate_json(row[0])

    def settlement_evidence(self, slot, *, void=False):
        """Read one completed local slot coherently, rejecting holds and oversized rows."""

        def read(db, table, kind, model):
            where, args = (
                ("slot=?", (slot,)) if kind is None else ("slot=? AND kind=?", (slot, kind))
            )
            size = db.execute(
                f"SELECT length(CAST(body AS BLOB)) FROM {table} WHERE {where}", args
            ).fetchone()
            if size is None:
                raise ValueError("local settlement execution evidence is incomplete")
            if type(size[0]) is not int or not 0 < size[0] <= MAX_BYTES:
                raise ValueError("local settlement evidence exceeds its byte bound")
            raw = db.execute(f"SELECT body FROM {table} WHERE {where}", args).fetchone()[0]
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            value = model.model_validate_json(raw)
            if canonical_json_bytes(value) != bytes(raw):
                raise ValueError("local settlement evidence is not canonical")
            return value

        with self.transaction() as db:
            status = db.execute("SELECT conflict FROM orders WHERE slot=?", (slot,)).fetchone()
            if status is None or status[0]:
                raise ValueError("local settlement order is missing or conflicted")
            return (
                read(db, "orders", None, SignedEvaluationOrder),
                read(
                    db,
                    "artifacts",
                    "void" if void else "independent",
                    VoidEvaluationEvidence if void else IndependentEvaluationEvidence,
                ),
                read(
                    db,
                    "artifacts",
                    "void_observation" if void else "independent_observation",
                    VoidEvidenceObservation if void else IndependentEvidenceObservation,
                ),
                read(db, "artifacts", "announcement", SignedExecutionAnnouncement),
            )

    def put(self, slot, kind, value):
        raw = canonical_json_bytes(value)
        conflict = False
        with self.transaction() as db:
            scored = ("result_intent", "run_intent", "vote", "independent")
            void = ("void_intent", "void_vote", "void")
            opposite = void if kind in scored else scored if kind in void else ()
            incompatible = (
                bool(opposite)
                and db.execute(
                    "SELECT 1 FROM artifacts WHERE slot=? AND kind IN ("
                    + ",".join("?" for _ in opposite)
                    + ") LIMIT 1",
                    (slot, *opposite),
                ).fetchone()
            )
            if incompatible:
                # Commit the hold even when capacity cannot retain another body.
                db.execute("UPDATE orders SET conflict=1 WHERE slot=?", (slot,))
                conflict = True
            row = db.execute(
                "SELECT body FROM artifacts WHERE slot=? AND kind=?", (slot, kind)
            ).fetchone()
            if incompatible:
                pass
            elif row:
                if bytes(row[0]) != raw:
                    conflict = True
                    db.execute("UPDATE orders SET conflict=1 WHERE slot=?", (slot,))
                    try:
                        self._capacity(db, len(raw))
                    except ValueError:
                        pass
                    else:
                        db.execute(
                            "INSERT OR IGNORE INTO artifacts VALUES (?,?,?)",
                            (slot, "conflict:" + kind + ":" + digest(value), raw),
                        )
            else:
                credit = evaluator_capacity.credit(db, slot, kind, raw)
                self._capacity(db, len(raw), credit=credit)
                db.execute("INSERT INTO artifacts VALUES (?,?,?)", (slot, kind, raw))
                evaluator_capacity.consume(db, slot, kind)
        if conflict:
            raise ValueError("retained evaluator artifact changed; conflict held")


class ContinuousEvaluator:
    def __init__(self, config, policy, wallet, provider, *, legacy=None, pulse_client=None):
        import bittensor as bt

        self.config = EvaluatorConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.legacy = legacy
        if config.policy_sha256 != digest(self.policy):
            raise ValueError("evaluator policy mismatch")
        if (legacy is None) != (config.legacy_policy_sha256 is None) or (
            legacy is not None and scoring_policy_hash(legacy) != config.legacy_policy_sha256
        ):
            raise ValueError("evaluator transport policy mismatch")
        if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
            config.evaluator_hotkey
        ):
            raise ValueError("evaluator wallet does not hold the named hotkey")
        if identity(config.evaluator_hotkey) not in {identity(e.hotkey) for e in policy.evaluators}:
            raise ValueError("evaluator is absent from the policy")
        self.wallet, self.provider = wallet, provider
        self.pulses = pulse_client or QuicknetClient()
        self.journal = EvaluatorJournal(config)
        self.executions = ExecutionJournal(
            Path(config.state_directory) / "executions",
            policy,
            maximum_jobs=config.maximum_orders,
            maximum_bytes=config.journal_limit("execution"),
        )
        self.dispatch = (
            None
            if legacy is None
            else AssignmentPublicationJournal(
                Path(config.dispatch_directory),
                policy,
                legacy,
                **config.scheduling_capacity.model_dump(),
            )
        )
        for name in ("order_directory", "reveal_directory", "peer_directory", "outbox_directory"):
            _private(Path(getattr(config, name)))
        self._cursor = None
        self._seen_orders = set()
        self._order_cursor = ""
        self._tasks = {}
        self._exchange_task = None
        self._round_task = None
        self._work_task = None
        self._settlement_task = None
        self.settlement_client = None
        self.review_store = None
        self.work_provider = None
        self.work_client = None
        self.round_client = None
        if config.round_coordinator_origin is not None:
            from .competition_rounds import RoundSigningClient

            self.round_client = RoundSigningClient(self, config.round_coordinator_origin)
        if config.settlement_review_directory is not None:
            from .competition_review_history import EvaluatorReviewStore
            from .competition_settlement_transport import SettlementSigningClient

            self.review_store = EvaluatorReviewStore(
                Path(config.settlement_review_directory),
                policy,
                limits=config.settlement_replay_limits,
            )

            self.settlement_client = SettlementSigningClient(
                self,
                config.round_coordinator_origin,
                self.round_client.journal,
                self.review_store,
                limits=config.settlement_replay_limits,
                loopback_port=config.settlement_loopback_port,
            )
        if config.work_signing_chain is not None:
            from .competition_dispatch import DispatchFinalityProvider
            from .competition_work_transport import WorkSigningClient

            self.work_provider = DispatchFinalityProvider(config.work_signing_chain, policy, legacy)
            self.work_client = WorkSigningClient(
                self,
                config.round_coordinator_origin,
                self.round_client.journal,
                transport_provider=self.work_provider,
                legacy=legacy,
                minimum_issue_ms=config.work_minimum_issue_ms,
            )
        self.exchange = None
        if config.exchange_origin is not None:
            from .competition_exchange import EvaluatorExchangeClient

            self.exchange = EvaluatorExchangeClient(self, config.exchange_origin)

    async def boundary(self):
        return execution_boundary(await self.provider.collect())

    async def signing_head(self, order):
        head = (await self.boundary()).block
        if not order.round.reveal_block <= head <= order.round.valid_through_block:
            raise ValueError("evaluation signing is premature or expired")
        slot = execution_slot(order.round, order.submission, self.config.evaluator_hotkey)
        with self.journal.transaction() as db:
            state = db.execute("SELECT conflict FROM orders WHERE slot=?", (slot,)).fetchone()
        if state != (0,):
            raise ValueError("evaluation signing order is missing or conflicted")
        return head

    def ingest_once(self):
        directory = Path(self.config.order_directory)
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(names) >= self.config.maximum_orders:
                    raise ValueError("evaluator inbox exceeds its file capacity")
                names.append(entry.name)
        names = sorted(n for n in names if n.endswith(".json") and n not in self._seen_orders)
        if not names:
            return
        after = [n for n in names if self._cursor is None or n > self._cursor]
        name = (after or names)[0]
        self._cursor = name
        signed = validate_order(
            _read(directory / name, SignedEvaluationOrder), self.policy, self.legacy
        )
        if name != digest(signed.order) + ".json":
            raise ValueError("evaluator order filename differs from its body digest")
        if identity(self.config.evaluator_hotkey) not in {
            identity(k) for k in signed.order.evaluators
        }:
            self._seen_orders.add(name)
            return
        job = order_job(signed.order, self.config.evaluator_hotkey, self.policy, self.legacy)
        self.journal.admit(signed, execution_key(job))
        self._seen_orders.add(name)

    async def _execute(self, job):
        fn = (
            run_endpoint_incumbent
            if isinstance(job, EndpointIncumbentJob)
            else run_model_evaluation
        )
        return await fn(
            job=job,
            policy=self.policy,
            archive=Path(self.config.archive_directory),
            videos=Path(self.config.video_directory),
            journal=self.executions,
            boundary_provider=self.boundary,
        )

    def _output(self, order, kind, value):
        name = f"{digest(order)}.{identity(self.config.evaluator_hotkey)}.{kind}.json"
        _publish(Path(self.config.outbox_directory) / name, value)

    def _peer(self, slot, order, hotkey, kind, model):
        name = f"{digest(order)}.{identity(hotkey)}.{kind}.json"
        try:
            return _read(Path(self.config.peer_directory) / name, model)
        except FileNotFoundError:
            saved = self.journal.get(slot, "peer_" + kind + ":" + identity(hotkey), model)
            if saved is None:
                raise
            return saved

    async def observe_independent(self, slot, order, evidence):
        receipt = self.journal.get(slot, "independent_observation", IndependentEvidenceObservation)
        if receipt is None:
            # If a crash followed evidence retention but preceded this receipt,
            # use the restart's actual observation. Never infer an earlier time
            # from execution finish, filesystem metadata or the relay's claim.
            receipt = IndependentEvidenceObservation(
                schema="umi-independent-evidence-observation/1",
                evaluator_hotkey=self.config.evaluator_hotkey,
                policy_sha256=digest(self.policy),
                round_sha256=digest(order.round),
                order_sha256=digest(order),
                submission_sha256=digest(order.submission.submission),
                evidence_sha256=independent_evidence_digest(evidence),
                observed=await self.boundary(),
            )
            validate_evidence_observation(receipt, order, evidence, self.config.evaluator_hotkey)
            self.journal.put(slot, "independent_observation", receipt)
        receipt = validate_evidence_observation(
            receipt, order, evidence, self.config.evaluator_hotkey
        )
        if self.review_store is not None:
            retained = self.journal.get(slot, "review_retention", IndependentEvidenceObservation)
            if retained is not None:
                validate_evidence_observation(
                    retained, order, evidence, self.config.evaluator_hotkey
                )
                return receipt
            suite = _read(
                Path(self.config.reveal_directory) / (order.round.suite_sha256 + ".json"),
                EvaluationSuite,
            )
            # The review database has its own actual arrival time. Never backdate
            # it to an earlier execution receipt after a crash or delayed replay.
            current = await self.boundary()
            self.review_store.record_independent_evaluation(
                signed=order.submission,
                evidence=evidence,
                round_=order.round,
                suite=suite,
                observed_block=current.block,
            )
            self.journal.put(
                slot, "review_retention", receipt.model_copy(update={"observed": current})
            )
        return receipt

    async def advance(self, slot, signed, head):
        order = signed.order
        job = order_job(order, self.config.evaluator_hotkey, self.policy, self.legacy)
        void = await run_owned_thread(self.journal.get, slot, "void", VoidEvaluationEvidence)
        if void is not None:
            await self.observe_void(slot, order, void)
            self._output(order, "void", void.certificate)
            return "complete"
        final = await run_owned_thread(
            self.journal.get, slot, "independent", IndependentEvaluationEvidence
        )
        if final is not None:
            await self.observe_independent(slot, order, final)
            self._output(order, "independent", final)
            return "complete"
        if head > order.round.valid_through_block:
            return "expired"
        state = await run_owned_thread(self.executions.status, execution_key(job))
        if state is None or (
            state["status"] in {"failed", "authorized"} and self.executions.recovery_ready(job)
        ):
            if head <= order.round.submission_close_block:
                return "scheduled"
            if head > order.round.evaluation_close_block:
                return "expired"
            if slot not in self._tasks and len(self._tasks) < self.config.maximum_parallel_jobs:
                self._tasks[slot] = asyncio.create_task(self._execute(job))
            return "executing" if slot in self._tasks else "scheduled"
        if state["status"] != "complete":
            return "executing" if slot in self._tasks else "held"
        if head < order.round.reveal_block:
            return "waiting_reveal"
        suite = _read(
            Path(self.config.reveal_directory) / (order.round.suite_sha256 + ".json"),
            EvaluationSuite,
        )
        if digest(suite) != order.round.suite_sha256:
            raise ValueError("revealed suite differs from the committed hash")
        own = self.journal.get(slot, "announcement", SignedExecutionAnnouncement)
        if own is None:
            announcement = self.journal.get(slot, "announcement_intent", ExecutionAnnouncement)
            if announcement is None:
                retained = self.executions.reserve(job)
                assert retained is not None
                if isinstance(job, EndpointIncumbentJob):
                    pulses = {}
                    for number in sorted(
                        {
                            a.request.reveal_round
                            for a in order.publication.publication.assignments
                            if identity(a.evaluator_hotkey) == identity(job.evaluator_hotkey)
                            and a.submission_sha256 == digest(job.submission.submission)
                        }
                    ):
                        key = "pulse:" + str(number)
                        pulse = self.journal.get(slot, key, RetainedRevealPulse)
                        if pulse is None:
                            fetched = await self.pulses.fetch(number)
                            pulse = RetainedRevealPulse(
                                round=fetched.round,
                                randomness=fetched.randomness,
                                signature=fetched.signature,
                            )
                            pulse.verified()
                            if pulse.round != number:
                                raise ValueError("wrong reveal pulse")
                            self.journal.put(slot, key, pulse)
                        pulses[number] = pulse
                    # An explicit quorum-signed amendment is an additional input;
                    # absent it, the historical complete-transcript rule is unchanged.
                    from .competition_dispatch_repair import (
                        SignedDispatchRepair,
                        assemble_unavailable_observations,
                    )

                    repair_path = (
                        Path(self.config.state_directory)
                        / "dispatch-repairs"
                        / (digest(order) + ".json")
                    )
                    repair = (
                        _read(repair_path, SignedDispatchRepair) if repair_path.exists() else None
                    )
                    own_repair_claims = (
                        ()
                        if repair is None
                        else tuple(
                            c
                            for c in repair.amendment.unavailable
                            if identity(c.evaluator_hotkey) == identity(job.evaluator_hotkey)
                        )
                    )
                    recovered = own_repair_claims and all(
                        (self.dispatch.status(c.assignment_key) or {}).get("state") == "completed"
                        for c in own_repair_claims
                    )
                    if own_repair_claims and not recovered:
                        retained = assemble_unavailable_observations(
                            incumbent=retained,
                            journal=self.dispatch,
                            signed_order=signed,
                            repair=repair,
                            suite=suite,
                            pulses=pulses,
                            current_block=head,
                        )
                    else:
                        retained = assemble_endpoint_observations(
                            incumbent=retained,
                            journal=self.dispatch,
                            publication_sha256=digest(order.publication.publication),
                            suite=suite,
                            pulses=pulses,
                            current_block=head,
                        )
                execution_observations(retained, suite, self.policy, current_block=head)
                announcement = ExecutionAnnouncement(
                    schema="umi-execution-announcement/1",
                    order_sha256=digest(order),
                    evaluator_hotkey=job.evaluator_hotkey,
                    evidence=retained,
                )
                self.journal.put(slot, "announcement_intent", announcement)
            if announcement.order_sha256 != digest(order) or identity(
                announcement.evaluator_hotkey
            ) != identity(job.evaluator_hotkey):
                raise ValueError("retained announcement intent differs from its order or evaluator")
            view = execution_observations(
                announcement.evidence, suite, self.policy, current_block=head
            )
            if view["job"] != job:
                raise ValueError("retained announcement intent differs from its execution job")
            from .competition_dispatch_repair import (
                EndpointUnavailableEvidence,
                validate_local_repair,
            )

            if isinstance(announcement.evidence, EndpointUnavailableEvidence):
                validate_local_repair(
                    announcement.evidence.repair,
                    journal=self.dispatch,
                    evaluator_hotkey=job.evaluator_hotkey,
                    retained_intent=(self.journal, slot),
                    signed_order=signed,
                    policy=self.policy,
                    legacy=self.legacy,
                    current_block=head,
                )
            head = await self.signing_head(order)
            own = SignedExecutionAnnouncement(
                announcement=announcement, signature=sign_object(announcement, self.wallet)
            )
            self.journal.put(slot, "announcement", own)
        self._output(order, "execution", own)
        executions, observations = [], []
        for evaluator in order.evaluators:
            value = (
                own
                if identity(evaluator) == identity(job.evaluator_hotkey)
                else self._peer(slot, order, evaluator, "execution", SignedExecutionAnnouncement)
            )
            body = value.announcement
            verify_signature(body, value.signature)
            if (
                body.order_sha256 != digest(order)
                or identity(body.evaluator_hotkey) != identity(evaluator)
                or identity(value.signature.hotkey) != identity(evaluator)
            ):
                raise ValueError("peer execution signer/order mismatch")
            view = execution_observations(body.evidence, suite, self.policy, current_block=head)
            if view["job"] != order_job(order, evaluator, self.policy, self.legacy):
                raise ValueError("peer execution differs from the assigned job")
            self.journal.put(slot, "peer_execution:" + identity(evaluator), value)
            executions.append(body.evidence)
            observations.append(value)
        try:
            proposed_void = propose_evaluation_void(
                signed_order=signed,
                observations=tuple(observations),
                suite=suite,
                policy=self.policy,
                current_block=head,
                legacy=self.legacy,
            )
        except ScorableObservations:
            pass
        else:
            return await self.advance_void(slot, signed, proposed_void, own, suite)
        common = common_execution_result(tuple(executions), suite, self.policy, current_block=head)
        record = run_record_from_execution(
            own.announcement.evidence, common, suite, self.policy, current_block=head
        )
        # Reserve exact bytes before either signing operation. A restart may
        # sign these same bytes again, never a second result for this slot.
        self.journal.put(slot, "result_intent", common)
        self.journal.put(slot, "run_intent", record)
        vote = self.journal.get(slot, "vote", EvaluationVote)
        if vote is None:
            head = await self.signing_head(order)
            vote = EvaluationVote(
                schema="umi-evaluation-vote/1",
                order_sha256=digest(order),
                result=common,
                result_signature=sign_object(common, self.wallet),
                run=SignedEvaluatorRunRecord(
                    run=record, signature=sign_evaluator_run(record, self.wallet)
                ),
            )
            self.journal.put(slot, "vote", vote)
        self._output(order, "vote", vote)
        votes = []
        for evaluator, evidence in zip(order.evaluators, executions, strict=True):
            value = (
                vote
                if identity(evaluator) == identity(job.evaluator_hotkey)
                else self._peer(slot, order, evaluator, "vote", EvaluationVote)
            )
            verify_signature(value.result, value.result_signature)
            verify_evaluator_run(value.run)
            expected = run_record_from_execution(
                evidence, common, suite, self.policy, current_block=head
            )
            if (
                value.order_sha256 != digest(order)
                or value.result != common
                or identity(value.result_signature.hotkey) != identity(evaluator)
                or value.run.run != expected
            ):
                raise ValueError("peer vote differs from retained independent execution")
            self.journal.put(slot, "peer_vote:" + identity(evaluator), value)
            votes.append(value)
        final = IndependentEvaluationEvidence(
            schema="umi-competition-independent-evaluation/1",
            attested_result=AttestedResult(
                result=common, signatures=tuple(v.result_signature for v in votes)
            ),
            evaluator_runs=tuple(v.run for v in votes),
        )
        head = await self.signing_head(order)
        replay_independent_evaluation(
            final, order.submission, order.round, suite, self.policy, current_block=head
        )
        self.journal.put(slot, "independent", final)
        await self.observe_independent(slot, order, final)
        self._output(order, "independent", final)
        return "complete"

    async def observe_void(self, slot, order, evidence):
        if evidence.certificate.void.reason == "coordinator_outcome_unavailable":
            suite = await run_owned_thread(
                _read,
                Path(self.config.reveal_directory) / (order.round.suite_sha256 + ".json"),
                EvaluationSuite,
            )
            await run_owned_thread(
                partial(self.dispatch.retire_void, evidence=evidence, suite=suite)
            )
        receipt = self.journal.get(slot, "void_observation", VoidEvidenceObservation)
        if receipt is None:
            receipt = VoidEvidenceObservation(
                schema="umi-void-evidence-observation/1",
                evaluator_hotkey=self.config.evaluator_hotkey,
                policy_sha256=digest(self.policy),
                round_sha256=digest(order.round),
                order_sha256=digest(order),
                submission_sha256=digest(order.submission.submission),
                evidence_sha256=void_evidence_digest(evidence),
                observed=await self.boundary(),
            )
            validate_void_observation(receipt, order, evidence, self.config.evaluator_hotkey)
            self.journal.put(slot, "void_observation", receipt)
        validate_void_observation(receipt, order, evidence, self.config.evaluator_hotkey)
        if self.review_store is not None:
            retained = self.journal.get(slot, "void_review_retention", VoidEvidenceObservation)
            if retained is not None:
                validate_void_observation(retained, order, evidence, self.config.evaluator_hotkey)
                return receipt
            suite = _read(
                Path(self.config.reveal_directory) / (order.round.suite_sha256 + ".json"),
                EvaluationSuite,
            )
            current = await self.boundary()
            self.review_store.record_void_evaluation(
                evidence=evidence, suite=suite, observed_block=current.block
            )
            self.journal.put(
                slot, "void_review_retention", receipt.model_copy(update={"observed": current})
            )
        return receipt

    async def advance_void(self, slot, signed, proposed, own, suite):
        order = signed.order
        context = dict(signed_order=signed, suite=suite, policy=self.policy, legacy=self.legacy)
        head = await self.signing_head(order)
        validate_own_void(
            proposed,
            own_observation=own,
            evaluator_hotkey=self.config.evaluator_hotkey,
            current_block=head,
            **context,
        )
        from .competition_dispatch_repair import validate_local_repair_observation

        validate_local_repair_observation(
            own,
            journal=self.dispatch,
            signed_order=signed,
            policy=self.policy,
            legacy=self.legacy,
            current_block=head,
            evaluator_hotkey=self.config.evaluator_hotkey,
        )
        self.journal.put(slot, "void_intent", proposed)
        vote = self.journal.get(slot, "void_vote", EvaluationVoidVote)
        if vote is None:
            head = await self.signing_head(order)
            vote = EvaluationVoidVote(void=proposed, signature=sign_object(proposed, self.wallet))
            self.journal.put(slot, "void_vote", vote)
        self._output(order, "void_vote", vote)
        votes = []
        for evaluator in order.evaluators:
            value = (
                vote
                if identity(evaluator) == identity(self.config.evaluator_hotkey)
                else self._peer(slot, order, evaluator, "void_vote", EvaluationVoidVote)
            )
            verify_signature(value.void, value.signature)
            if value.void != proposed or identity(value.signature.hotkey) != identity(evaluator):
                raise ValueError("peer void decision differs from retained observations")
            self.journal.put(slot, "peer_void_vote:" + identity(evaluator), value)
            votes.append(value.signature)
        certificate = AttestedEvaluationVoid(void=proposed, signatures=tuple(votes))
        verify_evaluation_void(certificate, current_block=await self.signing_head(order), **context)
        evidence = VoidEvaluationEvidence(
            schema="umi-competition-void-evidence/" + proposed.schema_.rsplit("/", 1)[1],
            order=signed,
            certificate=certificate,
            legacy_policy=self.legacy,
        )
        self.journal.put(slot, "void", evidence)
        await self.observe_void(slot, order, evidence)
        self._output(order, "void", certificate)
        return "complete"

    def _order_needs_boundary(self, slot):
        void = self.journal.get(slot, "void", VoidEvaluationEvidence)
        if void is not None:
            return self.journal.get(slot, "void_observation", VoidEvidenceObservation) is None or (
                self.review_store is not None
                and self.journal.get(slot, "void_review_retention", VoidEvidenceObservation) is None
            )
        final = self.journal.get(slot, "independent", IndependentEvaluationEvidence)
        if final is not None:
            return self.journal.get(
                slot, "independent_observation", IndependentEvidenceObservation
            ) is None or (
                self.review_store is not None
                and self.journal.get(slot, "review_retention", IndependentEvidenceObservation)
                is None
            )
        return True

    async def poll_once(self):
        cursors = self._cursor, self._order_cursor
        try:
            return await self._poll_once()
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", None)
            if code is None or code & 0xFF not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                raise
            # A contended control journal must not shut down this worker and
            # cancel its one-use inference tasks. Revisit the same page at the
            # normal poll interval; retained artifacts remain authoritative.
            self._cursor, self._order_cursor = cursors
            return {
                "status": "waiting_database",
                "reason_code": "sqlite_busy",
                "in_flight": len(self._tasks),
                "no_weight": True,
                "chain_submission_authorized": False,
            }

    async def _poll_once(self):
        counts = {"held": 0, "waiting": 0, "complete": 0, "expired": 0, "executing": 0}
        if self.settlement_client is not None:
            if self._settlement_task is not None and self._settlement_task.done():
                task, self._settlement_task = self._settlement_task, None
                try:
                    result = task.result()
                    counts["held"] += result["held"]
                except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                    counts["waiting"] += 1
            if self._settlement_task is None:
                self._settlement_task = asyncio.create_task(self.settlement_client.sync_once())
        if self.work_client is not None:
            if self._work_task is not None and self._work_task.done():
                task, self._work_task = self._work_task, None
                try:
                    result = task.result()
                    counts["held"] += result["held"]
                except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                    counts["waiting"] += 1
            if self._work_task is None:
                self._work_task = asyncio.create_task(self.work_client.sync_once())
        if self.round_client is not None:
            if self._round_task is not None and self._round_task.done():
                task, self._round_task = self._round_task, None
                try:
                    task.result()
                except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                    counts["waiting"] += 1
            if self._round_task is None:
                self._round_task = asyncio.create_task(self.round_client.sync_once())
        if self.exchange is not None:
            if self._exchange_task is not None and self._exchange_task.done():
                task, self._exchange_task = self._exchange_task, None
                try:
                    task.result()
                except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                    counts["waiting"] += 1
            if self._exchange_task is None:
                self._exchange_task = asyncio.create_task(self.exchange.sync_once())
        for slot, task in list(self._tasks.items()):
            if task.done():
                with suppress(Exception, asyncio.CancelledError):
                    task.result()
                del self._tasks[slot]
        for _ in range(self.config.page_size):
            try:
                await run_owned_thread(self.ingest_once)
            except (OSError, ValueError, RuntimeError):
                counts["held"] += 1
        orders = await run_owned_thread(
            partial(self.journal.orders, after=self._order_cursor, limit=self.config.page_size)
        )
        head = 0
        needs_boundary = await run_owned_thread(
            lambda: any(
                not conflict and self._order_needs_boundary(slot) for slot, _, conflict in orders
            )
        )
        if needs_boundary:
            try:
                head = (await self.boundary()).block
            except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                return {
                    "status": "waiting_finality",
                    "no_weight": True,
                    "chain_submission_authorized": False,
                }
        for slot, signed, conflict in orders:
            self._order_cursor = slot
            if conflict:
                if slot in self._tasks:
                    self._tasks[slot].cancel()
                counts["held"] += 1
                continue
            try:
                result = await self.advance(slot, signed, head)
                counts[result if result in counts else "waiting"] += 1
            except FileNotFoundError:
                counts["waiting"] += 1
            except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                counts["held"] += 1
        return {
            "status": "poll_complete",
            **counts,
            "in_flight": len(self._tasks),
            "no_weight": True,
            "chain_submission_authorized": False,
        }

    async def aclose(self):
        if self._settlement_task is not None:
            self._settlement_task.cancel()
            await asyncio.gather(self._settlement_task, return_exceptions=True)
            self._settlement_task = None
        if self._work_task is not None:
            self._work_task.cancel()
            await asyncio.gather(self._work_task, return_exceptions=True)
            self._work_task = None
        if self._round_task is not None:
            self._round_task.cancel()
            await asyncio.gather(self._round_task, return_exceptions=True)
            self._round_task = None
        if self._exchange_task is not None:
            self._exchange_task.cancel()
            await asyncio.gather(self._exchange_task, return_exceptions=True)
            self._exchange_task = None
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()
        if self.work_provider is not None:
            await self.work_provider.aclose()


async def run_evaluator(config, policy, *, legacy=None, once=False, report=None):
    import bittensor as bt

    config = EvaluatorConfig.model_validate_json(canonical_json_bytes(config))
    _private(Path(config.state_directory))
    lease = _lock_file(Path(config.state_directory) / "evaluator.lock")
    provider = worker = None
    stop, loop, handlers = asyncio.Event(), asyncio.get_running_loop(), []
    try:
        wallet = bt.Wallet(
            name=config.wallet_name, hotkey=config.hotkey_name, path=config.wallet_path
        )
        if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
            config.evaluator_hotkey
        ):
            raise ValueError("evaluator wallet does not hold the named hotkey")
        provider = FinalizedRegistrationProvider(config.chain, policy)
        worker = ContinuousEvaluator(config, policy, wallet, provider, legacy=legacy)
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
            handlers.append(sig)
        await provider.start()
        if worker.work_provider is not None:
            await worker.work_provider.start()

        async def cycle():
            provider.ensure_observer_running()
            if worker.work_provider is not None:
                worker.work_provider.ensure_observer_running()
            result = await worker.poll_once()
            if once:
                await asyncio.gather(*worker._tasks.values(), return_exceptions=True)
                result = {**result, "in_flight": 0}
            return result

        while not stop.is_set():
            result = await _until_stop(cycle(), stop)
            if result is None:
                break
            if report is not None:
                report(result)
            if once:
                return result
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=config.poll_seconds)
        return {"status": "stopped", "no_weight": True, "chain_submission_authorized": False}
    finally:
        try:
            try:
                if worker is not None:
                    await worker.aclose()
            finally:
                if provider is not None:
                    await provider.aclose()
        finally:
            for sig in handlers:
                loop.remove_signal_handler(sig)
            os.close(lease)


async def _until_stop(operation, stop):
    task, stopper = asyncio.create_task(operation), asyncio.create_task(stop.wait())
    try:
        done, _ = await asyncio.wait((task, stopper), return_when=asyncio.FIRST_COMPLETED)
        return None if stopper in done else task.result()
    finally:
        task.cancel()
        stopper.cancel()
        await asyncio.gather(task, stopper, return_exceptions=True)
