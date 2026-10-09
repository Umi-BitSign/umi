"""Per-case execution recovery for admitted, quorum-signed cohort assignments.

Raw completed invocations are immutable. Infrastructure interruption leaves the
same obligation pending. A replacement attempt requires stopping its predecessor;
this local journal does not fence a migrated host or authorize reward weights.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .canonical_reuse import canonical_json_reuse
from .competition_assignment_reuse import AssignmentVerificationReuse, assignment_reuse_key
from .competition_cohort_execution import RecoverableExecutionEvidence, RecoverableExecutionJob
from .competition_cohort_order_queue import SignedOrderDeliveryReceipt, check_delivery_receipt
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderParticipant,
    CohortOrderSignerConfig,
    order_slot,
    review_order,
)
from .competition_cohort_orders import (
    SignedRecoverableEvaluationOrder,
    recoverable_order_job,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import ExecutionBoundary, ExecutionStep, PendingExecutionStep
from .competition_round_journal import RecordReservation, RoundJournal
from .competition_runner import OfflineCaseExecution, validate_case_execution
from .open_competition import CompetitionPolicy, digest, identity
from .private_files import ensure_private_directory, lock_private_file
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


def control_exchange_timeout_seconds(config: CohortExecutionConfig) -> int:
    """Use the selected read budget for grants, response recovery and retirement.

    These calls may wait for the miner's authority or finalized-head checks.
    An independent short ceiling can abandon otherwise valid work repeatedly.
    The configured budget remains bounded and retry-safe; signed clocks and
    transmission counts are separate protocol checks.
    """
    return config.read_timeout_seconds


class CohortExecutionConfig(CohortOrderSignerConfig):
    schema_: Literal["umi-cohort-execution-config/1"] = Field(alias="schema")
    # Capacity is operational. Raising it does not replace original assignments.
    maximum_attempts: Annotated[int, Field(ge=1, le=65536)] = 4096
    read_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400


class CohortExecutionAssignment(StrictProtocolModel):
    certificate: SignedRecoverableEvaluationOrder
    participant: CohortOrderParticipant
    delivery: SignedOrderDeliveryReceipt


class CohortExecutionAttempt(StrictProtocolModel):
    schema_: Literal["umi-cohort-execution-attempt/1"] = Field(alias="schema")
    job_sha256: Hex32
    step_index: Annotated[int, Field(ge=0, le=4095)]
    number: Annotated[int, Field(ge=1, le=2**53 - 1)]
    predecessor_sha256: Hex32 | None
    started: ExecutionBoundary
    history_sha256: Hex32


class CohortIncumbentSource(StrictProtocolModel):
    """Choose a new source before inference; never select a favorable old run."""

    schema_: Literal["umi-cohort-incumbent-source/1"] = Field(alias="schema")
    scope_sha256: Hex32
    source_slot: Hex32
    source_job_sha256: Hex32
    reserved_at: ExecutionBoundary


class CohortIncumbentReuse(StrictProtocolModel):
    """Local provenance for borrowing original observations, not fresh inference."""

    schema_: Literal["umi-cohort-incumbent-reuse/1"] = Field(alias="schema")
    consumer_job_sha256: Hex32
    source_sha256: Hex32
    source_evidence_sha256: Hex32
    observed_at: ExecutionBoundary


def incumbent_scope(job: RecoverableExecutionJob) -> str:
    if job.mode != "endpoint_incumbent":
        raise ValueError("only endpoint comparators can share observations")
    return digest(
        {
            "schema": "umi-cohort-incumbent-scope/1",
            "round": digest(job.round),
            "preparation": job.preparation_closure_sha256,
            "model": digest(job.incumbent),
            "runtime": digest(job.runtime),
            "evaluator": identity(job.evaluator_hotkey),
            "cases": [case.model_dump(mode="json", by_alias=True) for case in job.cases],
        }
    )


class CohortStoppedAttempt(StrictProtocolModel):
    schema_: Literal["umi-cohort-stopped-attempt/1"] = Field(alias="schema")
    attempt_sha256: Hex32
    status: Literal["sandbox_stopped"]


def execution_step_key(job: RecoverableExecutionJob, index: int) -> str:
    if type(index) is not int or not 0 <= index < step_count(job):
        raise ValueError("execution step is outside its assignment")
    return digest({"schema": "umi-cohort-execution-step/1", "job": digest(job), "index": index})


def step_count(job: RecoverableExecutionJob) -> int:
    return len(job.cases) * (2 if job.mode == "paired_model" else 1)


def case_role_model(job: RecoverableExecutionJob, index: int):
    execution_step_key(job, index)
    width = 2 if job.mode == "paired_model" else 1
    case = job.cases[index // width]
    role = "candidate" if width == 2 and index % 2 == 0 else "incumbent"
    model = job.submission.submission.model_bundle if role == "candidate" else job.incumbent
    return case, role, model


def check_boundary(current: ExecutionBoundary, previous: ExecutionBoundary | None) -> None:
    if previous is not None and (
        current.block < previous.block
        or (
            current.block == previous.block
            and (current.block_hash, current.state_root, current.snapshot_sha256)
            != (previous.block_hash, previous.state_root, previous.snapshot_sha256)
        )
    ):
        raise ValueError("execution boundary regressed or changed within one block")


class CohortExecutionJournal:
    def __init__(self, config: CohortExecutionConfig, policy: CompetitionPolicy):
        self.config = CohortExecutionConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if self.config.policy_sha256 != digest(self.policy):
            raise ValueError("execution journal policy binding differs")
        if identity(self.config.signer) not in {identity(e.hotkey) for e in self.policy.evaluators}:
            raise ValueError("execution journal evaluator is not in its policy")
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in self.config.cohorts}
        self._assignment_reuse = AssignmentVerificationReuse()
        self._supplied_assignment_reuse = AssignmentVerificationReuse()
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json",
                by_alias=True,
                exclude={
                    "maximum_votes",
                    "maximum_bytes",
                    "maximum_attempts",
                    "signing_timeout_seconds",
                    "read_timeout_seconds",
                },
            ),
            maximum_rounds=self.config.maximum_attempts,
            maximum_bytes=self.config.maximum_bytes,
            maximum_record_bytes=16 * 1024**2,
        )
        ensure_private_directory(self.journal.root / "jobs")
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS execution_heads "
                "(step TEXT PRIMARY KEY, attempt TEXT NOT NULL)"
            )
            db.execute("CREATE TABLE IF NOT EXISTS execution_cursor (slot TEXT NOT NULL)")

    @contextmanager
    def locked(self, slot: str):
        if len(slot) != 64 or any(c not in "0123456789abcdef" for c in slot):
            raise ValueError("invalid execution job slot")
        fd = lock_private_file(self.journal.root / "jobs" / (slot + ".lock"))
        try:
            yield
        finally:
            os.close(fd)

    @canonical_json_reuse()
    def validate_assignment(self, value: CohortExecutionAssignment) -> RecoverableExecutionJob:
        """Check static supplied proofs; this does not grant execution authority."""
        raw = canonical_json_bytes(value)
        slot = hashlib.sha256(raw).hexdigest()
        key = assignment_reuse_key(
            self.journal, slot, (raw,), self.config, self.policy, self.cohorts
        )
        cached = self._supplied_assignment_reuse.lookup(slot, key)
        if cached is not None:
            return cached
        value = CohortExecutionAssignment.model_validate_json(raw)
        order = value.certificate.order
        verify_recovery_quorum(order, value.certificate.signatures, self.policy)
        if any(
            identity(s.hotkey) == identity(order.submission.submission.hotkey)
            for s in value.certificate.signatures
        ):
            raise ValueError("miner cannot authorize its own execution")
        receipt = check_delivery_receipt(value.certificate, value.delivery)
        if identity(receipt.receipt.evaluator_hotkey) != identity(self.config.signer):
            raise ValueError("execution delivery belongs to another evaluator")
        job = recoverable_order_job(order, self.config.signer)
        self._supplied_assignment_reuse.remember(slot, key, job)
        return job

    def retain(self, value: CohortExecutionAssignment, source: CohortOrderHistory, block: int):
        job = self.validate_assignment(value)
        if self.cohorts.get(job.round.cohort_sha256) != digest(source.history.authority.authority):
            raise ValueError("execution authority differs from configured cohort")
        slot = order_slot(value.certificate.order)
        old = self.journal.get("assignment", slot)
        if old is not None:
            if canonical_json_bytes(old) != canonical_json_bytes(value):
                raise ValueError("execution slot already belongs to another assignment")
            return job
        review_order(value.certificate.order, value.participant, source, self.policy, block)

        def index(db):
            if (
                db.execute("SELECT COUNT(*) FROM records WHERE kind='assignment'").fetchone()[0]
                > self.config.maximum_votes
            ):
                raise ValueError("execution job capacity exhausted")

        self.journal.put_many((("assignment", slot, value),), index=index)
        return job

    def _validated_assignment(self, slot: str):
        # Read exact bytes and current conflict holds in one short snapshot.
        # Static proof verification must not reserve the journal writer or keep
        # unrelated reads waiting on its process lock. This read grants no
        # current authority; dispatch still checks its owned fresh capture.
        with self.journal.read_transaction() as db:
            raw = self.journal.get_raw("assignment", slot, db=db)
            if raw is None:
                raise FileNotFoundError("execution assignment has not been retained")
        key = assignment_reuse_key(
            self.journal, slot, (raw,), self.config, self.policy, self.cohorts
        )
        cached = self._assignment_reuse.lookup(slot, key)
        if cached is not None:
            return cached
        saved = CohortExecutionAssignment.model_validate_json(raw)
        job = self.validate_assignment(saved)
        if order_slot(saved.certificate.order) != slot:
            raise ValueError("retained execution assignment changed its slot")
        self._assignment_reuse.remember(slot, key, (saved, job))
        return saved, job

    @canonical_json_reuse()
    def assignment(self, slot: str) -> CohortExecutionAssignment:
        return self._validated_assignment(slot)[0]

    @canonical_json_reuse()
    def assignment_and_job(
        self, slot: str
    ) -> tuple[CohortExecutionAssignment, RecoverableExecutionJob]:
        """Reuse exact retained static proofs; this grants no current authority."""
        return self._validated_assignment(slot)

    def _execution_started(self, job: RecoverableExecutionJob) -> bool:
        # An uncertain sandbox counts as started. It must finish its own original
        # recovery path, even when another source is already complete.
        with self.journal.read_transaction() as db:
            for index in range(step_count(job)):
                key = execution_step_key(job, index)
                if (
                    db.execute("SELECT 1 FROM execution_heads WHERE step=?", (key,)).fetchone()
                    or self.journal.get_raw("step", key, db=db) is not None
                ):
                    return True
        return False

    def _incumbent_source(self, job: RecoverableExecutionJob) -> CohortIncumbentSource | None:
        raw = self.journal.get("incumbent_source", incumbent_scope(job))
        if raw is None:
            return None
        value = CohortIncumbentSource.model_validate_json(canonical_json_bytes(raw))
        if value.scope_sha256 != incumbent_scope(job):
            raise ValueError("shared incumbent source changed its scope")
        return value

    def _source_evidence(self, job, source):
        _, original = self.assignment_and_job(source.source_slot)
        if (
            digest(original) != source.source_job_sha256
            or incumbent_scope(original) != incumbent_scope(job)
            or self.journal.get("incumbent_reuse", digest(original)) is not None
        ):
            raise ValueError("shared incumbent source assignment differs or forms a cycle")
        evidence = self.evidence(source.source_slot)
        if evidence is not None:
            check_boundary(evidence.steps[0].started, source.reserved_at)
        return evidence

    def unfinished_incumbent_sources(self) -> tuple[str, ...]:
        """Scheduling hints only; execution still checks current authority."""
        with self.journal.transaction() as db:
            sources = db.execute(
                "SELECT id, body FROM records WHERE kind='incumbent_source' ORDER BY id"
            ).fetchall()
        pending = []
        for key, raw in sources:
            source = CohortIncumbentSource.model_validate_json(raw)
            _, job = self.assignment_and_job(source.source_slot)
            if key != source.scope_sha256 or incumbent_scope(job) != key:
                raise ValueError("shared incumbent scheduling source changed its scope")
            if self._source_evidence(job, source) is None:
                pending.append(source.source_slot)
        return tuple(pending)

    def reuse_endpoint_incumbent(self, slot, job, observed):
        """Reserve one future source, keeping legacy executions in place.

        Existing attempts remain independent. Only an unstarted endpoint job may
        borrow all original observations from the fixed new source. An unfinished
        source holds its consumers; they cannot choose another completed result.
        Wire evidence keeps its established schema and original observed times.
        The private immutable journal retains explicit source/consumer provenance.
        """
        if job.mode != "endpoint_incumbent" or self._execution_started(job):
            return None
        _, retained_job = self.assignment_and_job(slot)
        if retained_job != job:
            raise ValueError("shared incumbent consumer is not its retained assignment")
        source = self._incumbent_source(job)
        if source is None:
            source = CohortIncumbentSource(
                schema="umi-cohort-incumbent-source/1",
                scope_sha256=incumbent_scope(job),
                source_slot=slot,
                source_job_sha256=digest(job),
                reserved_at=observed,
            )
            self.journal.put("incumbent_source", source.scope_sha256, source)
            return None
        if source.source_slot == slot:
            if source.source_job_sha256 != digest(job):
                raise ValueError("shared incumbent source changed its job")
            return None
        evidence = self._source_evidence(job, source)
        if evidence is None:
            raise OSError("shared incumbent source remains unfinished")
        check_boundary(observed, evidence.steps[-1].finished)
        receipt = CohortIncumbentReuse(
            schema="umi-cohort-incumbent-reuse/1",
            consumer_job_sha256=digest(job),
            source_sha256=digest(source),
            source_evidence_sha256=digest(evidence),
            observed_at=observed,
        )
        self.journal.put("incumbent_reuse", digest(job), receipt)
        return self.evidence(slot)

    def _reused_incumbent(self, job, raw):
        value = CohortIncumbentReuse.model_validate_json(canonical_json_bytes(raw))
        source = self._incumbent_source(job)
        if (
            value.consumer_job_sha256 != digest(job)
            or source is None
            or value.source_sha256 != digest(source)
            or source.source_job_sha256 == digest(job)
            or self._execution_started(job)
        ):
            raise ValueError("shared incumbent consumer changed its binding or has attempts")
        evidence = self._source_evidence(job, source)
        if evidence is None or digest(evidence) != value.source_evidence_sha256:
            raise ValueError("shared incumbent observations changed or disappeared")
        check_boundary(value.observed_at, evidence.steps[-1].finished)
        return RecoverableExecutionEvidence(
            schema="umi-recoverable-execution-evidence/1", job=job, steps=evidence.steps
        )

    def step(self, job: RecoverableExecutionJob, index: int) -> ExecutionStep | None:
        raw = self.journal.get("step", execution_step_key(job, index))
        if raw is None:
            return None
        attempt = self.head(job, index)
        if attempt is None:
            raise ValueError("completed step has no attempt")
        record = ExecutionStep.model_validate_json(canonical_json_bytes(raw))
        pending = self.result(job, attempt)
        if pending is None or (record.role, record.started, record.execution) != (
            pending.role,
            pending.started,
            pending.execution,
        ):
            raise ValueError("completed step differs from the retained result")
        check_boundary(record.finished, record.started)
        return record

    def head(self, job: RecoverableExecutionJob, index: int) -> CohortExecutionAttempt | None:
        with self.journal.read_transaction() as db:
            row = db.execute(
                "SELECT attempt FROM execution_heads WHERE step=?",
                (execution_step_key(job, index),),
            ).fetchone()
            if row is None:
                return None
            raw = self.journal.get("attempt", row[0], db=db)
        attempt = CohortExecutionAttempt.model_validate_json(canonical_json_bytes(raw))
        if (
            digest(attempt) != row[0]
            or attempt.job_sha256 != digest(job)
            or attempt.step_index != index
        ):
            raise ValueError("retained execution attempt changed its assignment")
        return attempt

    def result(
        self, job: RecoverableExecutionJob, attempt: CohortExecutionAttempt
    ) -> PendingExecutionStep | None:
        raw = self.journal.get("result", digest(attempt))
        if raw is None:
            return None
        result = PendingExecutionStep.model_validate_json(canonical_json_bytes(raw))
        self.check_result(job, attempt, result.execution)
        if (
            result.started != attempt.started
            or result.role != case_role_model(job, attempt.step_index)[1]
        ):
            raise ValueError("retained result changed its execution start or role")
        return result

    def check_result(self, job, attempt, result: OfflineCaseExecution):
        result = OfflineCaseExecution.model_validate_json(canonical_json_bytes(result))
        case, _, model = case_role_model(job, attempt.step_index)
        if (
            attempt.job_sha256 != digest(job)
            or result.model_sha256 != digest(model)
            or result.runtime_sha256 != digest(job.runtime)
            or result.video_sha256 != case.video_sha256
            or result.output.case_id != case.case_id
        ):
            raise ValueError("invocation result differs from its assigned model or case")
        validate_case_execution(result, self.policy)
        return result

    def stopped(self, attempt: CohortExecutionAttempt):
        self.journal.put(
            "stopped",
            digest(attempt),
            CohortStoppedAttempt(
                schema="umi-cohort-stopped-attempt/1",
                attempt_sha256=digest(attempt),
                status="sandbox_stopped",
            ),
        )

    def begin(
        self,
        job: RecoverableExecutionJob,
        index: int,
        source: CohortOrderHistory,
        started: ExecutionBoundary,
    ):
        if self.journal.get("incumbent_reuse", digest(job)) is not None:
            raise ValueError("shared incumbent consumer cannot invoke a fresh sandbox")
        if self.step(job, index) is not None:
            raise ValueError("completed execution cannot be attempted again")
        previous = self.head(job, index)
        if previous is not None:
            if self.result(job, previous) is not None:
                raise ValueError(
                    "retained result requires its finish observation, not another invocation"
                )
            raw = self.journal.get("stopped", digest(previous))
            if raw is None or CohortStoppedAttempt.model_validate_json(
                canonical_json_bytes(raw)
            ).attempt_sha256 != digest(previous):
                raise ValueError("prior sandbox must be stopped before replacement")
            check_boundary(started, previous.started)
        if index:
            prior_step = self.step(job, index - 1)
            if prior_step is None:
                raise ValueError("execution steps must complete in order")
            check_boundary(started, prior_step.finished)
        with self.journal.transaction() as db:
            if (
                db.execute("SELECT COUNT(*) FROM records WHERE kind='attempt'").fetchone()[0]
                >= self.config.maximum_attempts
            ):
                raise ValueError("execution attempt capacity exhausted")
        attempt = CohortExecutionAttempt(
            schema="umi-cohort-execution-attempt/1",
            job_sha256=digest(job),
            step_index=index,
            number=1 if previous is None else previous.number + 1,
            predecessor_sha256=None if previous is None else digest(previous),
            started=started,
            history_sha256=digest(source),
        )
        key = digest(attempt)
        step_key = execution_step_key(job, index)
        self.journal.reserve_records(
            key,
            (
                RecordReservation("result", key, 48 * 1024),
                RecordReservation("step", step_key, 48 * 1024),
                RecordReservation("stopped", key, 1024),
            ),
        )

        def advance(db):
            if (
                db.execute("SELECT COUNT(*) FROM records WHERE kind='attempt'").fetchone()[0]
                > self.config.maximum_attempts
            ):
                raise ValueError("execution attempt capacity exhausted")
            old = db.execute(
                "SELECT attempt FROM execution_heads WHERE step=?", (step_key,)
            ).fetchone()
            if old != (None if previous is None else (digest(previous),)):
                raise ValueError("execution attempt changed concurrently")
            db.execute(
                "INSERT INTO execution_heads VALUES (?,?) "
                "ON CONFLICT(step) DO UPDATE SET attempt=excluded.attempt",
                (step_key, key),
            )

        self.journal.put_many((("attempt", key, attempt),), index=advance)
        return attempt

    def observe(self, job, attempt, result):
        if self.head(job, attempt.step_index) != attempt:
            raise ValueError("invocation is no longer the selected attempt")
        result = self.check_result(job, attempt, result)
        self.journal.put(
            "result",
            digest(attempt),
            PendingExecutionStep(
                role=case_role_model(job, attempt.step_index)[1],
                started=attempt.started,
                execution=result,
            ),
        )

    def finish(self, job, attempt, finished):
        pending = self.result(job, attempt)
        if self.head(job, attempt.step_index) != attempt or pending is None:
            raise ValueError("execution finish has no selected retained result")
        check_boundary(finished, attempt.started)
        self.journal.put(
            "step",
            execution_step_key(job, attempt.step_index),
            ExecutionStep(
                role=pending.role,
                started=pending.started,
                execution=pending.execution,
                finished=finished,
            ),
        )

    @canonical_json_reuse()
    def evidence(self, slot: str) -> RecoverableExecutionEvidence | None:
        _, job = self._validated_assignment(slot)
        shared = self.journal.get("incumbent_reuse", digest(job))
        if shared is not None:
            return self._reused_incumbent(job, shared)
        steps = []
        for index in range(step_count(job)):
            step = self.step(job, index)
            if step is None:
                return None
            if steps:
                check_boundary(step.started, steps[-1].finished)
            steps.append(step)
        return RecoverableExecutionEvidence(
            schema="umi-recoverable-execution-evidence/1", job=job, steps=tuple(steps)
        )
