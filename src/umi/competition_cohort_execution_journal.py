"""Per-case execution recovery for admitted, quorum-signed cohort assignments.

Raw completed invocations are immutable. Infrastructure interruption leaves the
same obligation pending. A replacement attempt requires stopping its predecessor;
this local journal does not fence a migrated host or authorize reward weights.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

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


class CohortExecutionConfig(CohortOrderSignerConfig):
    schema_: Literal["umi-cohort-execution-config/1"] = Field(alias="schema")
    # Capacity is operational. Raising it does not replace original assignments.
    maximum_attempts: Annotated[int, Field(ge=1, le=65536)] = 4096
    read_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 300


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

    def validate_assignment(self, value: CohortExecutionAssignment) -> RecoverableExecutionJob:
        value = CohortExecutionAssignment.model_validate_json(canonical_json_bytes(value))
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
        return recoverable_order_job(order, self.config.signer)

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

    def assignment(self, slot: str) -> CohortExecutionAssignment:
        value = self.journal.get("assignment", slot)
        if value is None:
            raise FileNotFoundError("execution assignment has not been retained")
        saved = CohortExecutionAssignment.model_validate_json(canonical_json_bytes(value))
        self.validate_assignment(saved)
        if order_slot(saved.certificate.order) != slot:
            raise ValueError("retained execution assignment changed its slot")
        return saved

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
        with self.journal.transaction() as db:
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

    def evidence(self, slot: str) -> RecoverableExecutionEvidence | None:
        assignment = self.assignment(slot)
        job = self.validate_assignment(assignment)
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
