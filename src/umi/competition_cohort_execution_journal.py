"""Per-case execution recovery for admitted, quorum-signed cohort assignments.

Raw completed invocations are immutable. Infrastructure interruption leaves the
same obligation pending. A replacement attempt requires stopping its predecessor;
this local journal does not fence a migrated host or authorize reward weights.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer

from .canonical_reuse import canonical_json_reuse
from .competition_assignment_reuse import AssignmentVerificationReuse, assignment_reuse_key
from .competition_cohort_execution import (
    RecoverableExecutionEvidence,
    RecoverableExecutionJob,
    RecoverableSharedIncumbentEvidence,
    paired_incumbent_scope,
)
from .competition_cohort_export_checkpoint import (
    PartialExportCheckpoint,
    SharedPartialExportCheckpoint,
    SharedSourceRecord,
)
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
from .competition_cpu_efficiency_policy import prepared_cpu_efficiency_authorization
from .competition_execution import ExecutionBoundary, ExecutionStep, PendingExecutionStep
from .competition_round_journal import RecordReservation, RoundJournal
from .competition_runner import OfflineCaseExecution, validate_case_execution
from .competition_verification_rules import runtime_identity
from .host_memory_request_bounds import stage_limit
from .open_competition import CompetitionPolicy, digest, digest_canonical_bytes, identity
from .private_files import ensure_private_directory, lock_private_file
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_STEP_RECORD_BYTES = 48 * 1024


@dataclass(frozen=True, slots=True)
class _StepRecords:
    """Unvalidated immutable bytes copied together by the journal owner."""

    step: bytes | None
    head: str | None
    attempt: bytes | None
    result: bytes | None


@dataclass(frozen=True, slots=True)
class ExecutionScopeState:
    """Private scheduling result of the ordinary retained-evidence validation."""

    evidence: RecoverableExecutionEvidence | RecoverableSharedIncumbentEvidence | None
    model_roles: tuple[str, ...] = ("candidate", "incumbent")


class PartialExportSourceRepairRequired(ValueError):
    """A previously verified immutable source disappeared or changed."""


class IncumbentSourcePending(OSError):
    """The fixed source must finish before this consumer can prepare models."""


def _partial_export_source_repair(checkpoint, reason, index=None):
    logging.getLogger("umi.competition.progress").warning(
        json.dumps(
            dict(
                schema="umi-model-partial-export-source-repair/1",
                stage="model_partial_export_source_repair",
                status="repair_required",
                cohort_sha256=checkpoint.cohort_sha256,
                slot=checkpoint.slot,
                reason=reason,
                step_index=index,
                completed=0,
                total=1,
                unit="source_records",
                elapsed_seconds=0,
                eta_seconds=None,
                eta_basis="restore_exact_retained_native_source_record",
                stalled_or_retrying=True,
                certification_authority=False,
            ),
            separators=(",", ":"),
        )
    )
    raise PartialExportSourceRepairRequired(
        "immutable completed source record requires native repair: " + reason
    )


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
    # Enable only after all selected readers support explicit /2 provenance.
    share_paired_incumbent: bool = False

    @model_serializer(mode="wrap")
    def preserve_legacy_config(self, handler):
        value = handler(self)
        if not self.share_paired_incumbent:
            value.pop("share_paired_incumbent", None)
        return value


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
    if job.mode == "paired_model":
        return paired_incumbent_scope(job)
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
        self._partial_export_context = digest(
            {
                "schema": "umi-model-partial-export-context/1",
                "policy": digest(self.policy),
                "cohorts": self.cohorts,
                "signer": identity(self.config.signer),
                "verification_semantics": runtime_identity(),
            }
        )
        self._assignment_reuse = AssignmentVerificationReuse.for_execution("execution_retained")
        self._supplied_assignment_reuse = AssignmentVerificationReuse.for_execution(
            "execution_supplied"
        )
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
                    "share_paired_incumbent",
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

    def partial_export_context_matches(self, checkpoint: PartialExportCheckpoint) -> bool:
        """Bind the local completed source fact to this actual native owner."""
        info = self.journal.path.stat()
        return (
            checkpoint.context_sha256 == self._partial_export_context
            and checkpoint.owner_path == str(self.journal.path)
            and (checkpoint.owner_device, checkpoint.owner_inode)
            == (str(info.st_dev), str(info.st_ino))
        )

    def partial_export_projection(self, slot):
        """Project existing signed metadata for an upgrade receipt, without replay."""
        raw = self.journal.get_raw("assignment", slot)
        if raw is None:
            return None
        value = json.loads(raw)
        if value["certificate"]["order"]["submission"]["submission"]["track"] != "model":
            return None
        assignment = CohortExecutionAssignment.model_validate_json(raw)
        job = recoverable_order_job(assignment.certificate.order, self.config.signer)
        return assignment, job

    def partial_export_unchanged(self, checkpoint: PartialExportCheckpoint) -> bool:
        """Check fresh original bytes after releasing their coherent snapshot."""
        if not self.partial_export_context_matches(checkpoint):
            return False
        # Published objects bound assignment/step bodies. A borrowed step can
        # occur under both consumer and source keys; allow two copies plus the
        # three native source bindings and a newly appeared record. Retain the
        # journal's existing per-record envelope, including legacy originals,
        # rather than applying the current 48 KiB step reservation to all kinds.
        remaining = stage_limit(
            "maximum_input_bytes",
            min(
                self.journal.maximum_bytes,
                2 * checkpoint.maximum_bytes + 4 * self.journal.maximum_record_bytes,
            ),
        )
        records = {}

        def copy(db, kind, key):
            nonlocal remaining
            if (kind, key) not in records:
                raw = self.journal._copy_raw(db, kind, key, maximum_bytes=remaining)
                remaining -= 0 if raw is None else len(raw)
                records[kind, key] = raw
            return records[kind, key]

        with self.journal.read_transaction(coordinated=True) as db:
            copy(db, "assignment", checkpoint.slot)
            changed_prefix = False
            for key, expected in zip(checkpoint.step_keys, checkpoint.step_sha256s, strict=True):
                if copy(db, "step", key) is not None and expected is None:
                    # The first new step already invalidates this prefix. Its
                    # original bytes are still checked below, in the same order.
                    changed_prefix = True
                    break
            if not changed_prefix:
                if isinstance(checkpoint, SharedPartialExportCheckpoint):
                    for ref in checkpoint.source_records:
                        copy(db, ref.kind, ref.key)
                else:
                    copy(db, "incumbent_reuse", checkpoint.job_sha256)

        def checked(kind, key):
            return self.journal._check_record_bytes(records[kind, key], kind)

        raw = checked("assignment", checkpoint.slot)
        if raw is None:
            _partial_export_source_repair(checkpoint, "assignment_missing")
        if digest_canonical_bytes(raw) != checkpoint.assignment_sha256:
            _partial_export_source_repair(checkpoint, "assignment_changed")
        for index, (key, expected) in enumerate(
            zip(checkpoint.step_keys, checkpoint.step_sha256s, strict=True)
        ):
            raw = checked("step", key)
            if (None if raw is None else digest_canonical_bytes(raw)) != expected:
                if expected is not None:
                    _partial_export_source_repair(
                        checkpoint,
                        "completed_step_missing" if raw is None else "completed_step_changed",
                        index,
                    )
                return False
        if isinstance(checkpoint, SharedPartialExportCheckpoint):
            for ref in checkpoint.source_records:
                raw = checked(ref.kind, ref.key)
                if raw is None or digest_canonical_bytes(raw) != ref.sha256:
                    _partial_export_source_repair(checkpoint, "shared_source_missing_or_changed")
        elif checked("incumbent_reuse", checkpoint.job_sha256) is not None:
            # An unchanged /1 partial fact cannot authorize a new /2 source.
            return False
        return True

    def partial_export_checkpoint(
        self, slot, assignment, job, manifest, manifest_sha256, *, maximum_bytes, completed_by_block
    ):
        """Derive small reusable keys once, after the native partial was reviewed."""
        if job.mode != "paired_model" or len(manifest.steps) == step_count(job):
            return None
        if manifest.assignment_sha256 != digest(assignment):
            raise ValueError("partial export checkpoint changed its reviewed assignment")
        info = self.journal.path.stat()
        job_sha = digest(job)
        keys = tuple(
            digest(dict(schema="umi-cohort-execution-step/1", job=job_sha, index=index))
            for index in range(step_count(job))
        )
        steps = {step.index: step.sha256 for step in manifest.steps}
        checkpoint = PartialExportCheckpoint(
            schema="umi-private-model-partial-export/1",
            context_sha256=self._partial_export_context,
            owner_path=str(self.journal.path),
            owner_device=str(info.st_dev),
            owner_inode=str(info.st_ino),
            slot=slot,
            assignment_sha256=manifest.assignment_sha256,
            job_sha256=job_sha,
            cohort_sha256=job.round.cohort_sha256,
            step_keys=keys,
            step_sha256s=tuple(steps.get(index) for index in range(len(keys))),
            manifest_sha256=manifest_sha256,
            maximum_bytes=maximum_bytes,
            completed_by_block=completed_by_block,
        )
        shared = self.paired_incumbent_reuse(job)
        if shared is not None:
            receipt, source, source_evidence = shared
            references = [
                SharedSourceRecord(kind="incumbent_reuse", key=job_sha, sha256=digest(receipt)),
                SharedSourceRecord(
                    kind="incumbent_source", key=source.scope_sha256, sha256=digest(source)
                ),
                SharedSourceRecord(
                    kind="incumbent_source_selection",
                    key=source.scope_sha256,
                    sha256=digest({"source_sha256": digest(source)}),
                ),
                SharedSourceRecord(
                    kind="assignment",
                    key=source.source_slot,
                    sha256=digest(self.assignment(source.source_slot)),
                ),
            ]
            references.extend(
                SharedSourceRecord(
                    kind="step",
                    key=execution_step_key(source_evidence.job, index),
                    sha256=digest(step),
                )
                for index, step in enumerate(source_evidence.steps)
            )
            terminal = self.journal.get_raw("request_terminal", source.source_slot)
            if terminal is None:
                raise FileNotFoundError("shared incumbent source terminal awaits publication")
            references.append(
                SharedSourceRecord(
                    kind="request_terminal",
                    key=source.source_slot,
                    sha256=digest_canonical_bytes(terminal),
                )
            )
            checkpoint = SharedPartialExportCheckpoint.model_validate(
                {
                    **checkpoint.model_dump(mode="python", by_alias=True),
                    "schema": "umi-private-model-partial-export/2",
                    "source_records": tuple(references),
                }
            )
        # This describes exactly the prefix already collected and reviewed.
        # A concurrent new step need not be reread here: every future reuse
        # freshly compares all source records and rejects a changed prefix.
        return checkpoint

    @canonical_json_reuse()
    def validate_assignment(self, value: CohortExecutionAssignment) -> RecoverableExecutionJob:
        """Check static supplied proofs; this does not grant execution authority."""
        raw = canonical_json_bytes(value)
        slot = hashlib.sha256(raw).hexdigest()
        key = assignment_reuse_key(
            self.journal, slot, (raw,), self.config, self.policy, self.cohorts
        )

        def calculate():
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
            return recoverable_order_job(order, self.config.signer)

        return self._supplied_assignment_reuse.resolve(slot, key, calculate)

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

    def _validated_assignment(self, slot: str, *, project=None):
        # Read exact bytes and current conflict holds in one short snapshot.
        # Static proof verification must not reserve the journal writer or keep
        # unrelated reads waiting on its process lock. This read grants no
        # current authority; dispatch still checks its owned fresh capture.
        with self.journal.read_transaction(coordinated=True) as db:
            raw = self.journal._copy_raw(db, "assignment", slot)
        raw = self.journal._check_record_bytes(raw, "assignment")
        if raw is None:
            raise FileNotFoundError("execution assignment has not been retained")
        key = assignment_reuse_key(
            self.journal, slot, (raw,), self.config, self.policy, self.cohorts
        )

        def calculate():
            saved = CohortExecutionAssignment.model_validate_json(raw)
            job = self.validate_assignment(saved)
            if order_slot(saved.certificate.order) != slot:
                raise ValueError("retained execution assignment changed its slot")
            return saved, job

        if project is not None:
            return self._assignment_reuse._project(slot, key, calculate, project)
        return self._assignment_reuse.resolve(slot, key, calculate)

    def _project_assignment(self, slot: str, project):
        """Owned read-only projection after fresh assignment/conflict reads."""
        return self._validated_assignment(slot, project=project)

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
        scope = incumbent_scope(job)
        with self.journal.read_transaction() as db:
            raw = self.journal.get_raw("incumbent_source", scope, db=db)
            marker = self.journal.get_raw("incumbent_source_selection", scope, db=db)
        if raw is None:
            if marker is not None:
                raise ValueError("selected shared incumbent source requires repair")
            return None
        value = CohortIncumbentSource.model_validate_json(raw)
        if value.scope_sha256 != scope:
            raise ValueError("shared incumbent source scope requires repair")
        expected = canonical_json_bytes({"source_sha256": digest(value)})
        if (marker is None and job.mode == "paired_model") or (
            marker is not None and marker != expected
        ):
            raise ValueError("shared incumbent source selection requires repair")
        return value

    def _source_job(self, job, source):
        _, original = self.assignment_and_job(source.source_slot)
        if (
            digest(original) != source.source_job_sha256
            or incumbent_scope(original) != incumbent_scope(job)
            or self.journal.get("incumbent_reuse", digest(original)) is not None
        ):
            raise ValueError("shared incumbent source assignment differs or forms a cycle")
        return original

    def _source_evidence(self, job, source):
        self._source_job(job, source)
        evidence = self.evidence(source.source_slot)
        if evidence is not None:
            check_boundary(evidence.steps[0].started, source.reserved_at)
        elif (
            self.journal.get("incumbent_source_complete", digest(source)) is not None
            or self.journal.get("request_terminal", source.source_slot) is not None
        ):
            raise ValueError("completed shared incumbent source requires repair")
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

    def incumbent_source_status(
        self, slot: str, job: RecoverableExecutionJob
    ) -> Literal["ready", "pending", "unselected"]:
        """Read-only scheduling hint; ordinary execution still checks authority.

        Only opted-in, unstarted model consumers can wait here. Count retained
        source step identities without loading outputs or replaying evidence.
        The source reservation and all execution/reuse writes stay on their
        existing authenticated path.
        """
        if job.mode != "paired_model" or job.incumbent_observation_mode is None:
            return "ready"
        if self.journal.get_raw("incumbent_reuse", digest(job)) is not None:
            return "ready"
        if self._execution_started(job):
            return "ready"
        source = self._incumbent_source(job)
        if source is None:
            return "unselected"
        if source.source_slot == slot:
            if source.source_job_sha256 != digest(job):
                raise ValueError("shared incumbent source changed its job")
            return "ready"
        original = self._source_job(job, source)
        with self.journal.read_transaction() as db:
            if self._checkpoint_count(source.source_job_sha256, step_count(original), db) == (
                step_count(original)
            ):
                return "ready"
            if (
                self.journal.get_raw("incumbent_source_complete", digest(source), db=db) is not None
                or self.journal.get_raw("request_terminal", source.source_slot, db=db) is not None
            ):
                raise ValueError("completed shared incumbent source requires repair")
        return "pending"

    def _reserve_incumbent_source(self, slot, job, observed):
        # Different job locks do not serialize this shared immutable decision.
        # The short scope lock prevents two first jobs from writing conflicting
        # source reservations. A busy peer retries without reserving an attempt.
        scope = incumbent_scope(job)
        with self.locked(scope):
            source = self._incumbent_source(job)
            if source is None:
                source = CohortIncumbentSource(
                    schema="umi-cohort-incumbent-source/1",
                    scope_sha256=scope,
                    source_slot=slot,
                    source_job_sha256=digest(job),
                    reserved_at=observed,
                )
                self.journal.put_many(
                    (
                        ("incumbent_source", source.scope_sha256, source),
                        (
                            "incumbent_source_selection",
                            source.scope_sha256,
                            {"source_sha256": digest(source)},
                        ),
                    )
                )
            elif job.mode == "endpoint_incumbent":
                # Historical endpoint reservations predate the independent
                # selection marker. Preserve their exact original selection.
                self.journal.put(
                    "incumbent_source_selection",
                    source.scope_sha256,
                    {"source_sha256": digest(source)},
                )
            return source

    def reuse_endpoint_incumbent(self, slot, job, observed):
        """Compatibility entrypoint for the existing endpoint-only path."""
        if job.mode != "endpoint_incumbent":
            return None
        return self.reuse_incumbent(slot, job, observed)

    def reuse_incumbent(self, slot, job, observed):
        return self._reuse_incumbent(slot, job, observed)

    def prepare_execution_scope(self, slot, job, observed):
        """Return roles from the same authenticated reuse pass, without replaying it."""
        return self._reuse_incumbent(slot, job, observed, for_scope=True)

    def _reuse_incumbent(self, slot, job, observed, *, for_scope=False):
        """Reserve one future source, keeping legacy executions in place.

        Existing attempts remain independent. Endpoint reuse retains its /1
        format; opted-in model consumers retain explicit /2 provenance. A source
        is selected before inference and held fixed even on failure. Borrowed
        observations keep their original times and have no consumer attempts.
        """
        started_clock = time.monotonic()
        read_evidence = self.execution_scope_state if for_scope else self.evidence
        independent = ExecutionScopeState(None) if for_scope else None
        if self.journal.get("incumbent_reuse", digest(job)) is not None:
            return read_evidence(slot)
        if job.mode == "paired_model" and job.incumbent_observation_mode is None:
            return independent
        if self._execution_started(job):
            if job.mode == "paired_model":
                source = self._incumbent_source(job)
                if (
                    source is None
                    or source.source_slot != slot
                    or source.source_job_sha256 != digest(job)
                ):
                    raise ValueError("started shared incumbent source selection requires repair")
            return independent
        if job.mode == "paired_model" and not self.config.share_paired_incumbent:
            source = self._incumbent_source(job)
            if (
                source is not None
                and source.source_slot == slot
                and source.source_job_sha256 == digest(job)
            ):
                return independent
            raise OSError("shared incumbent order awaits reader-enabled producer")
        _, retained_job = self.assignment_and_job(slot)
        if retained_job != job:
            raise ValueError("shared incumbent consumer is not its retained assignment")
        source = self._reserve_incumbent_source(slot, job, observed)
        if source.source_slot == slot:
            if source.source_job_sha256 != digest(job):
                raise ValueError("shared incumbent source changed its job")
            return independent
        evidence = self._source_evidence(job, source)
        if evidence is None:
            raise IncumbentSourcePending("shared incumbent source remains unfinished")
        check_boundary(observed, evidence.steps[-1].finished)
        receipt = CohortIncumbentReuse(
            schema="umi-cohort-incumbent-reuse/1",
            consumer_job_sha256=digest(job),
            source_sha256=digest(source),
            source_evidence_sha256=digest(evidence),
            observed_at=observed,
        )
        records = [
            ("incumbent_reuse", digest(job), receipt),
            (
                "incumbent_source_complete",
                digest(source),
                {"source_evidence_sha256": digest(evidence)},
            ),
        ]
        if job.mode == "paired_model":
            # Preserve the exact source bytes under the consumer's observation
            # indices. No execution head, attempt, result or new time is made.
            records.extend(
                ("step", execution_step_key(job, index), evidence.steps[index])
                for index in range(1, step_count(job), 2)
            )
        self.journal.put_many(tuple(records))
        logging.getLogger("umi.competition.progress").info(
            json.dumps(
                dict(
                    schema="umi-incumbent-observation-reuse-progress/1",
                    stage="incumbent_observation_reuse",
                    status="completed",
                    cohort_sha256=job.round.cohort_sha256,
                    source_slot=source.source_slot,
                    consumer_slot=slot,
                    completed=len(job.cases),
                    total=len(job.cases),
                    unit="reused_incumbent_observations",
                    avoided_inferences=len(job.cases),
                    elapsed_seconds=round(time.monotonic() - started_clock, 3),
                    eta_seconds=0,
                    eta_basis="fixed_original_source_retained",
                    stalled_or_retrying=False,
                    fresh_inference=False,
                ),
                separators=(",", ":"),
            )
        )
        return read_evidence(slot)

    def _reused_incumbent(self, slot, job, raw):
        value = CohortIncumbentReuse.model_validate_json(canonical_json_bytes(raw))
        source = self._incumbent_source(job)
        if (
            value.consumer_job_sha256 != digest(job)
            or source is None
            or value.source_sha256 != digest(source)
            or source.source_job_sha256 == digest(job)
            or (job.mode == "endpoint_incumbent" and self._execution_started(job))
        ):
            raise ValueError("shared incumbent consumer changed its binding or has attempts")
        evidence = self._source_evidence(job, source)
        if evidence is None or digest(evidence) != value.source_evidence_sha256:
            raise ValueError("shared incumbent observations changed or disappeared")
        check_boundary(value.observed_at, evidence.steps[-1].finished)
        if job.mode == "paired_model":
            steps = []
            previous = value.observed_at
            for index, step in enumerate(
                self.steps_snapshot(job, shared=(value, source, evidence), stop_at_missing=True)
            ):
                if step is None:
                    return None
                if index % 2 == 0:
                    check_boundary(step.started, previous)
                    previous = step.finished
                steps.append(step)
            return RecoverableSharedIncumbentEvidence(
                schema="umi-recoverable-execution-evidence/2",
                job=job,
                steps=tuple(steps),
                incumbent_source=evidence,
                source_assignment_json=canonical_json_bytes(
                    self.assignment(source.source_slot)
                ).decode(),
                consumer_assignment_json=canonical_json_bytes(self.assignment(slot)).decode(),
                source_reserved_at=source.reserved_at,
                reuse_observed_at=value.observed_at,
            )
        return RecoverableExecutionEvidence(
            schema="umi-recoverable-execution-evidence/1", job=job, steps=evidence.steps
        )

    def paired_incumbent_reuse(self, job):
        """Return exact retained provenance, or require repair; never replace it."""
        if job.mode != "paired_model":
            return None
        raw = self.journal.get("incumbent_reuse", digest(job))
        if raw is None:
            return None
        value = CohortIncumbentReuse.model_validate_json(canonical_json_bytes(raw))
        source = self._incumbent_source(job)
        if (
            value.consumer_job_sha256 != digest(job)
            or source is None
            or value.source_sha256 != digest(source)
            or source.source_job_sha256 == digest(job)
        ):
            raise ValueError("shared incumbent source binding requires repair")
        evidence = self._source_evidence(job, source)
        if evidence is None or digest(evidence) != value.source_evidence_sha256:
            raise ValueError("shared incumbent original evidence requires repair")
        check_boundary(value.observed_at, evidence.steps[-1].finished)
        return value, source, evidence

    def reused_checkpoint_count(self, job: RecoverableExecutionJob) -> int:
        """Advisory count only; never authorizes source or candidate execution."""
        if job.mode != "paired_model":
            return 0
        return len(job.cases) if self.journal.get_raw("incumbent_reuse", digest(job)) else 0

    def checkpoint_count(self, job: RecoverableExecutionJob) -> int:
        """Metadata-only progress; execution still validates each retained step."""
        with self.journal.read_transaction() as db:
            return self._checkpoint_count(digest(job), step_count(job), db)

    @staticmethod
    def _checkpoint_count(job_sha256, total, db):
        keys = [
            digest({"schema": "umi-cohort-execution-step/1", "job": job_sha256, "index": i})
            for i in range(total)
        ]
        completed = 0
        for offset in range(0, len(keys), 128):
            batch = keys[offset : offset + 128]
            placeholders = ",".join("?" for _ in batch)
            completed += db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='step' AND id IN (" + placeholders + ")",
                batch,
            ).fetchone()[0]
        return completed

    def recent_assignment_slots(self, *, limit=32):
        """Small startup scheduling hints; no evidence is read or authorized."""
        if type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError("invalid execution startup hint bound")
        with self.journal.read_transaction() as db:
            return tuple(
                row[0]
                for row in db.execute(
                    "SELECT id FROM records WHERE kind='assignment' ORDER BY rowid DESC LIMIT ?",
                    (limit,),
                )
            )

    def step(
        self, job: RecoverableExecutionJob, index: int, *, db=None, shared=None
    ) -> ExecutionStep | None:
        if shared is None and job.mode == "paired_model" and index % 2:
            shared = self.paired_incumbent_reuse(job)
        key = execution_step_key(job, index)
        if db is None:
            with self.journal.read_transaction(coordinated=True) as db:
                records = self._copy_step_records(db, key)
        else:
            records = self._copy_step_records(db, key)
        return self._checked_step_records(job, index, records, shared=shared)

    def _copy_step_records(self, db, key):
        def read(kind, ident):
            return self.journal._copy_raw(db, kind, ident, maximum_bytes=_STEP_RECORD_BYTES)

        step = read("step", key)
        if step in (None, b"null"):
            return _StepRecords(step, None, None, None)
        row = db.execute("SELECT attempt FROM execution_heads WHERE step=?", (key,)).fetchone()
        if row is None:
            return _StepRecords(step, None, None, None)
        return _StepRecords(step, row[0], read("attempt", row[0]), read("result", row[0]))

    def _checked_step_records(self, job, index, records, *, shared):
        raw = self.journal._check_record_bytes(records.step, "step")
        raw_attempt = self.journal._check_record_bytes(records.attempt, "attempt")
        raw_result = self.journal._check_record_bytes(records.result, "result")
        if job.mode == "paired_model" and index % 2 and shared:
            original = shared[2].steps[index]
            if raw != canonical_json_bytes(original):
                raise ValueError("borrowed incumbent observation requires repair")
            if records.head is not None:
                self._checked_head(job, index, records.head, raw_attempt)
                raise ValueError("borrowed incumbent has an unexpected local invocation")
            return original
        if raw in (None, b"null"):
            return None
        if records.head is None:
            raise ValueError("completed step has no attempt")
        attempt = self._checked_head(job, index, records.head, raw_attempt)
        record = ExecutionStep.model_validate_json(raw)
        pending = self._checked_result(job, attempt, raw_result)
        if pending is None or (record.role, record.started, record.execution) != (
            pending.role,
            pending.started,
            pending.execution,
        ):
            raise ValueError("completed step differs from the retained result")
        check_boundary(record.finished, record.started)
        return record

    def steps_snapshot(self, job, *, shared=None, stop_at_missing=False):
        """Copy one bounded snapshot, then validate outside SQLite ownership.

        Step/head/result records remain bound to one committed snapshot. Only
        native per-step metadata is copied, with the same 48 KiB record bound
        as execution reservations; no model bytes or chain proofs are loaded.
        """
        if shared is None:
            shared = self.paired_incumbent_reuse(job) or False
        job_sha256 = digest(job)
        keys = [
            digest({"schema": "umi-cohort-execution-step/1", "job": job_sha256, "index": index})
            for index in range(step_count(job))
        ]
        records = []
        with self.journal.read_transaction(coordinated=True) as db:
            for key in keys:
                copied = self._copy_step_records(db, key)
                records.append(copied)
                if stop_at_missing and copied.step in (None, b"null"):
                    break
        return tuple(
            self._checked_step_records(job, index, copied, shared=shared)
            for index, copied in enumerate(records)
        )

    def first_unfinished(self, job):
        """One source read and one consumer snapshot for a scheduling scan."""
        shared = self.paired_incumbent_reuse(job) or False
        for index, step in enumerate(self.steps_snapshot(job, shared=shared, stop_at_missing=True)):
            if step is None:
                return index
        return None

    def head(
        self, job: RecoverableExecutionJob, index: int, *, db=None
    ) -> CohortExecutionAttempt | None:
        if db is None:
            with self.journal.read_transaction() as db:
                return self.head(job, index, db=db)
        row = db.execute(
            "SELECT attempt FROM execution_heads WHERE step=?",
            (execution_step_key(job, index),),
        ).fetchone()
        if row is None:
            return None
        return self._checked_head(
            job, index, row[0], self.journal.get_raw("attempt", row[0], db=db)
        )

    def _checked_head(self, job, index, key, raw):
        attempt = CohortExecutionAttempt.model_validate_json(b"null" if raw is None else raw)
        if (
            digest(attempt) != key
            or attempt.job_sha256 != digest(job)
            or attempt.step_index != index
        ):
            raise ValueError("retained execution attempt changed its assignment")
        return attempt

    def result(
        self, job: RecoverableExecutionJob, attempt: CohortExecutionAttempt, *, db=None
    ) -> PendingExecutionStep | None:
        return self._checked_result(
            job, attempt, self.journal.get_raw("result", digest(attempt), db=db)
        )

    def _checked_result(self, job, attempt, raw):
        if raw in (None, b"null"):
            return None
        result = PendingExecutionStep.model_validate_json(raw)
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
        timing = result.output.cpu_timing
        if timing is not None and timing.conditions.invocation_sha256 != digest(attempt):
            raise ValueError("CPU timing invocation differs from its retained attempt")
        from .competition_evaluation_runtime import prepared_runtime_authorization

        validate_case_execution(
            result,
            self.policy,
            runtime_authorization=prepared_runtime_authorization(job.round, self.policy),
            cpu_efficiency_authorization=prepared_cpu_efficiency_authorization(
                job.round, self.policy
            ),
            execution_runtime=job.runtime,
        )
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
        shared = self.journal.get("incumbent_reuse", digest(job))
        if shared is not None and (job.mode != "paired_model" or index % 2):
            raise ValueError("shared incumbent consumer cannot invoke a fresh baseline sandbox")
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
        prior_index = index - (2 if shared is not None else 1)
        if prior_index >= 0:
            prior_step = self.step(job, prior_index)
            if prior_step is None:
                raise ValueError("execution steps must complete in order")
            check_boundary(started, prior_step.finished)
        elif shared is not None:
            reuse = CohortIncumbentReuse.model_validate_json(canonical_json_bytes(shared))
            check_boundary(started, reuse.observed_at)
        with self.journal.read_transaction() as db:
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
                RecordReservation("result", key, _STEP_RECORD_BYTES),
                RecordReservation("step", step_key, _STEP_RECORD_BYTES),
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
        return self.execution_scope_state(slot).evidence

    @canonical_json_reuse()
    def execution_scope_state(self, slot: str) -> ExecutionScopeState:
        _, job = self._validated_assignment(slot)
        shared = self.journal.get("incumbent_reuse", digest(job))
        if shared is not None:
            evidence = self._reused_incumbent(slot, job, shared)
            roles = ("candidate",) if job.mode == "paired_model" else ("incumbent",)
            return ExecutionScopeState(evidence, roles)
        steps = []
        # Copy one committed snapshot; decoding and output checks must not keep
        # an exporter read lock open while another case commits its highwater.
        for step in self.steps_snapshot(job, shared=False, stop_at_missing=True):
            if step is None:
                return ExecutionScopeState(None)
            if steps:
                check_boundary(step.started, steps[-1].finished)
            steps.append(step)
        return ExecutionScopeState(
            RecoverableExecutionEvidence(
                schema="umi-recoverable-execution-evidence/1", job=job, steps=tuple(steps)
            )
        )
