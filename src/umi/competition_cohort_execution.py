"""Retained execution replay under certified recoverable cohort closures.

These versioned artifacts retain raw sandbox output and original execution
boundaries. They are host observations, not remote execution attestations.
This consumer neither invokes a model nor authorizes settlement or weights.
Endpoint transport and infrastructure-void certificates need separate evidence.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, model_serializer, model_validator
from typing_extensions import Self

from .competition_cohort_evaluation import (
    RecoverableEvaluationRound,
    verify_recoverable_round_participant,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
)
from .competition_evaluation_runtime import prepared_runtime_authorization
from .competition_evidence import EvaluatorRunRecord
from .competition_execution import ExecutionBoundary, ExecutionCase, ExecutionStep
from .competition_runner import OfflineRuntime, validate_case_execution
from .open_competition import (
    CaseOutput,
    CompetitionPolicy,
    EvaluationResult,
    EvaluationSuite,
    Hotkey,
    ModelBundle,
    RegistrationSnapshot,
    SignedSubmission,
    _quality,
    digest,
    identity,
    validate_bundle_policy,
    validate_suite_profile,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RecoverableExecutionJob(StrictProtocolModel):
    """Reference-free inputs, with an immutable certified preparation binding."""

    schema_: Literal["umi-recoverable-execution-job/1", "umi-recoverable-execution-job/2"] = Field(
        alias="schema"
    )
    incumbent_observation_mode: Literal["first_reserved_per_scope/1"] | None = None
    mode: Literal["paired_model", "endpoint_incumbent"]
    round: RecoverableEvaluationRound
    preparation_closure_sha256: Hex32
    submission: SignedSubmission
    incumbent: ModelBundle
    runtime: OfflineRuntime
    evaluator_hotkey: Hotkey
    cases: Annotated[tuple[ExecutionCase, ...], Field(min_length=3, max_length=2048)]

    @model_serializer(mode="wrap")
    def preserve_original_job(self, handler):
        value = handler(self)
        if self.incumbent_observation_mode is None:
            value.pop("incumbent_observation_mode", None)
        return value

    @model_validator(mode="after")
    def assignment_shape(self) -> Self:
        if (self.schema_ == "umi-recoverable-execution-job/2") != (
            self.incumbent_observation_mode is not None
        ) or (self.incumbent_observation_mode is not None and self.mode != "paired_model"):
            raise ValueError("shared incumbent sampling requires an explicit model job version 2")
        expected_track = "model" if self.mode == "paired_model" else "endpoint"
        if self.submission.submission.track != expected_track:
            raise ValueError("recoverable execution mode differs from submission track")
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("recoverable execution repeats case identities")
        return self


class RecoverableExecutionEvidence(StrictProtocolModel):
    schema_: Literal["umi-recoverable-execution-evidence/1"] = Field(alias="schema")
    job: RecoverableExecutionJob
    steps: Annotated[tuple[ExecutionStep, ...], Field(min_length=3, max_length=4096)]
    chain_submission_authorized: Literal[False] = False


class RecoverableSharedIncumbentEvidence(StrictProtocolModel):
    """Candidate observations plus one explicitly borrowed original baseline.

    The source remains ordinary /1 evidence. Its original boundaries are not
    consumer invocation times, and its failures are shared without reselection.
    """

    schema_: Literal["umi-recoverable-execution-evidence/2"] = Field(alias="schema")
    job: RecoverableExecutionJob
    steps: Annotated[tuple[ExecutionStep, ...], Field(min_length=6, max_length=4096)]
    incumbent_source: RecoverableExecutionEvidence
    source_assignment_json: Annotated[str, Field(min_length=1, max_length=16 * 1024**2)]
    consumer_assignment_json: Annotated[str, Field(min_length=1, max_length=16 * 1024**2)]
    source_reserved_at: ExecutionBoundary
    reuse_observed_at: ExecutionBoundary
    chain_submission_authorized: Literal[False] = False


RecoverableModelExecutionEvidence = Annotated[
    RecoverableExecutionEvidence | RecoverableSharedIncumbentEvidence,
    Field(discriminator="schema_"),
]
EXECUTION_EVIDENCE = TypeAdapter(RecoverableModelExecutionEvidence)


def paired_incumbent_scope(job: RecoverableExecutionJob) -> str:
    if job.mode != "paired_model":
        raise ValueError("shared model incumbent requires a paired model job")
    # The round binds suite, authority, runtime authorization and policy. The
    # runner passes no entrant-dependent inputs or seed to baseline inference.
    return digest(
        dict(
            schema="umi-paired-incumbent-scope/1",
            incumbent_observation_mode=job.incumbent_observation_mode,
            round=digest(job.round),
            preparation=job.preparation_closure_sha256,
            model=digest(job.incumbent),
            runtime=digest(job.runtime),
            evaluator=identity(job.evaluator_hotkey),
            cases=[case.model_dump(mode="json", by_alias=True) for case in job.cases],
        )
    )


def replay_shared_incumbent_steps(
    job,
    steps,
    source,
    source_reserved_at,
    reuse_observed_at,
    policy,
    *,
    started_after,
    finished_by,
    verified_source_outputs=None,
):
    """Replay two authentic timelines; never invent consumer baseline attempts.

    Archive consumers pass their independently cached native source verdict.
    This internal result is never accepted from evidence or network input.
    """
    if paired_incumbent_scope(job) != paired_incumbent_scope(source.job) or digest(job) == digest(
        source.job
    ):
        raise ValueError("shared incumbent differs from its exact source scope")
    if (
        job.incumbent_observation_mode is None
        or source.job.incumbent_observation_mode != job.incumbent_observation_mode
    ):
        raise ValueError("shared incumbent requires both prospective signed order capabilities")
    source_outputs = verified_source_outputs
    if source_outputs is None:
        source_outputs = replay_execution_steps(
            source.job,
            source.steps,
            policy,
            started_after=started_after,
            finished_by=finished_by,
        )
    _ordered(source_reserved_at, None, started_after=started_after, finished_by=finished_by)
    _ordered(
        source.steps[0].started,
        source_reserved_at,
        started_after=started_after,
        finished_by=finished_by,
    )
    _ordered(
        reuse_observed_at,
        source.steps[-1].finished,
        started_after=started_after,
        finished_by=finished_by,
    )
    steps = tuple(steps)
    if len(steps) != 2 * len(job.cases):
        raise ValueError("shared execution omits assigned case observations")
    previous = reuse_observed_at
    candidate = []
    authorization = prepared_runtime_authorization(job.round, policy)
    for index, case in enumerate(job.cases):
        own, borrowed = steps[2 * index : 2 * index + 2]
        if borrowed != source.steps[2 * index + 1]:
            raise ValueError("shared incumbent changed its original observation")
        if (
            own.role != "candidate"
            or own.execution.output.case_id != case.case_id
            or own.execution.video_sha256 != case.video_sha256
            or own.execution.model_sha256 != job.submission.submission.model_revision
            or own.execution.runtime_sha256 != digest(job.runtime)
        ):
            raise ValueError("shared execution changed its candidate assignment")
        validate_case_execution(own.execution, policy, runtime_authorization=authorization)
        for boundary in (own.started, own.finished):
            _ordered(boundary, previous, started_after=started_after, finished_by=finished_by)
            previous = boundary
        candidate.append(own.execution.output)
    return {"candidate": candidate, "incumbent": source_outputs["incumbent"]}


@dataclass(frozen=True)
class RecoverableExecutionObservation:
    job: RecoverableExecutionJob
    candidate: tuple[CaseOutput, ...]
    incumbent: tuple[CaseOutput, ...]
    started_block: int
    finished_block: int
    requests_closed_at_block: int
    evidence_sha256: str


def _ordered(
    boundary: ExecutionBoundary,
    previous: ExecutionBoundary | None,
    *,
    started_after: int,
    finished_by: int,
) -> None:
    if not started_after < boundary.block <= finished_by:
        raise ValueError("execution boundary is outside the certified request interval")
    if previous is not None and (
        boundary.block < previous.block
        or (
            boundary.block == previous.block
            and (boundary.block_hash, boundary.state_root, boundary.snapshot_sha256)
            != (previous.block_hash, previous.state_root, previous.snapshot_sha256)
        )
    ):
        raise ValueError("execution boundary rolled back or changed at the same block")


def replay_execution_steps(
    job: RecoverableExecutionJob,
    steps: Iterable[ExecutionStep],
    policy: CompetitionPolicy,
    *,
    started_after: int,
    finished_by: int,
) -> dict[str, list[CaseOutput]]:
    """Validate all original outputs and boundaries without reference answers.

    The caller authenticates the assignment and original chain proof sources.
    This verifies retained observations; it does not attest physical execution.
    """
    width = 2 if job.mode == "paired_model" else 1
    runtime_authorization = prepared_runtime_authorization(job.round, policy)
    previous = None
    outputs: dict[str, list[CaseOutput]] = {"candidate": [], "incumbent": []}
    for index, raw in zip(range(width * len(job.cases)), steps, strict=True):
        step = ExecutionStep.model_validate_json(canonical_json_bytes(raw))
        case = job.cases[index // width]
        role = "candidate" if width == 2 and index % 2 == 0 else "incumbent"
        model = (
            job.submission.submission.model_revision
            if role == "candidate"
            else digest(job.incumbent)
        )
        if (
            step.role != role
            or step.execution.output.case_id != case.case_id
            or step.execution.video_sha256 != case.video_sha256
            or step.execution.model_sha256 != model
        ):
            raise ValueError("recoverable execution step assignment/model binding differs")
        if step.execution.runtime_sha256 != digest(job.runtime):
            raise ValueError("recoverable execution step runtime differs from its job")
        validate_case_execution(step.execution, policy, runtime_authorization=runtime_authorization)
        for boundary in (step.started, step.finished):
            _ordered(
                boundary,
                previous,
                started_after=started_after,
                finished_by=finished_by,
            )
            previous = boundary
        outputs[role].append(step.execution.output)
    return outputs


def recoverable_execution_observations(
    evidence: RecoverableExecutionEvidence,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> RecoverableExecutionObservation:
    """Replay complete observations after reveal, preserving failure statuses.

    Evidence hashes and timing boundaries remain references to retained native
    proofs. Reviewers must authenticate those sources independently. Missing
    records cannot become failures or certified voids through this function.
    """
    evidence = EXECUTION_EVIDENCE.validate_json(canonical_json_bytes(evidence))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    job = evidence.job
    view = verify_recoverable_round_participant(
        job.submission,
        job.round,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    preparation = view.closure("preparation")
    requests = view.closure("requests")
    reveal = view.closure("reference_reveal")
    if not preparation.observed_at_block < requests.observed_at_block < reveal.observed_at_block:
        raise ValueError("execution requires ordered certified request closure and reveal")
    validate_suite_profile(suite, policy)
    expected_cases = tuple(
        ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
        for c in suite.cases
    )
    if (
        job.preparation_closure_sha256 != digest(preparation)
        or digest(job.incumbent) != job.round.incumbent_model_sha256
        or digest(job.runtime) != job.round.runtime_sha256
        or digest(suite) != job.round.suite_sha256
        or suite.policy_sha256 != digest(policy)
        or job.cases != expected_cases
    ):
        raise ValueError("execution assignment, preparation, model, runtime or suite differs")
    evaluator = identity(job.evaluator_hotkey)
    if evaluator not in {identity(e.hotkey) for e in policy.evaluators} or evaluator == identity(
        job.submission.submission.hotkey
    ):
        raise ValueError("unauthorized or self-evaluating recoverable execution")
    validate_bundle_policy(job.incumbent, policy)
    if job.mode == "paired_model":
        validate_bundle_policy(job.submission.submission.model_bundle, policy)
    interval = dict(
        started_after=preparation.observed_at_block, finished_by=requests.observed_at_block
    )
    if isinstance(evidence, RecoverableSharedIncumbentEvidence):
        # The embedded compatibility path has the same source authentication as
        # archive/closure readers. Its source is never merely an unsigned job.
        from .competition_cohort_execution_journal import CohortExecutionAssignment
        from .competition_cohort_order_queue import check_delivery_receipt
        from .competition_cohort_orders import recoverable_order_job, verify_recoverable_order

        for encoded, expected_job in (
            (evidence.source_assignment_json, evidence.incumbent_source.job),
            (evidence.consumer_assignment_json, job),
        ):
            assignment = CohortExecutionAssignment.model_validate_json(encoded)
            if canonical_json_bytes(assignment) != encoded.encode():
                raise ValueError("shared incumbent assignment is not canonical")
            receipt = check_delivery_receipt(assignment.certificate, assignment.delivery)
            assigned_job = recoverable_order_job(
                assignment.certificate.order, receipt.receipt.evaluator_hotkey
            )
            if assigned_job != expected_job or assigned_job.incumbent_observation_mode is None:
                raise ValueError("shared incumbent signed assignment differs from its observations")
            participant = assignment.participant
            verify_recoverable_order(
                assignment.certificate,
                policy,
                participant.consent,
                participant.admission,
                participant.admission_snapshot,
                history,
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
            )
        outputs = replay_shared_incumbent_steps(
            job,
            evidence.steps,
            evidence.incumbent_source,
            evidence.source_reserved_at,
            evidence.reuse_observed_at,
            policy,
            **interval,
        )
    else:
        outputs = replay_execution_steps(job, evidence.steps, policy, **interval)
    return RecoverableExecutionObservation(
        job=job,
        candidate=tuple(outputs["candidate"]),
        incumbent=tuple(outputs["incumbent"]),
        started_block=min(step.started.block for step in evidence.steps),
        finished_block=max(step.finished.block for step in evidence.steps),
        requests_closed_at_block=requests.observed_at_block,
        evidence_sha256=digest(evidence),
    )


def run_record_from_observation(
    view: RecoverableExecutionObservation,
    common: EvaluationResult,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
) -> EvaluatorRunRecord:
    job = view.job
    if (
        len(view.candidate) != len(job.cases)
        or common.round_sha256 != digest(job.round)
        or common.submission_sha256 != digest(job.submission.submission)
        or common.model_revision != job.submission.submission.model_revision
        or common.incumbent_model_sha256 != digest(job.incumbent)
        or common.runtime_sha256 != digest(job.runtime)
        or not view.finished_block <= common.finished_block <= view.requests_closed_at_block
    ):
        raise ValueError("common result does not bind this paired model execution")
    for role in ("candidate", "incumbent"):
        own, proposed = getattr(view, role), getattr(common, role)
        if len(own) != len(proposed):
            raise ValueError("common result has incomplete output coverage")
        for left, right in zip(own, proposed, strict=True):
            if (left.case_id, left.status, left.hypothesis) != (
                right.case_id,
                right.status,
                right.hypothesis,
            ) or right.elapsed_ms < left.elapsed_ms:
                raise ValueError("common result disagrees with retained execution")
            if (left.status == "ok" and left.elapsed_ms <= policy.maximum_inference_ms) != (
                right.status == "ok" and right.elapsed_ms <= policy.maximum_inference_ms
            ):
                raise ValueError("common result changes per-case resource eligibility")
        if _quality(own, suite, policy, incumbent=role == "incumbent") != _quality(
            proposed, suite, policy, incumbent=role == "incumbent"
        ):
            raise ValueError("common result changes execution quality or eligibility")
    return EvaluatorRunRecord(
        schema="umi-competition-evaluator-run/1",
        evaluator_hotkey=job.evaluator_hotkey,
        policy_sha256=digest(policy),
        round_sha256=digest(job.round),
        submission_sha256=digest(job.submission.submission),
        common_result_sha256=digest(common),
        suite_sha256=digest(suite),
        model_revision=job.submission.submission.model_revision,
        incumbent_model_sha256=digest(job.incumbent),
        runtime_sha256=digest(job.runtime),
        started_block=view.started_block,
        finished_block=view.finished_block,
        candidate=view.candidate,
        incumbent=view.incumbent,
        execution_evidence_sha256=view.evidence_sha256,
    )


def recoverable_run_record_from_execution(
    evidence: RecoverableExecutionEvidence,
    common: EvaluationResult,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> EvaluatorRunRecord:
    """Prepare an unsigned receipt only after replaying the original artifact."""
    common = EvaluationResult.model_validate_json(canonical_json_bytes(common))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    view = recoverable_execution_observations(
        evidence,
        suite,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    return run_record_from_observation(view, common, suite, policy)
