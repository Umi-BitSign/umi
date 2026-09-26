"""Retained execution replay under certified recoverable cohort closures.

These versioned artifacts retain raw sandbox output and original execution
boundaries. They are host observations, not remote execution attestations.
This consumer neither invokes a model nor authorizes settlement or weights.
Endpoint transport and infrastructure-void certificates need separate evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, model_validator
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

    schema_: Literal["umi-recoverable-execution-job/1"] = Field(alias="schema")
    mode: Literal["paired_model", "endpoint_incumbent"]
    round: RecoverableEvaluationRound
    preparation_closure_sha256: Hex32
    submission: SignedSubmission
    incumbent: ModelBundle
    runtime: OfflineRuntime
    evaluator_hotkey: Hotkey
    cases: Annotated[tuple[ExecutionCase, ...], Field(min_length=3, max_length=2048)]

    @model_validator(mode="after")
    def assignment_shape(self) -> Self:
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
    evidence = RecoverableExecutionEvidence.model_validate_json(canonical_json_bytes(evidence))
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
    width = 2 if job.mode == "paired_model" else 1
    if len(evidence.steps) != width * len(job.cases):
        raise ValueError("recoverable execution omits or repeats assigned runs")
    previous = None
    outputs: dict[str, list[CaseOutput]] = {"candidate": [], "incumbent": []}
    for index, step in enumerate(evidence.steps):
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
        validate_case_execution(step.execution, policy)
        for boundary in (step.started, step.finished):
            _ordered(
                boundary,
                previous,
                started_after=preparation.observed_at_block,
                finished_by=requests.observed_at_block,
            )
            previous = boundary
        outputs[role].append(step.execution.output)
    return RecoverableExecutionObservation(
        job=job,
        candidate=tuple(outputs["candidate"]),
        incumbent=tuple(outputs["incumbent"]),
        started_block=evidence.steps[0].started.block,
        finished_block=evidence.steps[-1].finished.block,
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
