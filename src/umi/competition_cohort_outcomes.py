"""Complete recoverable model or endpoint observations bound to signed receipts."""

from __future__ import annotations

from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_endpoint import (
    RecoverableEndpointPairedEvidence,
    recoverable_endpoint_observations,
)
from .competition_cohort_evaluation import (
    RecoverableEvaluationRound,
    replay_recoverable_independent_evaluation,
)
from .competition_cohort_execution import (
    RecoverableExecutionEvidence,
    RecoverableExecutionObservation,
    recoverable_execution_observations,
    run_record_from_observation,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
)
from .competition_evidence import EvaluatorRunRecord, IndependentEvaluationEvidence
from .open_competition import (
    CompetitionPolicy,
    EvaluationResult,
    EvaluationSuite,
    RegistrationSnapshot,
    SignedSubmission,
    identity,
)
from .protocol import StrictProtocolModel, canonical_json_bytes

RecoverableObservationEvidence = Annotated[
    RecoverableExecutionEvidence | RecoverableEndpointPairedEvidence,
    Field(discriminator="schema_"),
]


class RecoverableExecutedEvaluation(StrictProtocolModel):
    """Every signed run plus its complete model or endpoint artifact."""

    schema_: Literal["umi-recoverable-executed-evaluation/1"] = Field(alias="schema")
    receipts: IndependentEvaluationEvidence
    executions: Annotated[
        tuple[RecoverableObservationEvidence, ...], Field(min_length=1, max_length=64)
    ]
    chain_submission_authorized: Literal[False] = False


def recoverable_observations(
    evidence: RecoverableObservationEvidence,
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
    replay = (
        recoverable_endpoint_observations
        if isinstance(evidence, RecoverableEndpointPairedEvidence)
        else recoverable_execution_observations
    )
    return replay(
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


def recoverable_run_record_from_evidence(
    evidence: RecoverableObservationEvidence,
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
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    common = EvaluationResult.model_validate_json(canonical_json_bytes(common))
    view = recoverable_observations(
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


def replay_recoverable_executed_evaluation(
    evidence: RecoverableExecutedEvaluation,
    signed: SignedSubmission,
    round_: RecoverableEvaluationRound,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> tuple[dict[str, Fraction], dict[str, Fraction]]:
    """Require exact artifact coverage and replay before accepting scored receipts."""
    evidence = RecoverableExecutedEvaluation.model_validate_json(canonical_json_bytes(evidence))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    round_ = RecoverableEvaluationRound.model_validate_json(canonical_json_bytes(round_))
    quality = replay_recoverable_independent_evaluation(
        evidence.receipts,
        signed,
        round_,
        suite,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    artifacts = {}
    for artifact in evidence.executions:
        job = (
            artifact.incumbent.job
            if isinstance(artifact, RecoverableEndpointPairedEvidence)
            else artifact.job
        )
        evaluator = identity(job.evaluator_hotkey)
        if evaluator in artifacts:
            raise ValueError("duplicate evaluator execution artifact")
        if job.round != round_ or job.submission != signed:
            raise ValueError("execution artifact belongs to another round or submission")
        artifacts[evaluator] = artifact
    runs = evidence.receipts.evaluator_runs
    if set(artifacts) != {identity(r.run.evaluator_hotkey) for r in runs}:
        raise ValueError("execution artifacts do not cover exactly the signed evaluators")
    for signed_run in runs:
        run = signed_run.run
        view = recoverable_observations(
            artifacts[identity(run.evaluator_hotkey)],
            suite,
            policy,
            consent,
            admission,
            admission_snapshot,
            history,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        expected = run_record_from_observation(
            view, evidence.receipts.attested_result.result, suite, policy
        )
        # Equivalent address encodings identify the same signer.
        expected = expected.model_copy(update={"evaluator_hotkey": run.evaluator_hotkey})
        if run != expected:
            raise ValueError("signed evaluator receipt differs from its retained execution")
    return quality
