"""Native score replay against certified phase closures in a recoverable cohort.

This explicit future format is rejected by legacy round consumers. Replay here
does not authorize settlement, promotion, admission or a weight transaction.
Those consumers also need the complete execution evidence and recovery history.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_cohort_history import (
    CohortRecoveryHistory,
    RecoveryHistoryView,
    verify_cohort_history,
)
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
    verify_participant_admission,
)
from .competition_cohort_recovery import Block
from .competition_evidence import (
    EvaluationRunScope,
    IndependentEvaluationEvidence,
    replay_evaluator_run_agreement,
)
from .open_competition import (
    AttestedResult,
    CompetitionPolicy,
    EvaluationSuite,
    RegistrationSnapshot,
    SignedSubmission,
    Track,
    digest,
    identity,
    score_evaluation_outputs,
    verify_quorum,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RecoverableRoundParticipant(StrictProtocolModel):
    submission_sha256: Hex32
    admission_sha256: Hex32


class RecoverableEvaluationRound(StrictProtocolModel):
    schema_: Literal["umi-recoverable-evaluation-round/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256: Hex32
    intake_closure_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    suite_sha256: Hex32
    incumbent_model_sha256: Hex32
    runtime_sha256: Hex32
    eligible_tracks: Annotated[tuple[Track, ...], Field(min_length=1, max_length=2)]
    participants: Annotated[
        tuple[RecoverableRoundParticipant, ...], Field(min_length=1, max_length=512)
    ]
    prepared_at_block: Block

    @model_validator(mode="after")
    def canonical_roster(self) -> Self:
        submissions = tuple(p.submission_sha256 for p in self.participants)
        if submissions != tuple(sorted(set(submissions))):
            raise ValueError("recoverable round roster must be sorted and unique")
        if len({p.admission_sha256 for p in self.participants}) != len(self.participants):
            raise ValueError("recoverable round repeats a participant admission")
        if self.eligible_tracks != tuple(sorted(set(self.eligible_tracks))):
            raise ValueError("recoverable round tracks must be sorted and unique")
        return self


def verify_recoverable_round_participant(
    signed: SignedSubmission,
    round_: RecoverableEvaluationRound,
    policy: CompetitionPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> RecoveryHistoryView:
    """Bind an admitted participant and round to certified preparation.

    The selected tip must come from an authoritative monotonic publication;
    current_block must be the consumer's owned finalized observation. Neither
    caller argument may be chosen from untrusted result metadata. This does not
    authorize an invocation, reveal references or attest execution.
    """
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    round_ = RecoverableEvaluationRound.model_validate_json(canonical_json_bytes(round_))
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    accepted = verify_participant_admission(
        admission,
        signed,
        consent,
        history,
        policy,
        admission_snapshot,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    intake = view.closure("intake")
    preparation = view.closure("preparation")
    sub = signed.submission
    participant = RecoverableRoundParticipant(
        submission_sha256=digest(sub), admission_sha256=digest(accepted)
    )
    if (
        round_.cohort_sha256 != view.state.cohort_sha256
        or round_.policy_sha256 != digest(policy)
        or round_.sequence != history.plan.sequence
        or round_.suite_sha256 != history.plan.suite_sha256
        or round_.intake_closure_sha256 != digest(intake)
        or round_.runtime_sha256 != policy.evaluation_runtime_sha256
        or participant not in round_.participants
        or sub.track not in round_.eligible_tracks
    ):
        raise ValueError("recoverable evaluation identity or consent binding differs")
    if not (
        accepted.admitted_at_block
        <= intake.observed_at_block
        <= round_.prepared_at_block
        <= preparation.observed_at_block
        <= current_block
    ):
        raise ValueError("evaluation does not belong to the certified phase interval")
    return view


def replay_recoverable_evaluation(
    attested: AttestedResult,
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
    """Score retained outputs after certified reveal without a target expiry."""
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    attested = AttestedResult.model_validate_json(canonical_json_bytes(attested))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    round_ = RecoverableEvaluationRound.model_validate_json(canonical_json_bytes(round_))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    view = verify_recoverable_round_participant(
        signed,
        round_,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    sub, result = signed.submission, attested.result
    if (
        round_.suite_sha256 != digest(suite)
        or suite.policy_sha256 != digest(policy)
        or result.round_sha256 != digest(round_)
        or result.submission_sha256 != digest(sub)
        or result.model_revision != sub.model_revision
        or result.incumbent_model_sha256 != round_.incumbent_model_sha256
        or result.runtime_sha256 != round_.runtime_sha256
    ):
        raise ValueError("recoverable evaluation identity or consent binding differs")
    if not (
        view.closure("preparation").observed_at_block
        < result.finished_block
        <= view.closure("requests").observed_at_block
        < view.closure("reference_reveal").observed_at_block
        <= current_block
    ):
        raise ValueError("evaluation does not belong to the certified phase interval")
    verify_quorum(attested, policy)
    if any(identity(s.hotkey) == identity(sub.hotkey) for s in attested.signatures):
        raise ValueError("a submitting hotkey cannot attest its own evaluation")
    return score_evaluation_outputs(result, suite, policy)


def replay_recoverable_independent_evaluation(
    evidence: IndependentEvaluationEvidence,
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
    """Replay each evaluator's receipt under authenticated phase closures.

    Receipt signatures and identical outputs do not prove execution. Settlement
    must additionally retain and replay the referenced execution artifacts,
    complete roster, terminal failures and its own certified closure evidence.
    This function neither admits an allocation nor authorizes a transaction.
    """
    evidence = IndependentEvaluationEvidence.model_validate_json(canonical_json_bytes(evidence))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    round_ = RecoverableEvaluationRound.model_validate_json(canonical_json_bytes(round_))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    quality = replay_recoverable_evaluation(
        evidence.attested_result,
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
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    return replay_evaluator_run_agreement(
        evidence,
        signed,
        suite,
        policy,
        scope=EvaluationRunScope(
            round_sha256=digest(round_),
            incumbent_model_sha256=round_.incumbent_model_sha256,
            runtime_sha256=round_.runtime_sha256,
            started_after_block=view.closure("preparation").observed_at_block,
            finished_by_block=view.closure("requests").observed_at_block,
        ),
        common_quality=quality,
    )
