"""Build a reference-free round from the complete certified intake.

This is preparation evidence, not permission to dispatch or submit weights.
Independent phase reviewers must authenticate its original registration proofs
and promotion receipt before certifying preparation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Literal

from pydantic import Field

from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_evaluation import RecoverableEvaluationRound, RecoverableRoundParticipant
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake_seal import (
    CohortIntakeSeal,
    build_intake_seal,
    verify_intake_closure,
)
from .competition_cohort_participation import verify_participant_admission
from .competition_cohort_roster import (
    RecoverableRosterEvidence,
    RecoverableRosterParticipant,
)
from .competition_execution import ExecutionBoundary
from .competition_settlement import PromotionHeadBinding
from .open_competition import CompetitionPolicy, Track, digest
from .protocol import StrictProtocolModel, canonical_json_bytes


class PreparedCohortRound(StrictProtocolModel):
    schema_: Literal["umi-prepared-cohort-round/1"] = Field(alias="schema")
    roster: RecoverableRosterEvidence
    promotion_head: PromotionHeadBinding
    observation: ExecutionBoundary


def prepare_cohort_round(
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    seal: CohortIntakeSeal,
    participants: tuple[RecoverableRosterParticipant, ...],
    promotion: PromotionHeadBinding,
    observation: ExecutionBoundary,
    *,
    eligible_tracks: tuple[Track, ...],
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    expected_tip_sha256: str,
    current_block: int,
) -> PreparedCohortRound:
    """Derive the same round from original inputs even after a long outage.

    The owner supplies its first retained preparation observation and independently
    reviewed incumbent. Neither is taken from a miner or a newer promotion head on
    retry. The full consent inventory includes superseded submissions.
    """
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    seal = CohortIntakeSeal.model_validate_json(canonical_json_bytes(seal))
    promotion = PromotionHeadBinding.model_validate_json(canonical_json_bytes(promotion))
    observation = ExecutionBoundary.model_validate_json(canonical_json_bytes(observation))
    participants = tuple(
        RecoverableRosterParticipant.model_validate_json(canonical_json_bytes(p))
        for p in participants
    )
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    if view.state.phase in {"intake", "revoked"}:
        raise ValueError("round preparation requires certified intake and active authority")
    decisions: dict[str, CohortDecisionInput] = {}

    def decision(key: str) -> CohortDecisionInput:
        if key not in decisions:
            value = CohortDecisionInput.model_validate_json(
                canonical_json_bytes(decision_source(key))
            )
            if digest(value) != key:
                raise ValueError("preparation decision differs from its original identity")
            decisions[key] = value
        return decisions[key]

    state, _, _ = replay_cohort_decisions(history, policy, decision)
    if state != view.state:
        raise ValueError("preparation history differs from native decision replay")
    closing = view.closure("intake")
    if not closing.observed_at_block <= observation.block <= current_block:
        raise ValueError("preparation observation is outside the closed intake interval")
    index = next(i for i, s in enumerate(history.transitions) if s.transition == closing)
    original = history.model_copy(update={"transitions": history.transitions[:index]})
    # Stream the complete original inventory. Do not discard old consent or
    # silently construct a smaller round when one certificate is missing.
    expected = build_intake_seal(
        original,
        policy,
        seal.observation,
        seal.snapshot,
        intake_records,
        expected_tip_sha256=closing.predecessor_sha256,
    )
    if seal != expected:
        raise ValueError("preparation seal differs from the complete original intake")
    verify_intake_closure(seal, closing, decision(closing.evidence_sha256), policy)
    selected = {s.submission_sha256: s for s in seal.selected}
    members = tuple(digest(p.record.request.signed_submission.submission) for p in participants)
    if members != tuple(sorted(selected)):
        raise ValueError("preparation requires exactly every sealed participant")
    for key, participant in zip(members, participants, strict=True):
        record = participant.record
        accepted = verify_participant_admission(
            participant.admission,
            record.request.signed_submission,
            record.request.consent,
            history,
            policy,
            record.snapshot,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        if (
            digest(record) != selected[key].record_sha256
            or accepted != record.proposed_admission
            or accepted.consent_sha256 != selected[key].consent_sha256
            or record.request.signed_submission.submission.track not in eligible_tracks
        ):
            raise ValueError("prepared participant differs from certified intake selection")
    round_ = RecoverableEvaluationRound(
        schema="umi-recoverable-evaluation-round/1",
        policy_sha256=digest(policy),
        cohort_sha256=digest(history.plan),
        intake_closure_sha256=digest(closing),
        sequence=history.plan.sequence,
        suite_sha256=history.plan.suite_sha256,
        incumbent_model_sha256=promotion.model_sha256,
        runtime_sha256=policy.evaluation_runtime_sha256,
        eligible_tracks=eligible_tracks,
        participants=tuple(
            RecoverableRoundParticipant(
                submission_sha256=key, admission_sha256=digest(p.admission.admission)
            )
            for key, p in zip(members, participants, strict=True)
        ),
        prepared_at_block=observation.block,
    )
    roster = RecoverableRosterEvidence(
        schema="umi-recoverable-roster-evidence/1",
        round=round_,
        intake_seal=seal,
        participants=participants,
    )
    if view.state.phase != "preparation":
        # Recovery after preparation closed must reproduce the already certified
        # round, including its original observation and incumbent selection.
        preparation = view.closure("preparation")
        if observation.block > preparation.observed_at_block or decision(
            preparation.evidence_sha256
        ).progress.progress.phase_result_sha256 != digest(round_):
            raise ValueError("prepared round differs from certified preparation")
    return PreparedCohortRound(
        schema="umi-prepared-cohort-round/1",
        roster=roster,
        promotion_head=promotion,
        observation=observation,
    )
