"""Bind replayed allocations to the existing quorum-certified cohort phases."""

from __future__ import annotations

from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    replay_cohort_decisions,
)
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_model_award import build_model_award
from .competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    build_reward_allocation,
)
from .open_competition import digest
from .protocol import canonical_json_bytes


def replay_reward_allocation(
    allocation,
    promotion_store,
    service,
    service_review,
    benchmark,
    benchmark_review,
    *,
    maximum_promotion_bytes,
) -> CohortRewardAllocation:
    """Replay fixed historical attribution and full native score certificates.

    A caller cannot grant authority by passing these bytes. Certification and
    current standing control are verified separately.
    """
    allocation = CohortRewardAllocation.model_validate_json(canonical_json_bytes(allocation))
    if digest(promotion_store.policy) != digest(service_review.policy):
        raise ValueError("promotion history belongs to another policy")
    model_award = None
    if allocation.model_award is not None:
        model_award = build_model_award(
            benchmark,
            benchmark_review,
            allocation.model_award.acceptances,
            promotion_store.directory / "model-reward-artifacts",
        )
        promotion = None
    else:
        promotion = promotion_store.reviewed_promotion_at(
            allocation.round_sha256,
            allocation.promotion_head.promotion_sha256,
            maximum_bytes=maximum_promotion_bytes,
        )
    expected = build_reward_allocation(
        service, service_review, benchmark, benchmark_review, promotion, model_award=model_award
    )
    if allocation != expected:
        raise ValueError("reward allocation differs from independently replayed evidence")
    return expected


def reward_certification_progress(
    journal,
    promotion_store,
    service,
    service_review,
    benchmark,
    benchmark_review,
    history,
    decision_source,
    *,
    expected_tip_sha256,
    current_block,
    maximum_promotion_bytes,
) -> CohortPhaseProgress:
    """Review the owner's immutable allocation before requesting progress votes.

    Use the existing phase signer/controller to retain and certify this exact
    progress. The host supplies independently authenticated history/finality.
    No second reward-vote protocol or time-based certificate renewal is needed.
    """
    view = verify_cohort_history(
        history,
        service_review.policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    replay_cohort_decisions(history, service_review.policy, decision_source)
    if (
        view.state.phase != "certification"
        or view.state.cohort_sha256 != benchmark_review.roster.round.cohort_sha256
    ):
        raise ValueError("reward certification is not the current cohort phase")
    raw = journal.get("cohort_reward_allocation", service_review.slot)
    if raw is None:
        raise FileNotFoundError("reward certification lacks the owner's retained allocation")
    allocation = replay_reward_allocation(
        raw,
        promotion_store,
        service,
        service_review,
        benchmark,
        benchmark_review,
        maximum_promotion_bytes=maximum_promotion_bytes,
    )
    return CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=view.state.cohort_sha256,
        recovery_tip_sha256=view.state.tip_sha256,
        phase="certification",
        observed_at_block=current_block,
        unavailable_blocks=0,
        completion="complete",
        phase_result_sha256=digest(allocation),
        evidence_sha256=digest(allocation),
    )


def verify_certified_reward_allocation(
    allocation,
    promotion_store,
    service,
    service_review,
    benchmark,
    benchmark_review,
    history,
    decision_source,
    *,
    expected_tip_sha256,
    current_block,
    maximum_promotion_bytes,
) -> CohortRewardAllocation:
    """Consume original certification arbitrarily late under selected authority.

    Full source replay remains required. A quorum result digest alone is not a
    score, attribution or current chain permission. First admission and standing
    control still own transaction freshness, replacement and reconciliation.
    """
    view = verify_cohort_history(
        history,
        service_review.policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    replay_cohort_decisions(history, service_review.policy, decision_source)
    if (
        view.state.phase == "revoked"
        or view.state.cohort_sha256 != benchmark_review.roster.round.cohort_sha256
    ):
        raise ValueError("reward certification authority is revoked or belongs to another cohort")
    allocation = replay_reward_allocation(
        allocation,
        promotion_store,
        service,
        service_review,
        benchmark,
        benchmark_review,
        maximum_promotion_bytes=maximum_promotion_bytes,
    )
    closed = view.closure("certification")
    decision = CohortDecisionInput.model_validate_json(
        canonical_json_bytes(decision_source(closed.evidence_sha256))
    )
    progress = decision.progress.progress
    if (
        digest(decision) != closed.evidence_sha256
        or progress.completion != "complete"
        or progress.phase_result_sha256 != digest(allocation)
        or progress.evidence_sha256 != digest(allocation)
    ):
        raise ValueError("certification must bind this exact replayed reward allocation")
    return allocation
