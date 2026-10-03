"""Native pre-signing review of standing admission and reward activation.

Original chain proofs, packages and opportunity archives belong to their
durable owners. This result binds their replay to one immutable decision. It
does not grant authority to commit control or submit weights on the chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import Field

from .competition_cohort_model_award import ModelArtifactVerifier
from .competition_cohort_reward_package import (
    DEFAULT_PACKAGE_BYTES,
    CohortRewardPackage,
    replay_reward_package,
)
from .competition_reward_control_archive import (
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .competition_reward_decisions import (
    RewardControlDecision,
    SignedRewardControlDecision,
    StandingRewardControlReader,
    verify_reward_decision_proposal,
    verify_reward_decisions,
)
from .competition_reward_handoff_models import (
    LegacyRewardHandoffPlan,
    RewardHandoffPlan,
    StandingRewardHandoffPlan,
    verify_handoff_plan,
)
from .competition_reward_history import OwnedRewardControlHistory, validate_control_history
from .competition_reward_manifest import (
    StandingRewardOpportunityManifest,
    verify_reward_manifest,
)
from .competition_reward_opportunity import (
    VerifiedRewardOpportunity,
    check_opportunity_claim,
    validate_opportunity,
)
from .competition_reward_series_handoff import (
    VerifiedStandingPredecessorOpportunity,
    validate_standing_predecessor_opportunity,
)
from .competition_store import CompetitionStore
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ISSUER = object()


class RewardDecisionIntent(StrictProtocolModel):
    schema_: Literal["umi-reward-decision-intent/1"] = Field(alias="schema")
    decision: RewardControlDecision
    manifest_sha256: Hex32
    control_evidence_sha256: Hex32
    control_metadata_sha256: Hex32
    control_history_sha256: Hex32
    chain_config_sha256: Hex32


@dataclass(frozen=True, slots=True)
class ReviewedRewardDecision:
    intent: RewardDecisionIntent
    preceding: tuple[SignedRewardControlDecision, ...]
    chain_submission_authorized: Literal[False] = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: ReviewedRewardDecision) -> str:
    return digest([digest(value.intent), [digest(v) for v in value.preceding]])


def validate_reward_decision_review(value: ReviewedRewardDecision) -> RewardDecisionIntent:
    if (
        type(value) is not ReviewedRewardDecision
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.chain_submission_authorized is not False
    ):
        raise ValueError("reward decision lacks native pre-signing review")
    return value.intent


def review_reward_decision(
    reader: StandingRewardControlReader,
    manifest: StandingRewardOpportunityManifest,
    preceding: tuple[SignedRewardControlDecision, ...],
    decision: RewardControlDecision,
    *,
    control: OwnedHistoricalRewardControl,
    history: OwnedRewardControlHistory,
    package: CohortRewardPackage | None = None,
    promotion_store: CompetitionStore | None = None,
    approved_handoff: RewardHandoffPlan | None = None,
    previous_opportunity: (
        VerifiedRewardOpportunity | VerifiedStandingPredecessorOpportunity | None
    ) = None,
    maximum_promotion_bytes: int,
    maximum_package_bytes: int = DEFAULT_PACKAGE_BYTES,
    verify_model_artifact: ModelArtifactVerifier | None = None,
) -> ReviewedRewardDecision:
    """Replay at the proposal's original finalized block; elapsed time is irrelevant.

    The caller supplies the independently approved handoff plan for the first
    activation. Each validator still fences its own legacy writer at execution.
    Revocation requires a separate explicit policy action, never a liveness retry.
    """
    series, policy = reader.series, reader.policy
    if digest(series) != reader.series_sha256:
        raise ValueError("reward reader's independently selected series changed")
    manifest = verify_reward_manifest(canonical_json_bytes(manifest), series, policy)
    if not isinstance(manifest, StandingRewardOpportunityManifest):
        raise ValueError("reward signing requires approved opportunity terms")
    prefix = verify_reward_decisions(series, policy, preceding) if preceding else ()
    decision = verify_reward_decision_proposal(series, policy, prefix, decision)
    validate_historical_reward_control(
        control,
        expected_control_hotkey=series.control_hotkey,
        expected_chain_config_sha256=reader.admission_chain_config_sha256,
    )
    validate_control_history(
        history,
        first_block=series.recovery.authority.issued_at_block,
        tip=control.snapshot,
        control_hotkey=series.control_hotkey,
        chain_config_sha256=reader.admission_chain_config_sha256,
    )
    if decision.observed_at_block != control.snapshot.block_number:
        raise ValueError("reward proposal differs from its original finalized observation")
    if decision.kind == "revoke":
        raise ValueError("automatic reward signing cannot infer revocation")
    if not prefix:
        predecessor = (
            None if series.predecessor is None else series.predecessor.decision_sha256
        )
        if (
            history.unresolved_blocks
            or history.writes
            or control.control_sha256 != predecessor
        ):
            raise ValueError("series admission requires its exact predecessor control history")
    else:
        objects = {digest(v.decision): canonical_json_bytes(v) for v in prefix}
        selected = reader.review_history(control, objects.__getitem__, history)
        if selected.selection.decision_sha256 != decision.predecessor_sha256:
            raise ValueError("reward proposal does not extend the proved control predecessor")
        activation = decision.activation
        assert activation is not None
        if decision.sequence == 1:
            if approved_handoff is None:
                raise ValueError("first reward activation lacks its approved handoff")
            plan = verify_handoff_plan(approved_handoff, series)
            if type(plan) is LegacyRewardHandoffPlan:
                if digest(plan) != activation.prior_opportunity_sha256:
                    raise ValueError(
                        "first reward activation differs from the approved legacy handoff"
                    )
            else:
                assert type(plan) is StandingRewardHandoffPlan
                validate_standing_predecessor_opportunity(
                    previous_opportunity,
                    plan=plan,
                    activation=activation,
                    block=decision.observed_at_block,
                )
        else:
            certificate = validate_opportunity(previous_opportunity)
            prior = prefix[-1].decision.activation
            assert prior is not None
            check_opportunity_claim(
                certificate, manifest=manifest, series=series, policy=policy, activation=prior
            )
            if (
                digest(certificate) != activation.prior_opportunity_sha256
                or max(c.through_block for c in certificate.contributions)
                > decision.observed_at_block
            ):
                raise ValueError(
                    "reward proposal changes prior opportunity or backdates its cutoff"
                )
        if package is None or promotion_store is None:
            raise ValueError("reward activation requires native package and model replay")
        requirement = manifest.requirement(activation.cohort_sha256)
        if digest(package.inputs.history.authority.authority) != digest(series.recovery.authority):
            raise ValueError("reward package changes the approved standing authority")
        allocation = replay_reward_package(
            package,
            policy,
            promotion_store,
            package.inputs.history,
            expected_package_sha256=activation.package_sha256,
            expected_cohort_sha256=activation.cohort_sha256,
            expected_tip_sha256=activation.recovery_tip_sha256,
            current_block=decision.observed_at_block,
            expected_terms_sha256=requirement.terms_sha256,
            expected_catalog_sha256s=requirement.catalog_sha256s,
            maximum_promotion_bytes=maximum_promotion_bytes,
            maximum_bytes=maximum_package_bytes,
            verify_model_artifact=verify_model_artifact,
        )
        if digest(allocation) != activation.allocation_sha256:
            raise ValueError("reward proposal allocation differs from native package replay")
    intent = RewardDecisionIntent(
        schema="umi-reward-decision-intent/1",
        decision=decision,
        manifest_sha256=digest(manifest),
        control_evidence_sha256=control.evidence_sha256,
        control_metadata_sha256=control.metadata_sha256,
        control_history_sha256=history.evidence_sha256,
        chain_config_sha256=history.chain_config_sha256,
    )
    result = ReviewedRewardDecision(intent, prefix, _issuer=_ISSUER)
    object.__setattr__(result, "_binding", _binding(result))
    return result
