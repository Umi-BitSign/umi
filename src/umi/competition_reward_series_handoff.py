"""Native predecessor-opportunity replay for a standing-series successor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .competition_reward_coverage_service import (
    CoverageCompletion,
    StandingRewardCoverageService,
)
from .competition_reward_decisions import RewardActivation, SignedRewardControlDecision
from .competition_reward_handoff_models import (
    StandingRewardHandoffPlan,
    verify_handoff_plan,
)
from .competition_reward_opportunity import (
    RewardOpportunityCertificate,
    VerifiedRewardOpportunity,
    check_opportunity_claim,
    validate_opportunity,
)
from .open_competition import digest, identity

_ISSUER = object()


@dataclass(frozen=True, slots=True)
class VerifiedStandingPredecessorOpportunity:
    """Process-local result of replaying the predecessor's exact opportunity."""

    plan_sha256: str
    predecessor_activation_sha256: str
    successor_activation_sha256: str
    certificate: RewardOpportunityCertificate
    through_block: int
    chain_submission_authorized: Literal[False] = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: VerifiedStandingPredecessorOpportunity) -> str:
    return digest(
        {
            "plan_sha256": value.plan_sha256,
            "predecessor_activation_sha256": value.predecessor_activation_sha256,
            "successor_activation_sha256": value.successor_activation_sha256,
            "certificate_sha256": digest(value.certificate),
            "through_block": value.through_block,
        }
    )


def validate_standing_predecessor_opportunity(
    value,
    *,
    plan: StandingRewardHandoffPlan,
    activation: RewardActivation,
    block: int,
) -> RewardOpportunityCertificate:
    if (
        type(value) is not VerifiedStandingPredecessorOpportunity
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.chain_submission_authorized is not False
        or value.plan_sha256 != digest(plan)
        or value.predecessor_activation_sha256 != plan.predecessor.activation_sha256
        or value.successor_activation_sha256 != digest(activation)
        or digest(value.certificate) != activation.prior_opportunity_sha256
        or type(block) is not int
        or block < value.through_block
    ):
        raise ValueError("standing successor lacks its replayed predecessor opportunity")
    return value.certificate


class StandingRewardPredecessorOpportunity:
    """Discover and replay the exact completion selected by a successor series."""

    def __init__(self, *, successor, plan, coverage: StandingRewardCoverageService):
        if type(coverage) is not StandingRewardCoverageService:
            raise TypeError("standing predecessor requires the native coverage owner")
        plan = verify_handoff_plan(plan, successor)
        if type(plan) is not StandingRewardHandoffPlan:
            raise ValueError("standing predecessor requires a successor handoff")
        reader = coverage.preparation.reader
        prior = plan.predecessor
        if (
            digest(reader.series) != prior.series_sha256
            or digest(reader.policy) != prior.policy_sha256
            or digest(coverage.preparation.manifest) != prior.manifest_sha256
            or digest(reader.series.recovery) != prior.recovery_sha256
            or identity(reader.series.control_hotkey) != identity(prior.control_hotkey)
            or prior.cohort_sha256 not in {digest(c) for c in reader.series.cohorts}
        ):
            raise ValueError("standing predecessor owner differs from the signed boundary")
        self.successor, self.plan, self.coverage = successor, plan, coverage

    def _activation(self) -> RewardActivation:
        reader, prior = self.coverage.preparation.reader, self.plan.predecessor
        index = tuple(digest(c) for c in reader.series.cohorts).index(prior.cohort_sha256)
        retained = reader.journal.get("reward_control_decision", f"{index + 1:04d}")
        if retained is None:
            raise ValueError("predecessor reward selection is not retained")
        decision = SignedRewardControlDecision.model_validate(retained).decision
        activation = decision.activation
        if (
            decision.kind != "activate"
            or digest(decision) != prior.decision_sha256
            or activation is None
            or digest(activation) != prior.activation_sha256
            or activation.cohort_sha256 != prior.cohort_sha256
        ):
            raise ValueError("predecessor reward selection differs from the signed boundary")
        return activation

    def certificate_sha256(self) -> str | None:
        """Return a discovery hint only after static certificate checks."""
        activation = self._activation()
        retained = self.coverage.journal.journal.get(
            "coverage_completion", activation.cohort_sha256
        )
        if retained is None:
            return None
        completion = CoverageCompletion.model_validate(retained)
        certificate = RewardOpportunityCertificate.model_validate_json(
            self.coverage.files.certificate(completion.certificate_sha256)
        )
        check_opportunity_claim(
            certificate,
            manifest=self.coverage.preparation.manifest,
            series=self.coverage.preparation.reader.series,
            policy=self.coverage.preparation.reader.policy,
            activation=activation,
        )
        if digest(certificate) != completion.certificate_sha256:
            raise ValueError("predecessor completion differs from its certificate")
        return completion.certificate_sha256

    async def review(
        self, activation: RewardActivation, *, observed_at_block: int
    ) -> VerifiedStandingPredecessorOpportunity:
        predecessor = self._activation()
        verified: VerifiedRewardOpportunity = await self.coverage.completed_opportunity(
            predecessor
        )
        certificate = validate_opportunity(verified)
        check_opportunity_claim(
            certificate,
            manifest=self.coverage.preparation.manifest,
            series=self.coverage.preparation.reader.series,
            policy=self.coverage.preparation.reader.policy,
            activation=predecessor,
        )
        through = max(c.through_block for c in certificate.contributions)
        if (
            digest(certificate) != activation.prior_opportunity_sha256
            or through > observed_at_block
        ):
            raise ValueError("successor activation differs from the predecessor opportunity")
        value = VerifiedStandingPredecessorOpportunity(
            digest(self.plan),
            digest(predecessor),
            digest(activation),
            certificate,
            through,
            _issuer=_ISSUER,
        )
        object.__setattr__(value, "_binding", _binding(value))
        validate_standing_predecessor_opportunity(
            value,
            plan=self.plan,
            activation=activation,
            block=observed_at_block,
        )
        return value
