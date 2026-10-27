"""Derive proposals from completed settlement output and retained opportunity.

These are discovery inputs. The coordinator still replays their original native
evidence before retaining a decision or asking any evaluator to sign it.
"""

import logging
from pathlib import Path

from .competition_cohort_recovery import GeometricModelRewardCohortAuthority
from .competition_cohort_reward_package import CohortRewardPackage
from .competition_geometric_rewards import GeometricRewardParameters
from .competition_reward_adoption import RewardAdoptionSelection, verify_adoption_selection
from .competition_reward_coordinator import Prefix
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_service import CoverageCompletion, coverage_work_key
from .competition_reward_decisions import (
    RewardActivation,
    StandingRewardSeries,
    effective_activation_decision,
    verify_reward_decisions,
)
from .competition_reward_files import StandingRewardFiles
from .competition_reward_handoff_models import (
    RewardHandoffPlan,
    StandingRewardHandoffPlan,
    verify_handoff_plan,
)
from .competition_reward_manifest import StandingRewardOpportunityManifest, verify_reward_manifest
from .competition_reward_opportunity import (
    RewardOpportunityCertificate,
    check_opportunity_claim,
    opportunity_rule,
)
from .competition_reward_series_handoff import StandingRewardPredecessorOpportunity
from .competition_verification_snapshot import verified_package_digest
from .open_competition import CompetitionPolicy, digest
from .private_files import private_path
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)
_C5_MODEL_REWARD_PARAMETERS = GeometricRewardParameters(
    band_width_bps=250,
    band_decay_bps=7500,
    within_band_decay_bps=7500,
    score_duplicate_tolerance_bps=1,
)


def successor_reward_rule_ready(plan, authority, adoption) -> bool:
    """Gate C6+ offers on the intended C5 economics, without changing signed inputs."""
    if plan.sequence < 6:
        return True
    if adoption is not None:
        return adoption.adoption.parameters == _C5_MODEL_REWARD_PARAMETERS
    if isinstance(authority, GeometricModelRewardCohortAuthority):
        return authority.model_reward_parameters == _C5_MODEL_REWARD_PARAMETERS
    return False


class StandingRewardOffers:
    """Consume the next cohort's package; no operator-authored activation file."""

    def __init__(
        self,
        *,
        series: StandingRewardSeries,
        policy: CompetitionPolicy,
        manifest: StandingRewardOpportunityManifest,
        handoff: RewardHandoffPlan,
        settlements: Path,
        files: StandingRewardFiles,
        coverage: RewardCoverageJournal,
        predecessor: StandingRewardPredecessorOpportunity | None = None,
        reward_adoptions: RewardAdoptionSelection | None = None,
    ):
        verify_reward_manifest(canonical_json_bytes(manifest), series, policy)
        handoff = verify_handoff_plan(handoff, series)
        standing = type(handoff) is StandingRewardHandoffPlan
        if coverage.rule != opportunity_rule(manifest, series, policy) or standing != (
            predecessor is not None
        ):
            raise ValueError("reward offer sources differ from the approved series")
        self.series, self.policy, self.manifest = series, policy, manifest
        self.handoff, self.files, self.coverage = handoff, files, coverage
        self.predecessor = predecessor
        self.reward_adoptions = verify_adoption_selection(reward_adoptions, series, policy)
        self.settlements = Path(private_path(str(settlements)))
        self.packages = files.package_store
        self._reported_missing_successor_adoptions: set[str] = set()
        self.pending_reason: str | None = None

    def __call__(self, cohort: str, prefix: Prefix) -> RewardActivation | None:
        self.pending_reason = None
        prefix = verify_reward_decisions(
            self.series, self.policy, prefix, reward_adoptions=self.reward_adoptions
        )
        index = sum(v.decision.kind == "activate" for v in prefix)
        if (
            not 0 <= index < len(self.series.cohorts)
            or prefix[-1].decision.kind == "revoke"
            or cohort != digest(self.series.cohorts[index])
        ):
            raise ValueError("reward offer must extend the next admitted cohort")
        adoption = None if self.reward_adoptions is None else self.reward_adoptions.latest(cohort)
        if not successor_reward_rule_ready(
            self.series.cohorts[index], self.series.recovery.authority, adoption
        ):
            self.pending_reason = "reward_adoption_pending"
            if cohort not in self._reported_missing_successor_adoptions:
                logger.warning(
                    "reward_offer_waiting_for_c5_style_economics cohort_sha256=%s",
                    cohort,
                )
                self._reported_missing_successor_adoptions.add(cohort)
            return None
        # Completion is small and may take hours. Check it before reparsing a
        # potentially large settlement package on its first preparation.
        prior = digest(self.handoff)
        if not index and type(self.handoff) is StandingRewardHandoffPlan:
            prior = self.predecessor.certificate_sha256()
            if prior is None:
                return None
        if index:
            predecessor = effective_activation_decision(prefix).activation
            assert predecessor is not None
            raw = self.coverage.journal.get("coverage_completion", coverage_work_key(predecessor))
            if raw is None:
                return None
            prior = CoverageCompletion.model_validate(raw).certificate_sha256
            certificate = self.files.certificate(prior)
            check_opportunity_claim(
                RewardOpportunityCertificate.model_validate_json(certificate),
                manifest=self.manifest,
                series=self.series,
                policy=self.policy,
                activation=predecessor,
            )
        try:
            package = self.packages.load(
                self.settlements / (cohort + ".json"),
                CohortRewardPackage,
                maximum_bytes=self.files.maximum_package_bytes,
            )
        except FileNotFoundError:
            return None
        history = package.inputs.history
        requirement = self.manifest.requirement(cohort)
        if (
            history.plan != self.series.cohorts[index]
            or package.policy_sha256 != digest(self.policy)
            or digest(history.authority.authority) != digest(self.series.recovery.authority)
            or digest(package.inputs.terms) != requirement.terms_sha256
            or tuple(digest(c.catalog) for c in package.inputs.catalogs)
            != requirement.catalog_sha256s
        ):
            raise ValueError("settlement package differs from the approved cohort inputs")
        # Retain content before exposing a proposal. A lost acknowledgement
        # repeats exact immutable publication; it cannot reserve a signing slot.
        self.files.retain_package(package)
        tip = history.transitions[-1].transition if history.transitions else history.genesis
        return RewardActivation(
            cohort_sha256=cohort,
            allocation_sha256=digest(package.allocation),
            package_sha256=verified_package_digest(package),
            recovery_tip_sha256=digest(tip),
            prior_opportunity_sha256=prior,
            reward_adoption_sha256=None if adoption is None else digest(adoption.adoption),
            effective_allocation_sha256=None
            if adoption is None
            else adoption.adoption.effective_allocation_sha256,
        )
