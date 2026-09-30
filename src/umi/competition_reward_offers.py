"""Derive proposals from completed settlement output and retained opportunity.

These are discovery inputs. The coordinator still replays their original native
evidence before retaining a decision or asking any evaluator to sign it.
"""

from pathlib import Path

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_coordinator import Prefix
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_service import CoverageCompletion
from .competition_reward_decisions import (
    RewardActivation,
    StandingRewardSeries,
    verify_reward_decisions,
)
from .competition_reward_files import StandingRewardFiles
from .competition_reward_handoff_models import LegacyRewardHandoffPlan
from .competition_reward_manifest import StandingRewardOpportunityManifest, verify_reward_manifest
from .competition_reward_opportunity import (
    RewardOpportunityCertificate,
    check_opportunity_claim,
    opportunity_rule,
)
from .open_competition import CompetitionPolicy, digest
from .private_files import private_path, read_private_model
from .protocol import canonical_json_bytes


class StandingRewardOffers:
    """Consume the next cohort's package; no operator-authored activation file."""

    def __init__(
        self,
        *,
        series: StandingRewardSeries,
        policy: CompetitionPolicy,
        manifest: StandingRewardOpportunityManifest,
        handoff: LegacyRewardHandoffPlan,
        settlements: Path,
        files: StandingRewardFiles,
        coverage: RewardCoverageJournal,
    ):
        verify_reward_manifest(canonical_json_bytes(manifest), series, policy)
        if (
            handoff.series_sha256 != digest(series)
            or handoff.cohort_sha256 != digest(series.cohorts[0])
            or coverage.rule != opportunity_rule(manifest, series, policy)
        ):
            raise ValueError("reward offer sources differ from the approved series")
        self.series, self.policy, self.manifest = series, policy, manifest
        self.handoff, self.files, self.coverage = handoff, files, coverage
        self.settlements = Path(private_path(str(settlements)))

    def __call__(self, cohort: str, prefix: Prefix) -> RewardActivation | None:
        prefix = verify_reward_decisions(self.series, self.policy, prefix)
        index = len(prefix) - 1
        if (
            not 0 <= index < len(self.series.cohorts)
            or prefix[-1].decision.kind == "revoke"
            or cohort != digest(self.series.cohorts[index])
        ):
            raise ValueError("reward offer must extend the next admitted cohort")
        # Completion is small and may take hours. Check it before reparsing a
        # potentially large settlement package on each pending poll.
        prior = digest(self.handoff)
        if index:
            predecessor = prefix[-1].decision.activation
            assert predecessor is not None
            raw = self.coverage.journal.get("coverage_completion", predecessor.cohort_sha256)
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
            package = read_private_model(
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
            package_sha256=digest(package),
            recovery_tip_sha256=digest(tip),
            prior_opportunity_sha256=prior,
        )
