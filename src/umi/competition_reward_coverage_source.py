"""Native capture and replay adapter used by the automatic coverage collector."""

from __future__ import annotations

from collections import OrderedDict

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_evidence_codec import checked_size
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coverage import OwnedRewardCoverageEndpoint, review_reward_coverage
from .competition_reward_coverage_capture import capture_reward_eligibility
from .competition_reward_coverage_intervals import coverage_point
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_decisions import DecisionSource
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_opportunity import opportunity_rule
from .competition_reward_preparation import StandingRewardPreparation
from .historical_header_recovery import HistoricalHeaderRecoveryPending
from .open_competition import digest


class CoverageHistoryPending(Exception):
    """A bounded pass preserved progress but has not reached the requested block."""


class NativeRewardCoverageSource:
    def __init__(
        self,
        *,
        provider: HistoricalRewardControlProvider,
        journal: RewardCoverageJournal,
        history: RewardControlHistoryReader,
        preparation: StandingRewardPreparation,
        package: CohortRewardPackage,
        decisions: DecisionSource,
        profile: RewardEligibilityRuntime,
        maximum_history_blocks: int = 64,
        maximum_cached_endpoints: int = 16,
    ):
        checked_size(maximum_history_blocks, 4096)
        checked_size(maximum_cached_endpoints, 512)
        reader = preparation.reader
        if (
            journal.rule != opportunity_rule(preparation.manifest, reader.series, reader.policy)
            or journal.rule.runtime_profile_sha256 != digest(profile)
            or history.hotkey != reader.series.control_hotkey
            or history.config_sha256 != digest(provider.config)
            or digest(provider.policy) != digest(reader.policy)
        ):
            raise ValueError("coverage source differs from selected native context")
        self.provider, self.journal, self.history = provider, journal, history
        self.preparation, self.package, self.decisions = preparation, package, decisions
        self.profile = profile
        self.maximum_history_blocks = maximum_history_blocks
        self.maximum_cached_endpoints = maximum_cached_endpoints
        self._cache: OrderedDict[str, OwnedRewardCoverageEndpoint] = OrderedDict()

    async def finalized_height(self) -> int:
        control = await self.provider.collect_control(self.history.hotkey)
        return control.snapshot.block_number

    async def _history(self, height):
        try:
            return await self.history.verified_prefix(height)
        except ValueError:
            progress = await self.history.advance(
                self.provider, through_block=height, maximum_blocks=self.maximum_history_blocks
            )
            if progress.history is None:
                raise CoverageHistoryPending from None
            return progress.history

    def _remember(self, endpoint):
        key = coverage_point(endpoint, self.journal.rule).key()
        self._cache[key] = endpoint
        self._cache.move_to_end(key)
        while len(self._cache) > self.maximum_cached_endpoints:
            self._cache.popitem(last=False)
        return endpoint

    async def capture(self, validator_hotkey: str, height: int) -> OwnedRewardCoverageEndpoint:
        try:
            # RPCs/proof executors bound their individual operations. A total
            # timer here would repeatedly discard slow immutable package replay.
            return await self._capture(validator_hotkey, height)
        except HistoricalHeaderRecoveryPending:
            raise CoverageHistoryPending from None

    async def _capture(self, validator_hotkey, height):
        history = await self._history(height)
        control = await self.provider.capture_control_at(self.history.hotkey, height)
        eligibility = await capture_reward_eligibility(
            self.provider,
            control,
            validator_hotkey=validator_hotkey,
            control_hotkey=self.history.hotkey,
            profile=self.profile,
            expected_runtime_profile_sha256=self.journal.rule.runtime_profile_sha256,
        )
        return self._remember(
            await review_reward_coverage(
                self.preparation,
                self.package,
                eligibility=eligibility,
                history=history,
                source=self.decisions,
                expected_runtime_profile_sha256=self.journal.rule.runtime_profile_sha256,
            )
        )

    async def replay(self, key: str) -> OwnedRewardCoverageEndpoint:
        return await self._replay(key)

    async def _replay(self, key):
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        point = await self.journal.retained_point(key)
        history = await self._history(point.block)
        return self._remember(
            await self.journal.review_endpoint(
                key,
                provider=self.provider,
                preparation=self.preparation,
                package=self.package,
                history=history,
                source=self.decisions,
                profile=self.profile,
            )
        )
