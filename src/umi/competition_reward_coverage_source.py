"""Native capture and replay adapter used by the automatic coverage collector."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Callable

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_evidence_codec import checked_digest, checked_size
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coverage import OwnedRewardCoverageEndpoint, review_reward_coverage
from .competition_reward_coverage_capture import capture_reward_eligibility
from .competition_reward_coverage_intervals import CoverageEndpoint, coverage_point
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_prepared import (
    CoveragePackageReplayRequired,
    RetainedCoveragePackage,
)
from .competition_reward_decisions import DecisionSource
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_opportunity import opportunity_rule
from .competition_reward_preparation import StandingRewardPreparation
from .competition_verification_snapshot import verified_package_digest
from .concurrency import run_owned_thread
from .historical_header_recovery import HistoricalHeaderRecoveryPending
from .host_memory_runtime import memory_operation, selected_memory
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
        package: CohortRewardPackage | None = None,
        package_loader: Callable[[], CohortRewardPackage] | None = None,
        package_sha256: str | None = None,
        package_guard: asyncio.Lock | None = None,
        decisions: DecisionSource,
        profile: RewardEligibilityRuntime,
        maximum_history_blocks: int = 64,
        maximum_cached_endpoints: int = 16,
    ):
        checked_size(maximum_history_blocks, 4096)
        checked_size(maximum_cached_endpoints, 512)
        if selected_memory() is not None and package is not None:
            raise ValueError("host-admitted coverage requires a lazy private package loader")
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
        if (package is None) == (package_loader is None):
            raise ValueError(
                "coverage source selects exactly one package or private package loader"
            )
        if package_loader is not None:
            checked_digest(package_sha256)
        elif package_sha256 is not None:
            raise ValueError("eager coverage source does not take a package loader identity")
        self.preparation, self.package, self.decisions = preparation, package, decisions
        self._package_loader, self._package_sha256 = package_loader, package_sha256
        self._retained_package = None
        self._package_guard = package_guard if package_guard is not None else asyncio.Lock()
        self.profile = profile
        self.maximum_history_blocks = maximum_history_blocks
        self.maximum_cached_endpoints = maximum_cached_endpoints
        self._cache: OrderedDict[str, CoverageEndpoint] = OrderedDict()

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
            async with self._package_guard:
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

        async def review(package):
            return await review_reward_coverage(
                self.preparation,
                package,
                eligibility=eligibility,
                history=history,
                source=self.decisions,
                expected_runtime_profile_sha256=self.journal.rule.runtime_profile_sha256,
            )

        return self._remember(await self._with_package(review))

    @memory_operation
    async def _with_package(self, review):
        if self._package_loader is None:
            return await review(self.package)
        if self._retained_package is not None:
            try:
                return await review(self._retained_package)
            except CoveragePackageReplayRequired:
                pass
        package = await run_owned_thread(self._package_loader)
        if await run_owned_thread(verified_package_digest, package) != self._package_sha256:
            raise ValueError("coverage package loader changed the selected original")
        endpoint = await review(package)
        if type(endpoint) is OwnedRewardCoverageEndpoint:
            self._retained_package = RetainedCoveragePackage(endpoint.prepared)
        return endpoint

    async def replay(self, key: str) -> CoverageEndpoint:
        async with self._package_guard:
            return await self._replay(key)

    async def repair(self, key: str, *, reason: str):
        """Explicitly requalify one restored original after dependency damage."""
        async with self._package_guard:
            self._cache.pop(key, None)

            async def review(package):
                return await self.journal.review_endpoint(
                    key,
                    provider=self.provider,
                    preparation=self.preparation,
                    package=package,
                    history=None,
                    history_source=self._history,
                    source=self.decisions,
                    profile=self.profile,
                    repair_reason=reason,
                )

            return self._remember(await self._with_package(review))

    async def _replay(self, key):
        # A process-local endpoint cannot outlive damaged durable sources or a
        # changed authority. Compact restoration rechecks those dependencies
        # without reading payloads or repeating successful native verification.
        expected = self._package_sha256
        if expected is None:
            expected = await run_owned_thread(verified_package_digest, self.package)
        restored = await self.journal.restore_endpoint(
            key,
            provider=self.provider,
            preparation=self.preparation,
            expected_package_sha256=expected,
            history=None,
            history_source=self._history,
            profile=self.profile,
        )
        if restored is not None:
            cached = self._cache.get(key)
            return self._remember(cached if cached == restored else restored)

        async def review(package):
            return await self.journal.review_endpoint(
                key,
                provider=self.provider,
                preparation=self.preparation,
                package=package,
                history=None,
                history_source=self._history,
                source=self.decisions,
                profile=self.profile,
            )

        return self._remember(await self._with_package(review))
