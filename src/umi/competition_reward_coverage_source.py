"""Native capture and replay adapter used by the automatic coverage collector."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Callable

from .chain_evidence import FinalizedSnapshotRef
from .competition_cohort_reward_package import CohortRewardPackage
from .competition_evidence_codec import checked_digest, checked_size
from .competition_reward_control import validate_owned_reward_control
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coverage import OwnedRewardCoverageEndpoint, review_reward_coverage
from .competition_reward_coverage_capture import capture_reward_eligibility
from .competition_reward_coverage_intervals import CoverageEndpoint, CoveragePoint, coverage_point
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_prepared import (
    CoveragePackageReplayRequired,
    RetainedCoveragePackage,
)
from .competition_reward_decisions import DecisionSource
from .competition_reward_eligibility import RewardEligibilityRuntime, validate_reward_runtime_code
from .competition_reward_history import RewardControlHistoryReader, validate_control_history
from .competition_reward_opportunity import opportunity_rule
from .competition_reward_preparation import StandingRewardPreparation
from .competition_verification_snapshot import verified_package_digest
from .concurrency import run_owned_thread
from .historical_header_recovery import HistoricalHeaderRecoveryPending
from .host_memory_runtime import memory_operation, selected_memory
from .open_competition import digest, identity


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
        self.journal._credit_history = history
        self._native_credit_groups = {}
        self._completed_model_groups = {}
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
        self.runtime_selection = journal.runtime_selection
        if self.runtime_selection is not None:
            self.runtime_selection.recheck()
            if self.runtime_selection.manifest_sha256 != digest(
                preparation.manifest
            ) or self.runtime_selection.policy_sha256 != digest(reader.policy):
                raise ValueError("coverage runtime adoption differs from source authority")
        self.maximum_history_blocks = maximum_history_blocks
        self.maximum_cached_endpoints = maximum_cached_endpoints
        self._cache: OrderedDict[str, CoverageEndpoint] = OrderedDict()

    async def finalized_height(self) -> int:
        control = await self.provider.collect_control(self.history.hotkey)
        # A routine chain upgrade can change code while saved history and
        # package verdicts remain valid. Detect it at the already collected
        # native head, before starting an expensive fresh-history catch-up.
        # Keep the collector retryable; only an authenticated, qualified
        # adoption may change the selected profile. Never infer one from RPC.
        validate_owned_reward_control(
            control,
            expected_control_hotkey=self.history.hotkey,
            expected_chain_config_sha256=digest(self.provider.config),
        )
        profile = self.profile
        if self.runtime_selection is not None:
            self.runtime_selection.recheck()
            profile, _ = self.runtime_selection.selected(control.snapshot.block_number)
        validate_reward_runtime_code(control.runtime, profile)
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

    async def capture(self, validator_hotkey: str, height: int) -> CoverageEndpoint:
        try:
            # RPCs/proof executors bound their individual operations. A total
            # timer here would repeatedly discard slow immutable package replay.
            async with self._package_guard:
                return await self._capture(validator_hotkey, height)
        except HistoricalHeaderRecoveryPending:
            raise CoverageHistoryPending from None

    async def _capture(self, validator_hotkey, height):
        history = await self._history(height)
        if history.tip.block_number != height:
            raise ValueError("coverage capture history changes the requested finalized block")
        # Owned history supplies the exact immutable block identity. The private
        # checkpoint load detects lost/damaged completion metadata; it must not
        # become a routine recapture of already verified evidence. Restoration
        # rechecks policy, history, model dependencies and source generations.
        key = digest(
            {
                "series": self.journal.rule.series_sha256,
                "validator": identity(validator_hotkey),
                "block_hash": history.tip.block_hash,
            }
        )
        if await run_owned_thread(self.journal.checkpoints.load, key) is not None:
            return await self._replay(key)
        control = await self.provider.capture_control_at(self.history.hotkey, height)
        effective_profile = self.profile
        if self.runtime_selection is not None:
            effective_profile, _ = self.runtime_selection.selected(control.snapshot.block_number)
        eligibility = await capture_reward_eligibility(
            self.provider,
            control,
            validator_hotkey=validator_hotkey,
            control_hotkey=self.history.hotkey,
            profile=effective_profile,
            expected_runtime_profile_sha256=digest(effective_profile),
        )

        async def review(package):
            return await review_reward_coverage(
                self.preparation,
                package,
                eligibility=eligibility,
                history=history,
                source=self.decisions,
                expected_runtime_profile_sha256=self.journal.rule.runtime_profile_sha256,
                runtime_selection=self.runtime_selection,
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

    async def restore_credit(self, key):
        """Restore this owner's credited interval, refreshing shared native dependencies."""
        from .competition_reward_coverage_credits import (
            CoverageCreditRepairRequired,
            CreditReuseUnavailable,
            dependency_metadata_seal,
        )

        try:
            loaded = await run_owned_thread(self.journal.native_credits.load, key, self.history)
        except CreditReuseUnavailable:
            from .competition_transport_verification import TransferProgress

            with TransferProgress("coverage_credit_restore", 1, unit="intervals") as stage:
                stage.emit("waiting", reason="native_dependency_owner_upgrade_required")
            return None
        if loaded is None:
            return None
        fact, groups, snapshot = loaded
        self.preparation._authority()
        # Every skipped endpoint verdict is immutable under the captured source
        # generation and is checked by exact result identity. Group refresh only
        # amortizes the identical package/model/runtime dependencies.
        for group in groups:
            dependencies = group["dependencies"]
            expected_package = self._package_sha256
            if expected_package is None:
                expected_package = await run_owned_thread(verified_package_digest, self.package)
            if dependencies["package_sha256"] != expected_package:
                raise CoverageCreditRepairRequired("native credit selected package changed")
            group_key = digest(dependencies)
            before = await run_owned_thread(
                dependency_metadata_seal, self.preparation, dependencies
            )
            if self._native_credit_groups.get(group_key) != before:
                endpoint = await self.replay(group["endpoint"])
                if getattr(endpoint, "receipt_sha256", None) != group["verdict"]:
                    raise CoverageCreditRepairRequired("native credit group endpoint changed")
                after = await run_owned_thread(
                    dependency_metadata_seal, self.preparation, dependencies
                )
                if before != after:
                    raise CoverageCreditRepairRequired("native credit group changed during refresh")
                self._native_credit_groups[group_key] = after
        # The exact historical boundary still comes from the current native
        # history owner; neither a receipt nor a shared model group supplies it.
        for key, raw in fact["points"].items():
            point = CoveragePoint.model_validate(raw)
            if (
                point.key() != key
                or point.activation_sha256 != fact["interval"]["activation_sha256"]
            ):
                raise CoverageCreditRepairRequired("native credit point changed")
            history = await self._history(point.block)
            validate_control_history(
                history,
                first_block=self.preparation.reader.series.recovery.authority.issued_at_block,
                tip=FinalizedSnapshotRef(
                    point.block, point.block_hash, point.parent_hash, point.state_root
                ),
                control_hotkey=self.history.hotkey,
                chain_config_sha256=point.chain_config_sha256,
            )
            self.journal._runtime_profile(point, self.profile)
        await run_owned_thread(self.journal.native_credits.recheck, snapshot, self.history)
        return await run_owned_thread(self.journal.native_credits.apply, fact)

    async def replay(self, key: str) -> CoverageEndpoint:
        async with self._package_guard:
            return await self._replay(key)

    async def repair_credit(self, key, *, reason):
        """Rebind one completed credit only after both exact endpoint verdicts restore."""
        from .competition_reward_coverage_intervals import coverage_interval
        from .competition_transport_verification import TransferProgress

        if type(reason) is not str or not reason.strip() or len(reason) > 1024:
            raise ValueError("native credit repair requires an explicit bounded reason")
        hint = await self.journal.retained_interval(key)
        async with self._package_guard:
            self._native_credit_groups.clear()
            self._completed_model_groups.clear()
            # This does not repair or replace either endpoint automatically.
            # Missing/changed original endpoint facts keep their own repair hold.
            with TransferProgress(
                "coverage_credit_metadata_repair",
                1,
                unit="intervals",
                planning_unit_seconds=(1, 300),
            ) as progress:
                left, right = await self._replay(hint.left), await self._replay(hint.right)
                if coverage_interval(left, right, self.journal.rule) != hint:
                    raise ValueError("native credit repair changes its original interval")
                repaired = await self.journal.credit(left, right, credit_repair_reason=reason)
                if repaired != hint:
                    raise ValueError("native credit repair acknowledgement changed")
                progress.advance(1, restored=True)
        return dict(
            status="coverage_credit_repaired",
            interval_sha256=key,
            credited_ms=hint.credited_ms,
            original_interval_unchanged=True,
        )

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
            completed_model_groups=self._completed_model_groups,
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

    async def repair_model_transport(self, key, *, reason):
        """Repair supplementary metadata without replaying completed proofs."""
        async with self._package_guard:
            value = await run_owned_thread(self.journal.checkpoints.load, key)
            if value is None:
                raise ValueError("transport repair requires original completed coverage")
            await run_owned_thread(
                lambda: self.preparation.transport_qualifications.repair(
                    value["package_sha256"], value["cohort_sha256"], reason=reason
                )
            )
            return await self._replay(key)
