"""Native standing reward inputs selected by the installed supervisor command.

The root-owned configuration selects fixed consumers, never Python callbacks or
executable plugins. Remote delivery and archive replication populate private
stores separately; missing inputs remain pending in the native service.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_chain_resources import CompetitionChainResources
from .competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
    DirectModelSettlementVerifier,
)
from .competition_cohort_recovery import cohort_model_delivery
from .competition_host_activation import _read_root_control_path
from .competition_host_anchor import MaterializedSuccessorAnchor
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_service import StandingRewardCoverageService
from .competition_reward_decisions import (
    StandingRewardControlReader,
    StandingRewardSeries,
)
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_files import StandingRewardFiles
from .competition_reward_handoff_models import (
    LegacyRewardHandoffPlan,
    RewardHandoffPlan,
    verify_handoff_plan,
)
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_host import StandingRewardHostApproval
from .competition_reward_manifest import StandingRewardOpportunityManifest, verify_reward_manifest
from .competition_reward_opportunity import opportunity_rule
from .competition_reward_preparation import StandingRewardPreparation
from .competition_reward_proof_archive import RewardProofArchive
from .competition_reward_series_handoff import StandingRewardPredecessorOpportunity
from .competition_reward_service import StandingRewardServiceLimits, run_standing_reward_service
from .competition_store import CompetitionStore
from .competition_supervisor_adapters import ProductionSuccessorRuntimeAdapter
from .competition_supervisor_runtime import SuccessorSupervisorRuntime
from .concurrency import await_owned_task
from .open_competition import CompetitionPolicy, digest, identity
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES, Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_BOOT_BYTES = 8 * 1024**2
BOOT_FILENAME = "standing-reward-boot.json"
Capacity = Annotated[int, Field(ge=1024, le=512 * 1024**3)]
ObjectCapacity = Annotated[int, Field(ge=1024, le=MAX_CONFIGURED_PRIVATE_BYTES)]


class StandingLegacyChain(StrictProtocolModel):
    chain: CompetitionChainConfig
    resources: CompetitionChainResources

    @model_validator(mode="after")
    def bindings(self):
        self.resources.check(self.chain)
        return self


def _disjoint(paths: tuple[Path, ...]) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if left.is_relative_to(right) or right.is_relative_to(left):
                raise ValueError("standing mutable stores must be disjoint")


class StandingRewardBootConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-standing-reward-boot/1",
        "umi-standing-reward-boot/2",
        "umi-standing-reward-boot/3",
        "umi-standing-reward-boot/4",
    ] = Field(alias="schema")
    approval_path: Directory
    series: StandingRewardSeries
    policy: CompetitionPolicy
    manifest: StandingRewardOpportunityManifest
    chain: CompetitionChainConfig
    legacy_chains: Annotated[tuple[StandingLegacyChain, ...], Field(min_length=1, max_length=64)]
    legacy_policy: CompetitionPolicy
    handoff: RewardHandoffPlan
    eligibility: RewardEligibilityRuntime
    delivery_directory: Directory
    promotion_directory: Directory
    proof_import_directory: Directory
    proof_export_directory: Directory
    service: StandingRewardServiceLimits
    maximum_history_bytes: Capacity
    maximum_coverage_bytes: Capacity
    maximum_reader_bytes: Capacity
    maximum_package_bytes: ObjectCapacity
    maximum_promotion_bytes: ObjectCapacity
    maximum_witness_bytes: ObjectCapacity
    maximum_header_bytes: Capacity
    maximum_header_database_bytes: Capacity
    direct_model_review: DirectModelReviewSourceConfig | None = None
    predecessor_series: StandingRewardSeries | None = None
    predecessor_manifest: StandingRewardOpportunityManifest | None = None
    predecessor_eligibility: RewardEligibilityRuntime | None = None
    predecessor_approval_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def omit_successor_inputs(self, handler):
        value = handler(self)
        for name in (
            "direct_model_review",
            "predecessor_series",
            "predecessor_manifest",
            "predecessor_eligibility",
            "predecessor_approval_sha256",
        ):
            if getattr(self, name) is None:
                value.pop(name, None)
        return value

    @model_validator(mode="after")
    def bindings(self):
        verify_reward_manifest(canonical_json_bytes(self.manifest), self.series, self.policy)
        direct_selected = any(
            cohort_model_delivery(plan).mechanism == "direct_r2_multipart_v1"
            for plan in self.series.cohorts
            if plan.eligible_tracks is None or "model" in plan.eligible_tracks
        )
        successor = self.series.predecessor is not None
        predecessor_inputs = (
            self.predecessor_series,
            self.predecessor_manifest,
            self.predecessor_eligibility,
        )
        if (
            (self.schema_ in {"umi-standing-reward-boot/2", "umi-standing-reward-boot/4"})
            != direct_selected
            or (self.schema_ in {"umi-standing-reward-boot/3", "umi-standing-reward-boot/4"})
            != successor
            or direct_selected != (self.direct_model_review is not None)
            or successor != all(value is not None for value in predecessor_inputs)
            or successor != (self.predecessor_approval_sha256 is not None)
            or self.manifest.opportunity.runtime_profile_sha256 != digest(self.eligibility)
            or len(self.chain.proof_rpc_fallback_urls) != 2
            or self.service.mortality_period > self.series.maximum_transaction_lifetime_blocks
            or self.chain.policy_sha256 != digest(self.policy)
            or any(c.chain.policy_sha256 != digest(self.legacy_policy) for c in self.legacy_chains)
            or len({digest(c.chain) for c in self.legacy_chains}) != len(self.legacy_chains)
            or digest(self.chain) in {digest(c.chain) for c in self.legacy_chains}
        ):
            raise ValueError("standing boot inputs disagree with selected authority")
        verify_handoff_plan(self.handoff, self.series)
        if not successor and (
            type(self.handoff) is not LegacyRewardHandoffPlan
            or self.handoff.legacy_policy_sha256 != digest(self.legacy_policy)
        ):
            raise ValueError("standing boot legacy handoff changes its policy")
        if successor:
            prior = self.series.predecessor
            old, manifest, eligibility = predecessor_inputs
            assert prior is not None and old is not None and manifest is not None
            assert eligibility is not None
            verify_reward_manifest(canonical_json_bytes(manifest), old, self.policy)
            if (
                digest(old) != prior.series_sha256
                or old.policy_sha256 != prior.policy_sha256
                or old.manifest_sha256 != prior.manifest_sha256
                or digest(old.recovery) != prior.recovery_sha256
                or identity(old.control_hotkey) != identity(prior.control_hotkey)
                or not any(
                    digest(plan) == prior.cohort_sha256 and plan.sequence == prior.cohort_sequence
                    for plan in old.cohorts
                )
                or manifest.opportunity.runtime_profile_sha256 != digest(eligibility)
            ):
                raise ValueError("standing boot predecessor differs from its series boundary")
        _disjoint(self.mutable_stores())
        return self

    def mutable_stores(self) -> tuple[Path, ...]:
        return tuple(
            Path(p)
            for p in (
                self.chain.state_directory,
                self.delivery_directory,
                self.promotion_directory,
                self.proof_import_directory,
                self.proof_export_directory,
                *(c.resources.state_directory for c in self.legacy_chains),
                *(
                    (self.direct_model_review.r2_credentials_file,)
                    if self.direct_model_review
                    else ()
                ),
            )
        )


def load_standing_boot(path: Path, anchor: MaterializedSuccessorAnchor) -> StandingRewardBootConfig:
    """Validate root inputs and their existing installation before stopping it."""
    raw = _read_root_control_path(path, MAX_BOOT_BYTES, modes={0o444})
    value = StandingRewardBootConfig.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("standing boot configuration is not canonical")
    approval_raw = _read_root_control_path(Path(value.approval_path), 8192, modes={0o444})
    approval = StandingRewardHostApproval.model_validate_json(approval_raw)
    successor = value.series.predecessor is not None
    expected = StandingRewardHostApproval(
        schema=(
            "umi-standing-reward-host-approval/2"
            if successor
            else "umi-standing-reward-host-approval/1"
        ),
        source_config_sha256=digest(anchor.config),
        installation_receipt_sha256=anchor.receipt_sha256,
        host_manifest_sha256=anchor.receipt.host_manifest_sha256,
        validator_hotkey=anchor.config.validator_hotkey,
        series_sha256=digest(value.series),
        policy_sha256=digest(value.policy),
        manifest_sha256=digest(value.manifest),
        chain_config_sha256=digest(value.chain),
        legacy_handoff_plan_sha256=None if successor else digest(value.handoff),
        standing_handoff_plan_sha256=digest(value.handoff) if successor else None,
        predecessor_approval_sha256=value.predecessor_approval_sha256,
    )
    if canonical_json_bytes(approval) != approval_raw or approval != expected:
        raise ValueError("standing boot inputs differ from approved installation")
    if identity(anchor.config.validator_hotkey) not in {
        identity(k) for k in value.series.validators
    }:
        raise ValueError("standing boot validator is absent from the approved series")
    if successor:
        old = value.predecessor_series
        assert old is not None
        was_predecessor = identity(anchor.config.validator_hotkey) in {
            identity(k) for k in old.validators
        }
        if not was_predecessor or value.predecessor_approval_sha256 is None:
            raise ValueError("standing boot local predecessor authority is incomplete")
    _disjoint((*value.mutable_stores(), Path(anchor.config.state_root) / "standing-rewards"))
    return value


def select_standing_boot(
    supervisor_config: Path,
    anchor: MaterializedSuccessorAnchor,
    *,
    explicit_path: Path | None = None,
) -> StandingRewardBootConfig | None:
    """Select a root-approved sibling without replacing the installed command.

    Only an absent default means legacy operation. A missing explicit selection,
    dangling link, unreadable file or invalid approval must fail before startup
    stops the existing worker. lstat avoids treating a dangling link as absence.
    """
    path = explicit_path or supervisor_config.with_name(BOOT_FILENAME)
    if explicit_path is None:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
    return load_standing_boot(path, anchor)


async def _close_provider(provider):
    await await_owned_task(asyncio.create_task(provider.aclose()))


async def run_installed_standing_rewards(
    runtime: SuccessorSupervisorRuntime, config: StandingRewardBootConfig, stop: asyncio.Event
) -> None:
    """Construct fixed native readers inside the original runtime's live lease."""
    runtime._require_lease()
    if type(runtime.adapter) is not ProductionSuccessorRuntimeAdapter:
        raise TypeError("standing boot requires the original native runtime adapter")
    config = StandingRewardBootConfig.model_validate_json(canonical_json_bytes(config))
    root = Path(runtime.config.state_root) / "standing-rewards" / digest(config.series)
    files = StandingRewardFiles(
        Path(config.delivery_directory),
        maximum_package_bytes=config.maximum_package_bytes,
        maximum_witness_bytes=config.maximum_witness_bytes,
    )
    reader = StandingRewardControlReader(
        root / "control",
        config.series,
        config.policy,
        expected_series_sha256=digest(config.series),
        expected_chain_config_sha256=digest(config.chain),
        maximum_bytes=config.maximum_reader_bytes,
    )
    store = CompetitionStore(Path(config.promotion_directory), config.policy)
    model_artifacts = (
        None
        if config.direct_model_review is None
        else DirectModelSettlementVerifier(
            DirectModelArtifactReviewer(config.direct_model_review, config.policy, None),
            store.directory / "model-reward-artifacts",
            root / "direct-model-reward-receipts",
        )
    )
    preparation = StandingRewardPreparation(
        reader,
        store,
        config.manifest,
        maximum_promotion_bytes=config.maximum_promotion_bytes,
        maximum_package_bytes=config.maximum_package_bytes,
        model_artifacts=model_artifacts,
    )
    imported = RewardProofArchive(Path(config.proof_import_directory))
    exported = RewardProofArchive(Path(config.proof_export_directory))
    history = RewardControlHistoryReader(
        root / "history",
        control_hotkey=config.series.control_hotkey,
        chain_config_sha256=digest(config.chain),
        first_block=config.series.recovery.authority.issued_at_block,
        maximum_bytes=config.maximum_history_bytes,
        archive=imported,
        export_archive=exported,
    )
    coverage = RewardCoverageJournal(
        root / "coverage",
        opportunity_rule(config.manifest, config.series, config.policy),
        expected_rule_sha256=digest(
            opportunity_rule(config.manifest, config.series, config.policy)
        ),
        maximum_bytes=config.maximum_coverage_bytes,
        archive=imported,
        export_archive=exported,
    )
    async with AsyncExitStack() as constructing:
        providers = {}
        for chain, policy, locations in (
            (config.chain, config.policy, CompetitionChainResources.from_config(config.chain)),
            *((c.chain, config.legacy_policy, c.resources) for c in config.legacy_chains),
        ):
            sha = digest(chain)
            provider = HistoricalRewardControlProvider(
                chain,
                policy,
                resources=locations,
                historical_header_directory=root / "headers" / sha,
                historical_header_maximum_bytes=config.maximum_header_bytes,
                historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
            )
            # Constructors own cache locks. Close earlier owners if any later
            # constructor fails before the native service takes responsibility.
            providers[sha] = provider
            constructing.push_async_callback(_close_provider, provider)
        current = providers[digest(config.chain)]
        collection = StandingRewardCoverageService(
            provider=current,
            journal=coverage,
            history=history,
            preparation=preparation,
            files=files,
            profile=config.eligibility,
            maximum_history_blocks=config.service.maximum_history_blocks,
        )
        predecessor = None
        predecessor_coverage = None
        if config.predecessor_series is not None:
            old = config.predecessor_series
            old_root = Path(runtime.config.state_root) / "standing-rewards" / digest(old)
            old_reader = StandingRewardControlReader(
                old_root / "control",
                old,
                config.policy,
                expected_series_sha256=digest(old),
                expected_chain_config_sha256=digest(config.chain),
                maximum_bytes=config.maximum_reader_bytes,
            )
            old_history = RewardControlHistoryReader(
                old_root / "history",
                control_hotkey=old.control_hotkey,
                chain_config_sha256=digest(config.chain),
                first_block=old.recovery.authority.issued_at_block,
                maximum_bytes=config.maximum_history_bytes,
                archive=imported,
                export_archive=exported,
            )
            old_preparation = StandingRewardPreparation(
                old_reader,
                store,
                config.predecessor_manifest,
                maximum_promotion_bytes=config.maximum_promotion_bytes,
                maximum_package_bytes=config.maximum_package_bytes,
            )
            old_rule = opportunity_rule(config.predecessor_manifest, old, config.policy)
            predecessor_coverage = StandingRewardCoverageService(
                provider=current,
                journal=RewardCoverageJournal(
                    old_root / "coverage",
                    old_rule,
                    expected_rule_sha256=digest(old_rule),
                    maximum_bytes=config.maximum_coverage_bytes,
                    archive=imported,
                    export_archive=exported,
                ),
                history=old_history,
                preparation=old_preparation,
                files=files,
                profile=config.predecessor_eligibility,
                maximum_history_blocks=config.service.maximum_history_blocks,
            )
            predecessor = StandingRewardPredecessorOpportunity(
                successor=config.series,
                plan=config.handoff,
                coverage=predecessor_coverage,
            )

        def signer():
            from .named_hotkey import load_named_hotkey

            wallet = runtime.config.wallet
            return load_named_hotkey(
                Path(wallet.path) / wallet.name / "hotkeys" / wallet.hotkey,
                runtime.config.validator_hotkey,
            )

        # Keep constructor cleanup until invocation is entered; native provider
        # close is idempotent, so cancellation cannot leave an ownership gap.
        await run_standing_reward_service(
            runtime,
            approval_path=Path(config.approval_path),
            preparation=preparation,
            plan=config.handoff,
            provider=current,
            legacy_providers={
                digest(c.chain): providers[digest(c.chain)] for c in config.legacy_chains
            },
            history=history,
            packages=files.package,
            decisions=files.decision,
            opportunity=collection.opportunity,
            coverage=collection,
            load_signer=signer,
            stop=stop,
            limits=config.service,
            predecessor_series=config.predecessor_series,
            predecessor=predecessor,
            predecessor_coverage=predecessor_coverage,
            predecessor_approval_sha256=config.predecessor_approval_sha256,
        )
