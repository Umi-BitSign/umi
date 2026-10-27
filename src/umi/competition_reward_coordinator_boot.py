"""Fixed native startup for standing reward coordination and peer review.

The root-owned canonical configuration selects authority and resource bounds.
Replication supplies private inputs; it supplies no executable callbacks or
verification flags. Reviewer mode never loads the control transaction key.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_cohort_capacity import AggregateEvidenceCapacity
from .competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
    DirectModelSettlementVerifier,
)
from .competition_cohort_legacy_model_selection import (
    LegacyModelStorageSelections,
    authenticate_legacy_model_sources,
    selected_legacy_model_readers,
    validate_legacy_model_selections,
)
from .competition_cohort_model_transport_selection import (
    ModelDeliveryAdoptionSelections,
    requires_direct_model_review,
    selected_direct_model_review,
)
from .competition_history_forecast import DEFAULT_HISTORY_FORECAST_BYTES, select_history_forecasts
from .competition_host_activation import _read_root_control_path
from .competition_model_byte_store import shared_byte_store_paths, validate_shared_byte_stores
from .competition_proof_archive_selection import selected_proof_archives
from .competition_remote_proof_store import ProofArchiveStores
from .competition_reward_adoption import RewardAdoptionSelection, verify_adoption_selection
from .competition_reward_boot import Capacity, HistoryCapacity, ObjectCapacity, _disjoint
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_control_journal import RewardControlTransactionJournal
from .competition_reward_control_publisher import StandingControlPublisher
from .competition_reward_coordinator import (
    StandingRewardCoordinator,
    StandingRewardDecisionReviewer,
)
from .competition_reward_coordinator_ownership import owned_reward_state
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_service import StandingRewardCoverageService
from .competition_reward_decisions import (
    StandingRewardControlReader,
    StandingRewardSeries,
)
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_exchange import RewardReviewExchange
from .competition_reward_files import StandingRewardFiles
from .competition_reward_handoff_models import RewardHandoffPlan, verify_handoff_plan
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_manifest import StandingRewardOpportunityManifest, verify_reward_manifest
from .competition_reward_offers import StandingRewardOffers
from .competition_reward_opportunity import opportunity_rule
from .competition_reward_preparation import StandingRewardPreparation
from .competition_reward_revision import NativeRewardRevisionReviewer
from .competition_reward_runtime_adoption import RewardRuntimeAdoptionSelection, select_boot_runtime
from .competition_reward_series_handoff import StandingRewardPredecessorOpportunity
from .competition_reward_service import StandingRewardServiceLimits, _close_provider, _stop_task
from .competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .host_memory_runtime import HostMemoryAdmissionSelection, memory_runtime
from .named_hotkey import load_named_hotkey
from .open_competition import CompetitionPolicy, Hotkey, digest, identity, sign_object
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_CONFIG_BYTES = 8 * 1024**2


class RewardCoordinatorConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-reward-coordinator-config/1",
        "umi-reward-coordinator-config/2",
        "umi-reward-coordinator-config/3",
        "umi-reward-coordinator-config/4",
    ] = Field(alias="schema")
    role: Literal["coordinator", "reviewer"]
    series: StandingRewardSeries
    policy: CompetitionPolicy
    manifest: StandingRewardOpportunityManifest
    chain: CompetitionChainConfig
    handoff: RewardHandoffPlan
    eligibility: RewardEligibilityRuntime
    signer_hotkey: Hotkey
    proposer_hotkey: Hotkey
    signer_key_file: Directory
    control_key_file: Directory | None = None
    state_directory: Directory
    files_directory: Directory
    readback_directory: Directory | None = None
    settlement_directory: Directory | None = None
    promotion_directory: Directory
    proof_import_directory: Directory
    proof_stores: ProofArchiveStores | None = None
    proof_export_directory: Directory
    exchange_inbox: Directory
    exchange_outbox: Directory
    service: StandingRewardServiceLimits
    maximum_history_bytes: HistoryCapacity
    maximum_coverage_bytes: Capacity
    maximum_reader_bytes: Capacity
    maximum_package_bytes: AggregateEvidenceCapacity
    maximum_promotion_bytes: ObjectCapacity
    maximum_witness_bytes: ObjectCapacity
    maximum_header_bytes: Capacity
    maximum_header_database_bytes: Capacity
    forecast_accounting_bytes: Annotated[int, Field(ge=64 * 1024, le=1024**3)] = (
        DEFAULT_HISTORY_FORECAST_BYTES
    )
    runtime_proof_reads: bool = False
    direct_model_review: DirectModelReviewSourceConfig | None = None
    model_delivery_adoptions: ModelDeliveryAdoptionSelections = ()
    legacy_model_storage: LegacyModelStorageSelections = ()
    predecessor_series: StandingRewardSeries | None = None
    predecessor_manifest: StandingRewardOpportunityManifest | None = None
    predecessor_eligibility: RewardEligibilityRuntime | None = None
    reward_adoptions: RewardAdoptionSelection | None = None
    predecessor_reward_adoptions: RewardAdoptionSelection | None = None
    runtime_adoptions: RewardRuntimeAdoptionSelection | None = None
    predecessor_runtime_adoptions: RewardRuntimeAdoptionSelection | None = None

    host_memory_admission: HostMemoryAdmissionSelection | None = None

    @model_serializer(mode="wrap")
    def omit_direct_model_review(self, handler):
        value = handler(self)
        if self.forecast_accounting_bytes == DEFAULT_HISTORY_FORECAST_BYTES:
            value.pop("forecast_accounting_bytes", None)
        if self.proof_stores is None:
            value.pop("proof_stores", None)
        if self.host_memory_admission is None:
            value.pop("host_memory_admission", None)
        for name in (
            "direct_model_review",
            "predecessor_series",
            "predecessor_manifest",
            "predecessor_eligibility",
            "reward_adoptions",
            "predecessor_reward_adoptions",
            "runtime_adoptions",
            "predecessor_runtime_adoptions",
        ):
            if getattr(self, name) is None:
                value.pop(name, None)
        if not self.runtime_proof_reads:
            value.pop("runtime_proof_reads", None)
        if not self.model_delivery_adoptions:
            value.pop("model_delivery_adoptions", None)
        if not self.legacy_model_storage:
            value.pop("legacy_model_storage", None)
        return value

    @model_validator(mode="after")
    def bindings(self):
        verify_reward_manifest(canonical_json_bytes(self.manifest), self.series, self.policy)
        validate_legacy_model_selections(
            self.legacy_model_storage,
            series=self.series,
            policy=self.policy,
            model_delivery_adoptions=self.model_delivery_adoptions,
        )
        direct = self.direct_model_review
        if (
            self.legacy_model_storage
            and direct is not None
            and direct.materialization_boot_disk_cache is not None
        ):
            _disjoint(
                (
                    Path(direct.materialization_boot_disk_cache.directory),
                    *(Path(source.directory) for source in self.legacy_model_storage),
                )
            )
        direct_selected = requires_direct_model_review(
            self.series, self.policy, self.model_delivery_adoptions
        )
        evaluators = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        signer, proposer = identity(self.signer_hotkey), identity(self.proposer_hotkey)
        coordinator = self.role == "coordinator"
        successor = self.series.predecessor is not None
        predecessor_inputs = (
            self.predecessor_series,
            self.predecessor_manifest,
            self.predecessor_eligibility,
        )
        if (
            (self.schema_ in {"umi-reward-coordinator-config/2", "umi-reward-coordinator-config/4"})
            != direct_selected
            or (
                self.schema_
                in {"umi-reward-coordinator-config/3", "umi-reward-coordinator-config/4"}
            )
            != successor
            or direct_selected != (self.direct_model_review is not None)
            or successor != all(value is not None for value in predecessor_inputs)
            or (not successor and any(value is not None for value in predecessor_inputs))
            or signer not in evaluators
            or proposer not in evaluators
            or (signer == proposer) != coordinator
            or len(set(evaluators.values())) < self.policy.required_evaluator_groups
            or (self.control_key_file is not None) != coordinator
            or (self.readback_directory is not None) != coordinator
            or (self.settlement_directory is not None) != coordinator
            or self.chain.policy_sha256 != digest(self.policy)
            or len(self.chain.proof_rpc_fallback_urls) != 2
            or self.manifest.opportunity.runtime_profile_sha256 != digest(self.eligibility)
            or self.service.mortality_period > self.series.maximum_transaction_lifetime_blocks
        ):
            raise ValueError(
                "reward coordinator configuration changes its approved role or authority"
            )
        verify_handoff_plan(self.handoff, self.series)
        verify_adoption_selection(self.reward_adoptions, self.series, self.policy)
        select_boot_runtime(self)
        select_boot_runtime(self, predecessor=True)
        if self.predecessor_reward_adoptions is not None:
            if self.predecessor_series is None:
                raise ValueError("predecessor reward adoption requires its original series")
            verify_adoption_selection(
                self.predecessor_reward_adoptions, self.predecessor_series, self.policy
            )
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
                raise ValueError("reward coordinator predecessor differs from its series boundary")
        validate_shared_byte_stores(
            self.legacy_model_storage,
            (
                *self.stores(include_shared=False),
                *(p for p in (self.signer_key_file, self.control_key_file) if p is not None),
                *(
                    (direct.materialization_boot_disk_cache.directory,)
                    if direct is not None and direct.materialization_boot_disk_cache is not None
                    else ()
                ),
            ),
        )
        _disjoint(self.stores())
        for value in (self.signer_key_file, self.control_key_file):
            if value is not None:
                key = Path(value)
                if any(
                    key.is_relative_to(root) or root.is_relative_to(key) for root in self.stores()
                ):
                    raise ValueError("reward keys must be outside mutable and replicated stores")
        return self

    def stores(self, *, include_shared=True) -> tuple[Path, ...]:
        return tuple(
            Path(value)
            for value in (
                self.state_directory,
                self.chain.state_directory,
                self.files_directory,
                self.readback_directory,
                self.settlement_directory,
                self.promotion_directory,
                self.proof_import_directory,
                *(self.proof_stores.credential_paths() if self.proof_stores else ()),
                self.proof_export_directory,
                self.exchange_inbox,
                self.exchange_outbox,
                *(self.direct_model_review.stores() if self.direct_model_review else ()),
                *(source.directory for source in self.legacy_model_storage),
                *(shared_byte_store_paths(self.legacy_model_storage) if include_shared else ()),
            )
            if value is not None
        )


def load_reward_coordinator_config(path: Path) -> RewardCoordinatorConfig:
    raw = _read_root_control_path(path, MAX_CONFIG_BYTES, modes={0o444})
    config = RewardCoordinatorConfig.model_validate_json(raw)
    if canonical_json_bytes(config) != raw:
        raise ValueError("reward coordinator configuration is not canonical")
    return config


async def run_reward_coordinator(
    config: RewardCoordinatorConfig, stop: asyncio.Event, *, credit_repair=None
):
    config = RewardCoordinatorConfig.model_validate_json(canonical_json_bytes(config))
    if credit_repair is not None:
        from .competition_evidence_codec import checked_digest

        checked_digest(credit_repair["key"])
        reason = credit_repair["reason"]
        selected_history = credit_repair.get("history", "current")
        if (
            type(reason) is not str
            or not reason.strip()
            or len(reason) > 1024
            or selected_history not in {"current", "predecessor"}
            or (selected_history == "predecessor" and config.predecessor_series is None)
        ):
            raise ValueError("credit repair requires its configured owner and bounded reason")
    legacy_sources = await run_owned_thread(
        lambda: authenticate_legacy_model_sources(
            config.legacy_model_storage,
            series=config.series,
            policy=config.policy,
            model_delivery_adoptions=config.model_delivery_adoptions,
            original_verification_directory=Path(config.state_directory)
            / digest(config.series)
            / "legacy-original-verification",
        )
    )
    async with AsyncExitStack() as resources:
        root = resources.enter_context(owned_reward_state(config))
        resources.enter_context(
            memory_runtime(
                config.host_memory_admission,
                maximum_aggregate_bytes=config.maximum_package_bytes,
                role="reward_coordinator",
            )
        )
        files = StandingRewardFiles(
            Path(config.files_directory),
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
            reward_adoptions=config.reward_adoptions,
        )
        imported, exported = await run_owned_thread(
            selected_proof_archives,
            Path(config.proof_import_directory),
            Path(config.proof_export_directory),
            config.proof_stores,
        )
        history = RewardControlHistoryReader(
            root / "history",
            control_hotkey=config.series.control_hotkey,
            chain_config_sha256=digest(config.chain),
            first_block=config.series.recovery.authority.issued_at_block,
            maximum_bytes=config.maximum_history_bytes,
            verification_profile=config.service.history_verification,
            archive=imported,
            export_archive=exported,
            shutdown_event=stop,
        )
        select_history_forecasts(
            history, root=root, config=config, resources=resources, role=config.role
        )
        store = CompetitionStore(Path(config.promotion_directory), config.policy)
        direct_artifacts = (
            None
            if selected_direct_model_review(config) is None
            else DirectModelArtifactReviewer(
                config.direct_model_review,
                config.policy,
                None,
                verification_root=root / "direct-model-byte-verification",
            )
        )
        model_artifacts = (
            None
            if direct_artifacts is None
            else DirectModelSettlementVerifier(
                direct_artifacts,
                store.directory / "model-reward-artifacts",
                root / "direct-model-reward-receipts",
                legacy_readers=selected_legacy_model_readers(
                    legacy_sources,
                    multipart=direct_artifacts.multipart,
                    verification_root=root / "legacy-model-byte-verification",
                ),
            )
        )
        preparation = StandingRewardPreparation(
            reader,
            store,
            config.manifest,
            maximum_promotion_bytes=config.maximum_promotion_bytes,
            maximum_package_bytes=config.maximum_package_bytes,
            model_artifacts=model_artifacts,
            model_delivery_adoptions=config.model_delivery_adoptions,
            allocation_sink=files.retain_allocation,
        )
        provider = HistoricalRewardControlProvider(
            config.chain,
            config.policy,
            runtime_proof_reads=config.runtime_proof_reads,
            historical_header_directory=root / "headers",
            historical_header_maximum_bytes=config.maximum_header_bytes,
            historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
        )
        resources.push_async_callback(_close_provider, provider)
        rule = opportunity_rule(config.manifest, config.series, config.policy)
        coverage_package_guard = asyncio.Lock()
        coverage = StandingRewardCoverageService(
            provider=provider,
            history=history,
            preparation=preparation,
            files=files,
            profile=config.eligibility,
            maximum_history_blocks=config.service.maximum_history_blocks,
            package_guard=coverage_package_guard,
            journal=RewardCoverageJournal(
                root / "coverage",
                rule,
                expected_rule_sha256=digest(rule),
                maximum_bytes=config.maximum_coverage_bytes,
                archive=imported,
                export_archive=exported,
                runtime_selection=select_boot_runtime(config),
            ),
        )
        predecessor = None
        predecessor_coverage = None
        if config.predecessor_series is not None:
            old = config.predecessor_series
            old_root = Path(config.state_directory) / digest(old)
            old_reader = StandingRewardControlReader(
                old_root / "control",
                old,
                config.policy,
                expected_series_sha256=digest(old),
                expected_chain_config_sha256=digest(config.chain),
                maximum_bytes=config.maximum_reader_bytes,
                reward_adoptions=config.predecessor_reward_adoptions,
            )
            old_history = RewardControlHistoryReader(
                old_root / "history",
                control_hotkey=old.control_hotkey,
                chain_config_sha256=digest(config.chain),
                first_block=old.recovery.authority.issued_at_block,
                maximum_bytes=config.maximum_history_bytes,
                verification_profile=config.service.history_verification,
                archive=imported,
                export_archive=exported,
                shutdown_event=stop,
            )
            select_history_forecasts(
                old_history,
                root=old_root,
                config=config,
                resources=resources,
                role=config.role,
                predecessor=True,
            )
            old_preparation = StandingRewardPreparation(
                old_reader,
                store,
                config.predecessor_manifest,
                maximum_promotion_bytes=config.maximum_promotion_bytes,
                maximum_package_bytes=config.maximum_package_bytes,
                allocation_sink=files.retain_allocation,
            )
            old_rule = opportunity_rule(config.predecessor_manifest, old, config.policy)
            predecessor_coverage = StandingRewardCoverageService(
                provider=provider,
                history=old_history,
                preparation=old_preparation,
                files=files,
                profile=config.predecessor_eligibility,
                maximum_history_blocks=config.service.maximum_history_blocks,
                package_guard=coverage_package_guard,
                journal=RewardCoverageJournal(
                    old_root / "coverage",
                    old_rule,
                    expected_rule_sha256=digest(old_rule),
                    maximum_bytes=config.maximum_coverage_bytes,
                    archive=imported,
                    export_archive=exported,
                    runtime_selection=select_boot_runtime(config, predecessor=True),
                ),
            )
            predecessor = StandingRewardPredecessorOpportunity(
                successor=config.series,
                plan=config.handoff,
                coverage=predecessor_coverage,
            )
        if credit_repair is not None:
            # Original state lease, native configuration and provider are owned;
            # no signer, control publisher or autonomous collector is created.
            selection = dict(credit_repair)
            selected_history = selection.pop("history", "current")
            selected_coverage = coverage if selected_history == "current" else predecessor_coverage
            if selected_history not in {"current", "predecessor"} or selected_coverage is None:
                raise ValueError("credit repair requires its configured history owner")
            await provider.start()
            return await selected_coverage.repair_credit(stop=stop, **selection)
        key = await run_owned_thread(
            load_named_hotkey, Path(config.signer_key_file), config.signer_hotkey
        )

        async def sign(body):
            return await run_owned_thread(sign_object, body, key)

        signer = RewardDecisionSigner(
            RewardDecisionJournal(
                root / "decisions",
                config.series,
                config.policy,
                config.signer_hotkey,
                expected_chain_config_sha256=digest(config.chain),
                maximum_bytes=config.service.maximum_journal_bytes,
                reward_adoptions=config.reward_adoptions,
            ),
            sign,
        )
        reviewer = StandingRewardDecisionReviewer(
            reader=reader,
            provider=provider,
            history=history,
            files=files,
            manifest=config.manifest,
            promotion_store=store,
            handoff=config.handoff,
            opportunity=coverage.opportunity,
            maximum_promotion_bytes=config.maximum_promotion_bytes,
            maximum_history_blocks=config.service.maximum_history_blocks,
            model_artifacts=model_artifacts,
            predecessor=predecessor,
            revision_reviewer=(
                NativeRewardRevisionReviewer(coverage=coverage)
                if config.reward_adoptions is not None
                else None
            ),
        )
        exchange = RewardReviewExchange(
            signer=signer,
            proposer=config.proposer_hotkey,
            inbox=Path(config.exchange_inbox),
            outbox=Path(config.exchange_outbox),
        )
        if config.role == "coordinator":
            control = await run_owned_thread(
                load_named_hotkey,
                Path(config.control_key_file),
                config.series.control_hotkey,
            )
            publisher = StandingControlPublisher(
                reader=reader,
                provider=provider,
                history=history,
                files=files,
                signer=control,
                journal=RewardControlTransactionJournal(
                    root / "transactions",
                    config.series,
                    config_sha256=digest(config.chain),
                    maximum_bytes=config.service.maximum_journal_bytes,
                ),
                mortality_period=config.service.mortality_period,
                maximum_history_blocks=config.service.maximum_history_blocks,
                submission_timeout_seconds=config.service.submission_timeout_seconds,
            )

            coordinator = StandingRewardCoordinator(
                reviewer=reviewer,
                publisher=publisher,
                signer=signer,
                offers=StandingRewardOffers(
                    series=config.series,
                    policy=config.policy,
                    manifest=config.manifest,
                    handoff=config.handoff,
                    settlements=Path(config.settlement_directory),
                    files=files,
                    coverage=coverage.journal,
                    predecessor=predecessor,
                    reward_adoptions=config.reward_adoptions,
                ),
                readback=StandingRewardFiles(
                    Path(config.readback_directory),
                    maximum_package_bytes=config.maximum_package_bytes,
                    maximum_witness_bytes=config.maximum_witness_bytes,
                ),
                voters=tuple(
                    exchange.vote_port(e.hotkey)
                    for e in config.policy.evaluators
                    if identity(e.hotkey) != identity(config.signer_hotkey)
                ),
            )
            run = coordinator.run
        else:

            async def run(stop, *, poll_seconds):
                await exchange.run_reviewer(reviewer, stop, poll_seconds=poll_seconds)

        await provider.start()
        work = asyncio.create_task(run(stop, poll_seconds=config.service.poll_seconds))
        resources.push_async_callback(_stop_task, work)
        # Both roles keep their native history and opportunity evidence ready
        # while waiting for work. Otherwise a reviewer would start a full
        # historical replay only after the coordinator requests its first vote.
        # The reviewer still never loads the control transaction key.
        collectors = [
            asyncio.create_task(coverage.run(stop, poll_seconds=config.service.poll_seconds))
        ]
        if predecessor_coverage is not None:
            collectors.append(
                asyncio.create_task(
                    predecessor_coverage.run(stop, poll_seconds=config.service.poll_seconds)
                )
            )
        for collector in collectors:
            resources.push_async_callback(_stop_task, collector)
        done, _ = await asyncio.wait((work, *collectors), return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if not stop.is_set():
            raise RuntimeError("reward coordinator component exited before shutdown")
