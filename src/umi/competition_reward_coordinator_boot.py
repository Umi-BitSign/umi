"""Fixed native startup for standing reward coordination and peer review.

The root-owned canonical configuration selects authority and resource bounds.
Replication supplies private inputs; it supplies no executable callbacks or
verification flags. Reviewer mode never loads the control transaction key.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_host_activation import _read_root_control_path
from .competition_reward_boot import Capacity, ObjectCapacity, _disjoint
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_control_journal import RewardControlTransactionJournal
from .competition_reward_control_publisher import StandingControlPublisher
from .competition_reward_coordinator import (
    StandingRewardCoordinator,
    StandingRewardDecisionReviewer,
)
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_service import StandingRewardCoverageService
from .competition_reward_decisions import (
    RewardActivation,
    StandingRewardControlReader,
    StandingRewardSeries,
)
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_exchange import RewardReviewExchange
from .competition_reward_files import StandingRewardFiles
from .competition_reward_handoff_models import LegacyRewardHandoffPlan
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_manifest import StandingRewardOpportunityManifest, verify_reward_manifest
from .competition_reward_opportunity import opportunity_rule
from .competition_reward_preparation import StandingRewardPreparation
from .competition_reward_proof_archive import RewardProofArchive
from .competition_reward_service import StandingRewardServiceLimits, _close_provider, _stop_task
from .competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .named_hotkey import load_named_hotkey
from .open_competition import CompetitionPolicy, Hotkey, digest, identity, sign_object
from .private_files import (
    Directory,
    ensure_private_directory,
    lock_private_file,
    read_private_model,
)
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_CONFIG_BYTES = 8 * 1024**2


class RewardCoordinatorConfig(StrictProtocolModel):
    schema_: Literal["umi-reward-coordinator-config/1"] = Field(alias="schema")
    role: Literal["coordinator", "reviewer"]
    series: StandingRewardSeries
    policy: CompetitionPolicy
    manifest: StandingRewardOpportunityManifest
    chain: CompetitionChainConfig
    handoff: LegacyRewardHandoffPlan
    eligibility: RewardEligibilityRuntime
    signer_hotkey: Hotkey
    proposer_hotkey: Hotkey
    signer_key_file: Directory
    control_key_file: Directory | None = None
    state_directory: Directory
    files_directory: Directory
    readback_directory: Directory | None = None
    offer_directory: Directory | None = None
    promotion_directory: Directory
    proof_import_directory: Directory
    proof_export_directory: Directory
    exchange_inbox: Directory
    exchange_outbox: Directory
    service: StandingRewardServiceLimits
    maximum_history_bytes: Capacity
    maximum_coverage_bytes: Capacity
    maximum_reader_bytes: Capacity
    maximum_package_bytes: ObjectCapacity
    maximum_promotion_bytes: ObjectCapacity
    maximum_witness_bytes: ObjectCapacity
    maximum_header_bytes: Capacity
    maximum_header_database_bytes: Capacity

    @model_validator(mode="after")
    def bindings(self):
        verify_reward_manifest(canonical_json_bytes(self.manifest), self.series, self.policy)
        evaluators = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        signer, proposer = identity(self.signer_hotkey), identity(self.proposer_hotkey)
        coordinator = self.role == "coordinator"
        if (
            signer not in evaluators
            or proposer not in evaluators
            or (signer == proposer) != coordinator
            or len(set(evaluators.values())) < self.policy.required_evaluator_groups
            or (self.control_key_file is not None) != coordinator
            or (self.readback_directory is not None) != coordinator
            or (self.offer_directory is not None) != coordinator
            or self.chain.policy_sha256 != digest(self.policy)
            or len(self.chain.proof_rpc_fallback_urls) != 2
            or self.handoff.series_sha256 != digest(self.series)
            or self.handoff.cohort_sha256 != digest(self.series.cohorts[0])
            or self.manifest.opportunity.runtime_profile_sha256 != digest(self.eligibility)
            or self.service.mortality_period > self.series.maximum_transaction_lifetime_blocks
        ):
            raise ValueError(
                "reward coordinator configuration changes its approved role or authority"
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

    def stores(self) -> tuple[Path, ...]:
        return tuple(
            Path(value)
            for value in (
                self.state_directory,
                self.chain.state_directory,
                self.files_directory,
                self.readback_directory,
                self.offer_directory,
                self.promotion_directory,
                self.proof_import_directory,
                self.proof_export_directory,
                self.exchange_inbox,
                self.exchange_outbox,
            )
            if value is not None
        )


def load_reward_coordinator_config(path: Path) -> RewardCoordinatorConfig:
    raw = _read_root_control_path(path, MAX_CONFIG_BYTES, modes={0o444})
    config = RewardCoordinatorConfig.model_validate_json(raw)
    if canonical_json_bytes(config) != raw:
        raise ValueError("reward coordinator configuration is not canonical")
    return config


async def run_reward_coordinator(config: RewardCoordinatorConfig, stop: asyncio.Event) -> None:
    config = RewardCoordinatorConfig.model_validate_json(canonical_json_bytes(config))
    root = Path(config.state_directory) / digest(config.series)
    ensure_private_directory(root)
    descriptor = lock_private_file(root / "service.lock")
    async with AsyncExitStack() as resources:
        resources.callback(os.close, descriptor)
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
        )
        imported, exported = (
            RewardProofArchive(Path(p))
            for p in (config.proof_import_directory, config.proof_export_directory)
        )
        history = RewardControlHistoryReader(
            root / "history",
            control_hotkey=config.series.control_hotkey,
            chain_config_sha256=digest(config.chain),
            first_block=config.series.recovery.authority.issued_at_block,
            maximum_bytes=config.maximum_history_bytes,
            archive=imported,
            export_archive=exported,
        )
        store = CompetitionStore(Path(config.promotion_directory), config.policy)
        preparation = StandingRewardPreparation(
            reader,
            store,
            config.manifest,
            maximum_promotion_bytes=config.maximum_promotion_bytes,
            maximum_package_bytes=config.maximum_package_bytes,
        )
        provider = HistoricalRewardControlProvider(
            config.chain,
            config.policy,
            historical_header_directory=root / "headers",
            historical_header_maximum_bytes=config.maximum_header_bytes,
            historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
        )
        resources.push_async_callback(_close_provider, provider)
        rule = opportunity_rule(config.manifest, config.series, config.policy)
        coverage = StandingRewardCoverageService(
            provider=provider,
            history=history,
            preparation=preparation,
            files=files,
            profile=config.eligibility,
            maximum_history_blocks=config.service.maximum_history_blocks,
            journal=RewardCoverageJournal(
                root / "coverage",
                rule,
                expected_rule_sha256=digest(rule),
                maximum_bytes=config.maximum_coverage_bytes,
                archive=imported,
                export_archive=exported,
            ),
        )
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

            def offer(cohort):
                try:
                    return read_private_model(
                        Path(config.offer_directory) / (cohort + ".json"),
                        RewardActivation,
                        maximum_bytes=8192,
                    )
                except FileNotFoundError:
                    return None

            coordinator = StandingRewardCoordinator(
                reviewer=reviewer,
                publisher=publisher,
                signer=signer,
                offers=offer,
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
        # Opportunity certificates are reviewed from imported original proofs on
        # demand. Validators independently collect/export their coverage.
        await work
