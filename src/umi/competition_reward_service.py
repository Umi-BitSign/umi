"""Service lifecycle for standing rewards under the original supervisor lease.

The installed bootstrap supplies native, already verified inputs. This owner
starts proof providers, holds the C4 handoff through executor shutdown, and
closes providers before returning to the supervisor. It never creates approval
or substitutes serialized flags for preparation, handoff or opportunity proofs.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack, suppress
from pathlib import Path
from typing import Annotated

from pydantic import Field, model_validator

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_decisions import DecisionSource, RewardActivation
from .competition_reward_executor import StandingRewardExecutor
from .competition_reward_handoff import hold_legacy_reward_handoff
from .competition_reward_handoff_models import LegacyRewardHandoffPlan
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_host import (
    bind_standing_reward_host,
    check_standing_reward_host_selection,
)
from .competition_reward_opportunity import VerifiedRewardOpportunity
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .competition_supervisor_runtime import SuccessorSupervisorRuntime
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import digest
from .protocol import StrictProtocolModel

logger = logging.getLogger(__name__)


class StandingRewardServiceLimits(StrictProtocolModel):
    """Host capacities and individual-operation bounds, never cohort deadlines."""

    maximum_journal_bytes: Annotated[int, Field(ge=1024, le=512 * 1024**3)]
    mortality_period: Annotated[int, Field(ge=4, le=4096)]
    maximum_history_blocks: Annotated[int, Field(ge=1, le=4096)] = 64
    submission_timeout_seconds: Annotated[float, Field(gt=0, le=3600)] = 120
    poll_seconds: Annotated[float, Field(gt=0, le=3600)] = 12

    @model_validator(mode="after")
    def mortal_period(self):
        if self.mortality_period & (self.mortality_period - 1):
            raise ValueError("standing mortality period must be a power of two")
        return self


async def _close_provider(provider):
    # Repeated SIGINT/task cancellation must not abandon a live finality child.
    await await_owned_task(asyncio.create_task(provider.aclose()))


async def run_standing_reward_service(
    runtime: SuccessorSupervisorRuntime,
    *,
    approval_path: Path,
    preparation: StandingRewardPreparation,
    first: PreparedStandingReward,
    plan: LegacyRewardHandoffPlan,
    provider: HistoricalRewardControlProvider,
    legacy_providers: Mapping[str, HistoricalRewardControlProvider],
    history: RewardControlHistoryReader,
    packages: Callable[[str], CohortRewardPackage],
    decisions: DecisionSource,
    opportunity: Callable[[RewardActivation], Awaitable[VerifiedRewardOpportunity]],
    load_signer: Callable,
    stop: asyncio.Event,
    limits: StandingRewardServiceLimits,
) -> None:
    """Own the passed providers until stopped; preserve journals on every retry.

    Call inside the installed runtime's async context, with its native adapter.
    The bootstrap must load the first native preparation again on restart and
    retain its original historical authority even when a successor is current.
    Content callbacks cannot grant submission authority. No production timing
    policy is inferred from the per-operation retry interval.
    """
    owners = {id(value): value for value in (provider, *legacy_providers.values())}
    if any(not isinstance(value, HistoricalRewardControlProvider) for value in owners.values()):
        raise TypeError("standing service requires native proof providers")
    async with AsyncExitStack() as resources:
        # Register every owner before the first start, including providers whose
        # constructors acquired private cache locks but whose start can fail.
        for value in owners.values():
            resources.push_async_callback(_close_provider, value)
        limits = StandingRewardServiceLimits.model_validate(limits.model_dump())
        check_standing_reward_host_selection(
            runtime, approval_path=approval_path, preparation=preparation, first=first, plan=plan
        )
        providers = {digest(provider.config): provider}
        for key, value in legacy_providers.items():
            if key != digest(value.config) or (key in providers and providers[key] is not value):
                raise ValueError("standing service has conflicting proof provider owners")
            providers[key] = value
        if (
            digest(provider.config) != preparation.reader.chain_config_sha256
            or len(provider.config.proof_rpc_fallback_urls) != 2
            or limits.mortality_period
            > preparation.reader.series.maximum_transaction_lifetime_blocks
        ):
            raise ValueError("standing service differs from approved chain execution")
        for value in owners.values():
            await value.start()
        while not stop.is_set():
            for value in owners.values():
                value.ensure_observer_running()
            try:
                check_standing_reward_host_selection(
                    runtime,
                    approval_path=approval_path,
                    preparation=preparation,
                    first=first,
                    plan=plan,
                )
                async with hold_legacy_reward_handoff(
                    runtime,
                    preparation=preparation,
                    prepared=first,
                    plan=plan,
                    providers=legacy_providers,
                ) as handoff:
                    host = bind_standing_reward_host(
                        runtime,
                        approval_path=approval_path,
                        preparation=preparation,
                        first=first,
                        handoff=handoff,
                        maximum_journal_bytes=limits.maximum_journal_bytes,
                    )
                    if stop.is_set():
                        break
                    signer = await run_owned_thread(load_signer)
                    executor = StandingRewardExecutor(
                        preparation=preparation,
                        provider=provider,
                        history=history,
                        journal=host.journal,
                        first=first,
                        handoff=handoff,
                        host=host,
                        packages=packages,
                        decisions=decisions,
                        opportunity=opportunity,
                        signer=signer,
                        mortality_period=limits.mortality_period,
                        maximum_history_blocks=limits.maximum_history_blocks,
                        submission_timeout_seconds=limits.submission_timeout_seconds,
                    )
                    logger.info(
                        "standing_service_running series_sha256=%s", preparation.series_sha256
                    )
                    await executor.run(stop, poll_seconds=limits.poll_seconds)
            except Exception as error:
                logger.warning("standing_service_retry reason=%s", type(error).__name__)
            if not stop.is_set():
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=limits.poll_seconds)
    logger.info("standing_service_stopped")
