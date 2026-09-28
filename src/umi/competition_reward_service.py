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
from .competition_reward_executor import StandingHistoryPending, StandingRewardExecutor
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


async def _continue_predecessor(runtime, stop, poll_seconds):
    """Keep the existing supervisor reconciling while initial C5 replay waits.

    The native runtime checks its durable handoff intent under the same mutex
    as the handoff itself. A loop already awaiting that mutex cannot resurrect
    the old writer after the handoff has begun.
    """
    while not stop.is_set() and runtime._standing_handoff_intent() is None:
        try:
            result = await runtime.reconcile()
            logger.info("standing_predecessor status=%s reason=%s", result.status, result.reason)
        except Exception as error:
            # Legacy feed/RPC failure cannot prevent independent C5 recovery.
            logger.warning("standing_predecessor_retry reason=%s", type(error).__name__)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=poll_seconds)


async def _stop_predecessor(task):
    task.cancel()
    with suppress(asyncio.CancelledError):
        await await_owned_task(task)


async def _prepare_first(preparation, provider, history, packages, decisions, height, maximum):
    if height < history.first_block:
        return None
    try:
        prefix = await history.verified_prefix(height)
    except ValueError:
        progress = await history.advance(provider, through_block=height, maximum_blocks=maximum)
        if progress.history is None:
            logger.info(
                "standing_boot_history_pending next_block=%s target_block=%s",
                progress.next_block,
                height,
            )
            raise StandingHistoryPending from None
        prefix = progress.history
    control = await history.review_control(provider, height)
    if control.control_sha256 is None:
        return None
    reviewed = await run_owned_thread(preparation.reader.review_history, control, decisions, prefix)
    initial = reviewed.initial_selection
    if initial is None:
        return None
    package = await run_owned_thread(packages, initial.activation.package_sha256)
    first = await preparation.prepare_initial(
        package, control=control, history=prefix, source=decisions
    )
    logger.info("standing_boot_prepared cohort_sha256=%s", first.activation.cohort_sha256)
    return first


async def run_standing_reward_service(
    runtime: SuccessorSupervisorRuntime,
    *,
    approval_path: Path,
    preparation: StandingRewardPreparation,
    first: PreparedStandingReward | None = None,
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
    Without a supplied first preparation, replay the retained complete history
    and initial package before handoff, even when a successor is current.
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
            or digest(provider.config) != preparation.reader.admission_chain_config_sha256
            or digest(provider.policy) != preparation.policy_sha256
            or len(provider.config.proof_rpc_fallback_urls) != 2
            or limits.mortality_period
            > preparation.reader.series.maximum_transaction_lifetime_blocks
            or type(history) is not RewardControlHistoryReader
            or history.config_sha256 != digest(provider.config)
            or history.hotkey != preparation.reader.series.control_hotkey
            or history.first_block != preparation.reader.series.recovery.authority.issued_at_block
        ):
            raise ValueError("standing service differs from approved chain execution")
        if first is None:
            predecessor = asyncio.create_task(
                _continue_predecessor(runtime, stop, float(runtime.config.poll_seconds)),
                name="standing-predecessor-continuation",
            )
            resources.push_async_callback(_stop_predecessor, predecessor)
        for value in owners.values():
            await value.start()
        bootstrap_height = None
        while not stop.is_set():
            for value in owners.values():
                value.ensure_observer_running()
            try:
                if first is None:
                    check_standing_reward_host_selection(
                        runtime,
                        approval_path=approval_path,
                        preparation=preparation,
                        first=None,
                        plan=plan,
                    )
                    # Keep a fixed finalized target while replay catches up.
                    # Chasing a moving head can starve slow recovery forever.
                    if bootstrap_height is None:
                        control = await provider.collect_control(history.hotkey)
                        bootstrap_height = control.snapshot.block_number
                    first = await _prepare_first(
                        preparation,
                        provider,
                        history,
                        packages,
                        decisions,
                        bootstrap_height,
                        limits.maximum_history_blocks,
                    )
                    if first is None:
                        bootstrap_height = None
                        logger.info("standing_boot_waiting_for_initial_activation")
                        raise StandingHistoryPending
                    if stop.is_set():
                        break
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
            except StandingHistoryPending:
                if bootstrap_height is not None:
                    # A completed chunk made durable progress. Keep catching
                    # up without a poll delay per chunk, yielding for shutdown.
                    await asyncio.sleep(0)
                    continue
            except Exception as error:
                logger.warning("standing_service_retry reason=%s", type(error).__name__)
            if not stop.is_set():
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=limits.poll_seconds)
    logger.info("standing_service_stopped")
