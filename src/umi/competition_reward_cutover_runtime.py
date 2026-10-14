"""Stopped-owner native reconciliation assembly, with no signing or submission."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import AsyncExitStack, suppress
from pathlib import Path

from .competition_chain import _AwaitingFinality
from .competition_proof_archive_selection import selected_proof_archives
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_control_journal import RewardControlTransactionJournal
from .competition_reward_coordinator_boot import load_reward_coordinator_config
from .competition_reward_cutover import NativeRewardCutoverReview
from .competition_reward_cutover_ownership import hold_reward_cutover_owner
from .competition_reward_decisions import StandingRewardControlReader
from .competition_reward_files import StandingRewardFiles
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_service import _close_provider
from .competition_reward_signing import RewardDecisionJournal
from .concurrency import run_owned_thread, wait_for_owned
from .grandpa_finality_supervisor import GrandpaFinalitySupervisorError
from .host_memory_runtime import memory_runtime
from .open_competition import digest

logger = logging.getLogger(__name__)


async def _await_initial_finality(provider: HistoricalRewardControlProvider):
    """Wait only for absent/below-floor native finality, never retry corruption."""
    started, attempts = time.monotonic(), 0

    async def wait():
        nonlocal attempts
        while True:
            provider.ensure_observer_running()
            attempts += 1
            try:
                height = await provider.current_finalized_block()
                logger.info(
                    "reward_cutover_initial_finality %s",
                    {
                        "stage": "initial_native_finality",
                        "state": "completed",
                        "completed_items": 1,
                        "total_items": 1,
                        "percent": 100,
                        "elapsed_seconds": time.monotonic() - started,
                        "attempts": attempts,
                        "eta_seconds": 0,
                        "eta_basis": "complete",
                        "eta_scope": "initial_finality_only",
                        "finalized_block": height,
                    },
                )
                return height
            except _AwaitingFinality:
                pass
            except GrandpaFinalitySupervisorError as error:
                if error.reason_code != "no_verified_finalized_head":
                    raise
            logger.info(
                "reward_cutover_initial_finality %s",
                {
                    "stage": "initial_native_finality",
                    "state": "pending",
                    "completed_items": 0,
                    "total_items": 1,
                    "percent": 0,
                    "elapsed_seconds": time.monotonic() - started,
                    "attempts": attempts,
                    "eta_seconds": None,
                    "planning_eta_seconds": [0, provider.config.startup_timeout_seconds],
                    "eta_basis": "planning_first_head_within_selected_startup_budget",
                    "eta_scope": "initial_finality_only",
                    "retrying": True,
                },
            )
            await asyncio.sleep(0.25)

    return await wait_for_owned(wait(), timeout=provider.config.startup_timeout_seconds)


async def reconcile_reward_cutover(
    config_path: Path,
    *,
    cohort: str,
    operation: str,
    original_owner_selection: Path | None = None,
) -> dict:
    """One resumable bounded step; the original stopped owner stays stopped.

    An original installed-owner selection requires its completed-admission
    migration before any provider is constructed. A missing or damaged native
    success record is an explicit repair, never a fresh full-history pass.
    """
    started, phase = time.monotonic(), 0
    history = None

    def progress(state="running"):
        elapsed = time.monotonic() - started
        with suppress(Exception):
            logger.info(
                "reward_cutover_runner_progress %s",
                {
                    "stage": "stopped_reward_cutover_runtime",
                    "state": state,
                    "completed_items": phase,
                    "total_items": 4,
                    "percent": phase * 25,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": 0 if state == "completed" else None,
                    "planning_eta_seconds": [1, 300]
                    if state == "running" and elapsed <= 300
                    else None,
                    "eta_basis": "planning_local_open_and_bounded_native_batch"
                    if state == "running" and elapsed <= 300
                    else "complete"
                    if state == "completed"
                    else "withdrawn",
                    "eta_scope": "one_reconciliation_step_excludes_reward_activation",
                    "retrying": state == "retrying",
                    "stalled": state == "stalled",
                },
            )

    loop, timer = asyncio.get_running_loop(), None
    last_progress, changed_at = None, started

    def heartbeat():
        nonlocal timer, last_progress, changed_at
        latest = {} if history is None else history.progress.latest or {}
        current = (
            phase,
            latest.get("applied_blocks"),
            latest.get("verified_blocks"),
            latest.get("replicated_blocks"),
        )
        if current != last_progress:
            last_progress, changed_at = current, time.monotonic()
        progress("stalled" if time.monotonic() - changed_at > 300 else "running")
        timer = loop.call_later(30, heartbeat)

    progress()
    timer = loop.call_later(30, heartbeat)
    try:
        config = await run_owned_thread(load_reward_coordinator_config, Path(config_path))
        if cohort not in {digest(value) for value in config.series.cohorts}:
            raise ValueError("cutover cohort differs from the selected series")
        async with AsyncExitStack() as resources:
            # No old database or provider constructor precedes these locks.
            lease = resources.enter_context(
                hold_reward_cutover_owner(
                    config,
                    original_owner_selection=original_owner_selection,
                )
            )
            resources.enter_context(
                memory_runtime(
                    config.host_memory_admission,
                    maximum_aggregate_bytes=config.maximum_package_bytes,
                    role="reward_coordinator",
                )
            )
            phase = 1
            progress()
            root, chain = lease.root, digest(config.chain)
            imported, exported = await run_owned_thread(
                selected_proof_archives,
                Path(config.proof_import_directory),
                Path(config.proof_export_directory),
                config.proof_stores,
            )

            def assemble():
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
                    expected_chain_config_sha256=chain,
                    maximum_bytes=config.maximum_reader_bytes,
                    reward_adoptions=config.reward_adoptions,
                )
                history = RewardControlHistoryReader(
                    root / "history",
                    control_hotkey=config.series.control_hotkey,
                    chain_config_sha256=chain,
                    first_block=config.series.recovery.authority.issued_at_block,
                    maximum_bytes=config.maximum_history_bytes,
                    verification_profile=config.service.history_verification,
                    archive=imported,
                    export_archive=exported,
                )
                if (
                    original_owner_selection is not None
                    and history.completed_admission.load() is None
                ):
                    raise HistoryCheckpointRepairRequired(
                        "cutover requires the original completed-admission migration"
                    )
                decisions = RewardDecisionJournal(
                    root / "decisions",
                    config.series,
                    config.policy,
                    config.signer_hotkey,
                    expected_chain_config_sha256=chain,
                    maximum_bytes=config.service.maximum_journal_bytes,
                    reward_adoptions=config.reward_adoptions,
                )
                transactions = RewardControlTransactionJournal(
                    root / "transactions",
                    config.series,
                    config_sha256=chain,
                    maximum_bytes=config.service.maximum_journal_bytes,
                )
                return files, reader, history, decisions, transactions

            files, reader, history, decisions, transactions = await run_owned_thread(assemble)
            provider = None

            async def close_created():
                if provider is not None:
                    await _close_provider(provider)

            # Cancellation drains construction before closing the provider; its
            # cleanup finishes before memory ownership and process locks leave.
            resources.push_async_callback(close_created)

            def construct():
                nonlocal provider
                provider = HistoricalRewardControlProvider(
                    config.chain,
                    config.policy,
                    runtime_proof_reads=config.runtime_proof_reads,
                    historical_header_directory=root / "headers",
                    historical_header_maximum_bytes=config.maximum_header_bytes,
                    historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
                )

            await run_owned_thread(construct)
            await provider.start()
            phase = 2
            progress()
            try:
                await _await_initial_finality(provider)
            except asyncio.TimeoutError:
                result = {
                    "schema": "umi-standing-reward-cutover-review/1",
                    "status": "finality_pending",
                    "cutover_decision": "keep_stopped_and_resume_same_operation",
                    "publication_authorized": False,
                    "native_startup_recheck_required": True,
                }
                progress("retrying")
            else:
                review = await run_owned_thread(
                    lambda: NativeRewardCutoverReview(
                        config=config,
                        lease=lease,
                        provider=provider,
                        history=history,
                        reader=reader,
                        decisions=decisions,
                        transactions=transactions,
                        files=files,
                        operation=operation,
                    )
                )
                while True:
                    result = await review.step(cohort)
                    if result["status"] != "historical_recovery_progress":
                        break
                    # Preserve this genuine provider's bounded in-memory
                    # ancestry cursor; restarting each pass would rewalk its
                    # first retained hints indefinitely. Cancellation still
                    # drains native work and releases the original owner.
                    await asyncio.sleep(0)
            phase = 3
            progress()
        # The terminal event includes completion of provider cleanup and release.
        phase = 4
        progress("completed" if result["status"] == "reconciled" else "pending")
        return {
            **result,
            "operation": operation,
            "elapsed_seconds": time.monotonic() - started,
            "publishing_roles_started": False,
            "service_restart_performed": False,
        }
    except asyncio.CancelledError:
        progress("interrupted")
        raise
    except Exception:
        progress("repair_required")
        raise
    finally:
        if timer is not None:
            timer.cancel()
