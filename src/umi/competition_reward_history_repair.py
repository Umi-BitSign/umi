"""Explicit, exclusively owned repair of an existing configured history journal.

No signing keys are loaded, and no certification, reward or chain publication is
performed. Successful block facts remain in the original journal on every exit.
Lost identity metadata must be recovered in place before this route can proceed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import AsyncExitStack, suppress
from pathlib import Path
from typing import Literal

from .competition_chain_resources import CompetitionChainResources
from .competition_host_anchor import MaterializedSuccessorAnchor
from .competition_reward_boot import StandingRewardBootConfig, load_standing_boot
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coordinator_boot import RewardCoordinatorConfig
from .competition_reward_coordinator_ownership import owned_reward_state
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_history_repair_journal import HistoryRepairRequest
from .competition_reward_proof_archive import RewardProofArchive
from .competition_reward_service import _close_provider
from .competition_supervisor_runtime import hold_successor_startup_lease
from .concurrency import run_owned_thread
from .historical_header_recovery import HistoricalHeaderRecoveryProgress
from .host_memory_runtime import memory_runtime
from .open_competition import digest
from .protocol import canonical_json_bytes
from .validator_chain import ValidatorChainError

logger = logging.getLogger(__name__)


async def repair_history_scope(
    reader: RewardControlHistoryReader,
    provider: HistoricalRewardControlProvider,
    stop: asyncio.Event,
    *,
    through_block: int,
    reason: str,
    maximum_blocks: int,
    poll_seconds: float,
    request: HistoryRepairRequest | None = None,
) -> dict[str, object]:
    """Continue bounded native repair, preserving good blocks across retries."""
    if request is None:
        request = await run_owned_thread(HistoryRepairRequest, reader, through_block, reason)
    while not stop.is_set():
        try:
            result = await reader.repair_checkpoints(
                provider,
                through_block=through_block,
                reason=reason,
                maximum_blocks=maximum_blocks,
            )
        except HistoricalHeaderRecoveryProgress:
            # A bounded header pass made durable progress; continue immediately.
            await asyncio.sleep(0)
            continue
        except (OSError, ValidatorChainError):
            # Native diagnostics have already withdrawn the ETA. Retry only
            # operational failures; unsupported or invalid evidence still exits.
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
            continue
        if result.history is not None:
            await run_owned_thread(request.finish, result.history)
            return {
                "status": "history_repaired",
                "repair_request_sha256": request.sha256,
                **reader.progress.latest,
            }
        await asyncio.sleep(0)
    return {
        **reader.progress.latest,
        "status": "interrupted",
        "repair_request_sha256": request.sha256,
        "state": "interrupted",
        "eta_seconds": None,
        "planning_eta_seconds": None,
        "eta_basis": "withdrawn_interrupted",
    }


async def run_reward_history_repair(
    config: RewardCoordinatorConfig,
    stop: asyncio.Event,
    *,
    through_block: int,
    reason: str,
    history: Literal["current", "predecessor"] = "current",
) -> dict[str, object]:
    config = RewardCoordinatorConfig.model_validate_json(canonical_json_bytes(config))
    _repair_selection(config, history, through_block, reason)
    with owned_reward_state(config) as owner_root:
        return await _run_owned_history_repair(
            config,
            stop,
            through_block=through_block,
            reason=reason,
            history=history,
            state_directory=Path(config.state_directory),
            owner_root=owner_root,
            role="reward_coordinator",
        )


async def run_installed_history_repair(
    anchor: MaterializedSuccessorAnchor,
    config_path: Path,
    stop: asyncio.Event,
    *,
    through_block: int,
    reason: str,
    history: Literal["current", "predecessor"] = "current",
) -> dict[str, object]:
    """Repair the writer's original namespace under its authentic supervisor lease.

    The supervisor CLI first verifies the signed running host. This route also
    requires the native root-sealed anchor and reopens the exact approved boot
    configuration. It never constructs the writer, adapter, signer or executor.
    """
    with hold_successor_startup_lease(anchor) as lease:
        config = load_standing_boot(config_path, anchor)
        lease.recheck()
        state = Path(lease.config.state_root) / "standing-rewards"
        result = await _run_owned_history_repair(
            config,
            stop,
            through_block=through_block,
            reason=reason,
            history=history,
            state_directory=state,
            owner_root=state / digest(config.series),
            role="reward_writer",
        )
        lease.recheck()
        return result


def _repair_selection(config, history, through_block, reason):
    selected = config.series if history == "current" else config.predecessor_series
    if history not in {"current", "predecessor"} or selected is None:
        raise ValueError("repair history is not configured")
    first = selected.recovery.authority.issued_at_block
    if type(through_block) is not int or not first <= through_block < 2**53:
        raise ValueError("repair target must select a finite configured history interval")
    if type(reason) is not str or not reason.strip():
        raise ValueError("repair requires an explicit reason")
    return selected


async def _run_owned_history_repair(
    config: RewardCoordinatorConfig | StandingRewardBootConfig,
    stop: asyncio.Event,
    *,
    through_block: int,
    reason: str,
    history: Literal["current", "predecessor"],
    state_directory: Path,
    owner_root: Path,
    role: Literal["reward_writer", "reward_coordinator"],
) -> dict[str, object]:
    selected = _repair_selection(config, history, through_block, reason)
    first = selected.recovery.authority.issued_at_block
    started, reader = time.monotonic(), None
    common = {
        "history": history,
        "role": role,
        "series_sha256": digest(selected),
        "reason": reason,
        "first_block": first,
        "target_block": through_block,
        "total_blocks": through_block - first + 1,
    }
    startup = {
        "stage": "history_repair_startup",
        "state": "running",
        "completed_blocks": 0,
        "percent": 0.0,
        "eta_seconds": None,
        "planning_eta_seconds": [5.0, 120.0],
        "eta_basis": "planning_assumption_local_open_and_owned_provider_start_5_to_120_seconds",
        "eta_scope": "startup_only_excluding_history_repair",
    }

    def report(state=None, error=None):
        body = {
            **common,
            **(
                reader.progress.latest if reader is not None and reader.progress.latest else startup
            ),
            "operation_elapsed_seconds": time.monotonic() - started,
        }
        if "elapsed_seconds" not in body:
            body["elapsed_seconds"] = body["operation_elapsed_seconds"]
        if state is not None:
            body["state"] = state
        if state in {"repair_required", "failed", "interrupted", "stalled", "retrying"}:
            body.update(eta_seconds=None, planning_eta_seconds=None, eta_basis="withdrawn")
        if state == "repair_required":
            body["percent"] = None
        if error is not None:
            body["error_type"] = type(error).__name__
        with suppress(Exception):
            logger.info("reward_history_repair %s", json.dumps(body, separators=(",", ":")))
        return body

    loop, timer = asyncio.get_running_loop(), None

    def heartbeat():
        nonlocal timer
        stalled = (
            reader is None or not reader.progress.latest
        ) and time.monotonic() - started > startup["planning_eta_seconds"][1]
        report("interrupted" if stop.is_set() else "stalled" if stalled else None)
        timer = loop.call_later(30, heartbeat)

    report()
    timer = loop.call_later(30, heartbeat)
    try:
        async with AsyncExitStack() as resources:
            # Both public routes already hold their actual native owner locks.
            # Nothing above this point inspects an existing history journal.
            resources.enter_context(
                memory_runtime(
                    config.host_memory_admission,
                    maximum_aggregate_bytes=config.maximum_package_bytes,
                    role=role,
                )
            )
            root = state_directory / digest(selected)
            if not (root / "history" / "rounds.sqlite3").is_file():
                raise FileNotFoundError("repair requires the existing original history journal")
            imported = RewardProofArchive(Path(config.proof_import_directory))
            exported = RewardProofArchive(Path(config.proof_export_directory))

            def open_history():
                return RewardControlHistoryReader(
                    root / "history",
                    control_hotkey=selected.control_hotkey,
                    chain_config_sha256=digest(config.chain),
                    first_block=first,
                    maximum_bytes=config.maximum_history_bytes,
                    archive=imported,
                    export_archive=exported,
                )

            reader = await run_owned_thread(open_history)
            request = await run_owned_thread(HistoryRepairRequest, reader, through_block, reason)
            common["repair_request_sha256"] = request.sha256
            provider_options = (
                {"resources": CompetitionChainResources.from_config(config.chain)}
                if role == "reward_writer"
                else {}
            )
            provider = HistoricalRewardControlProvider(
                config.chain,
                config.policy,
                runtime_proof_reads=config.runtime_proof_reads,
                historical_header_directory=(owner_root / "headers" / digest(config.chain))
                if role == "reward_writer"
                else owner_root / "headers",
                historical_header_maximum_bytes=config.maximum_header_bytes,
                historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
                **provider_options,
            )
            resources.push_async_callback(_close_provider, provider)
            await provider.start()
            result = await repair_history_scope(
                reader,
                provider,
                stop,
                through_block=through_block,
                reason=reason,
                maximum_blocks=config.service.maximum_history_blocks,
                poll_seconds=config.service.poll_seconds,
                request=request,
            )
            return {**report(), **result, **common}
    except BaseException as error:
        state = (
            "repair_required"
            if isinstance(error, HistoryCheckpointRepairRequired)
            else "interrupted"
            if isinstance(error, asyncio.CancelledError)
            else "failed"
        )
        report(state, error)
        raise
    finally:
        if timer is not None:
            timer.cancel()
