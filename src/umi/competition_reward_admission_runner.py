"""Preserve the selected stopped C5 owner's completed admission; never launch.

Run with the original service UID and exact root-sealed configuration. Service
shutdown and fencing against restart are the operator's preceding responsibility.
This command starts only a read/proof provider; it never constructs a signer,
control publisher, coordinator loop or reward writer.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import time
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager, suppress
from dataclasses import asdict
from pathlib import Path

from .competition_reward_admission_migration import migrate_completed_admission
from .competition_reward_admission_provenance import (
    load_provenance,
    provenance_selection_digest,
    validate_provenance,
)
from .competition_reward_admission_source import read_admission_source
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coordinator_boot import load_reward_coordinator_config
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_service import _close_provider
from .concurrency import run_owned_thread, run_until_stopped
from .host_memory_runtime import memory_runtime
from .open_competition import digest

logger = logging.getLogger(__name__)


async def run_original_admission_migration(selection_path: Path):
    """No-launch runner; provider construction occurs inside original owner locks."""
    started, phase = time.monotonic(), 0

    def progress(state="running"):
        elapsed = time.monotonic() - started
        with suppress(Exception):
            logger.info(
                "reward_admission_runner_progress %s",
                {
                    "stage": "completed_admission_no_launch_runner",
                    "state": state,
                    "completed_items": phase,
                    "total_items": 3,
                    "percent": 100.0 * phase / 3,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": 0.0 if state == "completed" else None,
                    "planning_eta_seconds": [5.0, 300.0] if state == "running" else None,
                    "eta_basis": "planning_local_open_owned_provider_and_one_boundary"
                    if state == "running"
                    else "complete"
                    if state == "completed"
                    else "withdrawn",
                    "eta_scope": "migration_runner_excludes_tail_and_economics_reconciliation",
                },
            )

    loop, timer = asyncio.get_running_loop(), None

    def heartbeat():
        nonlocal timer
        progress("stalled" if time.monotonic() - started > 300 else "running")
        timer = loop.call_later(30, heartbeat)

    progress()
    timer = loop.call_later(30, heartbeat)
    try:
        selection = await run_owned_thread(load_provenance, Path(selection_path))
        if os.getuid() != selection["owner_uid"] or os.geteuid() != selection["owner_uid"]:
            raise HistoryCheckpointRepairRequired("migration requires the original service UID")
        # Only root configuration is read here. No provider/journal is constructed.
        await run_owned_thread(lambda: validate_provenance(selection, require_stopped=True))
        config = await run_owned_thread(
            load_reward_coordinator_config, Path(selection["configuration"]["path"])
        )
        root = Path(config.state_directory) / digest(config.series)
        if str(root) != selection["paths"]["service_root"]:
            raise HistoryCheckpointRepairRequired("original admission state root changed")
        phase = 1
        progress()

        @asynccontextmanager
        async def owned_provider(locked_selection):
            nonlocal phase
            if provenance_selection_digest(locked_selection) != provenance_selection_digest(
                selection
            ):
                raise HistoryCheckpointRepairRequired("original selection changed before ownership")
            # Missing native completion fails before provider construction. This
            # bounded read does not instantiate or migrate either source journal.
            await run_owned_thread(read_admission_source, locked_selection)
            async with AsyncExitStack() as resources:
                resources.enter_context(
                    memory_runtime(
                        config.host_memory_admission,
                        maximum_aggregate_bytes=config.maximum_package_bytes,
                        role="reward_coordinator",
                    )
                )
                provider = None

                async def close_created():
                    if provider is not None:
                        await _close_provider(provider)

                resources.push_async_callback(close_created)

                def construct_provider():
                    nonlocal provider
                    provider = HistoricalRewardControlProvider(
                        config.chain,
                        config.policy,
                        runtime_proof_reads=config.runtime_proof_reads,
                        historical_header_directory=root / "headers",
                        historical_header_maximum_bytes=config.maximum_header_bytes,
                        historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
                    )

                # Register cleanup before awaiting a blocking constructor: caller
                # cancellation drains that thread, then closes the created owner.
                await run_owned_thread(construct_provider)
                await provider.start()
                phase = 2
                progress()
                yield provider

        result = await migrate_completed_admission(
            Path(selection_path),
            provider_factory=owned_provider,
            series=config.series,
            policy=config.policy,
            maximum_history_bytes=config.maximum_history_bytes,
        )
        phase = 3
        progress("completed")
        return {
            **asdict(result),
            "publishing_roles_started": False,
            "service_restart_performed": False,
            "owner_uid": selection["owner_uid"],
            "elapsed_seconds": time.monotonic() - started,
            "inherited_limits": {
                "maximum_history_bytes": config.maximum_history_bytes,
                "maximum_header_bytes": config.maximum_header_bytes,
                "maximum_header_database_bytes": config.maximum_header_database_bytes,
                "maximum_package_bytes": config.maximum_package_bytes,
            },
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


async def _run(selection):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        return await run_until_stopped(run_original_admission_migration(selection), stop)
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


@contextmanager
def _logs():
    handler, selected = logging.StreamHandler(), []
    for name in (
        __name__,
        "umi.competition_reward_admission_migration",
        "umi.competition_reward_history_checkpoint",
        "umi.competition_reward_checkpoint_progress",
        "umi.competition_round_journal",
    ):
        current = logging.getLogger(name)
        selected.append((current, current.level, current.propagate))
        current.setLevel(logging.INFO)
        current.propagate = False
        current.addHandler(handler)
    try:
        yield
    finally:
        for current, level, propagate in selected:
            current.removeHandler(handler)
            current.setLevel(level)
            current.propagate = propagate
        handler.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with _logs():
            result = asyncio.run(_run(args.selection))
        print(json.dumps(result or {"status": "interrupted", "publication_authorized": False}))
    except Exception as error:
        # Provider and configuration exceptions can contain private URLs/paths.
        print(
            json.dumps(
                {
                    "status": "repair_required",
                    "error_type": type(error).__name__,
                    "publication_authorized": False,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
