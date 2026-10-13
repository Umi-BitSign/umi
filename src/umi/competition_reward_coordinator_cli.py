"""Commands for explicitly configured standing reward coordination or review."""

import argparse
import asyncio
import json
import logging
import signal
from contextlib import contextmanager
from pathlib import Path

from .competition_reward_coordinator_boot import (
    load_reward_coordinator_config,
    run_reward_coordinator,
)
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_history_repair import run_reward_history_repair
from .competition_round_journal import RoundCapacityRepairRequired
from .concurrency import run_until_stopped
from .open_competition import digest
from .private_files import PrivateStateBusyError


@contextmanager
def _logs():
    handler, selected = logging.StreamHandler(), []
    for name in (
        *(
            "umi.competition_reward_" + suffix
            for suffix in (
                "coordinator",
                "exchange",
                "control_publisher",
                "coverage_service",
                "history_progress",
                "history_checkpoint",
                "history_repair",
            )
        ),
        "umi.competition.progress",
        "umi.competition_round_journal",
    ):
        logger = logging.getLogger(name)
        selected.append((logger, logger.level, logger.propagate))
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(handler)
    try:
        yield
    finally:
        for logger, level, propagate in selected:
            logger.removeHandler(handler)
            logger.setLevel(level)
            logger.propagate = propagate
        handler.close()


async def _run(config, *, repair=None):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        work = (
            run_reward_coordinator(config, stop)
            if repair is None
            else run_reward_history_repair(config, stop, **repair)
        )
        return await run_until_stopped(work, stop)
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run", "repair-history"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--through-block", type=int, help="Inclusive bounded history repair target")
    parser.add_argument("--reason", help="Required operator reason retained with repaired blocks")
    parser.add_argument("--history", choices=("current", "predecessor"))
    args = parser.parse_args(argv)
    if args.action == "repair-history":
        if args.through_block is None or not args.reason or not args.reason.strip():
            parser.error("repair-history requires --through-block and a nonempty --reason")
    elif any(value is not None for value in (args.through_block, args.reason, args.history)):
        parser.error("history repair options require the repair-history action")
    try:
        config = load_reward_coordinator_config(args.config)
        if args.action == "check":
            print(
                json.dumps(
                    {
                        "status": "configuration_valid",
                        "role": config.role,
                        "series_sha256": digest(config.series),
                        "config_sha256": digest(config),
                        "runtime_qualified": False,
                    }
                )
            )
            return
        with _logs():
            if args.action == "repair-history":
                result = asyncio.run(
                    _run(
                        config,
                        repair=dict(
                            through_block=args.through_block,
                            reason=args.reason,
                            history=args.history or "current",
                        ),
                    )
                )
                print(json.dumps(result or {"status": "interrupted"}))
            else:
                asyncio.run(_run(config))
    except Exception as error:
        # Parsing and SDK exceptions can contain paths, URLs and credentials.
        report = {"status": "failed", "error_type": type(error).__name__}
        if args.action == "repair-history":
            if isinstance(error, PrivateStateBusyError):
                report["status"] = "owner_busy"
            elif isinstance(error, (HistoryCheckpointRepairRequired, RoundCapacityRepairRequired)):
                report.update(
                    status="repair_required",
                    recovery="restore_original_metadata_and_source_in_place_no_reset",
                )
        print(json.dumps(report))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
