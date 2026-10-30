"""Commands for explicitly configured standing reward coordination or review."""

import argparse
import asyncio
import json
import logging
import signal
from contextlib import contextmanager
from pathlib import Path

from .competition_evidence_codec import checked_digest
from .competition_reward_coordinator_boot import (
    load_reward_coordinator_config,
    run_reward_coordinator,
)
from .competition_reward_coverage_credits import CoverageCreditRepairRequired
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_history_repair import run_reward_history_repair
from .competition_reward_transition_cli import approve_successor
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
                "coverage_collector",
                "history_progress",
                "history_checkpoint",
                "checkpoint_progress",
                "history_repair",
                "adoption_exchange",
                "adoption_feed",
            )
        ),
        "umi.competition.progress",
        "umi.competition_round_journal",
        "umi.historical_header_progress",
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


async def _run(config, *, repair=None, credit_repair=None):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        work = (
            (
                run_reward_coordinator(config, stop)
                if credit_repair is None
                else run_reward_coordinator(config, stop, credit_repair=credit_repair)
            )
            if repair is None
            else run_reward_history_repair(config, stop, **repair)
        )
        return await run_until_stopped(work, stop)
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("check", "run", "repair-history", "repair-credit", "approve-successor")
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--through-block", type=int, help="Inclusive bounded history repair target")
    parser.add_argument("--reason", help="Required operator reason retained with repaired work")
    parser.add_argument(
        "--interval", help="Exact native coverage interval digest for credit repair"
    )
    parser.add_argument("--history", choices=("current", "predecessor"))
    parser.add_argument(
        "--predecessor", help="Exact currently selected predecessor decision digest"
    )
    parser.add_argument("--cohort", help="Exact completed successor cohort digest")
    parser.add_argument("--package", help="Exact completed successor reward-package digest")
    args = parser.parse_args(argv)
    if args.action == "approve-successor":
        if (
            not all((args.predecessor, args.cohort, args.package, args.reason))
            or not args.reason.strip()
            or any(value is not None for value in (args.interval, args.through_block, args.history))
        ):
            parser.error(
                "approve-successor requires --predecessor, --cohort, --package and --reason"
            )
        try:
            for value in (args.predecessor, args.cohort, args.package):
                checked_digest(value)
        except (ValueError, TypeError):
            parser.error("approve-successor requires exact digests")
    elif any(value is not None for value in (args.predecessor, args.cohort, args.package)):
        parser.error("successor selection options require approve-successor")
    elif args.action == "repair-credit":
        if (
            not args.interval
            or not args.reason
            or not args.reason.strip()
            or args.through_block is not None
            or len(args.reason) > 1024
        ):
            parser.error("repair-credit requires --interval and --reason, without block targets")
        try:
            checked_digest(args.interval)
        except (ValueError, TypeError):
            parser.error("repair-credit requires an exact interval digest")
    elif args.action == "repair-history":
        if args.interval:
            parser.error("repair-history does not take --interval")
        if args.through_block is None or not args.reason or not args.reason.strip():
            parser.error("repair-history requires --through-block and a nonempty --reason")
    elif any(
        value is not None
        for value in (args.through_block, args.reason, args.history, args.interval)
    ):
        parser.error("history repair options require the repair-history action")
    try:
        config = load_reward_coordinator_config(args.config)
        if args.action == "approve-successor":
            with _logs():
                print(
                    json.dumps(
                        approve_successor(
                            config,
                            predecessor=args.predecessor,
                            cohort=args.cohort,
                            package=args.package,
                            reason=args.reason,
                        )
                    )
                )
            return
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
            elif args.action == "repair-credit":
                result = asyncio.run(
                    _run(
                        config,
                        credit_repair=dict(
                            key=args.interval, reason=args.reason, history=args.history or "current"
                        ),
                    )
                )
                print(json.dumps(result or {"status": "interrupted"}))
            else:
                asyncio.run(_run(config))
    except Exception as error:
        # Parsing and SDK exceptions can contain paths, URLs and credentials.
        report = {"status": "failed", "error_type": type(error).__name__}
        if args.action in {"repair-history", "repair-credit"}:
            if isinstance(error, PrivateStateBusyError):
                report["status"] = "owner_busy"
            elif isinstance(
                error,
                (
                    HistoryCheckpointRepairRequired,
                    RoundCapacityRepairRequired,
                    CoverageCreditRepairRequired,
                ),
            ):
                report.update(
                    status="repair_required",
                    recovery="restore_original_metadata_and_source_in_place_no_reset",
                )
        print(json.dumps(report))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
