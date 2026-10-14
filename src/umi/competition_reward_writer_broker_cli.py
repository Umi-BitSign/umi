"""Select prepared writer history under original native owners; keep approval held."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
from pathlib import Path

from .competition_coordinator_namespace import ensure_coordinator_host_view
from .competition_host_anchor import load_materialized_successor_anchor_for_repair
from .competition_reward_writer_broker import launch_writer_history_selection


async def _run(anchor, args):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        return await launch_writer_history_selection(anchor, args, stop)
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--standing-boot", type=Path, required=True)
    parser.add_argument("--held-approval", type=Path, required=True)
    parser.add_argument("--preparation-approval", type=Path, required=True)
    parser.add_argument("--launch", type=Path, required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--reward-adoptions", type=Path)
    parser.add_argument("--readiness-only", action="store_true")
    parser.add_argument("--history", choices=("current", "predecessor"), default="current")
    args = parser.parse_args(argv)
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    try:
        if (os.getuid(), os.geteuid()) != (0, 0):
            raise ValueError("writer selection requires the actual root broker")
        ensure_coordinator_host_view(unit_name=args.unit, config_path=args.config)
        anchor = load_materialized_successor_anchor_for_repair(args.config)
        result = asyncio.run(_run(anchor, args))
        print(json.dumps(result, separators=(",", ":")))
    except BaseException as error:
        print(
            json.dumps(
                {
                    "status": "review_required",
                    "error_type": type(error).__name__,
                    "chain_submission_authorized": False,
                    "approval_hold_preserved": True,
                },
                separators=(",", ":"),
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
