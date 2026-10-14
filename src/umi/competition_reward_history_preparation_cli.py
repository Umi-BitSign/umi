"""Root staging command; no service operation, journal selection or weight action."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from .competition_coordinator_namespace import ensure_coordinator_host_view
from .competition_host_anchor import load_materialized_successor_anchor_for_repair
from .competition_reward_history_preparation import hold_history_preparation_lease
from .competition_reward_history_preparation_runtime import (
    launch_history_preparation,
)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("action", choices=("readiness", "replay"))
    parser.add_argument("--unit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--standing-boot", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--launch", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or (os.getuid(), os.geteuid()) != (0, 0):
        raise ValueError("history preparation requires a fresh root Linux broker")
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    # The authentic anchor uses installed logical paths. This creates only a
    # private broker view; it does not inspect or change the live service.
    ensure_coordinator_host_view(unit_name=args.unit, config_path=args.config)
    anchor = load_materialized_successor_anchor_for_repair(args.config)
    with hold_history_preparation_lease(
        anchor, standing_boot=args.standing_boot, approval_path=args.approval
    ) as lease:

        async def run():
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for signum in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(signum, stop.set)
            try:
                return await launch_history_preparation(
                    lease,
                    launch_path=args.launch,
                    standing_boot=args.standing_boot,
                    stop=stop,
                    action=args.action,
                )
            finally:
                for signum in (signal.SIGTERM, signal.SIGINT):
                    loop.remove_signal_handler(signum)

        return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
