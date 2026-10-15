"""Transfer matching local native history after both existing owners drain."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import threading
from pathlib import Path

from .competition_reward_history_transfer_owner import prepare_history_transfer_source
from .competition_reward_history_transfer_runtime import transfer_installed_history
from .competition_reward_writer_review_cli import _installed_account
from .competition_transport_verification import TransferProgress


async def _run(args, anchor):
    stop = threading.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        return await transfer_installed_history(
            anchor,
            unit=args.unit,
            config_path=args.config,
            standing_boot=args.standing_boot,
            coordinator_config=args.coordinator_config,
            held_approval=args.held_approval,
            first_block=args.first_block,
            through_block=args.through_block,
            maximum_blocks=args.maximum_blocks,
            stop_requested=stop,
        )
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--standing-boot", type=Path, required=True)
    parser.add_argument("--coordinator-config", type=Path, required=True)
    parser.add_argument("--held-approval", type=Path)
    parser.add_argument("--first-block", type=int, required=True)
    parser.add_argument("--through-block", type=int, required=True)
    parser.add_argument("--maximum-blocks", type=int, default=256)
    args = parser.parse_args(argv)
    if not 0 < args.first_block <= args.through_block or not 1 <= args.maximum_blocks <= 256:
        parser.error("select a positive interval and a work window of 1 to 256 blocks")
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    try:
        with TransferProgress(
            "history_transfer_account_preparation",
            2,
            unit="checks",
            planning_unit_seconds=(0.01, 120.0),
        ) as progress:
            if (os.getuid(), os.geteuid()) == (0, 0):
                args.coordinator_config = prepare_history_transfer_source(args.coordinator_config)
            progress.advance(1)
            anchor = _installed_account(args)
            progress.advance(1)
        result = asyncio.run(_run(args, anchor))
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "repair_required",
                    "error_type": type(error).__name__,
                    "chain_submission_authorized": False,
                }
            )
        )
        raise SystemExit(1) from None
    print(json.dumps(result, separators=(",", ":")))
    if result["status"] != "complete":
        raise SystemExit(130)


if __name__ == "__main__":
    main()
