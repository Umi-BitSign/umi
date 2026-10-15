"""Review a stopped installed writer; never switch history or authorize weights."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import pwd
import signal
import sys
from pathlib import Path

from .competition_coordinator_namespace import ensure_coordinator_host_view
from .competition_host_anchor import load_materialized_successor_anchor_for_repair
from .competition_reward_writer_review import review_installed_standing_writer
from .concurrency import run_until_stopped


def _installed_account(args):
    if sys.platform != "linux":
        raise ValueError("writer review requires the installed Linux host")
    if (os.getuid(), os.geteuid()) == (0, 0):
        # The exact original root mappings are private to this fresh process.
        # No mount, ownership or service configuration changes are persisted.
        ensure_coordinator_host_view(unit_name=args.unit, config_path=args.config)
        anchor = load_materialized_successor_anchor_for_repair(args.config)
        account = pwd.getpwuid(anchor.service_uid)
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        if os.getgroups() or (os.getuid(), os.geteuid()) != (anchor.service_uid,) * 2:
            raise ValueError("writer review could not enter the actual service account")
        return anchor
    if os.getuid() != os.geteuid():
        raise ValueError("writer review does not accept mixed process identity")
    anchor = load_materialized_successor_anchor_for_repair(args.config)
    if os.getuid() != anchor.service_uid:
        raise ValueError("writer review needs its actual installed service account")
    return anchor


async def _run(args, anchor):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        return await run_until_stopped(
            review_installed_standing_writer(
                anchor,
                args.standing_boot,
                unit=args.unit,
                config_path=args.config,
                through_block=args.through_block,
                history=args.history,
                held_approval=args.held_approval,
                reward_adoptions=args.reward_adoptions,
                resource_launch=args.launch,
                preparation_approval=args.preparation_approval,
            ),
            stop,
        )
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--standing-boot", type=Path, required=True)
    parser.add_argument("--held-approval", type=Path)
    parser.add_argument("--reward-adoptions", type=Path)
    parser.add_argument("--launch", type=Path)
    parser.add_argument("--preparation-approval", type=Path)
    parser.add_argument("--history", choices=("current", "predecessor"), default="current")
    parser.add_argument("--through-block", type=int, required=True)
    args = parser.parse_args(argv)
    if (args.launch is None) != (args.preparation_approval is None):
        parser.error("native resource selection requires launch and preparation approval")
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    try:
        anchor = _installed_account(args)
        result = asyncio.run(_run(args, anchor))
        print(
            json.dumps(
                result
                or {
                    "status": "interrupted",
                    "directory_selection_authorized": False,
                    "chain_submission_authorized": False,
                },
                separators=(",", ":"),
            )
        )
        if result is None:
            raise SystemExit(130)
    except Exception as error:
        # Provider exceptions may contain private transport details.
        print(
            json.dumps(
                {
                    "status": "review_required",
                    "error_type": type(error).__name__,
                    "directory_selection_authorized": False,
                    "chain_submission_authorized": False,
                },
                separators=(",", ":"),
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
