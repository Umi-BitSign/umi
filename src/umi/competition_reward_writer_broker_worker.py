"""Fixed fresh-process child for the native root writer-selection broker."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import socket
from contextlib import suppress
from pathlib import Path

from .competition_progress import _failure_details
from .competition_reward_writer_broker_channel import WriterBrokerChannel
from .competition_reward_writer_exchange import exchange_installed_standing_writer
from .competition_reward_writer_review_cli import _installed_account


def arguments(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--standing-boot", type=Path, required=True)
    parser.add_argument("--held-approval", type=Path, required=True)
    parser.add_argument("--history", choices=("current", "predecessor"), required=True)
    parser.add_argument("--through-block", type=int, required=True)
    parser.add_argument("--socket-fd", type=int, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--readiness-only", action="store_true")
    return parser.parse_args(argv)


async def _run(args, anchor, channel):
    loop = asyncio.get_running_loop()
    current = asyncio.current_task()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, current.cancel)
    try:
        return await exchange_installed_standing_writer(anchor, args, channel)
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def main(argv=None):
    args = arguments(argv)
    if (os.getuid(), os.geteuid()) != (0, 0) or os.getppid() != args.parent_pid:
        raise ValueError("writer worker requires its actual root parent")
    logging.basicConfig(level=logging.INFO)
    os.umask(0o077)
    endpoint = socket.socket(fileno=args.socket_fd)
    channel = WriterBrokerChannel(endpoint, peer_pid=args.parent_pid, peer_uid=0)
    try:
        # A fresh executable has no inherited process-local coordinator view.
        # Mount the exact preserved parent roots, then permanently drop all
        # supplementary groups/GID/UID before acquiring the native writer owner.
        anchor = _installed_account(args)
        asyncio.run(_run(args, anchor, channel))
    except BaseException as error:
        with suppress(Exception):
            logging.error("writer_broker_child_exit causes=%s", _failure_details(error))
        raise SystemExit(1) from None
    finally:
        endpoint.close()


if __name__ == "__main__":
    main()
