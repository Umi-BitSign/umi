"""Review stopped coordinator decisions, history and pending control; never launch."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
from contextlib import contextmanager
from pathlib import Path

from .competition_reward_cutover_runtime import reconcile_reward_cutover
from .concurrency import run_until_stopped


async def _run(args):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        return await run_until_stopped(
            reconcile_reward_cutover(
                args.config,
                cohort=args.cohort,
                operation=args.operation,
                original_owner_selection=args.original_owner_selection,
            ),
            stop,
        )
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


@contextmanager
def _logs():
    handler, selected = logging.StreamHandler(), []
    for name in (
        "umi.competition_reward_cutover",
        "umi.competition_reward_cutover_runtime",
        "umi.competition_reward_history_progress",
        "umi.competition_reward_history_checkpoint",
        "umi.competition_round_journal",
        "umi.competition.progress",
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
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--cohort", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--original-owner-selection", type=Path)
    args = parser.parse_args(argv)
    try:
        with _logs():
            result = asyncio.run(_run(args))
        print(json.dumps(result or {"status": "interrupted", "publication_authorized": False}))
        if result is None:
            raise SystemExit(130)
    except Exception as error:
        # Provider exceptions can contain credentials or private URLs.
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
