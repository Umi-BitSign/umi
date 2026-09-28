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
from .open_competition import digest


@contextmanager
def _logs():
    handler, selected = logging.StreamHandler(), []
    for suffix in ("coordinator", "exchange", "control_publisher", "coverage_service"):
        logger = logging.getLogger("umi.competition_reward_" + suffix)
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


async def _run(config):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        await run_reward_coordinator(config, stop)
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
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
            asyncio.run(_run(config))
    except Exception as error:
        # Parsing and SDK exceptions can contain paths, URLs and credentials.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
