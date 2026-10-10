"""Run or check a host-selected native cohort settlement service."""

import argparse
import asyncio
import json
import logging
import signal
from pathlib import Path

from .competition_cohort_settlement_boot import run_settlement_service
from .competition_cohort_settlement_config import load_settlement_service_config
from .open_competition import digest


async def _run(config):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        await run_settlement_service(config, stop)
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    handler, loggers = logging.StreamHandler(), []
    try:
        config = load_settlement_service_config(args.config)
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
        for suffix in ("service", "controller", "exchange", "preparation"):
            logger = logging.getLogger("umi.competition_cohort_settlement_" + suffix)
            loggers.append((logger, logger.level, logger.propagate))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
        asyncio.run(_run(config))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}))
        raise SystemExit(1) from None
    finally:
        for logger, level, propagate in loggers:
            logger.removeHandler(handler)
            logger.setLevel(level)
            logger.propagate = propagate
        handler.close()


if __name__ == "__main__":
    main()
