"""Check or run the private cohort phase reviewer selected by this host."""

import argparse
import asyncio
import json
import logging
import signal
from pathlib import Path

from .competition_cohort_review_boot import run_phase_review_service
from .competition_cohort_review_config import load_phase_review_config
from .competition_cohort_service_budget import service_execution_budget
from .competition_progress import _failure_details
from .open_competition import digest


async def _run(config):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for value in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(value, stop.set)
    try:
        await run_phase_review_service(config, stop)
    finally:
        for value in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    handler = logging.StreamHandler()
    loggers = []
    try:
        config = load_phase_review_config(args.config)
        if args.action == "check":
            print(
                json.dumps(
                    {
                        "status": "configuration_valid",
                        "config_sha256": digest(config),
                        "series_sha256": digest(config.series),
                        "runtime_qualified": False,
                        "phase_review_budget": (
                            None
                            if config.phase_review_budget is None
                            else config.phase_review_budget.effective()
                        ),
                        "managed_phase_path_qualified": False,
                        "service_execution_budget": (
                            None
                            if config.service_signing is None
                            else service_execution_budget(
                                config.phase_review_budget,
                                read_seconds=config.service_signing.read_timeout_seconds,
                                signing_seconds=config.service_signing.signing_timeout_seconds,
                                vote_seconds=config.review_timeout_seconds,
                            ).effective()
                        ),
                        "managed_service_path_qualified": False,
                    }
                )
            )
            return
        for name in (
            "umi.competition_cohort_review_boot",
            "umi.competition_cohort_benchmark_host",
            "umi.competition_cohort_endpoint_retirement",
            "umi.competition_cohort_grant_delivery",
            "umi.competition.progress",
        ):
            logger = logging.getLogger(name)
            loggers.append((logger, logger.level, logger.propagate))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
        asyncio.run(_run(config))
    except Exception as error:
        report = {"status": "failed", "error_type": type(error).__name__}
        reason_code = getattr(error, "reason_code", None)
        if reason_code in {
            "primary_finality_observer_stopped",
            "endpoint_finality_observer_stopped",
            "phase_review_listener_stopped",
            "benchmark_execution_worker_stopped",
            "benchmark_exports_worker_stopped",
            "benchmark_endpoints_worker_stopped",
        }:
            report["reason_code"] = reason_code
        report["details"] = _failure_details(error)
        print(json.dumps(report))
        raise SystemExit(1) from None
    finally:
        for logger, level, propagate in loggers:
            logger.removeHandler(handler)
            logger.setLevel(level)
            logger.propagate = propagate
        handler.close()


if __name__ == "__main__":
    main()
