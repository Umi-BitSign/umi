"""Publish or serve read-only public cohort results without a validator wallet."""

from __future__ import annotations

import argparse
import fcntl
import json
import logging
import os
from pathlib import Path

from .competition_cohort_public_api import CohortPublicApiConfig, create_cohort_public_app
from .competition_cohort_public_publisher import CohortPublicPublisherConfig, publish_native_cohort
from .competition_public_results_directory import owned_directory, read_owned_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("publish", "serve"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8108)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        raw = read_owned_file(args.config, 16 * 1024**2)
        if args.operation == "serve":
            import uvicorn

            config = CohortPublicApiConfig.model_validate_json(raw)
            uvicorn.run(
                create_cohort_public_app(config),
                host="127.0.0.1",
                port=args.port,
                access_log=False,
                limit_concurrency=config.maximum_concurrent_reads + 8,
            )
            return 0
        config = CohortPublicPublisherConfig.model_validate_json(raw)
        root = Path(config.api.results.directory)
        owned_directory(root, create=True)
        fd = os.open(root / ".publisher.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            report = publish_native_cohort(config)
        finally:
            os.close(fd)
        print(json.dumps(report, sort_keys=True), flush=True)
        return 0
    except (ValueError, OSError) as error:
        print(
            json.dumps(
                {
                    "status": "held",
                    "error_type": type(error).__name__,
                    "reason": str(error),
                    "chain_submission_authorized": False,
                }
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
