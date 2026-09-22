"""Export newly retained settlement scores without signing or weight authority."""

from __future__ import annotations

import argparse
import json
import signal
import sqlite3
import threading
from pathlib import Path

from .competition_public_results_publisher import (
    PublicResultsPublisher,
    PublicResultsPublisherConfig,
    read_config_file,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--watch",
        action="store_true",
        help="poll until SIGTERM/SIGINT; finish current bounded batch",
    )
    args = parser.parse_args()
    stop = threading.Event()
    if args.watch:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
    try:
        config = PublicResultsPublisherConfig.model_validate_json(read_config_file(args.config))
        publisher = PublicResultsPublisher(config)
        while True:
            try:
                report = publisher.poll_once()
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                report = dict(
                    status="held",
                    error_type=type(error).__name__,
                    chain_submission_authorized=False,
                )
            print(json.dumps(report, sort_keys=True), flush=True)
            if not args.watch:
                return 1 if report.get("held") or report.get("status") == "held" else 0
            if stop.wait(config.poll_seconds):
                return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(
            json.dumps(
                dict(
                    status="held",
                    error_type=type(error).__name__,
                    chain_submission_authorized=False,
                )
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
