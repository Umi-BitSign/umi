"""Download a public model from renewable cohort API capabilities."""

import argparse
import json
import sqlite3
from pathlib import Path

from .competition_cohort_public_download_client import PublicDownloadError, download_model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", required=True, help="HTTPS API origin")
    parser.add_argument("--cohort", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--timeout", type=float, default=60, help="Per-request idle timeout seconds"
    )
    parser.add_argument("--refresh-attempts", type=int, default=3)
    parser.add_argument(
        "--repair-file", action="append", default=[], help="Explicitly redownload one manifest path"
    )
    args = parser.parse_args()
    try:
        download_model(
            args.api,
            args.cohort,
            args.model,
            args.output,
            timeout=args.timeout,
            refresh_attempts=args.refresh_attempts,
            repair_files=args.repair_file,
            report=lambda event: print(json.dumps(event), flush=True),
        )
        return 0
    except (PublicDownloadError, OSError, sqlite3.Error):
        # Neither provider responses nor capability-bearing exception chains are
        # suitable for console output. Progress already identifies the substage.
        print(
            json.dumps(
                {"status": "repair_or_retry_required", "reason": "public_model_download_incomplete"}
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
