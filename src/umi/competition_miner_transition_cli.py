"""Inspect stopped original miner state without authorizing a revision switch."""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
import time
from pathlib import Path

from .competition_miner_transition import (
    MinerRevisionPreflightRequest,
    preflight_revision_transition,
)
from .competition_miner_transition_io import bounded_read
from .protocol import canonical_json_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--request",
        required=True,
        type=Path,
        help="Private canonical preflight request; never an activation instruction",
    )
    parser.add_argument(
        "--verification-repair-reason",
        help="Explicitly repair missing/damaged derived verification metadata",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    started = time.monotonic()
    try:
        request = MinerRevisionPreflightRequest.model_validate_json(
            bounded_read(args.request, 1048576)
        )
        result = preflight_revision_transition(
            request, repair_reason=args.verification_repair_reason
        )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        print(
            json.dumps(
                {
                    "schema": "umi-miner-revision-preflight-refusal/1",
                    "state": "refused",
                    "reason": str(error),
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "eta_seconds": None,
                    "eta_basis": "refused_requires_explicit_resolution",
                    "stalled": True,
                    "retrying": False,
                    "runtime_migration_authorized": False,
                }
            ),
            file=sys.stderr,
        )
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
