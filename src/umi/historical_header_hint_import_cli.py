"""Transfer untrusted hints into an existing cache as its account; no provider."""

from __future__ import annotations

import argparse
import json
import signal
import sqlite3
import threading
from pathlib import Path

from .historical_header_hint_import import HeaderHintImport


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target-directory", type=Path, required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--maximum-bytes", type=int, required=True)
    parser.add_argument("--maximum-database-bytes", type=int, required=True)
    parser.add_argument("--batch-size", type=int, default=256)
    args = parser.parse_args(argv)
    stop = threading.Event()
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, lambda *_: stop.set())
    importer = None
    latest = {
        "processed_headers": 0,
        "total_headers": None,
        "inserted_headers": 0,
        "reused_headers": 0,
    }
    try:
        importer = HeaderHintImport(
            args.source,
            args.target_directory,
            operation=args.operation,
            maximum_bytes=args.maximum_bytes,
            maximum_database_bytes=args.maximum_database_bytes,
            batch_size=args.batch_size,
        )
        while not stop.is_set():
            try:
                latest = importer.step()
            except sqlite3.OperationalError as error:
                code = getattr(error, "sqlite_errorcode", 0) & 0xFF
                capacity = (
                    code == sqlite3.SQLITE_FULL
                    or str(error) == "header hint payload capacity required"
                )
                if code not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} and not capacity:
                    raise
                state = "capacity_required" if capacity else "retrying"
                value = importer._progress(
                    latest["processed_headers"],
                    latest["total_headers"],
                    latest["inserted_headers"],
                    latest["reused_headers"],
                    state=state,
                    reason="selected_capacity_required" if capacity else "sqlite_writer_busy",
                )
                print(json.dumps(value), flush=True)
                if capacity:
                    raise SystemExit(2) from None
                stop.wait(1.0)
                continue
            print(json.dumps(latest), flush=True)
            if latest["state"] == "completed":
                return
            # Give the active provider a scheduling opportunity between short
            # additive transactions; signals do not interrupt a committed batch.
            stop.wait(0.01)
        print(
            json.dumps(
                {
                    **latest,
                    "state": "stopped",
                    "eta_seconds": None,
                    "planning_eta_seconds": None,
                    "eta_basis": "withdrawn_stopped",
                    "finality_authority": False,
                }
            ),
            flush=True,
        )
        raise SystemExit(130)
    except Exception as error:
        print(
            json.dumps(
                {
                    "stage": "untrusted_header_hint_import",
                    "state": "repair_required",
                    "error_type": type(error).__name__,
                    "finality_authority": False,
                    "eta_seconds": None,
                    "eta_basis": "withdrawn_repair_required",
                }
            ),
            flush=True,
        )
        raise SystemExit(1) from None
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    main()
