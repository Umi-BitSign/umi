"""Operator boundary for the preserving original-local-export history upgrade."""

import argparse
import json
import logging
import signal
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .competition_reward_admission_provenance import _canonical
from .competition_reward_history_origin import (
    capture_original_export_origin,
    load_original_export_origin,
)
from .competition_reward_history_origin_migration import migrate_original_export_history


@contextmanager
def _migration_signals():
    stop = threading.Event()
    saved = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        for number in saved:
            signal.signal(number, lambda *_: stop.set())
        yield stop
    finally:
        for number, previous in saved.items():
            signal.signal(number, previous)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    capture = actions.add_parser("capture")
    capture.add_argument("--original-owner", required=True, type=Path)
    capture.add_argument("--through-block", required=True, type=int)
    capture.add_argument("--select-exclusive-original-namespace", action="store_true")
    check = actions.add_parser("check")
    check.add_argument("--origin", required=True, type=Path)
    migrate = actions.add_parser("migrate")
    migrate.add_argument("--origin", required=True, type=Path)
    migrate.add_argument("--maximum-history-bytes", required=True, type=int)
    migrate.add_argument("--maximum-blocks", type=int)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    started, completed = time.monotonic(), False
    if args.action != "migrate":
        logging.info(
            "original_export_origin_progress %s",
            {
                "stage": args.action,
                "state": "running",
                "completed_items": 0,
                "total_items": 1,
                "percent": 0,
                "elapsed_seconds": 0,
                "eta_seconds": None,
                "planning_eta_seconds": [1, 30],
                "eta_basis": "bounded_local_installation_metadata",
            },
        )
    try:
        if args.action == "capture":
            print(
                _canonical(
                    capture_original_export_origin(
                        args.original_owner,
                        through_block=args.through_block,
                        exclusive_original_namespace=args.select_exclusive_original_namespace,
                    )
                ).decode()
            )
        elif args.action == "check":
            value, _ = load_original_export_origin(args.origin)
            print(
                json.dumps(
                    {
                        "status": "original_export_origin_selected",
                        "first_block": value["first_block"],
                        "through_block": value["through_block"],
                        "aggregate_completion_claimed": False,
                    }
                )
            )
        else:
            with _migration_signals() as stop:
                result = migrate_original_export_history(
                    args.origin,
                    maximum_history_bytes=args.maximum_history_bytes,
                    maximum_blocks=args.maximum_blocks,
                    stop_requested=stop,
                )
            print(json.dumps(result, sort_keys=True))
        completed = True
    finally:
        if args.action != "migrate":
            logging.info(
                "original_export_origin_progress %s",
                {
                    "stage": args.action,
                    "state": "completed" if completed else "repair_required",
                    "completed_items": int(completed),
                    "total_items": 1,
                    "percent": 100 if completed else 0,
                    "elapsed_seconds": time.monotonic() - started,
                    "eta_seconds": 0 if completed else None,
                    "eta_basis": "complete" if completed else "withdrawn_repair_required",
                },
            )


if __name__ == "__main__":
    main()
