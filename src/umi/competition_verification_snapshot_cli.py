"""Prepare, inspect or explicitly repair private package verification state.

Run under the consuming service account with its existing source and store paths.
This command neither signs evidence nor grants reward or chain authority.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_cohort_settlement_inputs import SettlementInputPackage
from .competition_evidence_codec import checked_digest
from .competition_verification_snapshot import (
    VerificationPackageStore,
    VerificationSnapshotRepairRequired,
    VerificationSnapshotUnavailable,
)
from .private_files import PrivateStateBusyError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("prepare", "check", "repair"))
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--kind", required=True, choices=("reward", "settlement"))
    parser.add_argument("--maximum-bytes", required=True, type=int)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--reason", help="Explicit nonempty operator reason for repair")
    args = parser.parse_args(argv)
    if args.action == "repair":
        if not args.reason or not args.reason.strip():
            parser.error("repair requires a nonempty --reason")
    elif args.reason is not None:
        parser.error("--reason requires the repair action")
    handler = logging.StreamHandler()
    logger = logging.getLogger("umi.competition.progress")
    previous = logger.level, logger.propagate
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        checked_digest(args.package_sha256)
        store = VerificationPackageStore(args.store)
        method = {
            "prepare": store.load,
            "check": store.load_existing,
            "repair": store.repair,
        }[args.action]
        options = dict(
            maximum_bytes=args.maximum_bytes,
            expected_sha256=args.package_sha256,
        )
        if args.action == "repair":
            options["reason"] = args.reason
        snapshot = method(
            args.source,
            CohortRewardPackage if args.kind == "reward" else SettlementInputPackage,
            **options,
        )
        print(
            json.dumps(
                dict(
                    status="ready",
                    action=args.action,
                    package_sha256=snapshot.sha256,
                    objects=len(snapshot.records),
                    certification_authority=False,
                )
            )
        )
    except Exception as error:
        status = "failed"
        if isinstance(error, VerificationSnapshotRepairRequired):
            status = "repair_required"
        elif isinstance(error, VerificationSnapshotUnavailable):
            status = "preparation_required"
        elif isinstance(error, PrivateStateBusyError):
            status = "owner_busy"
        print(json.dumps(dict(status=status, error_type=type(error).__name__)))
        raise SystemExit(1) from None
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous[0])
        logger.propagate = previous[1]
        handler.close()


if __name__ == "__main__":
    main()
