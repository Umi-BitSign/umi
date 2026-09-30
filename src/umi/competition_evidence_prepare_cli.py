"""Wallet-free command for stopped evidence preparation; never selects a runtime."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .competition_evidence_prepare import prepare_legacy_candidate
from .competition_evidence_store import EvidenceBudget
from .competition_evidence_worker import EvidenceWorkerProfile
from .competition_worker import _open_private_regular_file
from .protocol import canonical_json_bytes


def main() -> None:
    """Offline, wallet-free preparation. This command never selects a runtime."""
    parser = argparse.ArgumentParser(
        description="Prepare retained evidence from a stopped journal without activating it."
    )
    parser.add_argument(
        "--plan", type=Path, required=True, help="private canonical preparation-plan/1 JSON"
    )
    parser.add_argument("--resume", action="store_true", help="resume only the exact recorded plan")
    args = parser.parse_args()
    descriptor = _open_private_regular_file(args.plan, "offline evidence plan")
    try:
        raw = os.read(descriptor, 16 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(raw) > 16 * 1024:
        raise ValueError("offline evidence plan exceeds bound")
    plan = json.loads(raw)
    keys = {
        "schema",
        "source_root",
        "candidate_root",
        "expected_source_sha256",
        "expected_binding_sha256",
        "profile",
        "maximum_database_bytes",
        "minimum_free_bytes",
    }
    if (
        not isinstance(plan, dict)
        or set(plan) != keys
        or plan["schema"] != "umi-weight-evidence-preparation-plan/1"
        or canonical_json_bytes(plan) != raw
    ):
        raise ValueError("offline evidence plan is not the exact canonical schema")
    profile = plan["profile"]
    if not isinstance(profile, dict) or set(profile) != {"limits", "recovery_observations"}:
        raise ValueError("offline evidence profile changed")
    result = prepare_legacy_candidate(
        Path(plan["source_root"]),
        Path(plan["candidate_root"]),
        expected_source_sha256=plan["expected_source_sha256"],
        expected_binding_sha256=plan["expected_binding_sha256"],
        profile=EvidenceWorkerProfile(
            EvidenceBudget(**profile["limits"]), profile["recovery_observations"]
        ),
        maximum_database_bytes=plan["maximum_database_bytes"],
        minimum_free_bytes=plan["minimum_free_bytes"],
        resume=args.resume,
    )
    print(canonical_json_bytes(result).decode())


if __name__ == "__main__":
    main()
