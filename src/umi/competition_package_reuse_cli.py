"""Explicitly repair derived package-verification metadata under its native bounds."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_package import (
    CompetitionPackageLimits,
    CompetitionReleaseIdentity,
    load_competition_package,
)
from .competition_package_reuse import package_verification_session
from .competition_work_progress import WorkProgress
from .private_files import Directory, read_private_model
from .protocol import Hex32, StrictProtocolModel


class PackageVerificationRepairRequest(StrictProtocolModel):
    schema_: Literal["umi-package-verification-repair/1"] = Field(alias="schema")
    directory: Directory
    package_path: Directory
    expected_package_sha256: Hex32
    expected_policy_sha256: Hex32
    observed_release: CompetitionReleaseIdentity
    limits: CompetitionPackageLimits


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["repair"])
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    if not args.reason.strip():
        parser.error("repair requires a nonempty operator reason")
    request = read_private_model(
        args.request, PackageVerificationRepairRequest, maximum_bytes=65536
    )
    with (
        WorkProgress("package_verification_repair", 1, unit="packages") as progress,
        package_verification_session(directory=Path(request.directory), repair_reason=args.reason),
    ):
        value = load_competition_package(
            Path(request.package_path),
            expected_package_sha256=request.expected_package_sha256,
            expected_policy_sha256=request.expected_policy_sha256,
            observed_release=request.observed_release,
            limits=request.limits,
        )
        progress.advance()
    print(
        json.dumps(
            {
                "package_sha256": value.package_sha256,
                "manifest_sha256": value.manifest_sha256,
                "certification_authority": False,
                "chain_submission_authorized": False,
                "reason": args.reason,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
