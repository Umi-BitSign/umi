"""Resume the exact previously published evidence runtime on the Linux host."""

import argparse
import json
import subprocess
from pathlib import Path

from .competition_evidence_resume import resume_selected_evidence_service


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--transaction-root", type=Path, required=True)
    parser.add_argument("--startup-timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    try:
        result = resume_selected_evidence_service(
            config_path=args.config,
            unit_name=args.unit,
            transaction_root=args.transaction_root,
            startup_timeout_seconds=args.startup_timeout_seconds,
        )
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "evidence_service_recovery_failed",
                    "service_state": "unconfirmed",
                    "chain_submission_authorized": False,
                }
            )
        )
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
