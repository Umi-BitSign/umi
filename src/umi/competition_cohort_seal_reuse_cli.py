"""Repair derived intake seal metadata without changing original signed evidence."""

import argparse
import json
from pathlib import Path

from .competition_cohort_intake import CohortIntake
from .competition_service import CompetitionServiceConfig
from .open_competition import CompetitionPolicy, digest
from .private_files import read_private_model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-config", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--cohort", required=True)
    parser.add_argument("--tip", required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    config = read_private_model(Path(args.service_config), CompetitionServiceConfig)
    policy = read_private_model(Path(args.policy), CompetitionPolicy)
    if config.recoverable_intake is None or config.policy_sha256 != digest(policy):
        raise ValueError("seal repair requires the exact selected intake policy and config")
    intake = CohortIntake(
        config.recoverable_intake,
        policy,
        eligible_tracks=config.public_deployment.eligible_tracks,
        capacity=config.admission_capacity,
    )
    result = intake.repair_seal_reuse(args.cohort, args.tip, reason=args.reason)
    print(
        json.dumps(
            {
                "stage": "intake_seal_verification_repaired",
                "completed": 1,
                "total": 1,
                "eta_seconds": 0,
                "eta_basis": "completed_exact_seal_scope",
                "seal_sha256": digest(result),
                "signed_evidence_changed": False,
                "certification_authority": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
