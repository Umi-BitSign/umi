"""Explicit bounded repair of a service queue's private registration pin metadata."""

import argparse
import json
from pathlib import Path

from .competition_cohort_service_queue import ServiceWorkQueue, ServiceWorkQueueConfig
from .open_competition import CompetitionPolicy
from .private_files import read_private_model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue-config", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    config = read_private_model(Path(args.queue_config), ServiceWorkQueueConfig)
    policy = read_private_model(Path(args.policy), CompetitionPolicy)
    ServiceWorkQueue(config, policy, repair_registration_pins_reason=args.reason)
    print(
        json.dumps(
            {
                "stage": "registration_pin_metadata_repaired",
                "completed": 1,
                "total": 1,
                "eta_seconds": 0,
                "eta_basis": "completed_metadata_scope",
                "native_projection_resumes_in_owner": True,
                "signed_evidence_changed": False,
                "registration_authority": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    main()
