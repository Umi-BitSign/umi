"""Export native completed model byte facts for an explicitly selected old layout.

Run as the existing source service account with a root-controlled request. The
result grants no signing/adoption authority. Install its exact export pins in the
new account-private shared store selection before starting consumers.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_model_delivery_candidate import (
    ModelDeliveryAdoptionCandidate,
    ModelDeliveryAdoptionCandidateConfig,
)
from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_host_activation import _read_root_control_path
from .open_competition import CompetitionPolicy
from .protocol import StrictProtocolModel, canonical_json_bytes


class ModelByteStoreExportRequest(StrictProtocolModel):
    schema_: Literal["umi-model-byte-store-export-request/1"] = Field(alias="schema")
    candidate: ModelDeliveryAdoptionCandidateConfig
    policy: CompetitionPolicy
    history: CohortRecoveryHistory
    transition: CohortRecoveryTransition


async def export_request(request, *, seed_shared=False):
    candidate = ModelDeliveryAdoptionCandidate(request.candidate, request.policy)
    if seed_shared:
        await candidate.seed_shared_completed(request.history, request.transition)
        return ()
    return await candidate.export_completed(request.history, request.transition)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["export", "seed-shared"])
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    raw = _read_root_control_path(args.request, 64 * 1024**2, modes={0o444})
    request = ModelByteStoreExportRequest.model_validate_json(raw)
    if canonical_json_bytes(request) != raw:
        raise ValueError("model byte export request must retain canonical selected inputs")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    exports = asyncio.run(export_request(request, seed_shared=args.operation == "seed-shared"))
    print(
        canonical_json_bytes(
            {
                "imports": [v.model_dump(mode="json") for v in exports],
                "certification_authority": False,
                "shared_file_seed_completed": args.operation == "seed-shared",
            }
        ).decode()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
