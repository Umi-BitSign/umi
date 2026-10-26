"""Prepare private diverse suite candidates; never sign or alter a cohort."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Literal

from pydantic import Field, RootModel

from .competition_progress import configure_progress_logging
from .competition_suite_selection import (
    SuiteCandidateInventory,
    SuiteExclusions,
    SuiteSelectionCounts,
    select_future_suite,
)
from .competition_transport_verification import TransferProgress
from .open_competition import CompetitionPolicy, EvaluationSuite, digest
from .private_files import _read_private_bytes, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class SuiteSelectionReport(RootModel[dict]):
    pass


class PreparedSuiteSelection(StrictProtocolModel):
    schema_: Literal["umi-private-suite-selection-preparation/1"] = Field(alias="schema")
    input_bindings: dict[str, Hex32]
    suite: EvaluationSuite
    report: SuiteSelectionReport


def prepare(args):
    inventory = read_private_model(args.inventory, SuiteCandidateInventory)
    exclusions = read_private_model(args.exclusions, SuiteExclusions)
    counts = read_private_model(args.counts, SuiteSelectionCounts)
    policy = read_private_model(args.policy, CompetitionPolicy)
    key = _read_private_bytes(args.selection_key, maximum_bytes=32)
    bindings = dict(
        inventory=digest(inventory),
        exclusions=digest(exclusions),
        counts=digest(counts),
        policy=digest(policy),
        selection_key=hashlib.sha256(key).hexdigest(),
    )
    path = args.destination / "preparation.json"
    if path.exists():
        prepared = read_private_model(path, PreparedSuiteSelection)
        if prepared.input_bindings != bindings:
            raise ValueError("retained suite preparation has different original inputs")
        reused = True
    else:
        with TransferProgress(
            "future_suite_candidate_review",
            len(inventory.cases),
            unit="metadata_records",
            planning_unit_seconds=(0.00001, 0.05),
        ) as progress:
            suite, report = select_future_suite(
                inventory,
                exclusions,
                counts,
                policy,
                selection_key=key,
                observed=lambda: progress.advance(1),
            )
        prepared = PreparedSuiteSelection(
            schema="umi-private-suite-selection-preparation/1",
            input_bindings=bindings,
            suite=suite,
            report=SuiteSelectionReport(report),
        )
        publish_private_model(path, prepared)
        reused = False
    # Exact retry restores interrupted output publication from its completed
    # preparation without repeating candidate selection or touching any media.
    publish_private_model(args.destination / "suite.json", prepared.suite)
    publish_private_model(args.destination / "selection-report.json", prepared.report)
    return dict(
        status="unsigned_future_suite_prepared",
        suite_sha256=digest(prepared.suite),
        selection_manifest_sha256=digest(prepared.report),
        cases=len(prepared.suite.cases),
        reused_preparation=reused,
        production_state_changed=False,
        unknown_or_public_exposure_is_not_verified_holdout=(
            prepared.report.root["unknown_or_public_exposure_is_not_verified_holdout"]
        ),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "exclusions", "counts", "policy", "selection-key", "destination"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    configure_progress_logging()
    try:
        result = prepare(args)
    except (ValueError, OSError, RuntimeError) as error:
        # Validation details can contain private references and source identities.
        parser.exit(2, f"suite selection rejected ({type(error).__name__}); check private inputs\n")
    print(canonical_json_bytes(result).decode())


if __name__ == "__main__":
    main()
