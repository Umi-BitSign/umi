"""Eleven original identities; real native grants, responses, seals and closures."""

import pytest

from umi.competition_cohort_endpoint_archive import EndpointReplayArchive
from umi.competition_cohort_endpoint_decision import parse_case_review
from umi.competition_cohort_endpoint_terminal import EndpointTerminalSelection
from umi.competition_cohort_execution_journal import CohortExecutionAssignment
from umi.competition_cohort_request_inventory import RequestInventory, SignedRequestInventory
from umi.competition_cohort_request_partial import (
    PartialEndpointResponse,
    PartialExecutionStep,
    PartialRequestManifest,
)
from umi.competition_cohort_request_tail import (
    MINIMUM_REQUEST_OPEN_MS,
    RequestTailObservation,
    original_request_miners,
)
from umi.competition_cohort_request_terminal import RequestExecutionArchive
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_order_signer as order_fixtures
from . import test_competition_cohort_service_grants as service_fixtures
from .test_competition_execution import boundary
from .test_open_competition import wallet


@pytest.fixture
def tail_harness(scenario, tmp_path, monkeypatch):
    original = order_fixtures.make_round

    def expanded(*args, **kwargs):
        return original(
            *args,
            **kwargs,
            participant_names=("Alice", "Bob", *(f"Tail{i}" for i in range(9))),
        )

    monkeypatch.setattr(order_fixtures, "make_round", expanded)
    native = order_fixtures.harness.__wrapped__(scenario, tmp_path)
    return service_fixtures.harness.__wrapped__(native)


def tail_observation(b, unfinished=()):
    opened = next(
        t.transition for t in b["history"].transitions if t.transition.phase == "preparation"
    )
    return RequestTailObservation(
        schema="umi-cohort-request-tail-observation/1",
        opened_observation=b["decisions"][opened.evidence_sha256].observation,
        opened_timestamp_ms=1000,
        selected_observation=boundary(b["closure"].observation.block - 1),
        selected_timestamp_ms=1000 + MINIMUM_REQUEST_OPEN_MS,
        observation=b["closure"].observation,
        observed_timestamp_ms=1001 + MINIMUM_REQUEST_OPEN_MS,
        original_hotkeys=original_request_miners(b["roster"]),
        unfinished_hotkeys=tuple(sorted(unfinished)),
    )


def inventory_original(b, manifest_sha256, observation):
    """Sign a native partial snapshot with its exact original evaluator."""
    manifest = PartialRequestManifest.model_validate_json(b["objects"][manifest_sha256])
    assignment = CohortExecutionAssignment.model_validate_json(
        b["objects"][manifest.assignment_sha256]
    )
    evaluator = identity(assignment.delivery.receipt.evaluator_hotkey)
    signer = next(
        wallet(name)
        for name in ("Charlie", "Dave")
        if identity(wallet(name).hotkey.ss58_address) == evaluator
    )
    body = RequestInventory(
        schema="umi-cohort-request-inventory/1",
        assignment_sha256=manifest.assignment_sha256,
        policy_sha256=digest(b["policy"]),
        manifest_sha256=manifest_sha256,
        observation=observation,
    )
    signed = SignedRequestInventory(inventory=body, signature=sign_object(body, signer))
    key = digest(signed)
    b["objects"][key] = canonical_json_bytes(signed)
    return key


def partial_original(b, order, evaluator, *, retain_response=False):
    """One genuine retained execution step from an incomplete evaluator inventory."""
    terminal = b["terminals"][(digest(order), identity(evaluator))].terminal
    archive = RequestExecutionArchive.model_validate_json(
        b["objects"][terminal.execution_archive_sha256]
    )
    responses = ()
    if retain_response and terminal.endpoint_archive_sha256 is not None:
        endpoint = EndpointReplayArchive.model_validate_json(
            b["objects"][terminal.endpoint_archive_sha256]
        )
        selection = EndpointTerminalSelection.model_validate_json(
            b["objects"][endpoint.terminal_sha256]
        )
        case = selection.cases[0]
        review = parse_case_review(b["objects"][case.review_sha256])
        assert review.recovered is not None
        for original in (review.selection, review.recovered):
            b["objects"][digest(original)] = canonical_json_bytes(original)
        responses = (
            PartialEndpointResponse(
                case_id=case.case_id,
                selection_sha256=digest(review.selection),
                response_sha256=digest(review.recovered),
            ),
        )
    manifest = PartialRequestManifest(
        schema="umi-cohort-partial-request/1",
        assignment_sha256=terminal.assignment_sha256,
        steps=(PartialExecutionStep(index=0, sha256=archive.steps[0]),),
        cases=(),
        responses=responses,
    )
    key = digest(manifest)
    b["objects"][key] = canonical_json_bytes(manifest)
    return key
