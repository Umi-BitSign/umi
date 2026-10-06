"""Clock linkage and immutable legacy witness compatibility."""

from dataclasses import replace

import pytest

from umi.competition_cohort_attempt_clock import cohort_attempt_schedule
from umi.competition_cohort_request_window import EndpointRequestWindow, RetainedRequestBlock
from umi.endpoint_retirement import (
    EndpointRetirementReceipt,
    ExpiredOpportunityRetirementReceipt,
    retirement_absence_elapsed,
)
from umi.protocol import canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_miner_admission import _case
from .test_open_competition import wallet


@pytest.mark.parametrize("delay_ms", [0, 1, 2999, 10 * 3600_000, 7 * 86400_000])
def test_both_deadlines_have_one_issuance_and_budget(delay_ms):
    policy, request, blocks = _case()
    issuance = replace(
        blocks.blocks[request.issued_block],
        timestamp_ms=blocks.blocks[request.issued_block].timestamp_ms + delay_ms,
    )
    schedule = cohort_attempt_schedule(
        policy, issuance, cohort_sha256="12" * 32, job_sha256="34" * 32, attempt_number=2
    )
    nominal_ms = (
        schedule.response_deadline_blocks * policy.clock.target_block_interval_seconds * 1000
    )
    round_ms = QUICKNET_GENESIS_MS + (schedule.response_close_round - 1) * QUICKNET_PERIOD_MS
    assert 0 <= round_ms - issuance.timestamp_ms - nominal_ms < QUICKNET_PERIOD_MS
    assert schedule.reveal_round > schedule.response_close_round


@pytest.mark.parametrize("field", ["cohort_sha256", "job_sha256", "attempt_number"])
def test_window_cannot_move_to_another_authorized_attempt(field):
    policy, request, blocks = _case()
    issuance = blocks.blocks[request.issued_block]
    context = dict(cohort_sha256="12" * 32, job_sha256="34" * 32, attempt_number=2)
    original = cohort_attempt_schedule(policy, issuance, **context)
    context[field] = 3 if field == "attempt_number" else "56" * 32
    changed = cohort_attempt_schedule(policy, issuance, **context)
    assert changed.window_id != original.window_id


def test_legacy_request_witness_keeps_exact_bytes_and_derivation():
    policy, request, blocks = _case()
    witness = EndpointRequestWindow(
        announcement=RetainedRequestBlock.capture(blocks.blocks[policy.activation_block]),
        issuance=RetainedRequestBlock.capture(blocks.blocks[request.issued_block]),
    )
    encoded = canonical_json_bytes(witness)
    recovered = EndpointRequestWindow.model_validate_json(encoded)
    recovered.check(request, policy)
    assert canonical_json_bytes(recovered) == encoded
    assert set(recovered.model_dump()) == {"announcement", "issuance"}


def test_extension_does_not_relax_legacy_absence_expiry():
    _, request, _ = _case()
    # The predicate follows signature/binding verification; these receipts are
    # deliberately unsigned calculation inputs, not authoritative evidence.
    fields = dict(
        grant_sha256="12" * 32,
        request_digest="34" * 32,
        miner_hotkey=wallet("Alice").hotkey.ss58_address,
        evaluator_hotkey=wallet("Bob").hotkey.ss58_address,
        response_sha256=None,
    )
    old = EndpointRetirementReceipt(
        schema="umi-endpoint-retirement/1", result="no_response_retained", **fields
    )
    fence = ExpiredOpportunityRetirementReceipt(
        schema="umi-endpoint-retirement/2", result="expired_response_opportunity", **fields
    )
    early = dict(observed_block=request.issued_block, observed_round=request.response_close_round)
    assert not retirement_absence_elapsed(old, request, **early)
    assert retirement_absence_elapsed(fence, request, **early)
    assert not retirement_absence_elapsed(
        fence,
        request,
        observed_block=request.issued_block,
        observed_round=request.response_close_round - 1,
    )
    assert retirement_absence_elapsed(
        old,
        request,
        observed_block=request.deadline_block + 1,
        observed_round=request.response_close_round,
    )
