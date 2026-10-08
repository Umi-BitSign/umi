"""Completed retirement releases execution capacity, not historical policy counters."""

from dataclasses import replace

import pytest

from umi.config import Limits
from umi.endpoint_retirement import SignedEndpointRetirementReceipt
from umi.miner_resources import MinerResourceError, SQLiteMinerResourceLedger
from umi.open_competition import sign_object

from .factories import dev_wallet
from .test_miner_resources import POLICY_HASH, SIGNATURE, custom_binding


def store(tmp_path, **overrides):
    return SQLiteMinerResourceLedger(
        tmp_path / "resources.sqlite3",
        miner_hotkey=dev_wallet("//Bob").hotkey.ss58_address,
        scoring_policy_sha256=POLICY_HASH,
        limits=replace(Limits(), **overrides),
        maximum_recovery_assignments=8,
    )


def seal(ledger, assignment, *, pending=False):
    grant = "fa" * 32
    ledger.request_retirement(assignment, grant)
    body = ledger.prepare_retirement(assignment, grant)
    value = SignedEndpointRetirementReceipt(
        receipt=body, signature=sign_object(body, dev_wallet("//Bob"))
    )
    if pending:
        with pytest.raises(MinerResourceError, match="retirement_work_pending"):
            ledger.commit_retirement_receipt(assignment, value)
    else:
        ledger.commit_retirement_receipt(assignment, value)
    return value


def test_pending_resource_operation_cannot_release_window_capacity(tmp_path):
    ledger = store(tmp_path)
    try:
        first = custom_binding(1)
        other = custom_binding(2, window_id="30" * 32)
        ledger.record_request(first, observed_wire_bytes=1)
        operation = ledger.begin_video_fetch(first)
        sealed = seal(ledger, first, pending=True)
        assert ledger.retirement_receipt(first, "fa" * 32) is None
        with pytest.raises(MinerResourceError, match="active_window_limit"):
            ledger.record_request(other, observed_wire_bytes=1)
        ledger.finish_video_fetch(operation, observed_wire_bytes=0, error_code="fetch_failed")
        ledger.commit_retirement_receipt(first, sealed)
        assert ledger.record_request(other, observed_wire_bytes=1) is None
    finally:
        ledger.close()


def test_retired_assignments_keep_per_window_budget_across_restart(tmp_path):
    ledger = store(tmp_path, maximum_assignments_per_validator_window=2)
    try:
        for index in (1, 2):
            assignment = custom_binding(index)
            ledger.record_request(assignment, observed_wire_bytes=1)
            ledger.record_response(assignment, body=b"{}", signature=SIGNATURE)
            seal(ledger, assignment)
        ledger.close()
        ledger = store(tmp_path, maximum_assignments_per_validator_window=2)
        with pytest.raises(MinerResourceError, match="assignment_count_limit"):
            ledger.record_request(custom_binding(3), observed_wire_bytes=1)
        assert (
            ledger.record_request(custom_binding(4, window_id="30" * 32), observed_wire_bytes=1)
            is None
        )
        assert ledger.snapshot(custom_binding(1)).request_transmissions == 1
        assert ledger.snapshot(custom_binding(2)).response_bodies == 1
    finally:
        ledger.close()


def test_sealed_retirement_does_not_release_shared_active_window(tmp_path):
    ledger = store(tmp_path)
    try:
        first, shared = custom_binding(1), custom_binding(2)
        ledger.record_request(first, observed_wire_bytes=1)
        ledger.record_request(shared, observed_wire_bytes=1)
        # Resource declaration has no cache yet; releasing one assignment still
        # cannot release this window while another assignment has live work.
        seal(ledger, first)
        with pytest.raises(MinerResourceError, match="active_window_limit"):
            ledger.record_request(custom_binding(3, window_id="30" * 32), observed_wire_bytes=1)
        assert ledger.snapshot(shared).request_transmissions == 1
    finally:
        ledger.close()
