from __future__ import annotations

from fractions import Fraction

import pytest

from umi.resources import (
    DeadlineStage,
    PreflightBound,
    ResourceLedger,
    ResourceLimitExceeded,
    audit_bundle_bytes,
    nearest_rank_percentile,
    retained_storage_bytes,
)


def test_failed_assignment_charge_rolls_back_both_assignment_and_window_totals() -> None:
    ledger = ResourceLedger(
        maximum_assignment_wire_bytes=5,
        maximum_window_wire_bytes=10,
    )
    ledger.charge(4, assignment_id="assignment-a")
    before = ledger.snapshot()

    with pytest.raises(ResourceLimitExceeded, match="assignment wire-byte"):
        ledger.charge(2, assignment_id="assignment-a")

    assert ledger.snapshot() == before
    ledger.charge(6)
    assert ledger.snapshot().window_wire_bytes == 10


def test_failed_window_charge_rolls_back_assignment_and_attempt_limits_do_not_increment() -> None:
    ledger = ResourceLedger(
        maximum_assignment_wire_bytes=20,
        maximum_window_wire_bytes=5,
    )
    ledger.charge(5, assignment_id="assignment-a")
    before = ledger.snapshot()
    with pytest.raises(ResourceLimitExceeded, match="window wire-byte"):
        ledger.charge(1, assignment_id="assignment-b")
    assert ledger.snapshot() == before

    assert ledger.begin_attempt("video:abc", maximum_attempts=1) == 1
    before_attempt = ledger.snapshot()
    with pytest.raises(ResourceLimitExceeded, match="attempt ceiling"):
        ledger.begin_attempt("video:abc", maximum_attempts=1)
    assert ledger.snapshot() == before_attempt


def test_resource_snapshot_is_sorted_and_zero_byte_charges_are_accounted_canonically() -> None:
    ledger = ResourceLedger(
        maximum_assignment_wire_bytes=10,
        maximum_window_wire_bytes=20,
    )
    ledger.charge(2, assignment_id="z")
    ledger.charge(0, assignment_id="a")
    ledger.begin_attempt("z", maximum_attempts=2)
    ledger.begin_attempt("a", maximum_attempts=2)
    assert ledger.snapshot().assignment_wire_bytes == (("a", 0), ("z", 2))
    assert ledger.snapshot().attempts == (("a", 1), ("z", 1))


def test_deadline_success_is_half_open_and_utilization_is_exact() -> None:
    assert DeadlineStage("start", 100, 200, 100).utilization == Fraction(0, 1)
    assert DeadlineStage("middle", 100, 200, 150).utilization == Fraction(1, 2)
    assert DeadlineStage("last-ms", 100, 200, 199).utilization == Fraction(99, 100)

    for completion in (None, 99, 200, 201):
        stage = DeadlineStage("miss", 100, 200, completion)
        assert not stage.successful
        with pytest.raises(ResourceLimitExceeded, match="deadline miss"):
            _ = stage.utilization


def test_nearest_rank_percentile_uses_each_exact_sample_once() -> None:
    values = tuple(Fraction(value, 10) for value in (5, 1, 4, 2, 3))
    assert nearest_rank_percentile(values, Fraction(1, 100)) == Fraction(1, 10)
    assert nearest_rank_percentile(values, Fraction(1, 2)) == Fraction(3, 10)
    assert nearest_rank_percentile(values, Fraction(19, 20)) == Fraction(1, 2)
    assert nearest_rank_percentile(values, Fraction(1, 1)) == Fraction(1, 2)


def test_retained_and_audit_bytes_deduplicate_only_identical_content_digests() -> None:
    objects = (("a", 10), ("b", 20), ("a", 10))
    assert retained_storage_bytes(objects) == 30
    assert audit_bundle_bytes(b"manifest", {"a": 10, "b": 20}) == 38

    with pytest.raises(ValueError, match="conflicting sizes"):
        retained_storage_bytes((("a", 10), ("a", 11)))


def _preflight() -> PreflightBound:
    return PreflightBound(
        assignment_count=2,
        shared_artifact_bytes=100,
        retained_object_bytes=400,
        audit_manifest_bytes=50,
        audit_object_bytes=500,
        maximum_request_transmissions=2,
        maximum_response_bodies=2,
        maximum_http_header_bytes=10,
        maximum_request_body_bytes=20,
        maximum_response_body_bytes=30,
    )


def test_preflight_formula_and_exact_boundaries() -> None:
    bound = _preflight()
    assert bound.assignment_wire_bytes == 140
    assert bound.window_wire_bytes == 380
    assert bound.audit_bundle_bytes == 550
    bound.enforce(
        maximum_assignment_wire_bytes=140,
        maximum_window_wire_bytes=380,
        retained_storage_capacity=400,
        maximum_audit_bundle_bytes=550,
    )


@pytest.mark.parametrize(
    "limits",
    [
        {
            "maximum_assignment_wire_bytes": 139,
            "maximum_window_wire_bytes": 380,
            "retained_storage_capacity": 400,
            "maximum_audit_bundle_bytes": 550,
        },
        {
            "maximum_assignment_wire_bytes": 140,
            "maximum_window_wire_bytes": 379,
            "retained_storage_capacity": 400,
            "maximum_audit_bundle_bytes": 550,
        },
        {
            "maximum_assignment_wire_bytes": 140,
            "maximum_window_wire_bytes": 380,
            "retained_storage_capacity": 399,
            "maximum_audit_bundle_bytes": 550,
        },
        {
            "maximum_assignment_wire_bytes": 140,
            "maximum_window_wire_bytes": 380,
            "retained_storage_capacity": 400,
            "maximum_audit_bundle_bytes": 549,
        },
    ],
)
def test_preflight_fails_closed_when_any_single_capacity_is_short(limits: dict[str, int]) -> None:
    with pytest.raises(ResourceLimitExceeded):
        _preflight().enforce(**limits)
