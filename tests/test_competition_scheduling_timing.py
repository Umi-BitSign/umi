from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

import pytest

from umi.competition_authorization import SignedEndpointAuthorization
from umi.competition_dispatch_capacity import (
    DispatchTimingBudget,
    DispatchTimingLimits,
    timing_profile_sha256,
)
from umi.competition_scheduling import assignment_key
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_scheduling import (
    _claim,
    _new_sequence,
    _publish,
)
from .test_competition_scheduling import (
    schedule as schedule_fixture,
)
from .test_open_competition import policy as policy

schedule = schedule_fixture


@pytest.fixture
def timed_schedule(schedule):
    schedule.inbox = schedule.directory.parent / "publication-inbox"
    schedule.inbox.mkdir(mode=0o700)
    schedule.limits = DispatchTimingLimits(
        maximum_concurrency=4,
        page_size=8,
        poll_seconds=1,
        discovery_grace_seconds=5,
        request_timeout_seconds=1,
    )
    # Synthetic bounds for this fixture, not production measurements.
    schedule.budget = DispatchTimingBudget(
        proof_collection_ms=1,
        origin_collection_ms=1,
        publication_ingestion_ms=1,
        local_cycle_ms=1,
        publication_delay_ms=0,
        block_advance_numerator=1,
        block_advance_denominator_ms=60000,
        finality_headroom_blocks=0,
        measurement_sha256="ab" * 32,
    )
    schedule.evaluator = schedule.authorization.publication.publication.assignments[
        0
    ].evaluator_hotkey
    configure(schedule)
    return schedule


def configure(fixture, **changes):
    fixture.journal.configure_dispatch(
        **{
            "evaluator_hotkey": fixture.evaluator,
            "limits": fixture.limits,
            "budget": fixture.budget,
            "publication_directory": str(fixture.inbox),
            **changes,
        }
    )


def reserve(fixture, *, publication=None, batch_id="a" * 64):
    body = publication or fixture.authorization.publication.publication
    return fixture.journal.reserve_batch(
        batch_id=batch_id,
        publications=(body,),
        observed=fixture.observed,
        announcements=(fixture.announcement,),
        evaluator_hotkey=body.assignments[0].evaluator_hotkey,
    )


def snapshot(journal):
    with sqlite3.connect(journal.path) as db:
        return db.execute("PRAGMA user_version").fetchone()[0], tuple(db.iterdump())


def qualification(journal, batch_id="a" * 64):
    with sqlite3.connect(journal.path) as db:
        raw = db.execute(
            "SELECT document FROM reservation_qualifications WHERE batch_id=?", (batch_id,)
        ).fetchone()[0]
    value = json.loads(raw)
    assert canonical_json_bytes(value) == raw
    return value


def write_publication(fixture, publication):
    path = fixture.inbox / (digest(publication.publication) + ".json")
    path.write_bytes(canonical_json_bytes(publication))
    path.chmod(0o600)
    return path


def test_real_qualification_counts_only_the_local_evaluators_work(timed_schedule):
    fixture = timed_schedule
    reserve(fixture)
    retained = qualification(fixture.journal)
    plan = retained["plan"]
    assert plan["assignment_count"] == plan["pending_count"] == 3
    assert plan["publication_count"] == 1
    assert plan["maximum_miner_assignments"] == 3
    assert plan["profile_sha256"] == timing_profile_sha256(fixture.limits, fixture.budget)
    assert retained["profile"] == {
        "limits": fixture.limits.model_dump(mode="json"),
        "budget": fixture.budget.model_dump(mode="json"),
        "publication_directory": str(fixture.inbox),
    }
    with sqlite3.connect(fixture.journal.path) as db:
        assert db.execute("SELECT COUNT(*) FROM reservation_assignments").fetchone()[0] == 6
        assert db.execute("SELECT COUNT(*) FROM publications").fetchone()[0] == 0


def test_missing_profile_rolls_back_real_qualification_and_migration(schedule):
    before = snapshot(schedule.journal)
    with pytest.raises(ValueError, match="capacity profile is not configured"):
        reserve(schedule)
    assert snapshot(schedule.journal) == before


def test_exact_profile_configuration_is_idempotent(timed_schedule):
    fixture = timed_schedule
    before = snapshot(fixture.journal)
    configure(fixture)
    assert snapshot(fixture.journal) == before


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"budget": None}, "retain its configured timing budget"),
        ({"publication_directory": None}, "requires its publication inbox"),
    ],
)
def test_configured_profile_cannot_omit_its_budget_or_inbox(timed_schedule, changes, reason):
    fixture = timed_schedule
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match=reason):
        configure(fixture, **changes)
    assert snapshot(fixture.journal) == before


@pytest.mark.parametrize("changed", ["limits", "budget", "publication_directory"])
def test_unfinished_reservation_binds_runtime_limits_budget_and_inbox(timed_schedule, changed):
    fixture = timed_schedule
    reserve(fixture)
    if changed == "limits":
        replacement = fixture.limits.model_copy(update={"request_timeout_seconds": 2})
    elif changed == "budget":
        replacement = fixture.budget.model_copy(update={"measurement_sha256": "cd" * 32})
    else:
        other = fixture.inbox.parent / "other-inbox"
        other.mkdir(mode=0o700)
        replacement = str(other)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="unfinished assigned work"):
        configure(fixture, **{changed: replacement})
    assert snapshot(fixture.journal) == before


def test_claim_rechecks_profile_after_runtime_precheck_race(timed_schedule):
    fixture = timed_schedule
    old_profile = timing_profile_sha256(fixture.limits, fixture.budget)
    replacement = fixture.limits.model_copy(update={"request_timeout_seconds": 2})
    # A different dispatcher starts after the first one's runtime precheck.
    # There is no assigned work yet, so replacing the profile is permitted.
    configure(fixture, limits=replacement)
    reserve(fixture)
    _publish(fixture)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="timing profile differs from its runtime"):
        _claim(fixture, expected_dispatch_profile=old_profile)
    assert snapshot(fixture.journal) == before
    claim = _claim(
        fixture,
        expected_dispatch_profile=timing_profile_sha256(replacement, fixture.budget),
    )
    assert fixture.journal.status(claim.assignment_key)["state"] == "uncertain_dispatched"


def test_reserved_claim_cannot_omit_runtime_profile(timed_schedule):
    fixture = timed_schedule
    reserve(fixture)
    _publish(fixture)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="timing profile differs from its runtime"):
        _claim(fixture)
    assert snapshot(fixture.journal) == before


def test_unknown_claim_blocks_new_qualification_without_retrying_it(timed_schedule):
    fixture = timed_schedule
    reserve(fixture)
    _publish(fixture)
    claim = _claim(
        fixture, expected_dispatch_profile=timing_profile_sha256(fixture.limits, fixture.budget)
    )
    second = _new_sequence(fixture, 2).publication
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="awaits the prior claim outcome"):
        reserve(fixture, publication=second, batch_id="b" * 64)
    assert snapshot(fixture.journal) == before
    assert [event["kind"] for event in fixture.journal.events(claim.assignment_key)] == [
        "published",
        "dispatched",
    ]
    fixture.journal.complete(claim, evidence=b"original-dispatch-completed")
    reserve(fixture, publication=second, batch_id="b" * 64)
    assert qualification(fixture.journal, "b" * 64)["plan"]["assignment_count"] == 5


def test_same_cohort_continues_during_dispatch_without_new_admission(timed_schedule):
    fixture = timed_schedule
    fixture.budget = fixture.budget.model_copy(update={"publication_delay_ms": 100_000})
    configure(fixture)
    first = reserve(fixture)
    receipt = qualification(fixture.journal)
    _publish(fixture)
    claim = _claim(
        fixture, expected_dispatch_profile=timing_profile_sha256(fixture.limits, fixture.budget)
    )
    before = snapshot(fixture.journal)
    assert reserve(fixture) == first
    assert snapshot(fixture.journal) == before
    assert qualification(fixture.journal) == receipt
    assert fixture.journal.status(claim.assignment_key)["state"] == "uncertain_dispatched"
    with pytest.raises(ValueError, match="awaits the prior claim outcome"):
        reserve(fixture, publication=_new_sequence(fixture, 2).publication, batch_id="b" * 64)
    assert snapshot(fixture.journal) == before


def advance(fixture, milliseconds):
    fixture.now[0] += milliseconds
    fixture.observed = replace(
        fixture.observed, height=fixture.observed.height + 1, timestamp_ms=fixture.now[0]
    )


def test_late_continuation_requalifies_without_resetting_original_receipt(timed_schedule):
    fixture = timed_schedule
    fixture.budget = fixture.budget.model_copy(update={"publication_delay_ms": 100_000})
    configure(fixture)
    original_reservation = reserve(fixture)
    receipt = qualification(fixture.journal)
    advance(fixture, 50_000)
    assert reserve(fixture) == original_reservation
    assert qualification(fixture.journal) == receipt
    advance(fixture, 50_001)
    assert reserve(fixture) == original_reservation
    assert qualification(fixture.journal) == receipt


def test_late_continuation_rejects_stale_finality_without_changing_receipt(timed_schedule):
    fixture = timed_schedule
    reserve(fixture)
    before = snapshot(fixture.journal)
    fixture.now[0] += 60_001
    with pytest.raises(ValueError, match="fresh owned finality"):
        fixture.journal.reservation("a" * 64, evaluator_hotkey=fixture.evaluator)
    assert snapshot(fixture.journal) == before


def test_late_continuation_rejects_insufficient_remaining_time(timed_schedule):
    fixture = timed_schedule
    fixture.budget = fixture.budget.model_copy(update={"publication_delay_ms": 100_000})
    configure(fixture)
    reserve(fixture)
    advance(fixture, 200_000)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match=r"cannot fit|deadline reserve"):
        reserve(fixture)
    assert snapshot(fixture.journal) == before


def test_late_continuation_rejects_a_fit_without_twenty_percent_reserve(timed_schedule):
    fixture = timed_schedule
    fixture.budget = fixture.budget.model_copy(update={"publication_delay_ms": 100_000})
    configure(fixture)
    reserve(fixture)
    advance(fixture, 160_000)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="required deadline reserve"):
        reserve(fixture)
    assert snapshot(fixture.journal) == before


@pytest.mark.parametrize(
    "elapsed_ms,reason",
    [(160_000, "required deadline reserve"), (200_000, r"cannot fit|deadline reserve")],
)
def test_warm_reservation_receipt_rechecks_remaining_time(timed_schedule, elapsed_ms, reason):
    fixture = timed_schedule
    fixture.budget = fixture.budget.model_copy(update={"publication_delay_ms": 100_000})
    configure(fixture)
    reserve(fixture)
    assert fixture.journal.reservation("a" * 64, evaluator_hotkey=fixture.evaluator) is not None
    advance(fixture, elapsed_ms)
    fixture.journal.observe(observed=fixture.observed)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match=reason):
        fixture.journal.reservation("a" * 64, evaluator_hotkey=fixture.evaluator)
    assert snapshot(fixture.journal) == before


def test_late_continuation_does_not_retry_a_dispatch_with_unknown_outcome(timed_schedule):
    fixture = timed_schedule
    fixture.budget = fixture.budget.model_copy(update={"publication_delay_ms": 100_000})
    configure(fixture)
    reserve(fixture)
    issuance = fixture.observed
    advance(fixture, 100_001)
    _publish(fixture)
    _claim(
        fixture,
        issuance=issuance,
        expected_dispatch_profile=timing_profile_sha256(fixture.limits, fixture.budget),
    )
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="awaits the prior claim outcome"):
        reserve(fixture)
    assert snapshot(fixture.journal) == before


def test_timely_delivered_cohort_can_continue_after_delivery_allowance(timed_schedule):
    fixture = timed_schedule
    reserve(fixture)
    _publish(fixture)
    receipt = qualification(fixture.journal)
    advance(fixture, 10_000)
    reserve(fixture)
    assert qualification(fixture.journal) == receipt


@pytest.mark.parametrize("keep_file", [False, True])
def test_completed_history_counts_as_inbox_only_when_file_is_present(
    timed_schedule, keep_file, monkeypatch
):
    fixture = timed_schedule
    first = fixture.authorization.publication
    _publish(fixture)
    for assignment in first.publication.assignments:
        if identity(assignment.evaluator_hotkey) != identity(fixture.evaluator):
            continue
        claim = _claim(
            fixture,
            key=assignment_key(first, assignment),
            expected_dispatch_profile=timing_profile_sha256(fixture.limits, fixture.budget),
        )
        fixture.journal.complete(claim, evidence=b"completed-history")
    if keep_file:
        write_publication(fixture, first)
    second = _new_sequence(fixture, 2)
    decoded_history = []
    original = SignedEndpointAuthorization.model_validate_json

    def record_decode(raw, **kwargs):
        if raw == canonical_json_bytes(first):
            decoded_history.append(raw)
        return original(raw, **kwargs)

    monkeypatch.setattr(SignedEndpointAuthorization, "model_validate_json", record_decode)
    reserve(fixture, publication=second.publication)
    assert decoded_history == []
    plan = qualification(fixture.journal)["plan"]
    assert plan["assignment_count"] == 3
    assert plan["publication_count"] == 1 + int(keep_file)
    with sqlite3.connect(fixture.journal.path) as db:
        assert db.execute("SELECT COUNT(*) FROM publications").fetchone()[0] == 1
    assert fixture.journal.publication(digest(first.publication)) == first


def test_active_publication_file_is_not_counted_twice(timed_schedule):
    fixture = timed_schedule
    write_publication(fixture, fixture.authorization.publication)
    reserve(fixture)
    assert qualification(fixture.journal)["plan"]["publication_count"] == 1


def test_temporary_inbox_entries_are_included_in_delivery_budget(timed_schedule):
    fixture = timed_schedule
    (fixture.inbox / "in-progress.tmp").touch(mode=0o600)
    reserve(fixture)
    assert qualification(fixture.journal)["plan"]["publication_count"] == 2


@pytest.mark.parametrize(
    "entries,reason", [(1024, "publication inbox bound"), (1025, "file capacity")]
)
def test_real_inbox_pressure_rejects_reservation_atomically(timed_schedule, entries, reason):
    fixture = timed_schedule
    for number in range(entries):
        (fixture.inbox / f"pending-{number}.tmp").touch(mode=0o600)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match=reason):
        reserve(fixture)
    assert snapshot(fixture.journal) == before


def test_real_timing_failure_does_not_leave_reservation_or_migration(timed_schedule):
    fixture = timed_schedule
    configure(fixture, limits=fixture.limits.model_copy(update={"request_timeout_seconds": 600}))
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="original issue window"):
        reserve(fixture)
    assert snapshot(fixture.journal) == before


def test_nonprivate_inbox_rejection_leaves_no_partial_reservation(timed_schedule):
    fixture = timed_schedule
    fixture.inbox.chmod(0o755)
    before = snapshot(fixture.journal)
    with pytest.raises(ValueError, match="inbox must be owned and private"):
        reserve(fixture)
    assert snapshot(fixture.journal) == before
