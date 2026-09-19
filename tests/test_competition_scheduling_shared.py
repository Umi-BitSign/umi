from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from umi.competition_scheduling import AssignmentPublicationJournal
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_scheduling import _publish
from .test_competition_scheduling import schedule as schedule
from .test_competition_scheduling_reservations import logical_bytes
from .test_competition_scheduling_timing import configure, snapshot
from .test_competition_scheduling_timing import timed_schedule as timed_schedule
from .test_open_competition import policy as policy

_BATCH = "ab" * 32


@pytest.fixture
def shared(timed_schedule):
    fixture = timed_schedule
    fixture.other_evaluator = next(
        assignment.evaluator_hotkey
        for assignment in fixture.authorization.publication.publication.assignments
        if identity(assignment.evaluator_hotkey) != identity(fixture.evaluator)
    )
    fixture.other_limits = fixture.limits.model_copy(update={"request_timeout_seconds": 2})
    fixture.other_budget = fixture.budget.model_copy(update={"measurement_sha256": "cd" * 32})
    fixture.other_inbox = fixture.inbox.parent / "other-inbox"
    fixture.other_inbox.mkdir(mode=0o700)
    configure(
        fixture,
        evaluator_hotkey=fixture.other_evaluator,
        limits=fixture.other_limits,
        budget=fixture.other_budget,
        publication_directory=fixture.other_inbox,
    )
    return fixture


def reserve(fixture, evaluator, *, journal=None):
    return (journal or fixture.journal).reserve_batch(
        batch_id=_BATCH,
        publications=(fixture.authorization.publication.publication,),
        observed=fixture.observed,
        announcements=(fixture.announcement,),
        evaluator_hotkey=evaluator,
    )


def receipt(journal, evaluator):
    return journal.reservation(_BATCH, evaluator_hotkey=evaluator)


def qualification(journal, evaluator):
    with sqlite3.connect(journal.path) as db:
        raw = db.execute(
            "SELECT document FROM reservation_qualifications WHERE batch_id=? AND evaluator=?",
            (_BATCH, identity(evaluator)),
        ).fetchone()[0]
    value = json.loads(raw)
    assert canonical_json_bytes(value) == raw
    return value


def shared_state(journal):
    with journal._transaction() as db:
        return (
            {
                table: [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1")]
                for table in (
                    "blocks",
                    "reservation_batches",
                    "reservation_publications",
                    "reservation_assignments",
                    "reservation_consumptions",
                )
            },
            journal._proof_allowance(db),
        )


def test_two_evaluators_share_capacity_but_keep_distinct_timing_receipts(shared):
    fixture, journal = shared, shared.journal
    reserve(fixture, fixture.evaluator)
    first = receipt(journal, fixture.evaluator)
    shared_before = shared_state(journal)
    bytes_before = logical_bytes(journal)
    with pytest.raises(ValueError, match="timing receipt is missing"):
        receipt(journal, fixture.other_evaluator)

    reserve(fixture, fixture.other_evaluator)
    second = receipt(journal, fixture.other_evaluator)
    assert receipt(journal, fixture.evaluator) == first
    assert shared_state(journal) == shared_before
    assert first["document_sha256"] == second["document_sha256"]
    assert first["qualification_sha256"] != second["qualification_sha256"]
    assert first["evaluator"] == identity(fixture.evaluator)
    assert second["evaluator"] == identity(fixture.other_evaluator)

    other_qualification = qualification(journal, fixture.other_evaluator)
    assert logical_bytes(journal) - bytes_before == len(canonical_json_bytes(other_qualification))
    for evaluator, limits in (
        (fixture.evaluator, fixture.limits),
        (fixture.other_evaluator, fixture.other_limits),
    ):
        timing = qualification(journal, evaluator)
        assert timing["evaluator"] == identity(evaluator)
        assert timing["profile"]["limits"] == limits.model_dump(mode="json")
        assert timing["plan"]["assignment_count"] == 3
    assert len(shared_before[0]["reservation_assignments"]) == 6

    before_retry = snapshot(journal)
    reserve(fixture, fixture.evaluator)
    reserve(fixture, fixture.other_evaluator)
    reopened = AssignmentPublicationJournal(
        fixture.directory, fixture.authorization.policy, fixture.authorization.legacy_policy
    )
    reserve(fixture, fixture.other_evaluator, journal=reopened)
    assert snapshot(journal) == before_retry
    assert receipt(reopened, fixture.evaluator) == first
    assert receipt(reopened, fixture.other_evaluator) == second

    _publish(fixture)
    assert receipt(journal, fixture.evaluator) == first
    assert receipt(journal, fixture.other_evaluator) == second
    assert canonical_json_bytes(
        journal.publication(digest(fixture.authorization.publication.publication))
    ) == canonical_json_bytes(fixture.authorization.publication)


def test_second_evaluator_timing_failure_preserves_first_reservation(shared):
    fixture, journal = shared, shared.journal
    # Configure a genuinely infeasible second runtime before any work binds it.
    configure(
        fixture,
        evaluator_hotkey=fixture.other_evaluator,
        limits=fixture.other_limits.model_copy(update={"request_timeout_seconds": 120}),
        budget=fixture.other_budget,
        publication_directory=fixture.other_inbox,
    )
    reserve(fixture, fixture.evaluator)
    first = receipt(journal, fixture.evaluator)
    before = snapshot(journal)
    with pytest.raises(ValueError, match="cannot fit its original"):
        reserve(fixture, fixture.other_evaluator)
    assert snapshot(journal) == before
    assert receipt(journal, fixture.evaluator) == first


def test_second_evaluator_receipt_bytes_need_additional_capacity(shared):
    fixture, journal = shared, shared.journal
    reserve(fixture, fixture.evaluator)
    first = receipt(journal, fixture.evaluator)
    journal.maximum_bytes = logical_bytes(journal)
    before = snapshot(journal)
    with pytest.raises(ValueError, match="capacity exhausted"):
        reserve(fixture, fixture.other_evaluator)
    assert snapshot(journal) == before
    assert receipt(journal, fixture.evaluator) == first


def test_concurrent_evaluators_reserve_one_shared_cohort(shared):
    fixture, journal = shared, shared.journal
    other = AssignmentPublicationJournal(
        fixture.directory, fixture.authorization.policy, fixture.authorization.legacy_policy
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (
            pool.submit(reserve, fixture, fixture.evaluator),
            pool.submit(reserve, fixture, fixture.other_evaluator, journal=other),
        )
        for result in futures:
            result.result()
    state, _ = shared_state(journal)
    assert len(state["reservation_batches"]) == len(state["reservation_publications"]) == 1
    assert len(state["reservation_assignments"]) == 6
    assert receipt(journal, fixture.evaluator)["evaluator"] == identity(fixture.evaluator)
    assert receipt(other, fixture.other_evaluator)["evaluator"] == identity(fixture.other_evaluator)
