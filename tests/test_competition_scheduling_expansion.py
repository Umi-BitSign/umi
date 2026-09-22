"""Raise retained capacity without changing reservation identities or receipts."""

import pytest

from umi.competition_dispatch_capacity import timing_profile_sha256
from umi.competition_scheduling import AssignmentPublicationJournal, SchedulingCapacity
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_scheduling import _claim, _new_sequence, _publish
from .test_competition_scheduling_timing import qualification, reserve, snapshot
from .test_competition_scheduling_timing import schedule as schedule
from .test_competition_scheduling_timing import timed_schedule as timed_schedule
from .test_open_competition import policy as policy

EXPANDED = SchedulingCapacity(
    maximum_publications=4096,
    maximum_assignments=16384,
    maximum_bytes=48 * 1024**3,
    maximum_outcome_bytes=1024**2,
)


def reopen(fixture, capacity=EXPANDED):
    return AssignmentPublicationJournal(
        fixture.directory,
        fixture.authorization.policy,
        fixture.authorization.legacy_policy,
        **capacity.model_dump(),
    )


@pytest.mark.parametrize("phase", ["reserved", "published", "dispatched", "completed"])
def test_expansion_preserves_generation_two_journal_and_original_receipts(timed_schedule, phase):
    s = timed_schedule
    receipt = reserve(s)
    if phase != "reserved":
        _publish(s)
    if phase in {"dispatched", "completed"}:
        claim = _claim(s, expected_dispatch_profile=timing_profile_sha256(s.limits, s.budget))
        if phase == "completed":
            s.journal.complete(claim, evidence=b"synthetic retained transport outcome")
    before, timing = snapshot(s.journal), qualification(s.journal)
    assert before[0] == 2
    s.journal = reopen(s)
    assert snapshot(s.journal) == before
    assert reserve(s) == receipt
    assert qualification(s.journal) == timing
    assert snapshot(s.journal) == before
    if phase != "reserved":
        assert canonical_json_bytes(
            s.journal.publication(digest(s.authorization.publication.publication))
        ) == (canonical_json_bytes(s.authorization.publication))
    if phase in {"dispatched", "completed"}:
        with pytest.raises(ValueError, match="never retried"):
            _claim(s, observed=None, issuance=None)
    if phase == "completed":
        assert s.journal.outcome(claim.assignment_key) == b"synthetic retained transport outcome"
    s.journal = reopen(s)
    assert snapshot(s.journal) == before
    changed = EXPANDED.model_copy(update={"maximum_outcome_bytes": 2 * 1024**2})
    with pytest.raises(ValueError, match="outcome capacity mismatch"):
        reopen(s, changed)
    assert snapshot(s.journal) == before


def test_full_count_can_expand_then_admit_next_reservation_without_releasing_old(timed_schedule):
    s = timed_schedule
    s.journal = reopen(s, EXPANDED.model_copy(update={"maximum_publications": 1}))
    receipt = reserve(s)
    before = snapshot(s.journal)
    next_body = _new_sequence(s, 2).publication
    with pytest.raises(ValueError, match="capacity exhausted"):
        reserve(s, publication=next_body, batch_id="b" * 64)
    assert snapshot(s.journal) == before
    s.journal = reopen(s)
    assert snapshot(s.journal) == before
    reserve(s, publication=next_body, batch_id="b" * 64)
    assert reserve(s) == receipt
    after = snapshot(s.journal)
    s.journal = reopen(s)
    assert snapshot(s.journal) == after
    # A stale low-cap writer fails closed once retained usage exceeds its cap.
    with pytest.raises(ValueError, match="capacity exhausted"):
        reopen(s, EXPANDED.model_copy(update={"maximum_publications": 1}))
    assert snapshot(s.journal) == after
