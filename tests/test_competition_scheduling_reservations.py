from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from umi.competition_dispatch_capacity import (
    DispatchTimingBudget,
    DispatchTimingLimits,
    timing_profile_sha256,
)
from umi.competition_scheduling import _BLOCK_RESERVE_BYTES, AssignmentPublicationJournal
from umi.protocol import canonical_json_bytes
from umi.validator_plans import MAX_FINALITY_EVIDENCE_BYTES

from .test_competition_scheduling import (
    _claim,
    _fresh_head,
    _new_sequence,
    _publish,
    _resign,
)
from .test_competition_scheduling import (
    schedule as schedule_fixture,
)
from .test_open_competition import policy as policy

schedule = schedule_fixture


@pytest.fixture
def reserved_schedule(schedule, monkeypatch):
    monkeypatch.setattr(AssignmentPublicationJournal, "_qualify_capacity", lambda *args: {})
    monkeypatch.setattr(
        AssignmentPublicationJournal, "_recover_capacity", lambda *args, **kwargs: {}
    )
    return schedule


def reserve(fixture, *, journal=None, publications=None, batch_id="a" * 64):
    return (journal or fixture.journal).reserve_batch(
        batch_id=batch_id,
        publications=publications or (fixture.authorization.publication.publication,),
        observed=fixture.observed,
        announcements=(fixture.announcement,),
        evaluator_hotkey=(
            fixture.authorization.publication.publication.assignments[0].evaluator_hotkey
        ),
    )


def state(journal):
    with sqlite3.connect(journal.path) as db:
        tables = [
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        ]
        return (
            db.execute("PRAGMA user_version").fetchone()[0],
            {name: db.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall() for name in tables},
        )


def logical_bytes(journal):
    with journal._transaction() as db:
        retained = db.execute("SELECT COALESCE(SUM(reserved),0) FROM publications").fetchone()[0]
        blocks = db.execute(
            "SELECT COALESCE(SUM(LENGTH(document)+LENGTH(evidence)),0) FROM blocks"
        ).fetchone()[0]
        bodies = db.execute(
            "SELECT COALESCE(SUM(LENGTH(body)),0) FROM reservation_publications"
        ).fetchone()[0]
        manifests = db.execute(
            "SELECT COALESCE(SUM(LENGTH(document)),0) FROM reservation_batches"
        ).fetchone()[0]
        qualifications = db.execute(
            "SELECT COALESCE(SUM(LENGTH(document)),0) FROM reservation_qualifications"
        ).fetchone()[0]
        profiles = db.execute(
            "SELECT COALESCE(SUM(LENGTH(value)),0) FROM metadata "
            "WHERE key LIKE 'dispatch_profile:%'"
        ).fetchone()[0]
        pending = db.execute(
            "SELECT COALESCE(SUM(allowance),0) FROM reservation_publications r "
            "WHERE NOT EXISTS (SELECT 1 FROM reservation_consumptions c "
            "WHERE c.publication_id=r.id)"
        ).fetchone()[0]
        return (
            retained
            + blocks
            + bodies
            + manifests
            + qualifications
            + profiles
            + pending
            + journal._proof_allowance(db)
            + 64  # Stable journal identity is charged once, not per evaluator.
        )


def configure_claim(fixture):
    inbox = fixture.directory.parent / "inbox"
    inbox.mkdir(mode=0o700, exist_ok=True)
    limits = DispatchTimingLimits(
        maximum_concurrency=4,
        page_size=8,
        poll_seconds=1,
        discovery_grace_seconds=5,
        request_timeout_seconds=1,
    )
    budget = DispatchTimingBudget(
        proof_collection_ms=1,
        origin_collection_ms=1,
        publication_ingestion_ms=1,
        local_cycle_ms=1,
        publication_delay_ms=0,
        block_advance_numerator=1,
        block_advance_denominator_ms=60000,
        finality_headroom_blocks=0,
        measurement_sha256="f" * 64,
    )
    fixture.journal.configure_dispatch(
        evaluator_hotkey=fixture.authorization.publication.publication.assignments[
            0
        ].evaluator_hotkey,
        limits=limits,
        budget=budget,
        publication_directory=inbox,
    )
    return timing_profile_sha256(limits, budget)


def claim(fixture):
    return _claim(fixture, expected_dispatch_profile=configure_claim(fixture))


def test_reservation_migration_is_atomic_and_requires_capacity_profile(schedule):
    before = state(schedule.journal)
    with pytest.raises(ValueError, match="capacity profile"):
        reserve(schedule)
    assert state(schedule.journal) == before


def test_exact_cohort_retry_preserves_reservation_and_restart(reserved_schedule):
    fixture = reserved_schedule
    first = reserve(fixture)
    before = state(fixture.journal)
    assert before[0] == 2
    assert len(before[1]["reservation_publications"]) == 1
    assert len(before[1]["reservation_assignments"]) == 6
    assert before[1]["publications"] == []
    assert reserve(fixture) == first
    assert state(fixture.journal) == before
    restarted = AssignmentPublicationJournal(
        fixture.directory, fixture.authorization.policy, fixture.authorization.legacy_policy
    )
    assert reserve(fixture, journal=restarted) == first
    assert state(restarted) == before


def test_one_byte_short_budget_rolls_back_first_reservation_and_migration(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    needed = logical_bytes(fixture.journal)
    short = AssignmentPublicationJournal(
        fixture.directory.parent / "short",
        fixture.authorization.policy,
        fixture.authorization.legacy_policy,
        maximum_bytes=needed - 1,
    )
    before = state(short)
    with pytest.raises(ValueError, match="capacity exhausted"):
        reserve(fixture, journal=short)
    assert state(short) == before
    assert before[0] == 1


def test_assignment_budget_covers_entire_unsigned_cohort(reserved_schedule):
    fixture = reserved_schedule
    fixture.journal.maximum_assignments = 5
    before = state(fixture.journal)
    with pytest.raises(ValueError, match="capacity exhausted"):
        reserve(fixture)
    assert state(fixture.journal) == before


def test_concurrent_reservations_cannot_spend_same_publication_capacity(reserved_schedule):
    fixture = reserved_schedule
    fixture.journal.maximum_publications = 1
    other = AssignmentPublicationJournal(
        fixture.directory,
        fixture.authorization.policy,
        fixture.authorization.legacy_policy,
        maximum_publications=1,
    )
    second = _new_sequence(fixture, 2).publication

    def attempt(journal, body, key):
        try:
            reserve(fixture, journal=journal, publications=(body,), batch_id=key)
            return "reserved"
        except ValueError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(
            attempt, fixture.journal, fixture.authorization.publication.publication, "a" * 64
        )
        b = pool.submit(attempt, other, second, "b" * 64)
        results = [a.result(), b.result()]
    assert results.count("reserved") == 1
    assert sum("capacity exhausted" in result for result in results) == 1
    assert len(state(fixture.journal)[1]["reservation_batches"]) == 1


def test_signed_publication_consumes_bound_allowance_once_and_keeps_first_bytes(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    before = logical_bytes(fixture.journal)
    first = _publish(fixture)
    after = logical_bytes(fixture.journal)
    assert after <= before
    assert len(state(fixture.journal)[1]["reservation_consumptions"]) == 1
    replacement = _resign(fixture, fixture.authorization.publication.publication)
    assert _publish(fixture, publication=replacement) == first
    assert logical_bytes(fixture.journal) == after
    assert canonical_json_bytes(fixture.journal.publication(first["publication_sha256"])) == (
        canonical_json_bytes(fixture.authorization.publication)
    )


def test_new_unreserved_publication_cannot_bypass_upgraded_journal(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    before = state(fixture.journal)
    with pytest.raises(ValueError, match="exact cohort reservation"):
        _publish(fixture, publication=_new_sequence(fixture, 2))
    assert state(fixture.journal) == before


def test_preopened_old_writer_connection_is_fenced_on_all_mutation_paths(reserved_schedule):
    fixture = reserved_schedule
    old = sqlite3.connect(fixture.journal.path, isolation_level=None)
    try:
        old.execute("INSERT OR IGNORE INTO metadata VALUES ('old-probe','1')")
        reserve(fixture)
        for sql in (
            "INSERT OR IGNORE INTO metadata VALUES ('old-probe','1')",
            "UPDATE metadata SET value='2' WHERE key='old-probe'",
            "DELETE FROM metadata WHERE key='old-probe'",
            "INSERT INTO rounds VALUES (999,'unreserved')",
        ):
            with pytest.raises(sqlite3.DatabaseError, match="umi_scheduling_writer_generation"):
                old.execute(sql)
    finally:
        old.close()


def test_migration_waits_for_dispatched_claim_completion(reserved_schedule):
    fixture = reserved_schedule
    _publish(fixture)
    dispatched = claim(fixture)
    before = state(fixture.journal)
    with pytest.raises(ValueError, match="drain dispatched incomplete"):
        reserve(fixture)
    assert state(fixture.journal) == before
    fixture.journal.complete(dispatched, evidence=b"completed-before-migration")
    reserve(fixture)
    assert state(fixture.journal)[0] == 2
    assert len(state(fixture.journal)[1]["reservation_consumptions"]) == 1


def test_legacy_publication_remains_usable_after_reserving_next_round(reserved_schedule):
    fixture = reserved_schedule
    first = _publish(fixture)
    reserve(fixture, publications=(_new_sequence(fixture, 2).publication,))
    assert fixture.journal.publication(first["publication_sha256"]) == (
        fixture.authorization.publication
    )
    dispatched = claim(fixture)
    fixture.journal.complete(dispatched, evidence=b"legacy-claim-still-completes")
    assert fixture.journal.status(dispatched.assignment_key)["state"] == "completed"


def test_proof_height_reserved_once_across_overlapping_cohorts(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    with fixture.journal._transaction() as db:
        first = fixture.journal._proof_allowance(db)
    reserve(fixture, publications=(_new_sequence(fixture, 2).publication,), batch_id="b" * 64)
    with fixture.journal._transaction() as db:
        assert fixture.journal._proof_allowance(db) == first
    fixture.journal.observe(observed=_fresh_head(fixture))
    with fixture.journal._transaction() as db:
        assert fixture.journal._proof_allowance(db) == first - _BLOCK_RESERVE_BYTES


def test_out_of_interval_observation_does_not_spend_future_proof_headroom(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    with fixture.journal._transaction() as db:
        before = fixture.journal._proof_allowance(db)
        end = db.execute("SELECT MAX(proof_end) FROM reservation_batches").fetchone()[0]
    fixture.journal.observe(observed=_fresh_head(fixture, height=end + 1))
    with fixture.journal._transaction() as db:
        assert fixture.journal._proof_allowance(db) == before


def test_exact_fit_allows_maximum_in_interval_proof_and_full_outcome(reserved_schedule):
    fixture = reserved_schedule
    profile = configure_claim(fixture)
    reserve(fixture)
    fixture.journal.maximum_bytes = logical_bytes(fixture.journal)
    _publish(fixture)
    evidence = b"p" * MAX_FINALITY_EVIDENCE_BYTES
    head = replace(
        _fresh_head(fixture),
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )
    fixture.journal.observe(observed=head)
    dispatched = _claim(fixture, observed=head, expected_dispatch_profile=profile)
    outcome = b"o" * fixture.journal.maximum_outcome_bytes
    fixture.journal.complete(dispatched, evidence=outcome)
    assert fixture.journal.status(dispatched.assignment_key)["state"] == "completed"
    assert logical_bytes(fixture.journal) <= fixture.journal.maximum_bytes
    with fixture.journal._transaction() as db:
        assert (
            db.execute(
                "SELECT LENGTH(evidence) FROM blocks WHERE height=?", (head.height,)
            ).fetchone()[0]
            == MAX_FINALITY_EVIDENCE_BYTES
        )
        assert (
            db.execute(
                "SELECT LENGTH(evidence) FROM events WHERE assignment_id=? AND kind='completed'",
                (dispatched.assignment_key,),
            ).fetchone()[0]
            == fixture.journal.maximum_outcome_bytes
        )


def test_exact_fit_rejects_unrelated_proof_without_any_state_change(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    fixture.journal.maximum_bytes = logical_bytes(fixture.journal)
    before = state(fixture.journal)
    with fixture.journal._transaction() as db:
        end = db.execute("SELECT MAX(proof_end) FROM reservation_batches").fetchone()[0]
    evidence = b"u" * MAX_FINALITY_EVIDENCE_BYTES
    unrelated = replace(
        _fresh_head(fixture, height=end + 1),
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )
    with pytest.raises(ValueError, match="capacity exhausted"):
        fixture.journal.observe(observed=unrelated)
    assert state(fixture.journal) == before


def test_fully_known_terminal_batch_releases_only_unused_future_proof_allowance(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    publication = _publish(fixture)
    dispatched = claim(fixture)
    fixture.journal.complete(dispatched, evidence=b"completed")
    with fixture.journal._transaction() as db:
        allowance = fixture.journal._proof_allowance(db)
        retained = db.execute(
            "SELECT height,document,evidence FROM blocks ORDER BY height"
        ).fetchall()
        issue_close = db.execute("SELECT MAX(issue_close_ms) FROM assignments").fetchone()[0]
    assert allowance > 0
    fixture.now[0] = issue_close + 1
    with fixture.journal._transaction() as db:
        # Wall-clock expiry alone is not retained terminal evidence.
        assert fixture.journal._proof_allowance(db) == allowance
    before = logical_bytes(fixture.journal)
    fixture.journal.publication_status(publication["publication_sha256"])
    assert logical_bytes(fixture.journal) == before - allowance
    with fixture.journal._transaction() as db:
        assert fixture.journal._proof_allowance(db) == 0
        assert (
            db.execute("SELECT height,document,evidence FROM blocks ORDER BY height").fetchall()
            == retained
        )
        assert db.execute("SELECT COUNT(*) FROM reservation_publications").fetchone()[0] == 1


def test_unknown_claim_keeps_future_proof_allowance_after_other_assignments_expire(
    reserved_schedule,
):
    fixture = reserved_schedule
    reserve(fixture)
    publication = _publish(fixture)
    dispatched = claim(fixture)
    with fixture.journal._transaction() as db:
        allowance = fixture.journal._proof_allowance(db)
        fixture.now[0] = db.execute("SELECT MAX(issue_close_ms)+1 FROM assignments").fetchone()[0]
    fixture.journal.publication_status(publication["publication_sha256"])
    assert fixture.journal.status(dispatched.assignment_key)["state"] == "uncertain_dispatched"
    with fixture.journal._transaction() as db:
        assert fixture.journal._proof_allowance(db) == allowance


def test_unpublished_reservation_keeps_future_proof_allowance_after_wall_clock_expiry(
    reserved_schedule,
):
    fixture = reserved_schedule
    reserve(fixture)
    with fixture.journal._transaction() as db:
        allowance = fixture.journal._proof_allowance(db)
    fixture.now[0] += 24 * 60 * 60 * 1000
    fixture.journal.pending_dispatches(
        evaluator_hotkey=fixture.authorization.publication.publication.assignments[
            0
        ].evaluator_hotkey
    )
    with fixture.journal._transaction() as db:
        assert fixture.journal._proof_allowance(db) == allowance
        assert db.execute("SELECT COUNT(*) FROM publications").fetchone()[0] == 0


def test_changed_batch_or_same_round_new_batch_cannot_retime(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    before = state(fixture.journal)
    with pytest.raises(ValueError, match="cohort changed"):
        reserve(fixture, publications=(_new_sequence(fixture, 2).publication,))
    with pytest.raises(ValueError, match="another scheduling reservation"):
        reserve(fixture, batch_id="b" * 64)
    assert state(fixture.journal) == before


def test_reservation_documents_and_bodies_remain_append_only(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    for table in ("reservation_batches", "reservation_publications", "reservation_assignments"):
        with (
            pytest.raises(sqlite3.DatabaseError, match="append-only"),
            fixture.journal._transaction() as db,
        ):
            db.execute(f"DELETE FROM {table}")


def test_proof_document_bound_is_enforced_before_migration_commits(reserved_schedule, monkeypatch):
    fixture = reserved_schedule
    before = state(fixture.journal)
    monkeypatch.setattr(fixture.journal, "_block_document", lambda _: b"x" * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="proof exceeds reservation byte bound"):
        reserve(fixture)
    assert state(fixture.journal) == before
