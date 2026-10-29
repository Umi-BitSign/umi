"""Real journal contention and capacity fences for resident execution metadata.

The writers below use independent journal owners and SQLite connections. The
execution fixtures retain native assignments with synthetic finality; no test
here runs a model, signs a production artifact or contacts a live owner.
"""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from umi import competition_cohort_order_signer as histories
from umi.competition_cohort_execution_journal import execution_step_key
from umi.competition_round_journal import RecordReservation, RoundJournal
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import harness as harness
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_executor import scenario as scenario


def _writer_commits_during_validation(monkeypatch, reader, writer, kind, operation, block):
    entered, release = Event(), Event()
    original = reader._check_record_bytes

    def paused(raw, selected_kind):
        if selected_kind == kind and not entered.is_set():
            entered.set()
            assert release.wait(30), "test did not release canonical validation"
        return original(raw, selected_kind)

    with monkeypatch.context() as patch, ThreadPoolExecutor(max_workers=2) as pool:
        patch.setattr(reader, "_check_record_bytes", paused)
        checking = pool.submit(operation)
        try:
            assert entered.wait(10), "the exact retry did not validate retained bytes"
            pool.submit(writer.observe, block).result(timeout=3)
            with writer.read_transaction() as db:
                assert db.execute("SELECT block FROM highwater").fetchall() == [(block,)]
        finally:
            release.set()
        assert checking.result(timeout=10) is None


@pytest.fixture
def journal_pair(tmp_path):
    root = tmp_path / "short-snapshot-journal"
    binding = {"schema": "execution-short-snapshot-test/1"}
    owner = RoundJournal(root, binding)
    peer = RoundJournal(root, binding)
    return owner, peer


@pytest.mark.parametrize("reserved", [False, True])
def test_exact_put_validation_releases_snapshot_before_peer_commit(
    journal_pair, monkeypatch, reserved
):
    journal, peer = journal_pair
    value = {"original": True}
    raw = canonical_json_bytes(value)
    if reserved:
        journal.reserve_records(
            "batch", (RecordReservation("intent", "sample", 1024, sha256_hex(raw)),)
        )
    journal.put("intent", "sample", value)
    _writer_commits_during_validation(
        monkeypatch,
        journal,
        peer,
        "intent",
        lambda: journal.put("intent", "sample", value),
        23,
    )
    assert journal.get_raw("intent", "sample") == raw


async def test_same_order_history_validation_releases_snapshot_before_peer_commit(
    execution, monkeypatch
):
    e = execution
    executor = e.executor()
    source, boundary = await executor.current(e.assignment)
    journal = executor.journal.journal
    peer = e.journal().journal
    _writer_commits_during_validation(
        monkeypatch,
        journal,
        peer,
        "order_history",
        lambda: histories._remember_order_history_head(journal, source),
        boundary.block + 1,
    )
    with journal.read_transaction() as db:
        assert db.execute(
            "SELECT history FROM order_heads WHERE cohort=?", (digest(source.history.plan),)
        ).fetchone() == (digest(source),)


@pytest.mark.parametrize("damage", ["missing", "noncanonical", "changed", "held"])
async def test_same_order_history_still_rejects_damaged_retained_bytes(execution, damage):
    executor = execution.executor()
    source, _ = await executor.current(execution.assignment)
    journal = executor.journal.journal
    key = digest(source)
    with journal.transaction() as db:
        if damage == "missing":
            db.execute("DELETE FROM records WHERE kind='order_history' AND id=?", (key,))
        elif damage == "held":
            db.execute("INSERT INTO holds VALUES (?)", (key,))
        else:
            raw = b" " + canonical_json_bytes(source) if damage == "noncanonical" else b"{}"
            db.execute("UPDATE records SET body=? WHERE kind='order_history' AND id=?", (raw, key))
    message = (
        "conflict held"
        if damage == "held"
        else "not canonical"
        if damage == "noncanonical"
        else "changed or disappeared"
    )
    with pytest.raises(ValueError, match=message):
        histories._remember_order_history_head(journal, source)


@pytest.mark.parametrize("damage", ["hash", "size"])
def test_exact_put_keeps_bound_reservation_checks_after_short_snapshot(journal_pair, damage):
    journal, _ = journal_pair
    original = {"v": 1}
    raw = canonical_json_bytes(original)
    journal.reserve_records(
        "batch",
        (
            RecordReservation(
                "intent", "sample", len(raw) if damage == "size" else 1024, sha256_hex(raw)
            ),
        ),
    )
    journal.put("intent", "sample", original)
    changed = {"v": "longer"} if damage == "size" else {"v": 2}
    with journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind='intent' AND id='sample'",
            (canonical_json_bytes(changed),),
        )
    with pytest.raises(ValueError, match="differs from reservation"):
        journal.put("intent", "sample", changed)


def test_short_exact_put_keeps_fresh_holds_and_native_conflict_path(journal_pair):
    journal, peer = journal_pair
    value = {"original": True}
    journal.put("intent", "sample", value)
    with pytest.raises(ValueError, match="conflict retained"):
        peer.put("intent", "sample", {"original": False})
    with pytest.raises(ValueError, match="conflict held"):
        journal.put("intent", "sample", value)
    with journal.read_transaction() as db:
        assert db.execute(
            "SELECT body FROM records WHERE kind='intent' AND id='sample'"
        ).fetchone() == (canonical_json_bytes(value),)


async def _retained_job(execution, *, maximum_attempts=1):
    executor = execution.executor(maximum_attempts=maximum_attempts)
    source, started = await executor.current(execution.assignment)
    journal = executor.journal
    job = journal.retain(execution.assignment, source, started.block)
    return journal, job, source, started


async def test_attempt_capacity_preflight_reads_while_another_writer_is_active(
    execution, monkeypatch
):
    journal, job, source, started = await _retained_job(execution)
    peer = execution.journal(maximum_attempts=1).journal

    class ReachedReservation(Exception):
        pass

    def reached_reservation(*args, **kwargs):
        raise ReachedReservation

    monkeypatch.setattr(journal.journal, "reserve_records", reached_reservation)
    # A preflight COUNT needs only committed state. Actual attempt publication
    # will still require its own writer after this independent owner releases.
    with ThreadPoolExecutor(max_workers=1) as pool, peer.transaction():
        pending = pool.submit(journal.begin, job, 0, source, started)
        with pytest.raises(ReachedReservation):
            pending.result(timeout=3)


async def test_full_attempt_capacity_refuses_before_reserving_more_records(execution, monkeypatch):
    journal, job, source, started = await _retained_job(execution)
    journal.journal.put("attempt", "other-assignment", {"retained": True})

    def forbidden(*args, **kwargs):
        pytest.fail("full attempt capacity must refuse without reserving records or writing")

    monkeypatch.setattr(journal.journal, "reserve_records", forbidden)
    monkeypatch.setattr(journal.journal, "transaction", forbidden)
    with pytest.raises(ValueError, match="execution attempt capacity exhausted"):
        journal.begin(job, 0, source, started)


async def test_attempt_capacity_is_fenced_again_at_atomic_publication(execution, monkeypatch):
    journal, job, source, started = await _retained_job(execution)
    peer = execution.journal(maximum_attempts=1).journal
    reserve = journal.journal.reserve_records
    reservations = []

    def reserve_with_competing_attempt(key, records):
        reservations.append(key)
        result = reserve(key, records)
        # A different owner's attempt fills the last slot after this preflight.
        # The attempt record and execution_heads insertion must both roll back.
        peer.put("attempt", "competing-assignment", {"retained": True})
        return result

    monkeypatch.setattr(journal.journal, "reserve_records", reserve_with_competing_attempt)
    with pytest.raises(ValueError, match="execution attempt capacity exhausted"):
        journal.begin(job, 0, source, started)
    assert len(reservations) == 1
    with journal.journal.read_transaction() as db:
        assert db.execute("SELECT id FROM records WHERE kind='attempt'").fetchall() == [
            ("competing-assignment",)
        ]
        assert (
            db.execute(
                "SELECT attempt FROM execution_heads WHERE step=?", (execution_step_key(job, 0),)
            ).fetchone()
            is None
        )
    assert journal.head(job, 0) is None
