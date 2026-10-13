"""Derived accounting must preserve old journals and every supported SQL mutation."""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager

import pytest

import umi.competition_round_journal as rounds

from .logging_helpers import progress_payloads


def progress_events(caplog):
    return progress_payloads(caplog.records, logger=rounds.__name__, event="round_journal_progress")


def connection(journal):
    db = sqlite3.connect(journal.path)
    db.create_function("umi_round_writer_generation", 0, lambda: 2)
    return db


def expected(db):
    count, size = db.execute(
        "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM records NOT INDEXED"
    ).fetchone()
    return count, size, dict(db.execute("SELECT kind,COUNT(*) FROM records GROUP BY kind"))


def assert_usage(journal):
    with journal.read_transaction() as db:
        assert journal._record_capacity(db) == expected(db)


def legacy_metadata(journal):
    """Restore the exact pre-counter metadata layout of a synthetic journal."""
    with connection(journal) as db:
        for name in rounds._capacity_triggers():
            db.execute(f'DROP TRIGGER IF EXISTS "{name}"')
        for name in rounds._CAPACITY_TABLES:
            db.execute(f'DROP TABLE IF EXISTS "{name}"')
        db.execute("PRAGMA application_id=0")


@pytest.mark.usefixtures("http_log_redaction")
@pytest.mark.parametrize("reserved", [False, True])
def test_legacy_migration_preserves_bytes_reservations_and_old_writers(tmp_path, reserved, caplog):
    root, binding = tmp_path / "journal", {"original_signed_clock": 9178000}
    journal = rounds.RoundJournal(root, binding)
    if reserved:
        journal.reserve_records("pending", [rounds.RecordReservation("vote", "future", 128)])
    journal.put_many(("proof", str(i), {"original": i}) for i in range(4500))
    with journal.read_transaction() as db:
        records = db.execute("SELECT * FROM records ORDER BY kind,id").fetchall()
        original_binding = db.execute("SELECT body FROM binding").fetchall()
        generation = db.execute("PRAGMA user_version").fetchone()
        usage = journal._capacity(db) if reserved else None
    inode = journal.path.stat().st_ino
    legacy_metadata(journal)
    caplog.set_level(logging.INFO, logger=rounds.__name__)
    reopened = rounds.RoundJournal(root, binding)
    with reopened.read_transaction() as db:
        assert db.execute("SELECT * FROM records ORDER BY kind,id").fetchall() == records
        assert db.execute("SELECT body FROM binding").fetchall() == original_binding
        assert db.execute("PRAGMA user_version").fetchone() == generation
        if reserved:
            assert reopened._capacity(db) == usage
    assert reopened.path.stat().st_ino == inode
    assert_usage(reopened)
    progress = progress_events(caplog)
    if reserved:
        assert progress == []
    else:
        assert progress[-1]["state"] == "completed"
        assert progress[-1]["completed_records"] == 4500
        assert progress[-1]["eta_seconds"] == 0
        assert any(p["completed_records"] == 4096 for p in progress)
        assert any(p["planning_eta_seconds"] is not None for p in progress)
    # An already-open native owner and an older SQL writer both preserve counts.
    journal.put("vote", "future", {})
    with connection(journal) as old:
        old.execute("INSERT INTO records VALUES ('old','one',X'7b7d')")
        old.execute("UPDATE records SET kind='moved',body=X'7b2276223a317d' WHERE kind='old'")
        old.execute("DELETE FROM records WHERE kind='moved'")
    assert_usage(reopened)
    caplog.clear()
    rounds.RoundJournal(root, binding)
    assert not progress_events(caplog)


@pytest.mark.parametrize("reserved", [False, True])
def test_direct_mutations_savepoints_replacements_and_rollback(tmp_path, reserved):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    if reserved:
        journal.reserve_records("pending", [rounds.RecordReservation("vote", "a", 64)])
    journal.put_many((("vote", "a", {}), ("vote", "b", {"longer": True})))
    with journal.transaction() as db:
        db.execute("SAVEPOINT before_mutation")
        db.execute("UPDATE records SET body=X'7b7d',kind='changed' WHERE id='a'")
        assert journal._record_capacity(db) == expected(db)
        db.execute("ROLLBACK TO before_mutation")
        assert journal._record_capacity(db) == expected(db)
        db.execute("INSERT OR IGNORE INTO records VALUES ('vote','a',X'00')")
        assert journal._record_capacity(db) == expected(db)
        db.execute("INSERT OR REPLACE INTO records VALUES ('vote','a',X'7b2278223a307d')")
        assert journal._record_capacity(db) == expected(db)
        db.execute("UPDATE OR REPLACE records SET id='b',body=X'7b7d' WHERE id='a'")
        assert journal._record_capacity(db) == expected(db)
    with pytest.raises(RuntimeError, match="interrupt"), journal.transaction() as db:
        db.execute("DELETE FROM records")
        assert journal._record_capacity(db) == (0, 0, {})
        raise RuntimeError("interrupt")
    assert_usage(journal)
    rounds.RoundJournal(journal.root, {})
    assert_usage(journal)


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT OR REPLACE INTO records VALUES ('vote','a',X'7b7d')",
        "UPDATE OR REPLACE records SET id='a' WHERE id='b'",
    ],
)
def test_old_sql_replacement_without_recursive_delete_is_refused_before_mutation(tmp_path, sql):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    journal.put_many((("vote", "a", {"original": True}), ("vote", "b", {})))
    with connection(journal) as db:
        before = db.execute("SELECT * FROM records ORDER BY id").fetchall()
        with pytest.raises(sqlite3.IntegrityError, match="requires recursive triggers"):
            db.execute(sql)
        assert db.execute("SELECT * FROM records ORDER BY id").fetchall() == before
    assert_usage(journal)


@pytest.mark.usefixtures("http_log_redaction")
@pytest.mark.parametrize(
    "damage",
    [
        "DROP TABLE round_record_capacity_kinds",
        "DROP TRIGGER round_record_capacity_insert",
        "DELETE FROM round_record_capacity",
        "DELETE FROM round_record_capacity_kinds",
        "UPDATE round_record_capacity SET number=number+1",
        "UPDATE round_record_capacity_kinds SET nbytes=nbytes+1",
    ],
)
def test_damage_requires_explicit_metadata_only_repair(tmp_path, damage, caplog):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    journal.put("signed", "one", {"unchanged": "exact original bytes"})
    with connection(journal) as db:
        before = db.execute("SELECT * FROM records").fetchall()
        db.execute(damage)
    caplog.set_level(logging.INFO, logger=rounds.__name__)
    with pytest.raises(rounds.RoundCapacityRepairRequired, match="repair required"):
        rounds.RoundJournal(journal.root, {})
    assert any(event["state"] == "repair_required" for event in progress_events(caplog))
    recovered = rounds.RoundJournal(journal.root, {}, repair_record_capacity=True)
    assert_usage(recovered)
    with recovered.read_transaction() as db:
        assert db.execute("SELECT * FROM records").fetchall() == before
    assert progress_events(caplog)[-1]["state"] == "completed"
    assert progress_events(caplog)[-1]["stage"] == "record_capacity_repair"
    recovered.put("signed", "next", {})
    assert_usage(recovered)


def test_lost_all_auxiliary_tables_are_not_a_legacy_journal(tmp_path):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    with connection(journal) as db:
        for name in rounds._capacity_triggers():
            db.execute(f'DROP TRIGGER "{name}"')
        for name in rounds._CAPACITY_TABLES:
            db.execute(f'DROP TABLE "{name}"')
    with pytest.raises(rounds.RoundCapacityRepairRequired, match="repair required"):
        rounds.RoundJournal(journal.root, {})
    rounds.RoundJournal(journal.root, {}, repair_record_capacity=True)


def test_reservation_transition_preserves_accounting_and_original_generation_fences(tmp_path):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    receipt = journal.reserve_records("pending", [rounds.RecordReservation("vote", "a", 64)])
    recovered = rounds.RoundJournal(journal.root, {}, repair_record_capacity=True)
    assert recovered.reservation("pending") == receipt
    with recovered.read_transaction() as db:
        assert db.execute("PRAGMA application_id").fetchone() == (0,)
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name GLOB 'round_record_capacity*'"
        ).fetchall()
    recovered.put("vote", "a", {})
    assert_usage(recovered)
    with connection(journal) as db:
        db.execute("DROP TRIGGER round_generation_records_insert")
    with pytest.raises(ValueError, match="fence missing or changed"):
        rounds.RoundJournal(journal.root, {}, repair_record_capacity=True)


def test_hot_put_does_not_rescan_retained_record_lengths(tmp_path, monkeypatch):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    journal.put_many(("proof", str(i), {"bytes": "x" * 10}) for i in range(20000))
    original = journal.transaction
    statements = []

    @contextmanager
    def traced():
        with original() as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(journal, "transaction", traced)
    journal.put("proof", "new", {})
    aggregates = [s for s in statements if "COUNT(" in s.upper() or "SUM(" in s.upper()]
    assert not any("FROM records" in s for s in aggregates)
    assert any(
        "SELECT kind,number,nbytes FROM round_record_capacity_kinds" in s for s in statements
    )
    assert_usage(journal)


def test_telemetry_failure_cannot_fail_a_committed_migration(tmp_path, monkeypatch):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    journal.put("proof", "a", {})
    legacy_metadata(journal)

    def broken_handler(*_args, **_kwargs):
        raise RuntimeError("logging failed")

    monkeypatch.setattr(rounds.logger, "info", broken_handler)
    reopened = rounds.RoundJournal(journal.root, {})
    assert_usage(reopened)
    assert reopened._capacity_migration is None


@pytest.mark.usefixtures("http_log_redaction")
def test_interrupted_migration_rolls_back_only_derived_metadata(tmp_path, monkeypatch, caplog):
    journal = rounds.RoundJournal(tmp_path / "journal", {})
    journal.put("signed", "a", {"original": True})
    legacy_metadata(journal)
    caplog.set_level(logging.INFO, logger=rounds.__name__)

    def interrupted(_db):
        raise RuntimeError("before commit")

    with monkeypatch.context() as patch:
        patch.setattr(rounds.RoundJournal, "_record_capacity", staticmethod(interrupted))
        with pytest.raises(RuntimeError, match="before commit"):
            rounds.RoundJournal(journal.root, {})
    assert progress_events(caplog)[-1]["state"] == "retrying"
    assert progress_events(caplog)[-1]["eta_seconds"] is None
    with connection(journal) as db:
        assert db.execute("PRAGMA application_id").fetchone() == (0,)
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name GLOB 'round_record_capacity*'"
        ).fetchall()
    reopened = rounds.RoundJournal(journal.root, {})
    assert reopened.get("signed", "a") == {"original": True}
    assert_usage(reopened)
