from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_round_reservation_checkpoint as checkpoint
from umi.competition_round_journal import RecordReservation, RoundJournal
from umi.protocol import canonical_json_bytes


def insert(db, rowid, key):
    raw = canonical_json_bytes(dict(kind="vote", key=key, maximum_bytes=64, value_sha256=None))
    db.execute(
        "INSERT INTO record_reservations(rowid,kind,id,maximum_bytes,value_sha256,document) "
        "VALUES (?,'vote',?,64,NULL,?)",
        (rowid, key, raw),
    )


def old_writer(journal):
    db = sqlite3.connect(journal.path, isolation_level=None)
    db.create_function("umi_round_writer_generation", 0, lambda: 2)
    db.execute("PRAGMA recursive_triggers=ON")
    return db


def legacy(tmp_path, rowids):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    journal.reserve_records("empty", ())
    with old_writer(journal) as db:
        db.execute("BEGIN IMMEDIATE")
        for name in checkpoint.SCHEMA:
            category = "TABLE" if name in {checkpoint.STATE, checkpoint.PENDING} else "TRIGGER"
            db.execute(f"DROP {category} {name}")
        db.execute(
            "DELETE FROM records WHERE kind=? AND id=?",
            (checkpoint.MARKER_KIND, checkpoint.MARKER_ID),
        )
        for index, rowid in enumerate(rowids):
            insert(db, rowid, str(index))
        db.commit()
    return journal


def counter(monkeypatch):
    seen = []
    decode = RoundJournal._decode_obligation

    def observe(cls, row):
        seen.append(row[1])
        return decode(row)

    monkeypatch.setattr(RoundJournal, "_decode_obligation", classmethod(observe))
    return seen


def test_initial_restart_and_unchanged_writes_decode_once(tmp_path, monkeypatch):
    journal = legacy(tmp_path, [-(2**63), -1, 0, 1, 2**63 - 1])
    seen = counter(monkeypatch)
    reopened = RoundJournal(journal.root, {}, maximum_rounds=32)
    assert seen == ["0", "1", "2", "3", "4"]
    seen.clear()
    for index in range(3):
        reopened.put("other", str(index), {})
    restarted = RoundJournal(journal.root, {}, maximum_rounds=32)
    restarted.put("other", "last", {})
    assert seen == []
    with restarted.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (2,)
        assert db.execute("PRAGMA application_id").fetchone() == (0,)
        assert restarted._capacity(db) == restarted._capacity_totals(db)


def test_initial_interruption_resumes_cursor_and_overlapping_additions(tmp_path, monkeypatch):
    journal = legacy(tmp_path, [-100, 0, 100, 1000])
    monkeypatch.setattr(checkpoint, "CHUNK_SIZE", 2)
    decode = RoundJournal._decode_obligation
    seen = []

    def interrupt(cls, row):
        if len(seen) == 2:
            raise RuntimeError("interruption")
        seen.append(row[1])
        return decode(row)

    monkeypatch.setattr(RoundJournal, "_decode_obligation", classmethod(interrupt))
    with pytest.raises(RuntimeError, match="interruption"):
        RoundJournal(journal.root, {}, maximum_rounds=32)
    assert seen == ["0", "1"]
    with old_writer(journal) as db:
        insert(db, -200, "behind")
        insert(db, 50, "overlap")
        insert(db, 2000, "beyond")
    seen = counter(monkeypatch)

    # Restore the true decoder rather than the intentional interruption hook.
    def observe(cls, row):
        seen.append(row[1])
        return decode(row)

    monkeypatch.setattr(RoundJournal, "_decode_obligation", classmethod(observe))
    RoundJournal(journal.root, {}, maximum_rounds=32)
    assert sorted(seen) == sorted(["2", "3", "behind", "overlap", "beyond"])


def test_older_writer_additions_readonly_and_rollback(tmp_path, monkeypatch):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    receipt = journal.reserve_records("batch", (RecordReservation("vote", "initial", 64),))
    with old_writer(journal) as db:
        insert(db, -(2**63), "low")
        insert(db, 2**63 - 1, "high")
    seen = counter(monkeypatch)
    holder = old_writer(journal)
    try:
        holder.execute("BEGIN IMMEDIATE")
        assert journal.reservation("batch") == receipt
        assert sorted(seen) == ["high", "initial", "low"]
        with sqlite3.connect(journal.path) as db:
            assert db.execute(f"SELECT COUNT(*) FROM {checkpoint.PENDING}").fetchone() == (2,)
    finally:
        holder.rollback()
        holder.close()
    seen.clear()
    with pytest.raises(RuntimeError, match="rollback"), journal.transaction() as db:
        journal._capacity(db)
        raise RuntimeError("rollback")
    with sqlite3.connect(journal.path) as db:
        assert db.execute(f"SELECT COUNT(*) FROM {checkpoint.PENDING}").fetchone() == (2,)
    seen.clear()
    journal.put("other", "new", {})
    assert sorted(seen) == ["high", "low"]
    seen.clear()
    journal.put("other", "another", {})
    assert seen == []


@pytest.mark.parametrize(
    "damage", ["missing_state", "missing_pending", "missing_marker", "epoch", "abi"]
)
def test_damaged_completion_never_becomes_a_cache_miss(tmp_path, monkeypatch, damage):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    journal.reserve_records("batch", (RecordReservation("vote", "initial", 64),))
    with old_writer(journal) as db:
        if damage == "missing_state":
            db.execute(f"DELETE FROM {checkpoint.STATE}")
        elif damage == "missing_pending":
            insert(db, -1, "new")
            db.execute(f"DELETE FROM {checkpoint.PENDING}")
        elif damage == "missing_marker":
            db.execute(
                "DELETE FROM records WHERE kind=? AND id=?",
                (checkpoint.MARKER_KIND, checkpoint.MARKER_ID),
            )
        elif damage == "epoch":
            name, sql = db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND name='record_reservations_immutable_update'"
            ).fetchone()
            db.execute(f'DROP TRIGGER "{name}"')
            db.execute(sql)
        else:
            monkeypatch.setattr(checkpoint, "ABI", "different-semantics")
    with pytest.raises(checkpoint.ReservationValidationRepairRequired, match="repair required"):
        journal.put("other", "new", {})


def test_explicit_repair_after_external_ddl_revalidates_once(tmp_path, monkeypatch):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    journal.reserve_records("batch", (RecordReservation("vote", "initial", 64),))
    with old_writer(journal) as db:
        db.execute("CREATE INDEX older_external_index ON records(id)")
    with pytest.raises(checkpoint.ReservationValidationRepairRequired):
        RoundJournal(journal.root, {}, maximum_rounds=32)
    seen = counter(monkeypatch)
    repaired = RoundJournal(journal.root, {}, maximum_rounds=32, repair_reservation_validation=True)
    assert seen == ["initial"]
    seen.clear()
    repaired.put("other", "new", {})
    assert seen == []


def test_native_ddl_cannot_remove_source_fences(tmp_path):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    journal.reserve_records("batch", ())
    with pytest.raises(sqlite3.DatabaseError, match="authorized"), journal.transaction() as db:
        db.execute("DROP TRIGGER record_reservations_immutable_update")
    with journal.transaction() as db:
        db.execute("CREATE TABLE ordinary_native_index (id TEXT)")
    journal.put("other", "new", {})


def test_first_enable_installs_authorizer_before_returning_to_caller(tmp_path):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    with pytest.raises(sqlite3.DatabaseError, match="authorized"), journal.transaction() as db:
        journal.reserve_records("batch", (), db=db)
        db.execute("DROP TRIGGER record_reservations_immutable_update")
    with journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (0,)


def test_derived_fence_repair_preserves_strict_source_fences(tmp_path, monkeypatch):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    journal.reserve_records("batch", (RecordReservation("vote", "initial", 64),))
    with old_writer(journal) as db:
        db.execute(f"DROP TRIGGER round_generation_{checkpoint.STATE}_update")
    seen = counter(monkeypatch)
    RoundJournal(journal.root, {}, maximum_rounds=32, repair_reservation_validation=True)
    assert seen == ["initial"]
    with old_writer(journal) as db:
        db.execute("DROP TRIGGER record_reservations_immutable_update")
    with pytest.raises(ValueError, match="fence missing or changed"):
        RoundJournal(journal.root, {}, maximum_rounds=32, repair_reservation_validation=True)


def test_full_capacity_conflict_retains_hold_without_extra_capacity_pass(tmp_path, monkeypatch):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    journal.reserve_records("batch", (RecordReservation("vote", "initial", 64),))
    journal.put("vote", "initial", {})
    with journal.read_transaction() as db:
        journal.maximum_bytes = journal._capacity(db)[1]
    monkeypatch.setattr(journal, "_capacity_totals", lambda _: pytest.fail("extra capacity pass"))
    with pytest.raises(ValueError, match="conflict"):
        journal.put("vote", "initial", {"changed": True})
    with journal.read_transaction() as db:
        assert db.execute("SELECT id FROM holds").fetchall() == [("initial",)]


def test_checkpoint_authorizer_keeps_physical_budget_guards(tmp_path):
    from umi.competition_journal_physical_budget import JournalPhysicalBudget

    journal = RoundJournal(
        tmp_path / "journal",
        {},
        maximum_rounds=32,
        physical_budget=JournalPhysicalBudget(16 * 1024**2, 0, 4096),
    )
    journal.reserve_records("batch", ())
    for statement in (
        "ATTACH ':memory:' AS extra",
        "PRAGMA cache_spill=ON",
        "DROP TRIGGER record_reservations_immutable_update",
    ):
        with pytest.raises(sqlite3.DatabaseError, match="authorized"), journal.transaction() as db:
            db.execute(statement)


def test_mutable_receipt_drains_old_writer_success_once(tmp_path, monkeypatch):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    journal.reserve_records("batch", (RecordReservation("vote", "initial", 64),))
    with old_writer(journal) as db:
        insert(db, -100, "added")
    seen = counter(monkeypatch)
    journal.reservation("batch")
    assert seen == ["added", "initial"]
    seen.clear()
    journal.reservation("batch")
    assert seen == ["initial"]  # Exact requested receipt still checks its own obligation.


def test_invalid_legacy_allowance_is_not_checkpointed(tmp_path):
    journal = legacy(tmp_path, [1, 2])
    with old_writer(journal) as db:
        name, sql = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
            "AND name='record_reservations_immutable_update'"
        ).fetchone()
        db.execute(f'DROP TRIGGER "{name}"')
        db.execute("UPDATE record_reservations SET maximum_bytes=1 WHERE id='1'")
        db.execute(sql)
    with pytest.raises(ValueError, match="allowance columns changed"):
        RoundJournal(journal.root, {}, maximum_rounds=32)
    with sqlite3.connect(journal.path) as db:
        assert not checkpoint.installed(db)


class AggregateCountSnapshot:
    """Scale only aggregate results, keeping real native schema/binding checks.

    A reviewer may have millions of lifetime obligations. Materializing that
    history in a regression would test SQLite bulk insertion instead of the
    checkpoint's compatibility with its supported count envelope.
    """

    def __init__(self, db, count):
        self.db, self.count = db, count

    def execute(self, sql, *args):
        if sql == f"SELECT * FROM {checkpoint.STATE} LIMIT 2":
            state = list(self.db.execute(sql, *args).fetchone())
            state[5] = state[6] = self.count
            return SimpleNamespace(fetchall=lambda: [tuple(state)])
        if sql == "SELECT COUNT(*) FROM record_reservations":
            return SimpleNamespace(fetchone=lambda: (self.count,))
        return self.db.execute(sql, *args)


@pytest.mark.parametrize("count", [65536 * 80 + 1, 2**53 - 1, 2**63 - 1])
def test_checkpoint_count_integrity_does_not_shorten_service_review_envelope(
    tmp_path, monkeypatch, count
):
    from umi.competition_cohort_service_review import _ServiceReviewJournal

    journal = _ServiceReviewJournal(tmp_path / "reviewer", {}, maximum_rounds=1)
    journal.reserve_records("batch", (RecordReservation("vote", "initial", 64),))
    assert journal.maximum_records > 65536 * 80
    seen = counter(monkeypatch)
    with journal.read_transaction() as db:
        projected = AggregateCountSnapshot(db, count)
        state = checkpoint.check(journal, projected)
        assert state[5:7] == (count, count)
        assert checkpoint.advance(journal, projected, "", readonly=True)
    assert seen == []


@pytest.mark.parametrize("count", [-1, 2**63, True, 1.0])
def test_checkpoint_still_refuses_invalid_count_integrity(tmp_path, count):
    journal = RoundJournal(tmp_path / "journal", {})
    journal.reserve_records("batch", ())
    with (
        journal.read_transaction() as db,
        pytest.raises(
            checkpoint.ReservationValidationRepairRequired,
            match="checkpoint or validation dependency changed",
        ),
    ):
        checkpoint.check(journal, AggregateCountSnapshot(db, count))
