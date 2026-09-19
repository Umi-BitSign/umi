from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from umi.competition_round_journal import MAX_BYTES, RecordReservation, RoundJournal
from umi.protocol import canonical_json_bytes, sha256_hex


@pytest.fixture
def journal(tmp_path):
    return RoundJournal(tmp_path / "journal", {"purpose": "capacity"}, maximum_rounds=4)


def spec(kind="vote", key="one", value=None, *, maximum_bytes=4096):
    return RecordReservation(
        kind,
        key,
        maximum_bytes,
        None if value is None else sha256_hex(canonical_json_bytes(value)),
    )


def state(journal):
    with sqlite3.connect(journal.path) as db:
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        ).fetchall()
        return {
            "version": db.execute("PRAGMA user_version").fetchone()[0],
            "tables": {
                name: db.execute(f'SELECT * FROM "{name}"').fetchall() for (name,) in tables
            },
            "triggers": db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
            ).fetchall(),
        }


def usage(journal):
    with journal.transaction() as db:
        return journal._capacity(db)


def test_legacy_journal_writes_until_explicit_reservation(journal):
    journal.put("vote", "old", {"vote": 1})
    assert state(journal)["version"] == 0
    assert journal.reservation("absent") is None
    with sqlite3.connect(journal.path) as db:
        db.execute("INSERT INTO records VALUES ('vote','legacy',?)", (b"{}",))
    receipt = journal.reserve_records("batch", (spec(),))
    assert state(journal)["version"] == 2
    assert receipt["generation"] == 2
    assert journal.get("vote", "legacy") == {}


def test_reservation_is_private_atomic_and_recoverable(journal):
    specs = (spec(value={"x": 1}), spec("intent", "two"))
    receipt = journal.reserve_records("batch", iter(specs))
    assert journal.get("vote", "one") is None
    before = state(journal)
    assert journal.reserve_records("batch", reversed(specs)) == receipt
    assert journal.reservation("batch") == receipt
    assert state(journal) == before
    recovered = RoundJournal(journal.root, {"purpose": "capacity"}, maximum_rounds=4)
    assert recovered.reservation("batch") == receipt
    assert receipt["journal_path"] == str(journal.path.resolve())
    assert len(receipt["journal_identity"]) == 64
    assert receipt["binding_sha256"] == sha256_hex(canonical_json_bytes({"purpose": "capacity"}))
    assert receipt["maximum_bytes"] == journal.maximum_bytes
    assert receipt["maximum_rounds"] == 4


def test_database_identity_is_not_just_path_or_configuration(tmp_path):
    a = RoundJournal(tmp_path / "a", {})
    b = RoundJournal(tmp_path / "b", {})
    first = a.reserve_records("batch", (spec(),))
    second = b.reserve_records("batch", (spec(),))
    assert first["journal_identity"] != second["journal_identity"]
    assert first["binding_sha256"] == second["binding_sha256"]


def test_capacity_can_increase_but_cannot_drop_below_obligations(journal):
    receipt = journal.reserve_records("batch", (spec(),))
    journal.maximum_bytes += 1
    journal.maximum_rounds += 1
    assert journal.reservation("batch") == receipt
    assert journal.reserve_records("batch", (spec(),)) == receipt
    journal.maximum_bytes = 1024
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reservation("batch")


def test_existing_records_consume_credit_at_admission(journal):
    value = {"existing": True}
    journal.put("vote", "one", value)
    journal.reserve_records("batch", (spec(value=value, maximum_bytes=MAX_BYTES),))
    _, used, kinds = usage(journal)
    assert used < MAX_BYTES
    assert kinds["vote"] == 1
    before = state(journal)
    journal.put("vote", "one", value)
    assert state(journal) == before


def test_shared_obligation_is_counted_once_across_batches(journal):
    journal.reserve_records("first", (spec(maximum_bytes=8000),))
    before = usage(journal)
    journal.reserve_records("other", (spec(maximum_bytes=8000),))
    after = usage(journal)
    assert after[2] == before[2] == {"vote": 1}
    assert after[0] == before[0] + 1  # Only the additional batch manifest.
    assert 0 < after[1] - before[1] < 8000


def test_identical_duplicate_specs_are_idempotent(journal):
    receipt = journal.reserve_records("batch", (spec(), spec()))
    assert journal.reserve_records("batch", (spec(),)) == receipt


@pytest.mark.parametrize("change", ["batch", "identity", "duplicate"])
def test_changed_reservation_is_rejected_without_mutation(journal, change):
    journal.reserve_records("batch", (spec(),))
    before = state(journal)
    with pytest.raises(ValueError, match=r"changed|conflict"):
        if change == "batch":
            journal.reserve_records("batch", (spec(key="two"),))
        elif change == "identity":
            journal.reserve_records("other", (spec(maximum_bytes=4097),))
        else:
            journal.reserve_records("other", (spec(key="two"), spec(key="two", maximum_bytes=1)))
    assert state(journal) == before


@pytest.mark.parametrize("problem", ["bytes", "kind", "total"])
def test_whole_batch_capacity_failure_rolls_back_migration(tmp_path, problem):
    journal = RoundJournal(
        tmp_path / "journal",
        {},
        maximum_rounds=1,
        maximum_bytes=81920 if problem == "total" else 8192,
    )
    journal.put("vote", "existing", {})
    before = state(journal)
    if problem == "bytes":
        specs = (spec(maximum_bytes=8192),)
    elif problem == "kind":
        specs = (spec("intent", "a"), spec("intent", "b"))
    else:
        specs = tuple(spec("vote", str(i), maximum_bytes=1) for i in range(80))
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reserve_records("batch", specs)
    assert state(journal) == before


def test_capacity_includes_retained_binding_and_reservation_metadata(tmp_path):
    journal = RoundJournal(tmp_path / "journal", {"large": "x" * 900}, maximum_bytes=1024)
    journal.put("vote", "one", {})
    before = state(journal)
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reserve_records("batch", (spec(maximum_bytes=2),))
    assert state(journal) == before


def test_complete_batch_is_rolled_back_on_generator_error(journal):
    def broken():
        yield spec()
        raise RuntimeError("input failed")

    before = state(journal)
    with pytest.raises(RuntimeError, match="input failed"):
        journal.reserve_records("batch", broken())
    assert state(journal) == before


@pytest.mark.parametrize(
    "invalid",
    [
        RecordReservation("", "a", 1),
        RecordReservation("vote", "", 1),
        RecordReservation("vote", "a", 0),
        RecordReservation("vote", "a", MAX_BYTES + 1),
        RecordReservation("vote", "a", True),
        RecordReservation("vote", "a", 1, "x" * 64),
        RecordReservation("vote", "a", 1, "A" * 64),
        ("vote", "a", 1),
    ],
)
def test_specs_are_strictly_bounded_before_migration(journal, invalid):
    before = state(journal)
    with pytest.raises(ValueError, match="invalid round"):
        journal.reserve_records("batch", (invalid,))
    assert state(journal) == before


def test_matching_write_consumes_only_own_credit_once(journal):
    value = {"v": "x" * 100}
    journal.reserve_records("batch", (spec(value=value, maximum_bytes=4096), spec(key="two")))
    before = usage(journal)
    journal.put("vote", "one", value)
    after = usage(journal)
    assert after[0] == before[0]
    assert after[1] == before[1] - 4096 + len(canonical_json_bytes(value))
    assert after[2] == before[2] == {"vote": 2}
    retained = state(journal)
    journal.put("vote", "one", value)
    assert state(journal) == retained
    assert journal.reservation("batch") is not None


def test_exact_fit_reserved_writes_work_but_unrelated_write_cannot_spend_credit(journal):
    value = "x" * 4094
    journal.reserve_records("batch", (spec(value=value), spec(key="two")))
    # Set the accounting ceiling to the measured promise, without altering the
    # persisted admission configuration; this exercises the write accounting.
    journal.maximum_bytes = usage(journal)[1]
    before = state(journal)
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.put("vote", "unrelated", {})
    assert state(journal) == before
    journal.put("vote", "one", value)
    assert usage(journal)[1] == journal.maximum_bytes
    journal.put("vote", "two", value)
    assert usage(journal)[1] == journal.maximum_bytes
    journal.observe(2**53 - 1)
    assert usage(journal)[1] == journal.maximum_bytes


def test_reserved_per_kind_count_blocks_unrelated_write(journal):
    journal.reserve_records("batch", tuple(spec("intent", str(i)) for i in range(4)))
    before = state(journal)
    with pytest.raises(ValueError, match="record capacity exhausted"):
        journal.put("intent", "other", {})
    assert state(journal) == before
    journal.put_many(("intent", str(i), {}) for i in range(4))
    assert usage(journal)[2]["intent"] == 4


def test_oversized_write_does_not_consume_obligation(journal):
    journal.reserve_records("batch", (spec(maximum_bytes=2),))
    before = state(journal)
    with pytest.raises(ValueError, match="reserved allowance"):
        journal.put("vote", "one", {"long": "value"})
    assert state(journal) == before
    journal.put("vote", "one", {})


def test_hash_disagreement_retains_hold_without_partial_writes(journal):
    journal.reserve_records("batch", (spec(value={"exact": True}), spec(key="two")))
    before = state(journal)
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put_many((("vote", "two", {}), ("vote", "one", {"exact": False})))
    after = state(journal)
    before["tables"]["holds"] = [("one",)]
    assert after == before
    with pytest.raises(ValueError, match="conflict held"):
        journal.reservation("batch")


def test_callback_failure_rolls_back_records_and_credit(journal):
    journal.reserve_records("batch", (spec(), spec(key="two")))
    before = state(journal)

    def fail(db):
        db.execute("INSERT INTO highwater VALUES (1)")
        raise RuntimeError("index failed")

    with pytest.raises(RuntimeError, match="index failed"):
        journal.put_many((("vote", "one", {}), ("vote", "two", {})), index=fail)
    assert state(journal) == before


def test_retained_mismatch_or_hold_prevents_admission(journal):
    journal.put("vote", "one", {"value": 1})
    before = state(journal)
    with pytest.raises(ValueError, match="differs from reservation"):
        journal.reserve_records("batch", (spec(value={"value": 2}),))
    assert state(journal) == before
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put("vote", "one", {})
    with pytest.raises(ValueError, match="conflict held"):
        journal.reserve_records("batch", (spec(),))
    assert state(journal)["version"] == 0


def test_independent_openers_cannot_oversubscribe_a_kind(tmp_path):
    root = tmp_path / "journal"
    journals = [RoundJournal(root, {}, maximum_rounds=1) for _ in range(2)]
    barrier = Barrier(2)

    def reserve(index):
        barrier.wait()
        try:
            journals[index].reserve_records(str(index), (spec("intent", str(index)),))
            return "retained"
        except ValueError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(reserve, range(2)))
    assert sorted(outcomes) == ["retained", "round journal record capacity exhausted"]
    assert usage(journals[0])[2] == {"intent": 1}


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO records VALUES ('vote','old',X'7b7d')",
        "UPDATE records SET body=X'7b7d' WHERE id='existing'",
        "DELETE FROM records WHERE id='existing'",
        "INSERT INTO holds VALUES ('held')",
        "UPDATE binding SET body=X'7b7d'",
        "INSERT INTO highwater VALUES (1)",
        "INSERT INTO caller_index VALUES ('old',1)",
    ],
)
def test_preopened_old_connection_cannot_mutate_after_migration(journal, sql):
    journal.put("vote", "existing", {"old": True})
    with journal.transaction() as db:
        db.execute("CREATE TABLE caller_index (id TEXT PRIMARY KEY, value INTEGER)")
    old = sqlite3.connect(journal.path, isolation_level=None)
    try:
        assert old.execute("PRAGMA user_version").fetchone()[0] == 0
        journal.reserve_records("batch", (spec(),))
        before = state(journal)
        with pytest.raises(sqlite3.OperationalError, match="umi_round_writer_generation"):
            old.execute(sql)
        assert state(journal) == before
    finally:
        old.close()


def test_indexes_created_by_current_openers_are_fenced(journal):
    journal.reserve_records("batch", (spec(),))
    with journal.transaction() as db:
        db.execute("CREATE TABLE late_index (id TEXT PRIMARY KEY)")
        db.execute("INSERT INTO late_index VALUES ('current')")
    with (
        sqlite3.connect(journal.path) as old,
        pytest.raises(sqlite3.OperationalError, match="umi_round_writer_generation"),
    ):
        old.execute("INSERT INTO late_index VALUES ('old')")


@pytest.mark.parametrize(
    "table",
    [
        "record_reservations",
        "record_reservation_batches",
        "record_reservation_identity",
    ],
)
def test_reservation_evidence_is_append_only(journal, table):
    journal.reserve_records("batch", (spec(),))
    before = state(journal)
    with (
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
        journal.transaction() as db,
    ):
        db.execute(f"DELETE FROM {table}")
    assert state(journal) == before


def test_unknown_private_capability_is_rejected(journal):
    with sqlite3.connect(journal.path) as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(ValueError, match="unsupported"):
        journal.put("vote", "one", {})


def corrupt(journal, table, sql, arguments=()):
    """Inject retained-state damage while restoring the exact fence definitions."""
    with sqlite3.connect(journal.path) as db:
        db.create_function("umi_round_writer_generation", 0, lambda: 2)
        triggers = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)
        ).fetchall()
        for name, _definition in triggers:
            db.execute(f'DROP TRIGGER "{name}"')
        db.execute(sql, arguments)
        for _name, definition in triggers:
            db.execute(definition)


@pytest.mark.parametrize("operation", ["retry", "receipt"])
def test_missing_obligation_is_never_recreated_by_retry(journal, operation):
    journal.reserve_records("batch", (spec(), spec(key="two")))
    corrupt(journal, "record_reservations", "DELETE FROM record_reservations WHERE id='one'")
    before = state(journal)
    with pytest.raises(ValueError, match="obligation missing or changed"):
        if operation == "retry":
            journal.reserve_records("batch", (spec(), spec(key="two")))
        else:
            journal.reservation("batch")
    assert state(journal) == before


@pytest.mark.parametrize("operation", ["retry", "receipt", "write", "other_write"])
@pytest.mark.parametrize(
    "column,value",
    [
        ("maximum_bytes", 1),
        ("maximum_bytes", "x" * 10000),
        ("value_sha256", "0" * 64),
        ("value_sha256", "x" * 10000),
    ],
)
def test_allowance_sql_columns_must_match_canonical_spec(journal, operation, column, value):
    journal.reserve_records("batch", (spec(),))
    corrupt(journal, "record_reservations", f"UPDATE record_reservations SET {column}=?", (value,))
    before = state(journal)
    with pytest.raises(ValueError, match="allowance columns changed"):
        if operation == "retry":
            journal.reserve_records("batch", (spec(),))
        elif operation == "receipt":
            journal.reservation("batch")
        else:
            journal.put("vote", "one" if operation == "write" else "other", {})
    assert state(journal) == before


def test_retained_exact_write_also_verifies_obligation_columns(journal):
    journal.reserve_records("batch", (spec(),))
    journal.put("vote", "one", {})
    corrupt(journal, "record_reservations", "UPDATE record_reservations SET maximum_bytes=1")
    before = state(journal)
    with pytest.raises(ValueError, match="allowance columns changed"):
        journal.put("vote", "one", {})
    assert state(journal) == before


@pytest.mark.parametrize("change", ["extra", "duplicate", "reversed", "invalid_spec", "wrong_type"])
def test_manifest_shape_and_order_are_strict(journal, change):
    journal.reserve_records("batch", (spec(), spec(key="two")))
    with sqlite3.connect(journal.path) as db:
        doc = json.loads(db.execute("SELECT body FROM record_reservation_batches").fetchone()[0])
    if change == "extra":
        doc["generation"] = 2
    elif change == "duplicate":
        doc["records"].append(doc["records"][0])
    elif change == "reversed":
        doc["records"].reverse()
    elif change == "invalid_spec":
        doc["records"][0]["extra"] = True
    else:
        doc["records"] = {}
    corrupt(
        journal,
        "record_reservation_batches",
        "UPDATE record_reservation_batches SET body=?",
        (canonical_json_bytes(doc),),
    )
    before = state(journal)
    with pytest.raises(ValueError, match=r"manifest changed|unique and sorted|reservation fields"):
        journal.reservation("batch")
    assert state(journal) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("batch_id", "replacement"),
        ("generation", 0),
        ("manifest_sha256", "0" * 64),
        ("journal_identity", "x" * 64),
        ("maximum_rounds", True),
    ],
)
def test_identity_cannot_override_receipt_fields(journal, field, value):
    journal.reserve_records("batch", (spec(),))
    with sqlite3.connect(journal.path) as db:
        doc = json.loads(db.execute("SELECT body FROM record_reservation_identity").fetchone()[0])
    doc[field] = value
    corrupt(
        journal,
        "record_reservation_identity",
        "UPDATE record_reservation_identity SET body=?",
        (canonical_json_bytes(doc),),
    )
    before = state(journal)
    with pytest.raises(ValueError, match="binding changed"):
        journal.reservation("batch")
    assert state(journal) == before


@pytest.mark.parametrize(
    "table,column,bound",
    [
        ("record_reservation_identity", "body", 65536),
        ("record_reservation_batches", "body", MAX_BYTES),
        ("record_reservations", "document", 8192),
    ],
)
def test_retained_reservation_blobs_are_size_checked_before_loading(
    journal, table, column, bound, monkeypatch
):
    journal.reserve_records("batch", (spec(),))
    corrupt(journal, table, f"UPDATE {table} SET {column}=zeroblob(?)", (bound + 1,))
    statements = []
    connect = sqlite3.connect

    def traced(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(sqlite3, "connect", traced)
    with pytest.raises(ValueError, match="blob exceeds bound"):
        journal.reservation("batch")
    assert not any(
        statement.startswith(f'SELECT "{column}" FROM "{table}"') for statement in statements
    )


@pytest.mark.parametrize(
    "trigger",
    [
        "round_generation_records_insert",
        "round_generation_binding_update",
        "record_reservations_immutable_delete",
    ],
)
@pytest.mark.parametrize("changed", [False, True])
def test_missing_or_weakened_fence_is_not_silently_repaired(journal, trigger, changed):
    journal.reserve_records("batch", (spec(),))
    with sqlite3.connect(journal.path) as db:
        sql = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (trigger,)).fetchone()[0]
        db.execute(f'DROP TRIGGER "{trigger}"')
        if changed:
            if " IS NOT 2 " in sql:
                sql = sql.replace(" IS NOT 2 ", " != 2 ")
            else:
                sql = sql.replace("append-only", "different-error")
            db.execute(sql)
    before = state(journal)
    with pytest.raises(ValueError, match="fence missing or changed"):
        journal.reserve_records("batch", (spec(),))
    assert state(journal) == before


def test_missing_migrated_table_is_not_recreated(journal):
    journal.reserve_records("batch", (spec(),))
    with sqlite3.connect(journal.path) as db:
        db.execute("DROP TABLE record_reservations")
    before = state(journal)
    with pytest.raises(ValueError, match="capability table missing"):
        RoundJournal(journal.root, {"purpose": "capacity"}, maximum_rounds=4)
    assert state(journal) == before


def test_generation_guard_rejects_null(journal):
    journal.reserve_records("batch", (spec(),))
    before = state(journal)
    with sqlite3.connect(journal.path) as old:
        old.create_function("umi_round_writer_generation", 0, lambda: None)
        with pytest.raises(sqlite3.IntegrityError, match="writer capability required"):
            old.execute("INSERT INTO records VALUES ('vote','old',X'7b7d')")
    assert state(journal) == before


@pytest.mark.parametrize("count", [8, 128])
def test_accounting_streams_obligations_with_constant_query_count(journal, count):
    journal.reserve_records("batch", tuple(spec(key=str(i)) for i in range(count)))
    journal.put_many(("vote", str(i), {}) for i in range(count // 2))
    statements = []
    with journal.transaction() as db:
        expected = journal._capacity(db)
        db.set_trace_callback(statements.append)
        assert journal._capacity(db) == expected
    assert expected[2] == {"vote": count}
    # Accounting still validates every canonical obligation. It must not run
    # additional lookup queries for each row, including consumed obligations.
    assert len(statements) < 64


@pytest.mark.parametrize("operation", ["exact", "scan"])
@pytest.mark.parametrize(
    "column,value,message",
    [
        ("document", b"x" * 8193, "blob exceeds bound"),
        ("document", "x" * 8193, "blob exceeds bound"),
        ("maximum_bytes", "x" * 8193, "allowance columns changed"),
        ("value_sha256", "0" * 64 + "\0" + "x" * 8193, "allowance columns changed"),
        ("value_sha256", "\u00e9" * 64, "allowance columns changed"),
    ],
    ids=("large-blob", "text-body", "text-allowance", "nul-sha", "unicode-sha"),
)
def test_obligation_projection_does_not_load_oversized_columns(
    journal, operation, column, value, message
):
    journal.reserve_records("batch", (spec(),))
    corrupt(journal, "record_reservations", f"UPDATE record_reservations SET {column}=?", (value,))
    returned_sizes = []

    def inspect(_cursor, row):
        returned_sizes.extend(
            len(field.encode() if isinstance(field, str) else field)
            for field in row
            if isinstance(field, (str, bytes))
        )
        return row

    with journal.transaction() as db:
        db.row_factory = inspect
        with pytest.raises(ValueError, match=message):
            if operation == "exact":
                journal._obligation(db, "vote", "one")
            else:
                journal._capacity(db)
    assert max(returned_sizes, default=0) <= 8192
