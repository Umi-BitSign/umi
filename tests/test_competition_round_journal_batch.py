from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import pytest

import umi.competition_round_journal as rounds
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_round_preparation import setup as preparation_fixture
from .test_open_competition import policy as policy

preparation = preparation_fixture


@pytest.fixture
def journal(tmp_path):
    result = rounds.RoundJournal(tmp_path / "journal", {"policy": "batch-test"}, maximum_rounds=2)
    with result.transaction() as db:
        db.execute("CREATE TABLE caller_index (id TEXT PRIMARY KEY, value INTEGER)")
    return result


def retained(journal):
    with sqlite3.connect(journal.path) as db:
        return {
            table: db.execute(f"SELECT * FROM {table} ORDER BY 1,2").fetchall()
            for table in (
                "records",
                "round_index",
                "round_settlement_index",
                "plan_index",
                "caller_index",
            )
        }


def holds(journal):
    with sqlite3.connect(journal.path) as db:
        return db.execute("SELECT id FROM holds ORDER BY id").fetchall()


def valid_records(preparation):
    options = preparation.options
    result = preparation.store.prepare_round(**options)
    proposal = rounds.RoundProposal.model_validate_json(
        canonical_json_bytes(
            {
                "schema": "umi-round-proposal/1",
                "cutoff": result["cutoff_publication"],
                "submissions": result["submissions"],
                "signing_close_block": 130,
            }
        )
    )
    plan = rounds.RoundPlan(
        schema="umi-round-plan/2",
        suite=options["suite"],
        public_schedule=options["public_schedule"],
        eligible_tracks=options["eligible_tracks"],
        intake_opened_block=100,
        not_before_block=120,
        admission_close_by_block=125,
        signing_close_block=130,
        evaluation_close_block=140,
        reveal_block=150,
        evidence_cutoff_block=160,
        valid_through_block=190,
    )
    key = digest(plan.suite)
    return (("plan", key, plan), ("prepared", key, proposal))


def test_batch_commits_canonical_records_and_caller_index_together(journal):
    records = (("intent", "a", {"z": 1, "a": 2}), ("intent", "b", {"b": 3}))

    def index(db):
        assert db.in_transaction
        assert db.execute("SELECT COUNT(*) FROM records").fetchone() == (2,)
        db.execute("INSERT INTO caller_index VALUES ('batch',2)")

    assert journal.put_many(iter(records), index=index) is None
    state = retained(journal)
    assert state["records"] == [
        (kind, key, canonical_json_bytes(value)) for kind, key, value in records
    ]
    assert state["caller_index"] == [("batch", 2)]
    assert journal.get("intent", "a") == {"a": 2, "z": 1}


def test_batch_repeated_same_payload_is_idempotent_and_repairs_index(journal):
    calls = []

    def index(db):
        calls.append(True)
        db.execute("INSERT OR IGNORE INTO caller_index VALUES ('a',1)")

    records = (("intent", "a", {"b": 2, "a": 1}), ("intent", "a", {"a": 1, "b": 2}))
    journal.put_many(records, index=index)
    before = retained(journal)
    journal.put_many(records, index=index)
    assert retained(journal) == before
    assert calls == [True, True]
    assert len(before["records"]) == 1


def test_exact_batch_retry_repairs_index_without_ledger_accounting_scan(journal, monkeypatch):
    records = (("intent", "a", {"v": 1}),)
    journal.put_many(records)
    statements = []
    transaction = journal.transaction

    @contextmanager
    def traced_transaction():
        with transaction() as db:
            db.set_trace_callback(statements.append)
            yield db

    with monkeypatch.context() as patch:
        patch.setattr(journal, "transaction", traced_transaction)
        journal.put_many(
            records,
            index=lambda db: db.execute("INSERT OR IGNORE INTO caller_index VALUES ('a',1)"),
        )
    assert not any("COUNT(*)" in statement or "SUM(" in statement for statement in statements)
    assert any("SELECT length(body) FROM records" in statement for statement in statements)
    assert any("SELECT body FROM records" in statement for statement in statements)
    assert retained(journal)["caller_index"] == [("a", 1)]


def test_single_put_delegates_without_a_second_transaction(journal, monkeypatch):
    calls = []
    original = journal.put_many

    def put_many(records, *, index=None):
        calls.append(tuple(records))
        return original(calls[-1], index=index)

    monkeypatch.setattr(journal, "put_many", put_many)
    assert journal.put("intent", "a", {"a": 1}) is None
    assert calls == [(("intent", "a", {"a": 1}),)]


def test_batch_retains_all_existing_conflicts_without_new_records_or_index(journal):
    journal.put_many((("intent", "a", {"v": 1}), ("intent", "b", {"v": 2})))
    before = retained(journal)
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put_many(
            (("work", "new", {}), ("intent", "a", {"v": 3}), ("intent", "b", {"v": 4})),
            index=lambda _db: pytest.fail("conflicting batch must not index"),
        )
    assert retained(journal) == before
    assert holds(journal) == [("a",), ("b",)]
    recovered = rounds.RoundJournal(journal.root, {"policy": "batch-test"}, maximum_rounds=2)
    with pytest.raises(ValueError, match="conflict held"):
        recovered.get("intent", "a")


def test_batch_conflicting_duplicate_retains_hold_without_first_payload(journal):
    before = retained(journal)
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put_many(
            (("work", "new", {}), ("intent", "a", {"v": 1}), ("intent", "a", {"v": 2})),
            index=lambda _db: pytest.fail("conflicting duplicate must not index"),
        )
    assert retained(journal) == before
    assert holds(journal) == [("a",)]
    with pytest.raises(ValueError, match="conflict held"):
        journal.put("intent", "a", {"v": 1})


def test_batch_existing_hold_blocks_all_new_records(journal):
    journal.put("intent", "a", {"v": 1})
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put("intent", "a", {"v": 2})
    before = retained(journal)
    with pytest.raises(ValueError, match="conflict held"):
        journal.put_many(
            (("work", "new", {}), ("other-kind", "a", {"v": 1})),
            index=lambda _db: pytest.fail("held batch must not index"),
        )
    assert retained(journal) == before


def test_batch_kind_capacity_rolls_back_earlier_records(journal):
    journal.put("work", "retained", {"keep": True})
    before = retained(journal)
    with pytest.raises(ValueError, match="record capacity exhausted"):
        journal.put_many(
            (("intent", str(i), {"v": i}) for i in range(3)),
            index=lambda _db: pytest.fail("over-capacity batch must not index"),
        )
    assert retained(journal) == before
    assert holds(journal) == []


@pytest.mark.parametrize("capacity", ["records", "bytes"])
def test_batch_total_capacity_rolls_back_earlier_records(tmp_path, capacity):
    journal = rounds.RoundJournal(
        tmp_path / "journal",
        {},
        maximum_rounds=1,
        maximum_bytes=1024 if capacity == "bytes" else 4096,
    )
    with journal.transaction() as db:
        db.execute("CREATE TABLE caller_index (id TEXT PRIMARY KEY, value INTEGER)")
    if capacity == "records":
        journal.put_many(("work", str(i), {}) for i in range(79))
        records = (("work", "new-a", {}), ("work", "new-b", {}))
    else:
        journal.put("work", "retained", {})
        records = (("work", "new-a", "x" * 600), ("work", "new-b", "y" * 600))
    before = retained(journal)
    with pytest.raises(ValueError, match="round journal capacity exhausted"):
        journal.put_many(records)
    assert retained(journal) == before
    assert holds(journal) == []


@pytest.mark.parametrize("conflict", ["retained", "duplicate"])
def test_capacity_exhaustion_does_not_hide_later_conflicts(tmp_path, conflict):
    journal = rounds.RoundJournal(tmp_path / "journal", {}, maximum_rounds=1, maximum_bytes=1024)
    journal.put("work", "retained", {"v": 1})
    records = [("work", "new-a", "x" * 600), ("work", "new-b", "y" * 600)]
    if conflict == "retained":
        records.append(("work", "retained", {"v": 2}))
        conflicted = "retained"
    else:
        records.append(("work", "new-b", "changed"))
        conflicted = "new-b"
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put_many(records)
    assert holds(journal) == [(conflicted,)]
    with journal.transaction() as db:
        assert db.execute("SELECT kind,id,body FROM records").fetchall() == [
            ("work", "retained", canonical_json_bytes({"v": 1}))
        ]


@pytest.mark.parametrize("retry", [False, True])
def test_batch_does_not_retain_raw_retries_or_over_capacity_bodies(tmp_path, monkeypatch, retry):
    journal = rounds.RoundJournal(tmp_path / "journal", {}, maximum_rounds=1, maximum_bytes=32768)

    def records():
        for i in range(32):
            yield "work", str(i), {"v": "x" * 600}

    if retry:
        journal.put_many(records())
    journal.maximum_bytes = 1024
    live = set()
    peak = 0
    canonical = rounds.canonical_json_bytes

    class TrackedBytes(bytes):
        def __new__(cls, raw):
            nonlocal peak
            result = super().__new__(cls, raw)
            live.add(id(result))
            peak = max(peak, len(live))
            return result

        def __del__(self):
            live.discard(id(self))

    monkeypatch.setattr(
        rounds, "canonical_json_bytes", lambda value: TrackedBytes(canonical(value))
    )
    if retry:
        journal.put_many(records())
    else:
        with pytest.raises(ValueError, match="round journal capacity exhausted"):
            journal.put_many(records())
    # One staged new body at most, plus the current encode and its replacement;
    # exact retries also create a transient canonical copy for retained validation.
    assert peak <= 3


def test_batch_iterable_bound_precedes_all_mutation(tmp_path):
    journal = rounds.RoundJournal(tmp_path / "journal", {}, maximum_rounds=1)
    generated = []

    def records():
        for i in range(100):
            generated.append(i)
            yield "work", "same", {}

    with pytest.raises(ValueError, match="batch capacity exhausted"):
        journal.put_many(records())
    assert len(generated) == 81
    assert journal.get("work", "same") is None
    assert holds(journal) == []


def test_batch_object_bound_precedes_all_mutation(journal, monkeypatch):
    before = retained(journal)
    monkeypatch.setattr(rounds, "MAX_BYTES", 64)
    with pytest.raises(ValueError, match="object exceeds its byte bound"):
        journal.put_many((("work", "a", {}), ("work", "b", "x" * 64)))
    assert retained(journal) == before


def test_batch_generator_failure_does_not_insert_earlier_records(journal):
    before = retained(journal)
    failure = RuntimeError("injected input failure")

    def records():
        yield "work", "a", {}
        raise failure

    with pytest.raises(RuntimeError) as caught:
        journal.put_many(records())
    assert caught.value is failure
    assert retained(journal) == before


def test_batch_preserves_built_in_index_bytes_and_rows(journal, preparation):
    records = valid_records(preparation)
    journal.put_many(records)
    key = records[0][1]
    proposal = records[1][2]
    state = retained(journal)
    assert state["records"] == [
        (kind, key, canonical_json_bytes(value)) for kind, key, value in records
    ]
    assert state["plan_index"] == [(key, 120, 125)]
    assert state["round_index"] == [(1, key, digest(proposal), 120, 130, 140)]
    assert state["round_settlement_index"] == [(1, 160, 190)]
    journal.put_many(records)
    assert retained(journal) == state


@pytest.mark.parametrize("failure", ["validation", "callback"])
def test_batch_rolls_back_built_in_and_caller_indexes(journal, preparation, failure):
    records = valid_records(preparation)
    before = retained(journal)
    callback_failure = RuntimeError("injected index failure")

    def index(db):
        db.execute("INSERT INTO caller_index VALUES ('partial',1)")
        raise callback_failure

    if failure == "validation":
        records += (("plan", "invalid-plan", {}),)
    with pytest.raises(ValueError if failure == "validation" else RuntimeError) as caught:
        journal.put_many(records, index=index)
    if failure == "callback":
        assert caught.value is callback_failure
    assert retained(journal) == before
    assert holds(journal) == []


def test_empty_batch_may_repair_caller_index(journal):
    journal.put_many((), index=lambda db: db.execute("INSERT INTO caller_index VALUES ('a',1)"))
    assert retained(journal)["caller_index"] == [("a", 1)]
    assert retained(journal)["records"] == []


def test_get_uses_supplied_transaction_without_nested_open(journal, monkeypatch):
    journal.put("work", "a", {"v": 1})
    with journal.transaction() as db:
        monkeypatch.setattr(journal, "transaction", lambda: pytest.fail("nested transaction"))
        assert journal.get("work", "a", db=db) == {"v": 1}
        assert journal.get("work", "missing", db=db) is None
        db.execute("INSERT INTO holds VALUES ('a')")
        with pytest.raises(ValueError, match="conflict held"):
            journal.get("work", "a", db=db)


def test_get_with_supplied_transaction_preserves_canonical_validation(journal):
    journal.put("work", "a", {"v": 1})
    with journal.transaction() as db:
        db.execute("UPDATE records SET body=? WHERE id='a'", (b'{ "v": 1 }',))
        with pytest.raises(ValueError, match="not canonical"):
            journal.get("work", "a", db=db)
