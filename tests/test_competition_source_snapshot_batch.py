"""Bulk identity reads preserve scalar conflict and source-generation predicates."""

import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_history_source_externalization import ALIAS_KIND, JournalSourceExternalizer
from umi.competition_reward_history_checkpoint import SOURCE_KINDS, HistoryCheckpointRepairRequired
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest


@pytest.fixture
def sources(tmp_path):
    journal = RoundJournal(tmp_path / "journal", {"fixture": "source-identity-batch"})
    keys = [(SOURCE_KINDS[2], f"{number:064x}") for number in range(256)]
    journal.put_many((kind, key, {"opaque": key}) for kind, key in keys)
    with journal.transaction() as db:
        db.execute(
            "CREATE TABLE history_source_identity(kind TEXT,id TEXT,revision INTEGER,"
            "present INTEGER,PRIMARY KEY(kind,id))"
        )
        db.executemany("INSERT INTO history_source_identity VALUES (?,?,0,1)", keys)
    externalizer = JournalSourceExternalizer(
        journal,
        SimpleNamespace(owner="a" * 64),
        None,
        source_kinds=SOURCE_KINDS,
        repair_error=HistoryCheckpointRepairRequired,
    )
    return journal, externalizer, keys


@pytest.mark.parametrize("unrelated_hold", [False, True])
def test_local_batch_matches_scalar_with_fewer_queries_and_no_payload_reads(
    sources, unrelated_hold
):
    journal, source, keys = sources
    if unrelated_hold:
        with journal.transaction() as db:
            db.execute("INSERT INTO holds VALUES ('unrelated')")
    with journal.read_transaction() as db:
        statements = []
        db.set_trace_callback(statements.append)
        expected = [source.snapshot_token(*key, db) for key in keys]
        scalar_count = len(statements)
        statements.clear()
        # Supported older SQLite builds may permit only 999 parameters.
        old_limit = (
            db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
            if hasattr(db, "setlimit")
            else None  # Python3.10 uses its installed SQLite parameter bound.
        )
        try:
            assert source.snapshot_tokens(keys, db) == expected
        finally:
            if old_limit is not None:
                db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, old_limit)
        assert len(statements) < scalar_count / 8
        assert all("body" not in query.lower() for query in statements)
        assert db.execute("PRAGMA query_only").fetchone() == (1,)


@pytest.mark.parametrize("mutation", ["missing", "revision", "presence", "absent", "hold"])
def test_same_invalid_local_identity_refuses_in_scalar_and_bulk_paths(sources, mutation):
    journal, source, keys = sources
    kind, key = keys[0]
    with journal.transaction() as db:
        if mutation == "missing":
            db.execute("DELETE FROM history_source_identity WHERE kind=? AND id=?", (kind, key))
        elif mutation == "revision":
            db.execute("UPDATE history_source_identity SET revision=-1 WHERE id=?", (key,))
        elif mutation == "presence":
            db.execute("UPDATE history_source_identity SET present=2 WHERE id=?", (key,))
        elif mutation == "absent":
            db.execute("UPDATE history_source_identity SET present=0 WHERE id=?", (key,))
        else:
            db.execute("INSERT INTO holds VALUES (?)", (key,))
    with journal.read_transaction() as db:
        with pytest.raises(HistoryCheckpointRepairRequired):
            source.snapshot_token(kind, key, db)
        with pytest.raises(HistoryCheckpointRepairRequired):
            source.snapshot_tokens([(kind, key)], db)


def test_conflict_on_absent_alias_is_not_lost_by_the_join(sources):
    journal, source, keys = sources
    kind, key = keys[0]
    with journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (digest([kind, key]),))
    with journal.read_transaction() as db:
        with pytest.raises(HistoryCheckpointRepairRequired, match="alias or receipt damaged"):
            source.snapshot_token(kind, key, db)
        with pytest.raises(HistoryCheckpointRepairRequired, match="alias or receipt damaged"):
            source.snapshot_tokens([(kind, key)], db)


def test_null_alias_keeps_the_existing_scalar_absence_semantics(sources):
    journal, source, keys = sources
    kind, key = keys[0]
    journal.put_many(((ALIAS_KIND, digest([kind, key]), None),))
    with journal.read_transaction() as db:
        assert source.snapshot_tokens([(kind, key)], db) == [source.snapshot_token(kind, key, db)]


def test_malformed_alias_keeps_the_canonical_reader_and_repair_refusal(sources):
    journal, source, keys = sources
    kind, key = keys[0]
    alias = digest([kind, key])
    journal.put_many(((ALIAS_KIND, alias, {"malformed": True}),))
    with (
        journal.read_transaction() as db,
        pytest.raises(HistoryCheckpointRepairRequired, match="alias or receipt damaged"),
    ):
        source.snapshot_tokens([(kind, key)], db)
    with journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind=? AND id=?", (b' {"bad":1}', ALIAS_KIND, alias)
        )
    with (
        journal.read_transaction() as db,
        pytest.raises(HistoryCheckpointRepairRequired, match="alias or receipt damaged"),
    ):
        source.snapshot_tokens([(kind, key)], db)


def test_empty_string_conflict_is_present_even_though_its_key_is_falsey(sources):
    journal, source, _ = sources
    kind, key = SOURCE_KINDS[2], ""
    journal.put_many(((kind, key, {"opaque": True}),))
    with journal.transaction() as db:
        db.execute("INSERT INTO history_source_identity VALUES (?,?,0,1)", (kind, key))
        db.execute("INSERT INTO holds VALUES (?)", (key,))
    with journal.read_transaction() as db, pytest.raises(HistoryCheckpointRepairRequired):
        source.snapshot_tokens([(kind, key)], db)


def test_duplicates_keep_input_order_and_later_snapshots_see_new_revisions(sources):
    journal, source, keys = sources
    selected = [keys[2], keys[0], keys[2]]
    with journal.read_transaction() as db:
        assert source.snapshot_tokens(selected, db) == [
            source.snapshot_token(*key, db) for key in selected
        ]
    with journal.transaction() as db:
        db.execute(
            "UPDATE history_source_identity SET revision=revision+1 WHERE id=?", (keys[2][1],)
        )
    with journal.read_transaction() as db:
        values = source.snapshot_tokens(selected, db)
        assert [value.token[2] for value in values] == [1, 0, 1]


def test_internal_chunk_bound_and_invalid_source_kind_do_not_issue_queries(sources):
    journal, source, keys = sources
    with journal.read_transaction() as db:
        statements = []
        db.set_trace_callback(statements.append)
        for selected in ([], [*keys, keys[0]], [("unrelated_kind", "id")], [(keys[0][0], 1)]):
            with pytest.raises(ValueError):
                source.snapshot_tokens(selected, db)
        assert statements == []


def test_absence_facts_are_not_reused_when_the_same_transaction_adds_a_hold(sources):
    journal, source, keys = sources
    kind, key = keys[0]
    with journal.transaction() as db:
        assert source.snapshot_tokens([(kind, key)], db) == [source.snapshot_token(kind, key, db)]
        db.execute("INSERT INTO holds VALUES (?)", (digest([kind, key]),))
        with pytest.raises(HistoryCheckpointRepairRequired, match="alias or receipt damaged"):
            source.snapshot_tokens([(kind, key)], db)


def test_bulk_absence_checks_require_an_actual_transaction(sources):
    _, source, keys = sources
    with sqlite3.connect(":memory:") as db:
        assert not db.in_transaction
        with pytest.raises(ValueError, match="one SQL snapshot"):
            source.snapshot_tokens(keys[:1], db)


def test_bounded_lru_keeps_hot_sources_and_survives_eviction_inside_one_group(sources, monkeypatch):
    from collections import OrderedDict

    from umi import competition_reward_history_checkpoint as module

    journal, source, keys = sources
    monkeypatch.setattr(module, "_MAX_SNAPSHOT_TOKENS", 3)
    holder = SimpleNamespace(remote_sources=source)
    with journal.read_transaction() as db:
        initial = [keys[2], keys[0], keys[-1]]
        cache = OrderedDict(zip(initial, source.snapshot_tokens(initial, db), strict=True))
        result = module.HistoryCheckpoints._remote_snapshot_sources(holder, keys[:3], db, cache)
        assert result == [list(source.snapshot_token(*key, db).token) for key in keys[:3]]
        assert list(cache) == keys[:3]
        result = module.HistoryCheckpoints._remote_snapshot_sources(holder, keys[2:4], db, cache)
        assert result == [list(source.snapshot_token(*key, db).token) for key in keys[2:4]]
        assert list(cache) == keys[1:4]
        assert len(cache) == 3
