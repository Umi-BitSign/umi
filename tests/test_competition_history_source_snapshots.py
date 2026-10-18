"""Batch source reuse cannot outlive the fresh read-only transaction."""

import sqlite3

import pytest

from umi.competition_reward_history_checkpoint import (
    HistoryCheckpointRepairRequired,
    _CheckpointSourceSnapshot,
)

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_batch_resolves_each_shared_source_once_then_rechecks_fresh(
    history_case, monkeypatch
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    checkpoints = h.reader.checkpoints
    expected = [checkpoints.load(n) for n in range(h.old.height, h.end + 1)]
    unique = {(s[0], s[1]) for value in expected for s in value["sources"]}
    calls = []
    resolve = checkpoints.remote_sources.snapshot_token

    def counted(kind, key, db):
        calls.append((kind, key))
        return resolve(kind, key, db)

    monkeypatch.setattr(checkpoints.remote_sources, "snapshot_token", counted)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert checkpoints.load_many(h.old.height, h.end) == expected
    assert len(calls) == len(unique) and set(calls) == unique
    checkpoints.recheck_many(expected)
    assert len(calls) == 2 * len(unique)


async def test_new_hold_after_batch_is_not_hidden_by_reuse(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    checkpoints = h.reader.checkpoints
    values = checkpoints.load_many(h.old.height, h.end)
    key = values[0]["sources"][0][1]
    with h.reader.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (key,))
    with pytest.raises(HistoryCheckpointRepairRequired):
        checkpoints.recheck_many(values)


async def test_source_snapshot_rejects_writable_connection(history_case):
    h = history_case
    with (
        h.reader.journal.transaction() as db,
        pytest.raises(ValueError, match="read-only snapshot"),
    ):
        _CheckpointSourceSnapshot(h.reader.checkpoints, db)


async def test_reuse_is_bound_to_reader_and_connection(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    with h.reader.journal.read_transaction() as original:
        source = _CheckpointSourceSnapshot(h.reader.checkpoints, original)
        with (
            h.reader.journal.read_transaction() as other,
            pytest.raises(ValueError, match="another reader"),
        ):
            h.reader.checkpoints._load_snapshot(h.old.height, other, source)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            original.execute("INSERT INTO holds VALUES ('uncommitted')")


async def test_snapshot_cache_limit_keeps_uncached_sources_supported(history_case):
    checkpoints = history_case.reader.checkpoints
    with sqlite3.connect(":memory:") as db:
        db.executescript(
            "CREATE TABLE history_source_identity(kind,id,revision,present,PRIMARY KEY(kind,id));"
            "CREATE TABLE holds(id TEXT PRIMARY KEY);"
        )
        keys = [("control_history_object", f"{n:064x}") for n in range(8200)]
        db.executemany("INSERT INTO history_source_identity VALUES (?,?,0,1)", keys)
        # The local-source implementation has the same token shape; no remote
        # store or native proof is needed to exercise working-set saturation.
        remote = checkpoints.remote_sources
        checkpoints.remote_sources = None
        try:
            cache = {}
            assert checkpoints._sources(keys, db, cache) == [[*key, 0] for key in keys]
            assert len(cache) == 8192
            db.execute("INSERT INTO holds VALUES (?)", (keys[-1][1],))
            with pytest.raises(HistoryCheckpointRepairRequired):
                checkpoints._sources(keys, db, cache)
        finally:
            checkpoints.remote_sources = remote


async def test_storage_replacement_inside_read_snapshot_still_refuses(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    checkpoints = h.reader.checkpoints
    with h.reader.journal.read_transaction() as db:
        source = _CheckpointSourceSnapshot(checkpoints, db)
        assert checkpoints._load_snapshot(h.old.height, db, source)
        path = h.reader.journal.path
        path.rename(path.with_name("retained-original.sqlite3"))
        path.touch(mode=0o600)
        with pytest.raises(HistoryCheckpointRepairRequired, match="original directory or database"):
            checkpoints._load_snapshot(h.old.height, db, source)


async def test_cached_remote_token_rechecks_damage_outside_sql_snapshot(
    history_case, tmp_path, monkeypatch
):
    from .test_competition_history_source_externalization import reopen
    from .test_competition_remote_proof_store import EvidenceServer, store

    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    await h.reader.externalize_history_sources(maximum_records=4096)
    checkpoints = h.reader.checkpoints
    with h.reader.journal.read_transaction() as db:
        source = _CheckpointSourceSnapshot(checkpoints, db)
        assert checkpoints._load_snapshot(h.old.height, db, source)

        def damaged(_reference):
            raise ValueError("remote proof requires explicit original-generation repair")

        monkeypatch.setattr(h.reader.remote_store, "validate_reference", damaged)
        with pytest.raises(HistoryCheckpointRepairRequired, match="receipt damaged"):
            checkpoints._load_snapshot(h.old.height, db, source)
