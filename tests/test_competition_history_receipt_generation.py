"""Folded native history cannot outlive a changed original transport receipt."""

import hashlib

import pytest

from umi.competition_remote_proof_generation import MARKER, TABLE, triggers
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired

from .test_competition_history_source_externalization import fresh_remote, reopen
from .test_competition_readonly_proof_receipts import consumer
from .test_competition_remote_proof_store import EvidenceServer, store
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def direct_case(h, tmp_path, *, partial=False, independent=False):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    h.reader = fresh_remote(h.reader, producer, tmp_path / "direct")
    target = h.reader.first_block + 1 if partial else h.end
    result = await h.reader.advance(h.item.provider, through_block=target)
    with h.reader.journal.read_transaction() as db:
        reference = h.reader.remote_sources._alias(
            "control_history_block", str(h.reader.first_block), db
        )["remote"]
    remote = consumer(tmp_path / "consumer", producer, server) if independent else producer
    if independent:
        h.reader = reopen(h.reader, remote)
        assert await h.reader.advance(h.item.provider, through_block=target) == result
    return producer, remote, server, reference, result


def mutate(producer, reference, damage):
    key = hashlib.sha256(reference["key"].encode()).hexdigest()
    with producer.journal.transaction() as db:
        if damage == "delete":
            assert (
                db.execute(
                    "DELETE FROM records WHERE kind='remote_proof_object' AND id=?", (key,)
                ).rowcount
                == 1
            )
        elif damage == "update":
            assert (
                db.execute(
                    "UPDATE records SET body=body WHERE kind='remote_proof_object' AND id=?", (key,)
                ).rowcount
                == 1
            )
        else:
            assert (
                db.execute(
                    "UPDATE records SET body=? WHERE kind='remote_proof_object' AND id=?",
                    (b'{"damaged":true}', key),
                ).rowcount
                == 1
            )


@pytest.mark.parametrize("independent", [False, True])
@pytest.mark.parametrize("timing", ["before", "during_finality"])
@pytest.mark.parametrize("damage", ["delete", "update", "malformed"])
async def test_changed_original_receipt_refuses_fold_before_issuing_history(
    history_case, tmp_path, monkeypatch, independent, timing, damage
):
    h = history_case
    producer, remote, _server, reference, _expected = await direct_case(
        h, tmp_path, independent=independent
    )
    h.reader = reopen(h.reader, remote)
    prohibit_proof_replay(monkeypatch, h.reader)
    original = h.reader._validate_checkpoint_tip

    async def changed(*args, **kwargs):
        await original(*args, **kwargs)
        mutate(producer, reference, damage)

    if timing == "before":
        mutate(producer, reference, damage)
    else:
        monkeypatch.setattr(h.reader, "_validate_checkpoint_tip", changed)
    with pytest.raises(HistoryCheckpointRepairRequired, match="remote"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.reader.first_block
    assert h.reader.progress.latest["state"] == "repair_required"


@pytest.mark.parametrize("first_frontier", [False, True])
async def test_remember_never_rebaselines_mutation_during_new_work(
    history_case, tmp_path, monkeypatch, first_frontier
):
    h = history_case
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    h.reader = fresh_remote(h.reader, producer, tmp_path / "direct")
    old_highest = h.reader.first_block - 1
    if not first_frontier:
        await h.reader.advance(h.item.provider, through_block=h.reader.first_block + 1)
        old_highest = h.reader.first_block + 1
    remember = h.reader.folded_frontier.remember
    failures = []

    def changed(reader):
        if not failures:
            with reader.journal.read_transaction() as db:
                ref = reader.remote_sources._alias(
                    "control_history_block", str(reader.first_block), db
                )["remote"]
            mutate(producer, ref, "delete")
            failures.append(1)
        return remember(reader)

    monkeypatch.setattr(h.reader.folded_frontier, "remember", changed)
    with pytest.raises(HistoryCheckpointRepairRequired, match="remote"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    with h.reader.journal.read_transaction() as db:
        assert h.reader.folded_frontier.state(db)[2] == old_highest
    assert failures


async def test_ordinary_receipt_appends_preserve_frontier(history_case, tmp_path, monkeypatch):
    h = history_case
    producer, remote, server, _reference, expected = await direct_case(
        h, tmp_path, independent=True
    )
    producer.put_bytes(b"unrelated newly completed object")
    h.reader = reopen(h.reader, remote)
    prohibit_proof_replay(monkeypatch, h.reader)

    def forbidden(*args, **kwargs):
        pytest.fail("ordinary appends reconstructed the verified native prefix")

    monkeypatch.setattr(h.reader.checkpoints, "load_restore_batch", forbidden)
    server.calls.clear()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert server.calls == []


async def test_original_receipt_repair_then_explicit_frontier_repair_reuses_native_blocks(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    producer, remote, _server, reference, expected = await direct_case(h, tmp_path)
    original = [h.reader.checkpoints.load(n) for n in range(h.reader.first_block, h.end + 1)]
    mutate(producer, reference, "delete")
    h.reader = reopen(h.reader, remote)
    with pytest.raises(HistoryCheckpointRepairRequired):
        await h.reader.advance(h.item.provider, through_block=h.end)
    producer.repair_reference(reference)
    prohibit_proof_replay(monkeypatch, h.reader)
    partial = await h.reader.repair_checkpoints(
        h.item.provider,
        through_block=h.end,
        reason="restore original transport receipt",
        maximum_blocks=1,
    )
    assert partial.history is None and partial.next_block == h.reader.first_block + 1
    assert h.reader.progress.native_completed == 0 and h.reader.progress.restored_completed == 1
    h.reader = reopen(h.reader, remote)
    prohibit_proof_replay(monkeypatch, h.reader)
    result = await h.reader.advance(h.item.provider, through_block=h.end)
    assert result == expected and h.reader.progress.native_completed == 0
    assert [
        h.reader.checkpoints.load(n) for n in range(h.reader.first_block, h.end + 1)
    ] == original
    h.reader = reopen(h.reader, remote)
    prohibit_proof_replay(monkeypatch, h.reader)

    def forbidden(*args, **kwargs):
        pytest.fail("repaired frontier repeated native metadata work")

    monkeypatch.setattr(h.reader.checkpoints, "load_restore_batch", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected


def remove_generation(producer):
    # An isolated legacy /4 fixture, never a production metadata mutation.
    with producer.journal.transaction() as db:
        for name in triggers():
            db.execute("DROP TRIGGER " + name)
        db.execute("DROP TABLE " + TABLE)
        db.execute("DELETE FROM records WHERE kind=?", (MARKER,))


@pytest.mark.parametrize("reenroll", [False, True])
async def test_missing_component_on_guarded_frontier_never_becomes_first_adoption(
    history_case, tmp_path, reenroll
):
    h = history_case
    producer, _remote, server, _reference, _expected = await direct_case(h, tmp_path)
    remove_generation(producer)
    remote = store(tmp_path / "producer", server) if reenroll else producer
    h.reader = reopen(h.reader, remote)
    with pytest.raises(HistoryCheckpointRepairRequired, match="remote"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.reader.first_block


async def test_genuinely_legacy_readonly_producer_has_explicit_compatibility_status(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    producer, _remote, server, _reference, expected = await direct_case(h, tmp_path)
    with h.reader.journal.transaction() as db:
        for name in h.reader.folded_frontier.triggers:
            db.execute("DROP TRIGGER " + name)
        db.execute("DROP TABLE history_folded_state")
        db.execute("DROP TABLE history_folded_anchors")
        db.execute("DELETE FROM records WHERE kind LIKE 'control_history_folded_%'")
    remove_generation(producer)
    before = producer.journal.path.read_bytes()
    observer = consumer(tmp_path / "observer", producer, server)
    h.reader = reopen(h.reader, observer)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.frontier_reuse["state"] == "waiting_for_receipt_owner_upgrade"
    assert h.reader.progress.frontier_reuse["frontier_restart_reuse"] is False
    with h.reader.journal.read_transaction() as db:
        assert h.reader.folded_frontier.state(db)[3] is None
    assert producer.journal.path.read_bytes() == before


@pytest.mark.parametrize("kind", ["damage", "hold"])
async def test_independent_consumer_changes_with_unchanged_counts_invalidate_fold(
    history_case, tmp_path, monkeypatch, kind
):
    h = history_case
    producer, remote, _server, reference, expected = await direct_case(
        h, tmp_path, independent=True
    )
    unrelated = producer.put_bytes(b"unrelated diagnostic source")
    old_key = hashlib.sha256(unrelated["key"].encode()).hexdigest()
    actual_key = hashlib.sha256(reference["key"].encode()).hexdigest()
    if kind == "damage":
        remote._hold(remote.validate_reference(unrelated))
    else:
        with remote.journal.transaction() as db:
            db.execute("INSERT INTO holds VALUES (?)", (old_key,))
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (
        await h.reader.repair_checkpoints(
            h.item.provider, through_block=h.end, reason="accept unrelated diagnostic state"
        )
        == expected
    )
    with remote.journal.transaction() as db:
        if kind == "damage":
            db.execute(
                "UPDATE records SET id=? WHERE kind='remote_proof_damage' AND id=?",
                (actual_key, old_key),
            )
        else:
            db.execute("UPDATE holds SET id=? WHERE id=?", (actual_key, old_key))
    h.reader = reopen(h.reader, remote)
    with pytest.raises(HistoryCheckpointRepairRequired, match="remote"):
        await h.reader.advance(h.item.provider, through_block=h.end)


@pytest.mark.parametrize("damage", ["table", "trigger", "owner"])
async def test_partial_generation_damage_is_explicit_repair(history_case, tmp_path, damage):
    h = history_case
    producer, remote, _server, _reference, _expected = await direct_case(h, tmp_path)
    with producer.journal.transaction() as db:
        if damage == "table":
            db.execute("DROP TABLE " + TABLE)
        elif damage == "trigger":
            db.execute("DROP TRIGGER " + next(iter(triggers())))
        else:
            for name in triggers():
                if "_owner_" in name:
                    db.execute("DROP TRIGGER " + name)
            db.execute("DELETE FROM records WHERE kind=?", (MARKER,))
    h.reader = reopen(h.reader, remote)
    with pytest.raises(HistoryCheckpointRepairRequired, match="folded history"):
        await h.reader.advance(h.item.provider, through_block=h.end)
