"""Restore the owner's completed ordered fold without replaying block metadata."""

import pytest

from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_terminal_frontier_restart_has_no_per_block_restore(history_case, monkeypatch):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)

    def forbidden(*args, **kwargs):
        pytest.fail("unchanged folded history repeated per-block checkpoint restoration")

    monkeypatch.setattr(h.reader.checkpoints, "load_restore_batch", forbidden)
    monkeypatch.setattr(h.reader.checkpoints, "recheck_many", forbidden)
    monkeypatch.setattr(h.reader.checkpoints, "progress_rows", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.native_completed == 0
    assert h.reader.progress.restored_completed == h.end - h.old.height + 1
    assert h.reader.progress.completed_tip_refreshes == 1
    with h.reader.journal.read_transaction() as db:
        before = db.execute("SELECT kind,id,body FROM records ORDER BY kind,id").fetchall()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    with h.reader.journal.read_transaction() as db:
        assert db.execute("SELECT kind,id,body FROM records ORDER BY kind,id").fetchall() == before
        assert db.execute(
            "SELECT COUNT(*) FROM records WHERE kind='control_history_folded_frontier'"
        ).fetchone() == (1,)


async def test_sparse_historical_prefix_preserves_original_fold(history_case, monkeypatch):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    original = {
        height: await h.reader.verified_prefix(height) for height in range(h.old.height, h.end + 1)
    }
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    await h.reader.advance(h.item.provider, through_block=h.end)
    load, calls = h.reader.checkpoints.load_many, []

    def bounded(first, last):
        calls.append((first, last))
        assert last - first < 64
        return load(first, last)

    monkeypatch.setattr(h.reader.checkpoints, "load_many", bounded)
    for height, expected in original.items():
        assert await h.reader.verified_prefix(height) == expected
    assert calls


@pytest.mark.parametrize("timing", ["before", "during_finality"])
async def test_frontier_source_mutation_refuses_before_effects(history_case, monkeypatch, timing):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    original = h.reader._validate_checkpoint_tip

    def mutate():
        with h.reader.journal.transaction() as db:
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(h.old.height),),
            )

    async def during(*args, **kwargs):
        await original(*args, **kwargs)
        mutate()

    if timing == "before":
        mutate()
    else:
        monkeypatch.setattr(h.reader, "_validate_checkpoint_tip", during)
    with pytest.raises(HistoryCheckpointRepairRequired, match="folded history"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.old.height
    assert not h.reader._writes


@pytest.mark.parametrize("damage", ["marker", "trigger", "anchor"])
async def test_damaged_frontier_requires_repair(history_case, damage):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    with h.reader.journal.transaction() as db:
        if damage == "marker":
            db.execute("DELETE FROM records WHERE kind='control_history_folded_owner'")
        elif damage == "trigger":
            db.execute("DROP TRIGGER history_folded_source")
        else:
            db.execute("DELETE FROM records WHERE kind='control_history_folded_anchor'")
    with pytest.raises(HistoryCheckpointRepairRequired, match="folded history"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.old.height


async def test_explicit_repair_rebuilds_fold_and_next_restart_reuses_it(history_case, monkeypatch):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    with h.reader.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
            (str(h.old.height),),
        )
    with pytest.raises(HistoryCheckpointRepairRequired):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert (
        await h.reader.repair_checkpoints(
            h.item.provider, through_block=h.end, reason="repair observed source generation"
        )
        == expected
    )
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected


async def test_completed_selection_null_is_damage_not_first_run(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    with h.reader.journal.transaction() as db:
        db.execute("UPDATE history_folded_state SET key=NULL")
    with pytest.raises(HistoryCheckpointRepairRequired, match="lost its selection"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.old.height


async def test_new_export_destination_keeps_native_fold_and_exposes_delivery(
    history_case, tmp_path, monkeypatch
):
    from umi.competition_reward_proof_archive import RewardProofArchive

    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    h.reader.export_archive = RewardProofArchive(tmp_path / "new-exports")
    prohibit_proof_replay(monkeypatch, h.reader)

    def forbidden(*args, **kwargs):
        pytest.fail("a new export destination reconstructed the native history fold")

    monkeypatch.setattr(h.reader.checkpoints, "load_restore_batch", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.archive_delivery["state"] == "pending"
    assert h.reader.progress.archive_delivery["native_fold_reused"]


async def test_older_then_newer_scope_reuses_the_same_durable_terminal_fold(
    historical, monkeypatch, tmp_path
):
    from umi.open_competition import digest

    from .test_competition_reward_history import make_history_case

    first = historical.old.height
    historical.c.control_writes = {height: () for height in range(first, first + 130)}
    historical.c.control_writes[first] = (digest(historical.c.genesis.decision),)
    h = await make_history_case(historical, monkeypatch, tmp_path, distance=130)
    result = await h.reader.advance(h.item.provider, through_block=h.end)
    while result.history is None:
        result = await h.reader.advance(h.item.provider, through_block=h.end)
    expected = result.history
    older = await h.reader.verified_prefix(first + 65)
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    load = h.reader.checkpoints.load_restore_batch
    checks = []

    def bounded(low, high):
        values, tip = load(low, high)
        checks.extend(value["snapshot"]["block_number"] for value in values)
        return values, tip

    monkeypatch.setattr(h.reader.checkpoints, "load_restore_batch", bounded)
    assert (await h.reader.advance(h.item.provider, through_block=first + 65)).history == older
    before = len(checks)
    assert before <= 63
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history == expected
    assert len(checks) == before
