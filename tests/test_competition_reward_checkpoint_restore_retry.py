"""Bounded retained metadata survives ancestry progress, never changed dependencies."""

import asyncio
import logging
from collections import Counter
from types import SimpleNamespace

import pytest

from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_history_workers import HistoryVerificationProfile
from umi.competition_reward_writer_prefix import restore_completed_prefix
from umi.historical_header_recovery import HistoricalHeaderRecoveryProgress

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


def progress_error(target, completed=1):
    error = HistoricalHeaderRecoveryProgress("bounded ancestry advanced")
    error.ancestry_progress = {
        "anchor_evidence_sha256": "ab" * 32,
        "anchor_block": target + 100,
        "target_block": target,
        "completed_links": completed,
        "state": "running",
        "elapsed_seconds": 10,
        "eta_seconds": 30,
        "eta_basis": "measured_durable_ancestry_links_per_elapsed_second",
        "eta_scope": "current_owned_ancestry_only_excludes_block_proofs_and_rewards",
    }
    return error


async def retained(history_case, monkeypatch):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    h.offline_through = h.end
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    loads, native_load = [], h.reader.checkpoints.load

    def load(height):
        loads.append(height)
        return native_load(height)

    monkeypatch.setattr(h.reader.checkpoints, "load", load)
    return h, expected, loads


@pytest.mark.parametrize("parallel", [False, True])
async def test_progress_reuses_one_batch_but_rechecks_final_dependencies(
    history_case, monkeypatch, parallel, caplog
):
    h, expected, loads = await retained(history_case, monkeypatch)
    if parallel:
        h.reader.verification_profile = HistoryVerificationProfile(
            schema="umi-history-verification-profile/1"
        )
    resolve, attempts = h.item.provider._resolve_control_header, []

    async def progressing(ref, encoded):
        attempts.append(ref.block_number)
        if len(attempts) <= 3:
            raise progress_error(ref.block_number, len(attempts))
        return await resolve(ref, encoded)

    monkeypatch.setattr(h.item.provider, "_resolve_control_header", progressing)
    caplog.set_level(logging.INFO, logger="umi.competition_reward_history_progress")
    for _ in range(3):
        caplog.clear()
        with pytest.raises(HistoricalHeaderRecoveryProgress):
            await h.reader.advance(h.item.provider, through_block=h.end)
        assert loads == list(range(h.old.height, h.end + 1))
        assert h.reader._next == h.old.height
        assert h.reader.progress.latest["stage"] == "owned_historical_ancestry"
        emitted = [
            row.args
            for row in caplog.records
            if row.name == "umi.competition_reward_history_progress"
            and row.msg == "reward_history_progress %s"
        ]
        # A fast bounded continuation must reach the log before the next pass
        # replaces the current stage with history_preparation.
        assert emitted[-1]["stage"] == "owned_historical_ancestry"
        assert emitted[-1]["ancestry_progress"]["completed_links"] == len(attempts)
        assert emitted[-1]["stage_eta_seconds"] == 30
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert Counter(loads) == dict.fromkeys(range(h.old.height, h.end + 1), 2)
    assert h.reader._pending_checkpoint_restore is None
    assert h.reader.progress.latest["stage"] == "checkpoint_restore"
    assert h.reader.progress.latest["ancestry_progress"] is None


@pytest.mark.parametrize("damage", ["source", "result", "owner"])
async def test_changed_retained_dependency_during_ancestry_never_applies_cached_result(
    history_case, monkeypatch, damage
):
    h, _, loads = await retained(history_case, monkeypatch)
    resolve = h.item.provider._resolve_control_header

    async def progressing(ref, _):
        raise progress_error(ref.block_number)

    monkeypatch.setattr(h.item.provider, "_resolve_control_header", progressing)
    with pytest.raises(HistoricalHeaderRecoveryProgress):
        await h.reader.advance(h.item.provider, through_block=h.end)
    with h.reader.journal.transaction() as db:
        if damage == "source":
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(h.old.height),),
            )
        elif damage == "result":
            db.execute(
                "DELETE FROM records WHERE kind='control_history_verified' "
                "AND id=(SELECT key FROM history_checkpoint_index WHERE height=?)",
                (h.old.height,),
            )
        else:
            db.execute("DELETE FROM records WHERE kind='control_history_checkpoint_owner'")
    monkeypatch.setattr(h.item.provider, "_resolve_control_header", resolve)
    with pytest.raises(HistoryCheckpointRepairRequired):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.old.height
    assert h.reader._prefixes == {}
    assert h.reader._pending_checkpoint_restore is None
    assert loads[: h.end - h.old.height + 1] == list(range(h.old.height, h.end + 1))


async def test_changed_bounded_interval_drops_previous_pending_batch(history_case, monkeypatch):
    h, _, loads = await retained(history_case, monkeypatch)
    resolve = h.item.provider._resolve_control_header

    async def progressing(ref, _):
        raise progress_error(ref.block_number)

    monkeypatch.setattr(h.item.provider, "_resolve_control_header", progressing)
    with pytest.raises(HistoricalHeaderRecoveryProgress):
        await h.reader.advance(h.item.provider, through_block=h.end)
    loads.clear()
    monkeypatch.setattr(h.item.provider, "_resolve_control_header", resolve)
    result = await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=2)
    assert result.next_block == h.old.height + 2
    assert loads == [h.old.height, h.old.height + 1] * 2


async def test_cancelled_pending_restore_drops_batch_and_preserves_completed_checkpoints(
    history_case, monkeypatch
):
    h, expected, loads = await retained(history_case, monkeypatch)
    resolve, entered = h.item.provider._resolve_control_header, asyncio.Event()
    attempts = 0

    async def blocked(ref, _):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise progress_error(ref.block_number)
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr(h.item.provider, "_resolve_control_header", blocked)
    with pytest.raises(HistoricalHeaderRecoveryProgress):
        await h.reader.advance(h.item.provider, through_block=h.end)
    task = asyncio.create_task(h.reader.advance(h.item.provider, through_block=h.end))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert h.reader._pending_checkpoint_restore is None
    assert h.reader._next == h.old.height
    assert not h.reader._lock.locked() and not h.item.provider._lock.locked()
    loads.clear()
    monkeypatch.setattr(h.item.provider, "_resolve_control_header", resolve)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert Counter(loads) == dict.fromkeys(range(h.old.height, h.end + 1), 2)


async def test_writer_owner_failure_during_progress_drops_batch_and_drains_monitor(
    history_case, monkeypatch
):
    h, _, _ = await retained(history_case, monkeypatch)
    calls = 0

    async def owner_check():
        nonlocal calls
        calls += 1
        if calls > 1:
            assert h.reader.progress.latest["stage"] == "owned_historical_ancestry"
            assert h.reader.progress.latest["stage_eta_seconds"] == 30
            raise ValueError("stopped owner lost")

    async def progressing(ref, _):
        raise progress_error(ref.block_number)

    monkeypatch.setattr(h.item.provider, "_resolve_control_header", progressing)
    before = asyncio.all_tasks()
    with pytest.raises(ValueError, match="stopped owner lost"):
        await restore_completed_prefix(
            h.reader,
            h.item.provider,
            through_block=h.end,
            maximum_blocks=64,
            owner=SimpleNamespace(recheck=owner_check),
        )
    assert h.reader._pending_checkpoint_restore is None
    assert h.reader._next == h.old.height
    assert not h.reader.progress.active
    assert asyncio.all_tasks() <= before
