"""Measured owned ancestry telemetry preserves the native replay outcomes."""

import asyncio
from types import SimpleNamespace

import pytest

from umi import historical_header_progress as telemetry
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_progress import HistoryProgress
from umi.historical_header_recovery import (
    HistoricalHeaderRecovery,
    HistoricalHeaderRecoveryPending,
    HistoricalHeaderRecoveryProgress,
)

from .test_historical_header_recovery import (  # noqa: F401
    chain_config,
    finish,
    policy,
)
from .test_historical_header_recovery import walk as walk


@pytest.fixture
def measured_clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(telemetry, "time", SimpleNamespace(monotonic=lambda: now[0]))
    return now


async def test_bounded_native_pass_reports_measured_link_counts_and_unchanged_progress_error(
    walk, measured_clock
):
    w = walk
    service = HistoricalHeaderRecovery(w.connect, batch_size=8)

    async def request(method, params):
        measured_clock[0] += 1
        return await w.request(method, params)

    with pytest.raises(HistoricalHeaderRecoveryProgress) as raised:
        await service.recover(w.anchor, w.target, request)
    progress = raised.value.ancestry_progress
    assert str(raised.value) == "historical header recovery in progress"
    assert progress["state"] == "running"
    assert progress["completed_links"] == progress["newly_verified_links"] == 8
    assert progress["rpc_fetched_links"] == 8
    assert progress["total_links"] == 40
    assert progress["percent"] == 20
    assert progress["eta_seconds"] == 32
    assert progress["links_per_second"] == 1
    assert progress["retrying"] is False
    assert progress["finality_authority"] is False
    assert progress["eta_scope"] == "current_owned_ancestry_only_excludes_block_proofs_and_rewards"
    assert (await finish(service, w)).snapshot == w.target
    assert service.telemetry.latest["state"] == "completed"
    assert service.telemetry.latest["percent"] == 100
    assert service.telemetry.latest["eta_seconds"] == 0


async def test_restart_measures_retained_hint_checks_and_reuses_no_process_verification(walk):
    w = walk
    first = HistoricalHeaderRecovery(w.connect, batch_size=8)
    with pytest.raises(HistoricalHeaderRecoveryProgress):
        await first.recover(w.anchor, w.target, w.request)
    restarted = HistoricalHeaderRecovery(w.connect, batch_size=8)
    with pytest.raises(HistoricalHeaderRecoveryProgress) as raised:
        await restarted.recover(w.anchor, w.target, w.request)
    progress = raised.value.ancestry_progress
    assert progress["completed_links"] == progress["retained_hint_links"] == 8
    assert progress["rpc_fetched_links"] == progress["reused_process_ancestry_links"] == 0
    assert len(w.calls) == 8
    assert (await finish(restarted, w)).snapshot == w.target


async def test_completed_process_ancestry_reuse_does_not_inflate_rate(walk):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    assert (await finish(service, w)).snapshot == w.target
    count = len(w.calls)
    assert (await finish(service, w)).snapshot == w.target
    progress = service.telemetry.latest
    assert progress["completed_links"] == progress["reused_process_ancestry_links"] == 40
    assert progress["newly_verified_links"] == 0
    assert progress["links_per_second"] is None
    assert len(w.calls) == count


async def test_capacity_retry_counts_only_durable_native_links_and_withdraws_eta(walk):
    w = walk
    service = HistoricalHeaderRecovery(w.connect, maximum_bytes=600)
    with pytest.raises(HistoricalHeaderRecoveryPending) as raised:
        await service.recover(w.anchor, w.target, w.request)
    assert type(raised.value) is HistoricalHeaderRecoveryPending
    with w.connect() as database:
        retained = database.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone()[0]
    progress = raised.value.ancestry_progress
    assert progress["completed_links"] == retained
    assert progress["state"] == "retrying"
    assert progress["eta_seconds"] is None
    assert progress["planning_eta_seconds"] is None


async def test_stalled_rpc_heartbeat_cancels_cleanly_without_changing_native_cursor(
    walk, measured_clock, caplog
):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    service.telemetry.heartbeat_seconds = 0.001
    entered = asyncio.Event()
    caplog.set_level("INFO", logger=telemetry.__name__)

    async def blocked(*_):
        entered.set()
        await asyncio.Future()

    task = asyncio.create_task(service.recover(w.anchor, w.target, blocked))
    await asyncio.wait_for(entered.wait(), 5)
    measured_clock[0] += 61
    for _ in range(30):
        if service.telemetry.latest.get("state") == "stalled":
            break
        await asyncio.sleep(0.002)
    assert service.telemetry.latest["state"] == "stalled"
    assert service.telemetry.latest["completed_links"] == 0
    assert service.telemetry.latest["eta_seconds"] is None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert service.telemetry.latest["state"] == "stopped"
    assert service.progress == {}
    count = len(caplog.records)
    await asyncio.sleep(0.01)
    assert len(caplog.records) == count


async def test_broken_progress_sink_never_masks_native_result_or_rejection(walk, monkeypatch):
    w = walk

    def broken(*_):
        raise OSError("diagnostic sink unavailable")

    monkeypatch.setattr(telemetry._LOG, "info", broken)
    service = HistoricalHeaderRecovery(w.connect)
    assert (await finish(service, w)).snapshot == w.target
    # Keep the native bad-parent rejection when diagnostics cannot be delivered.
    fresh = HistoricalHeaderRecovery(w.connect)
    with w.connect() as database:
        database.execute("DELETE FROM historical_header_hints")
    w.headers[w.by_height[w.anchor.height - 1]]["stateRoot"] = "0x" + "ff" * 32
    with pytest.raises(ValueError, match="committed parent"):
        await fresh.recover(w.anchor, w.target, w.request)
    assert fresh.progress == {}
    assert fresh.telemetry.latest["state"] == "repair_required"


async def test_history_stage_exposes_ancestry_eta_without_claiming_block_proof_completion():
    reader = object.__new__(RewardControlHistoryReader)
    reader._next, reader._repair_reason, reader.remote_store = 10, None, None
    reader.progress = HistoryProgress(10)
    reader._validate_advance = lambda *_: None
    error = HistoricalHeaderRecoveryProgress("historical header recovery in progress")
    error.ancestry_progress = {
        "state": "running",
        "target_block": 10,
        "elapsed_seconds": 8,
        "eta_seconds": 32,
        "planning_eta_seconds": None,
        "percent": 20,
        "eta_basis": "measured_durable_ancestry_links_per_elapsed_second",
        "eta_scope": "current_owned_ancestry_only_excludes_block_proofs_and_rewards",
    }

    async def advancing(*_, **__):
        raise error

    reader._advance = advancing
    with pytest.raises(HistoricalHeaderRecoveryProgress) as raised:
        await reader._observed_advance(None, through_block=20, maximum_blocks=10)
    assert raised.value is error
    progress = reader.progress.latest
    assert progress["stage"] == "owned_historical_ancestry"
    assert progress["state"] == "running"
    assert progress["stage_eta_seconds"] == 32
    assert progress["eta_seconds"] is None
    assert progress["native_completed"] == progress["applied_blocks"] == 0
    assert progress["ancestry_progress"]["percent"] == 20
