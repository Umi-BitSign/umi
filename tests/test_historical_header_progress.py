"""Measured owned ancestry telemetry preserves the native replay outcomes."""

import ast
import asyncio
import logging
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_progress as history_telemetry
from umi import historical_header_progress as telemetry
from umi.competition_reward_coordinator_cli import _logs
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


def test_supervisor_exposes_handoff_and_ancestry_status_and_restores_loggers(capsys):
    from umi.competition_supervisor_cli import _standing_logs

    names = ("umi.competition_reward_handoff", "umi.historical_header_progress")
    loggers = [logging.getLogger(name) for name in names]
    before = [(logger.level, logger.propagate, tuple(logger.handlers)) for logger in loggers]
    with _standing_logs():
        loggers[0].info("legacy_handoff_inventory attempts=449")
        loggers[1].info("historical_header_recovery_progress bounded_native_pass")
    output = capsys.readouterr().err
    assert "legacy_handoff_inventory attempts=449" in output
    assert "historical_header_recovery_progress bounded_native_pass" in output
    assert [
        (logger.level, logger.propagate, tuple(logger.handlers)) for logger in loggers
    ] == before


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


async def test_coordinator_emits_each_bounded_ancestry_pass_across_outer_target_changes(
    walk, measured_clock, monkeypatch, capsys
):
    w = walk
    monkeypatch.setattr(history_telemetry, "time", telemetry.time)
    service = HistoricalHeaderRecovery(w.connect, batch_size=8)
    reader = object.__new__(RewardControlHistoryReader)
    reader._next, reader._repair_reason, reader.remote_store = w.target.block_number, None, None
    reader.progress = HistoryProgress(reader._next)
    reader._validate_advance = lambda *_: None

    async def request(method, params):
        measured_clock[0] += 0.25
        return await w.request(method, params)

    async def advancing(*_, **__):
        with reader.progress.watch_ancestry(service.telemetry, w.target.block_number):
            await service.recover(w.anchor, w.target, request)

    reader._advance = advancing
    key = (w.anchor.finality_evidence_sha256, w.target.block_number)
    outer_targets = [w.anchor.height + offset for offset in (100, 200, 101, 201)]
    with _logs():
        for index, target in enumerate(outer_targets, start=1):
            with pytest.raises(HistoricalHeaderRecoveryProgress) as raised:
                await reader._observed_advance(None, through_block=target, maximum_blocks=8)
            latest = reader.progress.latest
            ancestry = latest["ancestry_progress"]
            assert ancestry == raised.value.ancestry_progress
            assert ancestry["anchor_evidence_sha256"] == key[0]
            assert ancestry["target_block"] == key[1]
            assert ancestry["completed_links"] == ancestry["newly_verified_links"] == 8 * index
            assert ancestry["elapsed_seconds"] == latest["stage_elapsed_seconds"] == 2 * index
            assert ancestry["links_per_second"] == 4
            assert ancestry["eta_seconds"] == latest["stage_eta_seconds"] == 10 - 2 * index
            assert latest["eta_seconds"] is None
            assert latest["native_completed"] == latest["applied_blocks"] == 0
            # The outer display clock may reset; the native ancestry clock and
            # exact cursor must continue without refetching the prior page.
            assert latest["elapsed_seconds"] == 2
            assert len(service.progress) == 1
            assert key in service.progress
            assert len(w.calls) == len(set(w.calls)) == 8 * index
        assert (await service.recover(w.anchor, w.target, request)).snapshot == w.target

    records = capsys.readouterr().err.splitlines()
    history = [
        ast.literal_eval(line.removeprefix("reward_history_progress "))
        for line in records
        if line.startswith("reward_history_progress ")
    ]
    emitted = [record for record in history if record["ancestry_progress"] is not None]
    # Every pass is shorter than the 30-second heartbeat and follows a forced
    # preparation log. Reading latest alone would miss the production failure.
    assert [record["target_block"] for record in emitted] == outer_targets
    assert [record["ancestry_progress"]["completed_links"] for record in emitted] == [8, 16, 24, 32]
    assert [record["stage_eta_seconds"] for record in emitted] == [8, 6, 4, 2]
    native = [
        ast.literal_eval(line.removeprefix("historical_header_recovery_progress "))
        for line in records
        if line.startswith("historical_header_recovery_progress ")
    ]
    assert native[0]["completed_links"] == 0
    assert native[-1]["completed_links"] == 40
    assert native[-1]["elapsed_seconds"] == 10
    assert native[-1]["state"] == "completed"
    assert native[-1]["eta_seconds"] == 0
    assert service.progress == {}
    assert len(w.calls) == len(set(w.calls)) == 40


def test_coordinator_ancestry_log_handlers_restore_after_failure(capsys):
    selected = [logging.getLogger(module.__name__) for module in (telemetry, history_telemetry)]
    before = [(logger.level, logger.propagate, tuple(logger.handlers)) for logger in selected]
    with pytest.raises(RuntimeError, match="coordinator stopped"), _logs():
        for logger in selected:
            assert logger.level == logging.INFO
            assert logger.propagate is False
            logger.info("coordinator ancestry logging selected: %s", logger.name)
        raise RuntimeError("coordinator stopped")
    assert [
        (logger.level, logger.propagate, tuple(logger.handlers)) for logger in selected
    ] == before
    output = capsys.readouterr().err
    for logger in selected:
        assert output.count("coordinator ancestry logging selected: " + logger.name) == 1


@pytest.mark.parametrize("failure", ["retry", "stall"])
async def test_coordinator_logs_withdraw_ancestry_eta_without_losing_native_cursor(
    walk, measured_clock, monkeypatch, capsys, failure
):
    w = walk
    monkeypatch.setattr(history_telemetry, "time", telemetry.time)
    service = HistoricalHeaderRecovery(w.connect, batch_size=8)
    reader = object.__new__(RewardControlHistoryReader)
    reader._next, reader._repair_reason, reader.remote_store = w.target.block_number, None, None
    reader.progress = HistoryProgress(reader._next)
    reader._validate_advance = lambda *_: None
    fail = False
    entered = asyncio.Event()

    async def request(method, params):
        measured_clock[0] += 1
        if fail:
            entered.set()
            if failure == "retry":
                raise OSError("archive unavailable")
            await asyncio.Future()
        return await w.request(method, params)

    async def advancing(*_, **__):
        with reader.progress.watch_ancestry(service.telemetry, w.target.block_number):
            await service.recover(w.anchor, w.target, request)

    reader._advance = advancing
    with _logs():
        with pytest.raises(HistoricalHeaderRecoveryProgress):
            await reader._observed_advance(None, through_block=w.anchor.height, maximum_blocks=8)
        assert reader.progress.latest["stage_eta_seconds"] == 32
        cursor = dict(service.progress)
        fail = True
        operation = reader._observed_advance(None, through_block=w.anchor.height, maximum_blocks=8)
        if failure == "retry":
            with pytest.raises(OSError, match="archive unavailable"):
                await operation
        else:
            task = asyncio.create_task(operation)
            try:
                await asyncio.wait_for(entered.wait(), 5)
                measured_clock[0] += 61
                service.telemetry.report(force=True)
                reader.progress.report(reader, "running", force=True)
                assert reader.progress.latest["state"] == "stalled"
                assert reader.progress.latest["stage_eta_seconds"] is None
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        assert reader.progress.latest["stage_eta_seconds"] is None
        assert reader.progress.latest["stage_planning_eta_seconds"] is None
        assert dict(service.progress) == cursor
        assert len(w.calls) == 8

    output = capsys.readouterr().err.splitlines()
    history = [
        ast.literal_eval(line.removeprefix("reward_history_progress "))
        for line in output
        if line.startswith("reward_history_progress ")
    ]
    interrupted = [record for record in history if record["state"] != "running"]
    assert interrupted
    assert all(record["stage_eta_seconds"] is None for record in interrupted)
    assert all(record["stage_planning_eta_seconds"] is None for record in interrupted)
    assert all(record["ancestry_progress"]["completed_links"] == 8 for record in interrupted)
    assert (await finish(service, w)).snapshot == w.target
    assert len(w.calls) == len(set(w.calls)) == 40
