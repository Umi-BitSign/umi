"""Telemetry exposes preparation waits without issuing or repeating proofs."""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from umi import competition_reward_history as history_module
from umi import competition_reward_history_parallel as parallel
from umi import competition_reward_history_progress as progress_module
from umi import competition_transport_verification as transfer_module


def make_reader():
    progress = progress_module.HistoryProgress(10)
    progress.start(19, 10)
    return SimpleNamespace(_next=10, _repair_reason=None, progress=progress)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["capture", "review", "reused", "failure"])
async def test_native_wall_time_excludes_restore_and_reused_checkpoint(monkeypatch, caplog, mode):
    now = [100.0]
    monkeypatch.setattr(transfer_module.time, "monotonic", lambda: now[0])
    reader = make_reader()
    reader.checkpoints = SimpleNamespace(
        load=lambda height: {"completed": True} if mode == "reused" else None
    )
    reader.archive, reader.hotkey = None, "hotkey"

    def load(height):
        now[0] += 7
        return {"evidence": b"original"} if mode in {"review", "failure"} else None

    async def verify(*args, **kwargs):
        now[0] += 3
        if mode == "failure":
            raise ValueError("native proof refused")
        return "verified"

    reader._load = load
    monkeypatch.setattr(history_module, "capture_control_writes", verify)
    monkeypatch.setattr(history_module, "review_control_writes", verify)
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        if mode == "failure":
            with pytest.raises(ValueError, match="native proof refused"):
                await history_module.RewardControlHistoryReader._prepare(reader, None, 10)
        else:
            result = await history_module.RewardControlHistoryReader._prepare(reader, None, 10)
            assert result == (
                ({"completed": True}, True) if mode == "reused" else ("verified", mode == "review")
            )
    scopes = [
        json.loads(record.message)
        for record in caplog.records
        if '"stage":"history_native_verification"' in record.message
    ]
    if mode == "reused":
        assert scopes == []
    else:
        assert scopes[-1]["elapsed_seconds"] == 3
        assert scopes[-1]["status"] == ("retrying" if mode == "failure" else "completed")
        assert scopes[-1]["completed_units"] == (0 if mode == "failure" else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_native_worker_wait_excludes_source_and_checkpoint_persistence(
    monkeypatch, caplog, failure
):
    @dataclass
    class Snapshot:
        block_number: int

    now = [100.0]
    monkeypatch.setattr(transfer_module.time, "monotonic", lambda: now[0])
    reader = make_reader()
    reader._source_tokens = {}
    reader._repair_id = None
    persisted = []

    def save(height, fields):
        now[0] += 7
        reader._source_tokens[height] = []

    def remember(value, **kwargs):
        now[0] += 11
        persisted.append(value)

    def result(future):
        now[0] += 3
        if failure:
            raise ValueError("worker proof refused")
        return SimpleNamespace(
            snapshot=Snapshot(10),
            header={},
            control_sha256="a" * 64,
            committed_at_block=10,
            slot_evidence_sha256="b" * 64,
            slot_metadata_sha256="c" * 64,
            write_evidence_sha256="d" * 64,
            writes=[],
            unresolved_extrinsics=[],
        )

    reader._save_fields = save
    reader.checkpoints = SimpleNamespace(owner={}, semantics={}, remember=remember)
    future = asyncio.get_running_loop().create_future()
    future.set_result(None)
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        if failure:
            with pytest.raises(ValueError, match="worker proof refused"):
                await parallel._persist(reader, SimpleNamespace(result=result), future, {}, False)
        else:
            await parallel._persist(reader, SimpleNamespace(result=result), future, {}, False)
    scopes = [
        json.loads(record.message)
        for record in caplog.records
        if '"stage":"history_native_worker_wait"' in record.message
    ]
    assert scopes[-1]["elapsed_seconds"] == 3
    assert scopes[-1]["status"] == ("retrying" if failure else "completed")
    assert len(persisted) == (0 if failure else 1)


def test_preparation_time_never_becomes_proof_rate_and_stops_with_owner(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: now[0])
    reader = make_reader()
    progress = reader.progress
    progress.preparation_start("owned_history_header_resolution", 10, "finalized_ancestry")
    now[0] = 20
    progress.report(reader, "running")
    assert progress.latest["stage_elapsed_seconds"] == 20
    assert progress.latest["stage_planning_eta_seconds"] == [0.0, 280.0]
    assert progress.latest["native_elapsed_seconds"] == 0
    assert progress.latest["native_completed"] == 0
    assert progress.latest["blocks_per_second"] is None
    assert progress.latest["eta_seconds"] is None
    assert progress.latest["eta_basis"] == "waiting_for_retained_history_preparation"
    now[0] = 61
    progress.report(reader, "running")
    assert progress.latest["state"] == "stalled"
    assert progress.latest["stage_planning_eta_seconds"] is None
    progress.report(reader, "retrying", error_type="ValidatorChainError")
    assert progress.latest["state"] == "retrying"
    assert progress.latest["stage_reason"] == "finalized_ancestry"
    progress.finish()
    now[0] = 1000
    progress.report(reader, "pending")
    assert progress.latest["stage_elapsed_seconds"] == 61
    assert progress.latest["elapsed_seconds"] == 1000
    assert progress.latest["active_elapsed_seconds"] == 61
    assert progress.latest["stage_planning_eta_seconds"] is None
    progress.start(19, 10)
    progress.report(reader, "running")
    assert progress.latest["stage_reason"] is None
    assert progress.latest["active_block"] is None


def test_native_rate_starts_after_first_resolution_and_keeps_existing_pipeline_clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: now[0])
    reader = make_reader()
    progress = reader.progress
    progress.preparation_start("owned_history_header_resolution", 10, "finalized_ancestry")
    now[0] = 20
    progress.native_start(retained=True)
    now[0] = 23
    for height in (10, 11, 12):
        progress.native_finished(height)
        progress.applied(height)
    reader._next = 13
    progress.report(reader, "running")
    assert progress.latest["stage"] == "legacy_checkpoint_migration"
    assert progress.latest["stage_reason"] is None
    assert progress.latest["native_elapsed_seconds"] == 3
    assert progress.latest["blocks_per_second"] == 1
    progress.preparation_start("owned_history_header_resolution", 13, "finalized_ancestry")
    now[0] = 25
    progress.report(reader, "running")
    assert progress.latest["native_elapsed_seconds"] == 5
    assert progress.latest["native_verified_blocks_per_second"] == 0.6
    assert progress.latest["eta_seconds"] is None
    assert progress.latest["stage_elapsed_seconds"] == 2


@pytest.mark.asyncio
async def test_completed_checkpoint_loading_never_reads_unchanged_payload():
    reader = make_reader()
    receipt = {"completed": True}
    loads = []

    def load(height):
        loads.append(height)
        assert reader.progress.latest["stage"] == "retained_history_loading"
        return receipt

    def forbidden(*args):
        raise AssertionError("completed evidence must not be reread")

    reader.checkpoints = SimpleNamespace(load=load)
    reader._load = forbidden
    assert await parallel._load_input(reader, 10) == (receipt, None, True)
    assert loads == [10]
    assert reader.progress.native_started is None


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_before_submit", [False, True])
async def test_owned_header_wait_is_visible_before_any_worker_submission(
    monkeypatch, stop_before_submit
):
    reader = make_reader()
    waiting, release, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()
    snapshots, submitted, released = [], [], []
    snapshot = SimpleNamespace(block_number=10)
    fields = {"slot_evidence": b"retained"}

    async def resolve(selected, header):
        assert selected is snapshot and header == {"header": 10}
        snapshots.append(selected)
        assert reader.progress.latest["stage"] == "owned_history_header_resolution"
        assert reader.progress.latest["active_block"] == 10
        assert reader.progress.latest["stage_reason"] == (
            "resolve_header_and_finalized_ancestry_before_native_submission"
        )
        assert reader.progress.native_started is None
        waiting.set()
        await release.wait()
        return 100, 20

    def hint(raw):
        assert raw == b"retained"
        assert reader.progress.latest["stage"] == "retained_history_header"
        return snapshot, {"header": 10}

    def submit(**kwargs):
        assert reader.progress.latest["stage"] == "legacy_checkpoint_migration"
        submitted.append(kwargs)
        future = asyncio.get_running_loop().create_future()
        future.set_result(None)
        return future

    async def persist(*args):
        return {"unchanged_native_result": True}

    @asynccontextmanager
    async def window():
        yield resolve

    provider = SimpleNamespace(
        _lock=asyncio.Lock(),
        _closed=False,
        _owned=True,
        _cache_root=None,
        config=SimpleNamespace(maximum_cache_bytes=100),
        _control_header_window=window,
    )
    pool = SimpleNamespace(submit=submit, release=released.append)
    monkeypatch.setattr(parallel, "archive_header_hint", hint)
    monkeypatch.setattr(parallel, "_cache_usage", lambda *args: None)
    monkeypatch.setattr(parallel, "_persist", persist)
    task = asyncio.create_task(
        parallel._window(reader, provider, pool, [(10, fields, True)], stop, last_height=10)
    )
    await asyncio.wait_for(waiting.wait(), timeout=2)
    reader.progress.report(reader, "running", force=True)
    assert reader.progress.latest["native_completed"] == 0
    assert reader.progress.latest["native_elapsed_seconds"] == 0
    assert submitted == []
    if stop_before_submit:
        stop.set()
    release.set()
    result = await asyncio.wait_for(task, timeout=2)
    assert len(snapshots) == 1
    assert len(submitted) == len(released) == (0 if stop_before_submit else 1)
    assert result == ([] if stop_before_submit else [{"unchanged_native_result": True}])


def test_preparation_logging_failure_never_changes_native_state(monkeypatch):
    reader = make_reader()

    def failed(*args, **kwargs):
        raise OSError("diagnostic sink failed")

    monkeypatch.setattr(progress_module.logger, "info", failed)
    reader.progress.preparation_start("retained_history_loading", 10, "retained_frame")
    reader.progress.report(reader, "running", force=True)
    assert reader.progress.latest["stage"] == "retained_history_loading"
    assert reader.progress.native_completed == 0
