"""Runtime exports and cancellation around real native checkpoint transfer.

The transfer fixture substitutes the external installed-owner port. Native proof
facts, source generations, target checkpoints and archive publication are real;
the separate owner suite qualifies actual stopped leases and active-owner refusal.
"""

import asyncio
import json
import logging
import threading
from contextlib import asynccontextmanager

import pytest

from umi.competition_reward_proof_archive import RewardProofArchive

from .test_competition_reward_history_transfer import chain as chain
from .test_competition_reward_history_transfer import chain_config as chain_config
from .test_competition_reward_history_transfer import control as control
from .test_competition_reward_history_transfer import historical as historical
from .test_competition_reward_history_transfer import history_case as history_case
from .test_competition_reward_history_transfer import policy as policy
from .test_competition_reward_history_transfer import series_case as series_case
from .test_competition_reward_history_transfer import transfer_case as transfer_case


@pytest.fixture
async def runtime_case(transfer_case, monkeypatch, tmp_path):
    from umi import competition_reward_history_transfer_runtime as runtime

    h = transfer_case
    h.runtime = runtime
    h.archive = RewardProofArchive(tmp_path / "runtime-export")
    h.archive._ensure_root()
    h.events = []

    def recheck(source=None, target=None):
        assert h.owner.active
        if source is not None:
            assert source is h.source and target is h.target

    h.owner.recheck = recheck

    @asynccontextmanager
    async def hold(*args, **kwargs):
        h.owner.active = True
        h.events.append("acquired")
        try:
            yield h.owner
        finally:
            h.events.append("released")
            h.owner.active = False

    def open_readers(owner):
        assert owner is h.owner and owner.active
        h.target.export_archive = h.archive
        return h.source, h.target

    monkeypatch.setattr(runtime, "hold_history_transfer_owner", hold)
    monkeypatch.setattr(runtime, "_open_readers", open_readers)

    async def execute(**kwargs):
        return await runtime.transfer_installed_history(
            object(),
            unit="fixture-owner.service",
            config_path=tmp_path / "supervisor.json",
            standing_boot=tmp_path / "writer.json",
            coordinator_config=tmp_path / "coordinator.json",
            **(h.options | kwargs),
        )

    h.execute = execute
    return h


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_exports_real_native_facts_and_repeat_is_metadata_only(
    runtime_case, monkeypatch
):
    h = runtime_case
    expected_count = h.end - h.source.first_block + 1
    first = await h.execute(maximum_blocks=2)
    assert first["status"] == "complete"
    assert first["completed_blocks"] == first["transferred_blocks"] == expected_count
    assert first["new_export_receipts"] == expected_count
    assert first["chain_submission_authorized"] is False
    assert first["ordered_restore_and_fresh_finality_required"] is True
    materialization = first["materialization"]
    assert materialization["schema"] == "umi-local-history-materialization/1"
    assert materialization["checkpoint_blocks"] == expected_count
    assert materialization["source_complete_blocks"] == expected_count
    assert materialization["export_complete_blocks"] == expected_count
    assert materialization["newly_applied_blocks"] == 0
    assert materialization["applied_progress"] is None
    assert h.target._next == h.source.first_block
    h.target = h.reopen_target()
    original = h.source.journal.get_raw

    def no_payload_repeat(kind, record_id, **kwargs):
        if kind in {"control_history_block", "control_history_chunk", "control_history_object"}:
            pytest.fail("completed native source payload copied on repeat")
        return original(kind, record_id, **kwargs)

    monkeypatch.setattr(h.source.journal, "get_raw", no_payload_repeat)
    second = await h.execute(maximum_blocks=2)
    assert second["status"] == "complete"
    assert second["transferred_blocks"] == second["new_export_receipts"] == 0
    assert second["existing_blocks"] == expected_count
    assert second["materialization"] == materialization
    assert h.events == ["acquired", "released", "acquired", "released"]


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_export_failure_preserves_native_completion_for_retry(
    runtime_case, monkeypatch
):
    h = runtime_case
    first, last = h.source.first_block, h.source.first_block + 1
    export = h.target._ensure_checkpoint_export

    async def fail_second(value):
        assert h.owner.active
        if value["snapshot"]["block_number"] == last:
            raise OSError("fixture interrupted export")
        return await export(value)

    monkeypatch.setattr(h.target, "_ensure_checkpoint_export", fail_second)
    with pytest.raises(OSError, match="interrupted export"):
        await h.execute(through_block=last, maximum_blocks=2)
    assert not h.owner.active
    assert h.target.checkpoints.load(first)["exports"]
    assert h.target.checkpoints.load(last)["exports"] == []
    h.target = h.reopen_target()
    retry = await h.execute(through_block=last, maximum_blocks=2)
    assert retry["status"] == "complete"
    assert retry["transferred_blocks"] == 0
    assert retry["existing_blocks"] == 2
    assert retry["new_export_receipts"] == 1
    assert retry["materialization"]["export_complete_blocks"] == 2


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_cooperative_stop_reports_interruption_without_work(runtime_case, caplog):
    h = runtime_case
    stop = threading.Event()
    stop.set()
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    result = await h.execute(stop_requested=stop)
    assert result["status"] == "interrupted"
    assert result["completed_blocks"] == result["transferred_blocks"] == 0
    assert "materialization" not in result
    assert h.target.checkpoints.load(h.source.first_block) is None
    rows = []
    for record in caplog.records:
        if record.name == "umi.competition.progress":
            try:
                row = json.loads(record.getMessage())
            except ValueError:
                continue
            if row.get("stage") == "history_transfer_and_export":
                rows.append(row)
    assert rows
    assert not any(row.get("state") == "accounting_mismatch" for row in rows)
    assert rows[-1].get("state", rows[-1].get("status")) in {"interrupted", "retrying"}


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_task_cancellation_drains_before_releasing_owner(runtime_case, monkeypatch):
    h = runtime_case
    started, release = threading.Event(), threading.Event()
    transfer = h.runtime.transfer_history_checkpoints
    from umi.canonical_reuse import _ACTIVE

    caches = []

    def slow(*args, **kwargs):
        assert h.owner.active
        cache = _ACTIVE.get()
        assert cache is not None and not cache.closed
        caches.append(cache)
        started.set()
        assert release.wait(10), "test did not release bounded transfer"
        assert not cache.closed
        assert h.owner.active
        result = transfer(*args, **kwargs)
        h.events.append("worker_drained")
        return result

    monkeypatch.setattr(h.runtime, "transfer_history_checkpoints", slow)
    task = asyncio.create_task(h.execute(through_block=h.source.first_block, maximum_blocks=1))
    try:
        assert await asyncio.to_thread(started.wait, 10)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done() and h.owner.active
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert h.events.index("worker_drained") < h.events.index("released")
    assert caches and all(cache.closed and not cache.entries for cache in caches)
    assert not h.owner.active
    retry = await h.execute(through_block=h.source.first_block, maximum_blocks=1)
    assert retry["status"] == "complete"


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_stop_during_materialization_has_no_completed_terminal(
    runtime_case, monkeypatch
):
    h = runtime_case
    stop = threading.Event()
    review = h.runtime.review_history_materialization

    def interrupted(*args, **kwargs):
        assert h.owner.active
        stop.set()
        return review(*args, **kwargs)

    monkeypatch.setattr(h.runtime, "review_history_materialization", interrupted)
    result = await h.execute(through_block=h.source.first_block, stop_requested=stop)
    assert result["status"] == "interrupted"
    assert result["completed_blocks"] == 1
    assert "materialization" not in result
    assert h.target.checkpoints.load(h.source.first_block)["exports"]
    assert not h.owner.active
    monkeypatch.setattr(h.runtime, "review_history_materialization", review)
    retry = await h.execute(through_block=h.source.first_block)
    assert retry["status"] == "complete"
    assert retry["transferred_blocks"] == retry["new_export_receipts"] == 0
    assert retry["materialization"]["checkpoint_blocks"] == 1


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_cancellation_drains_materialization_before_owner_release(
    runtime_case, monkeypatch
):
    h = runtime_case
    started, release = threading.Event(), threading.Event()
    review = h.runtime.review_history_materialization

    def slow(*args, **kwargs):
        assert h.owner.active
        started.set()
        assert release.wait(10), "test did not release materialization review"
        assert h.owner.active
        try:
            return review(*args, **kwargs)
        finally:
            h.events.append("materialization_drained")

    monkeypatch.setattr(h.runtime, "review_history_materialization", slow)
    task = asyncio.create_task(h.execute(through_block=h.source.first_block))
    try:
        assert await asyncio.to_thread(started.wait, 10)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done() and h.owner.active
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert h.events.index("materialization_drained") < h.events.index("released")
    assert not h.owner.active


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_exact_json_reuse_reaches_owned_threads_and_expires(
    runtime_case, monkeypatch
):
    from umi import canonical_reuse as reuse
    from umi.protocol import canonical_json_bytes

    h = runtime_case
    check = h.owner.recheck
    calls, caches = [], []
    original = reuse.rfc8785.dumps
    selected = {"transfer_fixture_binding": ["owner", "unchanged"]}

    def counted(value):
        if value == selected:
            calls.append(value)
        return original(value)

    def recheck(*args):
        check(*args)
        cache = reuse._ACTIVE.get()
        assert cache is not None and not cache.closed
        caches.append(cache)
        probe = {"nested": ["before"]}
        assert canonical_json_bytes(probe) == b'{"nested":["before"]}'
        probe["nested"][0] = "after"
        assert canonical_json_bytes(probe) == b'{"nested":["after"]}'
        assert (
            canonical_json_bytes(selected) == b'{"transfer_fixture_binding":["owner","unchanged"]}'
        )

    monkeypatch.setattr(reuse.rfc8785, "dumps", counted)
    monkeypatch.setattr(h.owner, "recheck", recheck)
    first = await h.execute(maximum_blocks=1)
    assert len(calls) == 1 and len(caches) > 1
    first_cache = caches[0]
    assert all(cache is first_cache for cache in caches)
    assert first_cache.closed and first_cache.size == 0
    assert reuse._ACTIVE.get() is None
    h.target = h.reopen_target()
    caches.clear()
    second = await h.execute(maximum_blocks=1)
    assert len(calls) == 2
    assert all(cache is not first_cache and cache.closed for cache in caches)
    assert first["materialization"] == second["materialization"]
    assert second["transferred_blocks"] == second["new_export_receipts"] == 0


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_runtime_parent_tracks_actual_native_child_without_export_credit(
    runtime_case, monkeypatch, caplog
):
    h = runtime_case
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    # Native transfer events must reach the parent before the first export.
    export = h.target._ensure_checkpoint_export

    async def checked_export(value):
        rows = [
            json.loads(r.getMessage())
            for r in caplog.records
            if r.name == "umi.competition.progress"
        ]
        parents = [r for r in rows if r.get("stage") == "history_transfer_and_export"]
        assert any(
            r.get("active_child", {}).get("completed_units", 0) > 0
            for r in parents
            if r.get("active_child")
        )
        assert all(r["completed_units"] == 0 for r in parents)
        assert all(r["percent"] == 0 for r in parents)
        return await export(value)

    monkeypatch.setattr(h.target, "_ensure_checkpoint_export", checked_export)
    result = await h.execute(through_block=h.source.first_block)
    assert result["status"] == "complete"
