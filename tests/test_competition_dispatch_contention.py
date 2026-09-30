"""Native SQLite contention defers polling without abandoning dispatched work."""

import asyncio
import sqlite3
import threading

import pytest

from umi import competition_dispatch as module

from .async_ownership import PausedCall
from .test_competition_dispatch import authorization as authorization
from .test_competition_dispatch import dispatch as dispatch
from .test_competition_dispatch import feed as feed
from .test_competition_dispatch import policy as policy
from .test_competition_dispatch import ready


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["timing", "page"])
async def test_real_writer_lock_keeps_inflight_claim_and_retries_without_resending(
    dispatch, monkeypatch, stage
):
    d = dispatch.driver
    await ready(dispatch)
    entered, release = asyncio.Event(), asyncio.Event()
    send = module.send_prepared_request
    transmissions = 0

    async def held_send(*args, **kwargs):
        nonlocal transmissions
        transmissions += 1
        entered.set()
        await release.wait()
        return await send(*args, **kwargs)

    monkeypatch.setattr(module, "send_prepared_request", held_send)
    assert (await d.poll_once())["in_flight"] == 1
    await asyncio.wait_for(entered.wait(), timeout=2)
    key, (owned, _miner) = next(iter(d._tasks.items()))
    cursor = d._cursor
    before = d.journal.events(key)
    connect = sqlite3.connect
    blocker = connect(d.journal.path, isolation_level=None)

    def bounded_connect(*args, **kwargs):
        # Exercise actual SQLITE_BUSY with a shorter fixture-only wait.
        return connect(*args, **{**kwargs, "timeout": 0.03})

    monkeypatch.setattr(sqlite3, "connect", bounded_connect)
    if stage == "timing":
        blocker.execute("BEGIN IMMEDIATE")
    else:
        ingest = d.ingest_once

        async def lock_after_ingestion():
            result = await ingest()
            blocker.execute("BEGIN IMMEDIATE")
            return result

        monkeypatch.setattr(d, "ingest_once", lock_after_ingestion)
    heartbeat = asyncio.create_task(asyncio.sleep(0.005))
    try:
        result = await asyncio.wait_for(d.poll_once(), timeout=2)
        assert heartbeat.done(), "SQLite busy wait blocked the HTTP event loop"
        assert result["publication_intake"] == "held"
        assert result["in_flight"] == 1
        assert not owned.done() and d._tasks[key][0] is owned
        assert d._cursor == cursor and transmissions == 1
        blocker.rollback()
        assert d.journal.events(key) == before
        if stage == "page":
            monkeypatch.setattr(d, "ingest_once", ingest)
        assert (await d.poll_once())["in_flight"] == 1
        release.set()
        assert await asyncio.wait_for(owned, timeout=5) == "completed"
        assert [e["kind"] for e in d.journal.events(key)] == [
            "published",
            "dispatched",
            "completed",
        ]
        assert await d.dispatch_one(key) == "held"
        assert transmissions == 1 and dispatch.miner.translator.calls == 1
    finally:
        blocker.rollback()
        blocker.close()
        release.set()
        await heartbeat
        await d.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["timing", "page"])
@pytest.mark.parametrize("cancel", [False, True])
async def test_poll_thread_work_drains_before_cancellation_returns(
    dispatch, monkeypatch, stage, cancel
):
    d = dispatch.driver
    owner, name = (
        (d, "_configure_timing") if stage == "timing" else (d.journal, "pending_dispatches")
    )
    paused = PausedCall(getattr(owner, name))
    monkeypatch.setattr(owner, name, paused)
    poll = asyncio.create_task(d.poll_once())
    try:
        await asyncio.wait_for(paused.entered.wait(), timeout=2)
        assert paused.thread_id != threading.get_ident()
        assert not poll.done()
        if cancel:
            for _ in range(2):
                poll.cancel()
                await asyncio.sleep(0)
                assert not poll.done() and not paused.finished.is_set()
        paused.release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await poll
            assert not d._tasks
        else:
            await poll
        assert paused.finished.is_set()
    finally:
        paused.release.set()
        await asyncio.gather(poll, return_exceptions=True)
        await d.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["timing", "page"])
@pytest.mark.parametrize(
    "error", [ValueError("timing mismatch"), sqlite3.OperationalError("I/O failure")]
)
async def test_only_identified_busy_errors_are_retryable(dispatch, monkeypatch, stage, error):
    d = dispatch.driver
    owner, name = (
        (d, "_configure_timing") if stage == "timing" else (d.journal, "pending_dispatches")
    )

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(owner, name, fail)
    with pytest.raises(type(error), match=str(error)):
        await d.poll_once()
    assert not d._tasks
