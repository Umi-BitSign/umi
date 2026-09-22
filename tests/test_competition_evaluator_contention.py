"""Control-journal contention must not cancel one-use inference."""

import asyncio
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from umi import competition_evaluator as worker
from umi import competition_execution
from umi.competition_execution import execution_key

from .async_ownership import PausedCall
from .test_competition_evaluator import chain_config as chain_config
from .test_competition_evaluator import model_setup as model_setup
from .test_competition_evaluator import policy as policy
from .test_competition_evaluator import runtime as runtime
from .test_competition_evaluator import setup as setup


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["page", "advance"])
async def test_real_writer_lock_preserves_inference_and_completes_once(setup, monkeypatch, stage):
    driver = setup.drivers[0]
    entered, release = asyncio.Event(), asyncio.Event()
    execute = competition_execution.execute_offline_case
    invocations = []

    async def held_execute(**kwargs):
        invocations.append((kwargs["case_id"], kwargs["bundle"]))
        entered.set()
        await release.wait()
        return await execute(**kwargs)

    monkeypatch.setattr(competition_execution, "execute_offline_case", held_execute)
    assert (await driver.poll_once())["in_flight"] == 1
    await asyncio.wait_for(entered.wait(), timeout=2)
    slot, owned = next(iter(driver._tasks.items()))
    cursors = driver._cursor, driver._order_cursor
    connect = sqlite3.connect
    blocker = connect(driver.journal.path, isolation_level=None)
    before = blocker.execute("SELECT slot,body,conflict FROM orders ORDER BY slot").fetchall()

    def bounded_connect(*args, **kwargs):
        return connect(*args, **{**kwargs, "timeout": 0.03})

    monkeypatch.setattr(sqlite3, "connect", bounded_connect)
    boundary = driver.boundary
    if stage == "page":
        blocker.execute("BEGIN IMMEDIATE")
    else:

        async def lock_after_boundary():
            result = await boundary()
            blocker.execute("BEGIN IMMEDIATE")
            return result

        monkeypatch.setattr(driver, "boundary", lock_after_boundary)
    heartbeat = asyncio.create_task(asyncio.sleep(0.005))
    try:
        status = await asyncio.wait_for(driver.poll_once(), timeout=2)
        assert status["status"] == "waiting_database"
        assert heartbeat.done(), "SQLite waiting blocked inference/finality on the event loop"
        assert status["in_flight"] == 1
        assert not owned.done() and driver._tasks[slot] is owned
        assert (driver._cursor, driver._order_cursor) == cursors
        assert len(invocations) == 1
        blocker.rollback()
        assert (
            blocker.execute("SELECT slot,body,conflict FROM orders ORDER BY slot").fetchall()
            == before
        )
        monkeypatch.setattr(driver, "boundary", boundary)
        assert (await driver.poll_once())["in_flight"] == 1
        release.set()
        await asyncio.wait_for(owned, timeout=5)
        evidence = driver.executions.status(execution_key(setup.job))
        assert evidence["status"] == "complete"
        invocation_count = len(invocations)
        assert invocation_count == 2 * len(setup.job.cases)
        for _ in range(2):
            await driver.poll_once()
        assert len(invocations) == invocation_count
    finally:
        blocker.rollback()
        blocker.close()
        monkeypatch.setattr(driver, "boundary", boundary)
        release.set()
        await heartbeat
        await driver.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["settlement", "work", "round", "exchange"])
@pytest.mark.parametrize("code", [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED | (1 << 8)])
async def test_busy_background_completion_is_consumed_and_retried(setup, name, code):
    driver = setup.drivers[0]
    error = sqlite3.OperationalError("contended")
    error.sqlite_errorcode = code
    calls = []

    async def failed():
        raise error

    async def sync():
        calls.append(name)
        return {"held": 0}

    task_name = f"_{name}_task"
    setattr(
        driver, name if name == "exchange" else f"{name}_client", SimpleNamespace(sync_once=sync)
    )
    failed_task = asyncio.create_task(failed())
    await asyncio.gather(failed_task, return_exceptions=True)
    setattr(driver, task_name, failed_task)
    try:
        assert (await driver.poll_once())["status"] == "waiting_database"
        assert getattr(driver, task_name) is None
        assert (await driver.poll_once())["status"] == "poll_complete"
        await getattr(driver, task_name)
        assert calls == [name]
    finally:
        await driver.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [None, sqlite3.SQLITE_IOERR])
async def test_busy_message_without_code_and_nonbusy_database_errors_still_raise(
    setup, monkeypatch, code
):
    driver = setup.drivers[0]
    error = sqlite3.OperationalError("database is locked")
    if code is not None:
        error.sqlite_errorcode = code

    def fail():
        raise error

    monkeypatch.setattr(driver, "ingest_once", fail)
    with pytest.raises(sqlite3.OperationalError) as caught:
        await driver.poll_once()
    assert caught.value is error
    assert not driver._tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_owned_ingestion_thread_drains_before_shutdown(setup, monkeypatch, cancel):
    driver = setup.drivers[0]
    paused = PausedCall(driver.ingest_once)
    monkeypatch.setattr(driver, "ingest_once", paused)
    task = asyncio.create_task(driver.poll_once())
    try:
        await asyncio.wait_for(paused.entered.wait(), timeout=2)
        assert paused.thread_id != threading.get_ident()
        if cancel:
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and not paused.finished.is_set()
        paused.release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await task
            assert not driver._tasks
        else:
            await task
        assert paused.finished.is_set()
    finally:
        paused.release.set()
        await asyncio.gather(task, return_exceptions=True)
        await driver.aclose()


@pytest.mark.asyncio
async def test_service_keeps_running_after_contention_until_explicit_stop(setup, monkeypatch):
    import signal

    import bittensor as bt

    driver = setup.drivers[0]
    handlers, reports = {}, []
    error = sqlite3.OperationalError("contended")
    error.sqlite_errorcode = sqlite3.SQLITE_BUSY
    calls = 0

    async def poll():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise error
        return {"status": "poll_complete", "no_weight": True, "in_flight": 0}

    async def start():
        pass

    async def close():
        pass

    def report(result):
        reports.append(result["status"])
        if len(reports) == 2:
            handlers[signal.SIGTERM]()

    config = driver.config.model_copy(update={"poll_seconds": 1})
    monkeypatch.setattr(driver, "_poll_once", poll)
    monkeypatch.setattr(driver.provider, "start", start, raising=False)
    monkeypatch.setattr(driver.provider, "aclose", close, raising=False)
    monkeypatch.setattr(bt, "Wallet", lambda **kw: driver.wallet)
    monkeypatch.setattr(worker, "FinalizedRegistrationProvider", lambda *a: driver.provider)
    monkeypatch.setattr(worker, "ContinuousEvaluator", lambda *a, **kw: driver)
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "add_signal_handler", lambda sig, fn: handlers.setdefault(sig, fn))
    monkeypatch.setattr(loop, "remove_signal_handler", lambda sig: handlers.pop(sig, None))
    result = await asyncio.wait_for(
        worker.run_evaluator(config, driver.policy, report=report), timeout=10
    )
    assert result["status"] == "stopped"
    assert reports == ["waiting_database", "poll_complete"]
