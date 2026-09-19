import asyncio
import contextlib
import os
import sys
import threading

import pytest

from umi.concurrency import await_owned_task, run_owned_thread, wait_for_owned


@pytest.mark.parametrize("times_out", [False, True])
async def test_owned_timeout_drains_cleanup_despite_repeated_cancellation(times_out):
    entered, cleaning, finish, finished = (asyncio.Event() for _ in range(4))

    async def work():
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await finish.wait()
            finished.set()

    waiter = asyncio.create_task(wait_for_owned(work(), timeout=0.02 if times_out else 5))
    try:
        await asyncio.wait_for(entered.wait(), timeout=3)
        if not times_out:
            waiter.cancel()
        await asyncio.wait_for(cleaning.wait(), timeout=3)
        waiter.cancel()
        await asyncio.sleep(0)
        waiter.cancel()
        await asyncio.sleep(0)
        assert not waiter.done() and not finished.is_set()
        finish.set()
        with pytest.raises(asyncio.TimeoutError if times_out else asyncio.CancelledError):
            await waiter
        assert finished.is_set()
    finally:
        finish.set()
        await asyncio.gather(waiter, return_exceptions=True)


async def test_owned_timeout_returns_result_and_original_error():
    async def work():
        return 42

    assert await wait_for_owned(work(), timeout=1) == 42
    error = ValueError("invalid proof")

    async def fail():
        raise error

    with pytest.raises(ValueError) as caught:
        await wait_for_owned(fail(), timeout=1)
    assert caught.value is error


async def test_owned_task_returns_result():
    async def work():
        return 42

    task = asyncio.create_task(work())
    assert await await_owned_task(task) == 42
    assert task.done()


async def test_owned_task_propagates_original_error():
    failure = ValueError("owned task failure")

    async def work():
        raise failure

    task = asyncio.create_task(work())
    with pytest.raises(ValueError) as caught:
        await await_owned_task(task)
    assert caught.value is failure


@pytest.mark.parametrize("cooperative_callback", [False, True])
async def test_owned_task_repeated_cancellation_waits_for_cleanup(cooperative_callback):
    entered, shutdown_requested = asyncio.Event(), asyncio.Event()
    cleanup_entered, finish, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
    requests = []

    async def work():
        try:
            entered.set()
            await shutdown_requested.wait()
        finally:
            cleanup_entered.set()
            await finish.wait()
            finished.set()

    def request_shutdown():
        requests.append(True)
        shutdown_requested.set()

    owned = asyncio.create_task(work())
    waiter = asyncio.create_task(
        await_owned_task(owned, on_cancel=request_shutdown if cooperative_callback else None)
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=3)
        waiter.cancel()
        await asyncio.sleep(0)
        assert not waiter.done() and not owned.done()
        if not cooperative_callback:
            # Cancellation alone must leave the owned task running. Its normal
            # completion can initiate cleanup without a shutdown callback.
            assert not cleanup_entered.is_set()
            shutdown_requested.set()
        await asyncio.wait_for(cleanup_entered.wait(), timeout=3)
        waiter.cancel()
        await asyncio.sleep(0)
        assert not waiter.done() and not finished.is_set()
        finish.set()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert finished.is_set() and owned.done() and not owned.cancelled()
        assert requests == ([True] if cooperative_callback else [])
    finally:
        shutdown_requested.set()
        finish.set()
        await asyncio.gather(waiter, owned, return_exceptions=True)


async def test_owned_task_accepts_already_cancelled_task():
    async def work():
        await asyncio.Event().wait()

    task = asyncio.create_task(work())
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled()
    with pytest.raises(asyncio.CancelledError):
        await await_owned_task(task)


async def test_owned_thread_returns_result_and_propagates_worker_error():
    assert await run_owned_thread(lambda value: value + 1, 2) == 3

    def fail():
        raise ValueError("test failure")

    with pytest.raises(ValueError, match="test failure"):
        await run_owned_thread(fail)


@pytest.mark.parametrize("worker_fails", [False, True])
async def test_repeated_cancellation_drains_worker_without_losing_ownership(worker_fails):
    entered, cleanup_requested = asyncio.Event(), asyncio.Event()
    finish, finished = threading.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    def work():
        loop.call_soon_threadsafe(entered.set)
        try:
            if not finish.wait(3):
                raise TimeoutError("test cleanup did not finish")
            if worker_fails:
                raise ValueError("worker failed during cancellation")
        finally:
            finished.set()

    task = asyncio.create_task(run_owned_thread(work, on_cancel=cleanup_requested.set))
    try:
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        await asyncio.wait_for(cleanup_requested.wait(), timeout=3)
        assert not task.done() and not finished.is_set()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()
    finally:
        finish.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.to_thread(finished.wait, 3)


@pytest.mark.parametrize("name", ["successor", "legacy", "evaluator"])
async def test_command_cancellation_reaps_real_child(monkeypatch, name):
    started = asyncio.Event()
    children = []
    original = asyncio.create_subprocess_exec

    async def spawn(*args, **kwargs):
        child = await original(*args, **kwargs)
        children.append(child)
        started.set()
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    runner, options = _command_runner(name)
    task = asyncio.create_task(
        runner((sys.executable, "-I", "-c", "import time; time.sleep(30)"), **options)
    )
    try:
        await asyncio.wait_for(started.wait(), timeout=3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        assert len(children) == 1 and children[0].returncode is not None
        with pytest.raises(ProcessLookupError):
            os.kill(children[0].pid, 0)
    finally:
        task.cancel()
        for child in children:
            if child.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    child.kill()
            await child.wait()
        await asyncio.gather(task, return_exceptions=True)


def _command_runner(name):
    from umi.competition_container import _run_command
    from umi.competition_runner import _small_command
    from umi.validator_supervisor_adapters import _run_bounded_command

    if name == "evaluator":
        return _small_command, {"timeout": 30}
    runner = _run_command if name == "successor" else _run_bounded_command
    return runner, {"timeout_seconds": 30, "maximum_output_bytes": 1024}


@pytest.mark.parametrize("name", ["successor", "legacy", "evaluator"])
@pytest.mark.parametrize("reap_error", [False, True])
async def test_command_cancellation_drains_child_before_releasing_lock(
    monkeypatch, name, reap_error
):
    entered, reaping, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
    lock = asyncio.Lock()

    class Process:
        returncode = None
        killed = False

        def __init__(self):
            self.stdout = self

        async def read(self, _amount):
            entered.set()
            await asyncio.Event().wait()

        def kill(self):
            self.killed = True

        async def wait(self):
            assert self.killed
            reaping.set()
            await finish.wait()
            self.returncode = -9
            if reap_error:
                raise OSError("synthetic reap failure")
            return self.returncode

    process = Process()

    async def spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    runner, options = _command_runner(name)

    async def command():
        async with lock:
            return await runner(("/usr/bin/podman", "info"), **options)

    task = asyncio.create_task(command())
    try:
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        await asyncio.wait_for(reaping.wait(), timeout=3)
        assert process.killed and lock.locked() and not task.done()
        task.cancel()
        for _ in range(3):
            await asyncio.sleep(0)
        assert lock.locked() and not task.done() and process.returncode is None
        finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert process.returncode == -9 and not lock.locked()
    finally:
        finish.set()
        await asyncio.gather(task, return_exceptions=True)
