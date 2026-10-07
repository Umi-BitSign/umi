import asyncio
import errno
import os
import threading

import pytest

from umi.private_files import PrivateStateBusyError, lock_private_file
from umi.private_state_wait import run_private_state_operation


async def test_waits_for_real_private_mutex_without_deleting_it(tmp_path):
    path = tmp_path / "state.lock"
    held = lock_private_file(path)
    inode = path.stat().st_ino
    entered = threading.Event()

    def read():
        entered.set()
        fd = lock_private_file(path)
        try:
            return "original state"
        finally:
            os.close(fd)

    task = asyncio.create_task(run_private_state_operation(read, timeout=5))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        await asyncio.sleep(0.1)
        assert not task.done()
        os.close(held)
        held = None
        assert await task == "original state"
        assert path.stat().st_ino == inode
    finally:
        if held is not None:
            os.close(held)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize(
    "error", [ValueError("invalid record"), OSError("disk failed"), PermissionError("permission")]
)
async def test_non_contention_error_is_not_retried(error):
    calls = []

    def fail():
        calls.append(1)
        raise error

    with pytest.raises(type(error)) as caught:
        await run_private_state_operation(fail, timeout=5)
    assert caught.value is error and calls == [1]


async def test_wait_budget_preserves_busy_error():
    error = PrivateStateBusyError("round_journal_lock", "ab" * 32, errno.EAGAIN)

    def fail():
        raise error

    with pytest.raises(PrivateStateBusyError) as caught:
        await run_private_state_operation(fail, timeout=0.01)
    assert caught.value is error


async def test_cancellation_drains_thread_before_releasing_caller():
    entered, finish, finished = (threading.Event() for _ in range(3))

    def work():
        entered.set()
        assert finish.wait(5)
        finished.set()

    task = asyncio.create_task(run_private_state_operation(work, timeout=5))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        task.cancel()
        await asyncio.sleep(0.05)
        task.cancel()
        assert not task.done()
        finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()
    finally:
        finish.set()
        await asyncio.gather(task, return_exceptions=True)
