"""Async ownership of work that must finish before releasing a lock."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from contextlib import suppress
from typing import Any, TypeVar

_Result = TypeVar("_Result")


async def await_owned_task(
    task: asyncio.Task[_Result],
    *,
    on_cancel: Callable[[], None] | None = None,
) -> _Result:
    """Propagate caller cancellation only after the owned task has stopped.

    The optional callback requests cooperative shutdown. Caller cancellation
    alone does not cancel the owned task, including during cleanup. Callers
    must bound the task or provide a working shutdown callback.
    """
    try:
        # wait() leaves task ownership here when the waiter is cancelled. Unlike
        # shield() on Python 3.14, it installs no exception-logging callback that
        # could expose an error we explicitly consume during cleanup.
        await asyncio.wait((task,))
        return task.result()
    except asyncio.CancelledError:
        try:
            if on_cancel is not None:
                on_cancel()
        finally:
            while not task.done():
                try:
                    await asyncio.wait((task,))
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not task.cancelled():
                task.exception()
        raise


async def run_owned_thread(
    function: Callable[..., _Result],
    *args: object,
    on_cancel: Callable[[], None] | None = None,
) -> _Result:
    """Propagate cancellation only after the blocking operation has stopped.

    Cancelling a to_thread await cannot stop its thread. An optional callback
    requests cooperative shutdown; finite disk operations can drain without it.
    Callers must bound the operation or provide a working shutdown callback.
    """
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    return await await_owned_task(task, on_cancel=on_cancel)


async def wait_for_owned(coroutine: Coroutine[Any, Any, _Result], *, timeout: float) -> _Result:
    """Cancel on timeout or caller cancellation, then drain the owned operation.

    Owning the timed wait keeps repeated cancellation from abandoning child
    cleanup on Python 3.10. The child must implement bounded/cooperative cleanup;
    its shutdown can take longer than the operation's timeout.
    """
    task = asyncio.create_task(coroutine)
    try:
        done, _ = await asyncio.wait((task,), timeout=timeout)
        if not done:
            raise asyncio.TimeoutError
        return task.result()
    except (asyncio.CancelledError, asyncio.TimeoutError):
        task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await await_owned_task(task)
        raise


async def kill_and_reap(process: asyncio.subprocess.Process) -> int:
    """Stop one owned child and wait for it despite repeated caller cancellation.

    This establishes only the direct child's exit. Container runtimes must
    separately verify the absence of their managed containers and descendants.
    """
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.kill()
    return await await_owned_task(asyncio.create_task(process.wait()))
