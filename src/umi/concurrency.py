"""Async ownership of work that must finish before releasing a lock."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from typing import TypeVar

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
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            if on_cancel is not None:
                on_cancel()
        finally:
            while not task.done():
                try:
                    await asyncio.shield(task)
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


async def kill_and_reap(process: asyncio.subprocess.Process) -> int:
    """Stop one owned child and wait for it despite repeated caller cancellation.

    This establishes only the direct child's exit. Container runtimes must
    separately verify the absence of their managed containers and descendants.
    """
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.kill()
    return await await_owned_task(asyncio.create_task(process.wait()))
