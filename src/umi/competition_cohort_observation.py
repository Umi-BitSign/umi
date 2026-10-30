"""Owned, bounded HTTP observations with cooperative transport cancellation.

HTTPCore shields connection cleanup with AnyIO scopes. Raw asyncio cancellation
can bypass those scopes after a stream marks itself closed, stranding a pool
slot. Keep advisory deadlines and caller cancellation inside that same scope
mechanism, and retain the child until its cleanup has finished.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

import anyio

from .concurrency import await_owned_task

_Result = TypeVar("_Result")


async def observe_http(coroutine: Coroutine[Any, Any, _Result], *, timeout: float) -> _Result:
    """Apply a diagnostic deadline without raw cancellation into HTTP cleanup.

    Caller cancellation wins over a concurrent deadline. The scope can be cancelled
    before the child starts; entering it then delivers cooperative cancellation.
    Cleanup may exceed the deadline, but an expired observation is never returned
    as a successful sample.
    """
    scope = anyio.CancelScope(deadline=anyio.current_time() + timeout)
    caller_cancelled = False

    def cancel():
        nonlocal caller_cancelled
        caller_cancelled = True
        scope.cancel()

    async def run():
        try:
            with scope:
                result = await coroutine
        except TimeoutError as error:
            # Python 3.10 distinguishes these exception types. Preserve the
            # existing observer boundary on every supported interpreter.
            if type(error) is asyncio.TimeoutError:
                raise
            raise asyncio.TimeoutError from error
        if scope.cancel_called or anyio.current_time() >= scope.deadline:
            if caller_cancelled:
                raise asyncio.CancelledError
            raise asyncio.TimeoutError
        return result

    return await await_owned_task(asyncio.create_task(run()), on_cancel=cancel)
