"""Controlled blocking calls for async ownership regressions."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

_Result = TypeVar("_Result")


class PausedCall:
    """Hold one synchronous operation without hanging an unoffloaded caller."""

    def __init__(self, original):
        self.original = original
        self.loop = asyncio.get_running_loop()
        self.entered = asyncio.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.thread_id = None

    def __call__(self, *args, **kwargs):
        if self.thread_id is not None:
            return self.original(*args, **kwargs)
        self.thread_id = threading.get_ident()
        self.loop.call_soon_threadsafe(self.entered.set)
        try:
            # A synchronous caller blocks the loop. Its bounded fallback makes
            # the regression fail instead of deadlocking the test process.
            if not self.release.wait(2):
                raise AssertionError("blocking operation prevented event-loop progress")
            return self.original(*args, **kwargs)
        finally:
            self.finished.set()

    async def drive(
        self,
        operation: Coroutine[Any, Any, _Result],
        serial: asyncio.Lock,
        *,
        cancel: bool = False,
    ) -> _Result:
        """Exercise event-loop progress and repeated cancellation, then drain."""
        task = asyncio.create_task(operation)
        try:
            await asyncio.wait_for(self.entered.wait(), timeout=5)
            assert self.thread_id != threading.get_ident()
            assert serial.locked() and not task.done()
            if cancel:
                for _ in range(2):
                    task.cancel()
                    await asyncio.sleep(0)
                    assert serial.locked() and not task.done()
            self.release.set()
            return await asyncio.wait_for(task, timeout=5)
        finally:
            self.release.set()
            await asyncio.gather(task, return_exceptions=True)
            assert self.finished.is_set() and not serial.locked()
