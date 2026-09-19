"""Controlled blocking calls for async ownership regressions."""

from __future__ import annotations

import asyncio
import threading


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
