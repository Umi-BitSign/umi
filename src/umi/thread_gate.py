"""Serialize owned thread operations with bounded preference for short reads."""

from __future__ import annotations

import threading
from collections import deque
from contextlib import contextmanager


class ThreadGate:
    """Keep each queue FIFO and serve normal work after at most eight preferred reads.

    Preference changes admission order only. Operations remain exclusive, and
    recursive entry by the owning thread keeps its original admission. Waiting
    stores only tickets, never user data or validation results.
    """

    def __init__(self):
        self._condition = threading.Condition()
        self._normal: deque[object] = deque()
        self._preferred: deque[object] = deque()
        self._owner: int | None = None
        self._depth = 0
        self._preferred_runs = 0

    def _next(self):
        if self._preferred and (not self._normal or self._preferred_runs < 8):
            return self._preferred[0]
        return self._normal[0] if self._normal else None

    @contextmanager
    def hold(self, *, preferred: bool = False):
        if type(preferred) is not bool:
            raise ValueError("thread gate preference must be boolean")
        owner = threading.get_ident()
        with self._condition:
            if self._owner == owner:
                self._depth += 1
            else:
                queue = self._preferred if preferred else self._normal
                ticket = object()
                queue.append(ticket)
                self._condition.notify_all()
                try:
                    self._condition.wait_for(lambda: self._owner is None and self._next() is ticket)
                except BaseException:
                    queue.remove(ticket)
                    self._condition.notify_all()
                    raise
                queue.popleft()
                self._owner, self._depth = owner, 1
                self._preferred_runs = min(8, self._preferred_runs + 1) if preferred else 0
        try:
            yield
        finally:
            with self._condition:
                if self._owner != owner:
                    raise RuntimeError("thread gate released by another owner")
                self._depth -= 1
                if not self._depth:
                    self._owner = None
                    if not self._normal and not self._preferred:
                        self._preferred_runs = 0
                    self._condition.notify_all()
