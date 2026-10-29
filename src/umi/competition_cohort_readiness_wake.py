"""Process-local scheduling hints; durable owner checkpoints remain authority."""

import asyncio
import time
from contextlib import contextmanager
from threading import Lock


class ReadinessWake:
    """One coalesced hint for one serial owner, including thread-origin commits."""

    def __init__(self):
        self._lock = Lock()
        self._loop = asyncio.get_running_loop()
        self._event = asyncio.Event()
        self._closed = False
        self._queued_at = None
        self._active_at = None
        self._hints = self._awakened = self._completed = 0
        self._queue_seconds = 0.0
        self._retrying = False
        self._started_at = time.monotonic()
        self._last_poll_seconds = 0.0

    def notify(self):
        with self._lock:
            if self._closed:
                return
            self._hints += 1
            if self._queued_at is None:
                self._queued_at = time.monotonic()
                # Schedule only the empty -> queued transition, not every hint.
                self._loop.call_soon_threadsafe(self._signal)

    def _signal(self):
        with self._lock:
            # A callback queued before begin() must not resurrect a consumed hint.
            if not self._closed and self._queued_at is not None:
                self._event.set()

    def begin(self):
        with self._lock:
            now = time.monotonic()
            if self._queued_at is not None:
                self._awakened += 1
                self._queue_seconds = now - self._queued_at
            else:
                self._queue_seconds = 0.0
            self._queued_at = None
            self._event.clear()
            self._active_at = now
            self._retrying = False

    def finish(self, *, retrying=False):
        with self._lock:
            self._completed += 1
            self._last_poll_seconds = time.monotonic() - self._active_at
            self._active_at = None
            self._retrying = retrying

    def snapshot(self):
        with self._lock:
            now = time.monotonic()
            return {
                "stage": "readiness_scheduling",
                "status": (
                    "retrying"
                    if self._retrying
                    else "active"
                    if self._active_at is not None
                    else "queued"
                    if self._queued_at is not None
                    else "waiting"
                ),
                "hints_received": self._hints,
                "awakened_polls": self._awakened,
                "completed": self._completed,
                "total": None,
                "unit": "serial_owner_polls",
                "queued": self._queued_at is not None,
                "queue_wait_seconds": round(
                    now - self._queued_at if self._queued_at is not None else self._queue_seconds,
                    3,
                ),
                "elapsed_seconds": round(now - self._started_at, 3),
                "active_seconds": round(now - self._active_at, 3)
                if self._active_at is not None
                else None,
                "last_poll_seconds": round(self._last_poll_seconds, 3),
                "eta_seconds": None,
                "eta_scope": "next_serial_owner_scheduling_boundary",
                "eta_basis": "active_work_and_existing_fairness_rotation",
                "stalled_or_retrying": self._retrying,
            }

    async def wait(self, stop, seconds, *, retrying=False):
        # Contention keeps the existing retry delay. A hint remains queued for
        # that retry; a stream of hints cannot turn a locked store into a spin.
        tasks = [asyncio.create_task(stop.wait())]
        if not retrying:
            tasks.append(asyncio.create_task(self._event.wait()))
        try:
            await asyncio.wait(tasks, timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def close(self):
        with self._lock:
            self._closed = True


class CohortReadinessWakes:
    """Broadcast to local owners only; startup and polling recover lost hints."""

    def __init__(self):
        self._lock = Lock()
        self._owners = {}

    @contextmanager
    def subscribe(self, component):
        wake = ReadinessWake()
        with self._lock:
            self._owners.setdefault(component, set()).add(wake)
        try:
            yield wake
        finally:
            with self._lock:
                self._owners[component].remove(wake)
                if not self._owners[component]:
                    del self._owners[component]
            wake.close()

    def notify(self, component):
        with self._lock:
            for wake in self._owners.get(component, ()):
                wake.notify()
