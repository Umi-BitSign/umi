"""Retry failed transport/result retention while an existing model stays resident.

This never repeats inference, grants authority, or retries an execution decision.
Each failed operation has a short recovery allowance within the existing read
budget; exhaustion returns its original failure to the ordinary scheduler.
"""

import asyncio
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

import httpx

from .competition_progress import report_execution_retry
from .sqlite_contention import is_sqlite_contention


@dataclass
class _ResidentRetry:
    slot: str
    timeout: float


_RESIDENT_RETRY = ContextVar("cohort_resident_execution_retry", default=None)
# Brief owner restarts can take over a minute. Limit idle residency to two
# minutes rather than the entire (potentially hour-long) read allowance. This
# bounds retry scheduling only; it never cancels an in-flight owned operation.
MAX_RESIDENT_RETRY_SECONDS = 120.0


@contextmanager
def resident_execution_retries(slot, timeout):
    token = _RESIDENT_RETRY.set(_ResidentRetry(slot, min(timeout, MAX_RESIDENT_RETRY_SECONDS)))
    try:
        yield
    finally:
        _RESIDENT_RETRY.reset(token)


async def retry_resident_operation(operation, *, history=False):
    """Retry only a failed fresh history fetch or idempotent result persistence.

    No timeout cancels an owned operation. Cancellation at a retry wait propagates;
    the caller retains responsibility for draining its threads and sandbox result.
    Healthy inference between operations consumes none of this recovery allowance.
    """
    state = _RESIDENT_RETRY.get()
    if state is None:
        return await operation()
    delay = 1.0
    started = None
    failures = 0
    while True:
        try:
            return await operation()
        except (OSError, sqlite3.OperationalError) as error:
            retryable = (
                isinstance(error, OSError)
                and isinstance(error.__cause__, (httpx.NetworkError, httpx.TimeoutException))
                if history
                else isinstance(error, sqlite3.OperationalError) and is_sqlite_contention(error)
            )
            if not retryable:
                raise
            loop = asyncio.get_running_loop()
            if started is None:
                started = loop.time()
            elapsed = loop.time() - started
            remaining = max(0.0, state.timeout - elapsed)
            failures += 1
            report_execution_retry(
                slot=state.slot,
                error=error,
                retry_count=failures,
                retry_elapsed_seconds=elapsed,
                retry_remaining_seconds=remaining,
            )
            if remaining <= 0:
                raise
            await asyncio.sleep(min(delay, remaining))
            delay = min(delay * 2, 5.0)
