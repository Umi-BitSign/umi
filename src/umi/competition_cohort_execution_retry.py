"""Bound transient recovery while an existing model stays resident.

Transport/result retention never repeats inference. External timing pressure can
retry the ordinary fresh-attempt path, preserving its authority and cleanup checks.
Each allowance fits within the existing read budget; exhaustion returns the
failure to ordinary scheduling without accepting unusable timing.
"""

import asyncio
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

import httpx

from .competition_cpu_timing import CpuTimingInfrastructureError
from .competition_progress import report_execution_retry
from .competition_timing_admission import TimingAdmissionTimeout
from .sqlite_contention import is_sqlite_contention


@dataclass
class _ResidentRetry:
    slot: str
    timeout: float
    read_timeout: float


_RESIDENT_RETRY = ContextVar("cohort_resident_execution_retry", default=None)
# Default transient recovery is two minutes. Timing retries may need an observed
# sibling step plus headroom to drain the queue. Their measured allowance remains
# bounded by the configured read budget and never cancels owned execution.
MAX_RESIDENT_RETRY_SECONDS = 120.0


class ResidentTimingPressure(CpuTimingInfrastructureError):
    """External pressure rejected this invocation, before result retention."""

    def __init__(self):
        super().__init__("cpu_condition_external_pressure")


@contextmanager
def resident_execution_retries(slot, timeout):
    token = _RESIDENT_RETRY.set(
        _ResidentRetry(slot, min(timeout, MAX_RESIDENT_RETRY_SECONDS), timeout)
    )
    try:
        yield
    finally:
        _RESIDENT_RETRY.reset(token)


async def retry_resident_timing(operation, *, admission=None):
    """Keep residency for a bounded retry of rejected external-pressure timing.

    The operation must be ordinary executor.advance, not sandbox.invoke: every
    retry reconciles the old attempt, reads fresh authority and creates a new
    native attempt. No failed result or timing evidence is reused. This never
    cancels an owned invocation when its recovery allowance expires.
    """
    state = _RESIDENT_RETRY.get()
    if state is None:
        return await operation()
    started = None
    failures = 0
    last_error = None
    allowance = state.timeout
    while True:
        try:
            if admission is None:
                return await operation()
            # Ordinary queued work has not failed. Preserve its existing read
            # allowance while a rejected sibling gets its bounded recovery turn.
            remaining = (
                state.read_timeout
                if started is None
                else max(0.0, allowance - (asyncio.get_running_loop().time() - started))
            )
            async with admission.attempt(quiet=failures > 0, timeout=remaining):
                return await operation()
        except TimingAdmissionTimeout:
            # The rejected attempt remains the failure authority. Waiting
            # for siblings never fabricates another failed native attempt.
            if last_error is not None:
                raise last_error from last_error.__cause__
            raise
        except ResidentTimingPressure as error:
            last_error = error
            now = asyncio.get_running_loop().time()
            if started is None:
                started = now
                if admission is not None:
                    allowance = admission.retry_allowance(state.timeout, state.read_timeout)
            elapsed = now - started
            remaining = max(0.0, allowance - elapsed)
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
            # Avoid immediate retry bursts, while bounding idle residency and
            # retaining the ordinary per-invocation timeout on the next attempt.
            await asyncio.sleep(min(5.0 * 2 ** min(failures - 1, 3), 30.0, remaining))


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
