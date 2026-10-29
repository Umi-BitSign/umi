"""Measured work diagnostics, never a checkpoint or certification authority."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import math
import os
import re
import time
from collections import deque
from collections.abc import Awaitable, Iterator, Sequence
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from functools import wraps
from itertools import count
from threading import RLock
from typing import TypeVar

from .competition_cohort_public_progress import (
    EXECUTION_JOB_SCOPE,
    PUBLIC_COHORT_PROGRESS,
    PUBLIC_COHORT_SCOPE,
)
from .competition_forecast import ForecastAttempt, ForecastCapacityRequired

_LOG = logging.getLogger("umi.competition.progress")
_IDS = count(1)
_CONTEXT: ContextVar[dict[str, object] | None] = ContextVar(
    "competition_work_context", default=None
)
_T = TypeVar("_T")
_HEARTBEAT_SECONDS = 30
_CANCELLATION: ContextVar[object | None] = ContextVar("competition_read_cancellation", default=None)
_ACTIVE_METERS = ContextVar("competition_active_work_meters", default=None)


@contextmanager
def work_heartbeats():
    """One async timer observes its owned threads; it never cancels their work."""
    if _ACTIVE_METERS.get() is not None:
        yield
        return
    loop = asyncio.get_running_loop()
    active = (RLock(), set())
    token = _ACTIVE_METERS.set(active)
    timer = None

    def heartbeat():
        nonlocal timer
        with active[0]:
            meters = tuple(active[1])
        for meter in meters:
            if not meter.closed:
                meter.emit("running")
        timer = loop.call_later(_HEARTBEAT_SECONDS, heartbeat)

    try:
        timer = loop.call_later(_HEARTBEAT_SECONDS, heartbeat)
        yield
    finally:
        if timer is not None:
            timer.cancel()
        _ACTIVE_METERS.reset(token)


@contextmanager
def cancellable_work(event):
    """Select cooperative read boundaries; atomic writes still drain to completion."""
    token = _CANCELLATION.set(event)
    try:
        yield
    finally:
        _CANCELLATION.reset(token)


def check_work_cancelled():
    event = _CANCELLATION.get()
    if event is not None and event.is_set():
        raise asyncio.CancelledError("owned read work cancelled at a checkpoint")


def _name(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[a-z][a-z0-9_]{0," + str(maximum) + "}", value) is not None
    )


def _cohort(value: object) -> str | None:
    return value if type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) else None


class WorkProgress:
    """Count completed units; forecast this substage from this attempt's rate.

    Every instance gets a new identity. Earlier attempts and nested substage
    percentages are never added together. An estimate assumes the remaining
    units have similar cost; it does not include later stages or unknown waits.
    Invalid diagnostic accounting is reported without changing native results.
    """

    def __init__(
        self,
        stage: str,
        total: int,
        *,
        unit: str,
        cohort: str | None = None,
        estimate: bool = True,
        planning_range_seconds: tuple[float, float] | None = None,
        planning_basis: str | None = None,
    ):
        if planning_range_seconds is not None and (
            len(planning_range_seconds) != 2
            or any(
                type(value) not in (int, float) or not math.isfinite(value)
                for value in planning_range_seconds
            )
            or not 0 <= planning_range_seconds[0] <= planning_range_seconds[1]
            or not planning_basis
        ):
            raise ValueError("work planning range requires finite ordered bounds and basis")
        self.enabled = _name(stage, 79) and _name(unit, 39) and type(total) is int and total >= 0
        self.stage, self.total, self.unit, self.cohort = stage, total, unit, _cohort(cohort)
        self.estimate = estimate is True
        self.planning_range_seconds = planning_range_seconds
        self.planning_basis = planning_basis
        self.identity = next(_IDS)
        self.job_sha256 = EXECUTION_JOB_SCOPE.get()
        self.completed = 0
        self.started = time.monotonic()
        self.last_completed = self.started
        self.durations = deque(maxlen=5)
        self.last_emitted = self.started
        self.context = dict(_CONTEXT.get() or {})
        self.forecast = None
        self.forecast_error = None
        try:
            self.forecast = ForecastAttempt.current(stage, unit, self.context)
        except Exception:
            self.forecast_error = "repair_required"
        self.closed = False
        self.public_scope_token = None
        self.active_meters = _ACTIVE_METERS.get()
        if self.active_meters is not None:
            with self.active_meters[0]:
                self.active_meters[1].add(self)
        self.emit("started")

    def __enter__(self):
        cohort = self.cohort or _cohort(self.context.get("cohort_sha256"))
        if cohort is not None:
            self.public_scope_token = PUBLIC_COHORT_SCOPE.set(cohort)
        return self

    def __exit__(self, exception_type, exception, traceback):
        try:
            if exception_type is None:
                self.finish()
            else:
                self.interrupt()
        finally:
            if self.public_scope_token is not None:
                PUBLIC_COHORT_SCOPE.reset(self.public_scope_token)
        return False

    def emit(self, state: str) -> None:
        if not self.enabled:
            return
        # Formatting and sink failures are diagnostic failures, not protocol failures.
        with suppress(Exception):
            now = time.monotonic()
            elapsed = max(0.0, now - self.started)
            percent = 100.0 * self.completed / self.total if self.total else 0.0
            # Counted units alone do not establish successful scope completion.
            percent = 100.0 if state == "completed" else min(percent, 99.9)
            eta = None
            samples = [value for value in self.durations if value >= 1] or list(self.durations)
            mean = sum(samples) / len(samples) if samples else None
            stalled = mean is not None and now - self.last_completed > max(30, 3 * mean)
            if state == "completed":
                eta = 0.0
            elif (
                self.estimate
                and state == "running"
                and 0 < self.completed < self.total
                and elapsed >= 1
                and mean is not None
                and not stalled
            ):
                eta = max(0.0, mean * (self.total - self.completed))
            planning = None
            if (
                self.planning_range_seconds is not None
                and eta is None
                and state not in {"interrupted", "accounting_mismatch"}
            ):
                low, high = self.planning_range_seconds
                if elapsed > high:
                    stalled = True
                else:
                    planning = [
                        round(max(0.0, low - elapsed), 1),
                        round(max(0.0, high - elapsed), 1),
                    ]
            body = {
                "schema": "umi-competition-work-progress/1",
                "pid": os.getpid(),
                "observed_unix_ms": time.time_ns() // 1_000_000,
                **self.context,
                "work_id": self.identity,
                "job_sha256": self.job_sha256,
                "stage": self.stage,
                "state": state,
                "cohort_sha256": self.cohort or self.context.get("cohort_sha256"),
                "completed": self.completed,
                "total": self.total,
                "unit": self.unit,
                "percent": round(percent, 2),
                "elapsed_seconds": round(elapsed, 3),
                "eta_seconds": None if eta is None else round(eta, 1),
                **({"planning_eta_seconds": planning} if planning is not None else {}),
                "eta_basis": (
                    "completed"
                    if state == "completed"
                    else "planning_range_exceeded_retrying"
                    if self.planning_range_seconds is not None and stalled
                    else self.planning_basis
                    if planning is not None
                    else "unestimated_scope"
                    if not self.estimate
                    else "recent_active_item_rate"
                    if eta is not None
                    else "stalled_rate_invalidated"
                    if stalled
                    else "insufficient_samples"
                ),
                "eta_samples": len(samples),
                "eta_window_completed": len(self.durations),
                "eta_ignored_fast_samples": len(self.durations) - len(samples),
                "eta_raw_sample_seconds": list(self.durations),
                "eta_assumption": (
                    "remaining_units_match_recent_active_cost" if self.estimate else None
                ),
                **(
                    {
                        "forecast_classification": "planning_scenario",
                        "forecast_finish_range_seconds": planning,
                    }
                    if planning is not None
                    else {}
                ),
                "stalled": stalled,
                "scope": "current_attempt_substage",
                "certification_authority": False,
            }
            if self.forecast is not None:
                try:
                    body["forecast_accounting"] = self.forecast.observe(body)
                except ForecastCapacityRequired:
                    self.forecast_error = "capacity_required"
                except Exception as error:
                    self.forecast.ledger.note_failure("consumer_observation_failed", error=error)
                    # This ledger cannot change native validation, cancellation,
                    # transaction recovery, signed evidence or successful results.
                    self.forecast_error = "repair_required"
            if self.forecast_error is not None:
                body["forecast_accounting"] = {
                    "status": self.forecast_error,
                    "eta_seconds": None,
                    "eta_basis": (
                        "increase_forecast_accounting_budget_preserving_existing_records"
                        if self.forecast_error == "capacity_required"
                        else "restore_retained_forecast_accounting"
                    ),
                    "certification_authority": False,
                }
            PUBLIC_COHORT_PROGRESS.record("work", body)
            _LOG.info(json.dumps(body, separators=(",", ":")))
            self.last_emitted = now

    def advance(self) -> None:
        if self.closed or not self.enabled:
            return
        if self.completed >= self.total:
            self.closed = True
            self._release_heartbeat()
            self.emit("accounting_mismatch")
            return
        self.completed += 1
        now = time.monotonic()
        self.durations.append(max(0.0, now - self.last_completed))
        self.last_completed = now
        if self.completed <= 2 or time.monotonic() - self.last_emitted >= 10:
            self.emit("running")

    def finish(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._release_heartbeat()
        self.emit("completed" if self.completed == self.total else "accounting_mismatch")

    def interrupt(self) -> None:
        if not self.closed:
            self.closed = True
            self._release_heartbeat()
            self.emit("interrupted")

    def _release_heartbeat(self):
        if self.active_meters is not None:
            with self.active_meters[0]:
                self.active_meters[1].discard(self)


def progress_items(
    items: Sequence[_T], *, stage: str, unit: str, cohort: str | None = None
) -> Iterator[_T]:
    """Count an item only when its consumer resumes after successful processing."""
    progress = WorkProgress(stage, len(items), unit=unit, cohort=cohort)
    try:
        for item in items:
            check_work_cancelled()
            yield item
            progress.advance()
        progress.finish()
    finally:
        progress.interrupt()


def work_operation(name: str):
    """Attribute existing counters to one synchronous operation, without estimates.

    Nested calls preserve review/read context and identify their immediate parent.
    No arguments or results are retained, and this adds no completion checkpoint.
    """

    def decorate(operation):
        if (
            inspect.iscoroutinefunction(operation)
            or inspect.isgeneratorfunction(operation)
            or inspect.isasyncgenfunction(operation)
        ):
            raise TypeError("work_operation requires an eager synchronous function")

        @wraps(operation)
        def run(*args, **kwargs):
            parent = _CONTEXT.get() or {}
            token = _CONTEXT.set(
                {
                    **parent,
                    "operation_name": name if _name(name, 79) else "unknown",
                    "operation_id": next(_IDS),
                    "parent_operation_id": parent.get("operation_id"),
                }
            )
            try:
                return operation(*args, **kwargs)
            finally:
                _CONTEXT.reset(token)

        return run

    return decorate


_READS: ContextVar[WorkProgress | None] = ContextVar("competition_review_reads", default=None)


@contextmanager
def review_scope(kind: str, cohort: str | None, *, reads: int):
    """Identify one vote's read cycles without retaining its protocol objects."""
    token = _CONTEXT.set(
        {
            "review_id": next(_IDS),
            "review_kind": kind if _name(kind, 79) else "unknown",
            "cohort_sha256": _cohort(cohort),
            "parent_review_id": (_CONTEXT.get() or {}).get("review_id"),
        }
    )
    meter = WorkProgress("closure_read_cycles", reads, unit="replay_cycles") if reads else None
    read_token = _READS.set(meter)
    try:
        yield
        if meter is not None:
            meter.finish()
    finally:
        if meter is not None:
            meter.interrupt()
        _READS.reset(read_token)
        _CONTEXT.reset(token)


def review_read(operation):
    """Label child work by read number, counting only a successful full replay."""

    @wraps(operation)
    async def run(*args, **kwargs):
        meter = _READS.get()
        token = _CONTEXT.set(
            {
                **(_CONTEXT.get() or {}),
                "read_number": None if meter is None else meter.completed + 1,
                "reads_total": None if meter is None else meter.total,
            }
        )
        try:
            result = await operation(*args, **kwargs)
            if meter is not None:
                meter.advance()
            return result
        finally:
            _CONTEXT.reset(token)

    return run


def review_operation(*, reads: int):
    """Give a known remote-review operation its own exact read-cycle scope."""

    def decorate(operation):
        @wraps(operation)
        async def run(owner, *args, **kwargs):
            cohort = getattr(
                getattr(getattr(owner, "roster", None), "round", None), "cohort_sha256", None
            )
            with review_scope(operation.__name__, cohort, reads=reads):
                return await operation(owner, *args, **kwargs)

        return run

    return decorate


async def await_progress(
    work: Awaitable[_T],
    *,
    stage: str,
    cohort: str | None = None,
    planning_range_seconds: tuple[float, float] | None = None,
    planning_basis: str | None = None,
) -> _T:
    """Report an explicit wait, retaining the awaited operation's ownership.

    A cancellable loop timer emits diagnostics; it never owns or cancels work
    and adds no task or cleanup await that could alter native cancellation.
    """
    meter = WorkProgress(
        stage,
        1,
        unit="responses",
        cohort=cohort,
        planning_range_seconds=planning_range_seconds,
        planning_basis=planning_basis,
    )
    public_scope = meter.cohort or _cohort(meter.context.get("cohort_sha256"))
    public_token = PUBLIC_COHORT_SCOPE.set(public_scope) if public_scope is not None else None
    loop = asyncio.get_running_loop()
    timer = None

    def heartbeat():
        nonlocal timer
        meter.emit("waiting")
        with suppress(Exception):
            timer = loop.call_later(_HEARTBEAT_SECONDS, heartbeat)

    try:
        with suppress(Exception):
            timer = loop.call_later(_HEARTBEAT_SECONDS, heartbeat)
        result = await work
        meter.advance()
        meter.finish()
        return result
    finally:
        if timer is not None:
            timer.cancel()
        meter.interrupt()
        if public_token is not None:
            PUBLIC_COHORT_SCOPE.reset(public_token)
