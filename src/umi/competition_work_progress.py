"""Measured work diagnostics, never a checkpoint or certification authority."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections.abc import Awaitable, Iterator, Sequence
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from functools import wraps
from itertools import count
from typing import TypeVar

_LOG = logging.getLogger("umi.competition.progress")
_IDS = count(1)
_CONTEXT: ContextVar[dict[str, object] | None] = ContextVar(
    "competition_work_context", default=None
)
_T = TypeVar("_T")
_HEARTBEAT_SECONDS = 30


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
        self, stage: str, total: int, *, unit: str, cohort: str | None = None, estimate: bool = True
    ):
        self.enabled = _name(stage, 79) and _name(unit, 39) and type(total) is int and total >= 0
        self.stage, self.total, self.unit, self.cohort = stage, total, unit, _cohort(cohort)
        self.estimate = estimate is True
        self.identity = next(_IDS)
        self.completed = 0
        self.started = time.monotonic()
        self.last_emitted = self.started
        self.context = dict(_CONTEXT.get() or {})
        self.closed = False
        self.emit("started")

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        if exception_type is None:
            self.finish()
        else:
            self.interrupt()
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
            if state == "completed":
                eta = 0.0
            elif (
                self.estimate
                and state == "running"
                and 0 < self.completed < self.total
                and elapsed >= 1
            ):
                eta = max(0.0, elapsed * (self.total - self.completed) / self.completed)
            body = {
                "schema": "umi-competition-work-progress/1",
                "pid": os.getpid(),
                "observed_unix_ms": time.time_ns() // 1_000_000,
                **self.context,
                "work_id": self.identity,
                "stage": self.stage,
                "state": state,
                "cohort_sha256": self.cohort or self.context.get("cohort_sha256"),
                "completed": self.completed,
                "total": self.total,
                "unit": self.unit,
                "percent": round(percent, 2),
                "elapsed_seconds": round(elapsed, 3),
                "eta_seconds": None if eta is None else round(eta, 1),
                "eta_basis": (
                    "completed"
                    if state == "completed"
                    else "unestimated_scope"
                    if not self.estimate
                    else "completed_work_rate"
                    if eta is not None
                    else "insufficient_samples"
                ),
                "eta_samples": self.completed,
                "eta_assumption": "remaining_units_have_similar_cost" if self.estimate else None,
                "scope": "current_attempt_substage",
                "certification_authority": False,
            }
            _LOG.info(json.dumps(body, separators=(",", ":")))
            self.last_emitted = now

    def advance(self) -> None:
        if self.closed or not self.enabled:
            return
        if self.completed >= self.total:
            self.closed = True
            self.emit("accounting_mismatch")
            return
        self.completed += 1
        if self.completed <= 2 or time.monotonic() - self.last_emitted >= 10:
            self.emit("running")

    def finish(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.emit("completed" if self.completed == self.total else "accounting_mismatch")

    def interrupt(self) -> None:
        if not self.closed:
            self.closed = True
            self.emit("interrupted")


def progress_items(
    items: Sequence[_T], *, stage: str, unit: str, cohort: str | None = None
) -> Iterator[_T]:
    """Count an item only when its consumer resumes after successful processing."""
    progress = WorkProgress(stage, len(items), unit=unit, cohort=cohort)
    try:
        for item in items:
            yield item
            progress.advance()
        progress.finish()
    finally:
        progress.interrupt()


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


async def await_progress(work: Awaitable[_T], *, stage: str, cohort: str | None = None) -> _T:
    """Report an explicit wait, retaining the awaited operation's ownership.

    A cancellable loop timer emits diagnostics; it never owns or cancels work
    and adds no task or cleanup await that could alter native cancellation.
    """
    meter = WorkProgress(stage, 1, unit="responses", cohort=cohort)
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
