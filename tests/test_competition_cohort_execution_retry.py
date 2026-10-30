"""Bounded resident recovery using native journals and synthetic transport faults."""

import asyncio
import json
import logging
import sqlite3
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_cohort_execution_retry as retry
from umi.competition_cohort_execution_journal import step_count

from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import harness as harness
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_executor import scenario as scenario

BUSY = getattr(sqlite3, "SQLITE_BUSY", 5)
FULL = getattr(sqlite3, "SQLITE_FULL", 13)
IOERR = getattr(sqlite3, "SQLITE_IOERR", 10)


def busy(code=BUSY):
    error = sqlite3.OperationalError("synthetic SQLite failure")
    error.sqlite_errorcode = code
    return error


def unavailable():
    error = OSError("phase review transport unavailable; retry unchanged")
    error.__cause__ = httpx.ConnectError("synthetic owner interruption")
    return error


@pytest.fixture
def clock(monkeypatch):
    value = SimpleNamespace(now=0.0, sleeps=[])

    async def sleep(delay):
        value.sleeps.append(delay)
        value.now += delay
        await asyncio.sleep(0)

    monkeypatch.setattr(
        retry,
        "asyncio",
        SimpleNamespace(
            get_running_loop=lambda: SimpleNamespace(time=lambda: value.now), sleep=sleep
        ),
    )
    return value


@pytest.mark.parametrize("history", [False, True])
async def test_resident_transient_budget_is_counted_and_exhausts(clock, caplog, history):
    caplog.set_level(logging.WARNING, logger="umi.competition.progress")
    error = unavailable() if history else busy()
    calls = 0

    async def operation():
        nonlocal calls
        calls += 1
        raise error

    with (
        retry.resident_execution_retries("ab" * 32, 2),
        pytest.raises(type(error)) as raised,
    ):
        await retry.retry_resident_operation(operation, history=history)
    assert raised.value is error
    assert calls == 3 and clock.sleeps == [1, 1]
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert [event["retry_count"] for event in events] == [1, 2, 3]
    assert events[-1]["elapsed_seconds"] == 2
    assert events[-1]["retry_remaining_seconds"] == 0
    assert events[-1]["eta_basis"] == "bounded_retry_allowance_not_completion_prediction"
    assert all(event["certification_authority"] is False for event in events)


async def test_healthy_inference_does_not_consume_later_recovery_allowance(clock):
    attempts = 0

    async def operation():
        nonlocal attempts
        attempts += 1
        if attempts % 2:
            raise unavailable()
        return attempts

    with retry.resident_execution_retries("ab" * 32, 2):
        assert await retry.retry_resident_operation(operation, history=True) == 2
        clock.now += 10000  # Successful inference is not idle recovery time.
        assert await retry.retry_resident_operation(operation, history=True) == 4
    assert clock.sleeps == [1, 1]


@pytest.mark.parametrize(
    "history,error",
    [
        (True, OSError("authority changed")),
        (True, ValueError("owner signature invalid")),
        (True, busy()),
        (False, unavailable()),
        (False, busy(FULL)),
        (False, busy(IOERR)),
        (False, RuntimeError("immutable binding changed")),
    ],
)
async def test_unclassified_failures_propagate_unchanged(clock, history, error):
    async def operation():
        raise error

    with (
        retry.resident_execution_retries("ab" * 32, 120),
        pytest.raises(type(error)) as raised,
    ):
        await retry.retry_resident_operation(operation, history=history)
    assert raised.value is error and not clock.sleeps


async def test_nonresident_operation_keeps_existing_single_attempt(clock):
    async def operation():
        raise unavailable()

    with pytest.raises(OSError):
        await retry.retry_resident_operation(operation, history=True)
    assert not clock.sleeps


async def test_retry_allowance_does_not_cancel_an_owned_operation(clock):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def operation():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise unavailable()
        entered.set()
        await release.wait()
        return "completed"

    with retry.resident_execution_retries("ab" * 32, 2):
        task = asyncio.create_task(retry.retry_resident_operation(operation, history=True))
        await asyncio.wait_for(entered.wait(), 2)
        clock.now += 1000
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        assert await task == "completed"


@pytest.fixture
async def resident(execution):
    e = execution
    if e.job.mode != "paired_model":
        pytest.skip("resident model recovery applies to the public model track")
    scope = SimpleNamespace(entered=0, active=False, released=0)

    @asynccontextmanager
    async def execution_scope(order):
        scope.entered += 1
        scope.active = True
        try:
            yield True
        finally:
            scope.active = False
            scope.released += 1

    e.port.execution_scope = execution_scope
    worker = e.worker()
    return SimpleNamespace(e=e, worker=worker, executor=worker.executor, scope=scope)


async def test_history_recovers_after_sandbox_result_without_inference_repeat(
    resident, clock, monkeypatch
):
    h = resident
    original = h.executor.history
    failures = 0

    async def history(cohort):
        nonlocal failures
        if h.e.calls and failures == 0:
            attempt = h.executor.journal.head(h.e.job, 0)
            assert h.executor.journal.result(h.e.job, attempt) is not None
            assert h.scope.active
            failures += 1
            raise unavailable()
        return await original(cohort)

    monkeypatch.setattr(h.executor, "history", history)
    evidence = await h.executor.advance_batch(h.e.assignment)
    assert evidence is not None and failures == 1
    assert len(h.e.calls) == step_count(h.e.job) and not h.e.stops
    assert h.scope.entered == h.scope.released == 1
    assert clock.sleeps == [1]


async def test_result_persistence_retries_exact_result_inside_resident_scope(
    resident, clock, monkeypatch
):
    h = resident
    original = h.executor.journal.observe
    observations = []

    def observe(job, attempt, result):
        assert h.scope.active
        observations.append((attempt, result))
        if len(observations) == 1:
            raise busy()
        return original(job, attempt, result)

    monkeypatch.setattr(h.executor.journal, "observe", observe)
    evidence = await h.executor.advance_batch(h.e.assignment)
    assert evidence is not None
    assert observations[0] == observations[1]
    assert len(h.e.calls) == step_count(h.e.job) and not h.e.stops
    assert h.scope.entered == h.scope.released == 1


async def test_exhausted_history_releases_residency_and_returns_pending(
    resident, clock, monkeypatch
):
    h = resident
    monkeypatch.setattr(retry, "MAX_RESIDENT_RETRY_SECONDS", 2)

    async def history(cohort):
        raise unavailable()

    monkeypatch.setattr(h.executor, "history", history)
    slot, state, kind = await h.worker._one(h.e.r.slot)
    assert (slot, state, kind) == (h.e.r.slot, "pending", "OSError")
    assert not h.e.calls and not h.scope.active
    assert h.scope.entered == h.scope.released == 1
    assert clock.sleeps == [1, 1]
    # The returned task is terminal; ordinary rolling scheduling can use its lane.
    assert not h.worker.capacity.locked()
    with h.executor.journal.locked(h.e.r.slot):
        pass


@pytest.mark.parametrize("method", ["begin", "finish"])
async def test_execution_decision_contention_keeps_existing_pending_path(
    resident, clock, monkeypatch, method
):
    h = resident
    calls = 0

    def failed(*args):
        nonlocal calls
        calls += 1
        raise busy()

    monkeypatch.setattr(h.executor.journal, method, failed)
    _, state, kind = await h.worker._one(h.e.r.slot)
    assert (state, kind) == ("pending", "OperationalError")
    assert calls == 1 and not clock.sleeps and not h.scope.active
    if method == "finish":
        assert len(h.e.calls) == 1
        attempt = h.executor.journal.head(h.e.job, 0)
        assert h.executor.journal.result(h.e.job, attempt) is not None


async def test_cancellation_during_history_retry_releases_scope_and_reuses_result(
    resident, clock, monkeypatch
):
    h = resident
    original = h.executor.history
    entered = asyncio.Event()

    async def wait(delay):
        entered.set()
        await asyncio.Event().wait()

    async def history(cohort):
        if h.e.calls:
            raise unavailable()
        return await original(cohort)

    monkeypatch.setattr(retry.asyncio, "sleep", wait)
    monkeypatch.setattr(h.executor, "history", history)
    task = asyncio.create_task(h.executor.advance_batch(h.e.assignment))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not h.scope.active and len(h.e.calls) == 1
    attempt = h.executor.journal.head(h.e.job, 0)
    assert h.executor.journal.result(h.e.job, attempt) is not None
    monkeypatch.setattr(h.executor, "history", original)
    assert await h.executor.advance_batch(h.e.assignment) is not None
    assert len(h.e.calls) == step_count(h.e.job) and not h.e.stops


async def test_cancellation_drains_contended_result_before_releasing_owner(
    resident, clock, monkeypatch
):
    h = resident
    original = h.executor.journal.observe
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def wait(delay):
        entered.set()
        await release.wait()

    def observe(job, attempt, result):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise busy()
        return original(job, attempt, result)

    monkeypatch.setattr(retry.asyncio, "sleep", wait)
    monkeypatch.setattr(h.executor.journal, "observe", observe)
    task = asyncio.create_task(h.executor.advance_batch(h.e.assignment))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and h.scope.active
    with pytest.raises(BlockingIOError):
        await h.e.executor().advance(h.e.assignment)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not h.scope.active and len(h.e.calls) == 1
    attempt = h.executor.journal.head(h.e.job, 0)
    assert h.executor.journal.result(h.e.job, attempt) is not None
    assert await h.executor.advance_batch(h.e.assignment) is not None
    assert len(h.e.calls) == step_count(h.e.job) and not h.e.stops
