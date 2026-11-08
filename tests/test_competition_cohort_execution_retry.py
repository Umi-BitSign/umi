"""Bounded resident recovery using native journals and synthetic transport faults."""

import asyncio
import json
import logging
import sqlite3
from contextlib import asynccontextmanager, nullcontext
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


async def test_authority_preparation_does_not_occupy_a_timing_turn(resident, monkeypatch):
    h = resident
    original = h.executor.current
    entered, release = asyncio.Event(), asyncio.Event()

    async def current(assignment):
        if h.scope.active and not h.e.calls:
            entered.set()
            await release.wait()
        return await original(assignment)

    monkeypatch.setattr(h.executor, "current", current)
    task = asyncio.create_task(h.executor.advance_batch(h.e.assignment))
    try:
        await asyncio.wait_for(entered.wait(), 10)
        assert h.executor.timing_admission.active == 0
        async with h.executor.timing_admission.attempt(quiet=True, timeout=0):
            assert not h.e.calls
        release.set()
        assert await asyncio.wait_for(task, 10) is not None
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert h.scope.entered == h.scope.released == 1


@pytest.mark.parametrize("cancel", [False, True])
async def test_deferred_queue_has_no_attempt_and_refreshes_authority(resident, monkeypatch, cancel):
    h = resident
    original = h.executor.current
    queued = asyncio.Event()
    revoked = False

    async def current(assignment):
        if revoked:
            raise ValueError("authority changed while waiting for timing")
        return await original(assignment)

    monkeypatch.setattr(h.executor, "current", current)
    gate = h.executor.timing_admission
    acquire = gate._acquire

    async def acquire_observed(quiet, timeout):
        if not quiet and gate.quiet:
            queued.set()
        return await acquire(quiet, timeout)

    monkeypatch.setattr(gate, "_acquire", acquire_observed)
    async with gate.attempt(quiet=True, timeout=0):
        task = asyncio.create_task(h.executor.advance_batch(h.e.assignment))
        try:
            await asyncio.wait_for(queued.wait(), 10)
            # A blocked timing waiter must not create a native attempt.
            assert h.executor.journal.head(h.e.job, 0) is None
            assert not h.e.calls and gate.active == 1
            revoked = True
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    if not cancel:
        with pytest.raises(ValueError, match="authority changed while waiting"):
            await asyncio.wait_for(task, 10)
    assert not h.e.calls and not h.scope.active and gate.active == 0
    assert h.executor.journal.head(h.e.job, 0) is None


@pytest.mark.parametrize("occupied", [False, True])
async def test_preparation_spends_failed_retry_allowance_before_deferred_admission(clock, occupied):
    from umi.competition_timing_admission import TimingAttemptAdmission

    gate = TimingAttemptAdmission(clock=lambda: clock.now)
    error = retry.ResidentTimingPressure()
    calls = 0

    async def operation():
        nonlocal calls
        calls += 1
        if calls > 1:
            clock.now += 100
        async with retry.resident_timing_turn():
            raise error

    # Preparation consumes the allowance. Even an immediately available turn
    # cannot start a new invocation after the failed retry's allowance expires.
    async with gate.attempt(quiet=False, timeout=0) if occupied else nullcontext():
        with retry.resident_execution_retries("ab" * 32, 12), pytest.raises(type(error)) as raised:
            await retry.retry_resident_timing(operation, admission=gate, defer_admission=True)
        assert raised.value is error and gate.active == int(occupied) and not gate.quiet
    assert calls == 2 and gate.active == 0
    assert clock.sleeps == [5]


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


@pytest.mark.parametrize("method", ["finish"])
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


@pytest.mark.parametrize("failure_point", ["reservation", "attempt_write"])
async def test_begin_contention_retains_model_and_exact_native_reservation(
    resident, clock, monkeypatch, failure_point
):
    h = resident
    journal = h.executor.journal.journal
    method = "reserve_records" if failure_point == "reservation" else "put_many"
    original = getattr(journal, method)
    failed = []

    def persist(*args, **kwargs):
        is_attempt = method == "reserve_records" or args[0][0][0] == "attempt"
        if is_attempt and not failed:
            assert h.scope.active and not h.e.calls
            failed.append(args)
            raise busy()
        if is_attempt and len(failed) == 1:
            assert args == failed[0]
            failed.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(journal, method, persist)
    evidence = await h.executor.advance_batch(h.e.assignment)
    assert evidence is not None and len(failed) == 2
    assert len(h.e.calls) == step_count(h.e.job) and not h.e.stops
    assert all(attempt.number == 1 for attempt in h.e.calls)
    assert h.scope.entered == h.scope.released == 1
    assert clock.sleeps == [1]


async def test_begin_contention_exhausts_and_releases_resident_lane(resident, clock, monkeypatch):
    h = resident
    monkeypatch.setattr(retry, "MAX_RESIDENT_RETRY_SECONDS", 2)
    calls = []

    def begin(*args):
        calls.append(args)
        raise busy()

    monkeypatch.setattr(h.executor.journal, "begin", begin)
    _, state, kind = await h.worker._one(h.e.r.slot)
    assert (state, kind) == ("pending", "OperationalError")
    assert len(calls) == 3 and all(args == calls[0] for args in calls)
    assert clock.sleeps == [1, 1] and not h.e.calls
    assert h.scope.entered == h.scope.released == 1 and not h.scope.active
    assert not h.worker.capacity.locked()


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
    assert h.executor.timing_admission.active == 0
    async with h.executor.timing_admission.attempt(quiet=True, timeout=0):
        # Another timing turn can run while this exact result is retained.
        assert h.scope.active and len(h.e.calls) == 1
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


async def test_cancellation_during_early_release_still_retains_native_result(resident, monkeypatch):
    h = resident
    gate = h.executor.timing_admission
    original = h.e.port.invoke
    entered = asyncio.Event()

    async def invoke(job, attempt):
        result = await original(job, attempt)
        await gate.condition.acquire()
        entered.set()
        return result

    monkeypatch.setattr(h.e.port, "invoke", invoke)
    task = asyncio.create_task(h.executor.advance_batch(h.e.assignment))
    await asyncio.wait_for(entered.wait(), 10)
    for _ in range(2):
        task.cancel()
        for _ in range(10):
            await asyncio.sleep(0)
    assert not task.done() and h.scope.active
    gate.condition.release()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not h.scope.active and gate.active == 0 and not gate.quiet
    assert len(h.e.calls) == 1
    assert h.executor.journal.result(h.e.job, h.e.calls[0]) is not None
    monkeypatch.setattr(h.e.port, "invoke", original)
    assert await h.executor.advance_batch(h.e.assignment) is not None
    assert len(h.e.calls) == step_count(h.e.job)


async def test_pressure_retry_has_bounded_residency(clock, caplog):
    caplog.set_level(logging.WARNING, logger="umi.competition.progress")
    error = retry.ResidentTimingPressure()
    calls = 0

    async def operation():
        nonlocal calls
        calls += 1
        raise error

    with retry.resident_execution_retries("ab" * 32, 12), pytest.raises(type(error)):
        await retry.retry_resident_timing(operation)
    assert calls == 3 and clock.sleeps == [5, 7]
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert events[-1]["retry_remaining_seconds"] == 0
    assert events[-1]["certification_authority"] is False


async def test_pressure_recovery_does_not_cancel_owned_attempt(clock):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def operation():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise retry.ResidentTimingPressure()
        entered.set()
        await release.wait()
        return "accepted"

    with retry.resident_execution_retries("ab" * 32, 10):
        task = asyncio.create_task(retry.retry_resident_timing(operation))
        await asyncio.wait_for(entered.wait(), 2)
        clock.now += 1000
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        assert await task == "accepted"


async def test_unmarked_pressure_failure_is_not_a_retry(clock):
    # A stored evidence failure outside sandbox.invoke is not new contention.
    error = retry.CpuTimingInfrastructureError("cpu_condition_external_pressure")

    async def operation():
        raise error

    with retry.resident_execution_retries("ab" * 32, 10), pytest.raises(type(error)) as raised:
        await retry.retry_resident_timing(operation)
    assert raised.value is error and not clock.sleeps


async def test_pressure_admission_expiry_does_not_fabricate_an_attempt(clock):
    error = retry.ResidentTimingPressure()
    calls = 0
    admissions = []

    class Admission:
        def retry_allowance(self, fallback, maximum):
            return fallback

        @asynccontextmanager
        async def attempt(self, *, quiet, timeout):
            admissions.append((quiet, timeout))
            if quiet:
                raise retry.TimingAdmissionTimeout("timing_admission_allowance_expired")
            yield

    async def operation():
        nonlocal calls
        calls += 1
        raise error

    with retry.resident_execution_retries("ab" * 32, 12), pytest.raises(type(error)) as raised:
        await retry.retry_resident_timing(operation, admission=Admission())
    assert raised.value is error
    assert calls == 1 and admissions == [(False, 12), (True, 7)]


async def test_pressure_retry_reconciles_and_rechecks_with_fresh_attempt(
    resident, clock, monkeypatch
):
    h = resident
    original = h.e.port.invoke
    failed = []
    quiet_attempts = []

    async def invoke(job, attempt):
        assert h.scope.active
        quiet_attempts.append(h.executor.timing_admission.quiet)
        if not failed:
            failed.append(attempt)
            h.e.calls.append(attempt)
            raise retry.CpuTimingInfrastructureError("cpu_condition_external_pressure")
        return await original(job, attempt)

    monkeypatch.setattr(h.e.port, "invoke", invoke)
    assert await h.executor.advance_batch(h.e.assignment) is not None
    assert len(h.e.calls) == step_count(h.e.job) + 1
    assert h.e.stops == failed
    assert h.e.calls[0] != h.e.calls[1]
    assert quiet_attempts[:2] == [False, True]
    assert not any(quiet_attempts[2:])
    assert h.executor.journal.result(h.e.job, failed[0]) is None
    assert h.scope.entered == h.scope.released == 1 and clock.sleeps == [5]


async def test_pressure_retry_refuses_changed_authority(resident, clock, monkeypatch):
    h = resident
    original = h.executor.current

    async def current(assignment):
        if h.e.calls:
            raise ValueError("fresh authority no longer permits the attempt")
        return await original(assignment)

    async def invoke(job, attempt):
        h.e.calls.append(attempt)
        raise retry.CpuTimingInfrastructureError("cpu_condition_external_pressure")

    monkeypatch.setattr(h.executor, "current", current)
    monkeypatch.setattr(h.e.port, "invoke", invoke)
    with pytest.raises(ValueError, match="fresh authority"):
        await h.executor.advance_batch(h.e.assignment)
    assert len(h.e.calls) == 1 and not h.scope.active
    assert h.scope.entered == h.scope.released == 1


async def test_pressure_exhaustion_releases_pair_for_other_jobs(resident, clock, monkeypatch):
    h = resident
    monkeypatch.setattr(retry, "MAX_RESIDENT_RETRY_SECONDS", 5)

    async def invoke(job, attempt):
        h.e.calls.append(attempt)
        raise retry.CpuTimingInfrastructureError("cpu_condition_external_pressure")

    monkeypatch.setattr(h.e.port, "invoke", invoke)
    _, state, kind = await h.worker._one(h.e.r.slot)
    assert (state, kind) == ("pending", "ResidentTimingPressure")
    assert len(h.e.calls) == 2 and len(h.e.stops) == 1
    assert not h.scope.active and not h.worker.capacity.locked()
    assert h.scope.entered == h.scope.released == 1


async def test_cancellation_during_pressure_wait_keeps_recoverable_attempt(
    resident, clock, monkeypatch
):
    h = resident
    entered = asyncio.Event()

    async def wait(delay):
        entered.set()
        await asyncio.Event().wait()

    async def invoke(job, attempt):
        h.e.calls.append(attempt)
        raise retry.CpuTimingInfrastructureError("cpu_condition_external_pressure")

    monkeypatch.setattr(retry.asyncio, "sleep", wait)
    monkeypatch.setattr(h.e.port, "invoke", invoke)
    task = asyncio.create_task(h.executor.advance_batch(h.e.assignment))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(h.e.calls) == 1 and not h.scope.active
    assert h.executor.journal.result(h.e.job, h.e.calls[0]) is None
    with h.executor.journal.locked(h.e.r.slot):
        pass


async def test_measured_retry_allowance_is_frozen_and_read_bounded(clock):
    calls = 0
    allowances = []
    waits = []

    class Admission:
        def retry_allowance(self, fallback, maximum):
            allowances.append((fallback, maximum))
            return min(maximum, 200.0)

        @asynccontextmanager
        async def attempt(self, *, quiet, timeout):
            waits.append((quiet, timeout))
            yield

    async def operation():
        nonlocal calls
        calls += 1
        if calls <= 2:
            clock.now += 10
            raise retry.ResidentTimingPressure()
        return "accepted"

    with retry.resident_execution_retries("ab" * 32, 180):
        assert await retry.retry_resident_timing(operation, admission=Admission()) == "accepted"
    assert allowances == [(120, 180)]
    assert waits == [(False, 180), (True, 175), (True, 155)]
    assert clock.sleeps == [5, 10]


async def test_ordinary_wait_preserves_read_budget_behind_quiet_recovery(monkeypatch):
    from umi.competition_timing_admission import TimingAttemptAdmission

    # An immediately exhausted failed-attempt allowance must not terminate an
    # ordinary job that still has its read budget and a loaded model reservation.
    monkeypatch.setattr(retry, "MAX_RESIDENT_RETRY_SECONDS", 0)
    gate = TimingAttemptAdmission()
    calls = []

    async def operation():
        calls.append("native_attempt")
        return "accepted"

    async with gate.attempt(quiet=True, timeout=1):
        with retry.resident_execution_retries("ab" * 32, 1):
            task = asyncio.create_task(retry.retry_resident_timing(operation, admission=gate))
        for _ in range(10):
            await asyncio.sleep(0)
        assert not task.done()
        assert calls == []
    assert await asyncio.wait_for(task, 1) == "accepted"
    assert calls == ["native_attempt"]
