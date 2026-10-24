"""Diagnostics preserve results, failures, ownership and exact completion counts."""

import asyncio
import json
import logging
from threading import Event
from types import SimpleNamespace

import pytest

from umi import competition_work_progress as progress
from umi.competition_cohort_public_progress import EXECUTION_JOB_SCOPE, execution_job_scope
from umi.concurrency import await_owned_task, run_owned_thread


@pytest.fixture
def events(monkeypatch):
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(json.loads(record.getMessage()))

    logger = logging.Logger("isolated-work-progress", level=logging.INFO)
    logger.addHandler(Capture())
    monkeypatch.setattr(progress, "_LOG", logger)
    return records


@pytest.fixture
def clock(monkeypatch):
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(
        progress,
        "time",
        SimpleNamespace(monotonic=lambda: clock.now, time_ns=lambda: 1_700_000_000_000_000_000),
    )
    return clock


def test_counts_completed_units_and_estimates_only_this_scope(events, clock):
    values = [object(), object(), object(), object()]
    items = progress.progress_items(values, stage="closure_paid_terminals", unit="paid_items")
    assert next(items) is values[0]
    assert events[-1]["completed"] == 0 and events[-1]["eta_seconds"] is None
    clock.now += 10
    assert next(items) is values[1]
    assert events[-1]["completed"] == 1
    assert events[-1]["percent"] == 25
    assert events[-1]["eta_seconds"] == 30
    assert events[-1]["eta_samples"] == 1
    clock.now += 20
    assert next(items) is values[2]
    assert events[-1]["percent"] == 50
    assert events[-1]["eta_seconds"] == 30
    assert events[-1]["scope"] == "current_attempt_substage"
    assert events[-1]["certification_authority"] is False
    clock.now += 15
    assert next(items) is values[3]
    clock.now += 15
    with pytest.raises(StopIteration):
        next(items)
    assert events[-1]["state"] == "completed"
    assert events[-1]["percent"] == 100
    assert events[-1]["elapsed_seconds"] == 60
    assert events[-1]["eta_seconds"] == 0
    assert all(e["percent"] < 100 for e in events[:-1])


def test_empty_scope_finishes_only_when_exhausted(events):
    items = progress.progress_items([], stage="closure_paid_partials", unit="paid_items")
    assert events == []
    assert list(items) == []
    assert [e["state"] for e in events] == ["started", "completed"]
    assert [e["percent"] for e in events] == [0, 100]


def test_eta_excludes_fast_reuse_and_invalidates_stalled_rate(events, clock):
    meter = progress.WorkProgress("closure_participants", 209, unit="participants")
    for _ in range(124):
        clock.now += 0.01
        meter.advance()
    clock.now += 180
    meter.advance()
    meter.emit("running")
    assert events[-1]["eta_seconds"] == 84 * 180
    assert events[-1]["eta_basis"] == "recent_active_item_rate"
    assert events[-1]["eta_samples"] == 1
    assert events[-1]["eta_ignored_fast_samples"] == 4
    assert events[-1]["scope"] == "current_attempt_substage"
    clock.now += 541
    meter.emit("running")
    assert events[-1]["stalled"] is True
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["eta_basis"] == "stalled_rate_invalidated"
    meter.interrupt()


@pytest.mark.asyncio
async def test_owned_thread_stall_emits_without_a_completed_item(events, clock, monkeypatch):
    entered, release = Event(), Event()
    monkeypatch.setattr(progress, "_HEARTBEAT_SECONDS", 0.01)

    def read_items():
        for item in progress.progress_items([1, 2], stage="native_read", unit="items"):
            if item == 1:
                clock.now += 10
            else:
                clock.now += 40
                entered.set()
                assert release.wait(5)

    with progress.work_heartbeats():
        task = asyncio.create_task(run_owned_thread(read_items))
        assert await asyncio.to_thread(entered.wait, 5)
        try:

            async def observed():
                while not any(event.get("stalled") for event in events):
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(observed(), 2)
            stalled = [event for event in events if event.get("stalled")]
            assert stalled[-1]["completed"] == 1
            assert stalled[-1]["eta_seconds"] is None
            assert stalled[-1]["eta_basis"] == "stalled_rate_invalidated"
        finally:
            release.set()
            await task
    count = len(events)
    await asyncio.sleep(0.03)
    assert len(events) == count


def test_interrupted_item_does_not_count_or_leak_secrets_and_retry_has_new_identity(events):
    secret = "https://private.example/capability/secret"
    items = progress.progress_items([1, secret], stage="closure_paid_partials", unit="paid_items")
    assert next(items) == 1
    assert next(items) == secret
    items.close()
    assert events[-1]["state"] == "interrupted"
    assert events[-1]["completed"] == 1
    assert events[-1]["percent"] == 50
    assert events[-1]["eta_seconds"] is None
    original_id = events[-1]["work_id"]
    assert list(
        progress.progress_items([secret], stage="closure_paid_partials", unit="paid_items")
    ) == [secret]
    assert events[-1]["work_id"] != original_id
    assert secret not in json.dumps(events)


@pytest.mark.parametrize("action", ["finish_early", "advance_too_far"])
def test_bad_diagnostic_accounting_does_not_raise_or_claim_completion(events, action):
    meter = progress.WorkProgress("closure_read_cycles", 2, unit="replay_cycles")
    if action == "advance_too_far":
        meter.advance()
        meter.advance()
        meter.advance()
    else:
        meter.finish()
    meter.finish()
    assert events[-1]["state"] == "accounting_mismatch"
    assert events[-1]["percent"] < 100
    assert events[-1]["eta_seconds"] is None


def test_invalid_diagnostic_metadata_is_not_logged_or_a_protocol_error(events):
    secret = "private bearer token"
    assert list(progress.progress_items([secret], stage=secret, unit="items")) == [secret]
    assert events == []
    with progress.review_scope(secret, secret, reads=0):
        assert list(
            progress.progress_items([1], stage="safe_stage", unit="items", cohort=secret)
        ) == [1]
    assert secret not in json.dumps(events)
    assert events[0]["review_kind"] == "unknown"
    assert events[0]["cohort_sha256"] is None


def test_successful_body_with_missing_counters_is_not_fabricated_completion(events):
    with progress.review_scope("review", "a" * 64, reads=2):
        result = "native-result"
    assert result == "native-result"
    assert events[-1]["state"] == "accounting_mismatch"
    assert events[-1]["completed"] == 0 and events[-1]["percent"] == 0
    assert progress._CONTEXT.get() is None and progress._READS.get() is None


async def test_successful_reads_do_not_mark_failed_final_validation_complete(events):
    failure = ValueError("private native verification failure")

    @progress.review_read
    async def read():
        return object()

    with pytest.raises(ValueError) as caught, progress.review_scope("review", "a" * 64, reads=1):
        await read()
        raise failure
    assert caught.value is failure
    assert events[-1]["completed"] == 1
    assert events[-1]["state"] == "interrupted"
    assert events[-1]["percent"] < 100
    assert str(failure) not in json.dumps(events)
    assert progress._CONTEXT.get() is None and progress._READS.get() is None


async def test_nested_review_context_reaches_owned_thread_and_restores(events):
    owner = SimpleNamespace(roster=SimpleNamespace(round=SimpleNamespace(cohort_sha256="a" * 64)))

    @progress.review_read
    async def read():
        return await run_owned_thread(
            lambda: list(progress.progress_items([1], stage="thread_replay", unit="items"))
        )

    @progress.review_operation(reads=2)
    async def review(owner):
        return await read(), await read()

    with progress.review_scope("progress_vote", "a" * 64, reads=0):
        parent = progress._CONTEXT.get()["review_id"]
        assert await review(owner) == ([1], [1])
        assert progress._CONTEXT.get()["review_id"] == parent
    children = [e for e in events if e["stage"] == "thread_replay" and e["state"] == "started"]
    assert [e["read_number"] for e in children] == [1, 2]
    assert all(e["reads_total"] == 2 and e["parent_review_id"] == parent for e in children)
    cycles = [e for e in events if e["stage"] == "closure_read_cycles"]
    assert cycles[-1]["state"] == "completed" and cycles[-1]["completed"] == 2
    assert progress._CONTEXT.get() is None and progress._READS.get() is None


async def test_simultaneous_reviews_do_not_mix_context(events):
    release = asyncio.Event()

    @progress.review_read
    async def read():
        await release.wait()
        return list(progress.progress_items([1], stage="concurrent_replay", unit="items"))

    async def review(cohort):
        with progress.review_scope("review", cohort, reads=1):
            return await read()

    first = asyncio.create_task(review("a" * 64))
    second = asyncio.create_task(review("b" * 64))
    await asyncio.sleep(0)
    release.set()
    assert await asyncio.gather(first, second) == [[1], [1]]
    starts = [e for e in events if e["stage"] == "concurrent_replay" and e["state"] == "started"]
    assert {e["cohort_sha256"] for e in starts} == {"a" * 64, "b" * 64}
    assert len({e["review_id"] for e in starts}) == 2


async def test_failed_read_preserves_exception_and_does_not_advance(events):
    failure = OSError("private endpoint failure")

    @progress.review_read
    async def read():
        raise failure

    with pytest.raises(OSError) as caught, progress.review_scope("review", "a" * 64, reads=2):
        await read()
    assert caught.value is failure
    assert events[-1]["completed"] == 0 and events[-1]["state"] == "interrupted"
    assert progress._CONTEXT.get() is None and progress._READS.get() is None


async def test_wait_heartbeat_has_no_forecast_and_is_cancelled_after_success(events, monkeypatch):
    monkeypatch.setattr(progress, "_HEARTBEAT_SECONDS", 0.001)
    original = object()

    async def work():
        await asyncio.sleep(0.01)
        return original

    assert await progress.await_progress(work(), stage="request_owner_export") is original
    waiting = [e for e in events if e["state"] == "waiting"]
    assert waiting and all(e["eta_seconds"] is None and e["percent"] == 0 for e in waiting)
    assert events[-1]["state"] == "completed"
    count = len(events)
    await asyncio.sleep(0.01)
    assert len(events) == count


async def test_wait_failure_keeps_original_error_and_stops_heartbeat(events, monkeypatch):
    monkeypatch.setattr(progress, "_HEARTBEAT_SECONDS", 0.001)
    failure = OSError("private response")

    async def work():
        raise failure

    with pytest.raises(OSError) as caught:
        await progress.await_progress(work(), stage="request_owner_export")
    assert caught.value is failure
    assert events[-1]["state"] == "interrupted"
    assert events[-1]["completed"] == 0
    count = len(events)
    await asyncio.sleep(0.01)
    assert len(events) == count


async def test_job_attribution_isolated_between_tasks_and_owned_threads(events):
    ready, release = asyncio.Queue(), asyncio.Event()

    async def job(key):
        with execution_job_scope(key):
            ready.put_nowait(key)
            await release.wait()

            def operation():
                meter = progress.WorkProgress("journal", 1, unit="operations")
                meter.advance()
                meter.finish()

            await progress.await_progress(run_owned_thread(operation), stage="journal_wait")
        assert EXECUTION_JOB_SCOPE.get() is None

    tasks = [asyncio.create_task(job(key * 64)) for key in ("a", "b")]
    await ready.get()
    await ready.get()
    release.set()
    await asyncio.gather(*tasks)
    assert {event["job_sha256"] for event in events} == {"a" * 64, "b" * 64}
    assert len({event["work_id"] for event in events}) == 4
    assert EXECUTION_JOB_SCOPE.get() is None


async def test_wait_preserves_repeated_cancellation_and_owned_drain(events, monkeypatch):
    monkeypatch.setattr(progress, "_HEARTBEAT_SECONDS", 0.001)
    entered, release = asyncio.Event(), asyncio.Event()

    async def owned():
        entered.set()
        await release.wait()
        return "owned-result"

    child = asyncio.create_task(owned())
    waiter = asyncio.create_task(
        progress.await_progress(await_owned_task(child), stage="request_owner_export")
    )
    await entered.wait()
    waiter.cancel()
    await asyncio.sleep(0)
    waiter.cancel()
    await asyncio.sleep(0.01)
    assert not waiter.done() and not child.done()
    assert any(e["state"] == "waiting" for e in events)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert child.result() == "owned-result"
    assert events[-1]["state"] == "interrupted"
    assert all(e["state"] != "completed" for e in events)
    count = len(events)
    await asyncio.sleep(0.01)
    assert len(events) == count


async def test_failed_logging_sink_cannot_replace_native_success_or_failure(monkeypatch):
    class FailedSink:
        def info(self, value):
            raise RuntimeError("logging sink unavailable")

    monkeypatch.setattr(progress, "_LOG", FailedSink())
    result = object()
    failure = OSError("native failure")

    async def work(fail):
        if fail:
            raise failure
        return result

    with progress.review_scope("review", "a" * 64, reads=2):
        assert list(progress.progress_items([result], stage="replay", unit="items")) == [result]
        assert await progress.await_progress(work(False), stage="request_owner_export") is result
        with pytest.raises(OSError) as caught:
            await progress.await_progress(work(True), stage="request_owner_export")
        assert caught.value is failure


def test_context_meter_keeps_native_error_and_success_boundaries(events):
    failure = ValueError("native verification failed")
    with (
        pytest.raises(ValueError) as caught,
        progress.WorkProgress("response_validation", 2, unit="checks") as meter,
    ):
        meter.advance()
        raise failure
    assert caught.value is failure
    assert events[-1]["state"] == "interrupted" and events[-1]["completed"] == 1
    with progress.WorkProgress("response_validation", 2, unit="checks") as meter:
        meter.advance()
        meter.advance()
        assert events[-1]["percent"] < 100
    assert events[-1]["state"] == "completed" and events[-1]["percent"] == 100


def test_unequal_validation_steps_report_counts_without_extrapolating_eta(events, clock):
    with progress.WorkProgress(
        "response_validation", 5, unit="validation_steps", estimate=False
    ) as meter:
        for _ in range(5):
            clock.now += 10
            meter.advance()
            assert events[-1]["eta_seconds"] is None
            assert events[-1]["eta_basis"] == "unestimated_scope"
            assert events[-1]["eta_assumption"] is None
    assert events[-1]["state"] == "completed"
    assert events[-1]["eta_seconds"] == 0 and events[-1]["eta_basis"] == "completed"


def test_sync_operation_attributes_nested_and_repeated_work_without_merging_counts(events):
    @progress.work_operation("settlement_prepare")
    def prepare():
        return list(
            progress.progress_items([1, 2], stage="closure_benchmark_entries", unit="entries")
        )

    @progress.work_operation("settlement_assembly")
    def assembly():
        parent = progress._CONTEXT.get().copy()
        assert prepare() == [1, 2]
        assert progress._CONTEXT.get() == parent
        return prepare()

    with progress.review_scope("progress_vote", "a" * 64, reads=0):
        parent = progress._CONTEXT.get().copy()
        assert assembly() == [1, 2]
        assert progress._CONTEXT.get() == parent
    starts = [event for event in events if event["state"] == "started"]
    assert len(starts) == 2
    assert len({event["operation_id"] for event in starts}) == 2
    assert len({event["parent_operation_id"] for event in starts}) == 1
    assert all(event["operation_name"] == "settlement_prepare" for event in starts)
    assert all(event["review_id"] == parent["review_id"] for event in starts)
    assert all(event["total"] == 2 and event["completed"] == 0 for event in starts)
    assert all(event["eta_seconds"] is None for event in starts)
    assert progress._CONTEXT.get() is None


async def test_sync_operation_owned_thread_restores_context_and_original_failure(events):
    failure = ValueError("private validation detail")

    @progress.work_operation("settlement_replay")
    def replay():
        list(progress.progress_items([1], stage="closure_paid_terminals", unit="items"))
        raise failure

    with progress.review_scope("decision_vote", "b" * 64, reads=0):
        parent = progress._CONTEXT.get().copy()
        with pytest.raises(ValueError) as caught:
            await run_owned_thread(replay)
        assert caught.value is failure
        assert progress._CONTEXT.get() == parent
    assert events[0]["operation_name"] == "settlement_replay"
    assert events[0]["review_id"] == parent["review_id"]
    assert str(failure) not in json.dumps(events)
    assert progress._CONTEXT.get() is None


def test_sync_operation_redacts_invalid_name_and_rejects_lazy_functions(events):
    secret = "https://private.example/capability"

    @progress.work_operation(secret)
    def safe():
        return list(progress.progress_items([1], stage="safe_stage", unit="items"))

    assert safe() == [1]
    assert events[0]["operation_name"] == "unknown"
    assert secret not in json.dumps(events)

    async def coroutine():
        pass

    def generator():
        yield None

    async def async_generator():
        yield None

    for lazy in (coroutine, generator, async_generator):
        with pytest.raises(TypeError, match="eager synchronous"):
            progress.work_operation("scope")(lazy)
