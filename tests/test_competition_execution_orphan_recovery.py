"""Native local cleanup precedes RPC, phase gates and model cache reservation."""

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from umi.competition_cohort_executor import CohortExecutionWorker
from umi.competition_runner import EvaluationInfrastructureError
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

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


async def abandoned(e):
    e.fail = True
    with pytest.raises(EvaluationInfrastructureError):
        await e.executor().advance(e.assignment)
    e.fail = False
    return e.calls[-1]


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    "failure", [ValueError("cohort is closed"), OSError("provider unavailable")]
)
async def test_local_cleanup_precedes_closed_authority_rpc_and_cache(execution, batch, failure):
    e = execution
    attempt = await abandoned(e)
    worker = e.executor()
    entered = []

    async def unavailable(_):
        assert e.stops == [attempt]
        assert worker.journal.attempt_stopped(attempt)
        raise failure

    @asynccontextmanager
    async def scope(_):
        assert e.stops == [attempt]
        entered.append("cache")
        yield True

    worker.current = unavailable
    if batch:
        e.port.execution_scope = scope
    advance = worker.advance_batch if batch else worker.advance
    with pytest.raises(type(failure), match=str(failure)):
        await advance(e.assignment)
    assert e.stops == [attempt] and len(e.calls) == 1
    assert entered == (["cache"] if batch else [])
    # Restart reuses the original stopped fact without another container kill.
    restarted = e.executor()
    restarted.current = unavailable
    with pytest.raises(type(failure), match=str(failure)):
        await restarted.advance(e.assignment)
    assert e.stops == [attempt]


async def test_startup_sweep_recovers_closed_job_even_when_inbox_dispatch_is_unavailable(execution):
    e = execution
    attempt = await abandoned(e)
    worker = e.worker(concurrency=1, defer_endpoint_until_terminal=True)

    def forbidden(*args, **kwargs):
        raise AssertionError("cleanup must not need inbox, current authority or cache")

    e.box.assignments = forbidden
    e.box.assignment = forbidden
    worker.executor.current = forbidden
    assert await worker._recover_retained()
    assert e.stops == [attempt]
    assert worker.executor.journal.attempt_stopped(attempt)
    assert await worker._recover_retained()
    assert e.stops == [attempt]


async def test_already_cleaned_attempt_keeps_one_preflight_and_one_finish_capture(execution):
    e = execution
    attempt = await abandoned(e)
    worker = e.executor()
    current = worker.current
    captures = []

    async def counted(assignment):
        captures.append(assignment)
        return await current(assignment)

    worker.current = counted
    await worker.advance(e.assignment)
    assert e.stops == [attempt]
    assert len(captures) == 2 and len(e.calls) == 2


async def test_failed_startup_cleanup_retries_without_an_execution_capacity_slot(execution):
    e = execution
    attempt = await abandoned(e)
    e.fail_stop = True
    worker = e.worker(concurrency=1)
    await worker.capacity.acquire()
    try:
        first = await worker.poll_once()
        assert first["retry_count"] == 1 and worker.recovery_pending == {e.r.slot}
        assert not worker.executor.journal.attempt_stopped(attempt)
        e.fail_stop = False
        assert await worker._recover_retained()
        assert e.stops == [attempt, attempt]
        assert worker.executor.journal.attempt_stopped(attempt)
    finally:
        worker.capacity.release()


async def test_startup_without_uncertain_heads_never_decodes_assignment_graphs(execution):
    e = execution
    await e.executor().advance(e.assignment)
    worker = e.worker()

    def forbidden(*args, **kwargs):
        pytest.fail("no uncertain head means no assignment inventory or decode")

    worker.executor.journal.retained_assignment_page = forbidden
    worker.executor.journal.assignment_and_job = forbidden
    assert await worker._recover_retained()


async def test_cleanup_retries_rotate_past_a_persistently_failing_first_page():
    worker = object.__new__(CohortExecutionWorker)
    worker.recovery_started = True
    worker.recovery_pending = {f"{i:064x}" for i in range(40)}
    worker.recovery_retry_after = ""
    called = []

    async def unavailable(slot, **kwargs):
        called.append(slot)
        raise OSError("native cleanup remains unavailable")

    worker.executor = SimpleNamespace(reconcile_retained=unavailable)
    assert not await worker._recover_retained()
    assert len(called) == 32
    assert not await worker._recover_retained()
    assert set(called) == worker.recovery_pending


@pytest.mark.parametrize("missing", ["assignment", "attempt", "attempt_binding", "stopped_binding"])
async def test_missing_or_changed_local_authority_cannot_authorize_a_kill(execution, missing):
    e = execution
    attempt = await abandoned(e)
    worker = e.executor()
    if missing == "stopped_binding":
        worker.journal.journal.put(
            "stopped",
            digest(attempt),
            dict(
                schema="umi-cohort-stopped-attempt/1",
                attempt_sha256="f" * 64,
                status="sandbox_stopped",
            ),
        )
    with worker.journal.journal.transaction() as db:
        if missing == "attempt_binding":
            damaged = attempt.model_copy(update={"job_sha256": "f" * 64})
            db.execute(
                "UPDATE records SET body=? WHERE kind='attempt' AND id=?",
                (canonical_json_bytes(damaged), digest(attempt)),
            )
        elif missing != "stopped_binding":
            key = e.r.slot if missing == "assignment" else digest(attempt)
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (missing, key))
    with pytest.raises((ValueError, FileNotFoundError)):
        await worker.reconcile_retained(e.r.slot)
    assert not e.stops


async def test_missing_startup_authority_reports_repair_without_guessing_owner(execution, caplog):
    e = execution
    await abandoned(e)
    worker = e.worker()
    with worker.executor.journal.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='assignment' AND id=?", (e.r.slot,))
    caplog.set_level("INFO", logger="umi.competition.progress")
    with pytest.raises(RuntimeError, match="missing assignment authority repair"):
        await worker._recover_retained()
    assert not e.stops and not worker.recovery_started
    observations = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "umi.competition.progress" and record.message.startswith("{")
    ]
    progress = [
        row for row in observations if row.get("stage") == "execution_retained_recovery_inventory"
    ]
    assert progress[-1]["status"] == "retrying"
    assert "elapsed_seconds" in progress[-1] and "eta_basis" in progress[-1]


async def test_live_job_lock_and_cancelled_cleanup_never_release_before_drain(execution):
    e = execution
    attempt = await abandoned(e)
    worker = e.executor()
    with worker.journal.locked(e.r.slot), pytest.raises(OSError):
        await worker.reconcile_retained(e.r.slot)
    assert not e.stops
    entered, drain = asyncio.Event(), asyncio.Event()

    async def reconcile(job, selected):
        assert selected == attempt
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            await drain.wait()

    e.port.reconcile = reconcile
    task = asyncio.create_task(worker.reconcile_retained(e.r.slot))
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(OSError), worker.journal.locked(e.r.slot):
        pytest.fail("cleanup still owns the original job lock")
    drain.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not worker.journal.attempt_stopped(attempt)
    with worker.journal.locked(e.r.slot):
        pass
