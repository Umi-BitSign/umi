"""Real retained source selection with synthetic capacity, finality and inference."""

import asyncio
import sqlite3
from contextlib import asynccontextmanager

import pytest

from umi.competition_cohort_execution import RecoverableSharedIncumbentEvidence
from umi.competition_cohort_execution_journal import incumbent_scope, step_count
from umi.competition_cohort_executor import CohortExecutionWorker
from umi.competition_cohort_order_signer import order_slot
from umi.competition_cohort_orders import recoverable_order_job
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_consumers as consumers
from .test_competition_cohort_execution import observe
from .test_competition_cohort_incumbent_reuse import other_assignment
from .test_competition_cohort_paired_incumbent_reuse import base_policy as base_policy
from .test_competition_cohort_paired_incumbent_reuse import execution as execution
from .test_competition_cohort_paired_incumbent_reuse import harness as harness
from .test_competition_cohort_paired_incumbent_reuse import legacy_scenario as legacy_scenario
from .test_competition_cohort_paired_incumbent_reuse import original_harness as original_harness
from .test_competition_cohort_paired_incumbent_reuse import paired
from .test_competition_cohort_paired_incumbent_reuse import policy as policy
from .test_competition_cohort_paired_incumbent_reuse import receipt_scenario as receipt_scenario
from .test_competition_cohort_paired_incumbent_reuse import recovery as recovery
from .test_competition_cohort_paired_incumbent_reuse import relay as relay
from .test_competition_cohort_paired_incumbent_reuse import runtime as runtime
from .test_competition_cohort_paired_incumbent_reuse import scenario as scenario


@pytest.fixture(autouse=True)
def sixteen_case_suite(monkeypatch):
    original = consumers.suite_for

    def suite(policy):
        base = original(policy)
        return base.model_copy(
            update={
                "cases": tuple(
                    base.cases[index % len(base.cases)].model_copy(
                        update={
                            "case_id": f"{index + 1:064x}",
                            "video_sha256": f"{index + 101:064x}",
                        }
                    )
                    for index in range(16)
                )
            }
        )

    monkeypatch.setattr(consumers, "suite_for", suite)


async def test_pending_consumer_defers_without_scope_capture_or_source_replay(
    execution, monkeypatch
):
    e = execution
    source = paired(e)
    await source.advance(e.assignment)
    assignment, slot, _ = await other_assignment(e)
    source_record = canonical_json_bytes(
        source.journal.journal.get("incumbent_source", incumbent_scope(e.job))
    )
    source_step = canonical_json_bytes(source.journal.step(e.job, 0))
    reads = e.r.h.reads

    @asynccontextmanager
    async def forbidden_scope(order):
        raise AssertionError("waiting consumer must not acquire or prepare models")
        yield  # pragma: no cover

    def forbidden(*args, **kwargs):
        raise AssertionError("waiting consumer must not load source evidence or refresh authority")

    e.port.execution_scope = forbidden_scope
    for _ in range(2):
        executor = paired(e)
        monkeypatch.setattr(executor, "current", forbidden)
        monkeypatch.setattr(executor.journal, "_source_evidence", forbidden)
        worker = CohortExecutionWorker(e.box, executor)
        assert await worker._one(slot) == (slot, "deferred", "incumbent_source_pending")
        assert executor.journal.journal.get("assignment", slot) is None
    assert e.r.h.reads == reads and len(e.calls) == 1
    assert canonical_json_bytes(source.journal.step(e.job, 0)) == source_step
    assert (
        canonical_json_bytes(source.journal.journal.get("incumbent_source", incumbent_scope(e.job)))
        == source_record
    )
    assert (
        source.journal.journal.get(
            "incumbent_reuse",
            digest(recoverable_order_job(assignment.certificate.order, e.cfg.signer)),
        )
        is None
    )


@pytest.mark.parametrize("callback_supported", [False, True])
async def test_concurrent_first_jobs_reserve_one_source_before_model_capacity(
    execution, callback_supported
):
    e = execution
    executor = paired(e)
    _assignment, peer_slot, _ = await other_assignment(e)
    entered, release = asyncio.Event(), asyncio.Event()
    scopes = []
    current = executor.current
    arrivals = 0
    both_unselected = asyncio.Event()
    authority_calls = {}

    async def coordinated_current(value):
        nonlocal arrivals
        slot = order_slot(value.certificate.order)
        authority_calls[slot] = authority_calls.get(slot, 0) + 1
        if authority_calls[slot] == 1:
            arrivals += 1
            if arrivals == 2:
                both_unselected.set()
            await asyncio.wait_for(both_unselected.wait(), 10)
            # Keep the original assignment's first reservation deterministic.
            if slot == peer_slot:
                await asyncio.wait_for(entered.wait(), 10)
        return await current(value)

    @asynccontextmanager
    async def scope(order, *, before_reserve=None):
        if before_reserve is not None:
            await before_reserve()
        slot = order_slot(order)
        selected = executor.journal.journal.get("incumbent_source", incumbent_scope(e.job))
        assert selected is not None and selected["source_slot"] == slot
        scopes.append(slot)
        entered.set()
        await release.wait()
        yield True

    executor.current = coordinated_current
    e.port.execution_scope = scope
    e.port.execution_scope_before_reserve = callback_supported
    worker = CohortExecutionWorker(e.box, executor, concurrency=2)
    source_task = asyncio.create_task(worker._one(e.r.slot))
    peer_task = asyncio.create_task(worker._one(peer_slot))
    try:
        await asyncio.wait_for(entered.wait(), 10)
        assert await asyncio.wait_for(peer_task, 10) == (
            peer_slot,
            "deferred",
            "incumbent_source_pending",
        )
        assert scopes == [e.r.slot] and not e.calls
        e.r.h.block += 1
        release.set()
        assert await asyncio.wait_for(source_task, 30) == (e.r.slot, "complete", "")
        assert authority_calls[e.r.slot] >= 2
        assert executor.journal.step(e.job, 0).started.block == e.r.h.block
        assert len(e.calls) == 32
    finally:
        release.set()
        await worker._drain((source_task, peer_task))


async def test_eight_checkpoint_source_retry_precedes_consumers_and_preserves_replay(
    execution, monkeypatch
):
    e = execution
    executor = paired(e)
    assert step_count(e.job) == 32
    for _ in range(8):
        e.r.h.block += 1
        assert await executor.advance(e.assignment) is None
    original_steps = tuple(canonical_json_bytes(executor.journal.step(e.job, i)) for i in range(8))
    reservation = canonical_json_bytes(
        executor.journal.journal.get("incumbent_source", incumbent_scope(e.job))
    )
    _assignment, peer_slot, scenario = await other_assignment(e)
    scopes = []

    @asynccontextmanager
    async def scope(order):
        scopes.append(order_slot(order))
        yield True

    e.port.execution_scope = scope
    begin = executor.journal.begin

    def busy(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(executor.journal, "begin", busy)
    worker = CohortExecutionWorker(e.box, executor)
    assert await worker._one(e.r.slot) == (e.r.slot, "pending", "OperationalError")
    assert len(e.calls) == 8
    monkeypatch.setattr(executor.journal, "begin", begin)
    # A restarted worker meets the waiting consumer first. It needs no model
    # scope, so the retained source can resume with all eight checkpoints.
    executor = paired(e)
    worker = CohortExecutionWorker(e.box, executor)
    assert await worker._one(peer_slot) == (peer_slot, "deferred", "incumbent_source_pending")
    assert scopes == [e.r.slot]
    assert await worker._one(e.r.slot) == (e.r.slot, "complete", "")
    first = executor.journal.evidence(e.r.slot)
    assert len(e.calls) == 32 and scopes == [e.r.slot, e.r.slot]
    assert tuple(canonical_json_bytes(step) for step in first.steps[:8]) == original_steps
    assert (
        canonical_json_bytes(
            executor.journal.journal.get("incumbent_source", incumbent_scope(e.job))
        )
        == reservation
    )
    e.r.h.block += 1
    assert await worker._one(peer_slot) == (peer_slot, "complete", "")
    second = executor.journal.evidence(peer_slot)
    assert isinstance(second, RecoverableSharedIncumbentEvidence)
    assert second.incumbent_source == first and len(e.calls) == 48
    observe(scenario, second)


async def test_shared_batch_requires_scheduling_reader_before_resources(execution, monkeypatch):
    e = execution
    executor = paired(e)

    @asynccontextmanager
    async def scope(order):
        raise AssertionError("unsupported shared reader must fail before model preparation")
        yield  # pragma: no cover

    e.port.execution_scope = scope
    monkeypatch.setattr(executor.journal, "incumbent_source_status", None)
    with pytest.raises(RuntimeError, match="requires its journal reader"):
        await executor.advance_batch(e.assignment)
    assert not e.calls


async def test_source_binding_damage_is_repair_not_dependency_wait(execution):
    e = execution
    executor = paired(e)
    await executor.advance(e.assignment)
    assignment, peer_slot, _ = await other_assignment(e)
    job = recoverable_order_job(assignment.certificate.order, e.cfg.signer)
    with executor.journal.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind='assignment' AND id=?",
            (canonical_json_bytes(assignment), e.r.slot),
        )
    with pytest.raises(ValueError):
        executor.journal.incumbent_source_status(peer_slot, job)
    assert len(e.calls) == 1
