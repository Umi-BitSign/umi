"""Native original orders, journals and boundary replay with synthetic sandbox calls."""

import asyncio

import pytest

from umi.competition_cohort_execution_journal import (
    incumbent_scope,
    step_count,
)
from umi.competition_cohort_order_signer import CohortOrderParticipant, order_slot
from umi.competition_cohort_orders import recoverable_order_job
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_execution import observe
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
from .test_competition_cohort_executor import signed_order


async def other_assignment(e):
    b = e.r.h.batch
    m = b["scenarios"][1]
    signed = signed_order(m)
    p = next(
        p for p in b["roster"].participants if p.record.request.signed_submission == m["signed"]
    )
    participant = CohortOrderParticipant(
        consent=p.record.request.consent,
        admission=p.admission,
        admission_snapshot=p.record.snapshot,
    )
    await e.box.accept(signed, participant)
    slot = order_slot(signed.order)
    return e.box.assignment(slot), slot, m


async def finish(e, assignment):
    executor = e.executor()
    job = recoverable_order_job(assignment.certificate.order, e.box.config.signer)
    for _ in range(step_count(job)):
        e.r.h.block += 1
        result = await executor.advance(assignment)
    return result


def cursor_before_peer(e, peer_slot):
    with e.journal().journal.transaction() as db:
        db.execute("DELETE FROM execution_cursor")
        db.execute(
            "INSERT INTO execution_cursor VALUES (?)",
            (e.r.slot if e.r.slot < peer_slot else "",),
        )


async def test_fixed_source_advances_ahead_of_cursor_and_survives_worker_restart(execution):
    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    await e.executor().advance(e.assignment)
    assignment, peer_slot, _ = await other_assignment(e)
    cursor_before_peer(e, peer_slot)
    worker, active = e.worker(concurrency=1), {}
    await worker._rolling_poll(active)
    assert tuple(active) == (e.r.slot,)
    try:
        await asyncio.gather(*active.values())
    finally:
        await worker._drain(active.values())
    # A restart reads the original reservation and keeps its exact observations.
    while e.journal().evidence(e.r.slot) is None:
        worker, active = e.worker(concurrency=1), {}
        await worker._rolling_poll(active)
        assert tuple(active) == (e.r.slot,)
        try:
            await asyncio.gather(*active.values())
        finally:
            await worker._drain(active.values())
    assert e.journal().unfinished_incumbent_sources() == ()
    calls = len(e.calls)
    assert await e.executor().advance(assignment) is not None
    assert len(e.calls) == calls


async def test_unavailable_fixed_source_does_not_starve_single_slot_peer(execution):
    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    await e.executor().advance(e.assignment)
    assignment, peer_slot, _ = await other_assignment(e)
    # Keep this independent legacy attempt on its own recovery path.
    executor = e.executor()
    source, started = await executor.current(assignment)
    peer_job = executor.journal.retain(assignment, source, started.block)
    executor.journal.begin(peer_job, 0, source, started)
    invoke = e.port.invoke

    async def unavailable_source(job, attempt):
        if digest(job) == digest(e.job):
            raise OSError("source unavailable")
        return await invoke(job, attempt)

    e.port.invoke = unavailable_source
    cursor_before_peer(e, peer_slot)
    worker, active = e.worker(concurrency=1), {}
    await worker._rolling_poll(active)
    assert tuple(active) == (e.r.slot,)
    await asyncio.gather(*active.values())
    await worker._rolling_poll(active)
    assert tuple(active) == (peer_slot,)
    try:
        await asyncio.gather(*active.values())
        assert e.journal().step(peer_job, 0) is not None
        assert e.journal().evidence(e.r.slot) is None
    finally:
        await worker._drain(active.values())


async def test_one_forward_source_replays_for_other_original_entry_and_restart(execution):
    e = execution
    first = await finish(e, e.assignment)
    before = canonical_json_bytes(first)
    original_calls = len(e.calls)
    assignment, _slot, m = await other_assignment(e)
    second = await finish(e, assignment)
    if e.job.mode != "endpoint_incumbent":
        assert len(e.calls) == 2 * original_calls
        assert second.steps != first.steps
        return
    assert second.job != first.job and second.steps == first.steps
    assert len(e.calls) == original_calls
    assert canonical_json_bytes(e.journal().evidence(e.r.slot)) == before
    assert e.journal().head(second.job, 0) is None
    assert e.journal().journal.get("incumbent_reuse", digest(second.job)) is not None
    # Existing version-one replay independently validates unchanged original
    # times/model/runtime/cases against this consumer's signed preparation.
    observe(m, second)
    e.r.h.fail_collect = True
    restarted = await e.executor().advance(assignment)
    assert canonical_json_bytes(restarted) == canonical_json_bytes(second)
    assert len(e.calls) == original_calls and not e.stops


async def test_unfinished_fixed_source_holds_consumer_without_other_inference(execution):
    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    await e.executor().advance(e.assignment)
    assignment, slot, _ = await other_assignment(e)
    with pytest.raises(OSError, match="source remains unfinished"):
        await e.executor().advance(assignment)
    assert len(e.calls) == 1 and e.journal().evidence(slot) is None
    assert (
        e.journal().head(
            recoverable_order_job(assignment.certificate.order, e.box.config.signer), 0
        )
        is None
    )
    assert (
        e.journal().journal.get("incumbent_source", incumbent_scope(e.job))["source_slot"]
        == e.r.slot
    )
    for _ in range(step_count(e.job) - 1):
        e.r.h.block += 1
        await e.executor().advance(e.assignment)
    second = await e.executor().advance(assignment)
    assert second.steps == e.journal().evidence(e.r.slot).steps
    assert len(e.calls) == step_count(e.job)


async def test_legacy_attempt_is_preserved_and_never_adopted_as_shared_source(execution):
    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    executor = e.executor()
    source, started = await executor.current(e.assignment)
    job = executor.journal.retain(e.assignment, source, started.block)
    original_attempt = executor.journal.begin(job, 0, source, started)
    original_bytes = canonical_json_bytes(original_attempt)
    assert executor.journal.reuse_endpoint_incumbent(e.r.slot, job, started) is None
    assert executor.journal.journal.get("incumbent_source", incumbent_scope(job)) is None
    first = await finish(e, e.assignment)
    before = canonical_json_bytes(first)
    # The legacy unobserved invocation is reconciled before its replacement.
    # Preserve that original record rather than relabeling the replacement.
    assert (
        canonical_json_bytes(executor.journal.journal.get("attempt", digest(original_attempt)))
        == original_bytes
    )
    assert (
        executor.journal.journal.get("stopped", digest(original_attempt))["status"]
        == "sandbox_stopped"
    )
    assert first.steps[0].started == executor.journal.head(job, 0).started
    assert first.steps[0].started.block >= original_attempt.started.block
    assignment, slot, _ = await other_assignment(e)
    second = await finish(e, assignment)
    assert len(e.calls) == 2 * step_count(job)
    assert second.steps != first.steps
    assert (
        executor.journal.journal.get("incumbent_source", incumbent_scope(job))["source_slot"]
        == slot
    )
    assert canonical_json_bytes(executor.journal.evidence(e.r.slot)) == before
    assert executor.journal.journal.get("incumbent_reuse", digest(job)) is None


async def test_native_model_failure_is_retained_without_selecting_better_source(execution):
    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    e.miner_failure = True
    first = await finish(e, e.assignment)
    e.miner_failure = False
    assignment, _, _ = await other_assignment(e)
    second = await e.executor().advance(assignment)
    assert second.steps == first.steps
    assert all(s.execution.output.status == "miner_failure" for s in second.steps)
    assert len(e.calls) == step_count(e.job)


@pytest.mark.parametrize(
    "field", ["preparation_closure_sha256", "runtime", "evaluator_hotkey", "cases"]
)
async def test_shared_scope_keeps_all_original_authority_and_runtime_inputs(execution, field):
    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    changes = {
        "preparation_closure_sha256": "aa" * 32,
        "runtime": e.job.runtime.model_copy(update={"cpus": 7 if e.job.runtime.cpus != 7 else 6}),
        "evaluator_hotkey": e.r.h.order.evaluators[1],
        "cases": tuple(reversed(e.job.cases)),
    }
    changed = e.job.model_copy(update={field: changes[field]})
    assert incumbent_scope(changed) != incumbent_scope(e.job)


async def test_shared_source_conflict_is_not_borrowed_or_reexecuted(execution):
    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    await finish(e, e.assignment)
    assignment, _, _ = await other_assignment(e)
    with pytest.raises(ValueError, match="conflict"):
        e.journal().journal.put("incumbent_source", incumbent_scope(e.job), {"changed": True})
    with pytest.raises(ValueError):
        await e.executor().advance(assignment)
    assert len(e.calls) == step_count(e.job)


async def test_shared_source_survives_native_terminal_export_and_offline_replay(
    execution, monkeypatch
):
    from umi.competition_cohort_request_terminal import (
        RequestExecutionArchive,
        RequestTerminal,
        SignedRequestTerminal,
        read_request_terminal,
    )
    from umi.open_competition import sign_object

    from .test_competition_cohort_endpoint import attach_endpoint_artifacts
    from .test_competition_cohort_endpoint_quality import archive
    from .test_open_competition import wallet

    e = execution
    if e.job.mode != "endpoint_incumbent":
        return
    first = await finish(e, e.assignment)
    assignment, _slot, m = await other_assignment(e)
    second = await finish(e, assignment)
    assert second.steps == first.steps and second.job != first.job
    calls = len(e.calls)
    evaluator_name = next(
        name
        for name in ("Charlie", "Dave")
        if wallet(name).hotkey.ss58_address == e.box.config.signer
    )
    miner_name = next(
        name
        for name in ("Alice", "Bob", "Eve")
        if wallet(name).hotkey.ss58_address == second.job.submission.submission.hotkey
    )
    m = attach_endpoint_artifacts(dict(m), monkeypatch)
    endpoint_archive, objects, _ = archive(
        m, assignment=assignment, evaluator_name=evaluator_name, miner_name=miner_name
    )

    def put(value):
        key = digest(value)
        objects[key] = canonical_json_bytes(value)
        return key

    assignment_key = put(assignment)
    execution_archive = RequestExecutionArchive(
        schema="umi-request-execution-archive/1",
        assignment_sha256=assignment_key,
        steps=tuple(put(step) for step in second.steps),
    )
    body = RequestTerminal(
        schema="umi-cohort-request-terminal/1",
        assignment_sha256=assignment_key,
        execution_archive_sha256=put(execution_archive),
        endpoint_archive_sha256=put(endpoint_archive),
    )
    signed = SignedRequestTerminal(
        terminal=body, signature=sign_object(body, wallet(evaluator_name))
    )
    opened = min(1499, *(step.started.block - 1 for step in second.steps))
    closed = max(1511, *(step.finished.block for step in second.steps))
    before = dict(objects)
    for _ in range(2):
        assert (
            read_request_terminal(
                signed,
                objects.__getitem__,
                m["policy"],
                opened_at_block=opened,
                completed_by_block=closed,
            )
            == assignment
        )
    assert objects == before and len(e.calls) == calls
    bad_execution = execution_archive.model_copy(update={"assignment_sha256": digest(e.assignment)})
    wrong = body.model_copy(update={"execution_archive_sha256": put(bad_execution)})
    with pytest.raises(ValueError, match="changed its assignment"):
        read_request_terminal(
            SignedRequestTerminal(
                terminal=wrong, signature=sign_object(wrong, wallet(evaluator_name))
            ),
            objects.__getitem__,
            m["policy"],
            opened_at_block=opened,
            completed_by_block=closed,
        )
