"""Real inbox/journal recovery with synthetic finality and sandbox observations.

No test here proves an installed sandbox, reward admission or on-chain effects.
"""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_cohort_execution_journal import (
    CohortExecutionConfig,
    CohortExecutionJournal,
    case_role_model,
    step_count,
)
from umi.competition_cohort_executor import CohortExecutionWorker, CohortExecutor
from umi.competition_cohort_order_signer import CohortOrderParticipant
from umi.competition_cohort_orders import recoverable_order_job
from umi.competition_runner import EvaluationInfrastructureError, OfflineCaseExecution
from umi.open_competition import CaseOutput, digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_disposition import order as signed_order
from .test_competition_cohort_execution import observe
from .test_competition_cohort_order_delivery import base_policy as base_policy
from .test_competition_cohort_order_delivery import harness as harness
from .test_competition_cohort_order_delivery import legacy_scenario as legacy_scenario
from .test_competition_cohort_order_delivery import policy as policy
from .test_competition_cohort_order_delivery import receipt_scenario as receipt_scenario
from .test_competition_cohort_order_delivery import recovery as recovery
from .test_competition_cohort_order_delivery import relay as relay
from .test_competition_cohort_order_delivery import runtime as runtime
from .test_competition_cohort_order_delivery import scenario as scenario
from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_roster import close


@pytest.fixture
async def execution(relay, tmp_path):
    r = relay
    await r.worker().poll_once()
    box = r.inbox(r.h.order.evaluators[0])
    assignment = box.assignment(r.slot)
    cfg = CohortExecutionConfig.model_validate(
        {
            **box.config.model_dump(by_alias=True),
            "schema": "umi-cohort-execution-config/1",
            "directory": str(tmp_path / "execution"),
        }
    )
    e = SimpleNamespace(
        r=r,
        assignment=assignment,
        cfg=cfg,
        calls=[],
        stops=[],
        fail=False,
        fail_stop=False,
        after_result=None,
        miner_failure=False,
    )

    async def reconcile(job, attempt):
        e.stops.append(attempt)
        if e.fail_stop:
            raise OSError("container termination unavailable")

    async def invoke(job, attempt):
        e.calls.append(attempt)
        if e.fail:
            raise EvaluationInfrastructureError("sandbox interrupted")
        result = output(job, attempt, miner_failure=e.miner_failure)
        if e.after_result is not None:
            await e.after_result()
        return result

    e.port = SimpleNamespace(reconcile=reconcile, invoke=invoke)
    e.box = box
    e.journal = lambda **kw: CohortExecutionJournal(cfg.model_copy(update=kw), r.h.batch["policy"])
    e.executor = lambda **kw: CohortExecutor(e.journal(**kw), box.provider, box.history, e.port)
    e.worker = lambda **kw: CohortExecutionWorker(box, e.executor(), **kw)
    e.job = recoverable_order_job(assignment.certificate.order, box.config.signer)
    return e


def output(job, attempt, *, miner_failure=False):
    case, _, model = case_role_model(job, attempt.step_index)
    return OfflineCaseExecution(
        schema="umi-offline-case-execution/1",
        model_sha256=digest(model),
        runtime_sha256=digest(job.runtime),
        video_sha256=case.video_sha256,
        output=CaseOutput(
            case_id=case.case_id,
            status="miner_failure" if miner_failure else "ok",
            hypothesis="" if miner_failure else "hello",
            elapsed_ms=1,
        ),
        stdout_hex="" if miner_failure else b"hello\n".hex(),
        reason="process_failed" if miner_failure else "ok",
        returncode=1 if miner_failure else 0,
    )


async def test_inbox_to_complete_replay_and_offline_restart(execution):
    e = execution
    for index in range(step_count(e.job)):
        e.r.h.block += 1
        result = await e.worker().poll_once()
        assert result["retry_count"] == 0
        assert result["jobs_complete"] == int(index == step_count(e.job) - 1)
    evidence = e.journal().evidence(e.r.slot)
    assert evidence.job == e.job and len(e.calls) == step_count(e.job)
    # Native historical replay checks every retained output and boundary.
    observe(e.r.h.batch["scenarios"][0], evidence)
    original = canonical_json_bytes(evidence)
    e.r.h.fail_collect = True
    e.r.h.source = source_for(e.r.h.batch, e.r.h.batch["history"])
    assert canonical_json_bytes(await e.executor().advance(e.assignment)) == original
    assert len(e.calls) == step_count(e.job) and not e.stops


async def test_ten_hour_outages_keep_completed_steps_and_original_order(execution):
    e = execution
    await e.executor().advance(e.assignment)
    first = e.journal().step(e.job, 0)
    for block in (3400, 6400, 1000000):
        e.r.h.block = block
        e.r.h.fail_collect = True
        assert (await e.worker().poll_once())["retry_count"] == 1
        assert e.journal().step(e.job, 0) == first
    assert len(e.calls) == 1
    e.r.h.fail_collect = False
    for _ in range(step_count(e.job) - 1):
        await e.executor().advance(e.assignment)
    # The request phase closes at its actual delayed completion, not an old target.
    b = e.r.h.batch
    h = close(
        e.r.h.source.history, b["policy"], b["decisions"], 1000100, "ab" * 32, unavailable=999500
    )
    h = close(h, b["policy"], b["decisions"], 1000200, "ac" * 32)
    evidence = e.journal().evidence(e.r.slot)
    observe(
        b["scenarios"][0],
        evidence,
        history=h,
        expected_tip_sha256=digest(h.transitions[-1].transition),
        current_block=1000300,
    )
    assert e.journal().assignment(e.r.slot) == e.assignment
    assert len(e.calls) == step_count(e.job)


async def test_lost_finish_observation_never_repeats_retained_inference(execution):
    e = execution

    async def disconnect():
        e.r.h.fail_collect = True

    e.after_result = disconnect
    assert (await e.worker().poll_once())["retry_count"] == 1
    attempt = e.journal().head(e.job, 0)
    retained = e.journal().result(e.job, attempt)
    assert retained is not None and e.journal().step(e.job, 0) is None
    for block in (3400, 6400, 10**6):
        e.r.h.block = block
        assert (await e.worker().poll_once())["retry_count"] == 1
    e.r.h.fail_collect = False
    await e.executor().advance(e.assignment)
    assert e.journal().step(e.job, 0).execution == retained.execution
    assert len(e.calls) == 1 and not e.stops


async def test_uncertain_sandbox_must_stop_before_replacement(execution):
    e = execution
    e.fail = True
    assert (await e.worker().poll_once())["retry_count"] == 1
    old = e.journal().head(e.job, 0)
    e.fail_stop = True
    for _ in range(2):
        assert (await e.worker().poll_once())["retry_count"] == 1
        assert e.journal().head(e.job, 0) == old
    assert len(e.calls) == 1
    e.fail_stop = e.fail = False
    e.r.h.block = 3400
    await e.executor().advance(e.assignment)
    new = e.journal().head(e.job, 0)
    assert new.number == 2 and new.predecessor_sha256 == digest(old)
    assert e.journal().step(e.job, 0) is not None
    assert len(e.calls) == 2 and e.stops[-1] == old


@pytest.mark.parametrize("method", ["observe", "finish"])
async def test_lost_commit_ack_recovers_first_result(execution, monkeypatch, method):
    e = execution
    original = getattr(CohortExecutionJournal, method)

    def lost(self, *args):
        original(self, *args)
        raise OSError("local acknowledgement lost")

    monkeypatch.setattr(CohortExecutionJournal, method, lost)
    assert (await e.worker().poll_once())["retry_count"] == 1
    monkeypatch.setattr(CohortExecutionJournal, method, original)
    await e.executor().advance(e.assignment)
    assert e.journal().step(e.job, 0) is not None
    assert len(e.calls) == (2 if method == "finish" else 1)
    assert len({(a.step_index, a.number) for a in e.calls}) == len(e.calls)
    assert not e.stops


async def test_cancel_drains_retained_result_before_releasing_job_lock(execution):
    e = execution
    entered, release = asyncio.Event(), asyncio.Event()

    async def completing():
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()

    e.after_result = completing
    task = asyncio.create_task(e.executor().advance(e.assignment))
    await asyncio.wait_for(entered.wait(), 3)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    assert not task.done()
    with pytest.raises(BlockingIOError):
        await e.executor().advance(e.assignment)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    attempt = e.journal().head(e.job, 0)
    assert e.journal().result(e.job, attempt) is not None
    await e.executor().advance(e.assignment)
    assert len(e.calls) == 1 and not e.stops


async def test_actual_miner_failure_is_retained_without_infrastructure_retry(execution):
    e = execution
    e.miner_failure = True
    result = await e.worker().poll_once()
    assert result["retry_count"] == 0
    assert e.journal().step(e.job, 0).execution.output.status == "miner_failure"
    await e.executor().advance(e.assignment)
    assert e.calls[1].step_index == 1 and not e.stops


async def test_capacity_can_increase_without_replacing_accepted_work(execution):
    e = execution
    e.fail = True
    with pytest.raises(EvaluationInfrastructureError):
        await e.executor(maximum_attempts=1).advance(e.assignment)
    e.fail = False
    with pytest.raises(ValueError, match="capacity"):
        await e.executor(maximum_attempts=1).advance(e.assignment)
    assert len(e.calls) == 1
    await e.executor(maximum_attempts=2).advance(e.assignment)
    assert e.journal().step(e.job, 0) is not None
    assert e.journal().assignment(e.r.slot) == e.assignment


async def test_closed_authority_stops_new_work_and_prevents_rollback(execution):
    e = execution
    await e.executor().advance(e.assignment)
    old = e.r.h.source
    e.r.h.source = source_for(e.r.h.batch, e.r.h.batch["history"])
    e.r.h.block = 5000
    assert (await e.worker().poll_once())["retry_count"] == 1
    e.r.h.source = old
    assert (await e.worker().poll_once())["retry_count"] == 1
    assert len(e.calls) == 1


async def test_regressed_finality_holds_pending_result(execution):
    e = execution

    async def backwards():
        e.r.h.block -= 1

    e.after_result = backwards
    assert (await e.worker().poll_once())["retry_count"] == 1
    assert e.journal().step(e.job, 0) is None
    e.r.h.block = 401
    await e.executor().advance(e.assignment)
    assert e.journal().step(e.job, 0) is not None and len(e.calls) == 1


async def test_transport_timeout_drains_and_configuration_can_increase(execution):
    e = execution
    worker = e.executor(read_timeout_seconds=1)
    stopped = asyncio.Event()

    async def unavailable(cohort):
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    worker.history = unavailable
    with pytest.raises(asyncio.TimeoutError):
        await worker.advance(e.assignment)
    assert stopped.is_set() and not e.calls
    await e.executor(read_timeout_seconds=60).advance(e.assignment)
    assert e.journal().step(e.job, 0) is not None


async def test_result_cannot_be_replaced_or_retried_after_retention(execution):
    e = execution
    await e.executor().advance(e.assignment)
    j = e.journal()
    attempt = j.head(e.job, 0)
    with pytest.raises(ValueError, match="completed"):
        j.begin(e.job, 0, e.r.h.source, attempt.started)
    assert j.step(e.job, 0).execution.output.status == "ok"
    with pytest.raises(ValueError):
        j.observe(e.job, attempt, output(e.job, attempt, miner_failure=True))
    # Conflicting bytes put the journal identity on hold, never select a new score.
    with pytest.raises(ValueError, match="conflict held"):
        j.step(e.job, 0)


async def test_execution_scan_survives_blocked_first_job_and_restart(execution):
    e = execution
    r, b = e.r, e.r.h.batch
    p = b["roster"].participants[1]
    second = signed_order(b["scenarios"][1]).order
    r.queue().select(
        second,
        CohortOrderParticipant(
            consent=p.record.request.consent,
            admission=p.admission,
            admission_snapshot=p.record.snapshot,
        ),
        r.h.source,
        await r.capture(),
    )
    await r.worker().poll_once()
    slots = e.box.assignments()
    assert len(slots) == 2
    blocked = e.box.assignment(slots[0]).certificate.order.submission
    invoke = e.port.invoke

    async def selective(job, attempt):
        if job.submission == blocked:
            raise EvaluationInfrastructureError("one model unavailable")
        return await invoke(job, attempt)

    e.port.invoke = selective
    assert (await e.worker(batch_size=1).poll_once())["retry_count"] == 1
    assert (await e.worker(batch_size=1).poll_once())["retry_count"] == 0
    assert len(e.calls) == 1
    assert (await e.worker(batch_size=1).poll_once())["retry_count"] == 1


async def test_service_stop_preserves_inflight_result_for_next_process(execution):
    e = execution
    stop, entered = asyncio.Event(), asyncio.Event()

    async def wait_cancel():
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return

    e.after_result = wait_cancel
    task = asyncio.create_task(e.worker().run(stop, poll_seconds=0.01))
    await asyncio.wait_for(entered.wait(), 3)
    stop.set()
    await asyncio.wait_for(task, 3)
    attempt = e.journal().head(e.job, 0)
    assert e.journal().result(e.job, attempt) is not None
    await e.executor().advance(e.assignment)
    assert len(e.calls) == 1


@pytest.mark.parametrize("damage", ["quorum", "delivery", "participant"])
async def test_assignment_mutation_cannot_start_sandbox(execution, damage):
    e = execution
    a = e.assignment
    if damage == "quorum":
        a = a.model_copy(
            update={
                "certificate": a.certificate.model_copy(
                    update={"signatures": a.certificate.signatures[:1]}
                )
            }
        )
    elif damage == "delivery":
        a = a.model_copy(
            update={"delivery": e.r.inbox(e.r.h.order.evaluators[1]).assignment(e.r.slot).delivery}
        )
    else:
        a = a.model_copy(
            update={
                "participant": a.participant.model_copy(
                    update={
                        "admission_snapshot": a.participant.admission_snapshot.model_copy(
                            update={"block": 1}
                        )
                    }
                )
            }
        )
    with pytest.raises(ValueError):
        await e.executor().advance(a)
    assert not e.calls
