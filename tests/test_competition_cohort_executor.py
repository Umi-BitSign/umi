"""Real inbox/journal recovery with synthetic finality and sandbox observations.

No test here proves an installed sandbox, reward admission or on-chain effects.
"""

import asyncio
from contextlib import asynccontextmanager
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
async def model_partial_export(execution, tmp_path):
    from umi.competition_cohort_request_export_worker import RequestExportWorker
    from umi.competition_cohort_request_files import RequestCompletionFiles
    from umi.competition_round_journal import RoundJournal
    from umi.open_competition import identity, sign_object

    from .test_open_competition import wallet

    e = execution
    if e.job.mode != "paired_model":
        pytest.skip("this source optimization only covers public model jobs")
    executor = e.executor()
    e.r.h.block += 1
    assert await executor.advance(e.assignment) is None
    files = RequestCompletionFiles(tmp_path / "partial-exports")

    async def sign(body):
        return sign_object(body, wallet(e.r.names[identity(executor.journal.config.signer)]))

    worker = RequestExportWorker(
        (executor.journal,),
        e.box.provider,
        sign,
        files,
        RoundJournal(tmp_path / "partial-export-cursor", {"schema": "partial-export-test/1"}),
    )
    block = e.r.h.block
    assert await worker._export(executor.journal, e.r.slot, block) is False
    return SimpleNamespace(
        e=e,
        executor=executor,
        owner=executor.journal,
        files=files,
        worker=worker,
        slot=e.r.slot,
        block=block,
    )


async def test_model_partial_export_skips_unchanged_evidence_and_collection_after_restart(
    model_partial_export, monkeypatch
):
    import umi.competition_cohort_request_files as module

    h = model_partial_export
    key = h.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block)
    assert key is not None

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "unchanged source must not repeat evidence, collection or job projection"
        )

    monkeypatch.setattr(h.owner, "evidence", forbidden)
    monkeypatch.setattr(h.owner, "assignment_and_job", forbidden)
    monkeypatch.setattr(module, "collect_partial_request_with_inputs", forbidden)
    assert await h.worker._export(h.owner, h.slot, h.block + 1) is False
    h.worker.files = module.RequestCompletionFiles(h.files.root)
    assert await h.worker._export(h.owner, h.slot, h.block + 2) is False
    assert (
        h.worker.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block + 2) == key
    )


async def test_model_partial_export_upgrades_existing_publication_without_recollecting(
    model_partial_export, monkeypatch
):
    import umi.competition_cohort_request_files as module

    h = model_partial_export
    key = h.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block)
    for path in h.files._model_partials.root.glob("*.json"):
        path.unlink()
    h.worker.files = module.RequestCompletionFiles(h.files.root)

    def forbidden(*args, **kwargs):
        raise AssertionError("existing native publication must seed upgrade facts without replay")

    monkeypatch.setattr(h.owner, "evidence", forbidden)
    monkeypatch.setattr(module, "collect_partial_request_with_inputs", forbidden)
    monkeypatch.setattr(module, "review_partial_request", forbidden)
    h.worker.publish_inventory_proof = forbidden
    h.worker.inventory_cutoff = lambda cohort: None
    h.worker.inventory_needed = lambda cohort: True
    monkeypatch.setattr(h.owner, "assignment", forbidden)
    assert await h.worker._export(h.owner, h.slot, h.block + 1) is False
    assert (
        h.worker.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block + 1) == key
    )


async def test_model_partial_export_new_step_invalidates_only_that_source(model_partial_export):
    h = model_partial_export
    before = h.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block)
    h.e.r.h.block += 1
    assert await h.executor.advance(h.e.assignment) is None
    block = h.e.r.h.block
    assert h.files.current_model_partial(h.owner, h.slot, completed_by_block=block) is None
    assert await h.worker._export(h.owner, h.slot, block) is False
    after = h.files.current_model_partial(h.owner, h.slot, completed_by_block=block)
    assert after is not None and after != before


@pytest.mark.parametrize("held", ["assignment", "step"])
async def test_model_partial_export_still_observes_fresh_source_conflicts(
    model_partial_export, held
):
    h = model_partial_export
    checkpoint = h.files._model_partials.load(h.owner, h.slot)
    key = h.slot if held == "assignment" else checkpoint.step_keys[0]
    with h.owner.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (key,))
    with pytest.raises(ValueError, match="conflict held"):
        await h.worker._export(h.owner, h.slot, h.block + 1)


async def test_model_partial_export_repairs_missing_output_without_repeating_native_review(
    model_partial_export, monkeypatch
):
    import umi.competition_cohort_request_files as module

    h = model_partial_export
    key = h.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block)
    output = h.files.objects._path(key)
    original = output.read_bytes()
    output.unlink()
    assert h.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block) is None

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "unchanged verified source needs delivery repair, not repeated proof review"
        )

    monkeypatch.setattr(module, "review_partial_request", forbidden)
    assert await h.worker._export(h.owner, h.slot, h.block + 1) is False
    assert output.read_bytes() == original
    assert h.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block + 1) == key


async def test_model_partial_export_keeps_inventory_continuation_and_completion(
    model_partial_export,
):
    h = model_partial_export
    calls = []
    original = h.worker._partial

    async def inventory(owner, slot, block, **kwargs):
        calls.append(kwargs.get("manifest_key"))
        return await original(owner, slot, block, **kwargs)

    h.worker._partial = inventory
    assert await h.worker._export(h.owner, h.slot, h.block + 1) is False
    assert calls and calls[-1] is not None
    for _ in range(step_count(h.e.job) - 1):
        h.e.r.h.block += 1
        await h.executor.advance(h.e.assignment)
    block = h.e.r.h.block
    assert h.files.current_model_partial(h.owner, h.slot, completed_by_block=block) is None
    assert await h.worker._export(h.owner, h.slot, block) is True
    assert len(h.e.calls) == step_count(h.e.job)


async def test_model_partial_export_changed_context_and_damaged_checkpoint_reconstruct(
    model_partial_export, monkeypatch
):
    from umi.competition_cohort_request_files import RequestCompletionFiles

    h = model_partial_export
    checkpoint = h.files._model_partials.load(h.owner, h.slot)
    assert not h.owner.partial_export_unchanged(
        checkpoint.model_copy(update={"context_sha256": "ff" * 32})
    )
    assert not h.owner.partial_export_unchanged(checkpoint.model_copy(update={"owner_inode": "0"}))
    assert h.files.current_model_partial(h.owner, h.slot, completed_by_block=0) is None
    smaller = RequestCompletionFiles(h.files.root, maximum_bytes=h.files.maximum_bytes // 2)
    assert smaller.current_model_partial(h.owner, h.slot, completed_by_block=h.block) is None
    path = h.files._model_partials.root / (h.files._model_partials.key(h.owner, h.slot) + ".json")
    path.write_bytes(b"{damaged")
    h.worker.files = RequestCompletionFiles(h.files.root)
    assert await h.worker._export(h.owner, h.slot, h.block + 1) is False
    assert (
        h.worker.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block + 1)
        is not None
    )


async def test_model_partial_export_legacy_native_abi_refuses_upgrade_hint(
    model_partial_export, monkeypatch
):
    import umi.competition_cohort_request_files as module

    h = model_partial_export
    for path in h.files._model_partials.root.glob("*.json"):
        path.unlink()
    h.worker.files = module.RequestCompletionFiles(h.files.root)
    monkeypatch.setattr(module, "legacy_publication_compatible", lambda: False)
    assert h.worker.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block) is None
    reviewed = []
    original = module.review_partial_request

    def review(*args, **kwargs):
        reviewed.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "review_partial_request", review)
    assert await h.worker._export(h.owner, h.slot, h.block + 1) is False
    assert len(reviewed) == 1


async def test_model_partial_export_missing_completed_source_requires_repair(
    model_partial_export, monkeypatch, caplog
):
    from umi.competition_cohort_execution_journal import PartialExportSourceRepairRequired

    h = model_partial_export
    checkpoint = h.files._model_partials.load(h.owner, h.slot)
    with h.owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='step' AND id=?", (checkpoint.step_keys[0],))

    def forbidden(*args, **kwargs):
        raise AssertionError("lost completed work must not silently fall through to recollection")

    monkeypatch.setattr(h.owner, "evidence", forbidden)
    with pytest.raises(PartialExportSourceRepairRequired, match="completed_step_missing"):
        await h.worker._export(h.owner, h.slot, h.block + 1)
    assert '"status":"repair_required"' in caplog.text


async def test_model_partial_export_upgrade_repairs_lost_output_from_retained_verdict(
    model_partial_export, monkeypatch
):
    import umi.competition_cohort_request_files as module

    h = model_partial_export
    key = h.files.current_model_partial(h.owner, h.slot, completed_by_block=h.block)
    output = h.files.objects._path(key)
    original = output.read_bytes()
    output.unlink()
    for path in h.files._model_partials.root.glob("*.json"):
        path.unlink()
    h.worker.files = module.RequestCompletionFiles(h.files.root)

    def forbidden(*args, **kwargs):
        raise AssertionError("retained exact native verdict should survive lost delivery metadata")

    monkeypatch.setattr(module, "review_partial_request", forbidden)
    assert await h.worker._export(h.owner, h.slot, h.block + 1) is False
    assert output.read_bytes() == original


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
    with e.journal().locked(e.r.slot):
        assert canonical_json_bytes(await e.executor().advance(e.assignment)) == original
    assert len(e.calls) == step_count(e.job) and not e.stops


async def test_resident_batch_reuses_completed_steps_and_native_evidence(execution, caplog):
    import json
    import logging

    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    e = execution
    executor = e.executor()
    await executor.advance(e.assignment)
    original = canonical_json_bytes(executor.journal.step(e.job, 0))
    scopes = []

    @asynccontextmanager
    async def execution_scope(order):
        scopes.append(order)
        yield True

    e.port.execution_scope = execution_scope
    e.r.h.block += 1
    evidence = await executor.advance_batch(e.assignment)
    assert evidence is not None and len(e.calls) == step_count(e.job)
    assert canonical_json_bytes(executor.journal.step(e.job, 0)) == original
    observe(e.r.h.batch["scenarios"][0], evidence)
    e.r.h.fail_collect = True
    assert canonical_json_bytes(await executor.advance_batch(e.assignment)) == canonical_json_bytes(
        evidence
    )
    assert len(scopes) == 1
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    batch = [event for event in events if event.get("stage") == "model_pair_execution"]
    assert batch[-1]["completed_units"] == batch[-1]["total_units"] == step_count(e.job)
    assert batch[-1]["restored_units"] == 1
    assert batch[-1]["status"] == "completed"
    assert all("eta_basis" in event and "elapsed_seconds" in event for event in batch)


async def test_batch_cancellation_releases_scope_and_resumes_same_journal(execution):
    e = execution
    executor = e.executor()
    mutex = asyncio.Lock()
    entered = asyncio.Event()

    @asynccontextmanager
    async def execution_scope(order):
        async with mutex:
            entered.set()
            yield True

    e.port.execution_scope = execution_scope
    original = e.port.invoke
    first = True

    async def invoke(job, attempt):
        nonlocal first
        if first:
            first = False
            await asyncio.Event().wait()
        return await original(job, attempt)

    e.port.invoke = invoke
    task = asyncio.create_task(executor.advance_batch(e.assignment))
    await asyncio.wait_for(entered.wait(), 2)
    # Allow the first attempt to reach its cancellable sandbox.
    for _ in range(200):
        if not first:
            break
        await asyncio.sleep(0.01)
    assert not first
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not mutex.locked()
    evidence = await executor.advance_batch(e.assignment)
    assert evidence is not None and len(e.calls) == step_count(e.job)
    assert len(e.stops) == 1


async def test_worker_finishes_resident_pair_without_rotating_after_each_step(execution):
    e = execution

    @asynccontextmanager
    async def execution_scope(order):
        yield order.submission.submission.track == "model"

    e.port.execution_scope = execution_scope
    report = await e.worker().poll_once()
    assert report["retry_count"] == 0
    if e.job.mode == "paired_model":
        assert report["jobs_complete"] == 1
        assert len(e.calls) == step_count(e.job)
    else:
        assert report["steps_advanced"] == 1
        assert len(e.calls) == 1


async def test_completed_execution_uses_bounded_snapshots_and_fresh_conflict_checks(
    execution, monkeypatch
):
    from contextlib import contextmanager

    e = execution
    executor = e.executor()
    for _ in range(step_count(e.job)):
        e.r.h.block += 1
        await executor.advance(e.assignment)
    journal = executor.journal
    expected = canonical_json_bytes(journal.evidence(e.r.slot))
    transactions = 0
    original = journal.journal.read_transaction

    @contextmanager
    def counted():
        nonlocal transactions
        transactions += 1
        with original() as db:
            yield db

    monkeypatch.setattr(journal.journal, "read_transaction", counted)
    assert canonical_json_bytes(journal.evidence(e.r.slot)) == expected
    # Assignment and reuse lookup may have their own snapshots, but a full
    # completed result must not open three more connections for every step.
    assert transactions <= 3
    from umi.competition_cohort_execution_journal import execution_step_key

    key = execution_step_key(e.job, 0)
    with pytest.raises(ValueError, match="conflict"):
        journal.journal.put("step", key, {"changed": True})
    with pytest.raises(ValueError, match="conflict"):
        journal.evidence(e.r.slot)


async def test_unfinished_execution_still_requires_the_job_writer_lock(execution):
    from umi.private_files import PrivateStateBusyError

    e = execution
    with e.journal().locked(e.r.slot), pytest.raises(PrivateStateBusyError):
        await e.executor().advance(e.assignment)
    assert not e.calls and e.journal().journal.get("assignment", e.r.slot) is None


async def test_retained_attempt_head_does_not_wait_for_unrelated_writer(execution):
    from concurrent.futures import ThreadPoolExecutor

    e = execution
    executor = e.executor()
    source, started = await executor.current(e.assignment)
    journal = executor.journal
    job = journal.retain(e.assignment, source, started.block)
    attempt = journal.begin(job, 0, source, started)
    with ThreadPoolExecutor(max_workers=1) as pool, journal.journal.transaction():
        read = pool.submit(journal.head, job, 0)
        assert read.result(timeout=5) == attempt


async def test_endpoint_worker_can_defer_incumbent_until_miner_terminal(execution):
    e = execution
    worker = e.worker(defer_endpoint_until_terminal=True)
    first = await worker.poll_once()
    if e.job.mode != "endpoint_incumbent":
        assert first["jobs_deferred"] == 0 and len(e.calls) == 1
        return

    assert first["status"] == "cohort_execution_pending"
    assert first["jobs_deferred"] == 1
    assert first["last_deferred_reason"] == "endpoint_terminal_pending"
    assert first["retry_count"] == 0
    assert not e.calls
    assert e.journal().journal.get("assignment", e.r.slot) is None

    # The endpoint worker owns and validates this record. Execution only uses
    # its presence as the scheduling fence before beginning local inference.
    e.journal().journal.put("endpoint_terminal_selection", e.r.slot, {"terminal": True})
    e.r.h.block += 1
    second = await worker.poll_once()
    assert second["jobs_deferred"] == 0
    assert second["steps_advanced"] == 1
    assert len(e.calls) == 1


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


async def test_static_authority_review_survives_new_heads_and_owner_restart(execution, monkeypatch):
    from umi import competition_cohort_order_signer as native

    e = execution
    native_history = native.replay_cohort_decisions
    native_body = native.verify_recoverable_order_body
    calls = {"history": 0, "body": 0, "capture": 0}

    def history(*args, **kwargs):
        calls["history"] += 1
        return native_history(*args, **kwargs)

    def body(*args, **kwargs):
        calls["body"] += 1
        return native_body(*args, **kwargs)

    executor = e.executor()
    collect = executor.provider.collect

    async def capture():
        calls["capture"] += 1
        return await collect()

    monkeypatch.setattr(native, "replay_cohort_decisions", history)
    monkeypatch.setattr(native, "verify_recoverable_order_body", body)
    monkeypatch.setattr(executor.provider, "collect", capture)
    await executor.current(e.assignment)
    assert calls == {"history": 1, "body": 1, "capture": 1}
    e.r.h.block += 1
    await executor.current(e.assignment)
    e.r.h.block += 1
    await e.executor().current(e.assignment)
    assert calls == {"history": 1, "body": 1, "capture": 3}
    # Legacy callers without a selected durable owner still review the source
    # only once within their operation.
    native.review_order(
        e.assignment.certificate.order,
        e.assignment.participant,
        e.r.h.source,
        executor.journal.policy,
        e.r.h.block,
    )
    assert calls == {"history": 2, "body": 2, "capture": 3}


async def test_closed_history_is_a_durable_denial_without_fresh_registration(execution):
    e = execution
    await e.executor().advance(e.assignment)
    old = e.r.h.source
    prior = e.journal().step(e.job, 0)
    with e.journal().journal.read_transaction() as db:
        highwater = db.execute("SELECT block FROM highwater").fetchall()
    e.r.h.source = source_for(e.r.h.batch, e.r.h.batch["history"])
    e.r.h.fail_collect = True
    for _ in range(2):
        with pytest.raises(ValueError, match="open request phase"):
            await e.executor().current(e.assignment)
    assert e.journal().step(e.job, 0) == prior
    assert e.journal().assignment(e.r.slot) == e.assignment
    with e.journal().journal.read_transaction() as db:
        assert db.execute("SELECT block FROM highwater").fetchall() == highwater
    e.r.h.fail_collect = False
    e.r.h.source = old
    with pytest.raises(ValueError, match="rolled back"):
        await e.executor().current(e.assignment)
    assert len(e.calls) == 1


async def test_cached_order_review_still_rejects_changed_participant(execution):
    e = execution
    executor = e.executor()
    await executor.current(e.assignment)
    participant = e.assignment.participant
    snapshot = participant.admission_snapshot.model_copy(update={"block": 0})
    changed = e.assignment.model_copy(
        update={"participant": participant.model_copy(update={"admission_snapshot": snapshot})}
    )
    with pytest.raises(ValueError):
        await executor.current(changed)
    assert not e.calls


async def test_prepared_scope_never_materializes_an_invalid_assignment(execution):
    e = execution
    entered = []

    @asynccontextmanager
    async def scope(job):
        entered.append(job)
        yield True

    e.port.execution_scope = scope
    e.port.prepared_execution_scope = True
    changed = e.assignment.model_copy(
        update={
            "certificate": e.assignment.certificate.model_copy(
                update={"signatures": e.assignment.certificate.signatures[:1]}
            )
        }
    )
    with pytest.raises(ValueError):
        await e.executor().advance_batch(changed)
    assert not entered and not e.calls


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
    if e.job.mode == "endpoint_incumbent":
        # Qualify independent legacy work: an already retained invocation cannot
        # be adopted as a shared source or borrow another job's execution.
        legacy = e.box.assignment(slots[0])
        executor = e.executor()
        source, started = await executor.current(legacy)
        job = executor.journal.retain(legacy, source, started.block)
        executor.journal.begin(job, 0, source, started)
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


@pytest.mark.parametrize("rolling", [False, True])
async def test_restart_prefers_resident_unfinished_model_without_moving_cursor(
    execution, rolling, tmp_path
):
    e = execution
    if e.job.mode != "paired_model":
        pytest.skip("resident model scheduling applies to public model jobs")
    r, batch = e.r, e.r.h.batch
    participant = batch["roster"].participants[1]
    second = signed_order(batch["scenarios"][1]).order
    r.queue().select(
        second,
        CohortOrderParticipant(
            consent=participant.record.request.consent,
            admission=participant.admission,
            admission_snapshot=participant.record.snapshot,
        ),
        r.h.source,
        await r.capture(),
    )
    await r.worker().poll_once()
    assert len(e.box.assignments()) == 2
    await e.executor().advance(e.assignment)
    assert len(e.calls) == 1
    journal = e.journal().journal
    with journal.transaction() as db:
        db.execute("DELETE FROM execution_cursor")
        db.execute("INSERT INTO execution_cursor VALUES (?)", (r.slot,))
    from umi.competition_cohort_sandbox import DirectCohortCpuSandbox

    inventory_calls = []
    e.port.cache = tmp_path / "resident-cache"
    e.port.parallel = None
    warm = e.port.cache / "archive" / e.job.submission.submission.model_revision
    warm.mkdir(parents=True)
    # Other cache files and symlinks must not become scheduling inputs.
    (warm.parent / ("ff" * 32)).symlink_to(warm, target_is_directory=True)
    (warm.parent / "unrelated-metadata").write_bytes(b"not model evidence")

    def inventory():
        inventory_calls.append(True)
        return DirectCohortCpuSandbox.resume_model_revisions(e.port)

    e.port.resume_model_revisions = inventory
    worker = e.worker(batch_size=1, concurrency=1)
    if rolling:
        active = {}
        await worker._rolling_poll(active)
        assert tuple(active) == (r.slot,)
        await asyncio.gather(*active.values())
    else:
        assert (await worker.poll_once())["retry_count"] == 0
    assert len(e.calls) == 2
    assert [attempt.step_index for attempt in e.calls] == [0, 1]
    with journal.read_transaction() as db:
        assert db.execute("SELECT slot FROM execution_cursor").fetchall() == [(r.slot,)]
    # A preference is consumed once; the ordinary cursor then admits its peer.
    if rolling:
        await worker._rolling_poll(active)
        assert len(active) == 1 and r.slot not in active
        await asyncio.gather(*active.values())
    else:
        assert (await worker.poll_once())["retry_count"] == 0
    assert len(e.calls) == 3 and e.calls[-1].job_sha256 != digest(e.job)
    assert inventory_calls == [True]


async def test_startup_inventory_failure_cannot_block_ordinary_work(execution, caplog):
    e = execution

    def broken_inventory():
        raise OSError("fixture inventory unavailable")

    e.port.resume_model_revisions = broken_inventory
    assert (await e.worker().poll_once())["retry_count"] == 0
    assert len(e.calls) == 1
    assert "execution_retry" in caplog.text


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


async def test_slow_case_does_not_block_another_jobs_next_native_step(execution):
    e = execution
    r, b = e.r, e.r.h.batch
    participant = b["roster"].participants[1]
    second = signed_order(b["scenarios"][1]).order
    r.queue().select(
        second,
        CohortOrderParticipant(
            consent=participant.record.request.consent,
            admission=participant.admission,
            admission_snapshot=participant.record.snapshot,
        ),
        r.h.source,
        await r.capture(),
    )
    await r.worker().poll_once()
    slots = e.box.assignments()
    assert len(slots) == 2
    if e.job.mode == "endpoint_incumbent":
        # Qualify independent legacy work: an already retained invocation cannot
        # be adopted as a shared source or borrow another job's execution.
        legacy = e.box.assignment(slots[0])
        executor = e.executor()
        source, started = await executor.current(legacy)
        job = executor.journal.retain(legacy, source, started.block)
        executor.journal.begin(job, 0, source, started)
    slow_submission = e.box.assignment(slots[0]).certificate.order.submission
    fast_slot = slots[1]
    slow_entered, release_slow, fast_second_step = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )
    stop = asyncio.Event()
    invoke = e.port.invoke
    active, maximum_active = 0, 0
    slow_calls = 0

    async def selective(job, attempt):
        nonlocal active, maximum_active, slow_calls
        active += 1
        maximum_active = max(maximum_active, active)
        try:
            if job.submission == slow_submission:
                slow_calls += 1
                slow_entered.set()
                await release_slow.wait()
            elif attempt.step_index == 1:
                # The real executor must have committed step zero before this
                # second sandbox invocation. No synthetic completion shortcut.
                assert e.journal().step(job, 0) is not None
                fast_second_step.set()
            return await invoke(job, attempt)
        finally:
            active -= 1

    e.port.invoke = selective
    worker = e.worker(concurrency=2)
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01))
    try:
        await asyncio.wait_for(slow_entered.wait(), 30)
        await asyncio.wait_for(fast_second_step.wait(), 30)
        assert not release_slow.is_set()
        assert slow_calls == 1 and maximum_active <= 2
        assert e.journal().journal.get("assignment", fast_slot) is not None
    finally:
        stop.set()
        release_slow.set()
        await asyncio.wait_for(task, 60)


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


async def test_execution_retry_reports_native_boundary_without_exception_text(
    execution, monkeypatch
):
    from umi import competition_progress

    e = execution
    reports = []
    monkeypatch.setattr(competition_progress, "_emit", lambda body, **kw: reports.append(body))

    async def unavailable(_):
        raise OSError("https://private.example/secret-token")

    worker = e.worker()
    worker.executor.history = unavailable
    assert (await worker.poll_once())["retry_count"] == 1
    retry = next(r for r in reports if r["event"] == "execution_retry")
    assert retry["slot"] == e.r.slot
    assert retry["eta_basis"] == "retry_requires_new_progress_sample"
    assert any(f["function"] == "_current" for f in retry["causes"][0]["source_frames"])
    assert "secret-token" not in str(reports)
    assert not e.calls


async def test_execution_stages_report_current_cohort_and_preserve_native_result(
    execution, monkeypatch
):
    import json
    import logging

    from umi import competition_work_progress

    e = execution
    reports = []

    class Capture(logging.Handler):
        def emit(self, record):
            reports.append(json.loads(record.getMessage()))

    logger = logging.Logger("execution-progress-test", level=logging.INFO)
    logger.addHandler(Capture())
    monkeypatch.setattr(competition_work_progress, "_LOG", logger)
    result = await e.worker().poll_once()
    assert result["retry_count"] == 0 and len(e.calls) == 1
    expected = {
        "execution_owner_history",
        "execution_history_phase",
        "execution_registration_capture",
        "execution_history_review",
        "execution_order_review",
        "execution_history_freshness",
        "execution_sandbox",
    }
    assert expected <= {r["stage"] for r in reports if r["state"] == "completed"}
    assert all(r["cohort_sha256"] == e.job.round.cohort_sha256 for r in reports)
    assert all(r["certification_authority"] is False for r in reports)


def test_case_wait_preserves_preparation_and_full_signed_inference_budgets(policy):
    from umi.competition_cohort_executor import job_policy_timeout

    signed = canonical_json_bytes(policy)
    for read_budget in (120, 3600):
        journal = SimpleNamespace(
            policy=policy, config=SimpleNamespace(read_timeout_seconds=read_budget)
        )
        assert job_policy_timeout(journal) >= read_budget + policy.maximum_inference_ms / 1000
    assert canonical_json_bytes(policy) == signed
