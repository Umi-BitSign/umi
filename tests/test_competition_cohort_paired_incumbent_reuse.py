"""Synthetic execution proves shared originals without repeating model inference."""

from contextlib import asynccontextmanager

import pytest

from umi.competition_cohort_execution import (
    RecoverableExecutionEvidence,
    RecoverableSharedIncumbentEvidence,
    paired_incumbent_scope,
    replay_execution_steps,
)
from umi.competition_cohort_execution_journal import execution_step_key, incumbent_scope, step_count
from umi.competition_cohort_orders import recoverable_order_job
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_executor as executor_fixtures
from .test_competition_cohort_execution import observe
from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_executor import scenario as scenario
from .test_competition_cohort_incumbent_reuse import other_assignment

original_harness = executor_fixtures.harness


@pytest.fixture
def harness(original_harness):
    h = original_harness
    if h.order.submission.submission.track == "model":
        h.order = h.order.model_copy(
            update={
                "schema_": "umi-recoverable-evaluation-order/2",
                "incumbent_observation_mode": "first_reserved_per_scope/1",
            }
        )
    return h


def paired(e):
    if e.job.mode != "paired_model":
        pytest.skip("paired model reuse only")
    return e.executor(share_paired_incumbent=True)


async def finish(e, assignment):
    executor = paired(e)
    for _ in range(step_count(e.job)):
        e.r.h.block += 1
        result = await executor.advance(assignment)
        if result is not None:
            return result
    raise AssertionError("retained job did not complete")


async def test_paired_source_runs_once_and_original_boundaries_survive_restart(execution):
    e = execution
    executor = paired(e)
    first = await finish(e, e.assignment)
    original = canonical_json_bytes(first)
    assert isinstance(first, RecoverableExecutionEvidence)
    assignment, _slot, scenario = await other_assignment(e)
    second = await finish(e, assignment)
    assert isinstance(second, RecoverableSharedIncumbentEvidence)
    assert len(e.calls) == 3 * len(e.job.cases)
    assert second.incumbent_source == first
    assert second.steps[1::2] == first.steps[1::2]
    assert all(
        executor.journal.head(second.job, index) is None
        for index in range(1, step_count(second.job), 2)
    )
    assert canonical_json_bytes(executor.journal.evidence(e.r.slot)) == original
    view = observe(scenario, second)
    assert view.incumbent == observe(e.r.h.batch["scenarios"][0], first).incumbent
    with pytest.raises(ValueError):
        RecoverableExecutionEvidence.model_validate_json(canonical_json_bytes(second))
    with pytest.raises(ValueError, match="rolled back"):
        replay_execution_steps(
            second.job,
            second.steps,
            e.r.h.batch["policy"],
            started_after=0,
            finished_by=e.r.h.block,
        )
    e.r.h.fail_collect = True
    # Disabling emission still reads and resumes already selected /2 artifacts.
    assert canonical_json_bytes(await e.executor().advance(assignment)) == canonical_json_bytes(
        second
    )
    assert len(e.calls) == 3 * len(e.job.cases)
    assert executor.journal.checkpoint_count(second.job) == step_count(second.job)


async def test_unfinished_paired_source_holds_consumers_without_reselection(execution):
    e = execution
    executor = paired(e)
    await executor.advance(e.assignment)
    assignment, slot, _ = await other_assignment(e)
    with pytest.raises(OSError, match="source remains unfinished"):
        await paired(e).advance(assignment)
    assert len(e.calls) == 1
    assert (
        e.journal().journal.get("incumbent_source", incumbent_scope(e.job))["source_slot"]
        == e.r.slot
    )
    assert e.journal().evidence(slot) is None
    assert (
        e.journal().head(recoverable_order_job(assignment.certificate.order, e.cfg.signer), 0)
        is None
    )


async def test_disabled_evaluator_holds_new_mode_but_resumes_selected_source_and_consumer(
    execution,
):
    e = execution
    executor = paired(e)
    with pytest.raises(OSError, match="reader-enabled producer"):
        await e.executor().advance(e.assignment)
    assert not e.calls and e.journal().head(e.job, 0) is None
    await executor.advance(e.assignment)
    source_attempt = canonical_json_bytes(e.journal().head(e.job, 0))
    for _ in range(step_count(e.job) - 1):
        e.r.h.block += 1
        original = await e.executor().advance(e.assignment)
    assert isinstance(original, RecoverableExecutionEvidence)
    assert canonical_json_bytes(e.journal().head(e.job, 0)) == source_attempt
    assignment, slot, _ = await other_assignment(e)
    calls = len(e.calls)
    with pytest.raises(OSError, match="reader-enabled producer"):
        await e.executor().advance(assignment)
    assert len(e.calls) == calls
    e.r.h.block += 1
    await executor.advance(assignment)
    for _ in range(len(e.job.cases) - 1):
        e.r.h.block += 1
        second = await e.executor().advance(assignment)
    assert isinstance(second, RecoverableSharedIncumbentEvidence)
    assert second.incumbent_source == original
    assert len(e.calls) == 3 * len(e.job.cases)
    assert e.journal().evidence(slot) == second


async def test_source_failures_are_reused_without_favorable_reselection(execution):
    e = execution
    paired(e)
    e.miner_failure = True
    first = await finish(e, e.assignment)
    e.miner_failure = False
    assignment, _, scenario = await other_assignment(e)
    second = await finish(e, assignment)
    assert all(step.execution.output.status == "miner_failure" for step in second.steps[1::2])
    assert all(step.execution.output.status == "ok" for step in second.steps[::2])
    assert second.incumbent_source == first
    observe(scenario, second)
    assert len(e.calls) == 3 * len(e.job.cases)


@pytest.mark.parametrize(
    "damage", ["source_step", "consumer_step", "source_reservation", "reuse_record"]
)
async def test_missing_known_shared_evidence_requires_repair_without_new_inference(
    execution, damage
):
    e = execution
    paired(e)
    await finish(e, e.assignment)
    assignment, _slot, _ = await other_assignment(e)
    second = await finish(e, assignment)
    owner = e.journal()
    kind, key = {
        "source_step": ("step", execution_step_key(e.job, 1)),
        "consumer_step": ("step", execution_step_key(second.job, 1)),
        "source_reservation": ("incumbent_source", incumbent_scope(e.job)),
        "reuse_record": ("incumbent_reuse", digest(second.job)),
    }[damage]
    with owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, key))
    calls = len(e.calls)
    with pytest.raises(ValueError):
        await paired(e).advance(assignment)
    assert len(e.calls) == calls


async def test_paired_reuse_batch_reports_all_observations_but_invokes_only_candidates(
    execution, caplog
):
    import json
    import logging

    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    e = execution
    paired(e)
    await finish(e, e.assignment)
    assignment, _, _ = await other_assignment(e)

    @asynccontextmanager
    async def scope(order):
        yield True

    e.port.execution_scope = scope
    result = await paired(e).advance_batch(assignment)
    assert isinstance(result, RecoverableSharedIncumbentEvidence)
    assert len(e.calls) == 3 * len(e.job.cases)
    reports = [
        json.loads(record.message) for record in caplog.records if record.message.startswith("{")
    ]
    reports = [row for row in reports if row.get("stage") == "model_pair_execution"]
    assert reports[-1]["completed_units"] == reports[-1]["total_units"] == step_count(e.job)
    assert reports[-1]["status"] == "completed"
    assert reports[-1]["restored_units"] == len(e.job.cases)
    assert reports[-1]["native_units"] == len(e.job.cases)
    assert all("eta_basis" in row and "elapsed_seconds" in row for row in reports)


@pytest.mark.parametrize("field", ["round", "preparation", "runtime", "cases", "evaluator"])
async def test_paired_scope_invalidates_only_changed_execution_dependencies(execution, field):
    e = execution
    paired(e)
    job = e.job
    if field == "round":
        changed = job.model_copy(
            update={"round": job.round.model_copy(update={"suite_sha256": "ab" * 32})}
        )
    elif field == "preparation":
        changed = job.model_copy(update={"preparation_closure_sha256": "ab" * 32})
    elif field == "runtime":
        changed = job.model_copy(update={"runtime": job.runtime.model_copy(update={"cpus": 5})})
    elif field == "cases":
        changed = job.model_copy(update={"cases": tuple(reversed(job.cases))})
    else:
        changed = job.model_copy(update={"evaluator_hotkey": job.submission.submission.hotkey})
    assert paired_incumbent_scope(changed) != paired_incumbent_scope(job)


async def test_disabled_reuse_preserves_existing_config_and_journal_binding(execution):
    e = execution
    original = canonical_json_bytes(e.cfg)
    assert b"share_paired_incumbent" not in original
    assert canonical_json_bytes(type(e.cfg).model_validate_json(original)) == original
    owner = e.journal()
    enabled = e.journal(share_paired_incumbent=True)
    assert enabled.journal.path == owner.journal.path
    assert b'"share_paired_incumbent":true' in canonical_json_bytes(enabled.config)


async def test_embedded_shared_observation_authenticates_original_source_assignment(execution):
    import json

    e = execution
    paired(e)
    await finish(e, e.assignment)
    assignment, _, scenario = await other_assignment(e)
    evidence = await finish(e, assignment)
    original = json.loads(evidence.source_assignment_json)
    original["certificate"]["signatures"] = []
    changed = evidence.model_copy(
        update={
            "source_assignment_json": canonical_json_bytes(original).decode(),
        }
    )
    with pytest.raises(ValueError):
        observe(scenario, changed)


async def test_embedded_shared_observation_authenticates_consumer_assignment(execution):
    import json

    e = execution
    paired(e)
    await finish(e, e.assignment)
    assignment, _, scenario = await other_assignment(e)
    evidence = await finish(e, assignment)
    original = json.loads(evidence.consumer_assignment_json)
    original["certificate"]["signatures"] = []
    changed = evidence.model_copy(
        update={"consumer_assignment_json": canonical_json_bytes(original).decode()}
    )
    with pytest.raises(ValueError):
        observe(scenario, changed)


async def test_shared_partial_restart_reuses_verdict_and_missing_source_requires_repair(
    execution, tmp_path, monkeypatch
):
    from umi import competition_cohort_request_files as files_module
    from umi.competition_cohort_execution_journal import PartialExportSourceRepairRequired

    from .test_competition_shared_incumbent_archives import seal

    e = execution
    executor = paired(e)
    await finish(e, e.assignment)
    await seal(e, e.r.slot)
    assignment, slot, _ = await other_assignment(e)
    e.r.h.block += 1
    await executor.advance(assignment)
    owner = e.journal()
    files = files_module.RequestCompletionFiles(tmp_path / "shared-partials")
    key = files.publish_partial(owner, slot, completed_by_block=e.r.h.block)
    calls = len(e.calls)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unchanged shared source must not repeat native collection")

    monkeypatch.setattr(owner, "evidence", forbidden)
    monkeypatch.setattr(files_module, "collect_partial_request_with_inputs", forbidden)
    restored = files_module.RequestCompletionFiles(files.root)
    assert restored.current_model_partial(owner, slot, completed_by_block=e.r.h.block) == key
    source_key = execution_step_key(e.job, 1)
    with owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='step' AND id=?", (source_key,))
    with pytest.raises(PartialExportSourceRepairRequired, match="shared_source"):
        restored.current_model_partial(owner, slot, completed_by_block=e.r.h.block)
    assert len(e.calls) == calls


async def test_concurrent_first_jobs_reserve_one_source_without_conflict_hold(
    execution, monkeypatch
):
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from umi.private_files import PrivateStateBusyError

    e = execution
    executor = paired(e)
    source, started = await executor.current(e.assignment)
    first = executor.journal.retain(e.assignment, source, started.block)
    assignment, slot, _ = await other_assignment(e)
    peer = paired(e)
    source2, started2 = await peer.current(assignment)
    second = peer.journal.retain(assignment, source2, started2.block)
    entered, release = Event(), Event()
    original = executor.journal._incumbent_source

    def held(job):
        entered.set()
        assert release.wait(30)
        return original(job)

    monkeypatch.setattr(executor.journal, "_incumbent_source", held)
    with ThreadPoolExecutor(max_workers=1) as pool:
        selected = pool.submit(executor.journal.reuse_incumbent, e.r.slot, first, started)
        try:
            assert await asyncio.to_thread(entered.wait, 10)
            with pytest.raises(PrivateStateBusyError):
                peer.journal.reuse_incumbent(slot, second, started2)
        finally:
            release.set()
        assert await asyncio.wrap_future(selected) is None
    fixed = peer.journal._incumbent_source(second)
    assert fixed.source_job_sha256 == digest(first)
    with pytest.raises(OSError, match="source remains unfinished"):
        peer.journal.reuse_incumbent(slot, second, started2)
    with peer.journal.journal.read_transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM holds").fetchone()[0] == 0
    assert not e.calls
