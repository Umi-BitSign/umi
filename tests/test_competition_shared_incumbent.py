from __future__ import annotations

import asyncio
import sqlite3

import pytest

from tests.test_competition_execution import boundary
from tests.test_competition_execution import setup as setup
from tests.test_competition_runner import runtime as runtime
from tests.test_open_competition import policy as policy
from tests.test_open_competition import round_for, submission, wallet
from umi import competition_execution as execution
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


@pytest.fixture
def shared(setup):
    policy, paired, suite, archive, videos, calls = setup
    submissions = (submission(policy), submission(policy, name="Bob"))
    round_ = round_for(policy, suite, submissions, incumbent=digest(paired.incumbent))
    jobs = tuple(
        execution.EndpointIncumbentJob(
            schema="umi-endpoint-incumbent-job/1",
            round=round_,
            submission=signed,
            incumbent=paired.incumbent,
            runtime=paired.runtime,
            evaluator_hotkey=paired.evaluator_hotkey,
            cases=paired.cases,
        )
        for signed in submissions
    )
    return policy, jobs, archive, videos, calls


async def run(shared, tmp_path, *, job=None, source=None, prepare=None, **limits):
    policy, jobs, archive, videos, _ = shared
    journal = execution.ExecutionJournal(tmp_path / "shared", policy, **limits)

    async def capture():
        return boundary()

    result = await execution.run_endpoint_incumbent(
        job=job or jobs[0],
        policy=policy,
        archive=archive,
        videos=videos,
        journal=journal,
        boundary_provider=source or capture,
        prepare_boundaries=prepare,
    )
    return result, journal


async def forbidden(*args, **kwargs):
    raise AssertionError("reused incumbent performed external work")


async def test_two_miners_share_exact_baseline_receipts_across_restart(
    shared, tmp_path, monkeypatch
):
    policy, jobs, _, _, calls = shared
    first, journal = await run(shared, tmp_path)
    assert len([c for c in calls if isinstance(c, dict)]) == len(jobs[0].cases)
    monkeypatch.setattr(execution, "verify_runtime", forbidden)
    monkeypatch.setattr(execution, "execute_offline_case", forbidden)
    second, journal = await run(shared, tmp_path, job=jobs[1], source=forbidden, prepare=forbidden)
    assert second.job == jobs[1]
    assert second.steps == first.steps
    assert digest(second) != digest(first)
    execution.validate_execution(second, policy)
    assert not second.chain_submission_authorized
    assert journal.status(execution.execution_key(jobs[1]))["status"] == "complete"
    for job, original in zip(jobs, (first, second), strict=True):
        retried, _ = await run(shared, tmp_path, job=job, source=forbidden)
        assert canonical_json_bytes(retried) == canonical_json_bytes(original)
    with sqlite3.connect(journal.path) as db:
        assert db.execute("SELECT source_job FROM endpoint_incumbents").fetchall() == [
            (execution.execution_key(jobs[0]),)
        ]


@pytest.mark.parametrize("change", ["round", "evaluator"])
async def test_reuse_never_crosses_round_or_evaluator(shared, tmp_path, change):
    _, jobs, _, _, calls = shared
    await run(shared, tmp_path)
    job = jobs[1]
    if change == "round":
        job = job.model_copy(update={"round": job.round.model_copy(update={"sequence": 2})})
    else:
        job = job.model_copy(update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address})
    await run(shared, tmp_path, job=job)
    assert len([c for c in calls if isinstance(c, dict)]) == 2 * len(job.cases)


@pytest.mark.parametrize("change", ["order", "case_id", "video"])
async def test_changed_case_inputs_hold_without_second_attempt(shared, tmp_path, change):
    _, jobs, _, _, calls = shared
    first, journal = await run(shared, tmp_path)
    cases = list(jobs[1].cases)
    if change == "order":
        cases.reverse()
    else:
        field = "case_id" if change == "case_id" else "video_sha256"
        cases[0] = cases[0].model_copy(update={field: "ab" * 32})
    changed = jobs[1].model_copy(update={"cases": tuple(cases)})
    with pytest.raises(ValueError, match="assignment conflicts"):
        await run(shared, tmp_path, job=changed)
    assert len([c for c in calls if isinstance(c, dict)]) == len(first.steps)
    assert journal.status(execution.execution_key(changed))["status"] == "failed"
    assert journal.reserve(jobs[0]) == first


@pytest.mark.parametrize("failure", ["runtime", "cancelled", "boundary"])
async def test_failed_source_cannot_be_retried_through_another_miner(
    shared, tmp_path, monkeypatch, failure
):
    _, jobs, _, _, calls = shared
    count = 0

    async def fail_runtime(*args, **kwargs):
        if failure == "cancelled":
            raise asyncio.CancelledError()
        raise RuntimeError("test infrastructure failure")

    async def capture():
        nonlocal count
        count += 1
        if count == 2:
            raise RuntimeError("finished boundary unavailable")
        return boundary()

    if failure != "boundary":
        monkeypatch.setattr(execution, "verify_runtime", fail_runtime)
    with pytest.raises((RuntimeError, asyncio.CancelledError)):
        await run(shared, tmp_path, source=capture)
    executed = len(calls)
    with pytest.raises(ValueError, match="incomplete or failed"):
        await run(shared, tmp_path, job=jobs[1])
    assert len(calls) == executed


async def test_old_journal_evidence_is_preserved_but_not_retroactively_selected(shared, tmp_path):
    _, jobs, _, _, calls = shared
    first, journal = await run(shared, tmp_path)
    # A historical journal has jobs/steps but no shared-attempt reservation.
    with sqlite3.connect(journal.path) as db:
        db.execute("DROP TABLE endpoint_incumbents")
    retried, _ = await run(shared, tmp_path)
    assert retried == first
    with pytest.raises(ValueError, match="legacy incumbent attempts"):
        await run(shared, tmp_path, job=jobs[1])
    assert len([c for c in calls if isinstance(c, dict)]) == len(first.steps)


async def test_consumer_still_reserves_its_own_journal_capacity(shared, tmp_path):
    _, jobs, _, _, calls = shared
    first, _ = await run(shared, tmp_path, maximum_jobs=1)
    with pytest.raises(ValueError, match="capacity exhausted"):
        await run(shared, tmp_path, job=jobs[1], maximum_jobs=1)
    assert len([c for c in calls if isinstance(c, dict)]) == len(first.steps)


@pytest.mark.parametrize("damage", ["missing", "pending", "steps"])
async def test_damaged_source_never_causes_new_inference(shared, tmp_path, damage):
    _, jobs, _, _, calls = shared
    first, journal = await run(shared, tmp_path)
    key = execution.execution_key(jobs[0])
    with sqlite3.connect(journal.path) as db:
        if damage == "missing":
            db.execute("DELETE FROM jobs WHERE id=?", (key,))
        elif damage == "pending":
            db.execute("INSERT INTO pending_steps VALUES (?,?)", (key, b"{}"))
        else:
            db.execute("DELETE FROM steps WHERE job_id=? AND ordinal=0", (key,))
    with pytest.raises(ValueError):
        await run(shared, tmp_path, job=jobs[1])
    assert len([c for c in calls if isinstance(c, dict)]) == len(first.steps)


async def test_concurrent_consumer_cannot_start_second_baseline(shared, tmp_path):
    _, jobs, _, _, calls = shared
    entered, release = asyncio.Event(), asyncio.Event()

    async def capture():
        entered.set()
        await release.wait()
        return boundary()

    first = asyncio.create_task(run(shared, tmp_path, source=capture))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        with pytest.raises(ValueError, match="incomplete or failed"):
            await run(shared, tmp_path, job=jobs[1])
    finally:
        release.set()
        result, journal = await first
    assert len([c for c in calls if isinstance(c, dict)]) == len(result.steps)
    assert journal.status(execution.execution_key(jobs[0]))["status"] == "complete"
    assert journal.status(execution.execution_key(jobs[1]))["status"] == "failed"


async def test_248_endpoint_roster_runs_each_baseline_case_only_once(shared, tmp_path):
    # Synthetic journal/call-count load test, not admission or wall-time evidence.
    policy, jobs, _, _, calls = shared
    submissions = tuple(submission(policy, name=f"Miner{i}") for i in range(248))
    round_ = jobs[0].round.model_copy(
        update={"roster": tuple(sorted(digest(s.submission) for s in submissions))}
    )
    original_steps = None
    for signed in submissions:
        job = jobs[0].model_copy(update={"round": round_, "submission": signed})
        result, _ = await run(shared, tmp_path, job=job)
        if original_steps is None:
            original_steps = result.steps
        assert result.steps == original_steps
        execution.validate_execution(result, policy)
    assert len([c for c in calls if isinstance(c, dict)]) == len(jobs[0].cases)
