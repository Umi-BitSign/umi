"""Legacy operator-audited recovery; no synthetic evidence enters production."""

import asyncio
import hashlib
import os
import sqlite3

import pytest

from tests.test_competition_execution import boundary
from tests.test_competition_execution import setup as setup
from tests.test_competition_runner import runtime as runtime
from tests.test_competition_shared_incumbent import forbidden, run
from tests.test_competition_shared_incumbent import shared as shared
from tests.test_open_competition import policy as policy
from umi import competition_execution as ex
from umi.competition_execution_recovery import LegacyPreflightRecovery
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


def authorization(journal, job):
    return LegacyPreflightRecovery(
        schema="umi-legacy-preflight-recovery/1",
        source_execution_key=ex.execution_key(job),
        source_job_sha256=hashlib.sha256(canonical_json_bytes(job)).hexdigest(),
        scope_sha256=ex._incumbent_scope(job),
        policy_sha256=digest(journal.policy),
        round_sha256=digest(job.round),
        journal_state_sha256=journal.recovery_state_sha256(),
        preserved_snapshot_sha256="11" * 32,
        operator_audit_sha256="22" * 32,
        observed_block=125,
        basis="operator_audited_no_prior_model_invocation",
    )


async def failed(shared, tmp_path):
    policy, jobs, _archive, videos, calls = shared
    # Reproduce the real pre-invocation failure, then repair exact bytes.
    video = videos / (jobs[0].cases[0].video_sha256 + ".mp4")
    link = tmp_path / "hardlink"
    os.link(video, link)
    with pytest.raises(ValueError, match="single-link"):
        await run(shared, tmp_path)
    link.unlink()
    journal = ex.ExecutionJournal(tmp_path / "shared", policy)
    with pytest.raises(ValueError, match="incomplete or failed"):
        await run(shared, tmp_path, job=jobs[1])
    assert not [c for c in calls if isinstance(c, dict)]
    return journal


async def test_audited_source_and_failed_consumer_recover_preserving_all_old_rows(
    shared, tmp_path, monkeypatch
):
    journal = await failed(shared, tmp_path)
    _, jobs, _, _, calls = shared
    journal.reserve_jobs("ab" * 32, jobs)
    receipt = journal.reservation("ab" * 32)
    with sqlite3.connect(journal.path) as db:
        originals = db.execute("SELECT * FROM jobs ORDER BY id").fetchall()
        mapping = db.execute("SELECT * FROM endpoint_incumbents").fetchall()
    auth = authorization(journal, jobs[0])
    journal.authorize_legacy_preflight_recovery(jobs[0], auth)
    journal.authorize_legacy_preflight_recovery(jobs[0], auth)
    assert journal.recovery_ready(jobs[0])
    assert not journal.recovery_ready(jobs[1])
    first, journal = await run(shared, tmp_path)
    assert journal.recovery_ready(jobs[1])
    monkeypatch.setattr(ex, "execute_offline_case", forbidden)
    monkeypatch.setattr(ex, "verify_runtime", forbidden)
    second, journal = await run(shared, tmp_path, job=jobs[1], source=forbidden, prepare=forbidden)
    assert first.steps == second.steps
    assert len([c for c in calls if isinstance(c, dict)]) == len(jobs[0].cases)
    assert journal.reserve(jobs[0]) == first
    assert journal.reserve(jobs[1]) == second
    assert journal.reservation("ab" * 32) == receipt
    with sqlite3.connect(journal.path) as db:
        assert db.execute("SELECT * FROM jobs ORDER BY id").fetchall() == originals
        assert db.execute("SELECT * FROM endpoint_incumbents").fetchall() == mapping
        assert db.execute("SELECT status FROM recovery_attempts").fetchall() == [
            ("complete",),
            ("complete",),
        ]
        # An old writer even knowing reservation generation cannot modify state.
        db.create_function("umi_execution_writer_generation", 0, lambda: 2)
        with pytest.raises(sqlite3.OperationalError, match="recovery_writer"):
            db.execute("UPDATE jobs SET status='running'")
    with journal._transaction() as db:
        with pytest.raises(sqlite3.IntegrityError, match="immutable original"):
            db.execute("UPDATE jobs SET status='running'")
        with pytest.raises(sqlite3.IntegrityError, match="immutable execution recovery"):
            db.execute("DELETE FROM recovery_authorizations")


@pytest.mark.parametrize(
    "field",
    [
        "source_execution_key",
        "source_job_sha256",
        "scope_sha256",
        "round_sha256",
        "policy_sha256",
        "journal_state_sha256",
        "observed_block",
    ],
)
async def test_changed_authorization_rejected_without_mutation(shared, tmp_path, field):
    journal = await failed(shared, tmp_path)
    job = shared[1][0]
    before = journal.recovery_state_sha256()
    auth = authorization(journal, job).model_copy(
        update={field: 1000000 if field == "observed_block" else "ab" * 32}
    )
    with pytest.raises(ValueError, match="binding"):
        journal.authorize_legacy_preflight_recovery(job, auth)
    assert journal.recovery_state_sha256() == before


@pytest.mark.parametrize("table", ["steps", "pending_steps"])
async def test_any_retained_observation_prevents_authorization(shared, tmp_path, table):
    journal = await failed(shared, tmp_path)
    key = ex.execution_key(shared[1][0])
    with sqlite3.connect(journal.path) as db:
        if table == "steps":
            db.execute("INSERT INTO steps VALUES (?,0,?)", (key, b"{}"))
        else:
            db.execute("INSERT INTO pending_steps VALUES (?,?)", (key, b"{}"))
    auth = authorization(journal, shared[1][0])
    before = journal.recovery_state_sha256()
    with pytest.raises(ValueError, match="ambiguous"):
        journal.authorize_legacy_preflight_recovery(shared[1][0], auth)
    assert journal.recovery_state_sha256() == before


@pytest.mark.parametrize(
    "failure", ["claim_crash", "runtime", "runner", "finished_boundary", "cancelled"]
)
async def test_claimed_recovery_never_retries_after_ambiguity(
    shared, tmp_path, monkeypatch, failure
):
    journal = await failed(shared, tmp_path)
    job = shared[1][0]
    journal.authorize_legacy_preflight_recovery(job, authorization(journal, job))

    async def error(*a, **k):
        if failure == "cancelled":
            raise asyncio.CancelledError()
        raise RuntimeError("ambiguous test failure")

    calls = 0

    async def capture():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("missing finish")
        return boundary()

    if failure == "claim_crash":
        journal.reserve(job)
    else:
        if failure in ("runtime", "cancelled"):
            monkeypatch.setattr(ex, "verify_runtime", error)
        if failure == "runner":
            monkeypatch.setattr(ex, "execute_offline_case", error)
        with pytest.raises((RuntimeError, asyncio.CancelledError)):
            await run(shared, tmp_path, source=capture if failure == "finished_boundary" else None)
    journal = ex.ExecutionJournal(tmp_path / "shared", shared[0])
    assert not journal.recovery_ready(job)
    with pytest.raises(ValueError, match="incomplete or failed"):
        await run(shared, tmp_path)
    assert not journal.recovery_ready(shared[1][1])
    # Replaying authorization does not reset the consumed attempt.
    with journal._transaction() as db:
        raw = db.execute("SELECT document FROM recovery_authorizations").fetchone()[0]
    journal.authorize_legacy_preflight_recovery(
        job, LegacyPreflightRecovery.model_validate_json(raw)
    )
    assert not journal.recovery_ready(job)


async def test_concurrent_recovery_claim_never_invokes_twice(shared, tmp_path):
    journal = await failed(shared, tmp_path)
    job = shared[1][0]
    journal.authorize_legacy_preflight_recovery(job, authorization(journal, job))
    entered, release = asyncio.Event(), asyncio.Event()

    async def capture():
        entered.set()
        await release.wait()
        return boundary()

    task = asyncio.create_task(run(shared, tmp_path, source=capture))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        with pytest.raises(ValueError, match="incomplete or failed"):
            await run(shared, tmp_path)
        assert not journal.recovery_ready(shared[1][1])
    finally:
        release.set()
        result, _ = await task
    assert len([c for c in shared[4] if isinstance(c, dict)]) == len(result.steps)


async def test_last_clip_preflight_failure_never_invokes_first_case(shared, tmp_path):
    videos = shared[3]
    job = shared[1][0]
    os.link(videos / (job.cases[-1].video_sha256 + ".mp4"), tmp_path / "late-hardlink")
    with pytest.raises(ValueError, match="single-link"):
        await run(shared, tmp_path)
    assert not [c for c in shared[4] if isinstance(c, dict)]
