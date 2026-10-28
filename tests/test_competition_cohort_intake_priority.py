"""One serial owner prioritizes intake without preemption or background starvation."""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from umi.competition_cohort_public_progress import CohortProgressSnapshots
from umi.competition_model_certification_progress import ModelCertificationProgress


def worker_fixture(tmp_path, pending, chronology):
    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=tuple(SimpleNamespace(cohort_sha256=c) for c in sorted(pending)),
                automatic_progression_hold_cohorts=tuple(pending),
            ),
            model_certification_progress=ModelCertificationProgress(),
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            return tuple((key, key) for key in pending[cohort][offset : offset + limit])

        def entries(self, cohort, *, after, limit):
            return ()

    return ModelAcceptanceWorker(Owner(), None, tmp_path, tmp_path, priority_cohorts=chronology)


@pytest.mark.asyncio
async def test_held_oldest_intake_gets_four_attempts_then_fair_background_turn(tmp_path):
    a, b, c, d = (letter * 64 for letter in "abcd")
    pending = {cohort: [f"{cohort[0]}{n}" for n in range(20)] for cohort in (a, b, c, d)}
    worker = worker_fixture(tmp_path, pending, (c, d, a, b))
    holds = worker.owner.intake.config.automatic_progression_hold_cohorts
    calls = []

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        pending[cohort].remove(submission)

    worker._one = accept
    for _ in range(15):
        report = await worker.poll_once()
        assert report["entries_exported"] == 1
        assert set(report["pending_latest_cohorts"]) == set(pending)
    assert [cohort for cohort, _ in calls] == [c] * 4 + [a] + [c] * 4 + [b] + [c] * 4 + [d]
    assert len(set(calls)) == 15
    assert worker.owner.intake.config.automatic_progression_hold_cohorts == holds
    assert worker.owner.intake.model_certification_progress.owner_cohort is None


@pytest.mark.asyncio
async def test_priority_changes_do_not_reset_background_fairness_budget(tmp_path):
    first, second, future = (letter * 64 for letter in "abc")
    pending = {first: ["first"], second: ["second"], future: ["future"]}
    worker = worker_fixture(tmp_path, pending, (first, second, future))
    calls = []

    async def accept(cohort, submission):
        calls.append(cohort)
        pending[cohort].remove(submission)
        # A replacement arrives for the other early cohort on each completion.
        if cohort == second:
            pending[first].append("first")
        if cohort == first and not pending[second]:
            pending[second].append("second")

    worker._one = accept
    for _ in range(10):
        await worker.poll_once()
    assert future in calls
    assert calls.index(future) < 10


@pytest.mark.asyncio
async def test_priority_provider_retry_keeps_three_other_submission_gap(tmp_path):
    from umi.competition_chain import RegistrationProviderTimeout

    early, future = "c" * 64, "a" * 64
    pending = {early: [f"early{n}" for n in range(6)], future: [f"future{n}" for n in range(6)]}
    worker = worker_fixture(tmp_path, pending, (early, future))
    calls = []

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        if submission == "early0" and calls.count((early, submission)) == 1:
            raise RegistrationProviderTimeout("bounded provider wait")
        pending[cohort].remove(submission)

    worker._one = accept
    for _ in range(7):
        await worker.poll_once()
    assert [sub for cohort, sub in calls if cohort == early][:5] == [
        "early0",
        "early1",
        "early2",
        "early3",
        "early0",
    ]
    assert "early0" not in pending[early]


@pytest.mark.asyncio
async def test_new_earlier_work_waits_for_active_transfer_then_takes_next_turn(tmp_path):
    early, future = "c" * 64, "a" * 64
    pending = {early: [], future: ["future0", "future1"]}
    worker = worker_fixture(tmp_path, pending, (early, future))
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        if submission == "future0":
            entered.set()
            await release.wait()
        pending[cohort].remove(submission)

    worker._one = accept
    task = asyncio.create_task(worker.poll_once())
    try:
        await asyncio.wait_for(entered.wait(), 10)
        pending[early].append("early0")
        assert not task.done()
        assert worker.owner.intake.model_certification_progress.owner_cohort == future
    finally:
        release.set()
        await task
    await worker.poll_once()
    assert calls == [(future, "future0"), (early, "early0")]
    assert pending[future] == ["future1"]


@pytest.mark.asyncio
async def test_unavailable_oldest_item_yields_then_advances_offset(tmp_path):
    early, future = "c" * 64, "a" * 64
    pending = {early: ["blocked", "ready"], future: ["future0", "future1"]}
    worker = worker_fixture(tmp_path, pending, (early, future))
    calls = []

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        if submission == "blocked":
            raise OSError("original review is not ready")
        pending[cohort].remove(submission)

    worker._one = accept
    first = await worker.poll_once()
    assert first["entries_pending"] == 1
    await worker.poll_once()
    await worker.poll_once()
    assert calls == [(early, "blocked"), (future, "future0"), (early, "ready")]
    assert worker.owner.intake.model_certification_progress.owner_cohort is None


def test_cached_queue_owner_withdraws_eta_and_survives_public_projection(monkeypatch):
    from umi import competition_model_certification_progress as module

    early, future = "c" * 64, "a" * 64
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(module, "PUBLIC_COHORT_PROGRESS", snapshots)
    progress = ModelCertificationProgress()
    inventory = dict(
        cohort_sha256=early,
        roster_sha256="r" * 64,
        selection_scope="latest_model_submissions",
        completed=1,
        total=3,
        pending_submission_sha256s=("pending1", "pending2"),
    )
    progress.report(inventory, now=10)
    progress.acceptance_owner(future, "promotion")
    waiting = progress.report(inventory, now=20)
    assert waiting["eta_basis"] == "waiting_for_acceptance_owner"
    assert waiting["eta_seconds"] is waiting["planning_eta_seconds"] is None
    assert waiting["acceptance_owner_cohort_sha256"] == future
    later = progress.report(inventory, now=50)
    assert later["acceptance_queue_wait_seconds"] == 30
    public = snapshots.snapshot(early)
    assert public["completed"] == 1 and public["total"] == 3
    assert public["reason_code"] == "waiting_for_acceptance_owner"
    assert public["acceptance_owner_stage"] == "promotion"
    assert public["overall_eta_seconds"] is None
    assert public["eta_seconds"] is None
    progress.acceptance_owner(early, "review_quorum")
    own = progress.report(inventory, now=60)
    assert own["acceptance_queue_wait_seconds"] == 0
    assert own["reason_code"] is None
