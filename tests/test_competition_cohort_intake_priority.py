"""One serial owner prioritizes intake without preemption or background starvation."""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from umi.competition_cohort_public_progress import CohortProgressSnapshots
from umi.competition_model_certification_progress import ModelCertificationProgress


def worker_fixture(tmp_path, pending, chronology, *, batch_size=16):
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

    return ModelAcceptanceWorker(
        Owner(), None, tmp_path, tmp_path, priority_cohorts=chronology, batch_size=batch_size
    )


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
@pytest.mark.parametrize("batch_size", [1, 16])
async def test_pending_quorum_keeps_other_oldest_entries_ahead_of_background(tmp_path, batch_size):
    from umi.competition_cohort_model_acceptance_store import PendingModelArtifacts

    early, future = "c" * 64, "a" * 64
    pending = {early: ["blocked", "ready1", "ready2", "ready3", "ready4"], future: ["future"]}
    worker = worker_fixture(tmp_path, pending, (early, future), batch_size=batch_size)
    calls = []
    scans = []
    original_scan = worker.owner.pending_latest_entries

    def scan(cohort, *, limit, offset):
        scans.append((cohort, limit, offset))
        return original_scan(cohort, limit=limit, offset=offset)

    worker.owner.pending_latest_entries = scan
    entered, release = asyncio.Event(), asyncio.Event()

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        if submission == "blocked":
            raise PendingModelArtifacts("independent review is not ready")
        if cohort == future:
            assert len(calls) == 5, "pending review forfeited the other foreground attempts"
            entered.set()
            await release.wait()
        pending[cohort].remove(submission)

    worker._one = accept
    first = await worker.poll_once()
    assert first["entries_pending"] == 1
    for _ in range(3):
        await worker.poll_once()
    assert calls == [(early, "blocked"), *[(early, f"ready{n}") for n in range(1, 4)]]
    # The normal four-attempt ceiling still gives the background cohort its
    # full, nonpreemptible turn. No extra scan was added to find ready entries.
    assert len(scans) == 8
    assert {limit for _, limit, _ in scans} == {max(2, batch_size)}
    task = asyncio.create_task(worker.poll_once())
    try:
        await asyncio.wait_for(entered.wait(), 10)
        assert not task.done()
        assert calls[-1] == (future, "future")
        assert "ready4" in pending[early]
    finally:
        release.set()
        await task
    await worker.poll_once()
    assert calls[-1] == (early, "ready4")
    assert worker.owner.intake.model_certification_progress.owner_cohort is None


@pytest.mark.asyncio
@pytest.mark.parametrize("batch_size", [1, 16])
async def test_unavailable_singleton_yields_without_repeating_whole_quantum(tmp_path, batch_size):
    from umi.competition_cohort_model_acceptance_store import PendingModelArtifacts

    early, future = "c" * 64, "a" * 64
    pending = {early: ["blocked"], future: ["future0", "future1"]}
    worker = worker_fixture(tmp_path, pending, (early, future), batch_size=batch_size)
    calls = []

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        if submission == "blocked":
            raise PendingModelArtifacts("independent review is not ready")
        pending[cohort].remove(submission)

    worker._one = accept
    for _ in range(4):
        await worker.poll_once()
    assert calls == [
        (early, "blocked"),
        (future, "future0"),
        (early, "blocked"),
        (future, "future1"),
    ]
    assert worker.owner.intake.model_certification_progress.owner_cohort is None


@pytest.mark.asyncio
async def test_failed_priority_entries_preserve_background_budget_when_oldest_changes(tmp_path):
    from umi.competition_cohort_model_acceptance_store import PendingModelArtifacts

    first, second, future = (letter * 64 for letter in "abc")
    pending = {
        first: ["blocked", "first"],
        second: ["second1", "second2", "second3"],
        future: ["future"],
    }
    worker = worker_fixture(tmp_path, pending, (first, second, future), batch_size=1)
    calls = []

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        if submission == "blocked":
            raise PendingModelArtifacts("independent review is not ready")
        pending[cohort].remove(submission)
        if submission == "first":
            # A concurrent successful completion removes the previously blocked
            # entry. Selecting the next oldest cohort must not reset the budget.
            pending[first].clear()

    worker._one = accept
    for _ in range(5):
        await worker.poll_once()
    assert calls == [
        (first, "blocked"),
        (first, "first"),
        (second, "second1"),
        (second, "second2"),
        (future, "future"),
    ]


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
