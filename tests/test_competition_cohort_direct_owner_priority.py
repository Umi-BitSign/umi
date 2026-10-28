"""Synthetic cohort owners: scheduling never reads a journal or model payload."""

import asyncio
from types import SimpleNamespace

import pytest

from umi import competition_cohort_direct_model_owner as module
from umi.competition_cohort_direct_model_owner import DirectModelUploadOwners
from umi.competition_cohort_public_progress import CohortProgressSnapshots

A, B, C = (value * 64 for value in "abc")


@pytest.fixture(autouse=True)
def isolated_progress(monkeypatch):
    monkeypatch.setattr(module, "PUBLIC_COHORT_PROGRESS", CohortProgressSnapshots())


class Owner:
    def __init__(self, cohort, calls, pending=1):
        self.config = SimpleNamespace(cohort_sha256=cohort)
        self.calls = calls
        self.pending = pending
        self.retrying = 0
        self.failed = 0
        self.error = None
        self.gate = None

    async def poll_once(self, **kwargs):
        self.calls.append(self.config.cohort_sha256)
        if self.gate is not None:
            await self.gate.wait()
        if self.error is not None:
            raise self.error
        return dict(
            objects_pending=self.pending, objects_retrying=self.retrying, objects_failed=self.failed
        )


async def test_poll_dispatches_only_one_owner_with_legacy_constructor():
    calls = []
    owners = {c: Owner(c, calls) for c in (A, B, C)}
    manager = DirectModelUploadOwners(owners)
    result = await manager.poll_once(now_unix_ms=1_800_000_000_000)
    assert calls == [A]
    assert list(result["cohorts"]) == [A]
    await manager.poll_once()
    await manager.poll_once()
    assert calls == [A, B, C]


async def test_sequence_priority_and_background_discovery_are_bounded():
    calls = []
    owners = {c: Owner(c, calls) for c in (C, A, B)}
    manager = DirectModelUploadOwners(owners, priority_cohorts=(A, B, C))
    for _ in range(10):
        await manager.poll_once()
    assert calls == [A, A, A, A, C, A, A, A, A, B]


@pytest.mark.parametrize("historical_phase", ["reference_reveal", "complete", "revoked"])
async def test_historical_c6_yields_first_turn_to_intake_c7_before_any_owner_poll(
    historical_phase,
):
    calls = []
    owners = {c: Owner(c, calls) for c in (A, B, C)}
    phases = {A: historical_phase, B: "intake"}  # Future C is still unknown.
    manager = DirectModelUploadOwners(owners, priority_cohorts=(A, B, C), intake_phase=phases.get)
    for _ in range(10):
        await manager.poll_once()
    assert calls == [B, B, B, B, A, B, B, B, B, C]
    phases[B] = "preparation"
    await manager.poll_once()
    assert calls[-1] == C


async def test_unknown_earlier_cohort_cannot_preempt_known_intake():
    calls = []
    manager = DirectModelUploadOwners(
        {c: Owner(c, calls) for c in (A, B)},
        priority_cohorts=(A, B),
        intake_phase={B: "intake"}.get,
    )
    await manager.poll_once()
    assert calls == [B]


async def test_completed_and_terminal_owners_yield_but_new_work_is_discovered():
    calls = []
    owners = {c: Owner(c, calls) for c in (A, B, C)}
    owners[A].pending = 0
    owners[A].failed = 3  # Terminal holds are not unfinished work.
    manager = DirectModelUploadOwners(owners, priority_cohorts=(A, B, C))
    await manager.poll_once()
    await manager.poll_once()
    assert calls == [A, B]
    owners[A].pending = 1
    for _ in range(4):
        await manager.poll_once()
    assert calls == [A, B, B, B, A, A]


@pytest.mark.parametrize("error", [OSError("provider unavailable"), asyncio.CancelledError()])
async def test_failed_or_cancelled_dispatch_cannot_starve_background(error):
    calls = []
    owners = {c: Owner(c, calls) for c in (A, B)}
    owners[A].error = error
    manager = DirectModelUploadOwners(owners, priority_cohorts=(A, B))
    for _ in range(4):
        with pytest.raises(type(error)):
            await manager.poll_once()
    await manager.poll_once()
    assert calls == [A, A, A, A, B]


async def test_retryable_owner_remains_priority_after_batch_is_consumed():
    calls = []
    owners = {c: Owner(c, calls) for c in (A, B)}
    owners[A].pending = 0
    owners[A].retrying = 1
    manager = DirectModelUploadOwners(owners, priority_cohorts=(A, B))
    for _ in range(5):
        await manager.poll_once()
    assert calls == [A, A, A, A, B]


async def test_partial_priority_visits_every_unlisted_and_idle_owner():
    calls = []
    owners = {c: Owner(c, calls, pending=0) for c in (A, B, C)}
    owners[B].pending = 1
    manager = DirectModelUploadOwners(owners, priority_cohorts=(B,))
    for _ in range(10):
        await manager.poll_once()
    assert calls == [B, B, B, B, A, B, B, B, B, C]
    owners[B].pending = 0
    for _ in range(4):
        await manager.poll_once()
    assert calls[-4:] == [B, A, B, C]


async def test_concurrent_poll_calls_preserve_one_active_owner():
    calls = []
    owners = {c: Owner(c, calls) for c in (A, B)}
    owners[A].gate = asyncio.Event()
    manager = DirectModelUploadOwners(owners)
    first = asyncio.create_task(manager.poll_once())
    second = asyncio.create_task(manager.poll_once())
    try:
        await asyncio.sleep(0)
        assert calls == [A]
    finally:
        owners[A].gate.set()
        await asyncio.gather(first, second)
    assert calls == [A, B]


async def test_queue_progress_is_cached_while_selected_owner_is_running(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(module, "PUBLIC_COHORT_PROGRESS", snapshots)
    calls = []
    owners = {c: Owner(c, calls) for c in (A, B)}
    owners[A].gate = asyncio.Event()
    manager = DirectModelUploadOwners(owners, priority_cohorts=(A, B))
    task = asyncio.create_task(manager.poll_once())
    try:
        await asyncio.sleep(0)
        now[0] = 30.0
        queued = snapshots.snapshot(B)["components"]["direct_uploads"]
        selected = snapshots.snapshot(A)["components"]["direct_uploads"]
        assert queued["selected_cohort_sha256"] == A
        assert queued["queue_wait_seconds"] == 20
        assert selected["queue_wait_seconds"] == 0
        assert selected["elapsed_seconds"] == 20
        assert queued["eta_seconds"] is None
        assert queued["queue_wait_scope"] == "since_owner_start_or_last_poll_completion"
        assert queued["objects_pending"] is None
        assert calls == [A], "public reads must never dispatch or scan owners"
    finally:
        owners[A].gate.set()
        await task
    finished = snapshots.snapshot(A)["components"]["direct_uploads"]
    assert finished["selected_cohort_sha256"] is None
    assert finished["queue_wait_seconds"] == 0
    observed = finished["owner_report_observed_unix_ms"]
    owners[A].gate.clear()
    task = asyncio.create_task(manager.poll_once())
    await asyncio.sleep(0)
    try:
        running = snapshots.snapshot(A)["components"]["direct_uploads"]
        assert running["owner_report_observed_unix_ms"] == observed
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    cancelled = snapshots.snapshot(A)["components"]["direct_uploads"]
    assert cancelled["selected_cohort_sha256"] is None
    assert cancelled["objects_pending"] is None
    assert cancelled["stalled_or_retrying"] is True


async def test_partial_item_progress_does_not_freshen_another_cohort(monkeypatch):
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(module, "PUBLIC_COHORT_PROGRESS", snapshots)
    entered, release, published, finish = (asyncio.Event() for _ in range(4))
    owners = {c: Owner(c, []) for c in (A, B)}

    async def partial_poll(*, report, **kwargs):
        entered.set()
        await release.wait()
        report(
            dict(
                objects_total=3,
                objects_classified=0,
                objects_unclassified=3,
                object_count_status="partial",
                active_object_position=1,
                active_object_stage="source_verification",
                objects_retrying=0,
            )
        )
        published.set()
        await finish.wait()
        return dict(objects_pending=1, objects_retrying=0)

    owners[A].poll_once = partial_poll
    manager = DirectModelUploadOwners(owners, priority_cohorts=(A, B))
    task = asyncio.create_task(manager.poll_once())
    try:
        await entered.wait()
        other = snapshots.entries[B]["direct_uploads"]
        release.set()
        await published.wait()
        assert snapshots.entries[B]["direct_uploads"] == other
        assert snapshots.snapshot(A)["components"]["direct_uploads"]["objects_total"] == 3
        assert manager._reports == {}
    finally:
        release.set()
        finish.set()
        await task


@pytest.mark.parametrize("priority", [(A, A), ("d" * 64,)])
def test_invalid_priority_binding_is_rejected(priority):
    with pytest.raises(ValueError, match="priority"):
        DirectModelUploadOwners({A: Owner(A, [])}, priority_cohorts=priority)
