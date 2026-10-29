"""Advisory wakes preserve serial work, polling recovery and owned shutdown."""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_cohort_readiness_wake import CohortReadinessWakes
from umi.competition_cohort_service_host import ServiceAdmissionHost


async def test_thread_hints_coalesce_and_stale_callback_cannot_resurrect_consumed_hint():
    wakes = CohortReadinessWakes()
    with wakes.subscribe("models") as wake:
        wake.begin()
        await asyncio.to_thread(lambda: [wakes.notify("models") for _ in range(100)])
        await asyncio.wait_for(wake.wait(asyncio.Event(), 60), 1)
        assert wake.snapshot()["queued"]
        # Also cover a notify consumed before its call_soon callback can run.
        wake.begin()
        wakes.notify("models")
        wake.begin()
        await asyncio.sleep(0)
        assert not wake._event.is_set()
        report = wake.snapshot()
        assert report["hints_received"] == 101
        assert report["awakened_polls"] == 2
        assert report["status"] == "active"
        assert report["eta_scope"] == "next_serial_owner_scheduling_boundary"
    await asyncio.to_thread(wake.notify)
    assert wake.snapshot()["hints_received"] == 101


async def test_broadcast_keeps_hint_for_busy_reviewer_after_other_reviewer_consumes_it():
    wakes = CohortReadinessWakes()
    with wakes.subscribe("admissions") as slow, wakes.subscribe("admissions") as fast:
        slow.begin()
        fast.begin()
        fast.finish()
        wakes.notify("admissions")
        await asyncio.wait_for(fast.wait(asyncio.Event(), 60), 1)
        fast.begin()
        slow.finish()
        await asyncio.wait_for(slow.wait(asyncio.Event(), 60), 1)
        slow.begin()
        assert slow.snapshot()["awakened_polls"] == fast.snapshot()["awakened_polls"] == 1


async def test_timeout_and_new_owner_recover_lost_hints_without_retaining_subscriptions():
    wakes = CohortReadinessWakes()
    wakes.notify("models")  # Before startup; the ordinary first pass owns recovery.
    for _ in range(2):
        with wakes.subscribe("models") as wake:
            wake.begin()
            wake.finish()
            await asyncio.wait_for(wake.wait(asyncio.Event(), 0.001), 1)
            wake.begin()
            assert wake.snapshot()["hints_received"] == 0
        assert wakes._owners == {}


async def test_retry_delay_keeps_pending_hint_and_stop_cleans_waiters():
    wakes = CohortReadinessWakes()
    stop = asyncio.Event()
    before = asyncio.all_tasks()
    with wakes.subscribe("models") as wake:
        wake.begin()
        wake.finish(retrying=True)
        wakes.notify("models")
        waiting = asyncio.create_task(wake.wait(stop, 60, retrying=True))
        await asyncio.sleep(0.01)
        assert not waiting.done()
        assert wake.snapshot()["status"] == "retrying"
        assert wake.snapshot()["queued"]
        stop.set()
        await asyncio.wait_for(waiting, 1)
        wake.begin()
        assert wake.snapshot()["awakened_polls"] == 1
    assert asyncio.all_tasks() == before


async def test_cancelled_wait_drains_event_and_stop_tasks():
    wakes = CohortReadinessWakes()
    before = asyncio.all_tasks()
    with wakes.subscribe("models") as wake:
        waiting = asyncio.create_task(wake.wait(asyncio.Event(), 60))
        await asyncio.sleep(0)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
    assert asyncio.all_tasks() == before


async def test_host_hint_during_active_pass_runs_one_followup_without_preemption():
    wakes = CohortReadinessWakes()
    host = object.__new__(ServiceAdmissionHost)
    host.intake = SimpleNamespace(readiness_wakes=wakes)
    host.config = SimpleNamespace(poll_seconds=60)
    entered, release, again, stop = (asyncio.Event() for _ in range(4))
    calls = 0

    async def poll():
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            await release.wait()
        else:
            again.set()
        return {"status": "current"}

    task = asyncio.create_task(host._poll_component(stop, "models", poll))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        await asyncio.to_thread(lambda: [wakes.notify("models") for _ in range(20)])
        assert calls == 1
        release.set()
        await asyncio.wait_for(again.wait(), 1)
        await asyncio.sleep(0.01)
        assert calls == 2
    finally:
        release.set()
        stop.set()
        await asyncio.wait_for(task, 1)
    assert wakes._owners == {}
