"""Scheduling overlap and cancellation without changing timing authority."""

import asyncio
import json
import logging

import pytest

from umi.competition_timing_admission import TimingAdmissionTimeout, TimingAttemptAdmission


async def turn():
    # Let admission waiters run, without tying assertions to wall-clock delays.
    for _ in range(10):
        await asyncio.sleep(0)


async def test_normal_attempts_overlap_and_quiet_retries_drain_in_order():
    gate = TimingAttemptAdmission()
    release = asyncio.Event()
    entered = []

    async def normal(index):
        async with gate.attempt(quiet=False, timeout=1):
            entered.append(index)
            await release.wait()

    first = [asyncio.create_task(normal(i)) for i in range(3)]
    await turn()
    assert entered == [0, 1, 2]
    quiet_release = [asyncio.Event(), asyncio.Event()]

    async def quiet(index):
        async with gate.attempt(quiet=True, timeout=1):
            entered.append("retry" + str(index))
            await quiet_release[index].wait()

    retries = []
    for i in range(2):
        retries.append(asyncio.create_task(quiet(i)))
        await turn()
    later = asyncio.create_task(normal(3))
    await turn()
    assert entered == [0, 1, 2]
    release.set()
    await asyncio.gather(*first)
    await turn()
    assert entered == [0, 1, 2, "retry0"]
    quiet_release[0].set()
    await retries[0]
    await turn()
    assert entered == [0, 1, 2, "retry0", "retry1"]
    quiet_release[1].set()
    await asyncio.gather(retries[1], later)
    assert entered == [0, 1, 2, "retry0", "retry1", 3]


async def test_cancelled_waiter_releases_new_normal_attempts():
    gate = TimingAttemptAdmission()
    async with gate.attempt(quiet=False, timeout=1):

        async def retry():
            async with gate.attempt(quiet=True, timeout=1):
                pytest.fail("active ordinary attempt must drain first")

        task = asyncio.create_task(retry())
        await turn()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with gate.attempt(quiet=False, timeout=0):
            pass
    async with gate.attempt(quiet=True, timeout=0):
        pass


async def test_expired_wait_starts_no_attempt_and_keeps_running_owner(caplog):
    caplog.set_level(logging.INFO, logger="umi.competition_timing_admission")
    gate = TimingAttemptAdmission()
    async with gate.attempt(quiet=False, timeout=1):
        with pytest.raises(TimingAdmissionTimeout):
            async with gate.attempt(quiet=True, timeout=0):
                pytest.fail("expired queue must not start native work")
        async with gate.attempt(quiet=False, timeout=0):
            pass
    async with gate.attempt(quiet=True, timeout=0):
        with pytest.raises(TimingAdmissionTimeout):
            async with gate.attempt(quiet=False, timeout=0):
                pytest.fail("ordinary work must not overlap a quiet retry")
    events = [
        json.loads(record.message) for record in caplog.records if record.message.startswith("{")
    ]
    expired = [
        event
        for event in events
        if event.get("reason_code") == "timing_admission_allowance_expired"
    ]
    assert len(expired) >= 2
    assert all(event["completed_units"] == 0 for event in expired)
    assert all(event["planning_eta_seconds"] == [0, 0] for event in expired)
    assert all(event["eta_scope"] == "local_timing_admission_only" for event in expired)
    assert all(event["stalled_or_retrying"] for event in expired)


async def test_cancelled_active_retry_releases_its_gate():
    gate = TimingAttemptAdmission()
    entered = asyncio.Event()

    async def retry():
        async with gate.attempt(quiet=True, timeout=1):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(retry())
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with gate.attempt(quiet=False, timeout=0):
        pass


async def test_repeated_cancellation_drains_pending_release():
    gate = TimingAttemptAdmission()
    entered = asyncio.Event()

    async def retry():
        async with gate.attempt(quiet=True, timeout=1):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(retry())
    await asyncio.wait_for(entered.wait(), 1)
    await gate.condition.acquire()
    try:
        task.cancel()
        await turn()
        task.cancel()
        await turn()
        assert not task.done()
    finally:
        gate.condition.release()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with gate.attempt(quiet=False, timeout=0):
        pass
