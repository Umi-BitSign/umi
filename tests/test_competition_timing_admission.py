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
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
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


def test_reviewer_cli_emits_timing_wait_without_external_logger_configuration(monkeypatch, capsys):
    from umi import competition_cohort_review_cli as cli

    logger = logging.getLogger("umi.competition.progress")
    before = (logger.level, logger.propagate, tuple(logger.handlers))
    monkeypatch.setattr(cli, "load_phase_review_config", lambda path: object())

    async def run(config):
        gate = TimingAttemptAdmission()
        async with gate.attempt(quiet=False, timeout=1):
            with pytest.raises(TimingAdmissionTimeout):
                async with gate.attempt(quiet=True, timeout=0):
                    pytest.fail("waiting retry cannot enter")

    monkeypatch.setattr(cli, "_run", run)
    cli.main(["run", "--config", "unused.json"])
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    waiting = [event for event in events if event["status"] == "waiting"]
    assert waiting
    assert waiting[0]["stage"] == "timing_attempt_admission"
    assert waiting[0]["active_attempts"] == 1
    assert waiting[0]["queued_retries"] == 1
    assert waiting[0]["elapsed_seconds"] >= 0
    assert waiting[0]["admission_remaining_seconds"] == 0
    assert waiting[0]["stalled_or_retrying"]
    assert (logger.level, logger.propagate, tuple(logger.handlers)) == before


async def test_measured_ordinary_duration_extends_retry_without_exceeding_read_budget():
    now = [0.0]
    gate = TimingAttemptAdmission(clock=lambda: now[0])
    assert gate.retry_allowance(120, 1000) == 120
    async with gate.attempt(quiet=False, timeout=1):
        now[0] += 200
    assert gate.retry_allowance(120, 1000) == 250

    assert gate.retry_allowance(120, 180) == 180
    # Retrying or waiting cannot inflate later allowances indefinitely.
    async with gate.attempt(quiet=True, timeout=1):
        now[0] += 1000
    assert gate.retry_allowance(120, 1000) == 250
    async with gate.attempt(quiet=False, timeout=1):
        now[0] += 50
    assert gate.retry_allowance(120, 1000) == 250


async def test_drained_turn_releases_before_retention_and_only_once():
    now = [0.0]
    gate = TimingAttemptAdmission(clock=lambda: now[0])
    async with gate.attempt(quiet=False, timeout=1) as release:
        now[0] = 200
        await release()
        async with gate.attempt(quiet=True, timeout=0):
            await release()
            assert gate.active == 1 and gate.quiet
        now[0] = 2000  # Later retention cannot inflate the timing retry allowance.
    assert gate.active == 0 and not gate.quiet
    assert gate.retry_allowance(120, 1000) == 250
