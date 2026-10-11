"""Coverage guard owns complete native work through cancellation."""

import asyncio
import threading

import pytest


async def test_current_and_predecessor_coverage_share_guard_and_drain_cancelled_work():
    from umi.competition_reward_coverage_source import NativeRewardCoverageSource
    from umi.concurrency import run_owned_thread

    guard = asyncio.Lock()
    entered, release = threading.Event(), threading.Event()
    calls = []
    current, predecessor = (
        object.__new__(NativeRewardCoverageSource),
        object.__new__(NativeRewardCoverageSource),
    )
    current._package_guard = predecessor._package_guard = guard

    def owned():
        calls.append("current")
        entered.set()
        assert release.wait(timeout=10)

    async def capture_current(*args):
        return await run_owned_thread(owned)

    async def capture_predecessor(*args):
        calls.append("predecessor")

    current._capture = capture_current
    predecessor._capture = capture_predecessor
    first = asyncio.create_task(current.capture("validator", 1))
    assert await asyncio.to_thread(entered.wait, 5)
    second = asyncio.create_task(predecessor.capture("validator", 1))
    first.cancel()
    await asyncio.sleep(0)
    assert calls == ["current"] and guard.locked()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    await second
    assert calls == ["current", "predecessor"] and not guard.locked()
