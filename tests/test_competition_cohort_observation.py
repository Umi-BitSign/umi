"""Observation deadlines retain ownership through transport-style cleanup."""

import asyncio
import inspect

import anyio
import pytest

from umi.competition_cohort_observation import observe_http


async def test_deadline_drains_shielded_cleanup_and_never_returns_late_success():
    closing, release, closed = (asyncio.Event() for _ in range(3))

    async def request():
        # HTTPCore shields connection-state and pool cleanup on normal EOF.
        with anyio.CancelScope(shield=True):
            closing.set()
            await release.wait()
            closed.set()
        return "late response"

    task = asyncio.create_task(observe_http(request(), timeout=0.01))
    try:
        await asyncio.wait_for(closing.wait(), 1)
        await asyncio.sleep(0.02)
        assert not task.done() and not closed.is_set()
        release.set()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(task, 1)
        assert closed.is_set()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_repeated_caller_cancellation_drains_cleanup_before_propagation():
    entered, closing, release, closed = (asyncio.Event() for _ in range(4))

    async def request():
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            with anyio.CancelScope(shield=True):
                closing.set()
                await release.wait()
                closed.set()

    task = asyncio.create_task(observe_http(request(), timeout=30))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        await asyncio.wait_for(closing.wait(), 1)
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0)
        assert not task.done() and not closed.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
        assert closed.is_set()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_expired_before_child_start_closes_supplied_coroutine():
    closed = asyncio.Event()

    async def request():
        try:
            await asyncio.sleep(0)
        finally:
            closed.set()

    operation = request()
    with pytest.raises(asyncio.TimeoutError):
        await observe_http(operation, timeout=0)
    assert inspect.getcoroutinestate(operation) == inspect.CORO_CLOSED
    assert closed.is_set()
