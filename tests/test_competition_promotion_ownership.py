"""Promotion I/O must drain before its caller releases service ownership."""

from __future__ import annotations

import asyncio
import threading

import pytest

from .async_ownership import PausedCall
from .test_competition_promotion_delivery import apply
from .test_competition_promotion_delivery import history_setup as history_setup
from .test_competition_promotion_delivery import policy as policy
from .test_competition_promotion_delivery import scenario as scenario
from .test_competition_promotion_delivery import setup as setup
from .test_competition_rounds import OwnedProvider


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["accepted_review", "promotion_evidence", "promote"])
@pytest.mark.parametrize("cancel", [False, True], ids=["complete", "cancel"])
@pytest.mark.parametrize("fail", [False, True], ids=["success", "failure"])
async def test_promotion_work_drains_before_unlock(setup, monkeypatch, operation, cancel, fail):
    s = setup
    original = getattr(s.reviews, operation)
    failure = RuntimeError("injected promotion storage failure")

    def invoke(*args, **kwargs):
        if fail:
            raise failure
        return original(*args, **kwargs)

    paused = PausedCall(invoke)
    monkeypatch.setattr(s.reviews, operation, paused)
    serial = asyncio.Lock()
    provider_threads = []

    class Provider(OwnedProvider):
        async def collect(self):
            provider_threads.append(threading.get_ident())
            return await super().collect()

    async def promote():
        async with serial:
            return await apply(s, Provider(152))

    task = asyncio.create_task(promote())
    try:
        await asyncio.wait_for(paused.entered.wait(), 5)
        assert paused.thread_id != threading.get_ident()
        assert serial.locked() and not task.done()
        if cancel:
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                assert serial.locked() and not task.done()
        paused.release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        elif fail:
            with pytest.raises(RuntimeError) as caught:
                await asyncio.wait_for(task, 5)
            assert caught.value is failure
        else:
            result = await asyncio.wait_for(task, 5)
            assert result["sequence"] == 1
        assert paused.finished.is_set() and not serial.locked()
        assert all(thread == threading.get_ident() for thread in provider_threads)
        expected = int(not fail and (not cancel or operation == "promote"))
        assert s.reviews.baseline()["sequence"] == expected
        if expected:
            # A cancelled caller can retry the retained decision without
            # creating another promotion or changing its observation receipt.
            monkeypatch.setattr(s.reviews, operation, original)
            assert (await apply(s, OwnedProvider(500)))["sequence"] == 1
    finally:
        paused.release.set()
        await asyncio.gather(task, return_exceptions=True)
