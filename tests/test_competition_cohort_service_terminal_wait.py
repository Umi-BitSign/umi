"""Terminal contention budgets and cancellation, with fixture authority only."""

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

from umi.competition_cohort_service_worker import ServiceWorkWorker

from .test_competition_cohort_service_queue import capture
from .test_competition_cohort_service_worker import contention_error as contention_error


def worker_for(prepare, timeout=60):
    worker = object.__new__(ServiceWorkWorker)
    worker.transport = SimpleNamespace(timeout=timeout)
    worker.terminals = SimpleNamespace(prepare=prepare)
    worker._operation_stages = {}

    async def observation(assignment):
        return object(), capture()

    worker.observation = observation
    return worker, SimpleNamespace(admission=SimpleNamespace(work_sha256="ab" * 32))


async def test_terminal_contention_exhaustion_preserves_the_busy_error(contention_error):
    calls = []
    failure = contention_error

    def prepare(*args):
        calls.append(args)
        time.sleep(0.6)
        raise failure

    worker, assignment = worker_for(prepare, timeout=0.5)
    with pytest.raises(type(failure)) as caught:
        await worker._prepare_terminal(assignment, "slot", "response", "retirement")
    assert caught.value is failure
    assert len(calls) == 1


async def test_terminal_cancel_drains_owned_prepare_before_propagating(contention_error):
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    completed = []

    def prepare(*args):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(timeout=60)
        completed.append(args)
        raise contention_error

    worker, assignment = worker_for(prepare)
    task = asyncio.create_task(
        worker._prepare_terminal(assignment, "slot", "response", "retirement")
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=60)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=60)
        assert len(completed) == 1
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
