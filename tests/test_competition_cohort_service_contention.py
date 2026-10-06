"""Actual queue mutex contention must not discard admission or block HTTP."""

import asyncio
import os

import pytest

from umi.private_files import lock_private_file

from .test_competition_cohort_service_api import api_case as api_case
from .test_competition_cohort_service_api import chain as chain
from .test_competition_cohort_service_api import chain_config as chain_config
from .test_competition_cohort_service_api import finality_padding as finality_padding
from .test_competition_cohort_service_api import post, ready

# Fixture dependencies use the same native queue, policy and signed records.
from .test_competition_cohort_service_queue import base_policy as base_policy
from .test_competition_cohort_service_queue import harness as harness
from .test_competition_cohort_service_queue import inputs
from .test_competition_cohort_service_queue import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_queue import policy as policy
from .test_competition_cohort_service_queue import queue_case as queue_case
from .test_competition_cohort_service_queue import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_queue import recovery as recovery
from .test_competition_cohort_service_queue import runtime as runtime
from .test_competition_cohort_service_queue import scenario as scenario


@pytest.mark.parametrize("operation", ["readiness", "duplicate"])
async def test_native_mutex_wait_preserves_work_and_listener(api_case, operation, monkeypatch):
    s = api_case
    accepted = None
    if operation == "duplicate":
        accepted = (await post(s)).json()
        s.offline = {"history", "capture", "roster", "archive"}
        s.calls.clear()
    entered = asyncio.Event()
    loop = asyncio.get_running_loop()
    target = s.api._capacity if operation == "readiness" else s.c.queue.lookup

    def observed(*args):
        loop.call_soon_threadsafe(entered.set)
        return target(*args)

    owner, name = (s.api, "_capacity") if operation == "readiness" else (s.c.queue, "lookup")
    monkeypatch.setattr(owner, name, observed)
    lease = lock_private_file(s.c.queue.journal.lock_path)
    task = asyncio.create_task(ready(s) if operation == "readiness" else post(s))
    try:
        await asyncio.wait_for(entered.wait(), timeout=60)
        # The real native flock refuses this descriptor. HTTP ownership remains
        # held, while unrelated event-loop work still executes.
        await asyncio.sleep(0.1)
        assert not task.done()
        assert s.api.serial[s.c.cfg.catalog_sha256].locked()
        os.close(lease)
        lease = None
        reply = await asyncio.wait_for(task, timeout=60)
        assert reply.status_code == 200, reply.text
        if operation == "readiness":
            assert reply.json()["ready"] is True
            assert s.c.queue.entries() == ()
        else:
            assert reply.json() == accepted
            assert s.calls == []
            assert len(s.c.queue.entries()) == 1
            assert s.c.queue.lookup(inputs(s.c)[0]) is not None
    finally:
        if lease is not None:
            os.close(lease)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_mutex_wait_cancel_releases_owner_without_touching_queue(api_case, monkeypatch):
    s = api_case
    entered = asyncio.Event()
    loop = asyncio.get_running_loop()
    original = s.api._capacity

    def observed(*args):
        loop.call_soon_threadsafe(entered.set)
        return original(*args)

    monkeypatch.setattr(s.api, "_capacity", observed)
    lease = lock_private_file(s.c.queue.journal.lock_path)
    task = asyncio.create_task(ready(s))
    try:
        await asyncio.wait_for(entered.wait(), timeout=60)
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=60)
        assert not s.api.serial[s.c.cfg.catalog_sha256].locked()
    finally:
        os.close(lease)
        await asyncio.gather(task, return_exceptions=True)
    assert s.c.queue.entries() == ()
    assert (await ready(s)).json()["ready"] is True


@pytest.mark.parametrize("error", [OSError("I/O failure"), ValueError("changed record")])
async def test_local_validation_and_io_failures_are_not_retried(api_case, monkeypatch, error):
    s = api_case
    calls = 0

    def failed(*_args):
        nonlocal calls
        calls += 1
        raise error

    monkeypatch.setattr(s.api, "_capacity", failed)
    result = await ready(s)
    assert result.status_code == 200 and result.json()["ready"] is False
    assert calls == 1
    assert s.c.queue.entries() == ()
