"""Real kernel demand lifetime and independent transfer/export scheduling."""

import asyncio
import os
from types import SimpleNamespace

import pytest

from umi import host_memory_export_wait as demand
from umi.host_model_execution import ModelExecutionAdmission, yield_model_preparation_capacity

from .test_host_execution_memory import joint as joint
from .test_host_execution_memory import parallel_joint as parallel_joint
from .test_host_execution_memory import provisioned as provisioned
from .test_host_memory_peer import pool as pool


def test_export_demand_is_shared_but_does_not_own_capacity(pool):
    a, b, reader = [pool.controller() for _ in range(3)]
    assert not demand.export_waiting(reader)
    with demand.export_waiter(a, "owner_export"):
        with demand.export_waiter(b, "owner_export"):
            assert demand.export_waiting(reader)
            lease = reader.try_acquire_group("owner_export", 1)
            assert lease is not None
            lease.close()
        assert demand.export_waiting(reader)
    assert not demand.export_waiting(reader)


async def test_cancelled_export_waiter_drops_demand_and_never_claims_capacity(pool):
    owner, reader = pool.controller(), pool.controller()
    held = owner.try_acquire_group("owner_export", 1)
    assert held is not None
    task = asyncio.create_task(reader.acquire("owner_export"))
    try:
        await asyncio.sleep(0)
        assert demand.export_waiting(owner)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not demand.export_waiting(owner)
    finally:
        held.close()
    lease = reader.try_acquire_group("owner_export", 1)
    assert lease is not None
    lease.close()


async def test_completed_range_leaves_time_for_an_independent_export_waiter(pool, monkeypatch):
    model = ModelExecutionAdmission(pool.fixture.selection, pool.fixture.policy)
    exporter = pool.controller()
    original = exporter.try_acquire
    attempts = 0
    events = []

    def delayed(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        # Reproduce an export reader missing the old single 100ms yield.
        return None if attempts <= 3 else original(*args, **kwargs)

    monkeypatch.setattr(exporter, "try_acquire", delayed)

    async def export():
        lease = await exporter.acquire("owner_export")
        try:
            events.append("export")
            await asyncio.sleep(0)
        finally:
            lease.close()

    async def transfer():
        async with model.hold(pool.fixture.runtime, preparation=True):
            task = asyncio.create_task(export())
            try:
                await asyncio.sleep(0)
                assert demand.export_waiting(model.controller)
                await yield_model_preparation_capacity()
                events.append("transfer_resumed")
                await task
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    await asyncio.wait_for(transfer(), 2)
    assert events == ["export", "transfer_resumed"]
    assert not demand.export_waiting(model.controller)


async def test_capacity_blocked_export_cannot_delay_transfer_indefinitely(pool, monkeypatch):
    controller = pool.controller()
    monkeypatch.setattr(demand, "MAX_EXPORT_TURN_SECONDS", 0.03)
    with demand.export_waiter(controller, "owner_export"):
        await asyncio.wait_for(demand.yield_to_export(controller, 0.01), 1)
        assert demand.export_waiting(controller)
        lease = controller.try_acquire_group("owner_export", 1)
        assert lease is not None
        lease.close()


def test_process_exit_releases_export_demand(pool):
    controller = pool.controller()
    ready_read, ready_write = os.pipe()
    finish_read, finish_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)
        os.close(finish_write)
        with demand.export_waiter(controller, "owner_export"):
            os.write(ready_write, b"1")
            os.read(finish_read, 1)
            os._exit(0)  # Intentionally bypass Python context cleanup.
    os.close(ready_write)
    os.close(finish_read)
    try:
        assert os.read(ready_read, 1) == b"1"
        assert demand.export_waiting(controller)
        os.write(finish_write, b"1")
        assert os.waitpid(pid, 0)[1] == 0
        assert not demand.export_waiting(controller)
    finally:
        os.close(ready_read)
        os.close(finish_write)


async def test_legacy_policy_does_not_open_priority_files():
    legacy = SimpleNamespace(peer_execution_stage=False)
    with demand.export_waiter(legacy, "owner_export"):
        assert not demand.export_waiting(legacy)
        await demand.yield_to_export(legacy, 0.1)
