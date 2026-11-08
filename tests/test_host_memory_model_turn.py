"""Ready inference gets a bounded scheduling turn without additional capacity."""

import asyncio
import os
import signal

import pytest

from umi import host_memory_admission as native
from umi import host_memory_export_wait as demand
from umi import host_memory_startup as startup
from umi.host_model_execution import ModelExecutionAdmission

from .test_host_execution_memory import joint as joint
from .test_host_memory_graph_peer import shared as shared
from .test_host_memory_peer import parallel_joint as parallel_joint
from .test_host_memory_peer import pool as pool
from .test_host_memory_peer import provisioned as provisioned

GIB = 1024**3


async def waiting(controller):
    async def poll():
        while not demand.model_waiting(controller):
            await asyncio.sleep(0.005)

    await asyncio.wait_for(poll(), 2)


def test_export_and_model_markers_are_independent_and_reserve_nothing(pool):
    owner, reader = pool.controller(), pool.controller()
    with demand.export_waiter(owner, "owner_export"):
        assert demand.export_waiting(reader) and not demand.model_waiting(reader)
        with demand.model_waiter(owner, "transient"):
            assert demand.export_waiting(reader) and demand.model_waiting(reader)
            lease = reader.try_acquire_group("transient", 3)
            assert lease is not None
            lease.close()
        assert demand.export_waiting(reader) and not demand.model_waiting(reader)
    assert not demand.export_waiting(reader)
    with demand.model_waiter(owner, "owner_export"):
        assert not demand.model_waiting(reader)


async def test_ready_model_gets_released_slot_before_new_graph(pool):
    model = ModelExecutionAdmission(pool.fixture.selection, pool.fixture.policy)
    graph = pool.controller()
    occupied = [graph.try_acquire("transient") for _ in range(3)]
    entered, finish = asyncio.Event(), asyncio.Event()

    async def invoke():
        async with model.hold(pool.fixture.runtime):
            entered.set()
            await finish.wait()

    invocation = asyncio.create_task(invoke())
    graph_task = None
    try:
        await waiting(graph)
        graph_task = asyncio.create_task(graph.acquire("transient"))
        await asyncio.sleep(0)
        occupied.pop().close()
        await asyncio.wait_for(entered.wait(), 2)
        assert not graph_task.done()
        assert not demand.model_waiting(graph)
        finish.set()
        await asyncio.wait_for(invocation, 2)
        lease = await asyncio.wait_for(graph_task, 2)
        lease.close()
    finally:
        finish.set()
        for task in (invocation, graph_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(*(t for t in (invocation, graph_task) if t), return_exceptions=True)
        for lease in occupied:
            lease.close()


async def test_capacity_blocked_model_cannot_hold_fitting_graph_forever(pool, monkeypatch):
    model, graph = pool.controller(), pool.controller()
    graph.startup_reservation_bytes = 4 * GIB
    monkeypatch.setattr(startup, "enforced_service_limit", lambda: 4 * GIB)
    monkeypatch.setattr(native, "_available_memory", lambda: 9 * GIB)
    monkeypatch.setattr(demand, "MAX_MODEL_TURN_SECONDS", 0.02)
    assert model.try_acquire_group("transient", 1) is None
    with demand.model_waiter(model, "transient"):
        lease = await asyncio.wait_for(graph.acquire("transient"), 1)
        try:
            assert lease.service_bounded
            assert graph.last_model_admission["required_available_bytes"] == 9 * GIB
            assert demand.model_waiting(graph)
        finally:
            lease.close()


async def test_cancelled_model_removes_demand_without_later_acquisition(pool):
    model = ModelExecutionAdmission(pool.fixture.selection, pool.fixture.policy)
    graph = pool.controller()
    occupied = [graph.try_acquire("transient") for _ in range(3)]

    async def invoke():
        async with model.hold(pool.fixture.runtime):
            pytest.fail("cancelled invocation acquired capacity")

    task = asyncio.create_task(invoke())
    try:
        await waiting(graph)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not demand.model_waiting(graph)
    finally:
        for lease in occupied:
            lease.close()
    lease = graph.try_acquire_group("transient", 3)
    assert lease is not None
    lease.close()


async def test_graph_cancellation_during_courtesy_leaves_no_reservation(pool):
    controller = pool.controller()
    with demand.model_waiter(controller, "transient"):
        task = asyncio.create_task(controller.acquire("transient"))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        lease = controller.try_acquire_group("transient", 3)
        assert lease is not None
        lease.close()


async def test_retained_graph_and_export_do_not_wait_for_inference(pool, shared, monkeypatch):
    controller, _ = shared
    retained = controller.try_settlement("0" * 64, "coordinator")
    monkeypatch.setattr(demand, "MAX_MODEL_TURN_SECONDS", 10)
    try:
        with demand.model_waiter(pool.controller(), "transient"):
            graph = await asyncio.wait_for(controller.acquire("transient"), 2)
            export = await asyncio.wait_for(controller.acquire("owner_export"), 2)
            graph.close()
            export.close()
    finally:
        retained.close()


def test_dead_model_waiter_releases_kernel_demand(pool):
    controller = pool.controller()
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        try:
            with demand.model_waiter(controller, "transient"):
                os.write(write, b"ready")
                signal.pause()
        finally:
            os._exit(0)
    os.close(write)
    try:
        assert os.read(read, 5) == b"ready"
        assert demand.model_waiting(controller)
    finally:
        os.close(read)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    assert not demand.model_waiting(controller)
