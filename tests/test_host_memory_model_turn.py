"""Ready inference gets a bounded scheduling turn without additional capacity."""

import asyncio
import json
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


def test_pending_model_drains_shared_graph_before_new_owners(pool, shared):
    graph, _ = shared
    model = pool.controller()
    current = [graph.try_acquire("transient") for _ in range(2)]
    occupied = model.try_acquire_group("transient", 2)
    assert all(current) and occupied is not None
    admitted = None
    try:
        with demand.model_waiter(model, "transient"):
            assert model.try_acquire_group("transient", 1) is None
            assert graph.try_acquire("transient") is None
            assert graph.last_model_admission["active_graph_leases"] == 2
            current.pop().close()
            assert graph.try_acquire("transient") is None
            assert graph.last_model_admission["active_graph_leases"] == 1
            current.pop().close()
            admitted = model.try_acquire_group("transient", 1)
            assert admitted is not None
            assert graph.try_acquire("transient") is None
        admitted.close()
        admitted = graph.try_acquire("transient")
        assert admitted is not None
    finally:
        for lease in [admitted, occupied, *current]:
            if lease is not None:
                lease.close()


def test_removed_model_demand_resumes_sharing_without_drain(pool, shared):
    graph, _ = shared
    first = graph.try_acquire("transient")
    second = None
    try:
        with demand.model_waiter(pool.controller(), "transient"):
            assert graph.try_acquire("transient") is None
            assert graph.last_model_admission["graph_drain_for_model"]
        second = graph.try_acquire("transient")
        assert second is not None and first.slot == second.slot
    finally:
        for lease in (first, second):
            if lease is not None:
                lease.close()


async def test_waiting_third_model_runs_after_shared_graph_drains(
    pool, shared, monkeypatch, caplog
):
    graph, _ = shared
    occupied = pool.controller().try_acquire_group("transient", 2)
    current = graph.try_acquire("transient")
    assert occupied is not None and current is not None
    model = ModelExecutionAdmission(pool.fixture.selection, pool.fixture.policy)
    monkeypatch.setattr(demand, "MAX_MODEL_TURN_SECONDS", 0.02)
    caplog.set_level("INFO", logger="umi.competition.progress")
    entered, finish = asyncio.Event(), asyncio.Event()

    async def invoke():
        async with model.hold(pool.fixture.runtime):
            entered.set()
            await finish.wait()

    invocation = asyncio.create_task(invoke())
    queued = lease = None
    try:
        await waiting(graph)
        queued = asyncio.create_task(graph.acquire("transient"))
        await asyncio.sleep(0.05)
        assert not queued.done() and not current.closed
        observations = [json.loads(record.message) for record in caplog.records]
        assert any(
            row.get("eta_basis") == "awaiting_current_graph_drain_for_model"
            and row["active_graph_leases"] == 1
            for row in observations
        )
        current.close()
        await asyncio.wait_for(entered.wait(), 2)
        assert not queued.done()
        finish.set()
        await asyncio.wait_for(invocation, 2)
        lease = await asyncio.wait_for(queued, 2)
    finally:
        finish.set()
        for task in (invocation, queued):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (invocation, queued) if task), return_exceptions=True
        )
        for held in (current, occupied, lease):
            if held is not None:
                held.close()


def test_nonfitting_model_does_not_stop_fresh_graph_after_drain(pool, shared, monkeypatch):
    graph, root = shared
    model = pool.controller()
    graph.startup_reservation_bytes = 4 * GIB
    (root / "memory.max").write_text(str(4 * GIB))
    monkeypatch.setattr(startup, "enforced_service_limit", lambda: 4 * GIB)
    monkeypatch.setattr(native, "_available_memory", lambda: 9 * GIB)
    current = graph.try_acquire("transient")
    assert current is not None
    next_graph = None
    try:
        with demand.model_waiter(model, "transient"):
            assert model.try_acquire_group("transient", 1) is None
            assert graph.try_acquire("transient") is None
            current.close()
            # Model still cannot fit in this synthetic memory sample, even
            # after the graph drains; the lower graph service cap can proceed.
            assert model.try_acquire_group("transient", 1) is None
            next_graph = graph.try_acquire("transient")
            assert next_graph is not None
    finally:
        for lease in (current, next_graph):
            if lease is not None:
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
