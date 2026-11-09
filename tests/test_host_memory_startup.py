"""Actual native slot ownership for bounded, cancellable host construction."""

import asyncio
import contextvars
import os

import pytest

from umi import host_memory_admission as native
from umi import host_memory_runtime as memory
from umi import host_memory_startup as startup
from umi.host_model_execution import ModelExecutionAdmission

from .test_host_execution_memory import joint as joint
from .test_host_memory_admission import provisioned as provisioned

GIB = 1024**3


@pytest.fixture
def reserved(joint, monkeypatch):
    selection = joint.selection.model_copy(update={"startup_memory_bytes": 8 * GIB})
    monkeypatch.setattr(startup, "enforced_service_limit", lambda: 8 * GIB)
    monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB)
    monkeypatch.setattr(startup, "_available_memory", lambda: 13 * GIB)

    def runtime():
        return memory.memory_runtime(
            selection,
            maximum_aggregate_bytes=4 * GIB,
            role="phase_reviewer",
            protocol_policy_sha256=joint.body["protocol_policy_sha256"],
            evaluation_runtime_sha256=joint.body["evaluation_runtime_sha256"],
        )

    return selection, runtime


def test_explicit_selection_keeps_old_bytes_and_rejects_invalid_budget(joint):
    body = joint.selection.model_dump()
    assert "startup_memory_bytes" not in body
    assert memory.HostMemoryAdmissionSelection.model_validate(body).model_dump() == body
    for value in (0, -1, True):
        with pytest.raises(ValueError):
            memory.HostMemoryAdmissionSelection.model_validate(
                {**body, "startup_memory_bytes": value}
            )
    with pytest.raises(native.AdmissionBindingError, match="bounded joint"):
        native.HostMemoryAdmission(
            native._absolute(joint.selection.policy_path),
            expected_sha256=joint.selection.policy_sha256,
            _startup_reservation_bytes=9 * GIB,
        )


async def test_startup_replaces_idle_reservations_but_holds_actual_capacity(joint, reserved):
    _, runtime = reserved
    # Historical selections keep their original 20 GiB startup requirement.
    with pytest.raises(native.HostMemoryStartupPending):
        joint.graph()
    with runtime() as controller:
        async with startup.memory_startup(controller) as construction:
            assert startup.current_startup_reservation() is construction
            # Benchmark construction joins the reserved host, not a second idle
            # pool gate. Actual inference still cannot acquire the occupied slot.
            model = ModelExecutionAdmission(joint.selection, joint.policy)
            assert model.controller.try_acquire_group("transient", 1) is None
            assert controller.try_acquire("transient") is None
            startup.complete_memory_startup(construction)
            assert startup.current_startup_reservation() is None
            lease = model.controller.try_acquire_group("transient", 1)
            assert lease is not None
            lease.close()
    assert startup.current_startup_reservation() is None


async def test_waiter_cancellation_and_construction_failure_leave_no_grants(reserved):
    _, runtime = reserved
    entered = asyncio.Event()

    async def another_host():
        with runtime() as controller:
            async with startup.memory_startup(controller):
                entered.set()

    with runtime() as controller:
        with pytest.raises(RuntimeError, match="construction failed"):
            async with startup.memory_startup(controller):
                # Independent host context, sharing real kernel capacity files.
                waiter = contextvars.Context().run(asyncio.create_task, another_host())
                await asyncio.sleep(0)
                assert not entered.is_set()
                waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiter
                raise RuntimeError("construction failed")
        lease = controller.try_acquire("transient")
        assert lease is not None
        lease.close()
    assert not entered.is_set() and startup.current_startup_reservation() is None


@pytest.mark.parametrize("already_stopped", [False, True])
async def test_operator_stop_abandons_capacity_wait_without_waiting_for_owner(
    reserved, already_stopped
):
    _, runtime = reserved
    stop = asyncio.Event()
    if already_stopped:
        stop.set()

    async def another_host():
        with runtime() as controller, pytest.raises(startup.HostStartupStopped):
            async with startup.memory_startup(controller, stop=stop):
                pytest.fail("stopped host constructed")

    with runtime() as owner:
        async with startup.memory_startup(owner):
            waiter = contextvars.Context().run(asyncio.create_task, another_host())
            await asyncio.sleep(0)
            stop.set()
            await asyncio.wait_for(waiter, timeout=1)
            assert owner.try_acquire("transient") is None
        lease = owner.try_acquire("transient")
        assert lease is not None
        lease.close()


async def test_operator_stop_wins_when_capacity_becomes_free(reserved):
    _, runtime = reserved
    stop = asyncio.Event()
    with runtime() as controller:
        held = controller.try_acquire("transient")
        assert held is not None
        task = asyncio.create_task(controller.acquire("transient", stop=stop))
        await asyncio.sleep(0)
        held.close()
        stop.set()
        assert await asyncio.wait_for(task, timeout=1) is None
        lease = controller.try_acquire("transient")
        assert lease is not None
        lease.close()


async def test_service_cap_above_measured_budget_refuses_before_allocation(reserved, monkeypatch):
    _, runtime = reserved
    monkeypatch.setattr(startup, "enforced_service_limit", lambda: 9 * GIB)
    with runtime() as controller:
        with pytest.raises(native.AdmissionBindingError, match="service memory cap"):
            async with startup.memory_startup(controller):
                pytest.fail("unbounded host construction admitted")
        lease = controller.try_acquire("transient")
        assert lease is not None
        lease.close()


async def test_probe_is_not_a_lease_and_actual_grant_rechecks_memory(reserved, monkeypatch):
    selection, runtime = reserved
    observation = memory.probe_memory_startup(selection)
    assert observation["status"] == "admitted"
    assert observation["required_available_bytes"] == 13 * GIB
    assert observation["capacity_reserved"] is False
    with runtime() as controller:
        lease = controller.try_acquire("transient")
        assert lease is not None
        busy = memory.probe_memory_startup(selection)
        assert busy["required_available_bytes"] == 21 * GIB
        assert busy["status"] == "capacity_required"
        lease.close()
        monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB - 1)
        entered = False

        async def construct():
            nonlocal entered
            async with startup.memory_startup(controller):
                entered = True

        task = asyncio.create_task(construct())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not entered


def test_synchronous_factory_releases_on_success_and_failure(reserved):
    _, runtime = reserved
    with runtime() as controller:
        with startup.synchronous_memory_startup(controller):
            assert controller.try_acquire("transient") is None
        with (
            pytest.raises(ValueError, match="factory"),
            startup.synchronous_memory_startup(controller),
        ):
            raise ValueError("factory")
        lease = controller.try_acquire("transient")
        assert lease is not None
        lease.close()


async def test_async_caller_cannot_use_blocking_factory_or_nested_startup(reserved):
    _, runtime = reserved
    with runtime() as controller:
        with (
            pytest.raises(native.AdmissionBindingError, match="active event loop"),
            startup.synchronous_memory_startup(controller),
        ):
            pytest.fail("blocked event loop")
        async with startup.memory_startup(controller):
            with pytest.raises(native.AdmissionBindingError, match="nested host startup"):
                async with startup.memory_startup(controller):
                    pytest.fail("nested construction")


@pytest.mark.skipif(
    os.environ.get("UMI_TEST_BOUNDED_STARTUP") != "1", reason="bounded service only"
)
def test_real_service_budget_is_read_from_enforced_cgroup():
    # This suite runs in a bounded zero-swap systemd unit, not a synthetic path.
    assert 0 < startup.enforced_service_limit() <= 2 * GIB
