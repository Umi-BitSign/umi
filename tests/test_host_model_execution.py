"""Real file leases across independent owners, with synthetic memory readings."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from umi import host_memory_admission as native
from umi.host_model_execution import ModelExecutionAdmission
from umi.open_competition import digest
from umi.protocol import StrictProtocolModel

from .test_host_memory_admission import provisioned as provisioned


class Runtime(StrictProtocolModel):
    memory_bytes: int = 8 * 1024**3


class Policy(StrictProtocolModel):
    evaluation_runtime_sha256: str


@pytest.fixture
def capacity(provisioned, monkeypatch):
    _, path, original, write, _ = provisioned
    runtime = Runtime()
    policy = Policy(evaluation_runtime_sha256=digest(runtime))
    slots = [
        dict(original["slots"][0], reservation_bytes=1024**3),
        dict(original["slots"][1], reservation_bytes=runtime.memory_bytes),
        dict(
            original["slots"][2],
            reservation_bytes=runtime.memory_bytes,
            lane="transient",
            settlement_role=None,
        ),
    ]
    body = {
        k: v
        for k, v in original.items()
        if k not in ("maximum_aggregate_bytes", "settlement_gate", "settlement_signals")
    }
    body.update(
        schema="umi-host-model-execution-admission/1",
        minimum_available_bytes=4 * 1024**3,
        incremental_budget_bytes=17 * 1024**3,
        background_reservation_bytes=2 * 1024**3,
        protocol_policy_sha256=digest(policy),
        evaluation_runtime_sha256=digest(runtime),
        container_cgroup_roots=("/sys/fs/cgroup/umi-isolated-test-absent",),
        slots=slots,
    )
    selection = SimpleNamespace(
        policy_path=str(path), policy_sha256=write(body), host_identity_path="/etc/machine-id"
    )
    monkeypatch.setattr(native, "_available_memory", lambda: 32 * 1024**3)
    return SimpleNamespace(
        runtime=runtime,
        policy=policy,
        selection=selection,
        start=lambda: ModelExecutionAdmission(selection, policy),
    )


def test_two_shared_jobs_and_separate_preparation(capacity):
    a, b = capacity.start(), capacity.start()
    first = a.controller.try_acquire_group("transient", 1)
    second = b.controller.try_acquire_group("transient", 1)
    assert first and second
    assert a.controller.try_acquire_group("transient", 1) is None
    prepare = b.controller.try_acquire_group("owner_export", 1)
    assert prepare
    prepare.close()
    first.close()
    second.close()


def test_exclusive_group_cannot_leak_a_partial_acquisition(capacity):
    a, b = capacity.start(), capacity.start()
    first = a.controller.try_acquire_group("transient", 1)
    assert b.controller.try_acquire_group("transient", 2) is None
    free = b.controller.try_acquire_group("transient", 1)
    assert free
    free.close()
    first.close()
    exclusive = a.controller.try_acquire_group("transient", 2)
    assert exclusive and b.controller.try_acquire_group("transient", 1) is None
    exclusive.close()
    again = b.controller.try_acquire_group("transient", 2)
    assert again
    again.close()


def test_later_grants_charge_busy_signed_reservations(capacity, monkeypatch):
    a = capacity.start()
    first = a.controller.try_acquire_group("transient", 1)
    monkeypatch.setattr(native, "_available_memory", lambda: 19 * 1024**3)
    assert a.controller.try_acquire_group("transient", 1) is None
    first.close()
    single = a.controller.try_acquire_group("transient", 1)
    assert single
    single.close()


async def test_nested_native_invocation_keeps_its_explicit_lease(capacity):
    a = capacity.start()
    async with a.hold(capacity.runtime, exclusive=True), a.invocation(capacity.runtime):
        assert a.controller.try_acquire_group("transient", 1) is None
    available = a.controller.try_acquire_group("transient", 2)
    assert available
    available.close()


async def test_cancelled_waiter_never_claims_released_slots(capacity):
    a = capacity.start()
    entered = asyncio.Event()

    async def waiting():
        async with a.hold(capacity.runtime):
            entered.set()

    async with a.hold(capacity.runtime, exclusive=True):
        task = asyncio.create_task(waiting())
        await asyncio.sleep(0)
        assert not entered.is_set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not entered.is_set()
    held = a.controller.try_acquire_group("transient", 2)
    assert held
    held.close()


@pytest.mark.parametrize("preparation", [False, True])
async def test_capacity_wait_identifies_preparation_or_invocation(
    capacity, monkeypatch, caplog, preparation
):
    caplog.set_level("INFO", logger="umi.competition.progress")
    a = capacity.start()
    monkeypatch.setattr(native, "_available_memory", lambda: 0)

    async def waiting():
        async with a.hold(capacity.runtime, preparation=preparation):
            pytest.fail("unavailable memory cannot admit work")

    task = asyncio.create_task(waiting())
    try:
        await asyncio.sleep(0)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    waits = [
        event
        for record in caplog.records
        if record.name == "umi.competition.progress"
        if (event := json.loads(record.message))["status"] == "waiting"
    ]
    assert len(waits) == 1
    assert waits[0]["reason_code"] == (
        "host_model_preparation_capacity" if preparation else "host_model_invocation_capacity"
    )


def test_changed_runtime_cannot_borrow_a_smaller_reservation(capacity):
    with pytest.raises(ValueError, match="signed runtime"):
        capacity.start().check_runtime(Runtime(memory_bytes=16 * 1024**3))


def test_unowned_live_container_still_consumes_its_full_ceiling(capacity, tmp_path, monkeypatch):
    a = capacity.start()
    root = tmp_path / "kernel-view"
    target = root / ("libpod-" + "a" * 64 + ".scope") / "container"
    target.mkdir(parents=True)
    (target / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    (target / "memory.max").write_text(str(8 * 1024**3))
    a.controller.policy = a.controller.policy.model_copy(
        update={"container_cgroup_roots": (str(root),)}
    )
    monkeypatch.setattr(native, "_available_memory", lambda: 19 * 1024**3)
    assert a.controller.try_acquire_group("transient", 1) is None
    (target / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    recovered = a.controller.try_acquire_group("transient", 1)
    assert recovered
    recovered.close()
