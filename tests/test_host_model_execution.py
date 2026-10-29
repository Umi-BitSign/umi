"""Real file leases across independent owners, with synthetic memory readings."""

import asyncio
import json
import os
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
        if (event := json.loads(record.message)).get("schema") == "umi-transport-work-progress/1"
        and event["status"] == "waiting"
    ]
    assert len(waits) == 1
    assert waits[0]["reason_code"] == (
        "host_model_preparation_capacity" if preparation else "host_model_invocation_capacity"
    )
    observations = [
        event
        for record in caplog.records
        if (event := json.loads(record.message)).get("schema")
        == "umi-model-admission-observation/1"
    ]
    assert len(observations) == 1 and observations[0]["state"] == "waiting"
    assert observations[0]["available_bytes"] == 0
    assert observations[0]["required_available_bytes"] == (7 if preparation else 14) * 1024**3
    assert observations[0]["shortfall_bytes"] == observations[0]["required_available_bytes"]


def test_changed_runtime_cannot_borrow_a_smaller_reservation(capacity):
    with pytest.raises(ValueError, match="signed runtime"):
        capacity.start().check_runtime(Runtime(memory_bytes=16 * 1024**3))


def test_unowned_live_container_still_consumes_its_full_ceiling(capacity, tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_require_cgroup2", lambda descriptor: None)
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


@pytest.fixture
def model_cgroup(capacity, tmp_path, monkeypatch):
    """Explicit synthetic kernel view; production still requires cgroup2."""
    a = capacity.start()
    root = tmp_path / "kernel-model-view"
    root.mkdir()
    a.controller.policy = a.controller.policy.model_copy(
        update={"container_cgroup_roots": (str(root),)}
    )
    require_kernel = native._require_cgroup2
    monkeypatch.setattr(native, "_require_cgroup2", lambda descriptor: None)

    def create(cid="a" * 64, ceiling=8 * 1024**3):
        target = root / ("libpod-" + cid + ".scope") / "container"
        target.mkdir(parents=True)
        (target / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        (target / "memory.max").write_text(str(ceiling))
        return target

    return SimpleNamespace(a=a, root=root, create=create, require_kernel=require_kernel)


def test_exact_live_container_credits_only_its_already_charged_lease(model_cgroup, monkeypatch):
    c = model_cgroup.a.controller
    first = c.try_acquire_group("transient", 1)
    target = model_cgroup.create()
    second = None
    try:
        monkeypatch.setattr(native, "_available_memory", lambda: 22 * 1024**3)
        assert c.try_acquire_group("transient", 1) is None
        assert c.last_model_admission["required_available_bytes"] == 30 * 1024**3
        assert c.bind_model_container(first, "a" * 64, target)
        second = c.try_acquire_group("transient", 1)
        assert second
        observed = c.last_model_admission
        assert observed["pending_reservation_bytes"] == 16 * 1024**3
        assert observed["owned_container_credit_bytes"] == 8 * 1024**3
        assert observed["required_available_bytes"] == 22 * 1024**3
        # A standalone inventory has no proof that a lease was already charged.
        assert c._model_container_reservations() == 8 * 1024**3
    finally:
        if second:
            second.close()
        first.close()


def test_credit_does_not_make_insufficient_real_headroom_admissible(model_cgroup, monkeypatch):
    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    try:
        assert c.bind_model_container(lease, "a" * 64, model_cgroup.create())
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * 1024**3)
        assert c.try_acquire_group("transient", 1) is None
        assert c.last_model_admission["shortfall_bytes"] == 1024**3
    finally:
        lease.close()


def test_other_controller_and_orphan_keep_full_native_charge(model_cgroup, capacity, monkeypatch):
    c = model_cgroup.a.controller
    other = capacity.start().controller
    other.policy = c.policy
    lease = c.try_acquire_group("transient", 1)
    target = model_cgroup.create()
    try:
        assert c.bind_model_container(lease, "a" * 64, target)
        monkeypatch.setattr(native, "_available_memory", lambda: 22 * 1024**3)
        assert other.try_acquire_group("transient", 1) is None
        assert other.last_model_admission["owned_container_credit_bytes"] == 0
        lease.close()
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * 1024**3)
        assert c.try_acquire_group("transient", 1) is None
        assert c.last_model_admission["unreserved_container_bytes"] == 8 * 1024**3
        with pytest.raises(native.AdmissionBindingError, match="live model acquisition"):
            c.bind_model_container(lease, "a" * 64, target)
    finally:
        lease.close()


def test_reused_slot_and_expired_invocation_do_not_inherit_credit(model_cgroup, monkeypatch):
    from umi.host_model_execution import ModelInvocationCapacity

    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    token = ModelInvocationCapacity(c, lease)
    target = model_cgroup.create()
    assert token.bind_container("a" * 64, target)
    inode, generation = lease.slot.inode, lease._generation
    lease.close()
    replacement = c.try_acquire_group("transient", 1)
    try:
        assert replacement.slot.inode == inode and replacement._generation is not generation
        assert replacement._model_container is None
        with pytest.raises(native.AdmissionBindingError, match="no longer owned"):
            token.bind_container("a" * 64, target)
        monkeypatch.setattr(native, "_available_memory", lambda: 22 * 1024**3)
        assert c.try_acquire_group("transient", 1) is None
        assert c.last_model_admission["owned_container_credit_bytes"] == 0
    finally:
        token.close()
        replacement.close()


def test_one_container_and_one_acquisition_cannot_spend_credit_twice(model_cgroup):
    c = model_cgroup.a.controller
    first, second = c.try_acquire_group("transient", 1), c.try_acquire_group("transient", 1)
    a, b = model_cgroup.create(), model_cgroup.create("b" * 64)
    try:
        assert c.bind_model_container(first, "a" * 64, a)
        assert c.bind_model_container(first, "a" * 64, a)
        with pytest.raises(native.AdmissionBindingError, match="another model acquisition"):
            c.bind_model_container(second, "a" * 64, a)
        with pytest.raises(native.AdmissionBindingError, match="another container"):
            c.bind_model_container(first, "b" * 64, b)
        busy = {(first.slot.device, first.slot.inode)}
        assert c._model_container_reservations(busy) == 8 * 1024**3
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize("ceiling", ["max", "0", "-1", str(1024**4 + 1)])
def test_bound_container_never_hides_an_invalid_ceiling(model_cgroup, ceiling):
    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    target = model_cgroup.create()
    try:
        assert c.bind_model_container(lease, "a" * 64, target)
        (target / "memory.max").write_text(ceiling)
        with pytest.raises(native.AdmissionBindingError, match="no bounded memory ceiling"):
            c.try_acquire_group("owner_export", 1)
    finally:
        lease.close()


def test_bound_container_excess_ceiling_remains_charged(model_cgroup, monkeypatch):
    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    target = model_cgroup.create()
    try:
        assert c.bind_model_container(lease, "a" * 64, target)
        (target / "memory.max").write_text(str(16 * 1024**3))
        monkeypatch.setattr(native, "_available_memory", lambda: 22 * 1024**3)
        assert c.try_acquire_group("transient", 1) is None
        assert c.last_model_admission["container_ceiling_bytes"] == 16 * 1024**3
        assert c.last_model_admission["unreserved_container_bytes"] == 8 * 1024**3
    finally:
        lease.close()


def test_replaced_cgroup_identity_is_unowned(model_cgroup):
    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    target = model_cgroup.create()
    try:
        assert c.bind_model_container(lease, "a" * 64, target)
        target.rename(target.with_name("old-container"))
        model_cgroup.create()
        busy = {(lease.slot.device, lease.slot.inode)}
        assert c._model_container_reservations(busy) == 8 * 1024**3
    finally:
        lease.close()


def test_non_kernel_or_symlink_container_cannot_get_credit(model_cgroup, monkeypatch):
    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    target = model_cgroup.create()
    try:
        monkeypatch.setattr(native, "_require_cgroup2", model_cgroup.require_kernel)
        with pytest.raises(native.AdmissionBindingError, match="kernel cgroup2"):
            c.bind_model_container(lease, "a" * 64, target)
        monkeypatch.setattr(native, "_require_cgroup2", lambda descriptor: None)
        original = target.with_name("original")
        target.rename(original)
        target.symlink_to(original, target_is_directory=True)
        with pytest.raises(OSError):
            c.bind_model_container(lease, "a" * 64, target)
        assert lease._model_container is None
    finally:
        lease.close()


def test_forked_process_cannot_reuse_parent_container_credit(model_cgroup):
    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    target = model_cgroup.create()
    assert c.bind_model_container(lease, "a" * 64, target)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_fd)
            charged = c._model_container_reservations({(lease.slot.device, lease.slot.inode)})
            os.write(write_fd, str(charged).encode())
        finally:
            os._exit(0)
    try:
        os.close(write_fd)
        assert os.read(read_fd, 128) == str(8 * 1024**3).encode()
    finally:
        status = os.waitpid(pid, 0)[1]
        os.close(read_fd)
        lease.close()
    assert status == 0


def test_missing_unpopulated_and_expired_token_get_no_credit(model_cgroup):
    from umi.host_model_execution import ModelInvocationCapacity

    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    token = ModelInvocationCapacity(c, lease)
    target = model_cgroup.root / ("libpod-" + "a" * 64 + ".scope") / "container"
    try:
        assert not token.bind_container("a" * 64, target)
        model_cgroup.create()
        (target / "cgroup.events").write_text("populated 0\nfrozen 0\n")
        assert not token.bind_container("a" * 64, target)
        (target / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        assert token.bind_container("a" * 64, target)
        token.close()
        assert lease._model_container is None and not lease.closed
        with pytest.raises(native.AdmissionBindingError, match="no longer owned"):
            token.bind_container("a" * 64, target)
    finally:
        token.close()
        lease.close()


def test_cid_root_and_preparation_lease_must_match(model_cgroup, tmp_path):
    c = model_cgroup.a.controller
    lease = c.try_acquire_group("transient", 1)
    prepare = c.try_acquire_group("owner_export", 1)
    target = model_cgroup.create()
    try:
        for selected, cid, path in (
            (lease, "b" * 64, target),
            (lease, "a" * 64, tmp_path / target.parent.name / "container"),
            (prepare, "a" * 64, target),
        ):
            with pytest.raises(native.AdmissionBindingError, match="live model acquisition"):
                c.bind_model_container(selected, cid, path)
        assert lease._model_container is None and prepare._model_container is None
    finally:
        lease.close()
        prepare.close()


async def test_child_task_does_not_borrow_inherited_parent_invocation(capacity):
    a = capacity.start()
    entered = asyncio.Event()

    async def child():
        async with a.invocation(capacity.runtime):
            entered.set()

    async with a.hold(capacity.runtime, exclusive=True):
        task = asyncio.create_task(child())
        await asyncio.sleep(0)
        assert not entered.is_set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


async def test_successful_grant_reports_actual_owned_credit(model_cgroup, monkeypatch, caplog):
    a = model_cgroup.a
    caplog.set_level("INFO", logger="umi.competition.progress")
    async with a.invocation(Runtime()) as token:
        assert token.bind_container("a" * 64, model_cgroup.create())
        monkeypatch.setattr(native, "_available_memory", lambda: 22 * 1024**3)

        async def second():
            async with a.invocation(Runtime()):
                pass

        await asyncio.create_task(second())
    grants = [
        event
        for record in caplog.records
        if (event := json.loads(record.message)).get("schema")
        == "umi-model-admission-observation/1"
        and event["state"] == "admitted"
    ]
    assert len(grants) == 2
    assert grants[1]["owned_container_credit_bytes"] == 8 * 1024**3
    assert grants[1]["pending_reservation_bytes"] == 16 * 1024**3
    assert grants[1]["required_available_bytes"] == 22 * 1024**3
    assert grants[1]["shortfall_bytes"] == 0
