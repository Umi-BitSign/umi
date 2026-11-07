"""Real native leases/OFD lifetimes with an explicitly synthetic cgroup mount."""

import asyncio
import fcntl
import os
import signal
from types import SimpleNamespace

import pytest

from umi import host_memory_admission as native
from umi import host_memory_peer as peer
from umi import host_memory_startup as startup
from umi.host_execution_memory import expanded_execution_policy
from umi.host_model_execution import ModelExecutionAdmission, yield_model_preparation_capacity

from .test_host_execution_memory import joint as joint
from .test_host_execution_memory import parallel_joint as parallel_joint
from .test_host_execution_memory import provisioned as provisioned

GIB = 1024**3
pytestmark = pytest.mark.skipif(os.uname().sysname != "Linux", reason="Linux OFD witnesses")


def test_bounded_graph_uses_service_ceiling_without_discounting_models_or_peers(pool, monkeypatch):
    first, graph, next_model = [pool.controller() for _ in range(3)]
    graph.startup_reservation_bytes = 4 * GIB
    monkeypatch.setattr(startup, "enforced_service_limit", lambda: 4 * GIB)
    first_lease = first.try_acquire_group("transient", 1)
    graph_lease = next_lease = None
    try:
        # One 8 GiB job already owns capacity. A capped 4 GiB graph fits at
        # 17 GiB available, including the unchanged 4+1 GiB host/background.
        monkeypatch.setattr(native, "_available_memory", lambda: 17 * GIB - 1)
        assert graph.try_acquire("transient") is None
        assert graph.last_model_admission["shortfall_bytes"] == 1
        monkeypatch.setattr(native, "_available_memory", lambda: 17 * GIB)
        assert next_model.try_acquire_group("transient", 1) is None
        graph_lease = graph.try_acquire("transient")
        assert graph_lease is not None and graph_lease.service_bounded
        assert graph.last_model_admission["selected_reservation_bytes"] == 4 * GIB
        target = pool.container()
        with pytest.raises(native.AdmissionBindingError):
            graph.bind_model_container(graph_lease, "a" * 64, target)
        (target / "cgroup.events").write_text("populated 0\n")
        first_lease.close()
        # Peers continue charging the graph's full historical 8 GiB slot.
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB)
        next_lease = next_model.try_acquire_group("transient", 1)
        assert next_lease is not None and not next_lease.service_bounded
        assert next_model.last_model_admission["pending_reservation_bytes"] == 16 * GIB
    finally:
        for lease in (next_lease, graph_lease, first_lease):
            if lease is not None:
                lease.close()


@pytest.mark.parametrize("limit", [9 * GIB, "unavailable"])
def test_graph_cap_change_or_unavailable_measurement_keeps_full_charge(pool, monkeypatch, limit):
    controller = pool.controller()
    controller.startup_reservation_bytes = 4 * GIB

    def ceiling():
        if limit == "unavailable":
            raise native.AdmissionBindingError("no supported cap")
        return limit

    monkeypatch.setattr(startup, "enforced_service_limit", ceiling)
    monkeypatch.setattr(native, "_available_memory", lambda: 9 * GIB)
    assert controller.try_acquire("transient") is None
    assert controller.last_model_admission["selected_reservation_bytes"] == 8 * GIB
    assert controller.last_model_admission["required_available_bytes"] == 13 * GIB


def test_startup_probe_uses_selected_graph_budget_and_waits_for_consistent_slot_sample(
    pool, monkeypatch
):
    controller, model = pool.controller(), pool.controller()
    controller.startup_reservation_bytes = 4 * GIB
    lease = model.try_acquire_group("transient", 1)
    root = model._open_root()
    transaction = None
    try:
        monkeypatch.setattr(startup, "_available_memory", lambda: 17 * GIB)
        observation = startup.probe_startup_reservation(controller)
        assert observation["status"] == "admitted"
        assert observation["required_available_bytes"] == 17 * GIB
        assert observation["capacity_reserved"] is False
        transaction = model._transaction(root)
        assert transaction is not None
        observation = startup.probe_startup_reservation(controller)
        assert observation["status"] == "capacity_required"
        assert observation["eta_basis"] == "awaiting_native_capacity_transaction"
        assert "pending_reservation_bytes" not in observation
    finally:
        if transaction is not None:
            os.close(transaction)
        os.close(root)
        lease.close()


@pytest.mark.parametrize("cancel", [False, True])
async def test_transfer_yields_to_export_and_cancellation_cannot_grant_later(pool, cancel):
    model = ModelExecutionAdmission(pool.fixture.selection, pool.fixture.policy)
    peer_controller = pool.controller()
    entered = asyncio.Event()
    resumed = asyncio.Event()

    async def transfer():
        async with model.hold(pool.fixture.runtime, preparation=True):
            entered.set()
            await yield_model_preparation_capacity()
            resumed.set()

    task = asyncio.create_task(transfer())
    await asyncio.wait_for(entered.wait(), 1)
    export = peer_controller.try_acquire("owner_export")
    assert export is not None
    try:
        await asyncio.sleep(0.15)
        assert not resumed.is_set()
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    finally:
        export.close()
    if not cancel:
        await asyncio.wait_for(task, 1)
        assert resumed.is_set()
    next_export = peer_controller.try_acquire("owner_export")
    assert next_export is not None
    next_export.close()


async def test_second_transfer_waits_without_occupying_yielded_export_slot(pool):
    model = ModelExecutionAdmission(pool.fixture.selection, pool.fixture.policy)
    entered, finish = asyncio.Event(), asyncio.Event()
    second_entered = asyncio.Event()

    async def first():
        async with model.hold(pool.fixture.runtime, preparation=True):
            entered.set()
            await yield_model_preparation_capacity()
            await finish.wait()

    async def second():
        async with model.hold(pool.fixture.runtime, preparation=True):
            second_entered.set()

    first_task = asyncio.create_task(first())
    await asyncio.wait_for(entered.wait(), 1)
    second_task = asyncio.create_task(second())
    await asyncio.sleep(0)
    peer_controller = pool.controller()
    export = peer_controller.try_acquire("owner_export")
    try:
        assert export is not None
        await asyncio.sleep(0.15)
        assert not second_entered.is_set()
    finally:
        if export is not None:
            export.close()
        finish.set()
        await asyncio.wait_for(asyncio.gather(first_task, second_task), 1)
    assert second_entered.is_set()


async def test_preparation_checkpoint_cannot_release_another_tasks_lease(pool):
    model = ModelExecutionAdmission(pool.fixture.selection, pool.fixture.policy)
    async with model.hold(pool.fixture.runtime, preparation=True):
        with pytest.raises(RuntimeError, match="another task"):
            await asyncio.create_task(yield_model_preparation_capacity())
        assert pool.controller().try_acquire("owner_export") is None


@pytest.fixture
def pool(parallel_joint, provisioned, tmp_path, monkeypatch):
    fixture, _, previous = parallel_joint
    root, _, _, write, _ = provisioned
    slot = root / "third-model.slot"
    slot.write_bytes(b"")
    slot.chmod(0o440)
    info = slot.stat()
    policy = expanded_execution_policy(
        previous,
        [
            native.HostMemorySlot(
                name=slot.name,
                lane="transient",
                device=info.st_dev,
                inode=info.st_ino,
                reservation_bytes=8 * GIB,
            )
        ],
        qualification_sha256="c" * 64,
    )
    fixture.selection = fixture.selection.model_copy(
        update={"policy_sha256": write(policy.model_dump(mode="json", by_alias=True))}
    )
    kernel = tmp_path / "synthetic-cgroup-mount"
    kernel.mkdir()
    monkeypatch.setattr(native, "_available_memory", lambda: 64 * GIB)
    monkeypatch.setattr(native, "_require_cgroup2", lambda descriptor: None)

    def controller():
        value = fixture.graph()
        value.policy = value.policy.model_copy(update={"container_cgroup_roots": (str(kernel),)})
        return value

    def container(cid="a" * 64, ceiling=8 * GIB):
        target = kernel / ("libpod-" + cid + ".scope") / "container"
        target.mkdir(parents=True)
        (target / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        (target / "memory.max").write_text(str(ceiling))
        return target

    return SimpleNamespace(
        controller=controller,
        container=container,
        root=root,
        policy=policy,
        write=write,
        fixture=fixture,
    )


def test_three_independent_controllers_admit_staggered_live_models(pool):
    controllers = [pool.controller() for _ in range(3)]
    leases = []
    try:
        for index, controller in enumerate(controllers):
            lease = controller.try_acquire_group("transient", 1)
            assert lease is not None
            leases.append(lease)
            cid = "abc"[index] * 64
            assert controller.bind_model_container(lease, cid, pool.container(cid))
            row = controller.last_model_admission
            assert row["peer_container_credit_bytes"] == index * 8 * GIB
            assert row["owned_container_credit_bytes"] == 0
            assert row["pending_reservation_bytes"] == (index + 1) * 8 * GIB
            assert row["exclusive_orphan_hold"] is False
        assert pool.controller().try_acquire_group("transient", 1) is None
    finally:
        for lease in leases:
            lease.close()


def test_peer_credit_preserves_full_reservation_and_real_headroom(pool, monkeypatch):
    first, second = pool.controller(), pool.controller()
    lease = first.try_acquire_group("transient", 1)
    try:
        assert first.bind_model_container(lease, "a" * 64, pool.container())
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB - 1)
        assert second.try_acquire_group("transient", 1) is None
        assert second.last_model_admission["required_available_bytes"] == 21 * GIB
        assert second.last_model_admission["shortfall_bytes"] == 1
        assert second.last_model_admission["exclusive_orphan_hold"] is False
    finally:
        lease.close()


def test_three_model_live_gate_and_settlement_backpressure_use_current_reservations(
    pool, monkeypatch
):
    # Match the installed 8 GiB settlement allowances and 2 GiB background
    # reserve. Startup still needs the complete 47 GiB envelope; this test
    # characterizes per-operation admission AFTER that gate, not a bypass.
    body = pool.policy.model_dump(mode="json", by_alias=True)
    body["background_reservation_bytes"] = 2 * GIB
    for slot in body["slots"]:
        if slot["lane"] == "settlement_retained":
            slot["reservation_bytes"] = 8 * GIB
    body["incremental_budget_bytes"] = 41 * GIB
    pool.fixture.selection = pool.fixture.selection.model_copy(
        update={"policy_sha256": pool.write(body)}
    )
    monkeypatch.setattr(native, "_available_memory", lambda: 47 * GIB - 1)
    with pytest.raises(native.HostMemoryStartupPending):
        pool.controller()
    monkeypatch.setattr(native, "_available_memory", lambda: 47 * GIB)
    models = [pool.controller() for _ in range(3)]
    settlement = pool.controller()
    monkeypatch.setattr(native, "_available_memory", lambda: 32 * GIB)
    leases, containers = [], []
    retained = export = None
    try:
        for index, controller in enumerate(models):
            lease = controller.try_acquire_group("transient", 1)
            assert lease is not None
            leases.append(lease)
            cid = "abc"[index] * 64
            target = pool.container(cid)
            containers.append(target)
            assert controller.bind_model_container(lease, cid, target)
        assert models[-1].last_model_admission["required_available_bytes"] == 30 * GIB
        assert settlement.try_settlement("0" * 64, "coordinator") is None
        assert settlement.last_model_admission["required_available_bytes"] == 38 * GIB
        # Completed work frees its own capacity; the next settlement can run.
        (containers[0] / "cgroup.events").write_text("populated 0\n")
        leases[0].close()
        retained = settlement.try_settlement("0" * 64, "coordinator")
        assert retained is not None
        assert settlement.last_model_admission["required_available_bytes"] == 30 * GIB
        export = settlement.try_acquire("owner_export")
        assert export is not None
        assert settlement.last_model_admission["required_available_bytes"] == 31 * GIB
        assert settlement.try_settlement("1".zfill(64), "reviewer") is None
    finally:
        for lease in [export, retained, *leases]:
            if lease is not None:
                lease.close()


def test_staggered_models_remeasure_growth_and_do_not_credit_logical_release(pool, monkeypatch):
    # Use current allowances, with the startup gate satisfied separately.
    body = pool.policy.model_dump(mode="json", by_alias=True)
    body["background_reservation_bytes"] = 2 * GIB
    for slot in body["slots"]:
        if slot["lane"] == "settlement_retained":
            slot["reservation_bytes"] = 8 * GIB
    body["incremental_budget_bytes"] = 41 * GIB
    pool.fixture.selection = pool.fixture.selection.model_copy(
        update={"policy_sha256": pool.write(body)}
    )
    controllers = [pool.controller() for _ in range(3)]
    available = 31 * GIB
    monkeypatch.setattr(native, "_available_memory", lambda: available)
    leases, containers = [], []
    try:
        for index in range(2):
            controller = controllers[index]
            lease = controller.try_acquire_group("transient", 1)
            assert lease is not None
            leases.append(lease)
            cid = "ab"[index] * 64
            target = pool.container(cid)
            containers.append(target)
            assert controller.bind_model_container(lease, cid, target)
            # Synthetic full allocation after admission; no real memory consumed.
            available -= 8 * GIB
        third = controllers[2]
        assert third.try_acquire_group("transient", 1) is None
        assert third.last_model_admission["available_bytes"] == 15 * GIB
        assert third.last_model_admission["required_available_bytes"] == 30 * GIB
        assert third.last_model_admission["exclusive_orphan_hold"] is False
        # A closed lease and empty cgroup cannot invent returned resident pages.
        (containers[0] / "cgroup.events").write_text("populated 0\n")
        leases[0].close()
        assert third.try_acquire_group("transient", 1) is None
        assert third.last_model_admission["required_available_bytes"] == 22 * GIB
        assert third.last_model_admission["shortfall_bytes"] == 7 * GIB
        # Only the next native memory sample establishes actual returned space.
        available += 8 * GIB
        replacement = third.try_acquire_group("transient", 1)
        assert replacement is not None
        leases.append(replacement)
    finally:
        for lease in leases:
            lease.close()


@pytest.mark.parametrize("change", ["closed", "cleared", "inode", "ceiling", "unbound"])
def test_unknown_changed_or_expired_container_never_receives_peer_credit(pool, change):
    first, second = pool.controller(), pool.controller()
    lease = first.try_acquire_group("transient", 1)
    target = pool.container()
    other = None
    try:
        if change != "unbound":
            assert first.bind_model_container(lease, "a" * 64, target)
        if change == "closed":
            lease.close()
        elif change == "cleared":
            lease.clear_model_container()
        elif change == "inode":
            target.rename(target.with_name("old-container"))
            target = pool.container()
        elif change == "ceiling":
            (target / "memory.max").write_text(str(9 * GIB))
        other = second.try_acquire_group("transient", 1)
        assert other is None
        row = second.last_model_admission
        assert row["exclusive_orphan_hold"] is True
        assert row["unreserved_container_bytes"] == (GIB if change == "ceiling" else 8 * GIB)
    finally:
        if other is not None:
            other.close()
        lease.close()


def test_reused_slot_does_not_inherit_prior_container_witness(pool):
    first, second = pool.controller(), pool.controller()
    old = first.try_acquire_group("transient", 1)
    target = pool.container()
    assert first.bind_model_container(old, "a" * 64, target)
    old.close()
    (target / "cgroup.events").write_text("populated 0\n")
    new = first.try_acquire_group("transient", 1)
    try:
        assert new is not None and new.slot == old.slot
        (target / "cgroup.events").write_text("populated 1\n")
        assert second.try_acquire_group("transient", 1) is None
        assert second.last_model_admission["peer_container_credit_bytes"] == 0
    finally:
        new.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="native Linux process lifetime")
@pytest.mark.parametrize("kill", [False, True])
def test_process_death_drops_witness_and_orphan_remains_blocked(pool, kill):
    ready_read, ready_write = os.pipe()
    stop_read, stop_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(ready_read)
            os.close(stop_write)
            controller = pool.controller()
            lease = controller.try_acquire_group("transient", 1)
            assert lease is not None
            assert controller.bind_model_container(lease, "a" * 64, pool.container())
            os.write(ready_write, b"ready")
            os.read(stop_read, 1)
            # No Python finally/destructor cleanup: kernel owns release.
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(ready_write)
    os.close(stop_read)
    reaped = False
    other = None
    try:
        assert os.read(ready_read, 5) == b"ready"
        observer = pool.controller()
        other = observer.try_acquire_group("transient", 1)
        assert other is not None
        assert observer.last_model_admission["peer_container_credit_bytes"] == 8 * GIB
        other.close()
        other = None
        if kill:
            os.kill(child, signal.SIGKILL)
        else:
            os.write(stop_write, b"x")
        _, status = os.waitpid(child, 0)
        reaped = True
        assert status == (signal.SIGKILL if kill else 0)
        assert observer.try_acquire_group("transient", 1) is None
        assert observer.last_model_admission["exclusive_orphan_hold"] is True
        assert observer.last_model_admission["peer_container_credit_bytes"] == 0
    finally:
        if other is not None:
            other.close()
        os.close(ready_read)
        os.close(stop_write)
        if not reaped:
            os.kill(child, 9)
            os.waitpid(child, 0)


def test_readonly_slot_witness_survives_dup_only_until_last_descriptor(tmp_path):
    path = tmp_path / "slot"
    path.write_bytes(b"")
    path.chmod(0o440)
    owner, observer = os.open(path, os.O_RDONLY), os.open(path, os.O_RDONLY)
    duplicate = None
    try:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        peer.bind(owner, 123456)
        assert peer.observed_inode(observer) == 123456
        duplicate = os.dup(owner)
        os.close(owner)
        owner = None
        assert peer.observed_inode(observer) == 123456
        with pytest.raises(BlockingIOError):
            fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.close(duplicate)
        duplicate = None
        assert peer.observed_inode(observer) is None
        fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert path.read_bytes() == b"" and path.stat().st_mode & 0o777 == 0o440
    finally:
        for descriptor in (owner, observer, duplicate):
            if descriptor is not None:
                os.close(descriptor)


def test_leftover_witness_on_free_slot_refuses_new_generation(pool):
    controller = pool.controller()
    slot = next(s for s in controller.policy.slots if s.lane == "transient")
    descriptor = os.open(pool.root / slot.name, os.O_RDONLY)
    try:
        peer.bind(descriptor, 123456)
        with pytest.raises(native.AdmissionBindingError, match="unowned peer witness"):
            controller.try_acquire_group("transient", 1)
    finally:
        os.close(descriptor)


def test_malformed_kernel_witness_refuses_credit(pool):
    controller = pool.controller()
    slot = next(s for s in controller.policy.slots if s.lane == "transient")
    descriptor = os.open(pool.root / slot.name, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        peer._command(descriptor, "F_OFD_SETLK", fcntl.F_RDLCK, 12345, 2)
        with pytest.raises(ValueError, match="unsupported kernel geometry"):
            controller.try_acquire_group("transient", 1)
    finally:
        os.close(descriptor)


def test_cp_python_missing_gnu_constants_uses_actual_linux_capability(tmp_path, monkeypatch):
    for name in ("F_OFD_GETLK", "F_OFD_SETLK"):
        monkeypatch.delattr(fcntl, name, raising=False)
    path = tmp_path / "slot"
    path.write_bytes(b"")
    owner, observer = os.open(path, os.O_RDONLY), os.open(path, os.O_RDONLY)
    try:
        peer.bind(owner, 54321)
        assert peer.observed_inode(observer) == 54321
        peer.clear(owner)
        assert peer.observed_inode(observer) is None
    finally:
        os.close(owner)
        os.close(observer)


def test_unsupported_kernel_refuses_during_readonly_startup_probe(pool, monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("kernel OFD operation unsupported")

    monkeypatch.setattr(peer, "_command", unavailable)
    monkeypatch.setattr(
        fcntl, "flock", lambda *args: pytest.fail("probe must not acquire capacity")
    )
    with pytest.raises(OSError, match="OFD operation unsupported"):
        pool.controller()


def test_legacy_policy_keeps_local_only_credit(pool):
    first, second = pool.controller(), pool.controller()
    for controller in (first, second):
        controller.policy = controller.policy.model_copy(
            update={"schema_": "umi-host-execution-memory-admission/1"}
        )
    lease = first.try_acquire_group("transient", 1)
    try:
        assert first.bind_model_container(lease, "a" * 64, pool.container())
        assert second.try_acquire_group("transient", 1) is None
        assert second.last_model_admission["exclusive_orphan_hold"] is True
        assert "peer_container_credit_bytes" not in second.last_model_admission
    finally:
        lease.close()
