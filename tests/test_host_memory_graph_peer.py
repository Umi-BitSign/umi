"""Shared graph ceilings with real flock/OFD ownership and synthetic cgroups."""

import io
import os
from pathlib import Path

import pytest

from umi import host_memory_admission as native
from umi import host_memory_graph_peer as graph
from umi import host_memory_peer as peer
from umi import host_memory_startup as startup

from .test_host_execution_memory import joint as joint
from .test_host_memory_peer import parallel_joint as parallel_joint
from .test_host_memory_peer import pool as pool
from .test_host_memory_peer import provisioned as provisioned

GIB = 1024**3
_KERNEL_CGROUP_CHECK = native._require_cgroup2


@pytest.fixture
def shared(pool, tmp_path, monkeypatch):
    body = pool.policy.model_dump(mode="json", by_alias=True)
    for slot in body["slots"]:
        if slot["lane"] == "settlement_retained":
            slot["reservation_bytes"] = 8 * GIB
    body["incremental_budget_bytes"] = sum(slot["reservation_bytes"] for slot in body["slots"])
    pool.fixture.selection = pool.fixture.selection.model_copy(
        update={"policy_sha256": pool.write(body)}
    )
    root = tmp_path / "service"
    root.mkdir()
    for name in graph._FILES:
        (root / name).write_text("0\n")
    (root / "memory.max").write_text(str(8 * GIB))
    monkeypatch.setattr(graph, "_membership", lambda pid: root)
    monkeypatch.setattr(graph, "_operator_controlled", lambda root, name: True)
    monkeypatch.setattr(graph, "own_binding", pool.native_graph_binding)
    monkeypatch.setattr(startup, "enforced_service_limit", lambda: 8 * GIB)
    controller = pool.controller()
    controller.startup_reservation_bytes = 8 * GIB
    return controller, root


def test_three_graphs_charge_one_service_ceiling_but_models_keep_full_grant(
    pool, shared, monkeypatch
):
    controller, _ = shared
    model = pool.controller()
    leases = []
    try:
        monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB)
        for _ in range(3):
            lease = controller.try_acquire("transient")
            assert lease is not None and lease.service_bounded
            leases.append(lease)
            assert controller.last_model_admission["pending_reservation_bytes"] == 8 * GIB
            assert controller.last_model_admission["required_available_bytes"] == 13 * GIB
        assert len({lease._graph_binding[2] for lease in leases}) == 3
        target = pool.container()
        with pytest.raises(native.AdmissionBindingError, match="container binding"):
            controller.bind_model_container(leases[0], "a" * 64, target)
        (target / "cgroup.events").write_text("populated 0\n")
        leases.pop().close()
        assert model.try_acquire_group("transient", 1) is None
        assert model.last_model_admission["required_available_bytes"] == 21 * GIB
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB)
        model_lease = model.try_acquire_group("transient", 1)
        assert model_lease is not None and not model_lease.service_bounded
        leases.append(model_lease)
    finally:
        for lease in leases:
            lease.close()


def test_independent_reader_and_startup_probe_share_only_proven_graph_ceiling(
    pool, shared, monkeypatch
):
    controller, _ = shared
    leases = [controller.try_acquire("transient") for _ in range(2)]
    reader = pool.controller()
    try:
        monkeypatch.setattr(startup, "_available_memory", lambda: 21 * GIB)
        row = startup.probe_startup_reservation(reader)
        assert row["status"] == "admitted"
        assert row["pending_reservation_bytes"] == 16 * GIB
        assert row["shared_graph_ceiling_discount_bytes"] == 8 * GIB
        # Existing /2 model inventory remains compatible: each control-file
        # marker is unique, and neither can credit a model directory.
        busy = {(lease.slot.device, lease.slot.inode) for lease in leases}
        assert reader._model_container_reservations(busy) == 0
        assert reader.last_model_admission["peer_container_credit_bytes"] == 0
    finally:
        for lease in leases:
            lease.close()


def test_retained_settlement_and_transient_graph_share_the_service_cap(pool, shared, monkeypatch):
    controller, _ = shared
    reader = pool.controller()
    retained = controller.try_settlement("0" * 64, "coordinator")
    transient = model = None
    try:
        assert retained is not None and retained._graph_binding is not None
        monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB)
        transient = controller.try_acquire("transient")
        assert transient is not None
        assert transient.slot == retained.slot
        assert controller.last_model_admission["additional_reservation_bytes"] == 0
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB)
        model = reader.try_acquire_group("transient", 1)
        assert model is not None and not model.service_bounded
        assert reader.last_model_admission["required_available_bytes"] == 21 * GIB
        assert reader.last_model_admission["selected_reservation_bytes"] == 8 * GIB
    finally:
        for lease in (model, transient, retained):
            if lease is not None:
                lease.close()


@pytest.mark.parametrize("role", ["coordinator", "reviewer"])
def test_retained_graph_work_leaves_three_model_slots_and_survives_owner_close(
    pool, shared, monkeypatch, role
):
    controller, _ = shared
    reader = pool.controller()
    retained = controller.try_settlement("0" * 64, role)
    graphs, models = [], []
    try:
        graphs = [controller.try_acquire("transient") for _ in range(2)]
        assert all(lease.slot == retained.slot for lease in graphs)
        retained.close()
        # Closing the scheduler's reference cannot release work still draining,
        # its cohort marker, its witness, or the independent replica's gate.
        assert reader.try_settlement("0" * 64, role) is None
        monkeypatch.setattr(native, "_available_memory", lambda: 37 * GIB)
        for _ in range(3):
            lease = reader.try_acquire_group("transient", 1)
            assert lease is not None and not lease.service_bounded
            models.append(lease)
        assert reader.last_model_admission["required_available_bytes"] == 37 * GIB
        graphs[0].close()
        assert reader.try_settlement("0" * 64, role) is None
        graphs[1].close()
        replacement = reader.try_settlement("0" * 64, role)
        assert replacement is not None
        replacement.close()
    finally:
        for lease in [*models, *graphs, retained]:
            if lease is not None:
                lease.close()


@pytest.mark.parametrize("change", ["cap", "swap", "witness", "closed", "fork"])
def test_changed_retained_owner_cannot_lend_capacity(pool, shared, monkeypatch, change):
    controller, root = shared
    retained = controller.try_settlement("0" * 64, "coordinator")
    transient = None
    try:
        if change == "cap":
            (root / "memory.max").write_text(str(4 * GIB))
        elif change == "swap":
            (root / "memory.swap.max").write_text("1")
        elif change == "witness":
            peer.clear(retained._descriptor)
        elif change == "closed":
            retained.close()
        else:
            retained._creator_pid = -1
        transient = controller.try_acquire("transient")
        assert transient is not None and transient.slot.lane == "transient"
        assert "shared_retained_graph_slot" not in controller.last_model_admission
    finally:
        if transient is not None:
            transient.close()
        retained.close()


def test_export_does_not_borrow_retained_graph_capacity(pool, shared):
    controller, _ = shared
    retained = controller.try_settlement("0" * 64, "coordinator")
    export = controller.try_acquire("owner_export")
    try:
        assert export is not None and export.slot.lane == "owner_export"
        assert controller.try_acquire("owner_export") is None
    finally:
        export.close()
        retained.close()


def test_partial_graph_share_failure_keeps_original_owner_and_leaks_no_descriptors(
    pool, shared, monkeypatch
):
    controller, _ = shared
    retained = controller.try_settlement("0" * 64, "coordinator")
    original = os.dup
    calls = 0

    def fail(descriptor):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("injected cohort gate duplication failure")
        return original(descriptor)

    try:
        before = len(os.listdir("/proc/self/fd"))
        with monkeypatch.context() as patch:
            patch.setattr(os, "dup", fail)
            with pytest.raises(OSError, match="duplication failure"):
                controller.try_acquire("transient")
        assert len(os.listdir("/proc/self/fd")) == before
        assert pool.controller().try_settlement("0" * 64, "coordinator") is None
        borrowed = controller.try_acquire("transient")
        assert borrowed is not None and borrowed.slot == retained.slot
        borrowed.close()
    finally:
        retained.close()


def test_ambiguous_kernel_lock_does_not_erase_independent_owners(monkeypatch):
    raw = b"""1: FLOCK ADVISORY WRITE 123 00:19:100 0 EOF
2: FLOCK ADVISORY WRITE 456 00:19:200 0 EOF
3: FLOCK ADVISORY WRITE 789 00:19:100 0 EOF
4: FLOCK ADVISORY WRITE 123 00:19:100 0 EOF
5: FLOCK ADVISORY READ 999 00:19:300 0 EOF
"""
    original = Path.open

    def opened(path, *args, **kwargs):
        return io.BytesIO(raw) if str(path) == "/proc/locks" else original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened)
    assert graph._lock_owners() == {(os.makedev(0, 0x19), 200): 456}


def test_unwitnessed_retained_settlement_keeps_its_full_charge(pool, shared, monkeypatch):
    controller, _ = shared
    reader = pool.controller()
    monkeypatch.setattr(graph, "_operator_controlled", lambda *_: False)
    retained = controller.try_settlement("0" * 64, "coordinator")
    transient = controller.try_acquire("transient")
    try:
        assert retained is not None and retained._graph_binding is None
        assert transient is not None and transient._graph_binding is None
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB)
        assert reader.try_acquire_group("transient", 1) is None
        assert reader.last_model_admission["shared_graph_ceiling_discount_bytes"] == 0
        assert reader.last_model_admission["required_available_bytes"] == (
            21 * GIB + retained.slot.reservation_bytes
        )
    finally:
        transient.close()
        retained.close()


@pytest.mark.parametrize("change", ["swap", "enlarged", "moved", "unowned", "marker"])
def test_changed_or_unverifiable_peer_keeps_full_reservations(pool, shared, monkeypatch, change):
    controller, root = shared
    leases = [controller.try_acquire("transient") for _ in range(2)]
    reader = pool.controller()
    try:
        if change == "swap":
            (root / "memory.swap.max").write_text("1")
        elif change == "enlarged":
            (root / "memory.max").write_text(str(9 * GIB))
        elif change == "moved":
            monkeypatch.setattr(graph, "_membership", lambda pid: root / "absent")
        elif change == "unowned":
            monkeypatch.setattr(graph, "_lock_owners", lambda: {})
        else:
            for lease in leases:
                peer.clear(lease._descriptor)
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB)
        assert reader.try_acquire_group("transient", 1) is None
        assert reader.last_model_admission["required_available_bytes"] == 29 * GIB
        assert reader.last_model_admission["shared_graph_ceiling_discount_bytes"] == 0
    finally:
        for lease in leases:
            lease.close()


def test_closed_graph_cannot_discount_replacement_model(pool, shared, monkeypatch):
    controller, _ = shared
    lease = controller.try_acquire("transient")
    slot = lease.slot
    lease.close()
    parent = controller._open_root()
    descriptor = controller._open_slot(parent, slot)
    try:
        assert peer.observed_inode(descriptor) is None
    finally:
        os.close(descriptor)
        os.close(parent)
    first, second = pool.controller(), pool.controller()
    model = first.try_acquire_group("transient", 1)
    try:
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB - 1)
        assert second.try_acquire_group("transient", 1) is None
        assert second.last_model_admission["required_available_bytes"] == 21 * GIB
    finally:
        model.close()


def test_graph_marker_failure_releases_native_slot_and_open_descriptors(pool, shared, monkeypatch):
    controller, _ = shared
    original = peer.bind
    before = len(os.listdir("/proc/self/fd"))

    def fail(*args):
        raise OSError("injected witness failure")

    monkeypatch.setattr(peer, "bind", fail)
    with pytest.raises(OSError, match="injected witness"):
        controller.try_acquire("transient")
    assert len(os.listdir("/proc/self/fd")) == before
    monkeypatch.setattr(peer, "bind", original)
    leases = [controller.try_acquire("transient") for _ in range(3)]
    try:
        assert all(leases)
    finally:
        for lease in leases:
            if lease is not None:
                lease.close()


def test_uncontrolled_cgroup_limits_do_not_publish_graph_witness(pool, shared, monkeypatch):
    controller, _ = shared
    monkeypatch.setattr(graph, "_operator_controlled", lambda root, name: False)
    leases = [controller.try_acquire("transient") for _ in range(2)]
    reader = pool.controller()
    try:
        assert all(lease._graph_binding is None for lease in leases)
        monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB)
        assert reader.try_acquire_group("transient", 1) is None
        assert reader.last_model_admission["shared_graph_ceiling_discount_bytes"] == 0
    finally:
        for lease in leases:
            lease.close()


@pytest.mark.skipif(
    os.environ.get("UMI_TEST_BOUNDED_STARTUP") != "1", reason="bounded service only"
)
@pytest.mark.parametrize("retained", [False, True])
def test_actual_kernel_service_cap_and_separate_process_reader(pool, monkeypatch, retained):
    monkeypatch.setattr(graph, "own_binding", pool.native_graph_binding)
    monkeypatch.setattr(native, "_require_cgroup2", _KERNEL_CGROUP_CHECK)
    cap = startup.enforced_service_limit()
    assert 0 < cap <= 2 * GIB
    controller = pool.controller()
    controller.startup_reservation_bytes = cap
    leases = [
        controller.try_settlement("0" * 64, "coordinator")
        if retained
        else controller.try_acquire("transient"),
        controller.try_acquire("transient"),
    ]
    assert all(lease._graph_binding is not None for lease in leases)
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read)
        try:
            reader = pool.controller()
            monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB + cap)
            lease = reader.try_acquire_group("transient", 1)
            assert lease is not None and not lease.service_bounded
            assert reader.last_model_admission["pending_reservation_bytes"] == 8 * GIB + cap
            lease.close()
            os.write(write, b"ok")
        finally:
            os._exit(0)
    os.close(write)
    try:
        assert os.read(read, 10) == b"ok"
        assert os.waitpid(child, 0)[1] == 0
    finally:
        os.close(read)
        for lease in leases:
            lease.close()
