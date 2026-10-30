"""Reuse real temporary lease files; kernel accounting is synthetic."""

import os

import pytest

from umi import host_memory_admission as native

from .test_host_memory_admission import provisioned as provisioned
from .test_host_model_execution import capacity as capacity


def test_active_cpu_subset_does_not_recreate_or_borrow_other_slot_files(capacity):
    admission = capacity.start()
    slots = admission.slots
    selected = (slots[1].name,)
    originals = tuple((slot.name, slot.device, slot.inode) for slot in slots)
    lease = admission.controller.try_acquire_group("transient", 1, slot_names=selected)
    try:
        assert lease.slot.name == selected[0]
        assert admission.controller.try_acquire_group("transient", 1, slot_names=selected) is None
        assert os.fstat(lease._descriptor).st_ino == originals[1][2]
        other = admission.controller.try_acquire_group("transient", 1, slot_names=(slots[0].name,))
        assert other is not None
        other.close()
        with pytest.raises(native.AdmissionBindingError, match="existing model slot files"):
            admission.controller.try_acquire_group("transient", 1, slot_names=("invented.slot",))
    finally:
        lease.close()
    assert tuple((slot.name, slot.device, slot.inode) for slot in admission.slots) == originals


def test_cgroupfs_owned_binding_credits_once_and_orphan_remains_charged(
    capacity, tmp_path, monkeypatch
):
    admission = capacity.start()
    controller = admission.controller
    root = tmp_path / "cpu-parent"
    root.mkdir()
    controller.policy = controller.policy.model_copy(
        update={"container_cgroupfs_roots": (str(root),)}
    )
    monkeypatch.setattr(native, "_require_cgroup2", lambda descriptor: None)
    lease = controller.try_acquire_group("transient", 1)
    child = root / ("libpod-" + "a" * 64)
    child.mkdir()
    (child / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    (child / "memory.max").write_text(str(capacity.runtime.memory_bytes))
    try:
        assert controller.bind_model_container(lease, "a" * 64, child)
        assert (
            controller._model_container_reservations({(lease.slot.device, lease.slot.inode)}) == 0
        )
        with pytest.raises(native.AdmissionBindingError, match="live model acquisition"):
            controller.bind_model_container(lease, "b" * 64, child)
    finally:
        lease.close()
    assert controller._model_container_reservations() == capacity.runtime.memory_bytes


def test_legacy_policy_bytes_do_not_gain_new_empty_controls(capacity):
    from umi.protocol import canonical_json_bytes

    policy = capacity.start().controller.policy
    assert b"container_cgroupfs_roots" not in canonical_json_bytes(policy)
    assert b"cpu_timing_profile" not in canonical_json_bytes(policy)
