"""Prospective core-class selection over synthetic kernel metadata only."""

import hashlib

import pytest

from umi.competition_cpu_timing import CpuTimingInfrastructureError
from umi.host_cpu_conditions import slot_core_class, slot_topology
from umi.protocol import canonical_json_bytes


def cpuinfo(*, vendor="GenuineIntel", flags="", arm=False):
    identity = (
        "CPU implementer : 0x41\nCPU architecture : 8\nCPU part : 0xd0c"
        if arm
        else f"vendor_id : {vendor}\ncpu family : 6\nmodel : 170\nmodel name : Same model"
    )
    return "\n\n".join(f"processor : {cpu}\n{identity}\nflags : {flags}" for cpu in range(4))


@pytest.fixture
def topology(tmp_path):
    root = tmp_path / "cpu"
    for cpu in range(4):
        path = root / f"cpu{cpu}"
        (path / "topology").mkdir(parents=True)
        for name, value in {
            "thread_siblings_list": str(cpu),
            "physical_package_id": "0",
            "core_id": str(cpu),
        }.items():
            (path / "topology" / name).write_text(value)
        (path / "node0").mkdir()
        cache = path / "cache/index0"
        cache.mkdir(parents=True)
        for name, value in {
            "level": "1",
            "type": "Data",
            "size": "32K",
            "shared_cpu_list": str(cpu),
        }.items():
            (cache / name).write_text(value)
    return root


def expose(root, cpus, *, core_type=None, capacity=None):
    for cpu in cpus:
        path = root / f"cpu{cpu}"
        if core_type is not None:
            (path / "topology/core_type").write_text(str(core_type))
        if capacity is not None:
            (path / "cpu_capacity").write_text(str(capacity))


def test_same_model_name_cannot_hide_mixed_performance_and_efficiency_cores(topology):
    expose(topology, (0,), core_type=2, capacity=1024)
    expose(topology, (1,), core_type=1, capacity=1024)
    with pytest.raises(CpuTimingInfrastructureError, match="heterogeneous_core_class"):
        slot_topology(topology, (0, 1), (0,), cpuinfo=cpuinfo())


def test_equivalent_disjoint_slots_match_but_different_core_types_do_not(topology):
    expose(topology, range(4), core_type=2, capacity=1024)
    first = slot_topology(topology, (0, 1), (0,), cpuinfo=cpuinfo())
    assert slot_topology(topology, (2, 3), (0,), cpuinfo=cpuinfo()) == first
    expose(topology, (2, 3), core_type=1, capacity=1024)
    assert slot_topology(topology, (2, 3), (0,), cpuinfo=cpuinfo()) != first


def test_equal_core_type_does_not_hide_different_cpu_capacity(topology):
    expose(topology, (0,), core_type=2, capacity=1024)
    expose(topology, (1,), core_type=2, capacity=768)
    with pytest.raises(CpuTimingInfrastructureError, match="heterogeneous_core_class"):
        slot_core_class(topology, (0, 1), cpuinfo=cpuinfo())


@pytest.mark.parametrize("field", ["core_type", "capacity"])
def test_partial_class_exposure_is_not_a_homogeneous_class(topology, field):
    expose(topology, (0,), **{field: 2 if field == "core_type" else 1024})
    with pytest.raises(CpuTimingInfrastructureError, match="heterogeneous_core_class"):
        slot_core_class(topology, (0, 1), cpuinfo=cpuinfo())


@pytest.mark.parametrize("core_type,flags", [(None, ""), (0, ""), (None, "hybrid_cpu")])
def test_intel_without_known_core_type_refuses_even_with_capacity(topology, core_type, flags):
    expose(topology, (0, 1), core_type=core_type, capacity=1024)
    with pytest.raises(CpuTimingInfrastructureError, match="hybrid_core_class_unqualified"):
        slot_core_class(topology, (0, 1), cpuinfo=cpuinfo(flags=flags))


def test_hybrid_flag_cannot_use_vendor_fallback(topology):
    with pytest.raises(CpuTimingInfrastructureError, match="hybrid_core_class_unqualified"):
        slot_core_class(topology, (0, 1), cpuinfo=cpuinfo(vendor="AuthenticAMD", flags="hybrid"))


def test_virtual_amd_fallback_records_visible_identity_and_unknown_placement(topology):
    value = slot_core_class(
        topology, (0, 1), cpuinfo=cpuinfo(vendor="AuthenticAMD", flags="hypervisor")
    )
    assert value["basis"] == "uniform_visible_amd_identity"
    assert value["virtualization"] == "visible_hypervisor"
    assert value["physical_placement"] == "not_established"
    assert value["core_type"] is value["cpu_capacity"] is None


def test_arm_fallback_requires_uniform_visible_implementer_and_part(topology):
    raw = cpuinfo(arm=True)
    assert slot_core_class(topology, (0, 1), cpuinfo=raw)["basis"] == "uniform_visible_arm_identity"
    mixed = raw.replace("CPU part : 0xd0c", "CPU part : 0xd05", 1)
    with pytest.raises(CpuTimingInfrastructureError, match="heterogeneous_core_identity"):
        slot_core_class(topology, (0, 1), cpuinfo=mixed)


def test_exposed_arm_capacity_is_bound_across_slots(topology):
    expose(topology, (0, 1), capacity=1024)
    expose(topology, (2, 3), capacity=768)
    raw = cpuinfo(arm=True)
    assert slot_core_class(topology, (0, 1), cpuinfo=raw)["basis"] == "exposed_kernel_cpu_capacity"
    assert slot_topology(topology, (0, 1), (0,), cpuinfo=raw) != slot_topology(
        topology, (2, 3), (0,), cpuinfo=raw
    )


def test_unknown_unexposed_vendor_is_not_silently_qualified(topology):
    with pytest.raises(CpuTimingInfrastructureError, match="core_class_unqualified"):
        slot_core_class(topology, (0, 1), cpuinfo=cpuinfo(vendor="Unknown"))


@pytest.mark.parametrize("capacity", ["0", "-1", "unknown", str(2**31)])
def test_invalid_exposed_capacity_is_not_treated_as_absent(topology, capacity):
    expose(topology, (0, 1), core_type=2, capacity=capacity)
    with pytest.raises(CpuTimingInfrastructureError, match="invalid_core_class_metadata"):
        slot_core_class(topology, (0, 1), cpuinfo=cpuinfo())


def test_stronger_topology_requires_fresh_profile_without_rewriting_old_digest(topology):
    expose(topology, (0, 1), core_type=2, capacity=1024)
    legacy = dict(
        schema="umi-visible-slot-topology/1",
        numa=[(0,), (0,)],
        single_package=True,
        unique_physical_cores=2,
        cache_shape=[
            [dict(level=1, type="Data", size="32K", slot_members=(index,), total_visible_members=1)]
            for index in range(2)
        ],
    )
    legacy_digest = hashlib.sha256(canonical_json_bytes(legacy)).hexdigest()
    current = dict(
        legacy,
        schema="umi-visible-slot-topology/2",
        core_class=slot_core_class(topology, (0, 1), cpuinfo=cpuinfo()),
    )
    expected = hashlib.sha256(canonical_json_bytes(current)).hexdigest()
    assert slot_topology(topology, (0, 1), (0,), cpuinfo=cpuinfo()) == expected
    assert expected != legacy_digest
