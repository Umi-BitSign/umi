"""Prospective host CPU readiness over synthetic kernel metadata only."""

import fcntl
import hashlib
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import host_cpu_timing as host
from umi.competition_cpu_timing import (
    CpuTimingInfrastructureError,
    comparable_cpu_timings,
    hardware_fingerprints,
)
from umi.protocol import canonical_json_bytes

from .test_competition_cpu_timing import cpuinfo, evidence


@pytest.fixture
def selected_host(tmp_path):
    root = tmp_path / "cgroup"
    partition = root / "umi-exclusive.slice"
    parent = partition / "umi-model-a.slice"
    parent.mkdir(parents=True)
    for name, value in {
        "cpuset.cpus.partition": "root",
        "cpuset.cpus.exclusive.effective": "0-1",
        "cpuset.cpus.effective": "0-1",
    }.items():
        (partition / name).write_text(value)
    for name, value in {
        "cgroup.type": "domain",
        "cgroup.events": "populated 0\nfrozen 0\n",
        "cpu.max": "200000 100000",
        "cpuset.cpus.effective": "0-1",
        "cpuset.mems.effective": "0",
        "memory.max": str(1024**3),
        "memory.swap.max": "0",
        "cpu.stat": "usage_usec 0\nnr_throttled 0\nthrottled_usec 0\n",
    }.items():
        (parent / name).write_text(value)
    cpus = tmp_path / "cpus"
    cpus.mkdir()
    (cpus / "online").write_text("0-3")
    for cpu in range(4):
        location = cpus / f"cpu{cpu}" / "topology"
        location.mkdir(parents=True)
        (location / "thread_siblings_list").write_text(str(cpu))
        (location / "physical_package_id").write_text("0")
        (location / "core_id").write_text(str(cpu))
        (location.parent / "node0").mkdir()
        cache = location.parent / "cache/index0"
        cache.mkdir(parents=True)
        for key, value in {
            "level": "1",
            "type": "Data",
            "size": "32K",
            "shared_cpu_list": str(cpu),
        }.items():
            (cache / key).write_text(value)
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "cpuinfo").write_text(cpuinfo())
    (proc / "stat").write_text("cpu0 50 0 0 50 0 0 0 0\ncpu1 50 0 0 50 0 0 0 0\n")
    lock = tmp_path / "model-a.slot"
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    details = os.fstat(descriptor)
    slot = SimpleNamespace(
        name=lock.name, device=details.st_dev, inode=details.st_ino, lane="transient"
    )
    lease = SimpleNamespace(
        slot=slot, _descriptor=descriptor, closed=False, _creator_pid=os.getpid()
    )
    controller = SimpleNamespace(
        _model_leases=[lease],
        policy=SimpleNamespace(
            host_identity_sha256="1" * 64,
            protocol_policy_sha256="2" * 64,
            slots=(slot,),
            container_cgroup_roots=("/legacy",),
            container_cgroupfs_roots=(str(parent),),
        ),
    )
    hardware, cpu_class = hardware_fingerprints(cpuinfo(), (0, 1))

    def binding(path):
        return dict(path=str(path))

    from umi.host_cpu_conditions import slot_topology

    profile = host.CpuTimingHostProfile(
        schema="umi-host-cpu-timing-profile/1",
        host_identity_sha256="1" * 64,
        protocol_policy_sha256="2" * 64,
        runtime_sha256="3" * 64,
        hardware_sha256=hardware,
        cpu_class_sha256=cpu_class,
        qualification_sha256="4" * 64,
        topology_sha256=slot_topology(cpus, (0, 1), (0,)),
        partition=host.CpuTimingKernelDirectory(**binding(partition)),
        reserved_cpu_ids=(0, 1),
        background_cpu_ids=(2, 3),
        numa_node_ids=(0,),
        governor=None,
        frequency_class="virtual_frequency_unexposed",
        slots=(
            host.CpuTimingHostSlot(
                lock_name=lock.name,
                lock_device=details.st_dev,
                lock_inode=details.st_ino,
                cpu_ids=(0, 1),
                parents=(
                    host.CpuTimingParent(
                        **binding(parent),
                        uid=os.geteuid(),
                    ),
                ),
            ),
        ),
    )
    runtime = SimpleNamespace(cpus=2, memory_bytes=1024**3)
    authorization = SimpleNamespace(runtime_sha256="3" * 64, adoption_sha256="5" * 64)

    def start():
        return host.CpuTimingSession(
            profile,
            "6" * 64,
            controller,
            lease,
            runtime,
            authorization,
            cgroup_root=root,
            cpu_root=cpus,
            cpuinfo_path=proc / "cpuinfo",
            proc_stat_path=proc / "stat",
        )

    yield SimpleNamespace(**locals())
    os.close(descriptor)


def test_session_uses_existing_owned_slot_without_allocating_another(selected_host):
    fixture = selected_host
    session = fixture.start()
    try:
        assert session.podman_parent == "/umi-exclusive.slice/umi-model-a.slice"
        assert session.cpu_set_argument == "0,1"
        assert session.sample().populated is False
        assert fixture.controller._model_leases == [fixture.lease]
        assert os.fstat(fixture.descriptor).st_ino == fixture.slot.inode
    finally:
        session.close()
    # Timing close does not release the scheduler's shared lease.
    assert not fixture.lease.closed
    assert os.fstat(fixture.descriptor).st_ino == fixture.slot.inode


@pytest.mark.parametrize(
    "change,reason",
    [
        ("partition", "exclusive_partition_not_active"),
        ("exclusive", "exclusive_partition_not_active"),
        ("smt", "shared_smt_core_unqualified"),
        ("governor", "frequency_class_changed"),
        ("numa", "numa_profile_changed"),
        ("online", "online_cpu_partition_changed"),
        ("released", "existing_slot_lease_released"),
        ("quota", "cpu_quota_changed"),
        ("hardware", "profile_hardware_changed"),
    ],
)
def test_missing_or_changed_host_controls_refuse_timing(selected_host, change, reason):
    fixture = selected_host
    if change == "partition":
        (fixture.partition / "cpuset.cpus.partition").write_text("member")
    elif change == "exclusive":
        (fixture.partition / "cpuset.cpus.exclusive.effective").write_text("0")
    elif change == "smt":
        (fixture.cpus / "cpu0/topology/thread_siblings_list").write_text("0,2")
    elif change == "governor":
        directory = fixture.cpus / "cpu0/cpufreq"
        directory.mkdir()
        (directory / "scaling_governor").write_text("performance")
    elif change == "numa":
        (fixture.parent / "cpuset.mems.effective").write_text("1")
    elif change == "online":
        (fixture.cpus / "online").write_text("0-2")
    elif change == "released":
        fixture.lease.closed = True
    elif change == "quota":
        (fixture.parent / "cpu.max").write_text("100000 100000")
    else:
        (fixture.proc / "cpuinfo").write_text(cpuinfo(model="Other CPU"))
    with pytest.raises(CpuTimingInfrastructureError, match=reason):
        fixture.start()


def test_actual_container_resources_are_checked_before_gate_release(selected_host):
    fixture = selected_host
    child = fixture.parent / ("libpod-" + "ab" * 32)
    child.mkdir(parents=True)
    for source in fixture.parent.iterdir():
        if source.is_file():
            (child / source.name).write_bytes(source.read_bytes())
    session = fixture.start()
    try:
        session.verify_container(child)
        (child / "cpuset.cpus.effective").write_text("0,2")
        with pytest.raises(CpuTimingInfrastructureError, match="cpuset_changed"):
            session.verify_container(child)
        with pytest.raises(CpuTimingInfrastructureError, match="outside_owned_parent"):
            session.verify_container(fixture.partition / "wrong" / "container")
    finally:
        session.close()


def test_recreated_cgroup_keeps_measurement_semantics_but_not_live_identity(selected_host):
    fixture = selected_host
    session = fixture.start()
    first = session.context
    files = {path.name: path.read_bytes() for path in fixture.parent.iterdir()}
    # Keep the old directory alive under another name so inode reuse cannot
    # make this synthetic restart check accidentally pass.
    previous = fixture.parent.with_name("previous.slice")
    fixture.parent.rename(previous)
    fixture.parent.mkdir()
    for name, raw in files.items():
        (fixture.parent / name).write_bytes(raw)
    try:
        with pytest.raises(CpuTimingInfrastructureError, match="kernel_identity_changed"):
            session.sample()
    finally:
        session.close()
    restarted = fixture.start()
    try:
        second = restarted.context
        assert first.cgroup_inode != second.cgroup_inode
        assert first.profile_sha256 == second.profile_sha256
        comparable_cpu_timings(evidence(ctx=first), evidence(ctx=second))
    finally:
        restarted.close()
        shutil.rmtree(previous)


def test_measurement_profile_excludes_installation_paths_and_qualification_receipt(selected_host):
    fixture = selected_host
    original = host.measurement_profile_sha256(fixture.profile, fixture.runtime)
    moved = fixture.profile.model_copy(
        update={
            "partition": host.CpuTimingKernelDirectory(path="/other/isolated.slice"),
            "qualification_sha256": "f" * 64,
        }
    )
    assert host.measurement_profile_sha256(moved, fixture.runtime) == original
    changed = fixture.profile.model_copy(
        update={"frequency_class": "observable_governor", "governor": "performance"}
    )
    assert host.measurement_profile_sha256(changed, fixture.runtime) != original


@pytest.mark.parametrize(
    "change,reason",
    [
        (None, None),
        ("digest", "identity_changed"),
        ("writable", "not_protected"),
        ("locks", "existing_locks_mismatch"),
        ("roots", "container_roots_mismatch"),
    ],
)
def test_profile_is_exact_protected_metadata(selected_host, monkeypatch, change, reason):
    fixture = selected_host
    path = fixture.tmp_path / "cpu-profile.json"
    raw = canonical_json_bytes(fixture.profile)
    path.write_bytes(raw)
    path.chmod(0o444)
    # Do not chown host files: emulate ownership only for this isolated profile.
    original = host.os.fstat

    def fstat(descriptor):
        info = original(descriptor)
        if Path(os.readlink(f"/proc/self/fd/{descriptor}")) == path:
            values = list(info)
            values[4] = 0
            return os.stat_result(values)
        return info

    monkeypatch.setattr(host.os, "fstat", fstat)
    selection = host.CpuTimingHostSelection(
        profile_path=str(path),
        profile_sha256=hashlib.sha256(raw).hexdigest(),
    )
    if change == "digest":
        selection = selection.model_copy(update={"profile_sha256": "a" * 64})
    elif change == "writable":
        path.chmod(0o666)
    elif change == "locks":
        fixture.controller.policy.slots = ()
    elif change == "roots":
        fixture.controller.policy.container_cgroupfs_roots = ()
    if reason:
        with pytest.raises(CpuTimingInfrastructureError, match=reason):
            host.load_cpu_timing_profile(selection, fixture.controller)
    else:
        assert host.load_cpu_timing_profile(selection, fixture.controller) == fixture.profile
