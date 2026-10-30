"""Bounded CPU planning and immutable shared-lock preparation; no live services."""

import hashlib
import json
from fractions import Fraction
from pathlib import Path

import pytest

from umi import host_memory_admission as admission
from umi import host_model_lane_cli as lane_cli
from umi import host_model_lane_policy as lanes
from umi.competition_runner import OfflineCpuRuntime
from umi.host_memory_runtime import HostMemoryAdmissionSelection
from umi.host_model_lane_cli import prepare_lane_policy
from umi.open_competition import digest

from .test_host_memory_admission import provisioned as provisioned
from .test_host_model_execution import capacity as capacity


@pytest.fixture
def lane_capacity(capacity):
    runtime = OfflineCpuRuntime(
        schema="umi-offline-cpu-runtime/1",
        image="example.invalid/test@sha256:" + "a" * 64,
        cpus=6,
        memory_bytes=8 * 1024**3,
        scratch_bytes=1024**3,
        pids_limit=128,
        maximum_video_bytes=1024,
    )
    path = Path(capacity.selection.policy_path)
    body = json.loads(path.read_bytes())
    body["evaluation_runtime_sha256"] = digest(runtime)
    raw = json.dumps(body).encode()
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o440)
    selected = HostMemoryAdmissionSelection(
        policy_path=str(path),
        policy_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return selected, runtime, body


@pytest.mark.parametrize(
    "cpus,quota,cap,expected",
    [
        (32, None, None, 5),
        (32, Fraction(12), None, 2),
        (8, Fraction(64), None, 1),
        (32, Fraction(119, 10), None, 1),
        (32, None, 3, 3),
        (2, None, None, 1),
    ],
)
def test_cpu_affinity_quota_and_operator_cap(lane_capacity, cpus, quota, cap, expected):
    _, runtime, _ = lane_capacity
    assert (
        lanes.model_lane_count(
            lanes.CpuCapacity(tuple(range(cpus)), quota),
            runtime,
            maximum_lanes=cap,
        )
        == expected
    )


def test_observation_includes_parent_quota_and_detects_pid_change(tmp_path, monkeypatch):
    proc = tmp_path / "proc" / "123"
    proc.mkdir(parents=True)
    stat = "123 (worker with spaces) " + " ".join(["S"] + ["0"] * 18 + ["77"])
    (proc / "stat").write_text(stat)
    (proc / "cgroup").write_text("0::/slice/service\n")
    root = tmp_path / "cgroup"
    leaf = root / "slice/service"
    leaf.mkdir(parents=True)
    (root / "cpu.max").write_text("max 100000\n")
    (leaf.parent / "cpu.max").write_text("1250000 100000\n")
    (leaf / "cpu.max").write_text("2400000 100000\n")
    monkeypatch.setattr(lanes.os, "sched_getaffinity", lambda pid: set(range(32)))
    observed = lanes.observe_cpu_capacity(123, proc_root=proc.parent, cgroup_root=root)
    assert observed.effective == Fraction(25, 2)
    container_parent = root / "rootless"
    container_parent.mkdir()
    (container_parent / "cpu.max").write_text("max 100000\n")
    (container_parent / "cpuset.cpus.effective").write_text("0-7\n")
    observed = lanes.observe_cpu_capacity(
        123,
        proc_root=proc.parent,
        cgroup_root=root,
        execution_cgroup_roots=(str(container_parent),),
    )
    assert observed.effective == 8
    original = lanes._small_text
    calls = 0

    def changed(path):
        nonlocal calls
        raw = original(path)
        if path.name == "stat":
            calls += 1
            if calls == 2:
                return raw[:-2] + "78"
        return raw

    monkeypatch.setattr(lanes, "_small_text", changed)
    with pytest.raises(ValueError, match="changed"):
        lanes.observe_cpu_capacity(123, proc_root=proc.parent, cgroup_root=root)


def prepare(lane_capacity, *, maximum_lanes=None, output="expanded.json", progress=None):
    selection, runtime, previous = lane_capacity
    return prepare_lane_policy(
        selection,
        runtime,
        lanes.CpuCapacity(tuple(range(32)), None),
        output_policy=Path(previous["directory"]) / output,
        qualification_sha256="f" * 64,
        maximum_lanes=maximum_lanes,
        progress=progress,
    )


def test_expansion_preserves_all_old_locks_and_memory_gate(lane_capacity, monkeypatch):
    selection, _, _previous = lane_capacity
    old = admission.HostMemoryAdmission(
        Path(selection.policy_path),
        expected_sha256=selection.policy_sha256,
    )
    # No constructor/provisioning operation acquires an inference lease.
    assert not tuple(old._model_leases)
    held = old.try_acquire_group("transient", 1)
    assert held
    events = []
    try:
        result = prepare(lane_capacity, progress=lambda n, total: events.append((n, total)))
        selected = result["benchmark"]["model_execution_admission"]
        new = admission.HostMemoryAdmission(
            Path(selected["policy_path"]),
            expected_sha256=selected["policy_sha256"],
        )
        assert result["benchmark"]["concurrency"] == result["model_slots"] == 5
        assert new.policy.incremental_budget_bytes == 41 * 1024**3
        assert new.policy.slots[: len(old.policy.slots)] == old.policy.slots
        assert new.policy.transaction_lock == old.policy.transaction_lock
        assert new.policy.minimum_available_bytes == 4 * 1024**3
        assert new.policy.background_reservation_bytes == 2 * 1024**3
        assert events[-1] == (4, 4)
        # New readers observe the exact old lease; they cannot claim its slot.
        monkeypatch.setattr(admission, "_available_memory", lambda: 128 * 1024**3)
        leases = [new.try_acquire_group("transient", 1) for _ in range(4)]
        try:
            assert all(leases)
            assert new.try_acquire_group("transient", 1) is None
        finally:
            for lease in leases:
                if lease:
                    lease.close()
        monkeypatch.setattr(admission, "_available_memory", lambda: 0)
        assert new.try_acquire_group("transient", 1) is None
    finally:
        held.close()


def test_policy_repeat_reuses_slots_and_refuses_conflicting_generation(lane_capacity):
    first = prepare(lane_capacity)
    selection = first["benchmark"]["model_execution_admission"]
    path = Path(selection["policy_path"])
    raw = path.read_bytes()
    assert prepare(lane_capacity) == first
    assert path.read_bytes() == raw
    assert not list(path.parent.glob(".model-lane-*.partial"))
    with pytest.raises(ValueError, match="retained lane policy differs"):
        prepare(lane_capacity, maximum_lanes=3)
    assert path.read_bytes() == raw


def test_operator_cap_preserves_existing_shared_slot_identities(lane_capacity):
    result = prepare(lane_capacity, maximum_lanes=1)
    assert result["benchmark"]["concurrency"] == 1
    assert result["model_slots"] == 2
    assert result["incremental_budget_bytes"] == 17 * 1024**3


def test_invalid_signed_profile_or_qualification_refused_before_mutation(lane_capacity):
    selection, runtime, previous = lane_capacity
    root = Path(previous["directory"])
    before = sorted(p.name for p in root.iterdir())
    for altered_runtime, qualification in [
        (runtime.model_copy(update={"cpus": 4}), "f" * 64),
        (runtime, "invalid"),
    ]:
        with pytest.raises(ValueError):
            prepare_lane_policy(
                selection,
                altered_runtime,
                lanes.CpuCapacity(tuple(range(32)), None),
                output_policy=root / "refused.json",
                qualification_sha256=qualification,
            )
    assert sorted(p.name for p in root.iterdir()) == before


def test_interrupted_exact_generation_is_recovered_without_other_cleanup(lane_capacity):
    _, _, previous = lane_capacity
    root = Path(previous["directory"])
    # A death immediately after O_EXCL can precede group/mode initialization.
    # Only this deterministic target/content partial may be removed on retry.
    key = hashlib.sha256(b"model-0003.slot\0").hexdigest()
    interrupted = root / f".model-lane-{key}.partial"
    interrupted.write_bytes(b"")
    interrupted.chmod(0o600)
    unrelated = root / ".model-lane-unrelated.partial"
    unrelated.write_bytes(b"do not remove")
    result = prepare(lane_capacity)
    assert result["model_slots"] == 5
    assert not interrupted.exists()
    assert unrelated.read_bytes() == b"do not remove"
    assert all((root / f"model-{n:04d}.slot").stat().st_nlink == 1 for n in (3, 4, 5))


def test_publication_failure_then_repeat_reuses_completed_slots(lane_capacity, monkeypatch):
    original = lane_cli._publish_noreplace
    selected = []

    def fail_policy(parent, source, destination):
        if destination == "expanded.json":
            raise OSError("injected policy publication interruption")
        original(parent, source, destination)
        selected.append(destination)

    monkeypatch.setattr(lane_cli, "_publish_noreplace", fail_policy)
    with pytest.raises(OSError, match="interruption"):
        prepare(lane_capacity)
    root = Path(lane_capacity[2]["directory"])
    retained = {name: (root / name).stat().st_ino for name in selected}
    assert len(retained) == 3
    assert not (root / "expanded.json").exists()
    monkeypatch.setattr(lane_cli, "_publish_noreplace", original)
    assert prepare(lane_capacity)["model_slots"] == 5
    assert retained == {name: (root / name).stat().st_ino for name in retained}


def test_busy_shared_transaction_refuses_before_new_files(lane_capacity):
    selection, _, previous = lane_capacity
    controller = admission.HostMemoryAdmission(
        Path(selection.policy_path),
        expected_sha256=selection.policy_sha256,
    )
    root = Path(previous["directory"])
    before = sorted(p.name for p in root.iterdir())
    parent = controller._open_root()
    lock = controller._transaction(parent)
    assert lock is not None
    try:
        with pytest.raises(BlockingIOError, match="retry unchanged"):
            prepare(lane_capacity)
    finally:
        lane_cli.os.close(lock)
        lane_cli.os.close(parent)
    assert sorted(p.name for p in root.iterdir()) == before
