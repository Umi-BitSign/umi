"""Restoration refuses a live reviewer before any cgroup mutation."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import uuid
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_resident_notifies_then_stays_alive_until_service_stop():
    source = str(Path(__file__).resolve().parents[1] / "src")
    address = "umi-cpu-resident-test-" + uuid.uuid4().hex
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.bind("\0" + address)
        channel.settimeout(5)
        code = (
            "import sys;sys.path.insert(0," + repr(source) + ");"
            "from umi.host_cpu_partition import retain_partition_service;"
            "retain_partition_service()"
        )
        child = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", code],
            env={**os.environ, "NOTIFY_SOCKET": "@" + address},
        )
        try:
            assert channel.recv(1024).startswith(b"READY=1\n")
            assert child.poll() is None
        finally:
            child.terminate()
            child.wait(timeout=5)


def test_resident_requires_notify_supervision(monkeypatch):
    from umi import host_cpu_partition as module

    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    with pytest.raises(RuntimeError, match="notify supervision"):
        module.retain_partition_service()


def test_partition_directories_remain_readable_under_private_umask(tmp_path, monkeypatch):
    from umi import host_cpu_partition as module

    monkeypatch.setattr(module, "DOMAIN", tmp_path)
    before = os.umask(0o077)
    try:
        child = tmp_path / "models"
        module.directory(child)
        assert child.stat().st_mode & 0o777 == 0o755
    finally:
        os.umask(before)


def test_active_pool_refuses_startup_restoration_before_mutation(monkeypatch):
    from umi import host_cpu_partition as module

    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module.resource, "setrlimit", lambda *args: None)
    monkeypatch.setattr(
        module,
        "protected",
        lambda path: json.dumps({"schema": "umi-cpu-partition-restoration-plan/1"}).encode(),
    )
    monkeypatch.setattr(
        module,
        "read",
        lambda *args: b"0::/umiexecution.slice/umi-cpu-partition.service/setup\n",
    )
    monkeypatch.setattr(module.subprocess, "check_output", lambda *args, **kwargs: "active\n")
    writes = []
    monkeypatch.setattr(module, "write", lambda *args: writes.append(args))
    monkeypatch.setattr("sys.argv", ["umi.host_cpu_partition", "--config", "/selected-plan.json"])
    with pytest.raises(RuntimeError, match="reviewer must be quiescent"):
        module.main()
    assert writes == []


@pytest.mark.parametrize("reconfigure", [False, True])
def test_restored_shared_slot_has_no_quota_but_owned_payloads_keep_exact_limit(
    tmp_path, monkeypatch, reconfigure, capsys
):
    from umi import host_cpu_partition as module

    root = tmp_path / "cgroup"
    domain = root / "umiexecution.slice"
    unit = domain / "umi-cpu-partition.service"
    partition = unit / "models"
    (unit / "setup").mkdir(parents=True)
    for name, path in {
        "ROOT": root,
        "DOMAIN": domain,
        "UNIT": unit,
        "PARTITION": partition,
    }.items():
        monkeypatch.setattr(module, name, path)
    locks = tmp_path / "locks"
    locks.mkdir()
    lock = locks / "model-a.slot"
    lock.touch(mode=0o444)
    info = lock.stat()
    directory = locks.stat()
    identity = b"a" * 32
    policy = {
        "host_identity_sha256": hashlib.sha256(identity).hexdigest(),
        "directory": str(locks),
        "directory_device": directory.st_dev,
        "directory_inode": directory.st_ino,
        "group_id": 100,
        "protocol_policy_sha256": "b" * 64,
        "evaluation_runtime_sha256": "c" * 64,
        "incremental_budget_bytes": 1024**3,
        "slots": [
            {
                "name": lock.name,
                "lane": "transient",
                "device": info.st_dev,
                "inode": info.st_ino,
                "reservation_bytes": 1024**3,
            }
        ],
    }
    policy_raw = json.dumps(policy).encode()
    identities = {
        user: {"uid": 100 + index, "gid": 100 + index}
        for index, user in enumerate(module.ROLES.values())
    }
    plan = {
        "schema": "umi-cpu-partition-restoration-plan/1",
        "existing_memory_policy_path": "/policy.json",
        "existing_memory_policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
        "active_slots": {lock.name: [0, 1]},
        "partition_mode": "root",
        "background_cpus": "2-3",
        "runtime_cpus": 2,
        "runtime_memory_bytes": 1024**3,
        "numa_nodes": "0",
        "role_identities": identities,
    }
    protected = {
        "/selected-plan.json": json.dumps(plan).encode(),
        "/policy.json": policy_raw,
        "/etc/machine-id": identity,
    }
    if reconfigure:
        previous = dict(plan, background_cpus="2-5")
        protected["/old-plan.json"] = json.dumps(previous).encode()
        protected["/old-policy.json"] = policy_raw
        previous["existing_memory_policy_path"] = "/old-policy.json"
        protected["/old-plan.json"] = json.dumps(previous).encode()
        additional = locks / "model-b.slot"
        additional.touch(mode=0o444)
        extra = additional.stat()
        policy["slots"].append(
            dict(
                name=additional.name,
                lane="transient",
                device=extra.st_dev,
                inode=extra.st_ino,
                reservation_bytes=1024**3,
            )
        )
        policy["incremental_budget_bytes"] += 1024**3
        protected["/policy.json"] = json.dumps(policy).encode()
        plan = dict(
            plan,
            active_slots={"model-a.slot": [0, 1], "model-b.slot": [2, 3]},
            background_cpus="4-5",
            existing_memory_policy_sha256=hashlib.sha256(protected["/policy.json"]).hexdigest(),
        )
        protected["/selected-plan.json"] = json.dumps(plan).encode()
    reads = {
        "/proc/self/cgroup": b"0::/umiexecution.slice/umi-cpu-partition.service/setup\n",
        "/sys/devices/system/cpu/online": b"0-3",
        str(partition / "cpuset.cpus.partition"): b"root",
        str(partition / "cpuset.cpus.exclusive.effective"): b"0-1",
        "/sys/kernel/cgroup/delegate": b"cgroup.procs\ncgroup.threads\ncgroup.subtree_control\n",
    }
    if reconfigure:
        reads["/sys/devices/system/cpu/online"] = b"0-5"
        reads[str(partition / "cpuset.cpus.exclusive.effective")] = b"0-3"
    monkeypatch.setattr(module, "protected", lambda path: protected[str(path)])
    monkeypatch.setattr(module, "read", lambda path, limit=131072: reads[str(path)])
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module.os, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(module.os, "chmod", lambda *args, **kwargs: None)
    original_fstat = os.fstat

    def root_owned_fstat(descriptor):
        value = list(original_fstat(descriptor))
        value[4] = 0
        return os.stat_result(value)

    monkeypatch.setattr(module.os, "fstat", root_owned_fstat)
    monkeypatch.setattr(module.resource, "setrlimit", lambda *args: None)
    monkeypatch.setattr(module.subprocess, "check_output", lambda *args, **kwargs: "inactive\n")
    monkeypatch.setattr(module.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=100))
    monkeypatch.setattr(
        module.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(
            pw_uid=identities[name]["uid"], pw_gid=identities[name]["gid"]
        ),
    )
    writes = {}
    monkeypatch.setattr(module, "write", lambda path, value: writes.__setitem__(path, value))
    argv = ["umi.host_cpu_partition", "--config", "/selected-plan.json"]
    if reconfigure:
        argv += [
            "--previous-config",
            "/old-plan.json",
            "--previous-sha256",
            hashlib.sha256(protected["/old-plan.json"]).hexdigest(),
        ]
    monkeypatch.setattr("sys.argv", argv)
    module.main()
    messages = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    receipt = next(value for value in messages if value["stage"] == "kernel_ready")
    assert receipt["plan_sha256"] == hashlib.sha256(protected["/selected-plan.json"]).hexdigest()
    assert receipt["previous_plan_sha256"] == (
        hashlib.sha256(protected["/old-plan.json"]).hexdigest() if reconfigure else None
    )
    for name in plan["active_slots"]:
        slot = partition / name
        assert writes[slot / "cpu.max"] == "max 100000"
        for account in identities.values():
            parent = slot / f"uid{account['uid']}"
            assert writes[parent / "cpu.max"] == "200000 100000"
            assert writes[parent / "probe/cpu.max"] == "200000 100000"


@pytest.fixture
def expansion_plans(monkeypatch):
    from umi import host_cpu_partition as module

    policy = dict(
        host_identity_sha256="a" * 64,
        directory="/native-pool",
        directory_device=1,
        directory_inode=2,
        group_id=975,
        protocol_policy_sha256="b" * 64,
        evaluation_runtime_sha256="c" * 64,
        incremental_budget_bytes=17 * 1024**3,
        minimum_available_bytes=4 * 1024**3,
        slots=[
            dict(
                name="model-a.slot",
                lane="transient",
                device=1,
                inode=3,
                reservation_bytes=8 * 1024**3,
            ),
            dict(
                name="settlement.slot",
                lane="settlement_retained",
                device=1,
                inode=4,
                reservation_bytes=8 * 1024**3,
            ),
        ],
    )
    expanded = deepcopy(policy)
    expanded["slots"].append(
        dict(
            name="model-b.slot", lane="transient", device=1, inode=5, reservation_bytes=8 * 1024**3
        )
    )
    expanded["incremental_budget_bytes"] += 8 * 1024**3
    values = {
        "/old-policy.json": json.dumps(policy).encode(),
        "/new-policy.json": json.dumps(expanded).encode(),
    }
    monkeypatch.setattr(module, "protected", lambda path: values[str(path)])
    original = dict(
        schema="umi-cpu-partition-restoration-plan/1",
        existing_memory_policy_path="/old-policy.json",
        existing_memory_policy_sha256=hashlib.sha256(values["/old-policy.json"]).hexdigest(),
        active_slots={"model-a.slot": list(range(6))},
        partition_mode="root",
        background_cpus="6-19",
        runtime_cpus=6,
        runtime_memory_bytes=8 * 1024**3,
        numa_nodes="0",
        role_identities={
            name: dict(uid=993 + i, gid=983 + i) for i, name in enumerate(module.ROLES.values())
        },
    )
    target = dict(
        original,
        existing_memory_policy_path="/new-policy.json",
        existing_memory_policy_sha256=hashlib.sha256(values["/new-policy.json"]).hexdigest(),
        active_slots={"model-a.slot": list(range(6)), "model-b.slot": list(range(6, 12))},
        background_cpus="12-19",
    )
    return SimpleNamespace(
        module=module,
        original=original,
        target=target,
        policy=policy,
        expanded=expanded,
        values=values,
    )


def test_expansion_and_rollback_lock_both_generations_without_moving_old_slot(expansion_plans):
    p = expansion_plans
    for target, policy, prior in (
        (p.target, p.expanded, p.original),
        (p.original, p.policy, p.target),
    ):
        locks = p.module.previous_slots(target, policy, prior)
        assert set(locks) == {"model-a.slot", "model-b.slot"}
        assert locks["model-a.slot"] == p.policy["slots"][0]


@pytest.mark.parametrize(
    "change",
    [
        "moved_slot",
        "changed_lock",
        "changed_reserve",
        "changed_allowance",
        "changed_budget",
        "lost_settlement",
        "foreign_pool",
        "mismatched_digest",
        "untimed_slot",
        "overlap",
        "replacement",
        "duplicate",
    ],
)
def test_reconfiguration_refuses_unequal_resources_or_unbound_capacity(expansion_plans, change):
    p = expansion_plans
    target, policy, previous = deepcopy(p.target), deepcopy(p.expanded), deepcopy(p.original)
    if change == "moved_slot":
        target["active_slots"]["model-a.slot"] = list(range(12, 18))
    elif change == "changed_lock":
        policy["slots"][0]["inode"] += 1
    elif change == "changed_reserve":
        policy["minimum_available_bytes"] -= 1
    elif change == "changed_allowance":
        policy["slots"][-1]["reservation_bytes"] -= 1
    elif change == "changed_budget":
        policy["incremental_budget_bytes"] -= 1
    elif change == "lost_settlement":
        policy["slots"].pop(1)
    elif change == "foreign_pool":
        policy["directory_inode"] += 1
    elif change == "mismatched_digest":
        previous["existing_memory_policy_sha256"] = "0" * 64
    elif change == "untimed_slot":
        target["active_slots"].pop("model-b.slot")
    elif change == "overlap":
        target["active_slots"]["model-b.slot"] = list(range(6))
    elif change == "replacement":
        target["active_slots"].pop("model-a.slot")
        policy["slots"].pop(0)
    else:
        policy["slots"].append(deepcopy(policy["slots"][0]))
    with pytest.raises(RuntimeError):
        p.module.previous_slots(target, policy, previous)


@pytest.fixture
def retiring_partition(expansion_plans, tmp_path, monkeypatch):
    p = expansion_plans
    partition = tmp_path / "models"
    monkeypatch.setattr(p.module, "PARTITION", partition)
    for name in p.target["active_slots"]:
        slot = partition / name
        slot.mkdir(parents=True)
        (slot / "cgroup.events").write_text("populated 0\n")
        for identity in p.target["role_identities"].values():
            parent = slot / ("uid" + str(identity["uid"]))
            (parent / "probe").mkdir(parents=True)
            (parent / "cgroup.events").write_text("populated 0\n")
            (parent / "probe/cgroup.events").write_text("populated 0\n")
    return p, partition


def test_rollback_retires_only_obsolete_empty_tree_and_resumes_partial_removal(retiring_partition):
    p, partition = retiring_partition
    paths = p.module.retired_slot_directories(p.original, p.target)
    assert len(paths) == 5 and paths[-1] == partition / "model-b.slot"
    assert all("model-a.slot" not in path.parts for path in paths)
    # Simulate one completed cgroup rmdir before process interruption. Regular
    # filesystem fixtures need their fake cgroup pseudo-file removed first.
    (paths[0] / "cgroup.events").unlink()
    paths[0].rmdir()
    assert p.module.retired_slot_directories(p.original, p.target) == paths[1:]
    assert (partition / "model-a.slot/uid993/probe").is_dir()


@pytest.mark.parametrize(
    "change", ["live_payload", "unexpected_container", "foreign_slot", "aliased_uid"]
)
def test_rollback_refuses_live_or_unowned_descendants_before_retirement(retiring_partition, change):
    p, partition = retiring_partition
    parent = partition / "model-b.slot/uid993"
    if change == "live_payload":
        (parent / "probe/cgroup.events").write_text("populated 1\n")
    elif change == "unexpected_container":
        (parent / "container").mkdir()
    elif change == "foreign_slot":
        (partition / "unrelated.slot").mkdir()
    else:
        (parent / "probe/cgroup.events").unlink()
        (parent / "probe").rmdir()
        (parent / "cgroup.events").unlink()
        parent.rmdir()
        parent.symlink_to(partition / "model-a.slot/uid993", target_is_directory=True)
    with pytest.raises(RuntimeError):
        p.module.retired_slot_directories(p.original, p.target)
    assert (partition / "model-b.slot/uid994/probe").exists()


@pytest.mark.parametrize(
    "live_unit",
    [
        "umi-c5-primary-intake.service",
        "umi-c5-primary-settlement-uid54.service",
        "umi-c5-optional-settlement-uid0.service",
    ],
)
def test_live_reconfiguration_requires_all_pool_consumers_quiescent(monkeypatch, live_unit):
    from umi import host_cpu_partition as module

    raw = json.dumps(dict(schema="umi-cpu-partition-restoration-plan/1")).encode()
    monkeypatch.setattr(module, "protected", lambda path: raw)
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module.resource, "setrlimit", lambda *args: None)
    monkeypatch.setattr(
        module, "read", lambda *args: b"0::/umiexecution.slice/umi-cpu-partition.service/setup\n"
    )
    observed = []

    def inspect(argv, **kwargs):
        observed.append(argv[2])
        return "active\n" if argv[2] == live_unit else "inactive\n"

    monkeypatch.setattr(module.subprocess, "check_output", inspect)
    writes = []
    monkeypatch.setattr(module, "write", lambda *args: writes.append(args))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "umi.host_cpu_partition",
            "--config",
            "/new.json",
            "--previous-config",
            "/old.json",
            "--previous-sha256",
            hashlib.sha256(raw).hexdigest(),
        ],
    )
    with pytest.raises(RuntimeError, match="shared-pool consumer must be quiescent"):
        module.main()
    assert not writes and all("validator@" not in name for name in observed)


def test_live_reconfiguration_cannot_create_another_resident_owner(monkeypatch):
    from umi import host_cpu_partition as module

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "umi.host_cpu_partition",
            "--config",
            "/new.json",
            "--resident",
            "--previous-config",
            "/old.json",
            "--previous-sha256",
            "0" * 64,
        ],
    )
    with pytest.raises(SystemExit):
        module.main()
