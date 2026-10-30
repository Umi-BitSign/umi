"""Restoration refuses a live reviewer before any cgroup mutation."""

import hashlib
import json
import os
from types import SimpleNamespace

import pytest


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


def test_restored_shared_slot_has_no_quota_but_owned_payloads_keep_exact_limit(tmp_path, monkeypatch):
    from umi import host_cpu_partition as module

    root = tmp_path / "cgroup"
    domain = root / "umiexecution.slice"
    unit = domain / "umi-cpu-partition.service"
    partition = unit / "models"
    (unit / "setup").mkdir(parents=True)
    for name, path in {"ROOT": root, "DOMAIN": domain, "UNIT": unit, "PARTITION": partition}.items():
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
    reads = {
        "/proc/self/cgroup": b"0::/umiexecution.slice/umi-cpu-partition.service/setup\n",
        "/sys/devices/system/cpu/online": b"0-3",
        str(partition / "cpuset.cpus.partition"): b"root",
        str(partition / "cpuset.cpus.exclusive.effective"): b"0-1",
        "/sys/kernel/cgroup/delegate": b"cgroup.procs\ncgroup.threads\ncgroup.subtree_control\n",
    }
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
    monkeypatch.setattr("sys.argv", ["umi.host_cpu_partition", "--config", "/selected-plan.json"])
    module.main()
    slot = partition / lock.name
    assert writes[slot / "cpu.max"] == "max 100000"
    for account in identities.values():
        parent = slot / f"uid{account['uid']}"
        assert writes[parent / "cpu.max"] == "200000 100000"
        assert writes[parent / "probe/cpu.max"] == "200000 100000"
