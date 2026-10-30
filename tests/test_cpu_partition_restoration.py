"""Restoration refuses a live reviewer before any cgroup mutation."""

import json

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
