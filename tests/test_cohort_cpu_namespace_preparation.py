import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    source = (
        Path(__file__).parents[1] / "deploy/standing-reward-coordinator/ensure-cpu-namespace.py"
    )
    spec = importlib.util.spec_from_file_location("cpu_namespace", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proc = tmp_path / "proc"
    (proc / "self").mkdir(parents=True)
    (proc / "self/status").write_text("NoNewPrivs:\t0\n")
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("fixture-boot\n")
    binary = tmp_path / "podman"
    binary.write_bytes(b"fixture executable")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    home = tmp_path / "home"
    home.mkdir()
    storage = tmp_path / "storage.conf"
    storage.write_text("[storage]\n")
    containers = tmp_path / "containers.conf"
    containers.write_text("[engine]\n")
    monkeypatch.setattr(module, "PROC", proc)
    monkeypatch.setattr(module, "PODMAN", binary)
    environment = dict(
        HOME=str(home),
        CONTAINERS_STORAGE_CONF=str(storage),
        CONTAINERS_CONF_OVERRIDE=str(containers),
        XDG_RUNTIME_DIR=str(runtime),
    )
    calls = []

    def seed(pid="123", start="99"):
        path = proc / pid
        path.mkdir(exist_ok=True)
        (path / "comm").write_text("podman pause\n")
        (path / "exe").unlink(missing_ok=True)
        (path / "exe").symlink_to(binary)
        (path / "uid_map").write_text(f"0 {os.geteuid()} 1\n1 2000000 65536\n")
        (path / "stat").write_text(
            pid + " (podman pause) " + " ".join(["S"] + ["0"] * 18 + [start])
        )
        (path / "ns").mkdir(exist_ok=True)
        (path / "ns/user").unlink(missing_ok=True)
        (path / "ns/user").symlink_to("user:[fixture]")
        pause = runtime / "libpod/tmp/pause.pid"
        pause.parent.mkdir(parents=True, exist_ok=True)
        pause.write_text(pid)

    def inspect():
        calls.append(1)
        seed()
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                dict(host=dict(security=dict(rootless=True), cgroupVersion="v2"))
            ).encode(),
            stderr=b"",
        )

    return SimpleNamespace(
        module=module,
        environment=environment,
        runtime=runtime,
        proc=proc,
        seed=seed,
        inspect=inspect,
        calls=calls,
        storage=storage,
    )


def test_missing_keeper_is_prepared_and_healthy_repeats_skip_podman(prepared):
    p = prepared
    assert p.module.ensure(p.environment, inspect=p.inspect)["changed"]
    assert not p.module.ensure(p.environment, inspect=p.inspect)["changed"]
    assert len(p.calls) == 1
    assert (p.runtime / "umi-cpu-namespace-ready.json").stat().st_mode & 0o777 == 0o600


def test_dead_keeper_is_reprepared_without_resetting_store(prepared):
    p = prepared
    p.module.ensure(p.environment, inspect=p.inspect)
    (p.proc / "123/comm").unlink()
    sentinel = p.runtime / "retained-model-state"
    sentinel.write_text("preserve")
    assert p.module.ensure(p.environment, inspect=p.inspect)["changed"]
    assert len(p.calls) == 2 and sentinel.read_text() == "preserve"


@pytest.mark.parametrize("change", ["pid_reuse", "configuration", "boot", "receipt_damage"])
def test_changed_readiness_dependencies_require_inspection(prepared, change):
    p = prepared
    p.module.ensure(p.environment, inspect=p.inspect)
    if change == "pid_reuse":
        p.seed(start="100")
    elif change == "configuration":
        p.storage.write_text('[storage]\ndriver="vfs"\n')
    elif change == "boot":
        (p.proc / "sys/kernel/random/boot_id").write_text("next-boot\n")
    else:
        (p.runtime / "umi-cpu-namespace-ready.json").write_bytes(b"{")
    assert p.module.ensure(p.environment, inspect=p.inspect)["podman_inspected"]
    assert len(p.calls) == 2


def test_hardened_process_refuses_before_attempting_uid_mapping(prepared):
    p = prepared
    (p.proc / "self/status").write_text("NoNewPrivs:\t1\n")
    with pytest.raises(ValueError, match="outside the hardened reviewer"):
        p.module.ensure(p.environment, inspect=p.inspect)
    assert not p.calls


def test_failed_inspection_retains_numeric_error_and_does_not_publish_success(prepared):
    p = prepared

    def failed():
        return SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"newuidmap: Operation not permitted"
        )

    with pytest.raises(RuntimeError, match=r"exit=1.*newuidmap"):
        p.module.ensure(p.environment, inspect=failed)
    assert not (p.runtime / "umi-cpu-namespace-ready.json").exists()


def test_interrupted_publication_preserves_existing_record_and_pending_file(prepared):
    p = prepared
    record = p.runtime / "umi-cpu-namespace-ready.json"
    record.write_text("original receipt")
    pending = record.with_name(record.name + ".pending-" + str(os.getpid()))
    pending.write_text("retained interrupted publication")
    with pytest.raises(FileExistsError):
        p.module.ensure(p.environment, inspect=p.inspect)
    assert record.read_text() == "original receipt"
    assert pending.read_text() == "retained interrupted publication"


def test_package_upgrade_preserves_a_live_namespace_with_unlinked_old_executable(prepared):
    p = prepared
    p.module.ensure(p.environment, inspect=p.inspect)
    executable = p.proc / "123/exe"
    executable.unlink()
    executable.symlink_to(str(p.module.PODMAN) + " (deleted)")
    assert not p.module.ensure(p.environment, inspect=p.inspect)["changed"]
    assert len(p.calls) == 1


@pytest.mark.parametrize("bad", ["not_rootless", "cgroup_v1", "no_keeper", "oversized"])
def test_invalid_or_unbounded_inspection_cannot_become_ready(prepared, bad):
    p = prepared

    def inspect():
        if bad != "no_keeper":
            p.seed()
        info = dict(
            host=dict(
                security=dict(rootless=bad != "not_rootless"),
                cgroupVersion="v1" if bad == "cgroup_v1" else "v2",
            )
        )
        return SimpleNamespace(
            returncode=0,
            stdout=b"x" * (p.module.MAX_OUTPUT + 1)
            if bad == "oversized"
            else json.dumps(info).encode(),
            stderr=b"",
        )

    with pytest.raises((RuntimeError, ValueError)):
        p.module.ensure(p.environment, inspect=inspect)
    assert not (p.runtime / "umi-cpu-namespace-ready.json").exists()
