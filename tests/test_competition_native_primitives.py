from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from umi.competition_native_inventory import inventory
from umi.competition_native_sandbox import native_profile
from umi.competition_native_watchdog import scratch_usage


def test_native_runtime_is_explicit_and_cpu_bytes_are_unchanged():
    from umi.competition_native import OfflineMpsRuntime
    from umi.competition_runner import OFFLINE_RUNTIME, OfflineCpuRuntime
    from umi.protocol import canonical_json_bytes

    cpu = OfflineCpuRuntime(
        schema="umi-offline-cpu-runtime/2",
        image="ghcr.io/example/runtime@sha256:" + "ab" * 32,
        cpus=4,
        memory_bytes=1024**3,
        scratch_bytes=16 * 1024**2,
        pids_limit=64,
        maximum_video_bytes=1024,
    )
    raw = canonical_json_bytes(cpu)
    assert canonical_json_bytes(OFFLINE_RUNTIME.validate_json(raw)) == raw
    native = OfflineMpsRuntime(
        schema="umi-offline-mps-runtime/1",
        installation_sha256="cd" * 32,
        os_build="25F84",
        python_abi="cp310",
        cpu_threads=4,
        maximum_video_bytes=1024,
        rss_watchdog_bytes=1024**3,
        scratch_watchdog_bytes=16 * 1024**2,
        cold_start_in_deadline=True,
    )
    parsed = OFFLINE_RUNTIME.validate_json(canonical_json_bytes(native))
    assert isinstance(parsed, OfflineMpsRuntime)
    with pytest.raises(ValueError):
        OFFLINE_RUNTIME.validate_json(raw.replace(b"cpu-runtime/2", b"mps-runtime/1"))
    with pytest.raises(ValueError):
        OfflineMpsRuntime.model_validate_json(
            canonical_json_bytes(native.model_copy(update={"cold_start_in_deadline": False}))
        )


def test_private_runtime_json_rejects_world_readable_or_noncanonical_documents(tmp_path):
    from umi.competition_native import _private_json

    path = tmp_path / "paths.json"
    path.write_bytes(b'{"a":1}')
    path.chmod(0o600)
    assert _private_json(path, 100) == ({"a": 1}, b'{"a":1}')
    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-private"):
        _private_json(path, 100)
    path.chmod(0o600)
    path.write_bytes(b'{"a":1,"a":2}')
    with pytest.raises(ValueError, match="canonical"):
        _private_json(path, 100)


def test_case_namespace_is_retained_after_uncertain_failure():
    from umi.competition_native import _case_directory

    with _case_directory() as success:
        assert success.is_dir()
    assert not success.exists()
    with pytest.raises(RuntimeError), _case_directory() as failed:
        raise RuntimeError("uncertain child cleanup")
    assert failed.is_dir()
    failed.rmdir()  # This synthetic directory is empty and has no child process.


def test_installation_verification_rejects_modified_dependency(roots, tmp_path, monkeypatch):
    import hashlib

    from umi.competition_native import OfflineMpsRuntime, verify_installation
    from umi.protocol import canonical_json_bytes

    (roots["environment"] / "bin").mkdir(mode=0o700)
    (roots["python"] / "file").chmod(0o500)
    (roots["environment"] / "bin/python").symlink_to(roots["python"] / "file")
    raw = canonical_json_bytes(
        {"schema": "umi-native-evaluator-installation/1", "entries": inventory(roots)}
    )
    manifest = tmp_path / "installation.json"
    manifest.write_bytes(raw)
    manifest.chmod(0o600)
    paths = tmp_path / "paths.json"
    paths.write_bytes(
        canonical_json_bytes(
            {
                "schema": "umi-native-evaluator-paths/1",
                "roots": {name: str(path) for name, path in roots.items()},
                "manifest": str(manifest),
            }
        )
    )
    paths.chmod(0o600)
    monkeypatch.setenv("UMI_NATIVE_EVALUATOR_CONFIG", str(paths))
    runtime = OfflineMpsRuntime(
        schema="umi-offline-mps-runtime/1",
        installation_sha256=hashlib.sha256(raw).hexdigest(),
        os_build="25F84",
        python_abi="cp310",
        cpu_threads=4,
        maximum_video_bytes=1024,
        rss_watchdog_bytes=1024**3,
        scratch_watchdog_bytes=1024**2,
        cold_start_in_deadline=True,
    )
    assert verify_installation(runtime) == roots
    (roots["overlay"] / "file").chmod(0o600)
    (roots["overlay"] / "file").write_bytes(b"tampered")
    (roots["overlay"] / "file").chmod(0o400)
    with pytest.raises(ValueError, match="installed files differ"):
        verify_installation(runtime)


@pytest.fixture
def roots(tmp_path):
    result = {name: tmp_path / name for name in ("environment", "python", "overlay")}
    for path in result.values():
        path.mkdir(mode=0o700)
        (path / "file").write_bytes(b"reviewed")
        (path / "file").chmod(0o400)
    return result


def test_inventory_is_path_independent_and_binds_content(roots, tmp_path):
    first = inventory(roots)
    clone = tmp_path / "clone"
    clone.mkdir()
    moved = {}
    for name, path in roots.items():
        moved[name] = clone / name
        path.rename(moved[name])
    assert inventory(moved) == first
    (moved["python"] / "file").chmod(0o600)
    (moved["python"] / "file").write_bytes(b"modified")
    (moved["python"] / "file").chmod(0o400)
    assert inventory(moved) != first


def test_inventory_normalizes_internal_links_and_rejects_external_links(roots, tmp_path):
    link = roots["environment"] / "python"
    link.symlink_to(roots["python"] / "file")
    entry = next(row for row in inventory(roots) if row["kind"] == "symlink")
    assert entry["target_root"] == "python" and entry["target_path"] == "file"
    link.unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    link.symlink_to(outside)
    with pytest.raises(ValueError, match="escapes"):
        inventory(roots)


@pytest.mark.parametrize("attack", ["hardlink", "fifo", "writable", "overlap", "alias"])
def test_inventory_rejects_unsafe_installation(roots, tmp_path, attack):
    target = roots["environment"] / "bad"
    if attack == "hardlink":
        os.link(roots["python"] / "file", target)
    elif attack == "fifo":
        os.mkfifo(target)
    elif attack == "writable":
        roots["overlay"].chmod(0o777)
    elif attack == "overlap":
        roots["overlay"] = roots["python"]
    else:
        target.symlink_to(roots["overlay"], target_is_directory=True)
        roots["overlay"] = target
    with pytest.raises(ValueError):
        inventory(roots)


@pytest.fixture
def profile_inputs():
    return dict(
        python=Path("/installation/python/bin/python3"),
        readonly=(Path("/installation/python"), Path("/installation/model")),
        readable_files=(Path("/installation/runtime.json"),),
        scratch=Path("/private/case/scratch"),
        metal_cache=Path("/private/case/metal"),
    )


def test_native_profile_denies_fork_network_and_other_process_signals(profile_inputs):
    profile = native_profile(**profile_inputs)
    assert "(deny default)" in profile
    assert "(allow signal (target self))" in profile
    assert "(allow process-fork" not in profile
    assert "(allow process*" not in profile
    assert "(allow network" not in profile
    assert '(literal "/")' in profile
    assert '(subpath "/")' not in profile
    assert '(subpath "/Users")' not in profile
    assert '(subpath "/private")' not in profile
    assert '(subpath "/dev")' not in profile


@pytest.mark.parametrize("path", ["relative", "/", "/Users", "/a/../b", "/a\nb"])
def test_profile_rejects_unsafe_paths(profile_inputs, path):
    with pytest.raises(ValueError):
        native_profile(**dict(profile_inputs, scratch=Path(path)))


def test_profile_quotes_path_injection(profile_inputs):
    path = Path('/tmp/test") (allow default) ("')
    profile = native_profile(**dict(profile_inputs, scratch=path))
    assert json.dumps(str(path)) in profile


@pytest.mark.parametrize("field", ["scratch", "metal_cache", "python"])
def test_profile_rejects_overlapping_mutable_and_executable_roots(profile_inputs, field):
    value = "/private/case/scratch/python" if field == "python" else "/installation/model/inside"
    with pytest.raises(ValueError):
        native_profile(**dict(profile_inputs, **{field: Path(value)}))


def test_scratch_scan_has_byte_and_entry_bounds_and_never_follows_links(tmp_path):
    (tmp_path / "a").write_bytes(b"123")
    assert scratch_usage(tmp_path, maximum_bytes=3) == 3
    with pytest.raises(ValueError, match="byte"):
        scratch_usage(tmp_path, maximum_bytes=2)
    with pytest.raises(ValueError, match="entry"):
        scratch_usage(tmp_path, maximum_bytes=3, maximum_entries=0)
    (tmp_path / "b").symlink_to(tmp_path / "a")
    assert scratch_usage(tmp_path, maximum_bytes=4096) == 3 + (tmp_path / "b").lstat().st_size
    os.mkfifo(tmp_path / "fifo")
    assert scratch_usage(tmp_path, maximum_bytes=4096) == 3 + (tmp_path / "b").lstat().st_size


@pytest.mark.skipif(os.name != "posix", reason="native guard requires POSIX process groups")
@pytest.mark.parametrize("mode", ["success", "deadline", "disconnect", "pre_disconnected"])
def test_real_guard_reaps_child_without_controller(mode, tmp_path):
    from umi import competition_native_watchdog

    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    pid_path = scratch / "pid"
    child = (
        "import os,time;from pathlib import Path;"
        f"Path({str(pid_path)!r}).write_text(str(os.getpid()));"
        + ("print('translated',flush=True)" if mode == "success" else "time.sleep(20)")
    )
    command = [
        sys.executable,
        "-B",
        str(Path(competition_native_watchdog.__file__)),
        "--deadline-ms",
        "500" if mode == "deadline" else "5000",
        "--rss-ceiling",
        str(1024**3),
        "--scratch-ceiling",
        str(1024**2),
        "--scratch",
        str(scratch),
        "--",
        sys.executable,
        "-I",
        "-c",
        child,
    ]
    read_fd, write_fd = os.pipe()
    if mode == "pre_disconnected":
        os.close(write_fd)
        write_fd = None
    process = subprocess.Popen(
        command, stdin=read_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    os.close(read_fd)
    try:
        if mode == "disconnect":
            end = time.monotonic() + 5
            while not pid_path.exists() and time.monotonic() < end:
                time.sleep(0.01)
            assert pid_path.exists()
            os.close(write_fd)
            write_fd = None
        stdout, stderr = process.communicate(timeout=8)
        assert not stderr
        assert (
            process.returncode
            == {"success": 0, "deadline": 124, "disconnect": 125, "pre_disconnected": 125}[mode]
        )
        if mode == "success":
            assert stdout == b"translated\n"
        if mode == "pre_disconnected":
            assert not pid_path.exists()
        else:
            pid = int(pid_path.read_text())
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
    finally:
        if write_fd is not None:
            os.close(write_fd)
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=5)
