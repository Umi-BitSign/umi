from __future__ import annotations

import asyncio
import fcntl
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from umi import competition_container as containers
from umi import competition_supervisor_cleanup as cleanup
from umi.protocol import canonical_json_bytes

from .test_validator_supervisor import _config


@pytest.fixture
def cleanup_case(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    lock = state / "supervisor-process.lock"
    lock.write_bytes(b"original lock bytes must remain")
    lock.chmod(0o600)
    config = _config(state_root=str(state))
    config_path = tmp_path / "supervisor.json"
    config_path.write_bytes(canonical_json_bytes(config))
    config_path.chmod(0o400)
    limits = containers.SuccessorContainerLimits(1, 1024, 1, 1024, 1, 1024)
    container = containers.PodmanSuccessorContainer(config, limits=limits)
    case = SimpleNamespace(
        config=config,
        path=config_path,
        lock=lock,
        calls=[],
        empty_cgroups=[],
        fault=None,
        mutate=None,
        mutate_after=None,
    )
    case.record = {
        "Id": "ab" * 32,
        "Name": container.name,
        "Config": {
            "Labels": {
                "vision.umi.successor.config": container._config_sha256,
                "vision.umi.successor.hotkey": container._hotkey_sha256,
                "vision.umi.successor.directive": "cd" * 32,
                "vision.umi.successor.receipt": "ef" * 32,
                "vision.umi.successor.profile": "competition_weights",
            }
        },
        "State": {"Status": "running", "Running": True, "Pid": 901, "ExitCode": 0},
    }

    async def runner(arguments, **bounds):
        case.calls.append(arguments)
        assert arguments[:2] == ("/usr/bin/podman", "--cgroup-manager=systemd")
        assert bounds == {"timeout_seconds": 45, "maximum_output_bytes": 1024 * 1024}
        # The original lock is really held during every asynchronous command.
        descriptor = os.open(lock, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        if arguments[2] == "ps":
            assert arguments == (
                "/usr/bin/podman",
                "--cgroup-manager=systemd",
                "ps",
                "--all",
                f"--filter=name=^{container.name}$",
                "--format=json",
            )
            result = [] if case.record is None else [{"Id": case.record["Id"]}]
        elif arguments[2:4] == ("container", "inspect"):
            assert arguments[-1] == case.record["Id"]
            result = [case.record]
        elif arguments[2] == "stop":
            assert arguments == (
                "/usr/bin/podman",
                "--cgroup-manager=systemd",
                "stop",
                "--time=30",
                case.record["Id"],
            )
            if case.fault == "timeout":
                raise TimeoutError("secret error must not be printed")
            if case.fault == "cancel":
                raise asyncio.CancelledError()
            if case.fault != "still_running":
                case.record["State"] = {
                    "Status": "exited",
                    "Running": False,
                    "Pid": 0,
                    "ExitCode": 143,
                }
            result = "stopped"
        else:
            pytest.fail("cleanup attempted to start, remove, or inspect other resources")
        if case.mutate is not None and arguments[2] == case.mutate_after:
            case.mutate()
            case.mutate = None
        return json.dumps(result).encode()

    # Root-owned config/ancestor provenance is an explicit filesystem fixture
    # port. Actual inode checks, private lock/flock, and exact Podman ownership
    # validation remain active; no activation loader or wallet is involved.
    monkeypatch.setattr(cleanup.sys, "platform", "linux")
    if os.geteuid() == 0:
        monkeypatch.setattr(cleanup.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(cleanup, "_root_control", lambda path, maximum: path.read_bytes())
    monkeypatch.setattr(
        cleanup,
        "_ancestor_identity",
        lambda path: (path.stat().st_dev, path.stat().st_ino, path.stat().st_mode),
    )
    monkeypatch.setattr(cleanup, "_require_safe_executable", lambda path: None)
    monkeypatch.setattr(cleanup, "_run_command", runner)
    monkeypatch.setattr(containers, "_require_empty_container_cgroup", case.empty_cgroups.append)
    return case


def _assert_unlocked(case):
    descriptor = os.open(case.lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


async def test_cleanup_stops_exact_successor_and_retains_state_without_activation(cleanup_case):
    case = cleanup_case
    before = case.lock.read_bytes()
    assert await cleanup.cleanup_successor(case.path) == "stopped"
    assert case.record is not None and case.record["State"]["Running"] is False
    assert case.empty_cgroups == ["ab" * 32]
    assert case.lock.read_bytes() == before
    assert {call[2] for call in case.calls} == {"ps", "container", "stop"}
    _assert_unlocked(case)


async def test_absent_container_is_noop(cleanup_case):
    case = cleanup_case
    case.record = None
    assert await cleanup.cleanup_successor(case.path) == "absent"
    assert len(case.calls) == 1 and not case.empty_cgroups


async def test_already_stopped_checks_empty_cgroup_without_killing(cleanup_case):
    case = cleanup_case
    case.record["State"] = {"Status": "exited", "Running": False, "Pid": 0, "ExitCode": 0}
    assert await cleanup.cleanup_successor(case.path) == "stopped"
    assert all(call[2] != "stop" for call in case.calls)
    assert case.empty_cgroups == [case.record["Id"]]


async def test_live_supervisor_lock_blocks_cleanup_without_any_podman_calls(cleanup_case):
    case = cleanup_case
    descriptor = os.open(case.lock, os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(cleanup.SuccessorCleanupBusy):
            await cleanup.cleanup_successor(case.path)
        assert case.calls == [] and case.record["State"]["Running"] is True
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("damage", ["missing", "symlink", "mode", "hardlink"])
async def test_missing_or_replaced_lock_never_creates_a_fresh_lock(cleanup_case, damage):
    case = cleanup_case
    if damage == "missing":
        case.lock.unlink()
    elif damage == "symlink":
        original = case.lock.with_name("saved-lock")
        case.lock.rename(original)
        case.lock.symlink_to(original)
    elif damage == "mode":
        case.lock.chmod(0o644)
    else:
        os.link(case.lock, case.lock.with_name("hardlinked-lock"))
    with pytest.raises((ValueError, OSError)):
        await cleanup.cleanup_successor(case.path)
    assert case.calls == []
    if damage == "missing":
        assert not case.lock.exists()


@pytest.mark.parametrize("field", ["hotkey", "config", "profile", "directive", "receipt", "name"])
async def test_other_validator_or_unlabelled_container_is_never_stopped(cleanup_case, field):
    case = cleanup_case
    if field == "name":
        case.record["Name"] = "umi-legacy-other-hotkey"
    else:
        case.record["Config"]["Labels"]["vision.umi.successor." + field] = "unrelated"
    with pytest.raises(ValueError, match="unrelated"):
        await cleanup.cleanup_successor(case.path)
    assert all(call[2] != "stop" for call in case.calls)


@pytest.mark.parametrize("target", ["config", "lock", "state"])
async def test_filesystem_identity_change_between_commands_vetoes_stop(cleanup_case, target):
    case = cleanup_case

    def mutate():
        if target == "config":
            case.path.chmod(0o600)
            case.path.write_bytes(
                canonical_json_bytes(case.config.model_copy(update={"poll_seconds": 60}))
            )
        elif target == "lock":
            case.lock.rename(case.lock.with_name("old-lock"))
            case.lock.write_bytes(b"replacement")
            case.lock.chmod(0o600)
        else:
            case.lock.parent.chmod(0o755)

    case.mutate, case.mutate_after = mutate, "ps"
    with pytest.raises(ValueError):
        await cleanup.cleanup_successor(case.path)
    assert all(call[2] != "stop" for call in case.calls)


@pytest.mark.parametrize("fault", ["timeout", "still_running", "cancel"])
async def test_stop_failure_never_reports_absence_and_releases_process_lease(cleanup_case, fault):
    case = cleanup_case
    case.fault = fault
    expected = asyncio.CancelledError if fault == "cancel" else (ValueError, TimeoutError)
    with pytest.raises(expected):
        await cleanup.cleanup_successor(case.path)
    assert not case.empty_cgroups
    _assert_unlocked(case)


async def test_residual_cgroup_processes_are_not_success(cleanup_case, monkeypatch):
    def occupied(_):
        raise ValueError("cgroup remains populated")

    monkeypatch.setattr(containers, "_require_empty_container_cgroup", occupied)
    with pytest.raises(ValueError, match="populated"):
        await cleanup.cleanup_successor(cleanup_case.path)


@pytest.mark.parametrize(
    "arguments", [("rm", "ab" * 32), ("start", "ab" * 32), ("system", "prune")]
)
async def test_future_container_method_cannot_expand_cleanup_profile(
    cleanup_case, monkeypatch, arguments
):
    async def expanded(container):
        await container._command(*arguments)

    monkeypatch.setattr(containers.PodmanSuccessorContainer, "stop", expanded)
    with pytest.raises(ValueError, match="fixed stop profile"):
        await cleanup.cleanup_successor(cleanup_case.path)
    assert not cleanup_case.calls


async def test_cleanup_total_deadline_cancels_operation(monkeypatch):
    finished = asyncio.Event()

    async def stuck(_):
        try:
            await asyncio.Event().wait()
        finally:
            finished.set()

    monkeypatch.setattr(cleanup, "cleanup_successor", stuck)
    monkeypatch.setattr(cleanup, "_TOTAL_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(asyncio.TimeoutError):
        await cleanup._bounded_cleanup(None)
    assert finished.is_set()


def test_fixed_cleanup_cli_help_never_loads_configuration(monkeypatch, capsys):
    monkeypatch.setattr(cleanup, "_root_control", lambda *_: pytest.fail("help read configuration"))
    with pytest.raises(SystemExit) as result:
        cleanup.run_cli(["--help"])
    assert result.value.code == 0 and "--config" in capsys.readouterr().out


def test_cleanup_module_help_runs_fixed_entrypoint():
    result = subprocess.run(
        [sys.executable, "-m", "umi.competition_supervisor_cleanup", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0 and "--config" in result.stdout
    assert not result.stderr


@pytest.mark.parametrize("extra", ["--wallet", "--container", "--runtime", "--all", "--conf"])
def test_cleanup_cli_cannot_select_other_targets(extra):
    with pytest.raises(SystemExit) as result:
        cleanup.run_cli(["--config", "/etc/umi/config.json", extra, "anything"])
    assert result.value.code == 2


def test_cleanup_cli_redacts_failure(cleanup_case, capsys):
    cleanup_case.fault = "timeout"
    assert cleanup.run_cli(["--config", str(cleanup_case.path)]) == 1
    assert capsys.readouterr().err == "successor_cleanup=unconfirmed\n"


def test_cleanup_cli_busy_is_distinct_from_success(cleanup_case, capsys):
    descriptor = os.open(cleanup_case.lock, os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        assert cleanup.run_cli(["--config", str(cleanup_case.path)]) == 3
        assert capsys.readouterr().err == "successor_cleanup=busy\n"
        assert not cleanup_case.calls
    finally:
        os.close(descriptor)
