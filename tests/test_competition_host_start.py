from __future__ import annotations

import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_competition_host_switch import (
    _commit,
    hold,
    inputs,
    installed,
    switching,
)
from umi import competition_host_start as start
from umi import competition_host_switch as switch
from umi import competition_host_upgrade as host

__all__ = ["inputs", "installed", "switching"]


@pytest.fixture
def ready(switching, monkeypatch):
    case = switching
    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))
    with hold(case.installed) as stopped:
        case.result = _commit(case, stopped)
    case.calls = []

    def systemctl(verb, unit):
        case.calls.append((verb, unit))
        if unit == case.plan.unit_name:
            if verb == "start":
                case.unit.update(
                    ActiveState="active",
                    SubState="running",
                    MainPID="123",
                    ControlGroup="/system.slice/" + case.plan.unit_name,
                )
            else:
                case.unit.update(
                    ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup=""
                )

    monkeypatch.setattr(start, "_systemctl", systemctl)
    monkeypatch.setattr(start, "_unit_snapshot", switch._unit_snapshot)
    monkeypatch.setattr(start, "_read_drop_in", switch._read_drop_in)
    monkeypatch.setattr(start, "_require_empty_cgroup", switch._require_empty_cgroup)

    def owns_lock(pid, result):
        assert pid == 123 and result is case.result
        assert not result._stopped._lease.active

    monkeypatch.setattr(start, "_process_owns_lock", owns_lock)
    yield case
    start._STARTED.pop(id(case.result), None)


def test_start_uses_only_exact_committed_unit_after_lock_release(ready):
    result = start.start_committed_successor_service(ready.result)
    assert ready.calls == [
        ("start", ready.plan.required_user_manager),
        ("start", ready.plan.unit_name),
    ]
    assert result.main_pid == 123
    assert result.host_manifest_sha256 == ready.plan.host_manifest_sha256
    assert not result.chain_submission_authorized


def test_start_cannot_use_a_copied_capability(ready):
    with pytest.raises(host.HostUpgradeError, match="not committed"):
        start.start_committed_successor_service(replace(ready.result))
    assert not ready.calls


def test_start_rejects_changed_control_before_lifecycle_call(ready):
    ready.plan.drop_in_path.chmod(0o600)
    ready.plan.drop_in_path.write_bytes(b"changed")
    with pytest.raises(host.HostUpgradeError, match="changed"):
        start.start_committed_successor_service(ready.result)
    assert not ready.calls


def test_manager_start_is_followed_by_another_integrity_check(ready, monkeypatch):
    def replace_unit(*args):
        ready.calls.append(args)
        ready.unit["User"] = "root"

    monkeypatch.setattr(start, "_systemctl", replace_unit)
    with pytest.raises(host.HostUpgradeError):
        start.start_committed_successor_service(ready.result)
    assert ("start", ready.plan.unit_name) not in ready.calls


def test_failed_start_runs_exact_cleanup_and_preserves_switch(ready, monkeypatch):
    def failed(_):
        raise host.HostUpgradeError("startup validation failed")

    monkeypatch.setattr(start, "_running", failed)
    with pytest.raises(host.HostUpgradeError, match="startup validation failed"):
        start.start_committed_successor_service(ready.result)
    assert ready.calls[-2:] == [
        ("stop", ready.plan.unit_name),
        ("start", ready.plan.cleanup_unit_name),
    ]
    assert ready.plan.drop_in_path.read_bytes() == ready.plan.drop_in_bytes
    assert ready.unit["ActiveState"] == "inactive"
    with pytest.raises(host.HostUpgradeError, match="already has a start attempt"):
        start.start_committed_successor_service(ready.result)


def test_unconfirmed_cleanup_does_not_report_stopped(ready, monkeypatch):
    original = start._systemctl

    def command(verb, unit):
        if verb == "stop":
            raise OSError("stop failed")
        original(verb, unit)

    monkeypatch.setattr(start, "_systemctl", command)
    monkeypatch.setattr(start, "_running", lambda _: (_ for _ in ()).throw(ValueError("invalid")))
    with pytest.raises(host.HostUpgradeError, match="cleanup is unconfirmed"):
        start.start_committed_successor_service(ready.result)
    assert ready.unit["ActiveState"] == "active"


def test_type_simple_start_waits_for_lock_acquisition(ready, monkeypatch):
    attempts = []
    original = start._process_owns_lock

    def delayed(pid, switch):
        attempts.append(pid)
        if len(attempts) == 1:
            raise start._StartupPending("not acquired yet")
        original(pid, switch)

    monkeypatch.setattr(start, "_process_owns_lock", delayed)
    monkeypatch.setattr(start.time, "sleep", lambda _: None)
    assert start.start_committed_successor_service(ready.result).main_pid == 123
    assert len(attempts) == 2
    assert ("stop", ready.plan.unit_name) not in ready.calls


def test_start_timeout_is_bounded_and_contained(ready, monkeypatch):
    clock = iter([0, 31])
    monkeypatch.setattr(start.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        start, "_running", lambda _: (_ for _ in ()).throw(start._StartupPending("pending"))
    )
    with pytest.raises(host.HostUpgradeError, match="timed out"):
        start.start_committed_successor_service(ready.result)
    assert ready.calls[-1] == ("start", ready.plan.cleanup_unit_name)


@pytest.mark.parametrize(
    "field,value",
    [
        ("User", "root"),
        ("MainPID", "0"),
        ("MainPID", "-2"),
        ("ControlGroup", "/other.slice/vali.service"),
        ("ControlPID", "123"),
        ("ExecStart", "/tmp/unverified"),
        ("ActiveState", "failed"),
    ],
)
def test_started_service_must_match_exact_identity(ready, monkeypatch, field, value):
    original = start._systemctl

    def mutate(verb, unit):
        original(verb, unit)
        if verb == "start" and unit == ready.plan.unit_name:
            ready.unit[field] = value

    monkeypatch.setattr(start, "_systemctl", mutate)
    with pytest.raises(host.HostUpgradeError):
        start.start_committed_successor_service(ready.result)
    assert ("stop", ready.plan.unit_name) in ready.calls


def test_fixed_systemctl_call_never_uses_shell_or_wallet(monkeypatch):
    calls = []
    monkeypatch.setattr(
        start.subprocess,
        "run",
        lambda *args, **kwargs: calls.append((args, kwargs)) or SimpleNamespace(returncode=0),
    )
    start._systemctl("start", "umi-validator-supervisor.service")
    args, kwargs = calls[0]
    assert args == (["/usr/bin/systemctl", "start", "--", "umi-validator-supervisor.service"],)
    assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == start.subprocess.DEVNULL
    assert kwargs["timeout"] == 45
    assert not kwargs.get("shell")


@pytest.mark.parametrize(
    "line,expected",
    [
        ("pos: 0", False),
        ("lock: 1: FLOCK ADVISORY WRITE 123 00:01:42 0 EOF", True),
        ("lock: 1: FLOCK ADVISORY WRITE 124 00:01:42 0 EOF", False),
        ("lock: 1: FLOCK ADVISORY READ 123 00:01:42 0 EOF", False),
        ("lock: 1: POSIX ADVISORY WRITE 123 00:01:42 0 EOF", False),
        ("lock: 1: FLOCK ADVISORY WRITE 123 00:01:43 0 EOF", False),
        ("lock: 1: FLOCK ADVISORY WRITE 123 00:02:42 0 EOF", False),
        ("lock: 1: -> FLOCK ADVISORY WRITE 123 00:01:42 0 EOF", False),
        ("lock: 1: FLOCK ADVISORY WRITE 123 invalid 0 EOF", False),
    ],
)
def test_kernel_metadata_requires_this_process_exclusive_flock(line, expected):
    info = SimpleNamespace(st_dev=os.makedev(0, 1), st_ino=42)
    assert start._kernel_flock_matches(line.encode(), pid=123, info=info) is expected
