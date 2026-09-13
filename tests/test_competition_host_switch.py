from __future__ import annotations

import fcntl
import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_competition_host_upgrade import hold, inputs, installed
from umi import competition_host_switch as switch
from umi import competition_switch_recovery as recovery
from umi.competition_host_service import SuccessorServiceSwitchPlan
from umi.competition_host_upgrade import HostUpgradeError
from umi.competition_host_upgrade import _check_unit as _real_check_unit

# Reuse genuine legacy installation/lock fixtures, not a reconstructed stopped
# capability. The OS service boundary and separately tested root anchor/tree are
# replaced here; the opt-in Linux suite covers actual systemd behavior.
__all__ = ["inputs", "installed"]


@pytest.fixture
def switching(installed, monkeypatch, tmp_path):
    events = []
    unit = {
        "Id": "umi-validator-supervisor.service",
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ControlPID": "0",
        "User": "umi-validator",
        "ControlGroup": "",
        "DropInPaths": "",
        "OnFailure": "",
        "FragmentPath": str(installed.config_path),
        "ExecStart": "legacy",
    }
    monkeypatch.setattr(switch, "_require_root_linux", lambda: None)
    monkeypatch.setattr(switch, "_root_file", lambda path: None)
    monkeypatch.setattr(switch, "_require_empty_cgroup", lambda *args: events.append("empty"))
    payload = b"[Service]\nExecStart=fixed-test-only\n"
    plan = SuccessorServiceSwitchPlan(
        unit_name=unit["Id"],
        service_uid=os.geteuid(),
        service_user="umi-validator",
        drop_in_path=tmp_path / "systemd" / (unit["Id"] + ".d") / "50-umi-successor.conf",
        drop_in_bytes=payload,
        drop_in_sha256=hashlib.sha256(payload).hexdigest(),
        cleanup_unit_name="umi-validator-supervisor-successor-cleanup.service",
        cleanup_unit_path=tmp_path / "systemd/umi-validator-supervisor-successor-cleanup.service",
        cleanup_unit_bytes=b"fixed cleanup fixture",
        cleanup_unit_sha256=hashlib.sha256(b"fixed cleanup fixture").hexdigest(),
        observer_state_source=tmp_path / "observer",
        required_user_manager=f"user@{os.geteuid()}.service",
        source_parent_readonly_mount=tmp_path / "source",
        host_manifest_sha256="11" * 32,
        host_root=Path("/opt/umi-validator-supervisor-hosts") / ("22" * 20),
        checkpoint_sha256="33" * 32,
    )
    cleanup_unit = dict(unit)
    cleanup_unit.update(
        Id=plan.cleanup_unit_name,
        FragmentPath=str(plan.cleanup_unit_path),
        ExecStart=(
            str(plan.host_root)
            + "/.venv/bin/umi-competition-supervisor-cleanup --config "
            + str(installed.config_path)
            + " ;"
        ),
    )
    monkeypatch.setattr(
        switch,
        "_unit_snapshot",
        lambda unit_name, **kwargs: dict(cleanup_unit if kwargs.get("successor_cleanup") else unit),
    )
    anchor = SimpleNamespace(
        receipt=SimpleNamespace(checkpoint_sha256=plan.checkpoint_sha256),
        receipt_sha256="44" * 32,
        recheck=lambda: events.append("anchor"),
    )
    tree = SimpleNamespace(
        manifest_sha256=plan.host_manifest_sha256, recheck=lambda: events.append("tree")
    )

    def make_plan(**kwargs):
        kwargs["stopped"].recheck_stopped()
        assert kwargs["anchor"] is anchor and kwargs["host_tree"] is tree
        return plan

    monkeypatch.setattr(switch, "plan_successor_service_switch", make_plan)

    def marker(value):
        events.append("marker")
        value.drop_in_path.parent.mkdir(parents=True)
        return os.open(value.drop_in_path.parent, os.O_RDONLY)

    monkeypatch.setattr(switch, "_create_switch_marker", marker)

    def publish_intent(value, payload):
        recovery._parse(payload)
        descriptor = marker(value)
        path = value.drop_in_path.parent / recovery.INTENT_FILENAME
        path.write_bytes(payload)
        path.chmod(0o444)
        return descriptor

    def read_intent(value):
        payload = (value.drop_in_path.parent / recovery.INTENT_FILENAME).read_bytes()
        intent = recovery._parse(payload)
        if intent.plan_sha256 != recovery._plan_sha256(value):
            raise host_error("changed intent")
        return payload

    host_error = HostUpgradeError
    monkeypatch.setattr(recovery, "publish_switch_intent", publish_intent)
    monkeypatch.setattr(recovery, "read_switch_intent", read_intent)

    def write_once(value, descriptor):
        events.append("write")
        assert value is plan
        assert os.fstat(descriptor).st_ino == value.drop_in_path.parent.stat().st_ino
        value.drop_in_path.write_bytes(value.drop_in_bytes)
        value.drop_in_path.chmod(0o444)

    monkeypatch.setattr(switch, "_write_drop_in_once", write_once)

    def write_cleanup(value):
        events.append("write_cleanup")
        assert value.drop_in_path.parent.is_dir()
        value.cleanup_unit_path.parent.mkdir(parents=True, exist_ok=True)
        value.cleanup_unit_path.write_bytes(value.cleanup_unit_bytes)
        value.cleanup_unit_path.chmod(0o444)

    monkeypatch.setattr(switch, "_write_cleanup_once", write_cleanup)

    def read(value):
        assert value is plan
        if value.drop_in_path.read_bytes() != value.drop_in_bytes:
            raise HostUpgradeError("changed drop-in")
        if value.cleanup_unit_path.read_bytes() != value.cleanup_unit_bytes:
            raise HostUpgradeError("changed cleanup unit")
        events.append("read")

    monkeypatch.setattr(switch, "_read_drop_in", read)

    def reload():
        events.append("reload")
        unit["DropInPaths"] = str(plan.drop_in_path)
        unit["OnFailure"] = plan.cleanup_unit_name
        unit["ExecStart"] = (
            str(plan.host_root)
            + "/.venv/bin/umi-competition-supervisor --config "
            + str(installed.config_path)
            + " ;"
        )

    monkeypatch.setattr(switch, "_reload_systemd", reload)
    return SimpleNamespace(
        installed=installed,
        plan=plan,
        anchor=anchor,
        tree=tree,
        unit=unit,
        cleanup_unit=cleanup_unit,
        events=events,
    )


def _commit(case, stopped):
    # The genuine held capability was acquired against a mocked OS snapshot;
    # give that same observation the full fields used by the reload boundary.
    stopped._lease.unit_snapshot = dict(case.unit)
    return switch.commit_successor_service_switch(
        stopped=stopped, anchor=case.anchor, host_tree=case.tree, signed_host=None
    )


def test_switch_consumes_old_authority_but_holds_same_lock_through_context(switching, monkeypatch):
    case = switching
    # Legacy _check_unit normally returns the original full snapshot too.
    from umi import competition_host_upgrade as host

    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))
    lock = case.installed.root / "state" / "supervisor-process.lock"
    before = lock.read_bytes()
    with hold(case.installed) as stopped:
        old_fd = stopped._lease.lock_fd
        result = _commit(case, stopped)
        assert stopped._lease.lock_fd == old_fd
        with pytest.raises(HostUpgradeError):
            stopped.recheck_stopped()
        with pytest.raises(HostUpgradeError, match="still holds"):
            switch.recheck_committed_successor_switch(result, require_held=False)
        other = os.open(lock, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)
    switch.recheck_committed_successor_switch(result, require_held=False)
    assert lock.read_bytes() == before
    assert case.unit["ActiveState"] == "inactive"
    assert case.events.count("reload") == 1
    assert case.events.index("marker") < case.events.index("write_cleanup")


@pytest.mark.parametrize("changed", [None, "MainPID", "User", "DropInPaths", "ExecStart"])
def test_inactive_unit_autoload_accepts_only_the_exact_stopped_successor(
    switching, monkeypatch, changed
):
    case = switching
    from umi import competition_host_upgrade as host

    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))
    write = switch._write_drop_in_once

    def write_and_autoload(plan, descriptor):
        write(plan, descriptor)
        # An inactive instance can be garbage-collected and reloaded by show.
        case.unit.update(
            DropInPaths=str(plan.drop_in_path),
            OnFailure=plan.cleanup_unit_name,
            ExecStart=(
                str(plan.host_root)
                + "/.venv/bin/umi-competition-supervisor --config "
                + str(case.installed.config_path)
                + " ;"
            ),
        )
        if changed is not None:
            case.unit[changed] = "unexpected-unit-change"

    monkeypatch.setattr(switch, "_write_drop_in_once", write_and_autoload)
    if changed is None:
        with hold(case.installed) as stopped:
            _commit(case, stopped)
        assert case.events.count("reload") == 1
    else:
        with (
            pytest.raises(HostUpgradeError, match="exact stopped switch"),
            hold(case.installed) as stopped,
        ):
            _commit(case, stopped)
        assert "reload" not in case.events
        assert case.plan.drop_in_path.exists()


@pytest.mark.parametrize(
    "phase", ["write_cleanup", "write", "before_reload", "reload", "after_reload"]
)
def test_interrupted_switch_retains_evidence_and_cannot_reuse_legacy_lease(
    switching, monkeypatch, phase
):
    case = switching
    from umi import competition_host_upgrade as host

    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))

    def fail(*args, **kwargs):
        raise RuntimeError("interrupted")

    if phase == "write_cleanup":
        monkeypatch.setattr(switch, "_write_cleanup_once", fail)
    elif phase == "write":
        monkeypatch.setattr(switch, "_write_drop_in_once", fail)
    elif phase == "before_reload":
        monkeypatch.setattr(switch, "_lock_and_originals", fail)
    elif phase == "reload":
        monkeypatch.setattr(switch, "_reload_systemd", fail)
    else:
        monkeypatch.setattr(switch, "_switched_unit", fail)
    with pytest.raises(RuntimeError, match="interrupted"), hold(case.installed) as stopped:
        try:
            _commit(case, stopped)
        except RuntimeError:
            # Caller-visible fields cannot undo a one-way consumed lease.
            stopped._lease.successor_handoff = None
            with pytest.raises(HostUpgradeError):
                stopped.recheck_stopped()
            raise
    assert not stopped._lease.active
    assert case.plan.drop_in_path.parent.is_dir()
    assert id(stopped._lease) not in host._SUCCESSOR_HANDOFFS
    if phase not in {"write_cleanup", "write"}:
        assert case.plan.drop_in_path.read_bytes() == case.plan.drop_in_bytes
    assert case.unit["ActiveState"] == "inactive"
    # Model a new process after the consumed-lease registry has gone. Exercise
    # the real legacy unit check against the durable marker, not that registry.
    snapshot = dict(original)
    snapshot["ExecStart"] = "legacy --config " + str(case.installed.config_path) + " ;"
    snapshot["FragmentPath"] = "/etc/systemd/system/" + case.plan.unit_name
    monkeypatch.setattr(host, "_unit_snapshot", lambda *args: snapshot)
    monkeypatch.setattr(host.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=os.geteuid()))
    old_lstat = Path.lstat

    def lstat(path):
        if str(path) == "/etc/systemd/system/" + case.plan.unit_name + ".d":
            return old_lstat(case.plan.drop_in_path.parent)
        return old_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(host, "_check_unit", _real_check_unit)
    with pytest.raises(HostUpgradeError, match="unloaded or pending"), hold(case.installed):
        pytest.fail("interrupted successor switch granted another legacy lease")


@pytest.mark.parametrize(
    "name,value",
    [
        ("Id", "other.service"),
        ("LoadState", "not-found"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("MainPID", "123"),
        ("ControlPID", "123"),
        ("User", "root"),
        ("FragmentPath", "/other.service"),
        ("DropInPaths", "/unreviewed.conf"),
        ("OnFailure", "unreviewed.service"),
        ("ExecStart", "unexpected executable"),
    ],
)
def test_reload_must_match_exact_stopped_successor(switching, monkeypatch, name, value):
    case = switching
    from umi import competition_host_upgrade as host

    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))
    reload = switch._reload_systemd

    def changed():
        reload()
        case.unit[name] = value

    monkeypatch.setattr(switch, "_reload_systemd", changed)
    with pytest.raises(HostUpgradeError, match="exact stopped"), hold(case.installed) as stopped:
        _commit(case, stopped)


def test_changed_result_and_drop_in_fail_recheck(switching, monkeypatch):
    case = switching
    from umi import competition_host_upgrade as host

    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))
    with hold(case.installed) as stopped:
        result = _commit(case, stopped)
    with pytest.raises(HostUpgradeError, match="not committed"):
        switch.recheck_committed_successor_switch(replace(result), require_held=False)
    object.__setattr__(result.plan, "service_user", "root")
    with pytest.raises(HostUpgradeError, match="not committed"):
        switch.recheck_committed_successor_switch(result, require_held=False)


@pytest.mark.parametrize(
    "name,value",
    [
        ("Id", "other.service"),
        ("User", "root"),
        ("MainPID", "123"),
        ("DropInPaths", "/tmp/unknown.conf"),
        ("OnFailure", "other.service"),
        ("ExecStart", "unexpected"),
        ("FragmentPath", "/tmp/forged.service"),
    ],
)
def test_wrong_cleanup_unit_blocks_commit(switching, monkeypatch, name, value):
    case = switching
    from umi import competition_host_upgrade as host

    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))
    case.cleanup_unit[name] = value
    with (
        pytest.raises(HostUpgradeError, match="cleanup unit differs"),
        hold(case.installed) as stopped,
    ):
        _commit(case, stopped)


def test_reload_command_cannot_start_or_select_another_unit(monkeypatch):
    seen = []

    def run(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(switch.subprocess, "run", run)
    switch._reload_systemd()
    assert seen[0][0] == ["/usr/bin/systemctl", "daemon-reload"]
    assert seen[0][1]["timeout"] == 30
    assert seen[0][1]["stdin"] == switch.subprocess.DEVNULL


def test_reload_failure_does_not_restore_or_start_old_code(monkeypatch):
    monkeypatch.setattr(
        switch.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1)
    )
    with pytest.raises(HostUpgradeError, match="retain stopped"):
        switch._reload_systemd()
