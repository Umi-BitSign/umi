from __future__ import annotations

import fcntl
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from tests.test_competition_host_switch import hold, inputs, installed, switching
from umi import competition_host_start as start
from umi import competition_host_switch as switch
from umi import competition_host_upgrade as host
from umi import competition_switch_recovery as recovery
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    ValidatorSupervisorError,
    parse_canonical_supervisor_directive_state,
)

__all__ = ["inputs", "installed", "switching"]
_READ_DROP_IN = switch._read_drop_in
_WRITE_DROP_IN = switch._write_drop_in_once
_WRITE_CLEANUP = switch._write_cleanup_once
_READ_INTENT = recovery.read_switch_intent
_PUBLISH_INTENT = recovery.publish_switch_intent


def portable_noreplace(parent, source, destination, *, destination_parent=None):
    target = parent if destination_parent is None else destination_parent
    try:
        os.stat(destination, dir_fd=target, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(destination)
    os.rename(source, destination, src_dir_fd=parent, dst_dir_fd=target)


@pytest.fixture
def retained(switching, monkeypatch, tmp_path):
    case = switching
    root = case.plan.cleanup_unit_path.parent
    root.mkdir(mode=0o700)
    fragment = root / case.plan.unit_name
    fragment.write_bytes(b"[Service]\nExecStart=legacy-fixture\n")
    fragment.chmod(0o644)
    case.unit["FragmentPath"] = str(fragment)
    original = dict(case.unit)
    monkeypatch.setattr(host, "_check_unit", lambda *args: dict(original))
    case.anchor.config = case.installed.config
    case.anchor.anchor_path = tmp_path / "anchor"
    case.anchor.anchor_path.mkdir(mode=0o700)
    manifest = case.anchor.anchor_path / recovery.SIGNED_HOST_ARTIFACT_FILENAME
    manifest.write_bytes(b"{}")
    manifest.chmod(0o444)
    case.anchor.v3_state = parse_canonical_supervisor_directive_state(
        case.installed.state_path.read_bytes(), trust_policy=case.installed.config.trust_policy()
    )
    case.anchor.service_uid = os.geteuid()
    case.anchor.receipt.host_manifest_sha256 = case.plan.host_manifest_sha256
    case.anchor.receipt.host_umi_git_revision = "22" * 20
    case.tree.manifest_sha256 = case.plan.host_manifest_sha256
    with hold(case.installed) as stopped:
        case.anchor.receipt.source_config_sha256 = stopped.config_sha256
        case.anchor.receipt.legacy_installation_sha256 = stopped.installation_sha256
        case.payload = recovery._intent_bytes(stopped, case.anchor, case.plan)

    # Root/signature/anchor ports are covered in their own tests. This fixture
    # retains actual config/history files, lock contention, intent parsing,
    # partial preservation and exact systemd file comparison across calls.
    monkeypatch.setattr(recovery, "_require_root_linux", lambda: None)
    monkeypatch.setattr(recovery, "_root_owner_uid", os.geteuid)
    monkeypatch.setattr(recovery, "_SYSTEMD_ROOT", root)
    monkeypatch.setattr(recovery, "_UPGRADE_LOCK_ROOT", tmp_path / "upgrade-locks")
    monkeypatch.setattr(switch, "_root_directory", recovery._open_without_links)
    monkeypatch.setattr(switch, "_root_owner_uid", os.geteuid)
    monkeypatch.setattr(recovery, "_rename_noreplace", portable_noreplace)
    monkeypatch.setattr(switch, "_rename_noreplace", portable_noreplace)
    monkeypatch.setattr(recovery, "_unit_snapshot", switch._unit_snapshot)
    monkeypatch.setattr(recovery, "_require_empty_cgroup", switch._require_empty_cgroup)
    monkeypatch.setattr(recovery, "load_materialized_successor_anchor", lambda _: case.anchor)
    monkeypatch.setattr(recovery, "parse_signed_host_artifact", lambda _: None)
    monkeypatch.setattr(recovery, "verify_staged_host_tree", lambda *a, **kw: case.tree)
    monkeypatch.setattr(recovery, "_plan_from_anchor", lambda **kw: case.plan)
    monkeypatch.setattr(switch, "_read_drop_in", _READ_DROP_IN)
    monkeypatch.setattr(switch, "_write_drop_in_once", _WRITE_DROP_IN)
    monkeypatch.setattr(switch, "_write_cleanup_once", _WRITE_CLEANUP)
    monkeypatch.setattr(recovery, "read_switch_intent", _READ_INTENT)
    monkeypatch.setattr(recovery, "publish_switch_intent", _PUBLISH_INTENT)
    marker = recovery.publish_switch_intent(case.plan, case.payload)
    os.close(marker)
    return case


def resume(case):
    return recovery.resume_successor_service_publication(
        config_path=case.installed.config_path, unit_name=case.plan.unit_name
    )


@pytest.mark.parametrize("phase", ["intent", "cleanup", "drop_in", "reload", "partial"])
def test_resume_each_publication_boundary_retains_state_and_stays_stopped(retained, phase):
    case = retained
    marker = recovery._open_without_links(case.plan.drop_in_path.parent)
    try:
        if phase in {"cleanup", "drop_in", "reload"}:
            switch._write_cleanup_once(case.plan)
        if phase in {"drop_in", "reload"}:
            switch._write_drop_in_once(case.plan, marker)
        if phase == "reload":
            switch._reload_systemd()
        if phase == "partial":
            partial = case.plan.drop_in_path.parent / (".umi-successor-" + "ab" * 16)
            partial.write_bytes(b"interrupted bytes never interpreted")
            partial.chmod(0o600)
    finally:
        os.close(marker)
    before = case.installed.state_path.read_bytes()
    lock = case.installed.root / "state/supervisor-process.lock"
    inode, lock_bytes = lock.stat().st_ino, lock.read_bytes()
    # Retain an unrelated v4 journal. Recovery must neither restore nor edit it.
    successor_state = case.installed.root / "state/successor-v4"
    successor_state.mkdir(mode=0o700)
    journal = successor_state / "runtime-fixture"
    journal.write_bytes(b"newer accepted history must survive")
    for _ in range(2):
        result = resume(case)
        assert result["status"] == "source_switch_recovered"
        assert not result["service_started"] and not result["chain_submission_authorized"]
        assert case.unit["ActiveState"] == "inactive"
        assert case.installed.state_path.read_bytes() == before
        assert lock.stat().st_ino == inode and lock.read_bytes() == lock_bytes
        assert journal.read_bytes() == b"newer accepted history must survive"
        assert recovery.read_switch_intent(case.plan) == case.payload
    if phase == "partial":
        preserved = partial.parent / recovery.RETAINED_DIRECTORY / partial.name
        assert preserved.read_bytes() == b"interrupted bytes never interpreted"
        assert not partial.exists()


@pytest.mark.parametrize(
    "what", ["busy_lock", "replaced_lock", "history", "fragment", "anchor", "plan", "running"]
)
def test_recovery_rejects_mismatched_installation_before_publication(retained, what):
    case = retained
    lock = case.installed.root / "state/supervisor-process.lock"
    held = -1
    try:
        if what == "busy_lock":
            held = os.open(lock, os.O_RDONLY)
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif what == "replaced_lock":
            lock.rename(lock.with_suffix(".preserved"))
            lock.write_bytes(b"replacement")
            lock.chmod(0o600)
        elif what == "history":
            case.installed.state_path.write_bytes(b"{}")
        elif what == "fragment":
            Path(case.unit["FragmentPath"]).write_bytes(b"changed source")
        elif what == "anchor":
            case.anchor.receipt_sha256 = "99" * 32
        elif what == "plan":
            case.plan = replace(case.plan, drop_in_bytes=b"unverified command")
        else:
            case.unit.update(ActiveState="active", MainPID="123")
        with pytest.raises((ValueError, OSError, ValidatorSupervisorError)):
            resume(case)
        assert not case.plan.drop_in_path.exists()
        assert not case.plan.cleanup_unit_path.exists()
        assert "reload" not in case.events
    finally:
        if held >= 0:
            os.close(held)


def test_changed_final_file_is_never_overwritten(retained):
    case = retained
    case.plan.cleanup_unit_path.write_bytes(b"operator data")
    case.plan.cleanup_unit_path.chmod(0o444)
    with pytest.raises(ValueError, match="exact sealed"):
        resume(case)
    assert case.plan.cleanup_unit_path.read_bytes() == b"operator data"
    assert not case.plan.drop_in_path.exists()


@pytest.mark.parametrize("kind", ["link", "unknown", "fifo"])
def test_unrecognized_partial_is_preserved_and_holds(retained, kind):
    path = retained.plan.drop_in_path.parent / (".umi-successor-" + "cd" * 16)
    if kind == "link":
        path.symlink_to(retained.installed.config_path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path = path.with_name("unexpected.conf")
        path.write_bytes(b"unexpected")
    with pytest.raises(ValueError):
        resume(retained)
    assert path.lstat()
    assert not retained.plan.drop_in_path.exists()


def test_noncanonical_intent_and_other_unit_cannot_resume(retained):
    path = retained.plan.drop_in_path.parent / recovery.INTENT_FILENAME
    path.chmod(0o600)
    path.write_bytes(retained.payload + b"\n")
    path.chmod(0o444)
    with pytest.raises(ValueError, match="noncanonical"):
        resume(retained)
    with pytest.raises(ValueError, match="invalid recovery unit"):
        recovery.resume_successor_service_publication(
            config_path=retained.installed.config_path, unit_name="../other.service"
        )


def test_sealed_intent_precedes_fixed_marker_and_is_not_replaced(retained):
    case = retained
    assert recovery.read_switch_intent(case.plan) == case.payload
    assert set(p.name for p in case.plan.drop_in_path.parent.iterdir()) == {
        recovery.INTENT_FILENAME
    }
    with pytest.raises(FileExistsError):
        recovery.publish_switch_intent(case.plan, case.payload)
    assert recovery.read_switch_intent(case.plan) == case.payload
    assert not case.plan.cleanup_unit_path.exists()


def test_intent_is_bound_to_verified_service_plan(retained):
    intent = recovery._parse(retained.payload)
    altered = intent.model_copy(update={"plan_sha256": "ee" * 32})
    with pytest.raises(ValueError, match="differs"):
        recovery.publish_switch_intent(retained.plan, canonical_json_bytes(altered))


@pytest.fixture
def runtime(retained, monkeypatch):
    case = retained
    case.calls = []

    def systemctl(verb, unit):
        case.calls.append((verb, unit))
        if unit == case.plan.unit_name:
            case.unit.update(
                ActiveState="active" if verb == "start" else "inactive",
                SubState="running" if verb == "start" else "dead",
                MainPID="123" if verb == "start" else "0",
                ControlGroup="/system.slice/" + unit if verb == "start" else "",
            )

    def owns_lock(pid, handle):
        assert pid == 123 and type(handle) is recovery.RecoveredSuccessorServiceSwitch
        assert not hasattr(handle, "_stopped")
        _, lock_path, identity = start._installation(handle)
        descriptor = recovery._open_without_links(lock_path)
        try:
            # The upgrade process released its lock before starting the unit.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert recovery._fingerprint(os.fstat(descriptor)) == identity
        finally:
            os.close(descriptor)

    monkeypatch.setattr(start, "_systemctl", systemctl)
    monkeypatch.setattr(start, "_unit_snapshot", switch._unit_snapshot)
    monkeypatch.setattr(start, "_require_empty_cgroup", switch._require_empty_cgroup)
    monkeypatch.setattr(start, "_process_owns_lock", owns_lock)
    yield case
    for key, handle in list(start._STARTED.items()):
        if handle.plan is case.plan:
            start._STARTED.pop(key)
            recovery._RECOVERED.pop(key, None)


def test_recovered_switch_can_start_without_issuing_a_legacy_lease(runtime):
    old_history = runtime.installed.state_path.read_bytes()
    result = recovery.resume_and_start_successor_service(
        config_path=runtime.installed.config_path, unit_name=runtime.plan.unit_name
    )
    assert result["status"] == "successor_service_running" and result["main_pid"] == 123
    assert result["service_started"] and not result["chain_submission_authorized"]
    assert runtime.calls == [
        ("start", runtime.plan.required_user_manager),
        ("start", runtime.plan.unit_name),
    ]
    assert runtime.installed.state_path.read_bytes() == old_history


def test_recovered_start_failure_uses_exact_cleanup_and_preserves_history(runtime, monkeypatch):
    monkeypatch.setattr(start, "_running", lambda _: (_ for _ in ()).throw(ValueError("failure")))
    before = runtime.installed.state_path.read_bytes()
    with pytest.raises(ValueError, match="failure"):
        recovery.resume_and_start_successor_service(
            config_path=runtime.installed.config_path, unit_name=runtime.plan.unit_name
        )
    assert runtime.calls[-2:] == [
        ("stop", runtime.plan.unit_name),
        ("start", runtime.plan.cleanup_unit_name),
    ]
    assert runtime.unit["ActiveState"] == "inactive"
    assert runtime.installed.state_path.read_bytes() == before
    assert recovery.read_switch_intent(runtime.plan) == runtime.payload


def test_overlapping_recovery_cannot_clean_up_another_start(runtime, monkeypatch):
    original = start._systemctl

    def overlapping(verb, unit):
        if unit == runtime.plan.required_user_manager:
            # A second invocation opens the same mutex inode independently,
            # including the gap where neither writer holds the process lock.
            with pytest.raises(ValueError, match="another upgrade operation"):
                recovery.resume_and_start_successor_service(
                    config_path=runtime.installed.config_path, unit_name=runtime.plan.unit_name
                )
            with pytest.raises(ValueError, match="another upgrade operation"):
                resume(runtime)
        original(verb, unit)

    monkeypatch.setattr(start, "_systemctl", overlapping)
    result = recovery.resume_and_start_successor_service(
        config_path=runtime.installed.config_path, unit_name=runtime.plan.unit_name
    )
    assert result["service_started"]
    assert runtime.calls == [
        ("start", runtime.plan.required_user_manager),
        ("start", runtime.plan.unit_name),
    ]


def test_upgrade_mutex_is_per_unit_retained_and_released_on_failure(retained):
    unit = retained.plan.unit_name
    path = recovery._UPGRADE_LOCK_ROOT / (unit + ".lock")
    with (
        pytest.raises(RuntimeError, match="fixture interruption"),
        recovery.exclusive_upgrade_operation(unit),
    ):
        inode = path.stat().st_ino
        with recovery.exclusive_upgrade_operation("umi-validator-supervisor-other.service"):
            pass
        raise RuntimeError("fixture interruption")
    with recovery.exclusive_upgrade_operation(unit):
        assert path.stat().st_ino == inode and path.read_bytes() == b""


@pytest.mark.parametrize("change", ["symlink", "hardlink", "writable", "nonempty", "parent"])
def test_upgrade_mutex_refuses_unsafe_files_before_any_service_change(retained, change):
    unit = retained.plan.unit_name
    with recovery.exclusive_upgrade_operation(unit):
        pass
    path = recovery._UPGRADE_LOCK_ROOT / (unit + ".lock")
    if change == "symlink":
        saved = path.with_suffix(".original")
        path.rename(saved)
        path.symlink_to(saved)
    elif change == "hardlink":
        os.link(path, path.with_suffix(".linked"))
    elif change == "writable":
        path.chmod(0o666)
    elif change == "nonempty":
        path.write_bytes(b"not our mutex")
    else:
        path.parent.chmod(0o755)
    with pytest.raises((ValueError, OSError)):
        resume(retained)
    assert not retained.plan.drop_in_path.exists()


def test_upgrade_mutex_detects_replacement_without_deleting_retained_files(retained):
    unit = retained.plan.unit_name
    path = recovery._UPGRADE_LOCK_ROOT / (unit + ".lock")
    with (
        pytest.raises(ValueError, match="mutex changed"),
        recovery.exclusive_upgrade_operation(unit),
    ):
        saved = path.with_suffix(".original")
        path.rename(saved)
        path.touch(mode=0o600)
    assert saved.exists() and path.exists()


def test_recovered_start_handle_cannot_be_copied_or_mutated(runtime):
    handle = recovery.recover_successor_service_switch(
        config_path=runtime.installed.config_path, unit_name=runtime.plan.unit_name
    )
    try:
        with pytest.raises(ValueError, match="not recovered"):
            start.start_committed_successor_service(replace(handle))
        object.__setattr__(handle, "config_path", Path("/other/config"))
        with pytest.raises(ValueError, match="not recovered"):
            start.start_committed_successor_service(handle)
        assert not runtime.calls
    finally:
        recovery._RECOVERED.pop(id(handle), None)


def test_recovered_start_checks_changed_controls_after_user_manager(runtime, monkeypatch):
    def changed(verb, unit):
        runtime.calls.append((verb, unit))
        if unit == runtime.plan.required_user_manager:
            runtime.installed.state_path.write_bytes(b"changed history")

    monkeypatch.setattr(start, "_systemctl", changed)
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        recovery.resume_and_start_successor_service(
            config_path=runtime.installed.config_path, unit_name=runtime.plan.unit_name
        )
    assert ("start", runtime.plan.unit_name) not in runtime.calls


@pytest.mark.parametrize("command", ["resume-publication", "resume-start"])
def test_cli_selects_explicit_recovery_operation_without_printing_private_errors(
    command, monkeypatch, capsys
):
    name = (
        "resume_and_start_successor_service"
        if command == "resume-start"
        else "resume_successor_service_publication"
    )
    calls = []

    def operation(**kwargs):
        calls.append(kwargs)
        return {"status": "fixture_ok", "chain_submission_authorized": False}

    monkeypatch.setattr(recovery, name, operation)
    args = [command, "--config", "/private/config", "--unit", "umi-validator-supervisor.service"]
    assert recovery.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "fixture_ok"
    assert calls == [{"config_path": Path("/private/config"), "unit_name": args[-1]}]

    def fail(**kwargs):
        raise OSError("private-content-must-not-be-printed")

    monkeypatch.setattr(recovery, name, fail)
    assert recovery.main(args) == 1
    output = capsys.readouterr().out
    assert "private-content" not in output
    assert json.loads(output)["reason_code"] == "host_switch_recovery_failed"
    assert json.loads(output)["service_state"] == (
        "unconfirmed" if command == "resume-start" else "unchanged"
    )
    assert json.loads(output)["service_started"] is (None if command == "resume-start" else False)


def test_repeated_failed_intent_stages_are_bounded(retained, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("interrupted before publication")

    monkeypatch.setattr(recovery, "_rename_noreplace", fail)
    for _ in range(8):
        with pytest.raises(OSError, match="interrupted"):
            recovery.publish_switch_intent(retained.plan, retained.payload)
    with pytest.raises(ValueError, match="staging slots exhausted"):
        recovery.publish_switch_intent(retained.plan, retained.payload)
    assert recovery.read_switch_intent(retained.plan) == retained.payload
