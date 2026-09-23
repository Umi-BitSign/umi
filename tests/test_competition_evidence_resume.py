"""Recovery through retained files; native host/OS observation ports are fixtures."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_evidence_resume as resume
from umi import competition_evidence_service as service
from umi.competition_upgrade import _Reader
from umi.protocol import canonical_json_bytes

from .test_competition_evidence_service import publish, selected

__all__ = ["selected"]


@pytest.fixture
def ready(selected, monkeypatch):
    c = selected
    r = c.runtime
    r.unit_name = c.unit
    old_guard, guard_bytes = service.evidence_service_guard(c.unit, c.root)
    drop_directory = r.drop_in_path.parent / (c.unit + ".d")
    drop_directory.mkdir()
    guard = old_guard.rename(drop_directory / old_guard.name)
    r.drop_in_path = r.drop_in_path.rename(drop_directory / r.drop_in_path.name)
    monkeypatch.setattr(service, "evidence_service_guard", lambda *_: (guard, guard_bytes))
    c.calls = []
    c.owned_fd = None
    c.reload_failure = False
    config_root = c.root.parent
    original_lock = config_root / "process.lock"
    original_lock.rename(config_root / "supervisor-process.lock")
    original_identity = c.lease.runtime_identity

    def identity():
        # The fixture lease records the already existing original process lock.
        values = c.identity.copy()
        return values

    # Capture identity through the fixture's old path before selecting its name.
    original_lock.symlink_to(config_root / "supervisor-process.lock")
    c.identity = original_identity()
    c.identity["lock_path"] = str(config_root / "supervisor-process.lock")
    original_lock.unlink()
    monkeypatch.setattr(c.lease, "runtime_identity", identity)
    r.service_uid = os.getuid()
    r.service_user = "fixture"
    r.required_user_manager = f"user@{os.getuid()}.service"
    r.cleanup_unit_name = c.unit.removesuffix(".service") + "-successor-cleanup.service"
    c.command = (
        "/usr/bin/env -i /opt/fixture/.venv/bin/umi-competition-supervisor"
        " --config /etc/fixture.json"
    )
    r.drop_in_bytes = ("[Service]\nExecStart=\nExecStart=" + c.command + "\n").encode()
    c.anchor.config = SimpleNamespace(state_root=str(config_root))
    c.anchor.receipt_sha256 = c.plan.candidate_receipt_sha256
    c.anchor.receipt = SimpleNamespace(
        evidence_migration=SimpleNamespace(compatibility_sha256=c.plan.compatibility_sha256),
        host_manifest_sha256=r.host_manifest_sha256,
        host_umi_git_revision="fixture",
    )
    c.anchor.anchor_path = config_root / "sealed-anchor"
    c.anchor.anchor_path.mkdir()
    signed = c.anchor.anchor_path / "signed-host-artifact.json"
    signed.write_bytes(b"fixture signed host")
    signed.chmod(0o444)
    (c.root / "activation-plan.json").write_bytes(c.plan.encoded())
    (c.root / "activation-plan.json").chmod(0o600)
    publish(c)
    guard, _ = service.evidence_service_guard(c.unit, c.root)
    c.unit_state = {
        "Id": c.unit,
        "LoadState": "loaded",
        "User": "fixture",
        "FragmentPath": c.identity["fragment_path"],
        "DropInPaths": f"{guard} {r.drop_in_path}",
        "OnFailure": r.cleanup_unit_name,
        "ExecStart": "{ path=/usr/bin/env ; argv[]="
        + c.command
        + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
        " ; pid=0 ; code=(null) ; status=0/0 }",
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ControlPID": "0",
        "ControlGroup": "",
    }
    for name, value in (
        ("_Reader", lambda _: _Reader(os.getuid())),
        ("load_materialized_successor_anchor", lambda _: c.anchor),
        ("parse_signed_host_artifact", lambda _: None),
        ("verify_staged_host_tree", lambda *a, **k: c.tree),
        ("_plan_from_anchor", lambda **k: r),
        ("_receipt", lambda _: (None, c.plan.original_receipt_sha256)),
        ("_service_layout", lambda _: SimpleNamespace(fragment=Path(c.identity["fragment_path"]))),
        ("_root_directory", service._root_directory),
        ("evidence_service_guard", service.evidence_service_guard),
        ("_loaded_conditions", service._loaded_conditions),
        ("_unit_snapshot", lambda _: c.unit_state.copy()),
        ("_check_service_namespace", lambda *a: None),
        ("_expected_cgroup", lambda unit: "/umi.slice/umi-validators.slice/" + unit),
        ("_require_empty_cgroup", lambda *a: None),
        ("_cleanup_unit", lambda *a: c.calls.append("cleanup_checked")),
    ):
        monkeypatch.setattr(resume, name, value)

    def reload():
        c.calls.append("reload")
        if c.reload_failure:
            c.unit_state["ExecStart"] = "foreign command"

    monkeypatch.setattr(resume, "_reload_systemd", reload)

    def command(verb, unit, timeout):
        c.calls.append((verb, unit))
        if unit != c.unit:
            return
        if verb == "start":
            assert (c.root / "service-start.json").is_file()
            assert not (c.root / "HOLD").exists()
            c.owned_fd = os.open(c.identity["lock_path"], os.O_RDONLY)
            fcntl.flock(c.owned_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            c.unit_state.update(
                ActiveState="active",
                SubState="running",
                MainPID="1442",
                ControlGroup=resume._expected_cgroup(c.unit),
            )
        elif verb == "stop":
            if c.owned_fd is not None:
                os.close(c.owned_fd)
                c.owned_fd = None
            c.unit_state.update(
                ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup=""
            )

    monkeypatch.setattr(resume, "_service_command", command)

    def owns(pid, *, lock_path, lock_identity, service_uid):
        assert pid == 1442 and c.owned_fd is not None
        info = os.fstat(c.owned_fd)
        assert lock_identity == (info.st_dev, info.st_ino)
        assert str(lock_path) == c.identity["lock_path"] and service_uid == os.getuid()

    monkeypatch.setattr(resume, "_process_owns_exact_lock", owns)
    yield c
    if c.owned_fd is not None:
        os.close(c.owned_fd)


def run(c):
    return resume._resume(resume._load(c.args["config_path"], c.unit, c.root), 600)


def test_start_and_restart_recovery_preserve_original_lock_and_do_not_repeat_start(ready):
    first = run(ready)
    assert first["service_started"] and not first["chain_submission_authorized"]
    assert run(ready) == first
    assert ready.calls.count(("start", ready.unit)) == 1
    assert (ready.root / "HOLD.released").is_file()
    assert (ready.root / "original-supervisor.conf").read_bytes() == ready.old


@pytest.mark.parametrize(
    "boundary", ["service-start.json", "hold_release", "service-start-complete.json"]
)
def test_resume_after_durable_interruption_does_not_need_old_live_capability(
    ready, monkeypatch, boundary
):
    write, move = resume._write_control, resume._move_hold

    def interrupted(fd, name, raw):
        write(fd, name, raw)
        if name == boundary:
            raise RuntimeError("controller lost")

    def moved(selection, *, release):
        move(selection, release=release)
        if release and boundary == "hold_release":
            raise RuntimeError("controller lost")

    monkeypatch.setattr(resume, "_write_control", interrupted)
    monkeypatch.setattr(resume, "_move_hold", moved)
    with pytest.raises(RuntimeError, match="controller lost"):
        run(ready)
    monkeypatch.setattr(resume, "_write_control", write)
    monkeypatch.setattr(resume, "_move_hold", move)
    assert run(ready)["service_started"]
    assert ready.calls.count(("start", ready.unit)) == 1


@pytest.mark.parametrize(
    "record", ["service-selection.json", "service-publication.json", "activation-complete.json"]
)
def test_changed_record_never_releases_hold_or_starts_service(ready, record):
    p = ready.root / record
    d = json.loads(p.read_bytes())
    d["injected"] = True
    p.write_bytes(canonical_json_bytes(d))
    with pytest.raises(ValueError):
        run(ready)
    assert (ready.root / "HOLD").is_file()
    assert not ready.calls


@pytest.mark.parametrize(
    "fault", ["replaced_lock", "busy_lock", "changed_fragment", "foreign_loaded_command"]
)
def test_unsafe_or_unavailable_runtime_is_rejected_before_hold_release(ready, fault):
    fd = None
    p = Path(ready.identity["lock_path"])
    if fault == "replaced_lock":
        p.rename(p.with_name("retained-old-lock"))
        p.touch(mode=0o600)
    elif fault == "busy_lock":
        fd = os.open(p, os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    elif fault == "changed_fragment":
        fragment = Path(ready.identity["fragment_path"])
        fragment.chmod(0o644)
        fragment.write_bytes(b"changed unit")
    else:
        ready.reload_failure = True
    try:
        with pytest.raises((ValueError, OSError)):
            run(ready)
    finally:
        if fd is not None:
            os.close(fd)
    assert (ready.root / "HOLD").is_file()
    assert ("start", ready.unit) not in ready.calls


def test_failed_start_restores_hold_and_runs_owned_cleanup(ready, monkeypatch):
    running = resume._running
    monkeypatch.setattr(
        resume, "_running", lambda _: (_ for _ in ()).throw(ValueError("bad startup"))
    )
    with pytest.raises(ValueError, match="bad startup"):
        run(ready)
    assert (ready.root / "HOLD").is_file()
    assert ready.unit_state["MainPID"] == "0"
    assert ("start", ready.runtime.cleanup_unit_name) in ready.calls
    monkeypatch.setattr(resume, "_running", running)
    assert run(ready)["service_started"]


def test_lost_completion_record_recovers_running_process_without_stopping_it(ready):
    run(ready)
    (ready.root / "service-start-complete.json").unlink()
    ready.calls.clear()
    assert run(ready)["main_pid"] == 1442
    assert all(not isinstance(c, tuple) for c in ready.calls)


def test_released_hold_without_exact_start_intent_is_not_authority(ready):
    (ready.root / "HOLD").rename(ready.root / "HOLD.released")
    with pytest.raises(FileNotFoundError):
        run(ready)
    assert not ready.calls


@pytest.mark.parametrize("fault", ["extra_dropin", "unloaded_guard", "missing_hold", "both_holds"])
def test_incomplete_service_fencing_refuses_start(ready, fault):
    if fault == "extra_dropin":
        (ready.runtime.drop_in_path.parent / "99-foreign.conf").write_bytes(b"foreign")
    elif fault == "unloaded_guard":
        ready.conditions.clear()
    elif fault == "missing_hold":
        (ready.root / "HOLD").unlink()
    else:
        p = ready.root / "HOLD.released"
        p.write_bytes((ready.root / "HOLD").read_bytes())
        p.chmod(0o444)
    with pytest.raises(ValueError):
        run(ready)
    assert ("start", ready.unit) not in ready.calls


def test_failed_stop_can_reconcile_the_verified_running_process_on_retry(ready, monkeypatch):
    running, command = resume._running, resume._service_command
    monkeypatch.setattr(
        resume, "_running", lambda _: (_ for _ in ()).throw(ValueError("observation lost"))
    )

    def failed_stop(verb, unit, timeout):
        if verb == "stop":
            raise OSError("stop unconfirmed")
        command(verb, unit, timeout)

    monkeypatch.setattr(resume, "_service_command", failed_stop)
    with pytest.raises(OSError, match="stop unconfirmed"):
        run(ready)
    assert (ready.root / "HOLD").exists() and ready.unit_state["MainPID"] == "1442"
    monkeypatch.setattr(resume, "_running", running)
    monkeypatch.setattr(resume, "_service_command", command)
    assert run(ready)["main_pid"] == 1442
    assert ready.calls.count(("start", ready.unit)) == 1


def test_resume_wrapper_serializes_load_and_start_inside_exact_host_view(ready, monkeypatch):
    from contextlib import contextmanager

    held = []
    events = []

    @contextmanager
    def mutex(unit):
        assert unit == ready.unit and events == ["namespace"]
        held.append(True)
        try:
            yield
        finally:
            held.pop()

    load, operation = resume._load, resume._resume

    def locked_load(*args):
        assert held
        return load(*args)

    def locked_start(*args):
        assert held
        return operation(*args)

    monkeypatch.setattr(resume, "_require_root_linux", lambda: None)
    monkeypatch.setattr(
        resume, "ensure_coordinator_host_view", lambda **_: events.append("namespace")
    )
    monkeypatch.setattr(resume, "exclusive_upgrade_operation", mutex)
    monkeypatch.setattr(resume, "_load", locked_load)
    monkeypatch.setattr(resume, "_resume", locked_start)
    assert resume.resume_selected_evidence_service(
        config_path=ready.args["config_path"], unit_name=ready.unit, transaction_root=ready.root
    )["service_started"]
    assert not held
