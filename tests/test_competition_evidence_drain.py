"""Persistent drain ordering with real controls/locks and explicit native/OS ports.

Cryptographic eligibility and Linux process identity are covered in their native
suites. These cases exercise the composed filesystem and service failure paths.
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from umi import competition_evidence_activation as activation
from umi import competition_evidence_drain as drain
from umi import competition_evidence_service as service
from umi.competition_upgrade import _Reader


class Config(BaseModel):
    state_root: str
    target_platform: str = "linux/amd64"


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "transaction"
    root.mkdir(mode=0o700)
    controls = tmp_path / "systemd"
    controls.mkdir()
    dropins = controls / "umi-validator@54.service.d"
    dropins.mkdir()
    unit = "umi-validator@54.service"
    fragment = controls / unit
    fragment.write_bytes(b"original fragment\n")
    fragment.chmod(0o444)
    guard = dropins / "40-umi-evidence-hold.conf"
    guard_body = b"[Unit]\nConditionPathExists=!" + os.fsencode(root / "HOLD") + b"\n"
    dropin = dropins / "50-umi-successor.conf"
    cleanup = controls / "cleanup.service"
    command = (
        "/usr/bin/env -i /opt/old/.venv/bin/umi-competition-supervisor --config /etc/miner.json"
    )
    drop_body = ("[Service]\nExecStart=\nExecStart=" + command + "\n").encode()
    for path, raw in ((dropin, drop_body), (cleanup, b"original cleanup\n")):
        path.write_bytes(raw)
        path.chmod(0o444)
    anchor_dir = tmp_path / "anchor"
    anchor_dir.mkdir()
    signed = anchor_dir / "signed-host-artifact.json"
    signed.write_bytes(b"fixture manifest")
    signed.chmod(0o444)
    config = Config(state_root=str(tmp_path))
    anchor = SimpleNamespace(
        config=config,
        anchor_path=anchor_dir,
        receipt_sha256="ab" * 32,
        operator_consent=object(),
        recheck=lambda: None,
        observer_config=SimpleNamespace(chain=object()),
        receipt=SimpleNamespace(
            evidence_migration=None, host_manifest_sha256="aa" * 32, host_umi_git_revision="fixture"
        ),
    )
    runtime = SimpleNamespace(
        unit_name=unit,
        service_uid=os.getuid(),
        service_user="fixture",
        drop_in_path=dropin,
        drop_in_bytes=drop_body,
        cleanup_unit_path=cleanup,
        cleanup_unit_bytes=b"original cleanup\n",
        cleanup_unit_name="umi-validator@54-successor-cleanup.service",
    )
    request = drain.EvidenceDrainRequest(tmp_path / "config.json", unit, root, "cd" * 32)
    lock = tmp_path / "supervisor-process.lock"
    lock.touch(mode=0o600)
    lock_fd = os.open(lock, os.O_RDONLY)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state = {
        "Id": unit,
        "LoadState": "loaded",
        "User": "fixture",
        "FragmentPath": str(fragment),
        "DropInPaths": str(dropin),
        "OnFailure": runtime.cleanup_unit_name,
        "ExecStart": "{ path=/usr/bin/env ; argv[]="
        + command
        + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
        " ; pid=1234 ; code=(null) ; status=0/0 }",
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": "1234",
        "ControlPID": "0",
        "ControlGroup": "/system.slice/" + unit,
    }
    c = SimpleNamespace(
        root=root,
        controls=controls,
        guard=guard,
        fragment=fragment,
        guard_body=guard_body,
        runtime=runtime,
        request=request,
        anchor=anchor,
        config=config,
        lock=lock,
        lock_fd=lock_fd,
        state=state,
        calls=[],
        conditions=[],
        fail=None,
        fresh=True,
        permit=True,
        consent=SimpleNamespace(history_compatibility=object()),
    )

    def directory(path):
        assert Path(path).resolve() == path and Path(path).is_relative_to(tmp_path)
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    class Eligible:
        def recheck(self, **kw):
            assert kw["config"] is config and kw["consent"] is c.consent
            if not c.permit:
                raise ValueError("replacement proof no longer eligible")

    c.eligible = Eligible()

    class TargetTree:
        manifest_sha256 = "cd" * 32
        umi_git_revision = "target"
        target_platform = "linux/amd64"

        def recheck(self):
            if c.fail == "target_tree":
                raise ValueError("target tree changed")

    c.target_tree = TargetTree()
    c.target_signed = SimpleNamespace(manifest=SimpleNamespace(umi_git_revision="target"))
    for module, name, value in (
        (drain, "VerifiedHostTree", TargetTree),
        (drain, "verify_host_artifact_authority", lambda *a, **k: None),
        (drain, "validate_host_service_resources", lambda *a: None),
        (drain, "EligibleEvidenceRollover", Eligible),
        (drain, "load_materialized_successor_anchor", lambda _: anchor),
        (
            drain,
            "verify_history_compatibility",
            lambda *a, **k: SimpleNamespace(
                original_installation_receipt_sha256=anchor.receipt_sha256,
                target_host_manifest_sha256="cd" * 32,
            ),
        ),
        (drain, "validate_consent_transition", lambda *a: None),
        (drain, "_Reader", lambda _: _Reader(os.getuid())),
        (drain, "parse_signed_host_artifact", lambda _: None),
        (drain, "verify_staged_host_tree", lambda *a, **k: SimpleNamespace(recheck=lambda: None)),
        (drain, "_plan_from_anchor", lambda **k: runtime),
        (drain, "_root_directory", directory),
        (drain, "_check_service_namespace", lambda *a: SimpleNamespace(fragment=fragment)),
        (drain, "_unit_snapshot", lambda _: state.copy()),
        (drain, "_expected_cgroup", lambda _: "/system.slice/" + unit),
        (drain, "_cleanup_unit", lambda *a: c.calls.append("cleanup_checked")),
        (drain, "evidence_service_guard", lambda *a: (guard, guard_body)),
        (service, "evidence_service_guard", lambda *a: (guard, guard_body)),
        (service, "_loaded_conditions", lambda _: c.conditions),
        (activation, "_root_owner_uid", os.getuid),
    ):
        monkeypatch.setattr(module, name, value)

    def owns(pid, **kw):
        assert pid == 1234 and c.lock_fd is not None
        assert kw["lock_identity"] == (lock.stat().st_dev, lock.stat().st_ino)

    def reload():
        assert (root / "drain-plan.json").is_file()
        assert (root / "HOLD").is_file()
        assert guard.read_bytes() == guard_body
        c.calls.append("reload")
        state["DropInPaths"] = f"{guard} {dropin}"
        if c.fail == "reload":
            raise RuntimeError("reload lost")
        c.conditions[:] = [["ConditionPathExists", False, True, str(root / "HOLD"), 0]]

    def stopped(*a):
        if state["MainPID"] != "0" or c.lock_fd is not None:
            raise ValueError("supervisor remains running")

    def service_command(verb, name, timeout):
        assert (root / "HOLD").is_file() and c.conditions
        c.calls.append((verb, name))
        if name == unit:
            assert verb == "stop"
            if c.fail == "stop":
                raise TimeoutError("stop incomplete")
            if c.lock_fd is not None:
                os.close(c.lock_fd)
                c.lock_fd = None
            state.update(ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup="")
        else:
            assert name == runtime.cleanup_unit_name and verb == "start"
            if c.fail == "cleanup":
                raise RuntimeError("cleanup incomplete")

    async def observe():
        return SimpleNamespace(captured_monotonic_ns=time.monotonic_ns() if c.fresh else 0)

    c.observe = observe
    monkeypatch.setattr(drain, "_process_owns_exact_lock", owns)
    monkeypatch.setattr(drain, "_reload_systemd", reload)
    monkeypatch.setattr(drain, "_stopped_unit", stopped)
    monkeypatch.setattr(drain, "_service_command", service_command)
    yield c
    if c.lock_fd is not None:
        os.close(c.lock_fd)


def run(c):
    return asyncio.run(
        drain._drain_locked(
            c.request,
            consent=c.consent,
            eligible_replacement=c.eligible,
            target_host_tree=c.target_tree,
            target_signed_host=c.target_signed,
            observe_after_audit=c.observe,
            timeout_seconds=600,
        )
    )


def test_drain_and_repeat_preserve_original_controls_and_hold(case):
    c = case
    first = run(c)
    assert first["service_stopped"] and not first["hold_released"]
    assert run(c) == first
    assert c.runtime.drop_in_path.read_bytes() == c.runtime.drop_in_bytes
    assert c.runtime.cleanup_unit_path.read_bytes() == c.runtime.cleanup_unit_bytes
    assert c.lock_fd is None
    assert ("start", c.request.unit_name) not in c.calls


@pytest.mark.parametrize("boundary", ["drain-plan.json", "HOLD", "guard", "drain-complete.json"])
def test_interrupted_controller_resumes_same_drain(case, monkeypatch, boundary):
    write, seal = drain._write_control, drain._seal_control

    def interrupted(fd, name, raw):
        write(fd, name, raw)
        if name == boundary:
            raise RuntimeError("controller lost")

    def sealed(path, raw):
        seal(path, raw)
        if path.name == boundary or (path == case.guard and boundary == "guard"):
            raise RuntimeError("controller lost")

    monkeypatch.setattr(drain, "_write_control", interrupted)
    monkeypatch.setattr(drain, "_seal_control", sealed)
    with pytest.raises(RuntimeError, match="controller lost"):
        run(case)
    monkeypatch.setattr(drain, "_write_control", write)
    monkeypatch.setattr(drain, "_seal_control", seal)
    assert run(case)["service_stopped"]


@pytest.mark.parametrize("failure", ["reload", "stop", "cleanup"])
def test_service_failure_preserves_hold_and_retries_without_starting(case, failure):
    case.fail = failure
    with pytest.raises((RuntimeError, TimeoutError)):
        run(case)
    assert (case.root / "HOLD").is_file()
    assert not (case.root / "drain-complete.json").exists()
    case.fail = None
    assert run(case)["service_stopped"]
    assert ("start", case.request.unit_name) not in case.calls


@pytest.mark.parametrize(
    "failure", ["missing", "ineligible", "stale", "wrong_target", "target_tree"]
)
def test_unready_replacement_does_not_change_or_stop_service(case, failure):
    if failure == "missing":
        case.eligible = None
    elif failure == "ineligible":
        case.permit = False
    elif failure == "stale":
        case.fresh = False
    elif failure == "wrong_target":
        case.request = replace(case.request, target_host_manifest_sha256="ff" * 32)
    else:
        case.fail = failure
    with pytest.raises(ValueError):
        run(case)
    assert not list(case.root.iterdir())
    assert case.lock_fd is not None and ("stop", case.request.unit_name) not in case.calls


@pytest.mark.parametrize("fault", ["override", "loaded_command", "fragment", "lock", "later_phase"])
def test_changed_or_advanced_transaction_is_not_redrained(case, fault):
    run(case)
    if fault == "override":
        (case.runtime.drop_in_path.parent / "99-foreign.conf").write_bytes(b"foreign")
    elif fault == "loaded_command":
        case.state["ExecStart"] = "foreign"
    elif fault == "fragment":
        case.fragment.chmod(0o600)
        case.fragment.write_bytes(b"changed fragment")
    elif fault == "lock":
        case.lock.rename(case.lock.with_name("retained-lock"))
        case.lock.touch(mode=0o600)
    else:
        (case.root / "service-start.json").write_bytes(b"later transaction")
    case.calls.clear()
    with pytest.raises(ValueError):
        run(case)
    assert ("stop", case.request.unit_name) not in case.calls


@pytest.mark.parametrize("state", ["private_final", "partial_pending"])
def test_interrupted_hold_write_is_finished_before_service_changes(case, state):
    body = service.evidence_service_hold(
        case.request.unit_name, case.request.target_host_manifest_sha256
    )
    p = case.root / ("HOLD" if state == "private_final" else ".HOLD.pending")
    p.write_bytes(body if state == "private_final" else body[:17])
    p.chmod(0o600)
    assert run(case)["service_stopped"]
    assert (case.root / "HOLD").read_bytes() == body
    assert (case.root / "HOLD").stat().st_mode & 0o777 == 0o444
