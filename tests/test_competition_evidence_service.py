"""Durable runtime selection with OS/capability shims and real file operations.

These tests do not exercise a real systemd unit or mint a native stopped lease.
They cover exact-byte controls, persistent holds and interrupted file publication.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_evidence_activation as activation
from umi import competition_evidence_service as service
from umi.competition_evidence_activation import EvidenceActivationPlan
from umi.protocol import canonical_json_bytes


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def selected(tmp_path, monkeypatch):
    root = tmp_path / "transaction"
    root.mkdir(mode=0o700)
    controls = tmp_path / "systemd"
    controls.mkdir()
    unit = "umi-validator@54.service"
    guard = controls / "40-umi-evidence-hold.conf"
    dropin, cleanup = controls / "50-umi-successor.conf", controls / "cleanup.service"
    old, new = b"old supervisor\n", b"new supervisor\n"
    old_cleanup, new_cleanup = b"old cleanup\n", b"new cleanup\n"
    host_sha = "ab" * 32
    for path, raw in (
        (dropin, old),
        (cleanup, old_cleanup),
        (guard, b"fixture guard\n"),
        (root / "HOLD", service.evidence_service_hold(unit, host_sha)),
    ):
        path.write_bytes(raw)
        path.chmod(0o444)
    plan = EvidenceActivationPlan(
        tmp_path / "live", tmp_path / "prepared", root, "ac" * 32, "ad" * 32, "ae" * 32
    )
    complete = {
        "schema": "umi-weight-evidence-activation/1",
        "plan_sha256": sha(plan.encoded()),
        "selected_receipt_sha256": plan.candidate_receipt_sha256,
        "retained_original_receipt_sha256": plan.original_receipt_sha256,
        "chain_submission_authorized": False,
        "service_started": False,
    }
    (root / "activation-complete.json").write_bytes(canonical_json_bytes(complete))
    (root / "activation-complete.json").chmod(0o600)
    anchor = SimpleNamespace(
        source_root=plan.live_source, receipt=object(), config=object(), recheck=lambda: None
    )

    class Tree:
        def recheck(self):
            pass

    class Lease:
        _unit = unit
        failure = False

        def validate_scope(self, requested, config):
            assert requested == plan and config is anchor.config
            if self.failure:
                raise ValueError("stopped lease lost")

    runtime = SimpleNamespace(
        host_manifest_sha256=host_sha,
        drop_in_path=dropin,
        drop_in_bytes=new,
        cleanup_unit_path=cleanup,
        cleanup_unit_bytes=new_cleanup,
    )
    monkeypatch.setattr(service, "_root_linux", lambda: None)
    monkeypatch.setattr(service, "StoppedEvidenceMigration", Lease)
    monkeypatch.setattr(service, "VerifiedHostTree", Tree)
    monkeypatch.setattr(service, "load_materialized_successor_anchor", lambda _: anchor)
    monkeypatch.setattr(
        service, "_receipt", lambda _: (anchor.receipt, plan.candidate_receipt_sha256)
    )
    monkeypatch.setattr(service, "_plan_from_anchor", lambda **_: runtime)
    monkeypatch.setattr(service, "_root_owner_uid", os.getuid)
    monkeypatch.setattr(activation, "_root_owner_uid", os.getuid)

    def directory(path):
        assert Path(path).resolve() == path and Path(path).is_relative_to(tmp_path)
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(service, "_root_directory", directory)
    monkeypatch.setattr(service, "evidence_service_guard", lambda *_: (guard, b"fixture guard\n"))
    conditions = [["ConditionPathExists", False, True, str(root / "HOLD"), 0]]
    monkeypatch.setattr(service, "_loaded_conditions", lambda _: conditions)
    return SimpleNamespace(
        root=root,
        plan=plan,
        anchor=anchor,
        runtime=runtime,
        lease=Lease(),
        tree=Tree(),
        unit=unit,
        old=old,
        old_cleanup=old_cleanup,
        conditions=conditions,
        args=dict(config_path=tmp_path / "config.json", unit_name=unit, signed_host=None),
    )


def publish(c):
    return service.publish_stopped_evidence_service(
        c.plan, verified_host_tree=c.tree, lease=c.lease, **c.args
    )


def test_runtime_controls_preserve_originals_and_leave_service_held(selected):
    c = selected
    first = publish(c)
    assert publish(c) == first
    assert c.runtime.drop_in_path.read_bytes() == c.runtime.drop_in_bytes
    assert c.runtime.cleanup_unit_path.read_bytes() == c.runtime.cleanup_unit_bytes
    assert (c.root / "original-supervisor.conf").read_bytes() == c.old
    assert (c.root / "original-cleanup.service").read_bytes() == c.old_cleanup
    assert (c.root / "HOLD").is_file()
    assert first["service_started"] is first["hold_released"] is False


@pytest.mark.parametrize(
    "field",
    [
        "missing_hold",
        "unloaded_guard",
        "changed_host",
        "incomplete_exchange",
        "wrong_unit",
        "lost_lease",
    ],
)
def test_publication_refuses_incomplete_or_changed_migration(selected, field):
    c = selected
    if field == "missing_hold":
        (c.root / "HOLD").unlink()
    elif field == "unloaded_guard":
        c.conditions.clear()
    elif field == "changed_host":
        c.runtime.host_manifest_sha256 = "ff" * 32
    elif field == "incomplete_exchange":
        (c.root / "activation-complete.json").unlink()
    elif field == "wrong_unit":
        c.args["unit_name"] = "umi-validator@0.service"
    else:
        c.lease.failure = True
    with pytest.raises((ValueError, FileNotFoundError)):
        publish(c)
    assert c.runtime.drop_in_path.read_bytes() == c.old
    assert c.runtime.cleanup_unit_path.read_bytes() == c.old_cleanup


@pytest.mark.parametrize(
    "boundary", ["service-selection.json", "after_first_control", "service-publication.json"]
)
def test_crash_retries_exact_target_without_replacing_original_backups(
    selected, monkeypatch, boundary
):
    c = selected
    writer, replace = service._write_control, service._replace_control

    def interrupt_write(fd, name, raw):
        writer(fd, name, raw)
        if name == boundary:
            raise RuntimeError("controller killed")

    def interrupt_replace(path, **kwargs):
        replace(path, **kwargs)
        if boundary == "after_first_control" and path == c.runtime.drop_in_path:
            raise RuntimeError("controller killed")

    monkeypatch.setattr(service, "_write_control", interrupt_write)
    monkeypatch.setattr(service, "_replace_control", interrupt_replace)
    with pytest.raises(RuntimeError, match="controller killed"):
        publish(c)
    assert (c.root / "HOLD").is_file()
    assert (c.root / "original-supervisor.conf").read_bytes() == c.old
    assert (c.root / "original-cleanup.service").read_bytes() == c.old_cleanup
    monkeypatch.setattr(service, "_write_control", writer)
    monkeypatch.setattr(service, "_replace_control", replace)
    publish(c)
    assert c.runtime.drop_in_path.read_bytes() == c.runtime.drop_in_bytes
    assert c.runtime.cleanup_unit_path.read_bytes() == c.runtime.cleanup_unit_bytes
    assert (c.root / "original-supervisor.conf").read_bytes() == c.old


def test_resume_rejects_different_runtime_and_preserves_hold(selected):
    c = selected
    publish(c)
    c.runtime.drop_in_bytes = b"unapproved replacement\n"
    with pytest.raises(ValueError, match="control changed"):
        publish(c)
    assert c.runtime.drop_in_path.read_bytes() == b"new supervisor\n"
    assert (c.root / "HOLD").is_file()


@pytest.mark.parametrize("matching", [True, False])
def test_interrupted_temporary_control_must_match_exact_target(selected, matching):
    c = selected
    path = c.runtime.drop_in_path
    pending = path.with_name("." + path.name + ".evidence-pending")
    pending.write_bytes(c.runtime.drop_in_bytes[:5] if matching else b"foreign")
    pending.chmod(0o600)
    if matching:
        service._replace_control(path, old_sha256=sha(c.old), new=c.runtime.drop_in_bytes)
        assert path.read_bytes() == c.runtime.drop_in_bytes
        assert not pending.exists()
    else:
        with pytest.raises(ValueError, match="interrupted evidence service control differs"):
            service._replace_control(path, old_sha256=sha(c.old), new=c.runtime.drop_in_bytes)
        assert path.read_bytes() == c.old
        assert pending.read_bytes() == b"foreign"


@pytest.mark.parametrize("unsafe", ["changed_bytes", "hardlink", "symlink", "writable"])
def test_control_replacement_rejects_changed_or_unsafe_original(selected, unsafe):
    c = selected
    p = c.runtime.drop_in_path
    if unsafe == "changed_bytes":
        p.chmod(0o644)
        p.write_bytes(b"unexpected\n")
        p.chmod(0o444)
    elif unsafe == "hardlink":
        os.link(p, p.with_name("alias"))
    elif unsafe == "symlink":
        old = p.with_name("original")
        p.rename(old)
        p.symlink_to(old)
    else:
        p.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        service._replace_control(p, old_sha256=sha(c.old), new=c.runtime.drop_in_bytes)


@pytest.mark.parametrize(
    "root", ["/run/migration", "/tmp/migration", "/var/tmp/migration", "/var/lib/../migration"]
)
def test_hold_renderer_refuses_temporary_or_ambiguous_storage(root):
    with pytest.raises(ValueError):
        service.evidence_service_guard("umi-validator@54.service", Path(root))


def test_guard_renders_persistent_exact_unit_scope():
    path, raw = service.evidence_service_guard(
        "umi-validator@54.service", Path("/var/lib/umi-evidence-migration/uid54")
    )
    assert str(path) == "/etc/systemd/system/umi-validator@54.service.d/40-umi-evidence-hold.conf"
    assert raw == (
        b"[Unit]\n"
        b"RequiresMountsFor=/var/lib/umi-evidence-migration/uid54\n"
        b"ConditionPathExists=!/var/lib/umi-evidence-migration/uid54/HOLD\n"
    )


@pytest.mark.parametrize(
    "data", [None, {}, [["ConditionPathExists", 0, True, "/bad", 0]], [["short"]]]
)
def test_loaded_guard_parser_rejects_malformed_bus_records(monkeypatch, data):
    monkeypatch.setattr(
        service.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0, stdout=json.dumps({"type": "a(sbbsi)", "data": data}).encode()
        ),
    )
    with pytest.raises(ValueError, match="invalid loaded"):
        service._loaded_conditions("umi-validator@54.service")
