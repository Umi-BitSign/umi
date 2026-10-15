from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_worker_maintenance as maintenance
from umi.competition_host_maintenance import (
    SupervisorHostMaintenanceApproval,
    WorkerSourceOverlayScope,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_host_maintenance import _approval
from .test_competition_host_maintenance import staged as staged


def prepared(staged, monkeypatch):
    receipt, original = _approval(staged)
    amendment = {"fixture": "already checked by the activation verifier"}
    scope = WorkerSourceOverlayScope(
        package_sha256="a1" * 32,
        release_bundle_sha256="a2" * 32,
        recipient_amendment_sha256=digest(amendment),
    )
    approval = SupervisorHostMaintenanceApproval.model_validate(
        {
            **original.model_dump(by_alias=True),
            "schema": "umi-supervisor-host-maintenance/2",
            "worker_overlay": scope,
        }
    )
    monkeypatch.setattr(maintenance, "_HOST_PARENT", staged.path.parent)
    installation = SimpleNamespace(config=staged.config, _receipt=receipt)
    overlay = maintenance.approved_worker_source_overlay(
        canonical_json_bytes(approval),
        installation=installation,
        running_root=staged.path,
    )
    activation = SimpleNamespace(
        package_sha256=scope.package_sha256,
        release_identity=SimpleNamespace(release_bundle_sha256=scope.release_bundle_sha256),
        _inputs=SimpleNamespace(
            authorization=SimpleNamespace(
                authorization=SimpleNamespace(
                    continuation=SimpleNamespace(recipient_amendment=amendment),
                )
            )
        ),
    )
    return overlay, activation


def test_source_overlay_uses_verified_signed_host(staged, monkeypatch):
    overlay, activation = prepared(staged, monkeypatch)
    assert overlay.source_for(activation) == staged.path / "src/umi"


@pytest.mark.parametrize("change", ["package", "release", "amendment", "source"])
def test_overlay_rejects_another_scope_or_modified_source(staged, monkeypatch, change):
    overlay, activation = prepared(staged, monkeypatch)
    if change == "package":
        activation.package_sha256 = "ff" * 32
    elif change == "release":
        activation.release_identity.release_bundle_sha256 = "ff" * 32
    elif change == "amendment":
        activation._inputs.authorization.authorization.continuation.recipient_amendment = {
            "other": 1
        }
    else:
        source = staged.path / "src/umi/competition_supervisor.py"
        source.chmod(0o644)
        source.write_bytes(b"changed")
        source.chmod(0o444)
    with pytest.raises(ValueError):
        overlay.source_for(activation)


def test_original_approval_does_not_authorize_worker_changes(staged, monkeypatch):
    receipt, approval = _approval(staged)
    assert "worker_overlay" not in approval.model_dump()
    assert (
        maintenance.approved_worker_source_overlay(
            canonical_json_bytes(approval),
            installation=SimpleNamespace(config=staged.config, _receipt=receipt),
            running_root=staged.path,
        )
        is None
    )


def test_overlay_accepts_only_the_two_explicit_amendments(staged, monkeypatch):
    overlay, activation = prepared(staged, monkeypatch)
    assert (
        "successor_recipient_amendment_sha256" not in overlay.approval.worker_overlay.model_dump()
    )
    successor = {"fixture": "separately authenticated IP amendment"}
    scope = overlay.approval.worker_overlay.model_copy(
        update={"successor_recipient_amendment_sha256": digest(successor)}
    )
    receipt, _ = _approval(staged)
    updated = maintenance.approved_worker_source_overlay(
        canonical_json_bytes(overlay.approval.model_copy(update={"worker_overlay": scope})),
        installation=SimpleNamespace(config=staged.config, _receipt=receipt),
        running_root=overlay.root,
    )
    assert updated.source_for(activation) == staged.path / "src/umi"
    activation._inputs.authorization.authorization.continuation.recipient_amendment = successor
    assert updated.source_for(activation) == staged.path / "src/umi"
    activation._inputs.authorization.authorization.continuation.recipient_amendment = {"other": 2}
    with pytest.raises(ValueError, match="approved package or amendment"):
        updated.source_for(activation)


def test_overlay_rechecks_and_restart_do_not_read_verified_host_bytes(staged, monkeypatch):
    from umi import competition_host_artifacts as artifacts

    calls = []
    original = artifacts._file_hash

    def counted(fd, size):
        calls.append(size)
        return original(fd, size)

    monkeypatch.setattr(artifacts, "_file_hash", counted)
    overlay, activation = prepared(staged, monkeypatch)
    assert sum(calls) == staged.manifest.total_size_bytes
    for _ in range(3):
        assert overlay.source_for(activation) == staged.path / "src/umi"
    reopened, activation = prepared(staged, monkeypatch)
    assert reopened.source_for(activation) == staged.path / "src/umi"
    assert sum(calls) == staged.manifest.total_size_bytes


@pytest.mark.parametrize("change", ["root", "scope", "tree", "unissued"])
def test_overlay_rejects_forged_or_changed_capability(staged, monkeypatch, change):
    overlay, activation = prepared(staged, monkeypatch)
    if change == "root":
        altered = replace(overlay, root=staged.path.parent)
    elif change == "scope":
        altered = replace(
            overlay,
            approval=overlay.approval.model_copy(
                update={
                    "worker_overlay": overlay.approval.worker_overlay.model_copy(
                        update={"package_sha256": "ff" * 32}
                    )
                }
            ),
        )
        activation.package_sha256 = "ff" * 32
    elif change == "tree":
        altered = replace(overlay, _tree=replace(overlay._tree, path=staged.path.parent))
    else:
        altered = maintenance.ApprovedWorkerSourceOverlay(overlay.approval, overlay.root)
    with pytest.raises(ValueError):
        altered.source_for(activation)


def test_host_first_pass_resumes_completed_file_checks(staged, monkeypatch):
    from umi import competition_host_artifacts as artifacts

    calls = []
    original = artifacts._file_hash

    def interrupted(fd, size):
        calls.append(size)
        if len(calls) == 3:
            raise OSError("interrupted host check")
        return original(fd, size)

    monkeypatch.setattr(artifacts, "_file_hash", interrupted)
    with pytest.raises(OSError, match="interrupted host check"):
        prepared(staged, monkeypatch)
    first_completed = sum(calls[:2])
    calls.clear()

    def counted(fd, size):
        calls.append(size)
        return original(fd, size)

    monkeypatch.setattr(artifacts, "_file_hash", counted)
    overlay, activation = prepared(staged, monkeypatch)
    overlay.source_for(activation)
    assert sum(calls) == staged.manifest.total_size_bytes - first_completed


def test_host_digest_reuse_still_checks_current_signed_size(staged, monkeypatch):
    from umi import competition_host_artifacts as artifacts

    from .test_competition_host_artifacts import sign

    prepared(staged, monkeypatch)
    files = list(staged.manifest.files)
    files[0] = files[0].model_copy(update={"size_bytes": files[0].size_bytes + 1})
    staged.signed = sign(
        staged.manifest.model_copy(
            update={
                "files": files,
                "total_size_bytes": staged.manifest.total_size_bytes + 1,
            }
        )
    )
    monkeypatch.setattr(
        artifacts, "_file_hash", lambda *args: pytest.fail("cached bytes need no read")
    )
    with pytest.raises(ValueError, match="signed size"):
        prepared(staged, monkeypatch)
