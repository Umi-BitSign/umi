from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_validator_supervisor import _config, _wallets
from umi import competition_host_artifacts as artifacts
from umi.competition_host_upgrade import HostUpgradeError
from umi.crypto import sign_response_digest
from umi.protocol import canonical_json_bytes


def sign(manifest, wallets=None, signature_digest=None):
    return artifacts.SignedSuccessorHostArtifact(
        schema=artifacts.SIGNED_HOST_ARTIFACT_SCHEMA,
        manifest=manifest,
        manifest_sha256=artifacts.host_artifact_manifest_sha256(manifest),
        signatures=[
            {
                "hotkey": wallet.hotkey.ss58_address,
                "signature_scheme": "sr25519",
                "signature": sign_response_digest(
                    wallet,
                    signature_digest or artifacts.host_artifact_signature_digest(manifest),
                )[1],
            }
            for wallet in (wallets or _wallets()[:2])
        ],
    )


@pytest.fixture(params=["linux/amd64", "linux/arm64"])
def staged(tmp_path, monkeypatch, request):
    config = _config(target_platform=request.param)
    revision = "42" * 20
    parent = tmp_path / "host-stages"
    parent.mkdir(mode=0o755)
    stage = parent / revision
    stage.mkdir()
    files = []
    for name in sorted(artifacts._REQUIRED_FILES):
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        body = ("inert test bytes: " + name).encode()
        path.write_bytes(body)
        mode = 0o555 if name.startswith(".venv/bin/") else 0o444
        path.chmod(mode)
        files.append(
            artifacts.HostArtifactFile(
                path=name,
                sha256=hashlib.sha256(body).hexdigest(),
                size_bytes=len(body),
                mode=mode,
            )
        )
    for path in sorted(stage.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    stage.chmod(0o555)
    manifest = artifacts.SuccessorHostArtifactManifest(
        schema=artifacts.HOST_ARTIFACT_SCHEMA,
        channel_id=config.channel_id,
        umi_git_revision=revision,
        target_platform=request.param,
        host_entrypoint_profile="umi-competition-supervisor-host/1",
        total_size_bytes=sum(item.size_bytes for item in files),
        files=files,
    )
    monkeypatch.setattr(artifacts, "_STAGE_PARENT", parent)
    # Production checks /, /opt and the stage parent. The test parent replaces
    # that host boundary; temporary-directory ancestors are not installation roots.
    monkeypatch.setattr(artifacts, "_ancestor_paths", lambda root: (parent,))
    monkeypatch.setattr(artifacts, "_current_platform", lambda: request.param)
    original_owner = artifacts._immutable_owner

    def owner_port(info, mode, *, directory):
        # Test filesystem belongs to the test user. Production has no owner override.
        original_owner(
            SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink),
            mode,
            directory=directory,
        )

    monkeypatch.setattr(artifacts, "_immutable_owner", owner_port)
    original_ancestor_owner = artifacts._ancestor_owner
    monkeypatch.setattr(
        artifacts,
        "_ancestor_owner",
        lambda info: original_ancestor_owner(SimpleNamespace(st_uid=0, st_mode=info.st_mode)),
    )
    value = SimpleNamespace(config=config, path=stage, manifest=manifest, signed=sign(manifest))
    yield value
    # Undo fixture-only readonly modes so pytest can remove its own sandbox.
    stage.chmod(0o755)
    for path in stage.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)


def verify(value, **changes):
    arguments = dict(
        config=value.config,
        expected_manifest_sha256=value.signed.manifest_sha256,
        stage_root=value.path,
    )
    arguments.update(changes)
    return artifacts.verify_staged_host_tree(value.signed, **arguments)


def test_signed_tree_covers_every_file_without_executing_it(staged, monkeypatch):
    def no_execution(*args, **kwargs):
        pytest.fail("tree verification cannot execute staged programs")

    monkeypatch.setattr(os, "system", no_execution)
    parsed = artifacts.parse_signed_host_artifact(canonical_json_bytes(staged.signed))
    assert parsed == staged.signed
    verified = verify(staged)
    verified.recheck()
    assert verified.path == staged.path
    assert verified.manifest_sha256 == staged.signed.manifest_sha256
    assert not hasattr(verified, "chain_submission_authorized")


def test_bad_signature_domain_rejected(staged):
    staged.signed = sign(staged.manifest, signature_digest=b"\x00" * 32)
    with pytest.raises(HostUpgradeError, match="signature is invalid"):
        verify(staged)


def test_insufficient_quorum_rejected(staged):
    staged.signed = sign(staged.manifest, wallets=_wallets()[:1])
    with pytest.raises(HostUpgradeError, match="quorum"):
        verify(staged)


def test_wrong_approved_digest_rejected(staged):
    with pytest.raises(HostUpgradeError, match="approved"):
        verify(staged, expected_manifest_sha256="01" * 32)


def test_unknown_extra_file_rejected(staged):
    staged.path.chmod(0o755)
    (staged.path / "unreviewed.py").write_bytes(b"do not execute")
    (staged.path / "unreviewed.py").chmod(0o444)
    staged.path.chmod(0o555)
    with pytest.raises(HostUpgradeError, match="unsigned entry"):
        verify(staged)


def test_hash_mismatch_rejected(staged):
    target = staged.path / "uv.lock"
    target.chmod(0o644)
    target.write_bytes(b"X" * target.stat().st_size)
    target.chmod(0o444)
    with pytest.raises(HostUpgradeError, match="hash mismatch"):
        verify(staged)


def test_mode_mismatch_rejected(staged):
    (staged.path / "uv.lock").chmod(0o644)
    with pytest.raises(HostUpgradeError, match="mutable"):
        verify(staged)


def test_symlink_to_matching_file_rejected(staged, tmp_path):
    target = staged.path / "uv.lock"
    outside = tmp_path / "external"
    outside.write_bytes(target.read_bytes())
    outside.chmod(0o444)
    staged.path.chmod(0o755)
    target.unlink()
    target.symlink_to(outside)
    staged.path.chmod(0o555)
    with pytest.raises(HostUpgradeError, match="linked"):
        verify(staged)


def test_missing_file_rejected(staged):
    staged.path.chmod(0o755)
    (staged.path / "uv.lock").unlink()
    staged.path.chmod(0o555)
    with pytest.raises(HostUpgradeError, match="missing"):
        verify(staged)


def test_actual_platform_must_match(staged, monkeypatch):
    other = "linux/arm64" if staged.manifest.target_platform == "linux/amd64" else "linux/amd64"
    monkeypatch.setattr(artifacts, "_current_platform", lambda: other)
    with pytest.raises(HostUpgradeError, match="actual host"):
        verify(staged)


def test_stage_cannot_overlap_wallet_tree(staged):
    wallet = staged.config.wallet.model_copy(update={"path": str(staged.path / "wallet")})
    config = staged.config.model_copy(update={"wallet": wallet})
    with pytest.raises(HostUpgradeError, match="overlaps"):
        verify(staged, config=config)


def test_stage_cannot_be_relocated(staged, tmp_path):
    with pytest.raises(HostUpgradeError, match="fixed versioned"):
        verify(staged, stage_root=tmp_path / "somewhere")


def test_verified_capability_detects_rebinding_and_changed_file(staged):
    tree = verify(staged)
    with pytest.raises(HostUpgradeError, match="altered"):
        replace(tree, manifest_sha256="00" * 32).recheck()
    path = staged.path / "uv.lock"
    path.chmod(0o644)
    path.write_bytes(b"changed")
    path.chmod(0o444)
    with pytest.raises(HostUpgradeError, match="tree changed"):
        tree.recheck()


def test_noncanonical_document_rejected(staged):
    with pytest.raises(HostUpgradeError, match="canonical"):
        artifacts.parse_signed_host_artifact(canonical_json_bytes(staged.signed) + b"\n")


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a//b", "a/./b", "a/../../b"])
def test_unsafe_manifest_paths_rejected(path):
    with pytest.raises(ValueError):
        artifacts.HostArtifactFile(path=path, sha256="01" * 32, size_bytes=1, mode=0o444)


def test_owner_check_rejects_nonroot_even_when_readonly():
    with pytest.raises(HostUpgradeError, match="non-root"):
        artifacts._immutable_owner(
            SimpleNamespace(st_uid=1234, st_mode=0o100444, st_nlink=1), 0o444, directory=False
        )


def test_ancestor_set_includes_filesystem_root_and_every_parent():
    root = Path("/opt/umi-validator-supervisor-hosts") / ("42" * 20)
    assert artifacts._ancestor_paths(root) == (
        Path("/"),
        Path("/opt"),
        Path("/opt/umi-validator-supervisor-hosts"),
    )


@pytest.mark.parametrize("mode,uid", [(0o40777, 0), (0o40775, 0), (0o40755, 1000)])
def test_ancestor_boundary_rejects_mutable_or_nonroot_directories(mode, uid):
    with pytest.raises(HostUpgradeError, match="host ancestor"):
        artifacts._ancestor_owner(SimpleNamespace(st_uid=uid, st_mode=mode))


def test_writable_parent_rejected_even_when_signed_tree_is_readonly(staged):
    staged.path.parent.chmod(0o777)
    try:
        with pytest.raises(HostUpgradeError, match="host ancestor"):
            verify(staged)
    finally:
        staged.path.parent.chmod(0o755)


def test_parent_permissions_rechecked_after_verification(staged):
    tree = verify(staged)
    staged.path.parent.chmod(0o775)
    try:
        with pytest.raises(HostUpgradeError, match="host ancestor"):
            tree.recheck()
    finally:
        staged.path.parent.chmod(0o755)


def test_replaced_parent_rejected_after_verification(staged, tmp_path):
    tree = verify(staged)
    parent = staged.path.parent
    moved = tmp_path / "original-parent"
    parent.rename(moved)
    parent.mkdir(mode=0o755)
    try:
        with pytest.raises(HostUpgradeError, match="ancestor changed"):
            tree.recheck()
    finally:
        parent.rename(tmp_path / "replacement-parent")
        moved.rename(parent)


def test_unrelated_parent_entry_does_not_invalidate_source(staged):
    tree = verify(staged)
    (staged.path.parent / "other-host-release").mkdir()
    tree.recheck()
