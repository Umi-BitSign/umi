from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_validator_supervisor import _config, _wallets
from umi import competition_release as releases
from umi.competition_package import CompetitionReleaseIdentity
from umi.competition_supervisor import SuccessorSupervisorReleaseTarget
from umi.crypto import sign_response_digest
from umi.protocol import canonical_json_bytes


@pytest.fixture(params=["linux/amd64", "linux/arm64"])
def artifact(tmp_path, request, monkeypatch):
    archive = b"opaque archive bytes; never execute or untar in this test\n" * 16
    manifest = releases.SuccessorOCIReleaseManifest(
        schema=releases.SUCCESSOR_RELEASE_SCHEMA,
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256="11" * 32,
        oci_archive_sha256=hashlib.sha256(archive).hexdigest(),
        oci_archive_size_bytes=len(archive),
        target_platform=request.param,
        umi_git_revision="23" * 20,
        umi_source_tree_sha256="34" * 32,
        entrypoint_profile="umi-competition-replay-worker/1",
        state_schema_minimum=4,
        state_schema_maximum=4,
    )
    payload = canonical_json_bytes(manifest)
    signature = bytes.fromhex(
        sign_response_digest(_wallets()[0], releases.successor_release_signature_digest(manifest))[
            1
        ][2:]
    )
    bundle = releases._header(payload, signature) + archive
    bundle_hash, manifest_hash = (
        hashlib.sha256(bundle).hexdigest(),
        hashlib.sha256(payload).hexdigest(),
    )
    identity = CompetitionReleaseIdentity(
        schema="umi-competition-replay-release-identity/1",
        umi_revision=manifest.umi_git_revision,
        release_manifest_sha256=manifest_hash,
        release_bundle_sha256=bundle_hash,
        target_triple=("x86_64" if request.param == "linux/amd64" else "aarch64")
        + "-unknown-linux-gnu",
    )
    target = SuccessorSupervisorReleaseTarget(
        schema="umi-successor-supervisor-release-target/1",
        release_bundle_url="https://releases.umi.vision/competition/release.bundle",
        release_bundle_sha256=bundle_hash,
        release_bundle_size_bytes=len(bundle),
        release_manifest_sha256=manifest_hash,
        release_authority_hotkey=_wallets()[0].hotkey.ss58_address,
        release_authority_signature_scheme="sr25519",
        replay_release_identity=identity,
        **{name: getattr(manifest, name) for name in releases._BOUND_FIELDS},
    )
    root = tmp_path / "releases"
    root.mkdir(mode=0o700)
    (root / "successor").mkdir(mode=0o700)
    # Treat the fixture-owned cache as the host boundary. Production validates
    # every ancestor, including /; test OS temporary roots are not install paths.
    monkeypatch.setattr(releases, "_ancestor_paths", lambda path: (root, root / "successor"))
    stage = root / "successor" / bundle_hash
    stage.mkdir(mode=0o700)
    source = tmp_path / "download.bundle"
    source.write_bytes(bundle)
    source.chmod(0o600)
    value = SimpleNamespace(
        target=target,
        config=_config(target_platform=request.param, release_root=str(root)),
        stage=stage,
        source=source,
        bundle=bundle,
        manifest=manifest,
        payload=payload,
        signature=signature,
        archive=archive,
    )
    yield value
    stage.chmod(0o700)


def extract(value, **changes):
    args = dict(
        bundle=value.source, destination=value.stage, target=value.target, config=value.config
    )
    args.update(changes)
    return releases.extract_successor_release_bundle(**args)


def test_exact_signed_archive_staged_without_execution(artifact, monkeypatch):
    monkeypatch.setattr(os, "system", lambda *a: pytest.fail("must not execute artifact"))
    result = extract(artifact)
    assert result.archive_path.read_bytes() == artifact.archive
    assert result.path.stat().st_mode & 0o777 == 0o500
    assert result.archive_path.stat().st_mode & 0o777 == 0o400
    result.recheck()
    reopened = releases.verify_staged_successor_release(
        result.path,
        target=artifact.target,
        config=artifact.config,
    )
    reopened.recheck()
    assert not hasattr(result, "chain_submission_authorized")


def test_existing_stage_not_replaced(artifact):
    note = artifact.stage / "keep-me"
    note.write_bytes(b"prior staged state")
    with pytest.raises(releases.SuccessorReleaseError, match="refusing to replace"):
        extract(artifact)
    assert note.read_bytes() == b"prior staged state"


@pytest.mark.parametrize(
    "corruption", ["archive", "signature", "magic", "length", "truncated", "extra"]
)
def test_invalid_bundle_writes_nothing(artifact, corruption):
    body = bytearray(artifact.bundle)
    offset = len(releases._header(artifact.payload, artifact.signature))
    if corruption == "archive":
        body[-1] ^= 1
    elif corruption == "signature":
        body[offset - 1] ^= 1
    elif corruption == "magic":
        body[0] ^= 1
    elif corruption == "length":
        start = len(releases.SUCCESSOR_BUNDLE_MAGIC)
        body[start : start + 4] = struct.pack(">I", releases.MAX_RELEASE_MANIFEST_BYTES + 1)
    elif corruption == "truncated":
        body = body[:-1]
    else:
        body += b"x"
    artifact.source.write_bytes(body)
    with pytest.raises(releases.SuccessorReleaseError):
        extract(artifact)
    assert list(artifact.stage.iterdir()) == []


def test_old_signature_domain_cannot_authorize_successor(artifact):
    old_digest = hashlib.sha256(b"umi-validator-oci-release-v1\0" + artifact.payload).digest()
    signature = bytes.fromhex(sign_response_digest(_wallets()[0], old_digest)[1][2:])
    artifact.source.write_bytes(releases._header(artifact.payload, signature) + artifact.archive)
    with pytest.raises(releases.SuccessorReleaseError, match="signature"):
        extract(artifact)


def test_wrong_platform_or_origin_rejected_before_io(artifact):
    config = artifact.config.model_copy(update={"release_origins": ["https://other.example"]})
    with pytest.raises(releases.SuccessorReleaseError, match="authority or platform"):
        extract(artifact, config=config)


def test_staging_outside_release_root_rejected(artifact, tmp_path):
    with pytest.raises(releases.SuccessorReleaseError, match="configured content-addressed"):
        extract(artifact, destination=tmp_path)


def test_source_symlink_or_hardlink_rejected(artifact, tmp_path):
    link = tmp_path / "link.bundle"
    link.symlink_to(artifact.source)
    with pytest.raises(OSError):
        extract(artifact, bundle=link)
    os.link(artifact.source, tmp_path / "hardlink.bundle")
    with pytest.raises(releases.SuccessorReleaseError, match="regular file"):
        extract(artifact)


def test_unknown_staged_entry_rejected(artifact):
    result = extract(artifact)
    artifact.stage.chmod(0o700)
    (artifact.stage / "extra").write_bytes(b"never run")
    artifact.stage.chmod(0o500)
    with pytest.raises(releases.SuccessorReleaseError, match="exact file set"):
        result.recheck()


def test_changed_staged_archive_rejected(artifact):
    result = extract(artifact)
    result.archive_path.chmod(0o600)
    result.archive_path.write_bytes(b"x" * len(artifact.archive))
    result.archive_path.chmod(0o400)
    with pytest.raises(releases.SuccessorReleaseError, match="hash/size mismatch"):
        result.recheck()


def test_forged_staging_capability_rejected(artifact):
    result = extract(artifact)
    with pytest.raises(releases.SuccessorReleaseError, match="absent or altered"):
        replace(result, path=artifact.source).recheck()


def test_interrupted_stage_is_not_verified_or_overwritten(artifact, monkeypatch):
    write = releases._write_output

    def interrupt(directory, name, chunks):
        if name == "image.oci.tar":
            raise OSError("simulated full disk")
        return write(directory, name, chunks)

    monkeypatch.setattr(releases, "_write_output", interrupt)
    with pytest.raises(OSError, match="full disk"):
        extract(artifact)
    assert set(os.listdir(artifact.stage)) == {"release-manifest.json", "release-signature.bin"}
    with pytest.raises(releases.SuccessorReleaseError, match="ownership or mode"):
        releases.verify_staged_successor_release(
            artifact.stage,
            target=artifact.target,
            config=artifact.config,
        )
    monkeypatch.setattr(releases, "_write_output", write)
    with pytest.raises(releases.SuccessorReleaseError, match="refusing to replace"):
        extract(artifact)


def test_release_ancestry_walk_includes_root():
    path = Path("/var/lib/umi-supervisor/releases/successor/digest")
    assert releases._ancestor_paths(path) == tuple(reversed(path.parents))
    assert releases._ancestor_paths(path)[0] == Path("/")


@pytest.mark.parametrize("mode,uid", [(0o40777, 0), (0o40775, 0), (0o40700, 123456789)])
def test_unsafe_release_ancestor_rejected(mode, uid):
    with pytest.raises(releases.SuccessorReleaseError, match="ancestor"):
        releases._ancestor_owner(SimpleNamespace(st_mode=mode, st_uid=uid))


def test_changed_stage_parent_permissions_rejected(artifact):
    result = extract(artifact)
    artifact.stage.parent.chmod(0o777)
    try:
        with pytest.raises(releases.SuccessorReleaseError, match="ancestor"):
            result.recheck()
    finally:
        artifact.stage.parent.chmod(0o700)


def test_bounded_directory_listing_rejects_fourth_entry():
    class Entries:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def __iter__(self):
            for name in ("a", "b", "c", "d"):
                yield SimpleNamespace(name=name)
            pytest.fail("must reject before consuming more entries")

    from unittest.mock import patch

    with (
        patch.object(os, "scandir", return_value=Entries()),
        pytest.raises(releases.SuccessorReleaseError, match="exact file set"),
    ):
        releases._stage_entries(10)
