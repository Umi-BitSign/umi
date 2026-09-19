"""Fixed image manifest validation without executing native artifacts."""

import os
from types import SimpleNamespace

import pytest

from umi.bridge import native
from umi.protocol import canonical_json_bytes


@pytest.fixture
def manifest(tmp_path, monkeypatch):
    path = tmp_path.resolve() / "bridge-native-artifacts.json"
    value = native.BridgeNativeArtifacts(
        schema="umi-bridge-native-artifacts/1",
        target="linux/arm64",
        proof_sha256="a" * 64,
        runtime_sha256="b" * 64,
    )
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(0o444)
    monkeypatch.setattr(native, "IMAGE_MANIFEST", path)
    monkeypatch.setattr(native, "_IMAGE_OWNER_UID", os.getuid())
    monkeypatch.setattr(native.platform, "system", lambda: "Linux")
    monkeypatch.setattr(native.platform, "machine", lambda: "aarch64")
    return path, value


def test_fixed_manifest_parses_exact_bytes(manifest):
    assert native.read_image_artifacts() == manifest[1]


@pytest.mark.parametrize("mode", [0o644, 0o600, 0o666, 0o777])
def test_manifest_must_be_sealed(manifest, mode):
    manifest[0].chmod(mode)
    with pytest.raises(RuntimeError, match="manifest_unsafe"):
        native.read_image_artifacts()


def test_manifest_requires_image_owner(manifest, monkeypatch):
    monkeypatch.setattr(native, "_IMAGE_OWNER_UID", os.getuid() + 1)
    with pytest.raises(RuntimeError, match="manifest_unsafe"):
        native.read_image_artifacts()


def test_manifest_cannot_be_a_symlink_or_hardlink(manifest, monkeypatch):
    path = manifest[0]
    alias = path.with_name("alias")
    alias.symlink_to(path)
    monkeypatch.setattr(native, "IMAGE_MANIFEST", alias)
    with pytest.raises(RuntimeError, match="path_unsafe"):
        native.read_image_artifacts()
    monkeypatch.setattr(native, "IMAGE_MANIFEST", path)
    path.with_name("hardlink").hardlink_to(path)
    with pytest.raises(RuntimeError, match="manifest_unsafe"):
        native.read_image_artifacts()


@pytest.mark.parametrize("body", [b"", b"{}", b"x" * 4097, None])
def test_manifest_limits_and_canonical_bytes(manifest, body):
    path, value = manifest
    path.chmod(0o600)
    path.write_bytes(canonical_json_bytes(value) + b"\n" if body is None else body)
    path.chmod(0o444)
    with pytest.raises((ValueError, RuntimeError)):
        native.read_image_artifacts()


def test_manifest_target_is_checked_against_host(manifest, monkeypatch):
    monkeypatch.setattr(native.platform, "machine", lambda: "x86_64")
    with pytest.raises(RuntimeError, match="target_mismatch"):
        native.read_image_artifacts()


def test_factories_bind_the_fixed_binaries_and_digests(manifest, monkeypatch):
    proof, runtime = [], []
    monkeypatch.setattr(
        native, "SubprocessStorageProofVerifier", lambda **kw: proof.append(kw) or kw
    )
    monkeypatch.setattr(native, "RuntimeMetadataExecutor", lambda **kw: runtime.append(kw) or kw)
    monkeypatch.setattr(native, "BridgeSigningStateReader", lambda **kw: kw)
    monkeypatch.setattr(native, "BridgeReceiptReader", lambda **kw: kw)
    client = SimpleNamespace(endpoint="wss://rpc.example")
    finality, clock = object(), object()
    reader = native.signing_reader(client=client, finality=finality, clock=clock)
    receipt = native.receipt_reader(client=client, finality=finality)
    assert reader["finality"] is receipt["finality"] is finality
    assert reader["clock"] is clock
    assert (
        proof
        == [dict(binary_path="/opt/umi/bin/umi-substrate-proof-verifier", expected_sha256="a" * 64)]
        * 2
    )
    assert all(
        str(item["binary_path"]) == "/opt/umi/bin/umi-runtime-metadata"
        and item["expected_sha256"] == "b" * 64
        for item in runtime
    )
