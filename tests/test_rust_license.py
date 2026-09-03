from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from umi.rust_license import (
    RustLicenseClosureError,
    _build_from_metadata,
    verify_rust_license_closure,
)


def _fixture_graph(tmp_path: Path) -> tuple[dict[str, object], Path, Path, bytes]:
    repository = (tmp_path / "repository").resolve()
    source = repository / "rust" / "test-binary"
    dependency = (tmp_path / "cargo" / "registry" / "dep-1.2.3").resolve()
    source.mkdir(parents=True)
    dependency.mkdir(parents=True)
    (repository / "LICENSE").write_text("Apache License fixture\n")
    manifest = source / "Cargo.toml"
    manifest.write_text(
        '[package]\nname = "test-binary"\nversion = "0.1.0"\nlicense = "Apache-2.0"\n'
    )
    dependency_manifest = dependency / "Cargo.toml"
    dependency_manifest.write_text('[package]\nname = "dep"\nversion = "1.2.3"\nlicense = "MIT"\n')
    (dependency / "LICENSE-MIT").write_text("MIT License fixture\n")
    (dependency / "NOTICE").write_text("Dependency notice fixture\n")
    checksum = hashlib.sha256(b"dep-1.2.3-crate").hexdigest()
    lock_bytes = (
        "version = 4\n\n"
        "[[package]]\n"
        'name = "test-binary"\n'
        'version = "0.1.0"\n'
        'dependencies = ["dep"]\n\n'
        "[[package]]\n"
        'name = "dep"\n'
        'version = "1.2.3"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        f'checksum = "{checksum}"\n'
    ).encode()
    (source / "Cargo.lock").write_bytes(lock_bytes)
    root_id = "path+file:///fixture/test-binary#test-binary@0.1.0"
    dependency_id = "registry+https://github.com/rust-lang/crates.io-index#dep@1.2.3"
    metadata: dict[str, object] = {
        "packages": [
            {
                "id": root_id,
                "license": "Apache-2.0",
                "license_file": None,
                "manifest_path": str(manifest),
                "name": "test-binary",
                "repository": "https://example.invalid/test-binary",
                "source": None,
                "version": "0.1.0",
            },
            {
                "id": dependency_id,
                "license": "MIT",
                "license_file": None,
                "manifest_path": str(dependency_manifest),
                "name": "dep",
                "repository": "https://example.invalid/dep",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "version": "1.2.3",
            },
        ],
        "resolve": {
            "nodes": [
                {"deps": [{"pkg": dependency_id}], "id": root_id},
                {"deps": [], "id": dependency_id},
            ],
            "root": root_id,
        },
    }
    return metadata, manifest, repository, lock_bytes


def _build_fixture(
    metadata: dict[str, object],
    manifest: Path,
    repository: Path,
) -> bytes:
    return _build_from_metadata(
        metadata=metadata,
        manifest_path=manifest,
        repository_root=repository,
        target_triple="x86_64-unknown-linux-musl",
        binary_name="test-binary",
        expected_root_package="test-binary",
    )


def test_rust_license_closure_is_deterministic_and_lock_bound(tmp_path: Path) -> None:
    metadata, manifest, repository, lock_bytes = _fixture_graph(tmp_path)

    first = _build_fixture(metadata, manifest, repository)
    second = _build_fixture(metadata, manifest, repository)

    assert first == second
    verify_rust_license_closure(
        first,
        cargo_lock_bytes=lock_bytes,
        target_triple="x86_64-unknown-linux-musl",
        binary_name="test-binary",
    )
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        document = json.loads(archive.read("manifest.json"))
        assert [item["name"] for item in document["packages"]] == ["dep", "test-binary"]
        assert set(document["license_id_material_sha256s"]) == {"Apache-2.0", "MIT"}
        dep = document["packages"][0]
        assert len(dep["source_license_material_sha256s"]) == 2
        assert all(archive.read(item["archive_path"]) for item in document["license_materials"])

    changed_lock = lock_bytes.replace(b"1.2.3", b"1.2.4")
    with pytest.raises(
        RustLicenseClosureError,
        match="rust_license_manifest_binding_mismatch",
    ):
        verify_rust_license_closure(
            first,
            cargo_lock_bytes=changed_lock,
            target_triple="x86_64-unknown-linux-musl",
            binary_name="test-binary",
        )


@pytest.mark.parametrize(
    ("license_value", "reason"),
    [
        (None, "rust_license_expression_missing"),
        ("LicenseRef-unreviewed", "rust_license_expression_unknown"),
    ],
)
def test_rust_license_closure_rejects_missing_or_unknown_expression(
    tmp_path: Path,
    license_value: str | None,
    reason: str,
) -> None:
    metadata, manifest, repository, _lock_bytes = _fixture_graph(tmp_path)
    packages = metadata["packages"]
    assert isinstance(packages, list)
    dependency = packages[1]
    assert isinstance(dependency, dict)
    dependency["license"] = license_value

    with pytest.raises(RustLicenseClosureError, match=reason):
        _build_fixture(metadata, manifest, repository)


def test_rust_license_closure_rejects_known_license_without_material(
    tmp_path: Path,
) -> None:
    metadata, manifest, repository, _lock_bytes = _fixture_graph(tmp_path)
    packages = metadata["packages"]
    assert isinstance(packages, list)
    dependency = packages[1]
    assert isinstance(dependency, dict)
    dependency["license"] = "BSD-3-Clause"
    for name in ("LICENSE-MIT", "NOTICE"):
        (Path(dependency["manifest_path"]).parent / name).unlink()

    with pytest.raises(RustLicenseClosureError, match="rust_license_material_missing"):
        _build_fixture(metadata, manifest, repository)


def test_rust_license_closure_rejects_unapproved_dependency_source(
    tmp_path: Path,
) -> None:
    metadata, manifest, repository, lock_bytes = _fixture_graph(tmp_path)
    packages = metadata["packages"]
    assert isinstance(packages, list)
    dependency = packages[1]
    assert isinstance(dependency, dict)
    attacker_source = "git+https://attacker.invalid/dependency#deadbeef"
    dependency["source"] = attacker_source
    (manifest.parent / "Cargo.lock").write_bytes(
        lock_bytes.replace(
            b"registry+https://github.com/rust-lang/crates.io-index",
            attacker_source.encode(),
        )
    )

    with pytest.raises(RustLicenseClosureError, match="rust_license_dependency_source_unapproved"):
        _build_fixture(metadata, manifest, repository)
