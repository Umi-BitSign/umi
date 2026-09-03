from __future__ import annotations

import os
from pathlib import Path

import pytest

from umi.model_release import (
    build_model_release_manifest,
    read_model_release_manifest,
    verify_model_release_manifest,
)


def _manifest() -> bytes:
    return build_model_release_manifest(
        checkpoint_sha256="11" * 32,
        architecture_config_sha256="22" * 32,
        tokenizer_vocabulary_sha256="33" * 32,
        preprocessing_decoder_sha256="44" * 32,
        license_provenance_sha256="55" * 32,
    )


def test_release_manifest_is_canonical_and_content_addressed() -> None:
    manifest = _manifest()

    assert manifest == (
        b'{"architecture_config_sha256":"'
        + b"22" * 32
        + b'","checkpoint_sha256":"'
        + b"11" * 32
        + b'","license_provenance_sha256":"'
        + b"55" * 32
        + b'","preprocessing_decoder_sha256":"'
        + b"44" * 32
        + b'","schema":"umi-model-release/1","tokenizer_vocabulary_sha256":"'
        + b"33" * 32
        + b'"}'
    )
    assert verify_model_release_manifest(manifest) == (
        "11ce3f6c01c86a4e81b423f70499323ea6f47d212450fd15ed80c346d04eb2d1"
    )


@pytest.mark.parametrize(
    "value",
    (
        b'{"schema":"umi-model-release/1"}',
        b'{"schema":"umi-model-release/1","schema":"umi-model-release/1"}',
        b" {}",
    ),
)
def test_release_manifest_rejects_incomplete_duplicate_or_noncanonical_bytes(
    value: bytes,
) -> None:
    with pytest.raises(ValueError):
        verify_model_release_manifest(value)


def test_release_revision_binds_license_and_provenance() -> None:
    original = _manifest()
    changed = build_model_release_manifest(
        checkpoint_sha256="11" * 32,
        architecture_config_sha256="22" * 32,
        tokenizer_vocabulary_sha256="33" * 32,
        preprocessing_decoder_sha256="44" * 32,
        license_provenance_sha256="66" * 32,
    )

    assert verify_model_release_manifest(changed) != verify_model_release_manifest(original)
    with pytest.raises(ValueError, match="license/provenance"):
        build_model_release_manifest(
            checkpoint_sha256="11" * 32,
            architecture_config_sha256="22" * 32,
            tokenizer_vocabulary_sha256="33" * 32,
            preprocessing_decoder_sha256="44" * 32,
            license_provenance_sha256="not-a-digest",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow and file-mode assertion")
def test_safe_manifest_reader_rejects_writable_file_and_symlink(tmp_path: Path) -> None:
    path = (tmp_path / "model-release.json").resolve()
    path.write_bytes(_manifest())
    os.chmod(path, 0o600)
    with pytest.raises(RuntimeError, match="read-only regular file"):
        read_model_release_manifest(path)

    os.chmod(path, 0o400)
    value, revision = read_model_release_manifest(path)
    assert value == _manifest()
    assert revision == verify_model_release_manifest(value)

    link = (tmp_path / "model-release-link.json").resolve()
    link.symlink_to(path)
    with pytest.raises(RuntimeError, match="opened safely"):
        read_model_release_manifest(link)
