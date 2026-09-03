from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from umi.audit import MAX_COMPONENT_OBJECT_BYTES, EvidenceStore


def test_object_reference_rejects_path_traversal_before_io(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    with pytest.raises(ValueError, match="malformed"):
        store.read(
            {
                "sha256": "../manifest.json",
                "media_type": "application/json",
                "size_bytes": 1,
            }
        )


def test_declared_oversized_object_is_rejected_before_io(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    with pytest.raises(ValueError, match="byte ceiling"):
        store.read(
            {
                "sha256": "00" * 32,
                "media_type": "application/octet-stream",
                "size_bytes": MAX_COMPONENT_OBJECT_BYTES + 1,
            }
        )


def test_symlinked_content_object_is_rejected(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "bundle")
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    digest = hashlib.sha256(b"secret").hexdigest()
    (store.objects / digest).symlink_to(outside)

    with pytest.raises(ValueError, match="safely"):
        store.read(
            {
                "sha256": digest,
                "media_type": "application/octet-stream",
                "size_bytes": len(b"secret"),
            }
        )


def test_writes_fsync_content_and_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        observed.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    store = EvidenceStore(tmp_path / "bundle")
    initialization_fsyncs = len(observed)
    reference = store.add_bytes(b"durable", "application/octet-stream")
    store.write_manifest({"object": reference.as_dict()})

    # Each write flushes its regular file and the containing directory before
    # returning control to a state-machine transition.
    assert len(observed) - initialization_fsyncs == 4


def test_symlinked_evidence_root_is_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="root must be a real directory"):
        EvidenceStore(alias)


def test_add_bytes_requires_immutable_exact_bytes(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "bundle")
    with pytest.raises(TypeError, match="exact bytes"):
        store.add_bytes(bytearray(b"mutable"), "application/octet-stream")  # type: ignore[arg-type]
