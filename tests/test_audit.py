from __future__ import annotations

import hashlib
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
