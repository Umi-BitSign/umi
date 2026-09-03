"""Small content-addressed evidence store for local component-test runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .protocol import canonical_json_bytes

MAX_COMPONENT_MANIFEST_BYTES = 1024 * 1024
MAX_COMPONENT_OBJECT_BYTES = 4 * 1024 * 1024
MAX_COMPONENT_TOTAL_OBJECT_BYTES = 64 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"evidence file cannot be opened safely: {path.name}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"evidence path is not a regular file: {path.name}")
        if metadata.st_size > maximum_bytes:
            raise ValueError(f"evidence file exceeds its byte ceiling: {path.name}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError(f"evidence file exceeds its byte ceiling: {path.name}")
            chunks.append(chunk)
        if total != metadata.st_size:
            raise ValueError(f"evidence file changed while it was read: {path.name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class ObjectRef:
    sha256: str
    media_type: str
    size_bytes: int

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None:
            raise ValueError("object SHA-256 must be 64 lowercase hexadecimal characters")
        if not self.media_type:
            raise ValueError("object media type must not be empty")
        if self.size_bytes < 0:
            raise ValueError("object size must not be negative")

    def as_dict(self) -> dict[str, str | int]:
        return {
            "sha256": self.sha256,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
        }


class EvidenceStore:
    """Write immutable objects under their SHA-256 digest.

    This is local evidence only.  It deliberately does not represent a chain
    anchor or a conforming Section 12 audit bundle.
    """

    def __init__(
        self,
        root: Path,
        *,
        maximum_object_bytes: int = MAX_COMPONENT_OBJECT_BYTES,
        maximum_manifest_bytes: int = MAX_COMPONENT_MANIFEST_BYTES,
        maximum_total_object_bytes: int = MAX_COMPONENT_TOTAL_OBJECT_BYTES,
    ) -> None:
        if (
            maximum_object_bytes <= 0
            or maximum_manifest_bytes <= 0
            or maximum_total_object_bytes <= 0
        ):
            raise ValueError("evidence byte ceilings must be positive")
        self.root = root
        self.objects = root / "objects"
        self.maximum_object_bytes = maximum_object_bytes
        self.maximum_manifest_bytes = maximum_manifest_bytes
        self.maximum_total_object_bytes = maximum_total_object_bytes
        self._accounted_objects: dict[str, int] = {}
        root_existed = self.root.exists()
        self.objects.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("component evidence root must be a real directory")
        if self.objects.is_symlink() or not self.objects.is_dir():
            raise ValueError("component objects path must be a real directory")
        # Persist both directory entries before a later state transition can
        # reference an object beneath them.  A missing parent entry after a
        # power loss is otherwise possible even when the object file itself was
        # fsynced.
        _fsync_directory(self.root)
        if not root_existed:
            _fsync_directory(self.root.parent)

    def _account_object(self, digest: str, size_bytes: int) -> None:
        existing = self._accounted_objects.get(digest)
        if existing is not None:
            if existing != size_bytes:
                raise ValueError("one object digest is declared with different byte lengths")
            return
        if sum(self._accounted_objects.values()) + size_bytes > self.maximum_total_object_bytes:
            raise ValueError("component evidence exceeds its aggregate object-byte ceiling")
        self._accounted_objects[digest] = size_bytes

    def add_bytes(self, data: bytes, media_type: str) -> ObjectRef:
        if not isinstance(data, bytes):
            raise TypeError("component evidence object must be exact bytes")
        if len(data) > self.maximum_object_bytes:
            raise ValueError("component evidence object exceeds its byte ceiling")
        digest = hashlib.sha256(data).hexdigest()
        self._account_object(digest, len(data))
        destination = self.objects / digest
        if destination.exists():
            existing = _read_bounded_regular_file(destination, self.maximum_object_bytes)
            if existing != data:
                raise RuntimeError("content-addressed object collision")
        else:
            _write_content_addressed_file(destination, data)
        return ObjectRef(digest, media_type, len(data))

    def add_json(self, value: Any) -> ObjectRef:
        return self.add_bytes(canonical_json_bytes(value), "application/json")

    def read(self, reference: ObjectRef | dict[str, Any]) -> bytes:
        if not isinstance(reference, ObjectRef):
            try:
                reference = ObjectRef(
                    sha256=str(reference["sha256"]),
                    media_type=str(reference["media_type"]),
                    size_bytes=int(reference["size_bytes"]),
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("object reference is malformed") from error
        expected_digest = reference.sha256
        expected_size = reference.size_bytes
        if expected_size > self.maximum_object_bytes:
            raise ValueError(f"object {expected_digest} exceeds the component byte ceiling")
        self._account_object(expected_digest, expected_size)
        data = _read_bounded_regular_file(
            self.objects / expected_digest,
            self.maximum_object_bytes,
        )
        if len(data) != expected_size:
            raise ValueError(f"object {expected_digest} has the wrong byte length")
        if hashlib.sha256(data).hexdigest() != expected_digest:
            raise ValueError(f"object {expected_digest} failed SHA-256 verification")
        return data

    def write_manifest(self, manifest: dict[str, Any]) -> Path:
        path = self.root / "manifest.json"
        encoded = canonical_json_bytes(manifest)
        if len(encoded) > self.maximum_manifest_bytes:
            raise ValueError("component manifest exceeds its byte ceiling")
        _atomic_replace_file(path, encoded)
        return path

    def load_manifest_with_bytes(self) -> tuple[dict[str, Any], bytes]:
        """Load and decode one bounded, no-follow manifest snapshot."""

        data = _read_bounded_regular_file(
            self.root / "manifest.json",
            self.maximum_manifest_bytes,
        )
        try:
            decoded = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("component manifest is not valid JSON") from error
        if canonical_json_bytes(decoded) != data:
            raise ValueError("component manifest is not RFC 8785 canonical JSON")
        if not isinstance(decoded, dict):
            raise ValueError("component manifest must be a JSON object")
        return decoded, data

    def load_manifest(self) -> dict[str, Any]:
        decoded, _ = self.load_manifest_with_bytes()
        return decoded


def _write_content_addressed_file(path: Path, data: bytes) -> None:
    """Durably create an immutable object without replacing a concurrent writer."""

    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            existing = _read_bounded_regular_file(path, len(data))
            if existing != data:
                raise RuntimeError("content-addressed object collision") from None
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _atomic_replace_file(path: Path, data: bytes) -> None:
    """Durably replace a mutable manifest after its full contents reach disk."""

    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("evidence write made no progress")
        offset += written


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
