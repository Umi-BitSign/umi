"""Canonical model-release manifests built only from explicit artifact digests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

MODEL_RELEASE_SCHEMA = "umi-model-release/1"
MAXIMUM_MODEL_RELEASE_MANIFEST_BYTES = 4 * 1024
_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_FIELDS = (
    "architecture_config_sha256",
    "checkpoint_sha256",
    "license_provenance_sha256",
    "preprocessing_decoder_sha256",
    "tokenizer_vocabulary_sha256",
)
_MANIFEST_FIELDS = frozenset(("schema", *_ARTIFACT_FIELDS))


def build_model_release_manifest(
    *,
    checkpoint_sha256: str,
    architecture_config_sha256: str,
    tokenizer_vocabulary_sha256: str,
    preprocessing_decoder_sha256: str,
    license_provenance_sha256: str,
) -> bytes:
    """Build the exact canonical manifest without opening any artifact path."""

    document = {
        "schema": MODEL_RELEASE_SCHEMA,
        "checkpoint_sha256": _artifact_digest(checkpoint_sha256, "checkpoint"),
        "architecture_config_sha256": _artifact_digest(
            architecture_config_sha256,
            "architecture/config",
        ),
        "tokenizer_vocabulary_sha256": _artifact_digest(
            tokenizer_vocabulary_sha256,
            "tokenizer/vocabulary",
        ),
        "preprocessing_decoder_sha256": _artifact_digest(
            preprocessing_decoder_sha256,
            "preprocessing/decoder",
        ),
        "license_provenance_sha256": _artifact_digest(
            license_provenance_sha256,
            "license/provenance",
        ),
    }
    return _canonical_bytes(document)


def verify_model_release_manifest(value: bytes) -> str:
    """Validate canonical manifest bytes and return their SHA-256 revision."""

    if not isinstance(value, bytes):
        raise TypeError("model release manifest must be bytes")
    if not value or len(value) > MAXIMUM_MODEL_RELEASE_MANIFEST_BYTES:
        raise ValueError("model release manifest has an invalid byte length")
    document = _decode_manifest(value)
    if set(document) != _MANIFEST_FIELDS or document.get("schema") != MODEL_RELEASE_SCHEMA:
        raise ValueError("model release manifest has an invalid schema")
    for field in _ARTIFACT_FIELDS:
        _artifact_digest(document.get(field), field.removesuffix("_sha256"))
    if _canonical_bytes(document) != value:
        raise ValueError("model release manifest is not canonical")
    return hashlib.sha256(value).hexdigest()


def read_model_release_manifest(path: str | Path) -> tuple[bytes, str]:
    """Read and verify one owner-held, read-only regular manifest file.

    Artifact paths are intentionally unsupported. This function reads only the
    small release manifest and refuses symlinks, hard links, writable files, and a
    file that changes while its descriptor is open.
    """

    resolved = Path(path).expanduser()
    if not resolved.is_absolute():
        raise ValueError("model release manifest path must be absolute")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise RuntimeError("safe model release manifest reads require POSIX no-follow support")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise RuntimeError("model release manifest could not be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o222
        ):
            raise RuntimeError(
                "model release manifest must be an owner-held, read-only regular file"
            )
        if before.st_size <= 0 or before.st_size > MAXIMUM_MODEL_RELEASE_MANIFEST_BYTES:
            raise RuntimeError("model release manifest file size is invalid")
        encoded = bytearray()
        while chunk := os.read(
            descriptor,
            min(MAXIMUM_MODEL_RELEASE_MANIFEST_BYTES + 1 - len(encoded), 4096),
        ):
            encoded.extend(chunk)
            if len(encoded) > MAXIMUM_MODEL_RELEASE_MANIFEST_BYTES:
                raise RuntimeError("model release manifest exceeds its byte ceiling")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or len(encoded) != before.st_size:
            raise RuntimeError("model release manifest changed while it was read")
    finally:
        os.close(descriptor)
    value = bytes(encoded)
    return value, verify_model_release_manifest(value)


def model_release_revision(value: bytes) -> str:
    """Alias the validated canonical manifest digest used as model_revision."""

    return verify_model_release_manifest(value)


def _artifact_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} digest must be lowercase SHA-256 hexadecimal")
    return value


def _canonical_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _decode_manifest(value: bytes) -> dict[str, Any]:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, item in pairs:
            if key in document:
                raise ValueError("model release manifest contains a duplicate key")
            document[key] = item
        return document

    def reject_constant(value: str) -> None:
        raise ValueError(f"model release manifest contains invalid number {value}")

    try:
        document = json.loads(
            value,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("model release manifest is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ValueError("model release manifest must be a JSON object")
    return document


__all__ = [
    "MAXIMUM_MODEL_RELEASE_MANIFEST_BYTES",
    "MODEL_RELEASE_SCHEMA",
    "build_model_release_manifest",
    "model_release_revision",
    "read_model_release_manifest",
    "verify_model_release_manifest",
]
