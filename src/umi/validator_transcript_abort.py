"""Immutable restart binding for an in-flight no-score decision.

The stage journal remains the evidence authority.  This registry stores only the
canonical origin object and the digest of the journal receipt that first carried
it.  The origin can be a transcript failure or a fully evidenced pool decision
that issued no assignments.  Later transcript effects can propagate that exact
decision without needing a broader journal reader port.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .protocol import PROTOCOL_VERSION, canonical_json_bytes
from .validator_journal import StageJournalRecord

TRANSCRIPT_ABORT_REGISTRY_SCHEMA = "umi-validator-transcript-abort-registry/1"
MAX_TRANSCRIPT_ABORT_ORIGIN_BYTES = 64 * 1024

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_STAGES = frozenset({"pool_and_selection", "assignment", "request_transcript", "sealed_response"})


class TranscriptAbortRegistryError(RuntimeError):
    """The durable abort binding is missing, conflicting, or corrupted."""


@dataclass(frozen=True, slots=True)
class TranscriptAbortRegistryEntry:
    window_id: str
    origin_stage: str
    origin_receipt_evidence_sha256: str
    origin_sha256: str
    origin_bytes: bytes


class DurableTranscriptAbortRegistry:
    """One immutable, content-checked abort-origin pointer per window."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        _prepare_directory(self.root)
        self.audit()

    def record(
        self,
        *,
        window_id: str,
        origin_stage: str,
        origin_receipt_evidence_sha256: str,
        origin_bytes: bytes,
    ) -> TranscriptAbortRegistryEntry:
        entry = _entry(
            window_id=window_id,
            origin_stage=origin_stage,
            origin_receipt_evidence_sha256=origin_receipt_evidence_sha256,
            origin_bytes=origin_bytes,
        )
        encoded = _entry_bytes(entry)
        path = self._path(window_id)
        if path.exists():
            existing = self.load(window_id)
            if existing != entry:
                raise TranscriptAbortRegistryError("transcript_abort_origin_conflict")
            return existing
        _write_exclusive(path, encoded)
        existing = self.load(window_id)
        if existing != entry:
            raise TranscriptAbortRegistryError("transcript_abort_origin_write_mismatch")
        return existing

    def load(self, window_id: str) -> TranscriptAbortRegistryEntry | None:
        path = self._path(window_id)
        if not path.exists():
            return None
        encoded = _read_regular(path, MAX_TRANSCRIPT_ABORT_ORIGIN_BYTES * 2)
        return _parse_entry(encoded)

    def audit(self) -> None:
        for path in self.root.iterdir():
            if (
                not path.is_file()
                or _HEX32_RE.fullmatch(path.stem) is None
                or path.suffix != ".json"
            ):
                raise TranscriptAbortRegistryError("transcript_abort_registry_entry_unsafe")
            entry = _parse_entry(_read_regular(path, MAX_TRANSCRIPT_ABORT_ORIGIN_BYTES * 2))
            if path.name != f"{entry.window_id}.json":
                raise TranscriptAbortRegistryError("transcript_abort_registry_name_mismatch")

    def _path(self, window_id: str) -> Path:
        return self.root / f"{_hex32(window_id, 'window ID')}.json"


def read_receipt_objects(record: StageJournalRecord) -> dict[str, bytes]:
    """Read only objects named by one already-verified stage receipt.

    This is intentionally lock-independent and layout-bound to the journal
    record's own receipt path.  Every returned object is checked against the
    digest and length retained in that receipt.
    """

    if not isinstance(record, StageJournalRecord):
        raise TypeError("record must be StageJournalRecord")
    receipt_directory = record.path.parent.parent
    if receipt_directory.name != "receipts":
        raise TranscriptAbortRegistryError("transcript_abort_receipt_path_invalid")
    journal_root = receipt_directory.parent
    objects_root = journal_root / "objects"
    if objects_root.is_symlink() or not objects_root.is_dir():
        raise TranscriptAbortRegistryError("transcript_abort_object_store_unsafe")
    payloads: dict[str, bytes] = {}
    for reference in record.receipt.objects:
        data = _read_regular(objects_root / reference.sha256, reference.size_bytes)
        if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != (
            reference.sha256
        ):
            raise TranscriptAbortRegistryError("transcript_abort_receipt_object_mismatch")
        payloads[reference.sha256] = data
    return payloads


def _entry(
    *,
    window_id: str,
    origin_stage: str,
    origin_receipt_evidence_sha256: str,
    origin_bytes: bytes,
) -> TranscriptAbortRegistryEntry:
    window = _hex32(window_id, "window ID")
    receipt = _hex32(origin_receipt_evidence_sha256, "origin receipt digest")
    if origin_stage not in _STAGES:
        raise ValueError("no-score origin stage is unsupported")
    if not isinstance(origin_bytes, bytes) or not 0 < len(origin_bytes) <= (
        MAX_TRANSCRIPT_ABORT_ORIGIN_BYTES
    ):
        raise ValueError("abort origin bytes have an invalid size")
    try:
        decoded = json.loads(origin_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("abort origin is not JSON") from error
    if not isinstance(decoded, dict) or canonical_json_bytes(decoded) != origin_bytes:
        raise ValueError("abort origin is not an exact canonical JSON object")
    return TranscriptAbortRegistryEntry(
        window_id=window,
        origin_stage=origin_stage,
        origin_receipt_evidence_sha256=receipt,
        origin_sha256=hashlib.sha256(origin_bytes).hexdigest(),
        origin_bytes=origin_bytes,
    )


def _entry_bytes(entry: TranscriptAbortRegistryEntry) -> bytes:
    return canonical_json_bytes(
        {
            "schema": TRANSCRIPT_ABORT_REGISTRY_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window_id": entry.window_id,
            "origin_stage": entry.origin_stage,
            "origin_receipt_evidence_sha256": entry.origin_receipt_evidence_sha256,
            "origin_sha256": entry.origin_sha256,
            "origin": json.loads(entry.origin_bytes),
        }
    )


def _parse_entry(encoded: bytes) -> TranscriptAbortRegistryEntry:
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TranscriptAbortRegistryError("transcript_abort_registry_invalid") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "protocol",
            "window_id",
            "origin_stage",
            "origin_receipt_evidence_sha256",
            "origin_sha256",
            "origin",
        }
        or value["schema"] != TRANSCRIPT_ABORT_REGISTRY_SCHEMA
        or value["protocol"] != PROTOCOL_VERSION
        or canonical_json_bytes(value) != encoded
        or not isinstance(value["origin"], dict)
    ):
        raise TranscriptAbortRegistryError("transcript_abort_registry_invalid")
    origin_bytes = canonical_json_bytes(value["origin"])
    try:
        entry = _entry(
            window_id=value["window_id"],
            origin_stage=value["origin_stage"],
            origin_receipt_evidence_sha256=value["origin_receipt_evidence_sha256"],
            origin_bytes=origin_bytes,
        )
    except (TypeError, ValueError) as error:
        raise TranscriptAbortRegistryError("transcript_abort_registry_invalid") from error
    if entry.origin_sha256 != value["origin_sha256"] or _entry_bytes(entry) != encoded:
        raise TranscriptAbortRegistryError("transcript_abort_registry_digest_mismatch")
    return entry


def _prepare_directory(path: Path) -> None:
    if os.path.lexists(path) and path.is_symlink():
        raise TranscriptAbortRegistryError("transcript_abort_registry_directory_unsafe")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = path.stat()
    except OSError as error:
        raise TranscriptAbortRegistryError("transcript_abort_registry_unavailable") from error
    if not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o022:
        raise TranscriptAbortRegistryError("transcript_abort_registry_directory_unsafe")


def _read_regular(path: Path, maximum_bytes: int) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or not 0 <= before.st_size <= maximum_bytes
        ):
            raise TranscriptAbortRegistryError("transcript_abort_registry_entry_unsafe")
        data = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except TranscriptAbortRegistryError:
        raise
    except OSError as error:
        raise TranscriptAbortRegistryError("transcript_abort_registry_entry_unavailable") from error
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or len(data) != before.st_size:
        raise TranscriptAbortRegistryError("transcript_abort_registry_entry_changed")
    return data


def _write_exclusive(path: Path, data: bytes) -> None:
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".abort-", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("abort registry write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise TranscriptAbortRegistryError("transcript_abort_registry_write_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _hex32(value: str, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase SHA-256 hexadecimal")
    return value


__all__ = [
    "MAX_TRANSCRIPT_ABORT_ORIGIN_BYTES",
    "TRANSCRIPT_ABORT_REGISTRY_SCHEMA",
    "DurableTranscriptAbortRegistry",
    "TranscriptAbortRegistryEntry",
    "TranscriptAbortRegistryError",
    "read_receipt_objects",
]
