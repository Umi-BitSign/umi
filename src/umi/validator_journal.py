"""Crash-safe, content-addressed stage evidence for the live validator.

The control-plane database stores only the digest that authorizes a stage
transition.  This journal stores the exact receipt and objects behind that digest.
An adapter writes its deterministic receipt before returning ``StageCompletion``;
after a crash, writing the same receipt is idempotent and writing different bytes
for the same window/stage fails closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, JsonValue, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, ObjectRef
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_state import MAX_OPERATION_ID_BYTES, STAGE_ORDER, WindowStage

STAGE_RECEIPT_SCHEMA = "umi-validator-stage-receipt/1"
STAGE_RECEIPT_MEDIA_TYPE = "application/vnd.umi.validator-stage-receipt+json"
MAX_STAGE_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_STAGE_OBJECT_BYTES = 64 * 1024 * 1024
MAX_JOURNAL_OBJECT_BYTES = 384 * 1024 * 1024
MAX_JOURNAL_RETAINED_OBJECT_BYTES = 512 * 1024 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_OPERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")


class StageJournalError(RuntimeError):
    """Base class for a stable journal failure."""


class StageJournalConflict(StageJournalError):
    """A window/stage already has a different authoritative receipt."""


class StageObject(StrictProtocolModel):
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    media_type: Annotated[str, Field(min_length=1, max_length=256)]
    size_bytes: Annotated[int, Field(ge=0)]

    @classmethod
    def from_ref(cls, reference: ObjectRef) -> StageObject:
        return cls.model_validate(reference.as_dict())


class StageReceipt(StrictProtocolModel):
    schema_: Literal[STAGE_RECEIPT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    stage: Literal[
        "pool_and_selection",
        "assignment",
        "request_transcript",
        "sealed_response",
        "reveal_and_score",
        "weight_build",
        "commit_and_terminal_state",
    ]
    operation_id: Annotated[str, Field(min_length=1, max_length=MAX_OPERATION_ID_BYTES)]
    objects: Annotated[list[StageObject], Field(min_length=1)]
    metadata: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_canonical_fields(self) -> Self:
        if _OPERATION_RE.fullmatch(self.operation_id) is None:
            raise ValueError("operation ID contains unsupported characters")
        digests = [bytes.fromhex(item.sha256) for item in self.objects]
        if digests != sorted(digests) or len(set(digests)) != len(digests):
            raise ValueError("stage objects must be unique and sorted by raw digest")
        if any(not key or key.isspace() for key in self.metadata):
            raise ValueError("stage metadata keys must be non-empty")
        return self


@dataclass(frozen=True, slots=True)
class StageObjectInput:
    data: bytes
    media_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("stage object data must be exact bytes")
        if not isinstance(self.media_type, str) or not self.media_type:
            raise ValueError("stage object media type must be non-empty")


@dataclass(frozen=True, slots=True)
class StageJournalRecord:
    receipt: StageReceipt
    receipt_bytes: bytes
    evidence_sha256: str
    path: Path

    def __post_init__(self) -> None:
        if canonical_json_bytes(self.receipt) != self.receipt_bytes:
            raise ValueError("journal receipt bytes are not canonical")
        if hashlib.sha256(self.receipt_bytes).hexdigest() != self.evidence_sha256:
            raise ValueError("journal receipt digest does not reproduce")


class ValidatorStageJournal:
    """Durable object and receipt store shared by all live stage adapters."""

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_object_bytes: int = MAX_STAGE_OBJECT_BYTES,
        maximum_total_object_bytes: int = MAX_JOURNAL_OBJECT_BYTES,
        maximum_retained_object_bytes: int = MAX_JOURNAL_RETAINED_OBJECT_BYTES,
        maximum_receipt_bytes: int = MAX_STAGE_RECEIPT_BYTES,
    ) -> None:
        self.root = Path(root)
        self.receipts = self.root / "receipts"
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (
                maximum_object_bytes,
                maximum_total_object_bytes,
                maximum_retained_object_bytes,
                maximum_receipt_bytes,
            )
        ):
            raise ValueError("journal byte ceilings must be positive integers")
        if maximum_object_bytes > maximum_total_object_bytes:
            raise ValueError("one journal object cannot exceed the aggregate byte ceiling")
        if maximum_total_object_bytes > maximum_retained_object_bytes:
            raise ValueError("one window cannot exceed the retained-object byte ceiling")
        self.maximum_object_bytes = maximum_object_bytes
        self.maximum_total_object_bytes = maximum_total_object_bytes
        self.maximum_receipt_bytes = maximum_receipt_bytes
        self._store = EvidenceStore(
            self.root,
            maximum_object_bytes=maximum_object_bytes,
            maximum_manifest_bytes=maximum_receipt_bytes,
            maximum_total_object_bytes=maximum_retained_object_bytes,
        )
        self.receipts.mkdir(parents=True, exist_ok=True)
        if self.receipts.is_symlink() or not self.receipts.is_dir():
            raise ValueError("journal receipts path must be a real directory")
        self._audit_existing_receipts()

    def record(
        self,
        *,
        window_id: str,
        stage: WindowStage,
        operation_id: str,
        objects: Sequence[StageObjectInput],
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> StageJournalRecord:
        if not isinstance(stage, WindowStage):
            raise TypeError("stage must be a WindowStage")
        if isinstance(objects, (str, bytes, bytearray)) or not isinstance(objects, Sequence):
            raise TypeError("objects must be a sequence")
        inputs = tuple(objects)
        if any(not isinstance(item, StageObjectInput) for item in inputs):
            raise TypeError("objects must contain StageObjectInput values")
        if metadata is not None and not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")

        path = self._receipt_path(window_id, stage)
        if not os.path.lexists(path):
            stage_index = STAGE_ORDER.index(stage)
            if any(
                not os.path.lexists(self._receipt_path(window_id, prior))
                for prior in STAGE_ORDER[:stage_index]
            ):
                raise StageJournalConflict("a stage receipt cannot skip an earlier stage")
            if any(
                os.path.lexists(self._receipt_path(window_id, later))
                for later in STAGE_ORDER[stage_index + 1 :]
            ):
                raise StageJournalConflict("a new receipt cannot precede an existing later stage")

        references: dict[str, StageObject] = {}
        prospective: dict[str, int] = self._window_object_sizes(window_id)
        for item in inputs:
            if len(item.data) > self.maximum_object_bytes:
                raise ValueError("component evidence object exceeds its byte ceiling")
            digest = hashlib.sha256(item.data).hexdigest()
            previous_size = prospective.setdefault(digest, len(item.data))
            if previous_size != len(item.data):
                raise RuntimeError("one object digest has conflicting byte lengths")
        if sum(prospective.values()) > self.maximum_total_object_bytes:
            raise ValueError("window stage evidence exceeds its aggregate object-byte ceiling")
        for item in inputs:
            reference = StageObject.from_ref(self._store.add_bytes(item.data, item.media_type))
            previous = references.setdefault(reference.sha256, reference)
            if previous != reference:
                raise RuntimeError("one object digest has conflicting metadata")
        receipt = StageReceipt(
            schema=STAGE_RECEIPT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=window_id,
            stage=stage.value,
            operation_id=operation_id,
            objects=sorted(references.values(), key=lambda item: bytes.fromhex(item.sha256)),
            metadata=dict(metadata or {}),
        )
        encoded = canonical_json_bytes(receipt)
        if len(encoded) > self.maximum_receipt_bytes:
            raise StageJournalError("stage receipt exceeds its byte ceiling")
        digest = hashlib.sha256(encoded).hexdigest()
        parent_existed = path.parent.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise StageJournalError("window receipt path is not a real directory")
        if not parent_existed:
            _fsync_directory(self.receipts)
        try:
            _write_new_file(path, encoded)
        except FileExistsError:
            existing = _read_bounded_regular_file(path, self.maximum_receipt_bytes)
            if existing != encoded:
                raise StageJournalConflict(
                    f"window {window_id} stage {stage.value} already has another receipt"
                ) from None
        return StageJournalRecord(
            receipt=receipt,
            receipt_bytes=encoded,
            evidence_sha256=digest,
            path=path,
        )

    def load(self, window_id: str, stage: WindowStage) -> StageJournalRecord:
        if not isinstance(stage, WindowStage):
            raise TypeError("stage must be a WindowStage")
        path = self._receipt_path(window_id, stage)
        encoded = _read_bounded_regular_file(path, self.maximum_receipt_bytes)
        try:
            decoded = json.loads(encoded)
            receipt = StageReceipt.model_validate(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise StageJournalError("stage receipt is invalid") from error
        if canonical_json_bytes(receipt) != encoded:
            raise StageJournalError("stage receipt is not exact canonical JSON")
        if receipt.window_id != window_id or receipt.stage != stage.value:
            raise StageJournalError("stage receipt path and binding disagree")
        for reference in receipt.objects:
            self._store.read(reference.model_dump(mode="json"))
        return StageJournalRecord(
            receipt=receipt,
            receipt_bytes=encoded,
            evidence_sha256=hashlib.sha256(encoded).hexdigest(),
            path=path,
        )

    def load_window(self, window_id: str) -> tuple[StageJournalRecord, ...]:
        records: list[StageJournalRecord] = []
        missing_seen = False
        for stage in STAGE_ORDER:
            path = self._receipt_path(window_id, stage)
            if not os.path.lexists(path):
                missing_seen = True
                continue
            if missing_seen:
                raise StageJournalError("window stage receipts are not a complete prefix")
            records.append(self.load(window_id, stage))
        sizes: dict[str, int] = {}
        for record in records:
            for reference in record.receipt.objects:
                prior = sizes.setdefault(reference.sha256, reference.size_bytes)
                if prior != reference.size_bytes:
                    raise StageJournalError("one window object has conflicting byte lengths")
        if sum(sizes.values()) > self.maximum_total_object_bytes:
            raise StageJournalError(
                "window stage evidence exceeds its aggregate object-byte ceiling"
            )
        return tuple(records)

    def read_object(self, reference: StageObject) -> bytes:
        if not isinstance(reference, StageObject):
            raise TypeError("reference must be a StageObject")
        return self._store.read(reference.model_dump(mode="json"))

    def _receipt_path(self, window_id: str, stage: WindowStage) -> Path:
        if not isinstance(window_id, str) or re.fullmatch(r"[0-9a-f]{64}", window_id) is None:
            raise ValueError("window ID must be lowercase SHA-256 hexadecimal")
        return self.receipts / window_id / f"{stage.value}.json"

    def _window_object_sizes(self, window_id: str) -> dict[str, int]:
        """Return the unique object-byte accounting for one window only."""

        sizes: dict[str, int] = {}
        for record in self.load_window(window_id):
            for reference in record.receipt.objects:
                prior = sizes.setdefault(reference.sha256, reference.size_bytes)
                if prior != reference.size_bytes:
                    raise StageJournalError("one window object has conflicting byte lengths")
        return sizes

    def _audit_existing_receipts(self) -> None:
        for child in self.receipts.iterdir():
            if child.is_symlink() or not child.is_dir():
                raise StageJournalError("journal receipts contain an unsafe path")
            if re.fullmatch(r"[0-9a-f]{64}", child.name) is None:
                raise StageJournalError("journal receipts contain an invalid window directory")
            expected_names = {f"{stage.value}.json" for stage in STAGE_ORDER}
            actual_names = {path.name for path in child.iterdir()}
            if not actual_names.issubset(expected_names):
                raise StageJournalError("journal receipts contain an unknown stage file")
            self.load_window(child.name)


def _write_new_file(path: Path, data: bytes) -> None:
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            raise
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StageJournalError(f"stage receipt cannot be opened safely: {path.name}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise StageJournalError("stage receipt is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise StageJournalError("stage receipt exceeds its byte ceiling")
            chunks.append(chunk)
        if total != metadata.st_size:
            raise StageJournalError("stage receipt changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "MAX_JOURNAL_OBJECT_BYTES",
    "MAX_JOURNAL_RETAINED_OBJECT_BYTES",
    "MAX_STAGE_OBJECT_BYTES",
    "MAX_STAGE_RECEIPT_BYTES",
    "STAGE_RECEIPT_MEDIA_TYPE",
    "STAGE_RECEIPT_SCHEMA",
    "StageJournalConflict",
    "StageJournalError",
    "StageJournalRecord",
    "StageObject",
    "StageObjectInput",
    "StageReceipt",
    "ValidatorStageJournal",
]
