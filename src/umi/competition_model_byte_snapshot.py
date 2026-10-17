"""Portable metadata for explicitly selected native model byte results.

Root-controlled operator requests own snapshot trust. These objects retain the
original native export verbatim and carry bounded documents separately; they
are never model, admission, certification, or current-generation authority.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chunked_model_backup import BYTE_ABI
from .competition_model_byte_store import (
    MAX_DOCUMENT_BYTES,
    MAX_EXPORT_BYTES,
    ModelByteStoreImport,
    _ByteExport,
    _directory_identity,
    _pinned,
    _read,
)
from .competition_transport_verification import (
    ByteCheckpoints,
    TransferProgress,
    verifier_semantics,
)
from .competition_transport_verification import (
    _raw as checkpoint_bytes,
)
from .competition_transport_verification import (
    _sha as checkpoint_digest,
)
from .open_competition import digest
from .private_files import Directory, ensure_private_directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex


class PortableByteSnapshotPin(StrictProtocolModel):
    directory: Directory
    snapshot_sha256: Hex32
    export_sha256: Hex32
    model_sha256: Hex32
    context_sha256: Hex32


class _Document(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=0, le=MAX_DOCUMENT_BYTES)]


class _Snapshot(StrictProtocolModel):
    schema_: Literal["umi-model-byte-portable-snapshot/1"] = Field(alias="schema")
    export_sha256: Hex32
    model_sha256: Hex32
    context_sha256: Hex32
    documents: Annotated[tuple[_Document, ...], Field(max_length=4096)]

    @model_validator(mode="after")
    def ordered_documents(self):
        names = tuple(v.path for v in self.documents)
        if names != tuple(sorted(set(names))):
            raise ValueError("portable documents must be unique and ordered")
        return self


def portable_member_key(kind: str, sha: str) -> str:
    """Bound directory fan-out instead of relying on filesystem large_dir."""
    if (
        kind not in {"documents", "exports", "snapshots"}
        or len(sha) != 64
        or any(c not in "0123456789abcdef" for c in sha)
    ):
        raise ValueError("portable snapshot member identity differs")
    return f"{kind}/{sha[:2]}/{sha[2:4]}/{sha}.json"


def portable_member_path(root: Path, kind: str, sha: str) -> Path:
    path = root / portable_member_key(kind, sha)
    return path.with_suffix(".document") if kind == "documents" else path


def _export(raw, expected):
    if sha256_hex(raw) != expected:
        raise ValueError("selected original native export digest changed")
    value = _ByteExport.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("original native export encoding changed")
    if value.context.get("semantics") != [BYTE_ABI, verifier_semantics()]:
        raise ValueError("portable byte results require compatible verifier semantics")
    return value


def _fact(value, file):
    """Reproduce metadata only when its original native digest proves identity."""
    fact = {
        "schema": "umi-private-byte-verification/1",
        "context": checkpoint_digest(value.context),
        "identity": [v.model_dump(mode="json") for v in file.remote_objects],
        "result": file.sha256,
    }
    fact["checksum"] = checkpoint_digest(fact)
    raw = checkpoint_bytes(fact)
    marker = checkpoint_digest(file.path).encode()
    if sha256_hex(raw) != file.receipt.sha256 or sha256_hex(marker) != file.marker.sha256:
        raise ValueError("portable result differs from original native completion")
    ByteCheckpoints._validated_record(raw)
    return fact


def _source_root(value, root):
    return root / value.model_sha256 / "remote-bytes-v2" / digest(value.context)


def _publish(store, path, raw):
    """Never replace a changed immutable metadata member."""
    ensure_private_directory(path.parent)
    try:
        prior, _ = _read(path, max(MAX_EXPORT_BYTES, MAX_DOCUMENT_BYTES))
    except FileNotFoundError:
        store._write(path, raw)
    else:
        if prior != raw:
            raise ValueError("portable snapshot member requires explicit repair")


def _capture_original(source, *, report=None):
    with TransferProgress(
        "model_byte_snapshot_capture_selection",
        1,
        report,
        unit="snapshots",
        planning_unit_seconds=(0.01, 30.0),
    ) as selection:
        root = Path(source.directory)
        identity = _directory_identity(root)
        raw, _ = _read(root / "exports" / (source.export_sha256 + ".json"), MAX_EXPORT_BYTES)
        value = _export(raw, source.export_sha256)
        if value.source_directory != str(root) or list(value.source_identity) != identity:
            raise ValueError("original native export source root changed")
        with TransferProgress(
            "model_byte_snapshot_capture_coverage",
            len(value.files),
            report,
            unit="files",
            planning_unit_seconds=(0.001, 0.1),
        ) as coverage:
            for file in value.files:
                _fact(value, file)
                coverage.advance(1)
        selection.advance(1)
        return root, identity, raw, value


def capture_portable_snapshot(source: ModelByteStoreImport, directory: Path, *, report=None):
    """Capture one native export plus documents; read no model payloads.

    Select only pins produced by the authenticated native export operation. The
    protected caller must keep that provenance when replicating these members.
    """
    root, identity, raw, value = _capture_original(source, report=report)
    if directory == root or directory in root.parents or root in directory.parents:
        raise ValueError("portable snapshots must be separate from native source state")
    ensure_private_directory(directory)
    documents = directory / "documents"
    exports = directory / "exports"
    snapshots = directory / "snapshots"
    for path in (documents, exports, snapshots):
        ensure_private_directory(path)
    old = _source_root(value, root)
    _directory_identity(old)
    records = []
    with (
        TransferProgress(
            "model_byte_portable_capture",
            len(value.files),
            report,
            unit="files",
            planning_unit_seconds=(0.001, 0.1),
        ) as progress,
        ByteCheckpoints(
            directory, {"scope": "portable-byte-snapshot-publication/1"}, progress
        ) as _publication,
    ):
        for file in value.files:
            receipt = old / (checkpoint_digest(file.path) + ".json")
            _pinned(receipt, file.receipt, MAX_EXPORT_BYTES)
            _pinned(receipt.with_suffix(".complete"), file.marker, 64)
            if file.document is not None:
                data = _pinned(
                    old / (sha256_hex(file.path.encode()) + ".document"),
                    file.document,
                    MAX_DOCUMENT_BYTES,
                )
                if len(data) != file.size_bytes or sha256_hex(data) != file.sha256:
                    raise ValueError("portable document differs from signed file")
                # Publication has one private writer; objects are immutable and
                # content-addressed. Per-object native writes remain atomic.
                path = portable_member_path(directory, "documents", file.sha256)
                writer = ByteCheckpoints(path.parent, {}, progress)
                _publish(writer, path, data)
                records.append(
                    _Document(path=file.path, sha256=file.sha256, size_bytes=file.size_bytes)
                )
            progress.advance(1)
        if _directory_identity(root) != identity:
            raise ValueError("original native root changed during portable capture")
        path = portable_member_path(directory, "exports", source.export_sha256)
        _publish(ByteCheckpoints(path.parent, {}, progress), path, raw)
        snapshot = _Snapshot(
            schema="umi-model-byte-portable-snapshot/1",
            export_sha256=source.export_sha256,
            model_sha256=value.model_sha256,
            context_sha256=digest(value.context),
            documents=tuple(sorted(records, key=lambda v: v.path)),
        )
        encoded = canonical_json_bytes(snapshot)
        if len(encoded) > MAX_EXPORT_BYTES:
            raise ValueError("portable snapshot metadata exceeds native export capacity")
        sha = sha256_hex(encoded)
        path = portable_member_path(directory, "snapshots", sha)
        _publish(ByteCheckpoints(path.parent, {}, progress), path, encoded)
    return PortableByteSnapshotPin(
        directory=str(directory),
        snapshot_sha256=sha,
        export_sha256=source.export_sha256,
        model_sha256=value.model_sha256,
        context_sha256=digest(value.context),
    )


def _selected_snapshot(pin, *, report=None):
    with TransferProgress(
        "model_byte_snapshot_selection",
        1,
        report,
        unit="snapshots",
        planning_unit_seconds=(0.01, 30.0),
    ) as progress:
        try:
            result = _load_selected_snapshot(pin, report=report)
        except (OSError, ValueError, TypeError, UnicodeError):
            progress.emit("refused", reason="selected_portable_snapshot_unavailable_or_changed")
            raise
        progress.advance(1)
        return result


def _load_selected_snapshot(pin, *, report=None):
    root = Path(pin.directory)
    _directory_identity(root)
    raw, _ = _read(portable_member_path(root, "snapshots", pin.snapshot_sha256), MAX_EXPORT_BYTES)
    if sha256_hex(raw) != pin.snapshot_sha256:
        raise ValueError("selected portable snapshot digest changed")
    snapshot = _Snapshot.model_validate_json(raw)
    if canonical_json_bytes(snapshot) != raw or (
        snapshot.export_sha256,
        snapshot.model_sha256,
        snapshot.context_sha256,
    ) != (pin.export_sha256, pin.model_sha256, pin.context_sha256):
        raise ValueError("portable snapshot differs from protected original selection")
    raw, _ = _read(portable_member_path(root, "exports", pin.export_sha256), MAX_EXPORT_BYTES)
    value = _export(raw, pin.export_sha256)
    if value.source_identity[2] != str(os.getuid()):
        raise ValueError("portable native results require their original service UID")
    if (value.model_sha256, digest(value.context)) != (pin.model_sha256, pin.context_sha256):
        raise ValueError("portable snapshot model or validation context changed")
    expected = tuple(
        (v.path, v.sha256, v.size_bytes) for v in value.files if v.document is not None
    )
    if tuple((v.path, v.sha256, v.size_bytes) for v in snapshot.documents) != tuple(
        sorted(expected)
    ):
        raise ValueError("portable snapshot omits or changes retained documents")
    with TransferProgress(
        "model_byte_snapshot_fact_validation",
        len(value.files),
        report,
        unit="files",
        planning_unit_seconds=(0.001, 0.1),
    ) as progress:
        for file in value.files:
            _fact(value, file)
            progress.advance(1)
    return root, value


def restore_portable_snapshot(pin: PortableByteSnapshotPin, directory: Path, *, report=None):
    """Restore selected old facts to a new private root, without old filesystem IDs.

    No signed input or original export is rewritten. Ordinary native consumers
    still authenticate inputs and confirm current generations before reuse.
    """
    source, value = _selected_snapshot(pin, report=report)
    if directory == source or directory in source.parents or source in directory.parents:
        raise ValueError("portable restoration must be separate from its snapshot")
    ensure_private_directory(directory)
    target = _source_root(value, directory)
    restored = reused = 0
    with (
        TransferProgress(
            "model_byte_portable_restore",
            len(value.files),
            report,
            unit="files",
            planning_unit_seconds=(0.001, 0.1),
        ) as progress,
        ByteCheckpoints(target, value.context, progress) as saved,
    ):
        for file in value.files:
            fact = _fact(value, file)
            receipt = saved.path(file.path)
            # Never replace an intact newer-generation fact with this snapshot.
            try:
                existing_raw, _ = _read(receipt, MAX_EXPORT_BYTES)
            except FileNotFoundError:
                existing = None
            else:
                try:
                    existing = saved._validated_record(existing_raw)
                except (TypeError, ValueError, UnicodeError):
                    existing = None
                    progress.emit("repair_required", reason="portable_target_receipt_damaged")
            if existing is not None and (
                existing["context"],
                existing["identity"],
                existing["result"],
            ) != (fact["context"], fact["identity"], fact["result"]):
                raise ValueError("portable restoration conflicts with existing native fact")
            prior = saved.load(file.path, fact["identity"])
            if prior != file.sha256:
                saved.remember(file.path, fact["identity"], file.sha256)
                restored += 1
            else:
                reused += 1
            if file.document is not None:
                path = saved.root / (sha256_hex(file.path.encode()) + ".document")
                try:
                    data, _ = _read(path, MAX_DOCUMENT_BYTES)
                except FileNotFoundError:
                    data = None
                if data is None or len(data) != file.size_bytes or sha256_hex(data) != file.sha256:
                    progress.emit("repair_required", reason="portable_target_document_restore")
                    data, _ = _read(
                        portable_member_path(source, "documents", file.sha256), MAX_DOCUMENT_BYTES
                    )
                    if len(data) != file.size_bytes or sha256_hex(data) != file.document.sha256:
                        raise ValueError("portable document differs from native completion")
                    saved._write(path, data)
                    progress.emit("repair_completed", reason="portable_document_restored")
            progress.advance(1, restored=prior != file.sha256)
    return {
        "model_sha256": value.model_sha256,
        "files": len(value.files),
        "restored_files": restored,
        "reused_files": reused,
        "source_snapshot_sha256": pin.snapshot_sha256,
        "original_export_sha256": pin.export_sha256,
        "current_generation_checks_performed": False,
        "model_payloads_read": False,
        "certification_authority": False,
    }
