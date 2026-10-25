"""Explicit account-private sharing and pinned import of native model byte facts.

Service configurations authenticate the selection. These records establish byte
validity only; admission, rights and signing authority stay with each consumer.
"""

from __future__ import annotations

import os
import stat
from contextlib import nullcontext
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .competition_model_cache_space import disjoint
from .competition_transport_verification import ByteCheckpoints, TransferProgress
from .file_identity import file_fingerprint
from .open_competition import digest
from .private_files import Directory, ensure_private_directory, lock_private_file, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex

MAX_EXPORT_BYTES = 64 * 1024**2
MAX_DOCUMENT_BYTES = 16 * 1024**2


class ModelByteStoreImport(StrictProtocolModel):
    directory: Directory
    export_sha256: Hex32


class ModelByteStoreConfig(StrictProtocolModel):
    schema_: Literal["umi-model-byte-verification-store/1"] = Field(alias="schema")
    directory: Directory
    imports: Annotated[tuple[ModelByteStoreImport, ...], Field(max_length=4096)] = ()

    @model_validator(mode="after")
    def separate_imports(self):
        keys = tuple((v.directory, v.export_sha256) for v in self.imports)
        if keys != tuple(sorted(set(keys))) or any(
            not disjoint(Path(self.directory), Path(v.directory)) for v in self.imports
        ):
            raise ValueError("byte-store imports must be unique, ordered and separate")
        return self


_IdentityInteger = Annotated[str, Field(pattern=r"^-?[0-9]{1,24}$")]


class _MetadataPin(StrictProtocolModel):
    sha256: Hex32
    identity: Annotated[tuple[_IdentityInteger, ...], Field(min_length=9, max_length=9)]


class _ExportedObject(StrictProtocolModel):
    key: Annotated[str, Field(min_length=1, max_length=256)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=1)]
    etag: Annotated[str, Field(min_length=1, max_length=256)]


class _ExportedFile(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=0)]
    remote_objects: Annotated[tuple[_ExportedObject, ...], Field(max_length=131072)]
    receipt: _MetadataPin
    marker: _MetadataPin
    document: _MetadataPin | None


class _ByteExport(StrictProtocolModel):
    schema_: Literal["umi-model-byte-verification-export/1"] = Field(alias="schema")
    source_directory: Directory
    source_identity: tuple[_IdentityInteger, _IdentityInteger, _IdentityInteger]
    context: dict[str, Any]
    selection_sha256: Hex32
    provenance_sha256: Hex32
    model_sha256: Hex32
    files: Annotated[tuple[_ExportedFile, ...], Field(min_length=7, max_length=4096)]


def validate_shared_byte_stores(sources, protected=()):
    """Equal *explicit* stores may be shared; unrelated path rules stay intact."""
    protected = tuple(protected)
    stores = {}
    for source in sources:
        value = source.shared_byte_store
        if value is None:
            continue
        key = Path(value.directory)
        if key in stores and stores[key] != value:
            raise ValueError("shared byte-store selections conflict")
        stores[key] = value
    roots = tuple(stores)
    if any(not disjoint(a, b) for i, a in enumerate(roots) for b in roots[i + 1 :]) or any(
        not disjoint(a, Path(b)) for a in roots for b in protected
    ):
        raise ValueError("shared byte store overlaps protected state or cache")
    return tuple(stores.values())


def shared_byte_store_paths(sources):
    return tuple(Path(v.directory) for v in validate_shared_byte_stores(sources))


def qualify_shared_byte_stores(sources, *, report=None):
    """Prove account ownership and writable namespace before service startup.

    Config inventories expose these same roots to installed namespace/upgrade
    checks. This acquires no signing key and touches only a bounded access lock.
    A completed target need not keep mounting already imported old source roots.
    """
    roots = shared_byte_store_paths(sources)
    if not roots:
        return
    with TransferProgress(
        "model_byte_store_access",
        len(roots),
        report,
        unit="stores",
        planning_unit_seconds=(0.001, 0.1),
    ) as progress:
        for root in roots:
            try:
                ensure_private_directory(root)
                descriptor = lock_private_file(root / ".access.lock")
                os.close(descriptor)
            except (OSError, ValueError):
                progress.emit("repair_required", reason="model_byte_store_namespace_unavailable")
                raise
            progress.advance(1)


def _directory_identity(path):
    private_path(str(path))
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("byte-store source directory must be owned and not publicly writable")
    return [str(v) for v in (info.st_dev, info.st_ino, info.st_uid)]


def _read(path, maximum):
    """Bounded stable metadata only; never open a declared model payload."""
    private_path(str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or not 0 <= info.st_size <= maximum
        ):
            raise ValueError("byte-store metadata must be bounded, owned and private")
        raw = stream.read(maximum + 1)
        stamp = [str(v) for v in file_fingerprint(info)]
        if len(raw) != info.st_size or any(
            [str(v) for v in file_fingerprint(current)] != stamp
            for current in (os.fstat(stream.fileno()), path.lstat())
        ):
            raise ValueError("byte-store metadata changed while reading")
    return raw, stamp


def _pin(path, maximum):
    raw, stamp = _read(path, maximum)
    return raw, {"sha256": sha256_hex(raw), "identity": stamp}


def _pinned(path, pin, maximum):
    raw, actual = _pin(path, maximum)
    if actual != pin.model_dump(mode="json"):
        raise ValueError("selected byte-store source metadata changed; repair required")
    return raw


def export_completed_byte_facts(reader, heads, *, report=None, checkpoint=None):
    """Build a native export from every exact completed private file result.

    The authenticated reader's caller owns lineage; current generations were
    obtained immediately before this operation and must be confirmed afterward.
    This produces an unsigned local snapshot, never adoption or release authority.
    """
    root = reader.root
    identity = _directory_identity(root)
    values = []
    with (
        TransferProgress(
            "model_byte_store_export",
            len(reader.selection.bundle.files),
            report,
            unit="files",
            planning_unit_seconds=(0.001, 0.1),
        ) as progress,
        reader._store(progress) if checkpoint is None else nullcontext(checkpoint) as saved,
    ):
        reader._migrate_remote_receipts(saved, heads, report=report)
        for record, item in zip(
            reader.selection.bundle.files, reader.selection.package.files, strict=True
        ):
            source = reader._source(item, heads)
            if saved.load(record.path, source, repair_completion=False) != record.sha256:
                progress.emit("repair_required", reason="byte_store_export_incomplete")
                raise OSError("native completed byte source requires repair before export")
            receipt = saved.path(record.path)
            try:
                _, receipt_pin = _pin(receipt, MAX_EXPORT_BYTES)
                marker_raw, marker_pin = _pin(receipt.with_suffix(".complete"), 64)
            except (OSError, ValueError):
                progress.emit("repair_required", reason="byte_store_export_incomplete")
                raise
            if marker_raw != receipt.stem.encode():
                progress.emit("repair_required", reason="byte_store_export_marker_incomplete")
                raise OSError("native completion marker requires repair before export")
            document = None
            path = saved.root / (sha256_hex(record.path.encode()) + ".document")
            if not path.exists() and record.role in {"license", "provenance"}:
                reader._migrate_remote_document(saved, record, MAX_DOCUMENT_BYTES, report)
            if path.exists():
                raw, document = _pin(path, MAX_DOCUMENT_BYTES)
                if len(raw) != record.size_bytes or sha256_hex(raw) != record.sha256:
                    progress.emit("repair_required", reason="byte_store_export_document_damaged")
                    raise OSError("native retained document requires repair before export")
            values.append(
                {
                    "path": record.path,
                    "sha256": record.sha256,
                    "size_bytes": record.size_bytes,
                    "remote_objects": source,
                    "receipt": receipt_pin,
                    "marker": marker_pin,
                    "document": document,
                }
            )
            progress.advance(1)
    if _directory_identity(root) != identity:
        raise ValueError("byte-store source directory changed")
    return {
        "schema": "umi-model-byte-verification-export/1",
        "source_directory": str(root),
        "source_identity": identity,
        "context": reader._remote_context(),
        "selection_sha256": digest(reader.selection),
        "provenance_sha256": reader.selection.binding.provenance_sha256,
        "model_sha256": reader.selection.binding.model_sha256,
        "files": values,
    }


def publish_byte_export(reader, value):
    value = _ByteExport.model_validate_json(canonical_json_bytes(value))
    raw = canonical_json_bytes(value)
    if len(raw) > MAX_EXPORT_BYTES:
        raise ValueError("complete byte-store export exceeds bounded metadata")
    root = reader.root / "exports"
    ensure_private_directory(root)
    path = root / (sha256_hex(raw) + ".json")
    with (
        TransferProgress("model_byte_store_export_publication", 1, unit="exports") as progress,
        ByteCheckpoints(root, {"scope": "byte-store-export-publication/1"}, progress) as store,
    ):
        try:
            prior, _ = _read(path, MAX_EXPORT_BYTES)
        except FileNotFoundError:
            store._write(path, raw)
        else:
            if prior != raw:
                raise ValueError("native byte export changed")
        progress.advance(1)
    return ModelByteStoreImport(directory=str(reader.root), export_sha256=sha256_hex(raw))


def _needs_document(saved, record, names):
    if record.path not in names:
        return False
    path = saved.root / (sha256_hex(record.path.encode()) + ".document")
    try:
        raw, _ = _read(path, MAX_DOCUMENT_BYTES)
    except FileNotFoundError:
        return True
    return len(raw) != record.size_bytes or sha256_hex(raw) != record.sha256


def import_completed_byte_facts(reader, saved, heads, imports, *, document_paths=(), report=None):
    """Checkpoint exact pinned byte facts, without payload I/O or source writes.

    Each source is an immutable hash-pinned snapshot; stable metadata reads avoid
    nested source/target locks. The target holds its ordinary private store lock.
    Its native verify operation confirms current generations again before return.
    Completed target facts survive removal of the old source; repair of a missing
    target fact requires its explicitly selected source until native re-export.
    """
    if not imports:
        return
    records = reader.selection.bundle.files
    names = set(document_paths)
    pending = {
        record.path
        for record, item in zip(records, reader.selection.package.files, strict=True)
        if saved.load(record.path, reader._source(item, heads)) != record.sha256
        or _needs_document(saved, record, names)
    }
    if not pending:
        return
    for selected in imports:
        root = Path(selected.directory)
        try:
            identity = _directory_identity(root)
            raw, _ = _read(root / "exports" / (selected.export_sha256 + ".json"), MAX_EXPORT_BYTES)
            if sha256_hex(raw) != selected.export_sha256:
                raise ValueError("selected byte-store export digest changed")
            value = _ByteExport.model_validate_json(raw)
            if canonical_json_bytes(value) != raw:
                raise ValueError("native byte-store export shape changed")
            if value.source_directory != str(root) or list(value.source_identity) != identity:
                raise ValueError("native byte-store export source root changed")
        except (OSError, ValueError, TypeError, UnicodeError):
            saved.progress.emit("repair_required", reason="selected_byte_store_export_unavailable")
            raise
        if (
            value.model_sha256 != reader.selection.binding.model_sha256
            or value.context != reader._remote_context()
        ):
            continue  # Other explicitly selected model/context; conveys no current fact.
        if [(f.path, f.sha256, f.size_bytes) for f in value.files] != [
            (f.path, f.sha256, f.size_bytes) for f in records
        ]:
            saved.progress.emit("repair_required", reason="byte_store_export_files_changed")
            raise ValueError("byte-store export omits or changes signed files")
        source_root = root / value.model_sha256 / "remote-bytes-v2" / digest(value.context)
        source_store = ByteCheckpoints(source_root, value.context, saved.progress)
        with TransferProgress(
            "model_byte_store_import",
            len(records),
            report,
            unit="files",
            planning_unit_seconds=(0.001, 0.1),
        ) as progress:
            try:
                _directory_identity(source_root)
                for record, item, pin in zip(
                    records, reader.selection.package.files, value.files, strict=True
                ):
                    source = reader._source(item, heads)
                    prior = saved.load(record.path, source)
                    document_path = saved.root / (sha256_hex(record.path.encode()) + ".document")
                    want_document = _needs_document(saved, record, names)
                    if prior == record.sha256 and not want_document:
                        progress.advance(1, restored=True)
                        continue
                    expected_objects = [v.model_dump(mode="json") for v in pin.remote_objects]
                    if expected_objects != source:
                        progress.emit("repair_required", reason="byte_store_generation_changed")
                        progress.advance(1)
                        continue  # This affected file uses the native byte check below.
                    path = source_store.path(record.path)
                    receipt = _pinned(path, pin.receipt, MAX_EXPORT_BYTES)
                    marker = _pinned(path.with_suffix(".complete"), pin.marker, 64)
                    fact = ByteCheckpoints._validated_record(receipt)
                    if (
                        marker != path.stem.encode()
                        or fact["context"] != source_store.context
                        or fact["result"] != record.sha256
                        or fact["identity"] != expected_objects
                    ):
                        raise ValueError("native byte-store exported fact differs")
                    if want_document and pin.document is not None:
                        progress.emit("repair_required", reason="byte_store_document_restore")
                        doc = _pinned(
                            source_root / document_path.name, pin.document, MAX_DOCUMENT_BYTES
                        )
                        if len(doc) != record.size_bytes or sha256_hex(doc) != record.sha256:
                            raise ValueError("native byte-store document differs")
                        saved._write(document_path, doc)
                    if prior != record.sha256:
                        saved.remember(record.path, source, record.sha256)
                    pending.discard(record.path)
                    progress.advance(1, restored=True)
                if _directory_identity(root) != identity:
                    raise ValueError("byte-store source directory changed during import")
            except (OSError, ValueError, TypeError, UnicodeError):
                progress.emit(
                    "repair_required", reason="byte_store_import_source_missing_or_damaged"
                )
                raise
        if not pending:
            return
