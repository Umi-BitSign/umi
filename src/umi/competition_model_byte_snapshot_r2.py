"""Immutable R2 replication and bounded retrieval of portable byte snapshots."""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_model_byte_snapshot import (
    PortableByteSnapshotPin,
    _selected_snapshot,
    portable_member_key,
    portable_member_path,
)
from .competition_model_byte_store import MAX_DOCUMENT_BYTES, MAX_EXPORT_BYTES, _read
from .competition_transport_verification import ByteCheckpoints, TransferProgress
from .private_files import ensure_private_directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .r2_evidence import R2EvidenceClient


class PortableByteSnapshotRemotePin(StrictProtocolModel):
    endpoint: Annotated[str, Field(pattern=r"^https://[0-9a-f]{32}\.r2\.cloudflarestorage\.com$")]
    bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
    prefix: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)+$")
    ]
    snapshot_sha256: Hex32
    export_sha256: Hex32
    model_sha256: Hex32
    context_sha256: Hex32


class _DocumentEnvelope(StrictProtocolModel):
    schema_: Literal["umi-model-byte-portable-document/1"] = Field(alias="schema")
    sha256: Hex32
    content_hex: Annotated[
        str, Field(max_length=2 * MAX_DOCUMENT_BYTES, pattern=r"^(?:[0-9a-f]{2})*$")
    ]


def _namespace(client, selected):
    if (client.signer.endpoint, client.signer.bucket) != (selected.endpoint, selected.bucket):
        raise ValueError("portable R2 snapshot selects another remote namespace")


def _document(raw, sha, size):
    value = _DocumentEnvelope.model_validate_json(raw)
    if canonical_json_bytes(value) != raw or value.sha256 != sha:
        raise ValueError("portable R2 document encoding or selection changed")
    data = bytes.fromhex(value.content_hex)
    if len(data) != size or sha256_hex(data) != sha:
        raise ValueError("portable R2 document differs from native verification")
    return data


def replicate_portable_snapshot(
    pin: PortableByteSnapshotPin, client: R2EvidenceClient, prefix: str, *, report=None
):
    """Publish dependencies before their immutable manifest; never delete locals."""
    root, value = _selected_snapshot(pin, report=report)
    remote = PortableByteSnapshotRemotePin(
        endpoint=client.signer.endpoint,
        bucket=client.signer.bucket,
        prefix=prefix,
        snapshot_sha256=pin.snapshot_sha256,
        export_sha256=pin.export_sha256,
        model_sha256=pin.model_sha256,
        context_sha256=pin.context_sha256,
    )
    documents = {v.sha256: v.size_bytes for v in value.files if v.document is not None}
    with TransferProgress(
        "model_byte_snapshot_R2_replication",
        len(documents) + 2,
        report,
        unit="objects",
        planning_unit_seconds=(0.05, 5.0),
    ) as progress:
        for sha, size in sorted(documents.items()):
            try:
                data, _ = _read(portable_member_path(root, "documents", sha), MAX_DOCUMENT_BYTES)
            except (OSError, ValueError):
                progress.emit("repair_required", reason="portable_source_document_unavailable")
                raise
            if len(data) != size or sha256_hex(data) != sha:
                progress.emit("repair_required", reason="portable_source_document_damaged")
                raise ValueError("portable source document requires repair")
            # A small canonical envelope also represents an empty retained
            # document without shortening the existing supported file budget.
            body = canonical_json_bytes(
                _DocumentEnvelope(
                    schema="umi-model-byte-portable-document/1", sha256=sha, content_hex=data.hex()
                )
            )
            client.publish(prefix + portable_member_key("documents", sha), body, sha256_hex(body))
            progress.advance(1)
        for folder, sha in (("exports", pin.export_sha256), ("snapshots", pin.snapshot_sha256)):
            body, _ = _read(portable_member_path(root, folder, sha), MAX_EXPORT_BYTES)
            if sha256_hex(body) != sha:
                raise ValueError("portable source metadata changed during replication")
            client.publish(prefix + portable_member_key(folder, sha), body, sha)
            progress.advance(1)
    return remote


def _remote_bytes(client, key, maximum, *, expected=None):
    head = client.head(key)
    if head is None:
        raise ValueError("selected portable R2 member is missing; repair required")
    if expected is not None and head.content_sha256 != expected:
        raise ValueError("selected portable R2 member digest changed")
    return client.read(key, head, maximum=maximum)


def download_portable_snapshot(
    pin: PortableByteSnapshotRemotePin,
    client: R2EvidenceClient,
    directory: Path,
    *,
    repair=False,
    report=None,
):
    """Fetch only one selected model's result metadata and bounded documents.

    Persist each member atomically. Exact local members survive interrupted
    retrieval; changed owned cache bytes require explicit scoped repair.
    """
    _namespace(client, pin)
    ensure_private_directory(directory)
    local = PortableByteSnapshotPin(
        directory=str(directory),
        snapshot_sha256=pin.snapshot_sha256,
        export_sha256=pin.export_sha256,
        model_sha256=pin.model_sha256,
        context_sha256=pin.context_sha256,
    )
    for folder in ("snapshots", "exports", "documents"):
        ensure_private_directory(directory / folder)
    with (
        TransferProgress(
            "model_byte_snapshot_R2_metadata",
            2,
            report,
            unit="objects",
            planning_unit_seconds=(0.05, 5.0),
        ) as progress,
        ByteCheckpoints(
            directory, {"scope": "portable-byte-snapshot-publication/1"}, progress
        ) as _publication,
    ):
        for folder, sha in (("snapshots", pin.snapshot_sha256), ("exports", pin.export_sha256)):
            path = portable_member_path(directory, folder, sha)
            try:
                data, _ = _read(path, MAX_EXPORT_BYTES)
            except FileNotFoundError:
                data = None
            damaged = data is not None and sha256_hex(data) != sha
            if damaged:
                progress.emit("repair_required", reason="portable_download_metadata_damaged")
                if not repair:
                    raise ValueError("portable metadata requires explicit scoped repair")
                data = None
            reused = data is not None
            if data is None:
                data = _remote_bytes(
                    client,
                    pin.prefix + portable_member_key(folder, sha),
                    MAX_EXPORT_BYTES,
                    expected=sha,
                )
                if sha256_hex(data) != sha:
                    raise ValueError("portable R2 metadata differs from selected digest")
                ensure_private_directory(path.parent)
                ByteCheckpoints(path.parent, {}, progress)._write(path, data)
                if damaged:
                    progress.emit("repair_completed", reason="portable_download_metadata_restored")
            progress.advance(1, restored=reused)
        _, value = _selected_snapshot(local, report=report)
        documents = {v.sha256: v.size_bytes for v in value.files if v.document is not None}
        with TransferProgress(
            "model_byte_snapshot_R2_documents",
            len(documents),
            report,
            unit="objects",
            planning_unit_seconds=(0.05, 5.0),
        ) as child:
            for sha, size in sorted(documents.items()):
                path = portable_member_path(directory, "documents", sha)
                try:
                    data, _ = _read(path, MAX_DOCUMENT_BYTES)
                except FileNotFoundError:
                    data = None
                damaged = data is not None and (len(data) != size or sha256_hex(data) != sha)
                if damaged:
                    child.emit("repair_required", reason="portable_download_document_damaged")
                    if not repair:
                        raise ValueError("portable document requires explicit scoped repair")
                    data = None
                reused = data is not None
                if data is None:
                    body = _remote_bytes(
                        client,
                        pin.prefix + portable_member_key("documents", sha),
                        2 * MAX_DOCUMENT_BYTES + 512,
                    )
                    data = _document(body, sha, size)
                    ensure_private_directory(path.parent)
                    ByteCheckpoints(path.parent, {}, child)._write(path, data)
                    if damaged:
                        child.emit("repair_completed", reason="portable_download_document_restored")
                child.advance(1, restored=reused)
    return local
