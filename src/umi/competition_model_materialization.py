"""Resumable bounded model-cache transfers; completed byte facts live separately."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_artifacts import _artifact, _directory, _file_identity
from .competition_remote_model_verification import _RemoteModelRanges
from .competition_transport_verification import ByteCheckpoints, verifier_semantics
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import ensure_private_directory, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .r2_multipart import MAXIMUM_RANGE_BYTES


class PendingModelMaterialization(StrictProtocolModel):
    schema_: Literal["umi-pending-model-materialization/1"] = Field(alias="schema")
    selection_sha256: Hex32
    source: dict[str, str | int]


class CompletedModelMaterialization(StrictProtocolModel):
    payload_sha256: Hex32
    documents: dict[str, str]


def pending_materialization(archive, selection):
    ensure_private_directory(archive)
    pending = read_private_model(
        archive / "materialization-pending.json", PendingModelMaterialization
    )
    return pending.selection_sha256 == selection


def _identity(path, root):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise ValueError("model cache file is not an owned private regular file")
    return {"archive": [str(root.st_dev), str(root.st_ino)], "file": _file_identity(info)}


async def materialize_model_files(
    *,
    archive,
    bundle,
    payload,
    multipart,
    key,
    selection,
    source,
    verification_root,
    document_paths,
    progress,
    available_bytes,
    reserve_bytes,
    check_write=None,
    check_file_write=None,
):
    """Resume completed files and authenticate only affected local materializations.

    The unfinished concatenated checksum still reads restored local files. It
    never redownloads or repeats their already successful per-file checks.
    """
    if archive.exists():
        if not pending_materialization(archive, selection):
            raise ValueError("pending model cache belongs to another selection")
        pending = read_private_model(
            archive / "materialization-pending.json", PendingModelMaterialization
        )
        if pending.source != source:
            progress.emit("repair_required", reason="materialization_remote_generation_changed")
            raise ValueError("pending model cache remote source changed")
    else:
        ensure_private_directory(archive)
        publish_private_model(
            archive / "materialization-pending.json",
            PendingModelMaterialization(
                schema="umi-pending-model-materialization/1",
                selection_sha256=selection,
                source=source,
            ),
        )
    root = archive.stat()
    target = archive / digest(bundle)
    ensure_private_directory(target)
    model = target / "model"
    ensure_private_directory(model)
    state_root = (
        archive / ".transfer-checkpoints"
        if verification_root is None
        else Path(verification_root)
        / "materializations"
        / hashlib.sha256(os.fsencode(archive)).hexdigest()
    )
    binding = {
        "selection": selection,
        "bundle": digest(bundle),
        "payload": digest(payload),
        "semantics": verifier_semantics(),
        "source": source,
    }
    with ByteCheckpoints(state_root, binding, progress) as saved:
        reusable = {}
        local = {}
        for record in bundle.files:
            destination = model / record.path
            try:
                stamp = _identity(destination, root)
            except FileNotFoundError:
                stamp = None
            prior = saved.load(record.path, stamp)
            if prior is not None and prior != record.sha256:
                progress.emit(
                    "repair_required", reason="materialization_file_digest_binding_changed"
                )
            if stamp is not None:
                local[record.path] = stamp
            if prior == record.sha256 and stamp is not None:
                reusable[record.path] = stamp
        identities = [[record.path, local.get(record.path)] for record in bundle.files]
        completed = saved.load("payload", identities)
        if completed is not None:
            try:
                result_path = saved.root / "payload-result.json"
                if result_path.lstat().st_size > 64 * 1024**2:
                    raise ValueError("materialization result exceeds its metadata bound")
                raw = saved._read(result_path)
            except FileNotFoundError:
                raw = None
            try:
                result = CompletedModelMaterialization.model_validate_json(raw or b"")
                if (
                    canonical_json_bytes(result) != raw
                    or digest(result) != completed
                    or result.payload_sha256 != payload.payload_sha256
                    or set(result.documents) != set(document_paths)
                    or any(stamp is None for _, stamp in identities)
                ):
                    raise ValueError("materialization result differs")
                documents = {name: bytes.fromhex(value) for name, value in result.documents.items()}
                if any(documents[name].hex() != value for name, value in result.documents.items()):
                    raise ValueError("materialization document encoding differs")
            except ValueError:
                progress.emit("repair_required", reason="materialization_result_missing_or_damaged")
            else:
                for record in bundle.files:
                    if record.path not in reusable:
                        saved.remember(record.path, local[record.path], record.sha256)
                progress.advance(payload.total_bytes, restored=True)
                progress.advance_operations(len(bundle.files), restored=True)
                await run_owned_thread(publish_private_model, target / "manifest.json", bundle)
                return target, documents, [[name, stamp["file"]] for name, stamp in identities]
        # Owned partial files cannot contribute completed bytes. Reclaim them
        # before measuring capacity, so an interrupted large file cannot prevent
        # its own repair. Complete-size files need no new allocation even when
        # their missing receipt requires a local native check.
        for record in bundle.files:
            info = local.get(record.path)
            if info is not None and int(info["file"][2]) != record.size_bytes:
                destination = model / record.path
                if _identity(destination, root) != info:
                    raise ValueError("partial model cache changed before repair")
                destination.unlink()
                del local[record.path]
                reusable.pop(record.path, None)
        retained_bytes = sum(record.size_bytes for record in bundle.files if record.path in local)
        if available_bytes() < payload.total_bytes - retained_bytes + reserve_bytes:
            raise OSError("direct model scratch capacity is unavailable")
        offset = 0
        # Coalesce only adjacent missing files. A retained file splits the
        # remote range so restart never downloads its completed bytes again.
        missing_ends = {}
        position = end = payload.total_bytes
        for record in reversed(bundle.files):
            position -= record.size_bytes
            if record.path in local:
                end = position
            else:
                missing_ends[record.path] = end
        ranges = None
        stream_hash = hashlib.sha256()
        documents, written_files = {}, []
        with _directory(model) as model_fd:
            for record in bundle.files:
                destination = model / record.path
                # Existing complete-size files without a usable receipt are
                # verified locally during explicit repair, without downloading.
                info = local.get(record.path)
                local_file = info is not None and int(info["file"][2]) == record.size_bytes
                restored = record.path in reusable
                file_hash = None if restored else hashlib.sha256()
                document = bytearray() if record.path in document_paths else None
                remaining = record.size_bytes
                output = None
                reader = None
                try:
                    if local_file:
                        ranges = None
                        reader = _artifact(model_fd, record)
                        stream, _ = reader.__enter__()
                    else:
                        if ranges is None:
                            ranges = _RemoteModelRanges(
                                multipart,
                                key,
                                missing_ends[record.path],
                                start_offset=offset,
                                maximum_range_bytes=MAXIMUM_RANGE_BYTES,
                            )
                        if destination.exists():
                            if _identity(destination, root) != info:
                                raise ValueError("partial model cache changed before repair")
                            destination.unlink()
                        ensure_private_directory(destination.parent)
                        descriptor = os.open(
                            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                        )
                        # Space accounting sees each append's actual file size;
                        # user-space buffering must not hide allocated bytes.
                        output = os.fdopen(descriptor, "wb", buffering=0)
                    while remaining:
                        size = min(remaining, MAXIMUM_RANGE_BYTES)
                        data = (
                            await run_owned_thread(stream.read, size)
                            if local_file
                            else await ranges.read(size)
                        )
                        if local_file and len(data) != size:
                            raise ValueError("direct model materialization range differs")
                        size = len(data)
                        if output is not None:
                            if check_file_write is not None:
                                await run_owned_thread(check_file_write, destination, size)
                            elif check_write is not None:
                                await run_owned_thread(check_write, size)
                        if (
                            output is not None
                            and await run_owned_thread(output.write, data) != size
                        ):
                            raise OSError("direct model materialization write was incomplete")
                        stream_hash.update(data)
                        if file_hash is not None:
                            file_hash.update(data)
                        if document is not None:
                            document.extend(data)
                        offset += size
                        remaining -= size
                        progress.advance(size, restored=restored)
                        del data
                    if output is not None:
                        await run_owned_thread(output.flush)
                        os.fchmod(output.fileno(), 0o400)
                        await run_owned_thread(os.fsync, output.fileno())
                        stamp = {
                            "archive": [str(root.st_dev), str(root.st_ino)],
                            "file": _file_identity(os.fstat(output.fileno())),
                        }
                    else:
                        stamp = _identity(destination, root)
                        if stamp != info:
                            raise ValueError("retained model cache changed during materialization")
                    if file_hash is not None and file_hash.hexdigest() != record.sha256:
                        raise ValueError("materialized model file differs from its manifest")
                    if local_file and not restored:
                        os.fchmod(stream.fileno(), 0o400)
                        await run_owned_thread(os.fsync, stream.fileno())
                        stamp = {
                            "archive": [str(root.st_dev), str(root.st_ino)],
                            "file": _file_identity(os.fstat(stream.fileno())),
                        }
                    if _identity(destination, root) != stamp:
                        raise ValueError("model cache changed after transfer")
                    if not restored:
                        saved.remember(record.path, stamp, record.sha256)
                    written_files.append([record.path, stamp["file"]])
                    if document is not None:
                        documents[record.path] = bytes(document)
                        document[:] = b"\x00" * len(document)
                    progress.advance_operations(1, restored=restored)
                finally:
                    if output is not None:
                        output.close()
                    if reader is not None:
                        reader.__exit__(None, None, None)
        if offset != payload.total_bytes or stream_hash.hexdigest() != payload.payload_sha256:
            raise ValueError("materialized model payload differs")
        result = CompletedModelMaterialization(
            payload_sha256=payload.payload_sha256,
            documents={name: raw.hex() for name, raw in documents.items()},
        )
        saved._write(saved.root / "payload-result.json", canonical_json_bytes(result))
        saved.remember(
            "payload",
            [
                [name, {"archive": [str(root.st_dev), str(root.st_ino)], "file": stamp}]
                for name, stamp in written_files
            ],
            digest(result),
        )
        await run_owned_thread(publish_private_model, target / "manifest.json", bundle)
        return target, documents, written_files
