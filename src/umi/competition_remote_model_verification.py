"""Durable byte results for exact R2 model objects, independent of local caches.

These private results establish bytes only. Callers retain their own admission,
rights, policy and signing checks; a result never grants protocol authority.
"""

from __future__ import annotations

import hashlib
from contextlib import nullcontext
from pathlib import Path

from .competition_transport_verification import (
    ByteCheckpoints,
    TransferProgress,
    owned_byte_checkpoint,
    verifier_semantics,
)
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import StrictProtocolModel, canonical_json_bytes
from .r2_multipart import MAXIMUM_RANGE_BYTES, R2ObjectHead

REMOTE_MODEL_ABI = "umi-r2-model-bytes/1"


class _RemoteModelRanges:
    """Read adjacent manifest files through one bounded contiguous range.

    A range may span files, but callers consume and hash bytes in the original
    manifest order. No prefetch task or unbounded working set survives a caller.
    """

    def __init__(
        self,
        multipart,
        key,
        total_bytes,
        *,
        start_offset=0,
        maximum_range_bytes=None,
    ):
        if maximum_range_bytes is None:
            maximum_range_bytes = MAXIMUM_RANGE_BYTES
        if (
            not 0 <= start_offset <= total_bytes
            or not 1 <= maximum_range_bytes <= MAXIMUM_RANGE_BYTES
        ):
            raise ValueError("direct model range bounds differ")
        self.multipart, self.key, self.total = multipart, key, total_bytes
        self.maximum_range_bytes = maximum_range_bytes
        self.buffer = b""
        self.position, self.offset = 0, start_offset

    async def read(self, maximum):
        if self.position == len(self.buffer):
            size = min(self.total - self.offset, self.maximum_range_bytes)
            if size <= 0:
                raise ValueError("direct model verification range differs")
            self.buffer = await self.multipart.read_range(
                self.key, offset=self.offset, size_bytes=size
            )
            if len(self.buffer) != size:
                raise ValueError("direct model verification range differs")
            self.position = 0
        size = min(maximum, len(self.buffer) - self.position)
        data = memoryview(self.buffer)[self.position : self.position + size]
        self.position += size
        self.offset += size
        return data


class RemoteModelBytes(StrictProtocolModel):
    """Small original documents are retained; model weights never enter this record."""

    payload_sha256: str
    documents: dict[str, str]


def remote_identity(multipart, key, head):
    """Bind the authenticated provider namespace as well as its object version."""
    return {
        "endpoint": multipart.signer.endpoint,
        "bucket": multipart.signer.bucket,
        "key_sha256": hashlib.sha256(key.encode()).hexdigest(),
        "etag": head.etag,
        "size_bytes": head.size_bytes,
    }


def model_byte_store(root, key, bundle, payload, context, document_paths, progress):
    binding = {
        "scope": REMOTE_MODEL_ABI,
        "semantics": verifier_semantics(),
        "bundle": digest(bundle),
        "payload": digest(payload),
        "authority": context,
        "document_paths": sorted(document_paths),
    }
    return (
        ByteCheckpoints(Path(root) / hashlib.sha256(key.encode()).hexdigest(), binding, progress)
        if root is not None
        else nullcontext(None)
    )


def remember_model_bytes(saved, source, payload, documents):
    if saved is not None:
        result = RemoteModelBytes(
            payload_sha256=payload.payload_sha256,
            documents={name: raw.hex() for name, raw in documents.items()},
        )
        saved._write(saved.root / "result.json", canonical_json_bytes(result))
        saved.remember("object", source, digest(result))


def require_remote_model_bytes(multipart, key, bundle, payload, *, root, context, head):
    """Require completed owner byte facts; never repair by rereading a payload.

    The caller authenticates the original promotion and rechecks current provider
    identity around I/O. Missing or damaged completion is an explicit repair gate.
    """
    with TransferProgress("remote_model_completed_verification", 1, unit="objects") as progress:
        source = remote_identity(multipart, key, head)
        with model_byte_store(root, key, bundle, payload, context, (), progress) as saved:
            if saved is None:
                raise ValueError("completed remote model requires durable byte verification")
            prior = saved.load("object", source)
            try:
                path = saved.root / "result.json"
                if path.lstat().st_size > 64 * 1024**2:
                    raise ValueError("completed remote model result exceeds its metadata bound")
                raw = saved._read(path)
                result = RemoteModelBytes.model_validate_json(raw)
                if (
                    prior is None
                    or canonical_json_bytes(result) != raw
                    or digest(result) != prior
                    or result.payload_sha256 != payload.payload_sha256
                    or result.documents
                ):
                    raise ValueError("completed remote model byte facts differ")
            except (OSError, ValueError) as error:
                progress.emit("repair_required", reason="remote_model_completion_repair_required")
                raise OSError("completed remote model byte verification requires repair") from error
            progress.advance(1, restored=True)
            return result


async def verify_remote_model(
    multipart,
    key,
    bundle,
    payload,
    *,
    root: Path | None,
    context: dict,
    document_paths=(),
    expected_head=None,
    report=None,
    object_role=None,
):
    """Verify once per immutable source/context; retain each completed file check.

    An interrupted concatenated SHA256 is unfinished work: its next pass reads
    the stream again, while completed file checks are reused. A completed object
    needs only current HEAD and compact private metadata across restarts.
    """
    identity = {
        "source_object_key_sha256": hashlib.sha256(key.encode()).hexdigest(),
        "model_sha256": digest(bundle),
    }
    if object_role is not None:
        identity["object_role"] = object_role
    with TransferProgress(
        "remote_model_verification", payload.total_bytes, report, identity=identity
    ) as progress:
        observed = await multipart.head(key)
        if observed is None:
            raise OSError("direct model object is unavailable")
        head = R2ObjectHead(size_bytes=observed.size_bytes, etag=observed.etag)
        if head.size_bytes != payload.total_bytes or (
            expected_head is not None
            and (head.size_bytes, head.etag) != (expected_head.size_bytes, expected_head.etag)
        ):
            raise ValueError("direct model object metadata changed")
        # Injected stateless test/legacy ports need no provider namespace. Durable
        # production callers must supply the actual R2 client and explicit root.
        source = remote_identity(multipart, key, head) if root is not None else None
        async with owned_byte_checkpoint(
            model_byte_store(root, key, bundle, payload, context, document_paths, progress),
            progress,
        ) as saved:
            result_path = None if saved is None else saved.root / "result.json"
            prior = None if saved is None else saved.load("object", source)
            if prior is not None:
                try:
                    if result_path.lstat().st_size > 64 * 1024**2:
                        raise ValueError("remote model result exceeds its metadata bound")
                    raw = await run_owned_thread(saved._read, result_path)
                except FileNotFoundError:
                    raw = None
                # Unsafe links/owners/modes are refusals. Only missing or malformed
                # owned result content receives an explicit native repair.
                try:
                    if raw is None:
                        raise ValueError("remote model result is missing")
                    result = RemoteModelBytes.model_validate_json(raw)
                    if (
                        canonical_json_bytes(result) != raw
                        or digest(result) != prior
                        or result.payload_sha256 != payload.payload_sha256
                        or set(result.documents) != set(document_paths)
                    ):
                        raise ValueError("remote model result binding changed")
                    documents = {name: bytes.fromhex(raw) for name, raw in result.documents.items()}
                    if any(documents[name].hex() != raw for name, raw in result.documents.items()):
                        raise ValueError("remote model document encoding changed")
                except ValueError:
                    progress.emit(
                        "repair_required", reason="remote_model_result_missing_or_damaged"
                    )
                else:
                    progress.advance(payload.total_bytes, restored=True)
                    return documents, head
            stream_hash = hashlib.sha256()
            documents = {}
            offset = 0
            ranges = _RemoteModelRanges(multipart, key, payload.total_bytes)
            for record in bundle.files:
                identity = {"source": source, "offset": offset, "size_bytes": record.size_bytes}
                verified = None if saved is None else saved.load(["file", record.path], identity)
                if verified is not None and verified != record.sha256:
                    progress.emit("repair_required", reason="remote_model_file_result_changed")
                    verified = None
                file_hash = None if verified is not None else hashlib.sha256()
                document = bytearray() if record.path in document_paths else None
                remaining = record.size_bytes
                while remaining:
                    data = await ranges.read(remaining)
                    size = len(data)
                    stream_hash.update(data)
                    if file_hash is not None:
                        file_hash.update(data)
                    if document is not None:
                        document.extend(data)
                    offset += size
                    remaining -= size
                    progress.advance(size)
                    del data
                if file_hash is not None and file_hash.hexdigest() != record.sha256:
                    raise ValueError("direct model file differs from its manifest")
                if saved is not None and verified is None:
                    saved.remember(["file", record.path], identity, record.sha256)
                if document is not None:
                    documents[record.path] = bytes(document)
                    document[:] = b"\x00" * len(document)
            if offset != payload.total_bytes or stream_hash.hexdigest() != payload.payload_sha256:
                raise ValueError("direct model payload digest differs")
            final = await multipart.head(key)
            if final is None or (final.size_bytes, final.etag) != (head.size_bytes, head.etag):
                raise ValueError("direct model object changed while reading")
            await run_owned_thread(remember_model_bytes, saved, source, payload, documents)
            return documents, head
