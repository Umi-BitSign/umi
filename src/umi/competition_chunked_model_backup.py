"""Read retained chunked model backups without changing signed cohort artifacts.

The caller authenticates ``ChunkedBackupBinding`` from its retained migration
inventory and policy/authority. A backup association is byte provenance, never
admission, rights review, certification or permission to evict another archive.
``validate_chunked_backup`` preserves the installed backup /1 format. ``verify``
retains per-file byte results independently of local caches; ``materialize``
creates the ordinary native archive layout under an explicitly budgeted cache.

The format has per-file/chunk digests, not a concatenated direct-upload digest.
It is deliberately not represented as a signed direct multipart reservation.
Consumers must retain the original acceptance and use a separate source resolver.
No upload, remote deletion, consumer release or signed transport adoption occurs
here. Callers own their cache lease and supported restart/eviction coordination.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_artifacts import (
    _artifact,
    _copy_verified,
    _directory,
    _file_identity,
    _preserved_verification_record,
    _remember_preserved_verification,
)
from .competition_transport_verification import (
    ByteCheckpoints,
    ProgressReader,
    TransferProgress,
    verifier_semantics,
)
from .concurrency import run_owned_thread
from .open_competition import CompetitionPolicy, ModelBundle, digest, validate_bundle_policy
from .private_files import ensure_private_directory, private_path, publish_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .r2_multipart import R2MultipartClient

CHUNK_BYTES = 8 * 1024**2
METADATA_BYTES = 64 * 1024**2
BYTE_ABI = "umi-chunked-model-backup-bytes/1"


class ChunkedBackupBinding(StrictProtocolModel):
    """Caller-authenticated pins; construction alone does not authenticate them."""

    schema_: Literal["umi-chunked-model-backup-binding/1"] = Field(alias="schema")
    association_sha256: Hex32
    model_sha256: Hex32
    policy_sha256: Hex32
    provenance_sha256: Hex32
    endpoint: Annotated[str, Field(pattern=r"^https://[0-9a-f]{32}\.r2\.cloudflarestorage\.com$")]
    bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]

    @model_validator(mode="after")
    def present_provenance(self):
        if "0" * 64 in (
            self.association_sha256,
            self.model_sha256,
            self.policy_sha256,
            self.provenance_sha256,
        ):
            raise ValueError("chunked model source requires explicit retained provenance")
        return self


class ChunkedBackupAssociation(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-backup-association/1"] = Field(alias="schema")
    model_sha256: Hex32
    package_key: Annotated[str, Field(min_length=1, max_length=256)]
    package_sha256: Hex32
    verification: Literal["all_declared_bytes_uploaded_and_read_back"]
    artifact_acceptance_certified: Literal[False]

    @model_validator(mode="after")
    def exact_key(self):
        if self.package_key != f"packages/{self.model_sha256}/{self.package_sha256}.json":
            raise ValueError("chunked backup package key differs")
        return self


class BackupChunk(StrictProtocolModel):
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=1, le=CHUNK_BYTES)]

    @property
    def key(self) -> str:
        return "chunks/sha256/" + self.sha256


class BackupFile(StrictProtocolModel):
    path: str
    chunks: Annotated[tuple[BackupChunk, ...], Field(max_length=131072)]


class ChunkedBackupPackage(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-preserved-package/1"] = Field(alias="schema")
    model_sha256: Hex32
    native_bundle: ModelBundle
    files: Annotated[tuple[BackupFile, ...], Field(min_length=7, max_length=4096)]
    chunk_bytes: Literal[8388608]
    policy_sha256: Hex32
    source: Literal["verified_native_c5_artifact_archive"]
    rights_approved: Literal[False]
    benchmark_certified: Literal[False]
    rewards_authorized: Literal[False]

    @model_validator(mode="after")
    def exact_coverage(self):
        if digest(self.native_bundle) != self.model_sha256 or tuple(
            f.path for f in self.files
        ) != tuple(f.path for f in self.native_bundle.files):
            raise ValueError("chunked backup changes its signed model inventory")
        sizes = {}
        for record, item in zip(self.native_bundle.files, self.files, strict=True):
            remaining = record.size_bytes
            for chunk in item.chunks:
                if remaining <= 0 or chunk.size_bytes != min(CHUNK_BYTES, remaining):
                    raise ValueError("chunked backup chunk geometry differs")
                if sizes.setdefault(chunk.sha256, chunk.size_bytes) != chunk.size_bytes:
                    raise ValueError("chunked backup reuses a chunk with a different size")
                remaining -= chunk.size_bytes
            if remaining:
                raise ValueError("chunked backup file coverage is incomplete")
        return self


class ChunkedBackupSelection(StrictProtocolModel):
    binding: ChunkedBackupBinding
    association: ChunkedBackupAssociation
    package: ChunkedBackupPackage

    @model_validator(mode="after")
    def bindings(self):
        b, a, p = self.binding, self.association, self.package
        if (
            sha256_hex(canonical_json_bytes(a)) != b.association_sha256
            or sha256_hex(canonical_json_bytes(p)) != a.package_sha256
            or a.model_sha256 != b.model_sha256
            or p.model_sha256 != b.model_sha256
            or p.policy_sha256 != b.policy_sha256
        ):
            raise ValueError("chunked backup differs from authenticated retained pins")
        return self

    @property
    def bundle(self) -> ModelBundle:
        return self.package.native_bundle


def _canonical(raw, model, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ValueError("chunked backup metadata exceeds its bound")
    value = model.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("chunked backup metadata is not canonical")
    return value


def validate_chunked_backup(
    association_raw: bytes,
    package_raw: bytes,
    manifest_raw: bytes,
    *,
    policy: CompetitionPolicy,
    binding: ChunkedBackupBinding,
) -> ChunkedBackupSelection:
    """Validate exact backup metadata against already authenticated caller pins."""
    association = _canonical(association_raw, ChunkedBackupAssociation, 64 * 1024)
    package = _canonical(package_raw, ChunkedBackupPackage, METADATA_BYTES)
    bundle = _canonical(manifest_raw, ModelBundle, 16 * 1024**2)
    binding = ChunkedBackupBinding.model_validate_json(canonical_json_bytes(binding))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if package.native_bundle != bundle or binding.policy_sha256 != digest(policy):
        raise ValueError("chunked backup differs from the original manifest or policy")
    validate_bundle_policy(bundle, policy)
    return ChunkedBackupSelection(binding=binding, association=association, package=package)


class ChunkedObjectGeneration(StrictProtocolModel):
    key: str
    sha256: Hex32
    size_bytes: int
    etag: Annotated[str, Field(min_length=1, max_length=256)]


class ChunkedModelVerification(StrictProtocolModel):
    """Private byte result; documents are bounded original bytes encoded as hex."""

    schema_: Literal["umi-chunked-model-verification/1"] = Field(alias="schema")
    selection_sha256: Hex32
    namespace_sha256: Hex32
    objects: tuple[ChunkedObjectGeneration, ...]
    documents: dict[str, str]


def _local_identity(path, root):
    private_path(str(path))
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("chunked model cache file is unsafe")
    return {"archive": [str(root.st_dev), str(root.st_ino)], "file": _file_identity(info)}


def _document(path, maximum):
    """Read bounded owned bytes; unsafe paths are refusals, not repairs."""
    private_path(str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
        ):
            raise ValueError("chunked model document is not an owned private regular file")
        raw = stream.read(maximum + 1) if before.st_size <= maximum else None
        if _file_identity(os.fstat(stream.fileno())) != _file_identity(before) or _file_identity(
            path.lstat()
        ) != _file_identity(before):
            raise ValueError("chunked model document changed while reading")
        return raw


class ChunkedModelBackupReader:
    """A bounded R2 reader with independently retained remote/local byte results."""

    def __init__(
        self,
        selection: ChunkedBackupSelection,
        *,
        policy: CompetitionPolicy,
        multipart: R2MultipartClient,
        verification_root: Path,
        metadata_workers: int = 8,
    ):
        self.selection = ChunkedBackupSelection.model_validate_json(canonical_json_bytes(selection))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if digest(self.policy) != self.selection.binding.policy_sha256:
            raise ValueError("chunked model reader policy differs")
        validate_bundle_policy(self.selection.bundle, self.policy)
        if type(metadata_workers) is not int or not 1 <= metadata_workers <= 32:
            raise ValueError("chunked model metadata concurrency is outside its bound")
        self.metadata_workers = metadata_workers
        self.multipart, self.root = multipart, Path(verification_root)
        private_path(str(self.root))
        self.serial = asyncio.Lock()
        self._namespace()
        self.chunks = {
            chunk.sha256: chunk for item in self.selection.package.files for chunk in item.chunks
        }

    def _namespace(self):
        binding = self.selection.binding
        actual = {
            "endpoint": self.multipart.signer.endpoint,
            "bucket": self.multipart.signer.bucket,
        }
        if actual != {"endpoint": binding.endpoint, "bucket": binding.bucket}:
            raise ValueError("chunked model provider namespace differs")
        return actual

    def _context(self):
        return {
            "semantics": [BYTE_ABI, verifier_semantics()],
            "selection": digest(self.selection),
            "namespace": self._namespace(),
        }

    async def _heads(self, report, chunks=None, *, expected=None):
        chunks = self.chunks if chunks is None else chunks
        values = {}
        stage = (
            "chunked_model_remote_metadata"
            if expected is None
            else "chunked_model_generation_confirmation"
        )
        with TransferProgress(stage, len(chunks), report, unit="objects") as progress:
            pending = iter(sorted(chunks.items()))

            async def worker():
                for key, chunk in pending:
                    self._namespace()
                    head = await self.multipart.head(chunk.key)
                    if head is None:
                        raise OSError("retained model chunk is unavailable")
                    if head.size_bytes != chunk.size_bytes or not head.etag or len(head.etag) > 256:
                        progress.emit("repair_required", reason="chunked_model_generation_changed")
                        raise ValueError("retained model chunk metadata differs")
                    value = ChunkedObjectGeneration(
                        key=chunk.key, sha256=key, size_bytes=chunk.size_bytes, etag=head.etag
                    )
                    if expected is not None and value != expected[key]:
                        progress.emit("repair_required", reason="chunked_model_generation_changed")
                        raise ValueError("retained model chunk generation changed")
                    values[key] = value
                    progress.advance(1)

            tasks = [
                asyncio.create_task(worker())
                for _ in range(min(self.metadata_workers, len(chunks)))
            ]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        return values

    def _source(self, item, heads):
        return [heads[c.sha256].model_dump(mode="json") for c in item.chunks]

    async def _chunk(self, chunk, heads):
        self._namespace()
        raw = await self.multipart.read_range(chunk.key, offset=0, size_bytes=chunk.size_bytes)
        if len(raw) != chunk.size_bytes or sha256_hex(raw) != chunk.sha256:
            raise ValueError("retained model chunk bytes differ")
        self._namespace()
        head = await self.multipart.head(chunk.key)
        expected = heads[chunk.sha256]
        if head is None or (head.size_bytes, head.etag) != (expected.size_bytes, expected.etag):
            raise ValueError("retained model chunk changed during transfer")
        return raw

    async def _unchanged(self, heads, report):
        await self._heads(report, {key: self.chunks[key] for key in heads}, expected=heads)

    def _store(self, progress):
        return ByteCheckpoints(
            self.root / self.selection.binding.model_sha256 / "remote", self._context(), progress
        )

    async def verify(
        self,
        *,
        document_paths: Sequence[str] = (),
        maximum_document_bytes: int = 16 * 1024**2,
        report: Callable[[dict], None] | None = None,
    ) -> ChunkedModelVerification:
        """Reuse successful files after HEAD; interrupted work rechecks unfinished files only."""
        async with self.serial:
            names = set(document_paths)
            bundle = self.selection.bundle
            if (
                len(names) != len(document_paths)
                or not names <= {r.path for r in bundle.files}
                or type(maximum_document_bytes) is not int
                or not 1 <= maximum_document_bytes <= 16 * 1024**2
                or sum(r.size_bytes for r in bundle.files if r.path in names)
                > maximum_document_bytes
            ):
                raise ValueError("chunked model document selection exceeds its bound")
            self._context()  # Refuse an unqualified verifier before remote I/O.
            heads = await self._heads(report)
            documents = {}
            with (
                TransferProgress(
                    "chunked_model_verification", sum(r.size_bytes for r in bundle.files), report
                ) as progress,
                self._store(progress) as saved,
            ):
                for record, item in zip(bundle.files, self.selection.package.files, strict=True):
                    source = self._source(item, heads)
                    prior = saved.load(record.path, source)
                    document = None
                    if prior == record.sha256 and record.path in names:
                        path = saved.root / (sha256_hex(record.path.encode()) + ".document")
                        try:
                            document = _document(path, maximum_document_bytes)
                        except FileNotFoundError:
                            document = None
                        if (
                            document is None
                            or len(document) != record.size_bytes
                            or sha256_hex(document) != record.sha256
                        ):
                            progress.emit(
                                "repair_required",
                                reason="chunked_model_document_missing_or_damaged",
                            )
                            document = None
                    if prior == record.sha256 and (
                        record.path not in names or document is not None
                    ):
                        progress.advance(record.size_bytes, restored=True)
                    else:
                        if prior is not None and prior != record.sha256:
                            progress.emit(
                                "repair_required", reason="chunked_model_file_receipt_changed"
                            )
                        hasher = hashlib.sha256()
                        content = bytearray() if record.path in names else None
                        for chunk in item.chunks:
                            raw = await self._chunk(chunk, heads)
                            hasher.update(raw)
                            if content is not None:
                                content.extend(raw)
                            progress.advance(len(raw))
                        if hasher.hexdigest() != record.sha256:
                            raise ValueError("chunked model file differs from its signed manifest")
                        document = None if content is None else bytes(content)
                        if document is not None:
                            saved._write(
                                saved.root / (sha256_hex(record.path.encode()) + ".document"),
                                document,
                            )
                        saved.remember(record.path, source, record.sha256)
                    if document is not None:
                        documents[record.path] = document.hex()
                await self._unchanged(heads, report)
            return ChunkedModelVerification(
                schema="umi-chunked-model-verification/1",
                selection_sha256=digest(self.selection),
                namespace_sha256=digest(self._namespace()),
                objects=tuple(heads[key] for key in sorted(heads)),
                documents=documents,
            )

    async def materialize(
        self,
        archive: Path,
        *,
        maximum_materialized_bytes: int,
        available_bytes: Callable[[], int],
        reserve_bytes: int,
        check_write: Callable[[int], None],
        report: Callable[[dict], None] | None = None,
    ) -> Path:
        """Restore a native archive under the caller's held cache/capacity lease.

        ``available_bytes`` and ``check_write`` are the common bounded-cache ports.
        Completed files survive interruption; unfinished files are explicitly
        retried. The durable state directory must be outside the disposable cache.
        This does not authorize activation or eviction of an existing consumer.
        """
        async with self.serial:
            archive = Path(archive)
            private_path(str(archive))
            if archive == self.root or archive in self.root.parents or self.root in archive.parents:
                raise ValueError("chunked model verification state overlaps its cache")
            bundle = self.selection.bundle
            total = sum(record.size_bytes for record in bundle.files)
            if (
                type(maximum_materialized_bytes) is not int
                or total > maximum_materialized_bytes
                or type(reserve_bytes) is not int
                or reserve_bytes < 0
                or not callable(available_bytes)
                or not callable(check_write)
            ):
                raise ValueError("chunked model restoration lacks an explicit capacity budget")
            context = {**self._context(), "archive": str(archive)}
            ensure_private_directory(archive)
            marker = archive / "chunked-materialization.json"
            await run_owned_thread(publish_private_model, marker, self.selection.binding)
            root = archive.stat()
            target = archive / digest(bundle)
            ensure_private_directory(target)
            model = target / "model"
            ensure_private_directory(model)
            state_root = (
                self.root
                / self.selection.binding.model_sha256
                / "materializations"
                / sha256_hex(os.fsencode(archive))
            )
            written = []
            with (
                TransferProgress("chunked_model_materialization", total, report) as progress,
                ByteCheckpoints(state_root, context, progress) as local,
                self._store(progress) as remote,
            ):
                retained, reusable, needed = {}, set(), {}
                with TransferProgress(
                    "chunked_model_local_cache_inventory", len(bundle.files), report, unit="files"
                ) as inventory:
                    for record, item in zip(
                        bundle.files, self.selection.package.files, strict=True
                    ):
                        destination = model / record.path
                        try:
                            stamp = _local_identity(destination, root)
                        except FileNotFoundError:
                            stamp = None
                        prior = local.load(record.path, stamp)
                        if stamp is not None and int(stamp["file"][2]) != record.size_bytes:
                            progress.emit("retrying", reason="chunked_model_incomplete_file_retry")
                            if _local_identity(destination, root) != stamp:
                                raise ValueError(
                                    "partial chunked model cache changed before repair"
                                )
                            destination.unlink()
                            stamp = None
                        if stamp is None:
                            needed.update((chunk.sha256, chunk) for chunk in item.chunks)
                        else:
                            retained[record.path] = stamp
                            if prior == record.sha256:
                                reusable.add(record.path)
                        inventory.advance(1)
                missing_bytes = sum(r.size_bytes for r in bundle.files if r.path not in retained)
                if missing_bytes and available_bytes() < missing_bytes + reserve_bytes:
                    raise OSError("chunked model cache capacity is unavailable")
                # Intact local bytes depend on their signed hashes and retained
                # file identities, not current remote availability. Only missing
                # files require an R2 generation snapshot and subsequent checks.
                heads = await self._heads(report, needed) if needed else {}
                for record, item in zip(bundle.files, self.selection.package.files, strict=True):
                    destination = model / record.path
                    stamp = retained.get(record.path)
                    if record.path in reusable:
                        if _local_identity(destination, root) != stamp:
                            raise ValueError("chunked model cache changed during reuse")
                        progress.advance(record.size_bytes, restored=True)
                    elif stamp is not None:
                        progress.emit(
                            "repair_required", reason="chunked_model_local_verification_required"
                        )
                        with (
                            _directory(model) as descriptor,
                            _artifact(descriptor, record) as (stream, _),
                        ):
                            await run_owned_thread(
                                _copy_verified, ProgressReader(stream, progress), record, None
                            )
                            if _local_identity(destination, root) != stamp:
                                raise ValueError("chunked model cache changed during local repair")
                            os.fchmod(stream.fileno(), 0o400)
                            await run_owned_thread(os.fsync, stream.fileno())
                            stamp = {
                                "archive": [str(root.st_dev), str(root.st_ino)],
                                "file": _file_identity(os.fstat(stream.fileno())),
                            }
                        if _local_identity(destination, root) != stamp:
                            raise ValueError("chunked model cache changed during local repair")
                        local.remember(record.path, stamp, record.sha256)
                    else:
                        if available_bytes() < record.size_bytes + reserve_bytes:
                            raise OSError("chunked model cache capacity is unavailable")
                        ensure_private_directory(destination.parent)
                        descriptor = os.open(
                            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                        )
                        hasher = hashlib.sha256()
                        with os.fdopen(descriptor, "wb", buffering=0) as output:
                            for chunk in item.chunks:
                                raw = await self._chunk(chunk, heads)
                                await run_owned_thread(check_write, len(raw))
                                if await run_owned_thread(output.write, raw) != len(raw):
                                    raise OSError("chunked model cache write was incomplete")
                                hasher.update(raw)
                                progress.advance(len(raw))
                            if hasher.hexdigest() != record.sha256:
                                raise ValueError(
                                    "restored model file differs from its signed manifest"
                                )
                            os.fchmod(output.fileno(), 0o400)
                            await run_owned_thread(os.fsync, output.fileno())
                            stamp = {
                                "archive": [str(root.st_dev), str(root.st_ino)],
                                "file": _file_identity(os.fstat(output.fileno())),
                            }
                        if _local_identity(destination, root) != stamp:
                            raise ValueError("restored model cache identity changed")
                        with _directory(destination.parent) as descriptor:
                            os.fsync(descriptor)
                        local.remember(record.path, stamp, record.sha256)
                        remote.remember(record.path, self._source(item, heads), record.sha256)
                    written.append([record.path, stamp["file"]])
                if heads:
                    await self._unchanged(heads, report)
                await run_owned_thread(publish_private_model, target / "manifest.json", bundle)
                expected = await run_owned_thread(_preserved_verification_record, bundle, archive)
                if json.loads(expected)["files"] != written:
                    raise ValueError("restored model changed before native receipt publication")
                await run_owned_thread(_remember_preserved_verification, bundle, archive, expected)
            return target
