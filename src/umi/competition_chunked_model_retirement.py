"""Read completed chunked-model byte facts for the existing cache owner.

These metadata facts grant no terminal authority or consumer release. Missing
records and active generation writes refuse retirement without repairing state,
contacting R2, reading model payloads or creating verification records.
"""

import asyncio
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from threading import Event

from .competition_artifacts import _file_identity, _preserved_verification_record
from .competition_chunked_model_backup import (
    BYTE_ABI,
    ChunkedBackupBinding,
    ChunkedObjectGeneration,
)
from .competition_model_generation_store import (
    ModelGenerationStore,
    ModelGenerationStoreConfig,
    _paths,
)
from .competition_transport_verification import (
    ByteCheckpoints,
    TransferProgress,
    verifier_semantics,
)
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import digest
from .private_files import _read_bounded_private_bytes, read_private_model


def completed_cache_retirement(reader, archive):
    archive = Path(archive)
    bundle = reader.selection.bundle
    if not reader.root.is_dir():
        raise ValueError("cache retirement durable byte records are missing")
    if read_private_model(archive / "chunked-materialization.json", ChunkedBackupBinding) != (
        reader.selection.binding
    ):
        raise ValueError("cache retirement changed its chunked materialization")
    if (archive / "materialization-pending.json").exists():
        raise ValueError("cache retirement materialization is unfinished")
    local = archive / (".verified-" + digest(bundle) + ".json")
    if _read_bounded_private_bytes(local, maximum_bytes=4 * 1024**2) != (
        _preserved_verification_record(bundle, archive)
    ):
        raise ValueError("cache retirement local identity requires repair")

    stamps = {}

    def pin(path):
        path = Path(path)
        stamp = _file_identity(path.lstat())
        if str(path) in stamps and stamps[str(path)] != stamp:
            raise ValueError("cache retirement durable byte facts changed")
        stamps[str(path)] = stamp

    # Persist the exact scope, not a stamp of the mutable shared database.
    # The execution owner reacquires this scope's read lease through eviction;
    # unrelated completed scopes must not invalidate a pending retirement.
    retained, fence = None, None
    if reader.generation_owner is not None:
        _, _, marker = _paths(reader.root, reader.generation_owner)
        pin(marker)
        owner = ModelGenerationStore(
            reader.root,
            reader.generation_owner,
            semantics=[BYTE_ABI, verifier_semantics()],
            read_only=True,
        )
        with owner.scope_lease(reader._remote_context(), reader._declarations()) as retained:
            if retained is not None:
                fence = {
                    "schema": "umi-model-cache-retirement-generation-fence/1",
                    "root": str(reader.root),
                    "owner": reader.generation_owner.model_dump(mode="json", by_alias=True),
                    "model_sha256": digest(bundle),
                    "context": reader._remote_context(),
                    "declarations": reader._declarations(),
                    "objects_sha256": digest(retained),
                }
        if retained is None:
            raise ValueError("cache retirement generation completion requires repair")
        retained = {key: ChunkedObjectGeneration.model_validate(v) for key, v in retained.items()}

    heads = {}
    with TransferProgress(
        "chunked_model_cache_retirement_verification", len(bundle.files), unit="files"
    ) as progress:
        modern = reader._store(progress)
        legacy = ByteCheckpoints(
            reader.root / reader.selection.binding.model_sha256 / "remote",
            reader._context(),
            progress,
        )
        for record, item in zip(bundle.files, reader.selection.package.files, strict=True):
            path = modern.path(record.path)
            saved = modern
            # Preserve supported original receipts. A damaged modern pair must
            # not disappear behind an older successful record.
            if not path.exists() and not path.with_suffix(".complete").exists():
                saved, path = legacy, legacy.path(record.path)
            marker = path.with_suffix(".complete")
            pin(path)
            pin(marker)
            value = saved._validated_record(
                _read_bounded_private_bytes(path, maximum_bytes=64 * 1024**2)
            )
            if (
                value["context"] != saved.context
                or value["result"] != record.sha256
                or _read_bounded_private_bytes(marker, maximum_bytes=64) != path.stem.encode()
                or not isinstance(value["identity"], list)
            ):
                raise ValueError("cache retirement remote completion requires repair")
            objects = tuple(ChunkedObjectGeneration.model_validate(v) for v in value["identity"])
            if len(objects) != len(item.chunks) or any(
                (v.key, v.sha256, v.size_bytes) != (reader._key(c), c.sha256, c.size_bytes)
                for v, c in zip(objects, item.chunks, strict=True)
            ):
                raise ValueError("cache retirement remote object coverage changed")
            for value in objects:
                if heads.setdefault(value.sha256, value) != value:
                    raise ValueError("cache retirement remote generations conflict")
            progress.advance(1, restored=True)
    if retained is not None and retained != heads:
        raise ValueError("cache retirement selected generations changed")
    if any(_file_identity(Path(name).lstat()) != stamp for name, stamp in stamps.items()):
        raise ValueError("cache retirement durable byte facts changed")
    result = {
        "request_sha256": digest(reader.selection),
        "model_sha256": digest(bundle),
        "payload_bytes": sum(record.size_bytes for record in bundle.files),
        "remote_records": stamps,
    }
    if fence is not None:
        result["generation_fence"] = fence
    return result


@contextmanager
def _generation_lease(intent):
    fence = intent["generation_fence"]
    if (
        set(fence)
        != {"schema", "root", "owner", "model_sha256", "context", "declarations", "objects_sha256"}
        or fence["schema"] != "umi-model-cache-retirement-generation-fence/1"
        or fence["model_sha256"] != intent["model_sha256"]
    ):
        raise ValueError("cache retirement generation fence differs from intent")
    config = ModelGenerationStoreConfig.model_validate(fence["owner"])
    semantics = [BYTE_ABI, verifier_semantics()]
    if (
        fence["context"]["semantics"] != semantics
        or digest(fence["context"]["namespace"]) != config.namespace_sha256
    ):
        raise ValueError("cache retirement generation semantics or namespace changed")
    owner = ModelGenerationStore(fence["root"], config, semantics=semantics, read_only=True)
    with owner.scope_lease(fence["context"], fence["declarations"]) as objects:
        if objects is None or digest(objects) != fence["objects_sha256"]:
            raise ValueError("cache retirement original generations require repair")
        yield


@asynccontextmanager
async def retirement_generation_lease(intent):
    """Keep SQLite ownership in one drained thread while the cache owner unlinks."""
    if "generation_fence" not in intent:
        yield  # Existing direct/legacy intents retain their original semantics.
        return
    release, ready = Event(), asyncio.Event()
    loop = asyncio.get_running_loop()

    def held():
        with _generation_lease(intent):
            loop.call_soon_threadsafe(ready.set)
            release.wait()

    worker = asyncio.create_task(run_owned_thread(held, on_cancel=release.set))
    waiting = asyncio.create_task(ready.wait())
    try:
        await asyncio.wait((worker, waiting), return_when=asyncio.FIRST_COMPLETED)
        if worker.done():
            worker.result()
            raise ValueError("cache retirement generation lease ended before release")
        yield
    finally:
        release.set()
        waiting.cancel()

        async def drain():
            await asyncio.gather(waiting, return_exceptions=True)
            await worker

        await await_owned_task(asyncio.create_task(drain()), on_cancel=release.set)
