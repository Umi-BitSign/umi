"""Live native consumer bindings for automatic local model retirement.

Consumers publish only authenticated storage metadata. Shared leases prevent a
replacement process from changing those bindings during retirement; PID start
identity rejects a leftover capability after shutdown. No capability grants
model admission, proof validity or rewards.
"""

from __future__ import annotations

import asyncio
import os
import stat
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_transport_verification import TransferProgress
from .competition_verification_rules import runtime_identity
from .open_competition import Hotkey, Signature, digest, identity, verify_signature
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

try:
    import fcntl
except ImportError:  # Public model clients do not select local coordination.
    fcntl = None

MAX_CAPABILITY_BYTES = 4 * 1024**2


class ModelStorageConsumerConfig(StrictProtocolModel):
    directory: Directory


class ModelStorageConsumerBinding(ModelStorageConsumerConfig):
    kind: Literal["reviewer", "settlement"]
    hotkey: Hotkey


class ModelUploadRetirementConfig(StrictProtocolModel):
    consumers: Annotated[
        tuple[ModelStorageConsumerBinding, ...], Field(min_length=2, max_length=128)
    ]
    protected_models: Annotated[tuple[Hex32, ...], Field(max_length=65536)] = ()
    batch_models: Annotated[int, Field(ge=1, le=16)] = 1

    @model_validator(mode="after")
    def unique(self):
        keys = [(c.kind, identity(c.hotkey)) for c in self.consumers]
        if len(keys) != len(set(keys)) or len({c.directory for c in self.consumers}) != len(keys):
            raise ValueError("model retirement repeats a consumer or lease directory")
        if tuple(sorted(set(self.protected_models))) != self.protected_models:
            raise ValueError("model retirement protected models must be unique and ordered")
        return self


class _RemoteCohort(StrictProtocolModel):
    cohort_sha256: Hex32
    preservation_sha256: Hex32
    models: Annotated[tuple[Hex32, ...], Field(max_length=65536)]


class ModelStorageCapability(StrictProtocolModel):
    schema_: Literal["umi-model-storage-consumer/1"] = Field(alias="schema")
    kind: Literal["reviewer", "settlement"]
    hotkey: Hotkey
    process_id: Annotated[int, Field(ge=1)]
    process_start: str
    owner_uid: Annotated[int, Field(ge=0)]
    policy_sha256: Hex32
    series_sha256: Hex32
    authority_sha256: Hex32
    verification_semantics: Hex32
    remote: Annotated[tuple[_RemoteCohort, ...], Field(max_length=512)]


class SignedModelStorageCapability(StrictProtocolModel):
    capability: ModelStorageCapability
    signature: Signature


def _process_start(pid):
    # Linux starttime is stable through ordinary clock adjustments and cannot
    # be confused with a later process reusing this PID. Unsupported hosts
    # refuse only this explicitly selected local coordination feature.
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw.rsplit(")", 1)[1].split()[19]


def _directory(path, *, owner=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if (owner is not None and info.st_uid != owner) or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError("model storage lease directory must be owned and not writable by peers")
    return fd


def _lease(root, *, writing, name="consumer.lock"):
    if fcntl is None:
        raise RuntimeError("local model storage coordination requires POSIX leases")
    flags = os.O_RDWR | os.O_CREAT if writing else os.O_RDONLY
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640, dir_fd=root)
    info = os.fstat(fd)
    parent = os.fstat(root)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size
        or info.st_uid != parent.st_uid
        or info.st_mode & 0o027
    ):
        os.close(fd)
        raise ValueError("model storage consumer lease identity changed")
    if writing:
        os.fchmod(fd, 0o640)
    return fd


@asynccontextmanager
async def model_storage_consumer(config, *, kind, hotkey, policy, series, sources, sign):
    """Publish and keep this process's selected R2 bindings alive until shutdown."""
    if config is None:
        yield
        return
    if sources is None:
        raise ValueError("model storage consumer requires authenticated remote sources")
    root = _directory(config.directory, owner=os.geteuid())
    fd = live = None
    published = False
    try:
        fd = _lease(root, writing=True)
        live = _lease(root, writing=True, name="consumer.live")
        with TransferProgress(
            "model_storage_consumer_publication", 1, unit="consumers"
        ) as progress:
            while True:
                try:
                    fcntl.flock(live, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    progress.emit("waiting", reason="existing_model_storage_consumer")
                    await asyncio.sleep(0.5)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    progress.emit("waiting", reason="existing_model_storage_retirement_lease")
                    await asyncio.sleep(0.5)
            body = ModelStorageCapability(
                schema="umi-model-storage-consumer/1",
                kind=kind,
                hotkey=hotkey,
                process_id=os.getpid(),
                process_start=_process_start(os.getpid()),
                owner_uid=os.geteuid(),
                policy_sha256=digest(policy),
                series_sha256=digest(series),
                authority_sha256=digest(series.recovery.authority),
                verification_semantics=runtime_identity(),
                remote=tuple(
                    _RemoteCohort(
                        cohort_sha256=cohort,
                        preservation_sha256=digest(value.preservation),
                        models=tuple(
                            sorted(model.model_sha256 for model in value.preservation.models)
                        ),
                    )
                    for cohort, value in sorted(sources.authenticated.items())
                ),
            )
            signed = SignedModelStorageCapability(capability=body, signature=await sign(body))
            if identity(signed.signature.hotkey) != identity(hotkey):
                raise ValueError("model storage capability has another signer")
            verify_signature(body, signed.signature)
            raw = canonical_json_bytes(signed)
            if len(raw) > MAX_CAPABILITY_BYTES:
                raise ValueError("model storage capability exceeds its byte bound")
            temporary = ".consumer-next.json"
            out = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o640,
                dir_fd=root,
            )
            try:
                info = os.fstat(out)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                ):
                    raise ValueError("model storage capability staging identity changed")
                with os.fdopen(out, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o640)
                    os.fsync(stream.fileno())
            finally:
                os.close(out)
            os.rename(temporary, "consumer.json", src_dir_fd=root, dst_dir_fd=root)
            os.fsync(root)
            fcntl.flock(fd, fcntl.LOCK_SH)
            published = True
            progress.advance(1)
        yield
    finally:
        if published:
            # Orderly shutdown preserves the declaration while a retirement
            # reader still owns it. A successor cannot start model work until
            # that reader releases its shared transition lease.
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    await asyncio.sleep(0.5)
        if live is not None:
            os.close(live)
        if fd is not None:
            os.close(fd)
        os.close(root)


@contextmanager
def model_storage_consumer_release(config, *, policy, series, requests, sources):
    """Hold exact live consumer declarations throughout one model's retirement."""
    expected = {
        (kind, identity(e.hotkey)) for kind in ("reviewer", "settlement") for e in policy.evaluators
    }
    if {(c.kind, identity(c.hotkey)) for c in config.consumers} != expected:
        raise ValueError(
            "model retirement must include every native reviewer and settlement consumer"
        )
    held = []
    try:
        for selected in sorted(config.consumers, key=lambda c: c.directory):
            root = _directory(selected.directory)
            held.append(root)
            fd = _lease(root, writing=False)
            held.append(fd)
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            live = _lease(root, writing=False, name="consumer.live")
            held.append(live)
            try:
                fcntl.flock(live, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(live, fcntl.LOCK_UN)
                raise OSError("model storage consumer declaration is no longer live")
            capability_fd = os.open(
                "consumer.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root
            )
            try:
                info = os.fstat(capability_fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.fstat(root).st_uid
                    or info.st_mode & 0o027
                    or not 0 < info.st_size <= MAX_CAPABILITY_BYTES
                ):
                    raise ValueError("model storage consumer capability is unsafe")
                with os.fdopen(capability_fd, "rb", closefd=False) as stream:
                    signed = SignedModelStorageCapability.model_validate_json(
                        stream.read(MAX_CAPABILITY_BYTES + 1)
                    )
            finally:
                os.close(capability_fd)
            body = signed.capability
            if (
                (body.kind, identity(body.hotkey)) != (selected.kind, identity(selected.hotkey))
                or identity(signed.signature.hotkey) != identity(selected.hotkey)
                or body.owner_uid != info.st_uid
                or (
                    body.policy_sha256,
                    body.series_sha256,
                    body.authority_sha256,
                    body.verification_semantics,
                )
                != (
                    digest(policy),
                    digest(series),
                    digest(series.recovery.authority),
                    runtime_identity(),
                )
                or _process_start(body.process_id) != body.process_start
            ):
                raise ValueError(
                    "model storage consumer changed process, lineage or verifier semantics"
                )
            verify_signature(body, signed.signature)
            remote = {value.cohort_sha256: value for value in body.remote}
            if len(remote) != len(body.remote):
                raise ValueError("model storage consumer repeats a cohort")
            for request in requests:
                cohort = request.consent.consent.cohort_sha256
                original = sources.authenticated[cohort]
                binding = remote.get(cohort)
                if (
                    binding is None
                    or binding.preservation_sha256 != digest(original.preservation)
                    or request.signed_submission.submission.model_revision not in binding.models
                ):
                    raise OSError(
                        "model storage consumer has not selected this preserved remote model"
                    )
        yield
    finally:
        for fd in reversed(held):
            os.close(fd)
