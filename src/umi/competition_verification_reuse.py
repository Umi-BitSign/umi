"""Owner-private receipts for completed, exact-input native verification.

Receipts are durable local verification records, never signed evidence or remote
certification authority. Unchanged immutable sources retain their original
verdict across phases and restart; collector coverage remains complete.
Current authority/finality checks stay outside these pure replay boundaries.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import tempfile
import time
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Literal

from pydantic import BaseModel, Field

from .canonical_stream import canonical_json_matches
from .competition_policy_lineage import admitted_policy_sha256s
from .competition_verification_rules import runtime_identity
from .competition_work_progress import WorkProgress
from .host_memory_request_bounds import check_stage_json, stage_bounds, stage_limit
from .private_files import (
    PrivateStateBusyError,
    _read_bounded_private_bytes,
    ensure_private_directory,
    lock_private_file,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_LOG = logging.getLogger("umi.competition.progress")
_CURRENT = ContextVar("competition_verification_reuse", default=None)
_LOCKED = ContextVar("competition_verification_locked", default=())


class VerificationSourceChanged(ValueError):
    """An owned immutable input needs native restoration before reuse."""


class VerificationDependency(StrictProtocolModel):
    kind: Literal["objects", "source", "decision_source", "pulses"]
    key: Hex32 | int
    sha256: Hex32
    source_identity: str | None = None


class VerificationReceipt(StrictProtocolModel):
    schema_: Literal["umi-private-native-verification/1"] = Field(alias="schema")
    identity: Hex32
    dependencies: tuple[VerificationDependency, ...]
    result_json: str
    checksum: Hex32


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_verification_metadata(path: Path):
    """Read owner-generated metadata without a second evidence capacity limit.

    These files are private derived state, never network declarations. Their
    exact current size bounds the read; the ordinary private-file checks apply.
    Evidence admission and replay still enforce the selected native budgets.
    """
    before = path.lstat()
    raw = _read_bounded_private_bytes(path, maximum_bytes=before.st_size)
    after = path.lstat()
    if any(
        getattr(before, field) != getattr(after, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
        )
    ):
        raise VerificationSourceChanged("verification metadata changed while reading")
    return raw


def metadata_completion(path: Path):
    return path.with_suffix(".complete")


def remember_metadata_completion(path: Path):
    """Distinguish a missing completed record from a first native evaluation."""
    marker = metadata_completion(path)
    if marker.exists():
        return
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, path.stem.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _identity(value):
    """Encode all inputs without retaining mutable models or raw evidence."""
    if isinstance(value, BaseModel):
        return {"model": type(value).__name__, "sha256": _sha(canonical_json_bytes(value))}
    if isinstance(value, bytes):
        return {"bytes": _sha(value), "length": len(value)}
    if isinstance(value, (tuple, list)):
        return {type(value).__name__: [_identity(v) for v in value]}
    if isinstance(value, dict):
        return {"dict": [[k, _identity(v)] for k, v in sorted(value.items())]}
    if value is None or type(value) in (str, int, bool):
        return value
    raise TypeError("unsupported native verification context")


def _payload(identity, dependencies, result):
    return canonical_json_bytes(
        [identity, [d.model_dump(mode="json") for d in dependencies], result]
    )


class VerificationReuse:
    def __init__(self, directory: Path, *, owner):
        self.owner = _identity(owner)
        shared = os.environ.get("UMI_NATIVE_VERIFICATION_DIRECTORY")
        selected = (
            Path(shared) / _sha(canonical_json_bytes(self.owner))
            if shared is not None
            else directory
        )
        ensure_private_directory(selected)
        self.directory = selected
        self.legacy_directory = directory if selected != directory and directory.is_dir() else None
        self.runtime = runtime_identity()
        self.pid = os.getpid()
        self.lock = RLock()

    @contextmanager
    def selected(self):
        token = _CURRENT.set(self if self.pid == os.getpid() else None)
        try:
            yield self
        finally:
            _CURRENT.reset(token)

    @contextmanager
    def exclusive(self):
        """One native first verification per owner across workers and processes."""
        with self.lock:
            key = str(self.directory)
            if key in _LOCKED.get():
                yield
                return
            try:
                descriptor = lock_private_file(self.directory / ".verification.lock")
            except PrivateStateBusyError:
                _event("verification_owner", "waiting_for_owner")
                raise
            token = _LOCKED.set((*_LOCKED.get(), key))
            try:
                yield
            finally:
                _LOCKED.reset(token)
                os.close(descriptor)

    def load(self, key):
        directories = (self.directory,) + (
            () if self.legacy_directory is None else (self.legacy_directory,)
        )
        for directory in directories:
            path = directory / (key + ".json")
            try:
                raw = read_verification_metadata(path)
                receipt = VerificationReceipt.model_validate_json(raw)
                if not canonical_json_matches(receipt, raw):
                    raise ValueError("verification receipt is not canonical")
                if receipt.identity != key or receipt.checksum != _sha(
                    _payload(key, receipt.dependencies, receipt.result_json)
                ):
                    raise ValueError("verification receipt checksum or identity differs")
            except FileNotFoundError:
                if metadata_completion(path).exists():
                    _event("verification_receipt", "repair_required")
            except (OSError, ValueError):
                _event("verification_receipt", "repair_required")
            else:
                # A write failure after a valid read is pending storage work,
                # not permission to throw away and recompute the native result.
                if directory != self.directory:
                    self.remember(key, receipt.dependencies, receipt.result_json)
                    _event("verification_receipt", "metadata_migrated", len(receipt.dependencies))
                else:
                    remember_metadata_completion(path)
                return receipt
        return None

    def remember(self, key, dependencies, result):
        receipt = VerificationReceipt(
            schema="umi-private-native-verification/1",
            identity=key,
            dependencies=dependencies,
            result_json=result,
            checksum=_sha(_payload(key, dependencies, result)),
        )
        # Atomic replacement repairs only this derived record. A process exit
        # before replacement retains the prior record; after it retains the new
        # one. Publication failure is visible and cannot silently discard work.
        path = self.directory / (key + ".json")
        raw = canonical_json_bytes(receipt)
        fd, pending = tempfile.mkstemp(prefix=".verification-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(pending, path)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            remember_metadata_completion(path)
        finally:
            Path(pending).unlink(missing_ok=True)


def _event(stage, state, dependencies=0, *, elapsed=0.0, planning_range=None):
    _LOG.info(
        json.dumps(
            {
                "schema": "umi-native-verification-reuse/1",
                "stage": stage,
                "state": state,
                "dependencies": dependencies,
                "elapsed_seconds": round(elapsed, 3),
                "eta_seconds": 0 if state in {"hit", "retained"} else None,
                "eta_basis": "completed"
                if state in {"hit", "retained"}
                else "native_substage_counts",
                "certification_authority": False,
                **(
                    {}
                    if planning_range is None
                    else {
                        "planning_eta_seconds": planning_range,
                        "planning_eta_basis": "package_bytes_at_1_to_10_mib_per_second",
                        "planning_eta_scope": "native_package_decode_and_identity_only",
                    }
                ),
            },
            separators=(",", ":"),
        )
    )


def verified_replay(stage, result_model):
    """Memoize only eager deterministic replay with explicit dynamic sources."""

    def decorate(function):
        signature = inspect.signature(function)

        @wraps(function)
        def run(*args, **kwargs):
            reuse = _CURRENT.get()
            if reuse is None or reuse.pid != os.getpid():
                return function(*args, **kwargs)
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            if "intake_records" in bound.arguments:
                bound.arguments["intake_records"] = tuple(bound.arguments["intake_records"])
            sources = {
                k: v
                for k, v in bound.arguments.items()
                if k in ("objects", "source", "decision_source", "pulses")
            }

            def context():
                return _identity(
                    {
                        "arguments": {k: v for k, v in bound.arguments.items() if k not in sources},
                        "bounds": stage_bounds(),
                        "lineage": admitted_policy_sha256s(bound.arguments["policy"]),
                        "owner": reuse.owner,
                        "runtime": reuse.runtime,
                        "stage": stage,
                    }
                )

            started = time.monotonic()
            original = context()
            key = _sha(canonical_json_bytes(original))
            # Serialize same-owner work, including nested replay. Separate owners
            # have separate receipts and must establish their own verification.
            with reuse.exclusive():
                receipt = reuse.load(key)
                if receipt is not None:
                    with WorkProgress(
                        "verification_dependencies", len(receipt.dependencies), unit="objects"
                    ) as progress:
                        valid = True
                        for dependency in receipt.dependencies:
                            source = sources[dependency.kind]
                            trusted = (
                                getattr(source, "verification_identity", lambda _: None)(
                                    dependency.key
                                )
                                if dependency.kind in {"objects", "source"}
                                else None
                            )
                            authenticated_sha = (
                                getattr(source, "verification_sha256", None)
                                if trusted is not None
                                else None
                            )
                            # A second natively imported package may hold the
                            # same bytes under another immutable local identity.
                            # Its owning snapshot has already authenticated its
                            # byte SHA and just checked its actual current stamp.
                            # Do not reread those bytes solely due to package role.
                            if trusted is not None and (
                                trusted == dependency.source_identity
                                or (
                                    authenticated_sha is not None
                                    and authenticated_sha(dependency.key) == dependency.sha256
                                )
                            ):
                                replay = getattr(source, "verification_replay", None)
                                if replay is not None:
                                    replay(dependency.key)
                                else:
                                    source(dependency.key)
                                progress.advance()
                                continue
                            value = source(dependency.key)
                            raw = (
                                value
                                if dependency.kind in {"objects", "source"}
                                else canonical_json_bytes(value)
                            )
                            if not isinstance(raw, bytes) or _sha(raw) != dependency.sha256:
                                valid = False
                                break
                            if dependency.kind in {"objects", "source"}:
                                if (
                                    not 1
                                    <= len(raw)
                                    <= stage_limit("maximum_object_bytes", 16 * 1024**2)
                                ):
                                    raise ValueError(
                                        "cached evidence exceeds its selected object bound"
                                    )
                                check_stage_json(raw, kind="object")
                            progress.advance()
                    if valid and context() == original:
                        decode = getattr(result_model, "model_validate_json", None)
                        result = (
                            decode(receipt.result_json)
                            if decode is not None
                            else result_model.validate_json(receipt.result_json)
                        )
                        _event(
                            stage,
                            "hit",
                            len(receipt.dependencies),
                            elapsed=time.monotonic() - started,
                        )
                        return result
                    _event(stage, "invalidated")
                else:
                    _event(stage, "miss")
                dependencies = {}

                def capture(kind, source):
                    def record(identity, raw=None):
                        trusted = (
                            getattr(source, "verification_identity", lambda _: None)(identity)
                            if kind in {"objects", "source"}
                            else None
                        )
                        byte_digest = (
                            getattr(source, "verification_sha256", None)
                            if kind in {"objects", "source"}
                            else None
                        )
                        if byte_digest is not None and trusted is not None:
                            sha = byte_digest(identity)
                        else:
                            if raw is None:
                                return read(identity)
                            sha = _sha(raw)
                        captured = (sha, trusted)
                        if dependencies.setdefault((kind, identity), captured) != captured:
                            raise ValueError("native verification dependency changed during replay")

                    def read(identity):
                        before = (
                            getattr(source, "verification_identity", lambda _: None)(identity)
                            if kind in {"objects", "source"}
                            else None
                        )
                        value = source(identity)
                        raw = (
                            value if kind in {"objects", "source"} else canonical_json_bytes(value)
                        )
                        if not isinstance(raw, bytes):
                            raise TypeError("native verification object source must return bytes")
                        record(identity, raw)
                        after = (
                            getattr(source, "verification_identity", lambda _: None)(identity)
                            if kind in {"objects", "source"}
                            else None
                        )
                        if before != after:
                            raise VerificationSourceChanged(
                                "verification source changed during read"
                            )
                        return value

                    if kind in {"objects", "source"}:
                        for method in (
                            "verification_identity",
                            "verification_sha256",
                            "verification_size",
                        ):
                            if hasattr(source, method):
                                setattr(read, method, getattr(source, method))
                        if hasattr(source, "verification_replay"):

                            def replay(identity):
                                source.verification_replay(identity)
                                record(identity)

                            read.verification_replay = replay
                    return read

                for name, source in sources.items():
                    bound.arguments[name] = capture(name, source)
                result = function(*bound.args, **bound.kwargs)
                if context() != original:
                    raise ValueError("native verification context changed during replay")
                recorded = tuple(
                    VerificationDependency(kind=k, key=i, sha256=s, source_identity=t)
                    for (k, i), (s, t) in sorted(dependencies.items())
                )
                encoded = (
                    result
                    if isinstance(result, BaseModel)
                    else result_model.dump_python(result, mode="json", by_alias=True)
                )
                reuse.remember(key, recorded, canonical_json_bytes(encoded).decode())
                _event(stage, "retained", len(recorded), elapsed=time.monotonic() - started)
                return result

        return run

    return decorate


def verification_owner_operation(function):
    """Async entry scope copied to owned native worker threads by asyncio."""

    @wraps(function)
    async def run(self, *args, **kwargs):
        with self.verification_reuse.selected():
            try:
                return await function(self, *args, **kwargs)
            except VerificationSourceChanged:
                _event("verification_snapshot", "repair_required")
                if hasattr(self, "_release_active_inputs"):
                    self._release_active_inputs()
                raise

    return run


class RetainedObjectInventory:
    """Immutable bytes from an independently authenticated native package.

    The owning package reader establishes the selected package identity before
    constructing this source. Callers cannot mutate its byte inventory in place.
    Context-bound receipt replay still establishes miner semantic correctness.
    """

    def __init__(self, values, package_sha256):
        self._values = MappingProxyType(dict(values))
        if any(type(raw) is not bytes for raw in self._values.values()):
            raise TypeError("retained inventory requires immutable bytes")
        self._package = package_sha256

    def __call__(self, key):
        return self._values[key]

    def verification_identity(self, key):
        self._values[key]
        return self._package + ":" + key
