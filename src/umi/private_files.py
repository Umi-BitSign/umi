"""Private, bounded canonical-model files shared by competition services.

These operations preserve the historical evaluator file/lock contract. They do
not know about evaluation, signing, or round policy. Callers own service-level
locking; publication additionally serializes writers in the destination folder.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import tempfile
from pathlib import Path
from typing import Annotated, Literal, TypeVar

from pydantic import AfterValidator, BaseModel, Field

from .canonical_stream import canonical_json_matches
from .host_memory_request_bounds import charge_stage_declaration, check_stage_json, stage_limit
from .protocol import canonical_json_bytes

MAX_PRIVATE_BYTES = 64 * 1024**2
MAX_CONFIGURED_PRIVATE_BYTES = 512 * 1024**2
_Model = TypeVar("_Model", bound=BaseModel)


class PrivateStateBusyError(BlockingIOError):
    """A validated private mutex is held by another descriptor."""

    def __init__(self, operation: str, resource_sha256: str, error_number: int | None):
        super().__init__(error_number, "private state mutex is busy")
        self.operation = operation
        self.resource_sha256 = resource_sha256

    def __reduce__(self):
        return type(self), (self.operation, self.resource_sha256, self.errno)


def acquire_private_mutex(
    descriptor: int,
    path: Path,
    *,
    operation: Literal["private_file_lock", "round_journal_lock"],
    shared: bool = False,
) -> None:
    """Classify only actual nonblocking flock contention, without disclosing paths.

    The caller owns descriptor validation, identity checks and cleanup. Failures
    in those steps, or in journal I/O, must not be reported as mutex contention.
    """
    try:
        fcntl.flock(descriptor, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
    except BlockingIOError as error:
        resource = hashlib.sha256(
            b"umi-private-state-lock-v1\0" + os.fsencode(os.path.abspath(path))
        ).hexdigest()
        raise PrivateStateBusyError(operation, resource, error.errno) from error


def private_path(value: str) -> str:
    path = Path(value)
    if (
        not path.is_absolute()
        or path == Path(path.anchor)
        or ".." in path.parts
        or "\x00" in value
        or any(part.is_symlink() for part in (path, *path.parents))
    ):
        raise ValueError("evaluator paths must be explicit absolute non-symlink directories")
    return value


Directory = Annotated[str, Field(min_length=1, max_length=4096), AfterValidator(private_path)]


def ensure_private_directory(path: Path) -> None:
    private_path(str(path))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("evaluator directory must be owned and private")


def _byte_bound(maximum_bytes: int | None) -> int:
    if maximum_bytes is None:
        return MAX_PRIVATE_BYTES
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_CONFIGURED_PRIVATE_BYTES:
        raise ValueError("invalid private file byte bound")
    return maximum_bytes


def _read_private_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    maximum_bytes = _byte_bound(maximum_bytes)
    return _read_bounded_private_bytes(path, maximum_bytes=maximum_bytes)


def _read_bounded_private_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    """Read with a caller-validated capacity; all private file checks still apply."""
    private_path(str(path))
    ensure_private_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("evaluator input must be an owned private regular file")
        if not 1 <= info.st_size <= maximum_bytes:
            raise ValueError("evaluator input exceeds its byte bound")
        raw = stream.read(maximum_bytes + 1)
    if len(raw) != info.st_size:
        raise ValueError("evaluator input must have stable canonical bytes")
    return raw


def read_private_model(
    path: Path, model: type[_Model], *, maximum_bytes: int | None = None
) -> _Model:
    raw = _read_private_bytes(
        path, maximum_bytes=stage_limit("maximum_declaration_bytes", _byte_bound(maximum_bytes))
    )
    charge_stage_declaration(len(raw))
    check_stage_json(raw, kind="declaration")
    value = model.model_validate_json(raw)
    if not canonical_json_matches(value, raw):
        raise ValueError("evaluator input must have stable canonical bytes")
    return value


def lock_private_file(path: Path, *, shared: bool = False) -> int:
    """Return an exclusively locked descriptor; its owner must close it."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("evaluator lock must be an owned private regular file")
        acquire_private_mutex(fd, path, operation="private_file_lock", shared=shared)
    except BaseException:
        os.close(fd)
        raise
    return fd


def publish_private_model(
    path: Path, value: BaseModel, *, maximum_bytes: int | None = None
) -> None:
    maximum_bytes = _byte_bound(maximum_bytes)
    _publish_bounded_private_model(path, value, maximum_bytes=maximum_bytes)


def _publish_bounded_private_model(path: Path, value: BaseModel, *, maximum_bytes: int) -> None:
    """Publish with a caller-validated capacity and unchanged ownership/durability."""
    raw = canonical_json_bytes(value)
    if len(raw) > maximum_bytes:
        raise ValueError("evaluator output exceeds its byte bound")
    ensure_private_directory(path.parent)
    lock = lock_private_file(path.parent / ".publish.lock")
    try:
        _publish_locked(path, value, raw, maximum_bytes=maximum_bytes)
        # An exact retry may follow a successful rename whose directory sync
        # failed. Verify existing bytes, then retry durability before success.
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        # A concurrent proof-helper fork can temporarily inherit this open
        # description, even with close_fds/CLOEXEC. Closing our descriptor alone
        # then leaves flock held until that child closes its copy. Release our
        # completed publication explicitly before handing off the directory.
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            os.close(lock)


def _publish_locked(path: Path, value: BaseModel, raw: bytes, *, maximum_bytes: int) -> None:
    if path.exists() or path.is_symlink():
        # The caller already serialized the supplied model canonically. Exact
        # bytes prove canonical equality without serializing the retained object
        # twice more. Retain schema validation: callers can supply a constructed
        # model that skipped validation, or a model with mutated nested content.
        if _read_bounded_private_bytes(path, maximum_bytes=maximum_bytes) != raw:
            raise ValueError("evaluator outbox already contains different bytes")
        retained = type(value).model_validate_json(raw)
        if not canonical_json_matches(retained, raw):
            raise ValueError("evaluator input must have stable canonical bytes")
        return
    _write_private_bytes(path, raw)


def _write_private_bytes(path: Path, raw: bytes) -> None:
    """Write under the caller's private directory lease; caller syncs its directory."""
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # All writers hold the dedicated directory lock. Atomic rename publishes
        # one link, including when the process dies immediately afterward.
        os.rename(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
