"""Private, bounded canonical-model files shared by competition services.

These operations preserve the historical evaluator file/lock contract. They do
not know about evaluation, signing, or round policy. Callers own service-level
locking; publication additionally serializes writers in the destination folder.
"""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from pathlib import Path
from typing import Annotated, TypeVar

from pydantic import AfterValidator, BaseModel, Field

from .protocol import canonical_json_bytes

MAX_PRIVATE_BYTES = 64 * 1024**2
_Model = TypeVar("_Model", bound=BaseModel)


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


def read_private_model(path: Path, model: type[_Model]) -> _Model:
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
        if not 1 <= info.st_size <= MAX_PRIVATE_BYTES:
            raise ValueError("evaluator input exceeds its byte bound")
        raw = stream.read(MAX_PRIVATE_BYTES + 1)
    value = model.model_validate_json(raw)
    if len(raw) != info.st_size or raw != canonical_json_bytes(value):
        raise ValueError("evaluator input must have stable canonical bytes")
    return value


def lock_private_file(path: Path) -> int:
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
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def publish_private_model(path: Path, value: BaseModel) -> None:
    raw = canonical_json_bytes(value)
    if len(raw) > MAX_PRIVATE_BYTES:
        raise ValueError("evaluator output exceeds its byte bound")
    ensure_private_directory(path.parent)
    lock = lock_private_file(path.parent / ".publish.lock")
    try:
        _publish_locked(path, value, raw)
        # An exact retry may follow a successful rename whose directory sync
        # failed. Verify existing bytes, then retry durability before success.
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(lock)


def _publish_locked(path: Path, value: BaseModel, raw: bytes) -> None:
    if path.exists() or path.is_symlink():
        if canonical_json_bytes(read_private_model(path, type(value))) != raw:
            raise ValueError("evaluator outbox already contains different bytes")
        return
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
