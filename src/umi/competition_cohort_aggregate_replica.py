"""Replicate an already natively verified aggregate without retaining its model.

The caller supplies the digest it obtained from native schema and semantic
replay. This only preserves those exact bytes; it never validates new evidence
or grants certification, signing, or reward authority.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO

from .competition_cohort_capacity import check_aggregate_evidence_bytes
from .private_files import ensure_private_directory, lock_private_file, private_path

_CHUNK_BYTES = 1024**2


def _private_info(descriptor: int, maximum_bytes: int) -> os.stat_result:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("aggregate replica requires an owned private regular file")
    if not 1 <= info.st_size <= maximum_bytes:
        raise ValueError("aggregate replica exceeds its byte bound")
    return info


def _transfer(
    path: Path,
    output: BinaryIO | None,
    expected_digest: str,
    maximum_bytes: int,
) -> None:
    private_path(str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        original = _private_info(stream.fileno(), maximum_bytes)
        sha = hashlib.sha256(b"umi-open-competition-v1\0")
        used = 0
        while chunk := stream.read(min(_CHUNK_BYTES, maximum_bytes + 1 - used)):
            used += len(chunk)
            if used > maximum_bytes:
                raise ValueError("aggregate replica exceeds its byte bound")
            sha.update(chunk)
            if output is not None:
                output.write(chunk)
        current = _private_info(stream.fileno(), maximum_bytes)
        selected = path.stat(follow_symlinks=False)
        if (
            used != original.st_size
            or (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
            != (original.st_size, original.st_mtime_ns, original.st_ctime_ns)
            or (selected.st_dev, selected.st_ino) != (original.st_dev, original.st_ino)
            or sha.hexdigest() != expected_digest
        ):
            raise ValueError("aggregate replica differs from its verified original")


def replicate_verified_aggregate(
    source: Path,
    destination: Path,
    *,
    expected_digest: str,
    maximum_bytes: int,
) -> None:
    """Copy exact verified bytes privately; missing originals remain mandatory.

    Both first publication and an exact retry authenticate the source again.
    A matching existing destination stays in place and its directory is synced
    again, including recovery after a lost publication acknowledgement.
    """
    maximum_bytes = check_aggregate_evidence_bytes(maximum_bytes)
    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != 64
        or any(c not in "0123456789abcdef" for c in expected_digest)
    ):
        raise ValueError("aggregate replica requires a verified protocol digest")
    private_path(str(source))
    private_path(str(destination))
    ensure_private_directory(source.parent)
    ensure_private_directory(destination.parent)
    lock = lock_private_file(destination.parent / ".publish.lock")
    try:
        if destination.exists() or destination.is_symlink():
            _transfer(source, None, expected_digest, maximum_bytes)
            _transfer(destination, None, expected_digest, maximum_bytes)
        else:
            descriptor, name = tempfile.mkstemp(prefix=".pending-", dir=destination.parent)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    _transfer(source, output, expected_digest, maximum_bytes)
                    output.flush()
                    os.fsync(output.fileno())
                os.rename(name, destination)
            finally:
                if os.path.exists(name):
                    os.unlink(name)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(lock)
