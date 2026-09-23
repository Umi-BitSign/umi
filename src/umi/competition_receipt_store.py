"""Crash-recoverable publication of one immutable root installation receipt.

This is a filesystem primitive, not authorization to install a host. Callers
must validate the signed inputs and hold their native stopped-host capability.
The digest-named pending file binds interrupted writes to the original bytes.
An exclusive hard-link publication never replaces an existing final receipt;
recovery removes only the proven second name for that same completed inode.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat

from .file_identity import file_fingerprint


def _read(parent: int, name: str, owner: int, maximum: int, *, pending: bool):
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or before.st_nlink not in {1, 2}
            or stat.S_IMODE(before.st_mode)
            not in ({0o600, 0o444} if pending else {0o400, 0o440, 0o444})
            or not (0 if pending else 1) <= before.st_size <= maximum
        ):
            raise ValueError("installation receipt file is unsafe or oversized")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024**2))
            if not chunk:
                raise ValueError("installation receipt was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or file_fingerprint(before) != file_fingerprint(
            os.fstat(descriptor)
        ):
            raise ValueError("installation receipt changed while reading")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _existing(parent: int, name: str, owner: int, maximum: int, *, pending: bool):
    try:
        return _read(parent, name, owner, maximum, pending=pending)
    except FileNotFoundError:
        return None


def publish_installation_receipt(
    parent: int, name: str, payload: bytes, *, owner: int, maximum_bytes: int
) -> None:
    """Publish once under a directory lock, or finish the exact interrupted write.

    The parent must already be opened without symlinks. Unknown pending files,
    foreign links, different bytes and unsafe metadata are retained and rejected.
    Loaders still require a single-linked final file; only this writer can finish
    an interruption between link publication and removal of the pending name.
    """
    if name != "installation-receipt.json" or not 0 < len(payload) <= maximum_bytes:
        raise ValueError("invalid installation receipt name or size")
    info = os.fstat(parent)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("installation receipt parent is not root controlled")
    fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        _publish(parent, name, payload, owner, maximum_bytes)
    finally:
        fcntl.flock(parent, fcntl.LOCK_UN)


def _publish(parent: int, name: str, payload: bytes, owner: int, maximum: int) -> None:
    prefix = ".installation-receipt."
    pending = prefix + hashlib.sha256(payload).hexdigest() + ".pending"
    if {entry for entry in os.listdir(parent) if entry.startswith(prefix)} - {pending}:
        raise ValueError("installation receipt has a different interrupted publication")
    retained = _existing(parent, pending, owner, maximum, pending=True)
    final = _existing(parent, name, owner, maximum, pending=False)
    if final is not None:
        raw, selected = final
        if raw != payload:
            raise ValueError("installation receipt already exists with other bytes")
        if retained is None:
            if selected.st_nlink != 1:
                raise ValueError("installation receipt has an unknown hard link")
            os.fsync(parent)
            return
        partial, source = retained
        if (
            partial != payload
            or stat.S_IMODE(source.st_mode) != 0o444
            or source.st_nlink != 2
            or file_fingerprint(source) != file_fingerprint(selected)
        ):
            raise ValueError("pending receipt is not the selected completed inode")
        os.unlink(pending, dir_fd=parent)
        os.fsync(parent)
        return
    if retained is None:
        descriptor = os.open(
            pending,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        os.close(descriptor)
        # Retain the exact target digest before any body bytes are written.
        os.fsync(parent)
        retained = _read(parent, pending, owner, maximum, pending=True)
    partial, source = retained
    if source.st_nlink != 1 or not payload.startswith(partial):
        raise ValueError("interrupted installation receipt differs from requested bytes")
    if stat.S_IMODE(source.st_mode) == 0o444 and partial != payload:
        raise ValueError("sealed pending installation receipt is incomplete")
    flags = os.O_RDWR if stat.S_IMODE(source.st_mode) == 0o600 else os.O_RDONLY
    descriptor = os.open(
        pending, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
    )
    try:
        if file_fingerprint(os.fstat(descriptor)) != file_fingerprint(source):
            raise ValueError("pending installation receipt identity changed")
        os.lseek(descriptor, len(partial), os.SEEK_SET)
        offset = len(partial)
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise ValueError("installation receipt write made no progress")
            offset += count
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        raw, sealed = _read(parent, pending, owner, maximum, pending=True)
        if raw != payload or file_fingerprint(sealed) != file_fingerprint(os.fstat(descriptor)):
            raise ValueError("sealed installation receipt readback differs")
        # link is atomic and fails if final already exists; it cannot overwrite.
        os.link(pending, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
        selected_raw, selected = _read(parent, name, owner, maximum, pending=False)
        if selected_raw != payload or file_fingerprint(selected) != file_fingerprint(
            os.fstat(descriptor)
        ):
            raise ValueError("published installation receipt identity changed")
        if selected.st_nlink != 2:
            raise ValueError("published installation receipt has an unknown hard link")
        os.unlink(pending, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(descriptor)
