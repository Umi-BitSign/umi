"""Authenticate newly written sealed package copies without semantic replay.

Only the actual copier issues the destination verdict. It binds an existing
source verdict to all byte streams written, their held destination descriptors,
the complete sealed tree, and unchanged source/policy/release/capacity identities.
No serialized copy claim or caller-supplied digest proves successful copying.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .competition_materialization_reuse import sealed_materialization_identity
from .competition_package import (
    _canonical_absolute_path,
    _file_identity,
    _opened_sealed_directory,
    _package_reuse_key,
    _read_sealed_file,
)
from .competition_package_reuse import current_package_reuse
from .competition_work_progress import WorkProgress
from .competition_worker import _open_directory_without_links
from .protocol import canonical_json_bytes

_CHUNK = 1024 * 1024


def _write(fd, payload):
    pending = memoryview(payload)
    while pending:
        count = os.write(fd, pending)
        if count <= 0:
            raise ValueError("package copy write stopped")
        pending = pending[count:]


def _copy_file(source_fd, destination_fd, name, identity, expected_sha256, progress):
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd)
    destination = -1
    try:
        if _file_identity(os.fstat(source)) != identity:
            raise ValueError("verified source changed before package copying")
        destination = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destination_fd,
        )
        observed, digest = 0, hashlib.sha256()
        previous_chunks = progress.completed
        while True:
            chunk = os.read(source, min(_CHUNK, identity[2] + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > identity[2]:
                raise ValueError("package source grew during copying")
            digest.update(chunk)
            _write(destination, chunk)
            completed = observed // _CHUNK + int(observed == identity[2] and observed % _CHUNK != 0)
            while progress.completed < previous_chunks + completed:
                progress.advance()
        if (
            observed != identity[2]
            or digest.hexdigest() != expected_sha256
            or _file_identity(os.fstat(source)) != identity
        ):
            raise ValueError("package source changed during copying")
        os.fchmod(destination, 0o400)
        os.fsync(destination)
        written = os.fstat(destination)
        if written.st_size != observed:
            raise ValueError("package destination size differs after copying")
        return written
    finally:
        os.close(source)
        if destination >= 0:
            os.close(destination)


def copy_verified_package(source: Path, destination: Path, manifest, **arguments) -> None:
    """Copy under native package bounds; retain a verdict only from proven source."""
    destination = _canonical_absolute_path(destination, "package copy destination")
    before, input_bytes = _package_reuse_key(source, **arguments)
    reuse = current_package_reuse()
    authenticated = None if reuse is None else reuse.verified_manifest(before)
    if reuse is not None and authenticated is None:
        raise ValueError("package copy requires completed source verification")
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if authenticated is not None and authenticated != manifest_sha256:
        raise ValueError("copy manifest differs from verified source")
    expected = {entry.name: entry.sha256 for entry in manifest.files}
    expected["manifest.json"] = manifest_sha256
    identities = dict(before[6])
    if expected.keys() != identities.keys():
        raise ValueError("copy manifest differs from the sealed source tree")
    total = sum((identity[2] + _CHUNK - 1) // _CHUNK for identity in identities.values())
    with _opened_sealed_directory(source) as source_fd:
        if _file_identity(os.fstat(source_fd)) != before[5]:
            raise ValueError("verified source directory changed before copying")
        # Small manifest equality binds the supplied model to actual source bytes;
        # large payloads are each read and hashed just once while being written.
        if (
            _read_sealed_file(
                source_fd, "manifest.json", maximum_bytes=arguments["limits"].maximum_manifest_bytes
            )
            != manifest_bytes
        ):
            raise ValueError("copy manifest bytes differ from source")
        parent_fd = _open_directory_without_links(destination.parent)
        try:
            os.mkdir(destination.name, mode=0o700, dir_fd=parent_fd)
            destination_fd = os.open(
                destination.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)
        written = {}
        try:
            with WorkProgress("package_authenticated_copy", total, unit="chunks") as progress:
                for name, identity in identities.items():
                    written[name] = _copy_file(
                        source_fd, destination_fd, name, identity, expected[name], progress
                    )
                os.fchmod(destination_fd, 0o500)
                os.fsync(destination_fd)
                directory_identity = _file_identity(os.fstat(destination_fd))
                after, copied_bytes = _package_reuse_key(destination, **arguments)
                if (
                    after[5] != directory_identity
                    or dict(after[6])
                    != {name: _file_identity(info) for name, info in written.items()}
                    or copied_bytes != input_bytes
                ):
                    raise ValueError("package destination changed during copying")
                if _package_reuse_key(source, **arguments) != (before, input_bytes):
                    raise ValueError("verified source changed during package copying")
                if authenticated is not None:
                    if reuse.verified_manifest(before) != authenticated:
                        raise ValueError("source verification changed during copying")
                    # No copied destination byte is read again to obtain this
                    # result. The sealed identities bind the successful writes.
                    for name, info in written.items():
                        observed = reuse.materialization.digest(
                            destination / name,
                            sealed_materialization_identity(info),
                            lambda name=name: expected[name],
                        )
                        if observed != expected[name]:
                            raise ValueError("copied file digest metadata differs")
                    if _package_reuse_key(destination, **arguments) != (after, copied_bytes):
                        raise ValueError("package destination changed before copy publication")
                    reuse._remember_manifest(after, authenticated)
        finally:
            os.close(destination_fd)
