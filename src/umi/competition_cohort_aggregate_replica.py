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
from .competition_transport_verification import (
    ByteCheckpoints,
    TransferProgress,
    verification_tick,
    verifier_semantics,
)
from .file_identity import file_fingerprint
from .private_files import ensure_private_directory, lock_private_file, private_path

_CHUNK_BYTES = 1024**2


def _stamp(path, maximum_bytes):
    private_path(str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = _private_info(descriptor, maximum_bytes)
        if file_fingerprint(path.lstat()) != file_fingerprint(before):
            raise ValueError("aggregate replica changed during metadata check")
        return [str(value) for value in file_fingerprint(before)]
    finally:
        os.close(descriptor)


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
    *,
    verified_identity=None,
    progress=None,
):
    private_path(str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        original = _private_info(stream.fileno(), maximum_bytes)
        original_identity = [str(value) for value in file_fingerprint(original)]
        if verified_identity is not None and verified_identity != original_identity:
            raise ValueError("aggregate replica source changed after verification lookup")
        sha = hashlib.sha256(b"umi-open-competition-v1\0") if verified_identity is None else None
        used = 0
        while chunk := stream.read(min(_CHUNK_BYTES, maximum_bytes + 1 - used)):
            used += len(chunk)
            if used > maximum_bytes:
                raise ValueError("aggregate replica exceeds its byte bound")
            if sha is not None:
                sha.update(chunk)
            if output is not None:
                output.write(chunk)
            if progress is not None:
                progress.advance(len(chunk))
        current = _private_info(stream.fileno(), maximum_bytes)
        selected = path.stat(follow_symlinks=False)
        if (
            used != original.st_size
            or (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
            != (original.st_size, original.st_mtime_ns, original.st_ctime_ns)
            or (selected.st_dev, selected.st_ino) != (original.st_dev, original.st_ino)
            or file_fingerprint(current) != file_fingerprint(original)
            or file_fingerprint(selected) != file_fingerprint(original)
            or (sha is not None and sha.hexdigest() != expected_digest)
        ):
            raise ValueError("aggregate replica differs from its verified original")
        return original_identity


def replicate_verified_aggregate(
    source: Path,
    destination: Path,
    *,
    expected_digest: str,
    maximum_bytes: int,
) -> None:
    """Copy exact verified bytes privately; missing originals remain mandatory.

    Successful byte checks persist under the destination's private metadata
    directory. Exact retries inspect file identities without payload reads.
    Legacy files and damaged receipts receive a visible scoped first check or
    repair. A matching destination stays in place across lost acknowledgements.
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
        source_identity = _stamp(source, maximum_bytes)
        exists = destination.exists() or destination.is_symlink()
        target_identity = _stamp(destination, maximum_bytes) if exists else None
        total = int(source_identity[6]) + (
            int(target_identity[6]) if exists and destination != source else 0
        )
        context = {
            "digest": expected_digest,
            "owner_uid": os.getuid(),
            "semantics": verifier_semantics(),
            "authority_scope": "exact_aggregate_bytes_only",
        }
        root = (
            destination.parent
            / ".aggregate-verification"
            / hashlib.sha256(destination.name.encode()).hexdigest()
        )
        with (
            TransferProgress("aggregate_replica", total) as progress,
            ByteCheckpoints(root, context, progress) as saved,
        ):
            if exists:
                for path, stamp in ((source, source_identity), (destination, target_identity)):
                    if path == destination == source and progress.completed:
                        continue
                    if saved.load(str(path), stamp) == expected_digest:
                        progress.advance(int(stamp[6]), restored=True)
                    else:
                        progress.emit("running")
                        reusable = verification_tick(int(stamp[-1]), progress)
                        observed = _transfer(
                            path, None, expected_digest, maximum_bytes, progress=progress
                        )
                        if reusable:
                            saved.remember(str(path), observed, expected_digest)
            else:
                verified = saved.load(str(source), source_identity) == expected_digest
                reusable = verified or verification_tick(int(source_identity[-1]), progress)
                descriptor, name = tempfile.mkstemp(prefix=".pending-", dir=destination.parent)
                try:
                    with os.fdopen(descriptor, "wb") as output:
                        observed = _transfer(
                            source,
                            output,
                            expected_digest,
                            maximum_bytes,
                            verified_identity=source_identity if verified else None,
                            progress=progress,
                        )
                        if reusable and not verified:
                            saved.remember(str(source), observed, expected_digest)
                        output.flush()
                        os.fsync(output.fileno())
                        # Keep the verified output descriptor across rename. A
                        # replaced destination cannot acquire this copy verdict.
                        output_identity = file_fingerprint(os.fstat(output.fileno()))
                        os.rename(name, destination)
                        current_output = file_fingerprint(os.fstat(output.fileno()))
                        target_identity = _stamp(destination, maximum_bytes)
                        if current_output[:-1] != output_identity[:-1] or target_identity != [
                            str(value) for value in current_output
                        ]:
                            raise ValueError("aggregate replica output changed during publication")
                        # Newly copied output is not eligible for stamp-only
                        # reuse in its creation tick. The original source verdict
                        # remains reusable; a later native check qualifies output.
                        progress.emit(
                            "running", reason="new_replica_requires_stable_identity_check"
                        )
                finally:
                    if os.path.exists(name):
                        os.unlink(name)
            if _stamp(source, maximum_bytes) != source_identity:
                raise ValueError("aggregate replica source changed during publication")
            if _stamp(destination, maximum_bytes) != target_identity:
                raise ValueError("aggregate replica destination changed during publication")
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        os.close(lock)
