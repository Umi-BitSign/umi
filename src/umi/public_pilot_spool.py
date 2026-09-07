"""One-way spool consumer for publishing completed pilot evidence to the observer."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import logging
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from pydantic import Field

from .audit import _read_bounded_regular_file
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .public_pilot_archive import MAX_PUBLIC_PILOT_ARCHIVE_BYTES
from .public_pilot_publication import InvalidPublicPilotArchive, import_public_pilot_archive

PUBLICATION_RECEIPT_SCHEMA = "umi-public-pilot-publication-receipt/1"
_ARCHIVE_NAME = re.compile(r"^([0-9a-f]{64})\.tar\.gz$")
_COPY_CHUNK_BYTES = 1024 * 1024
LOGGER = logging.getLogger(__name__)


class PublicPilotPublicationReceipt(StrictProtocolModel):
    schema_: str = Field(alias="schema", pattern=f"^{PUBLICATION_RECEIPT_SCHEMA}$")
    archive_sha256: Hex32
    pilot_id: Hex32
    already_installed: bool


@dataclass(frozen=True, slots=True)
class SpoolResult:
    archive_sha256: str
    pilot_id: str
    receipt_path: Path


def _require_owned_private_directory(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError("pilot spool private directory path must be absolute")
    metadata = expanded.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ValueError("pilot spool private directory is unsafe")
    return expanded.resolve(strict=True)


def _require_identity(value: int, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"pilot spool {label} is invalid")
    return value


def _require_incoming_directory(
    path: Path,
    *,
    producer_uid: int,
    producer_gid: int,
) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError("pilot spool incoming directory path must be absolute")
    metadata = expanded.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {os.geteuid(), producer_uid}
        or metadata.st_gid != producer_gid
        or metadata.st_mode & 0o007
    ):
        raise ValueError("pilot spool incoming directory is unsafe")
    return expanded.resolve(strict=True)


def _require_disjoint_directories(paths: tuple[Path, ...]) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError("pilot spool role directories must not overlap")


def _require_atomic_spool_filesystem(paths: tuple[Path, ...]) -> None:
    if len({path.stat().st_dev for path in paths}) != 1:
        raise ValueError(
            "pilot spool claim, retention, and quarantine directories must share a filesystem"
        )


@contextmanager
def _exclusive_spool_lock(path: Path) -> Iterator[None]:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError("pilot spool consumer lock path must be absolute")
    parent = _require_owned_private_directory(expanded.parent)
    resolved = parent / expanded.name
    descriptor = os.open(
        resolved,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("pilot spool consumer lock is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_new(path: Path, data: bytes, *, mode: int = 0o640) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("pilot spool receipt write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _archive_digest(path: Path) -> str:
    return hashlib.sha256(
        _read_bounded_regular_file(path, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
    ).hexdigest()


def _freeze_claimed_archive(
    path: Path,
    *,
    archive_sha256: str,
    producer_uid: int,
    producer_gid: int,
) -> None:
    """Copy a producer inode onto one private consumer-owned inode and verify its name."""

    path_metadata = path.lstat()
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        raise ValueError("pilot spool archive path is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    temporary_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        metadata = os.fstat(descriptor)
        permissions = stat.S_IMODE(metadata.st_mode)
        consumer_owned = metadata.st_uid == os.geteuid() and permissions == 0o600
        producer_owned = (
            metadata.st_uid == producer_uid
            and metadata.st_gid == producer_gid
            and permissions in {0o600, 0o640}
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_PUBLIC_PILOT_ARCHIVE_BYTES
            or not (consumer_owned or producer_owned)
        ):
            raise ValueError("pilot spool archive ownership, mode, or link count is unsafe")

        if consumer_owned:
            if _archive_digest(path) != archive_sha256:
                raise ValueError("pilot spool archive filename does not match its bytes")
            return

        temporary_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.freeze-", dir=path.parent
        )
        os.fchmod(temporary_descriptor, 0o600)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_PUBLIC_PILOT_ARCHIVE_BYTES:
                raise ValueError("pilot spool archive exceeds its byte ceiling")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(temporary_descriptor, chunk[offset:])
                if written <= 0:
                    raise OSError("pilot spool archive copy made no progress")
                offset += written
        if copied != metadata.st_size:
            raise ValueError("pilot spool archive changed while it was claimed")
        if digest.hexdigest() != archive_sha256:
            raise ValueError("pilot spool archive filename does not match its bytes")
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = None
        os.replace(temporary_name, path)
        temporary_name = None
        _fsync_directory(path.parent)
    finally:
        os.close(descriptor)
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _quarantine_claimed_archive(path: Path, quarantine: Path, *, reason: str) -> Path:
    destination = quarantine / f"{path.name}.invalid"
    if destination.exists():
        suffix = 1
        while (quarantine / f"{path.name}.invalid-{suffix}").exists():
            suffix += 1
        destination = quarantine / f"{path.name}.invalid-{suffix}"
    os.rename(path, destination)
    _fsync_directory(path.parent)
    _fsync_directory(quarantine)
    LOGGER.warning(
        "quarantined invalid public-pilot archive %s (%s)",
        destination.name,
        reason,
    )
    return destination


def load_publication_receipt(path: Path) -> PublicPilotPublicationReceipt:
    raw = _read_bounded_regular_file(path, 16 * 1024)
    try:
        receipt = PublicPilotPublicationReceipt.model_validate_json(raw)
    except ValueError as error:
        raise ValueError("pilot publication receipt is invalid") from error
    if canonical_json_bytes(receipt) != raw:
        raise ValueError("pilot publication receipt is not canonical JSON")
    return receipt


def enqueue_publication_archive(source: Path, incoming_dir: Path) -> tuple[str, Path]:
    """Atomically hand one immutable archive to the observer-owned consumer."""

    expanded = incoming_dir.expanduser()
    if not expanded.is_absolute():
        raise ValueError("pilot spool incoming directory path must be absolute")
    metadata = expanded.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o007
    ):
        raise ValueError("pilot spool incoming directory is unsafe for the producer")
    incoming = expanded.resolve(strict=True)
    archive = source.expanduser().resolve(strict=True)
    raw = _read_bounded_regular_file(archive, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
    archive_sha256 = hashlib.sha256(raw).hexdigest()
    destination = incoming / f"{archive_sha256}.tar.gz"
    if destination.exists():
        destination_metadata = destination.lstat()
        if (
            not stat.S_ISREG(destination_metadata.st_mode)
            or destination_metadata.st_uid != os.geteuid()
            or destination_metadata.st_gid != metadata.st_gid
            or stat.S_IMODE(destination_metadata.st_mode) != 0o640
            or destination_metadata.st_nlink != 1
        ):
            raise ValueError("pilot spool destination has unsafe ownership, mode, or links")
        existing = _read_bounded_regular_file(destination, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
        if hashlib.sha256(existing).hexdigest() != archive_sha256:
            raise ValueError("pilot spool destination conflicts with the archive")
        return archive_sha256, destination

    temporary = incoming / f".{archive_sha256}.{os.getpid()}.tmp"
    if temporary.exists():
        raise ValueError("pilot spool contains a stale producer temporary file")
    try:
        _write_new(temporary, raw, mode=0o640)
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        _fsync_directory(incoming)
    finally:
        temporary.unlink(missing_ok=True)
    destination_metadata = destination.lstat()
    if (
        not stat.S_ISREG(destination_metadata.st_mode)
        or destination_metadata.st_uid != os.geteuid()
        or destination_metadata.st_gid != metadata.st_gid
        or stat.S_IMODE(destination_metadata.st_mode) != 0o640
        or destination_metadata.st_nlink != 1
    ):
        raise ValueError("pilot spool handoff has unsafe ownership, mode, or links")
    return archive_sha256, destination


def consume_public_pilot_spool(
    *,
    incoming_dir: Path,
    processing_dir: Path,
    processed_dir: Path,
    quarantine_dir: Path,
    receipts_dir: Path,
    work_root: Path,
    publication_root: Path,
    config_path: Path,
    lock_path: Path,
    spool_lock_path: Path,
    public_origin: str,
    expected_coordinator_hotkey: str,
    producer_uid: int,
    producer_gid: int,
) -> tuple[SpoolResult, ...]:
    """Claim, replay, install, and receipt every complete incoming archive."""

    producer = _require_identity(producer_uid, label="producer UID")
    producer_group = _require_identity(producer_gid, label="producer GID")
    # Reject a bad service configuration before claiming or quarantining any
    # producer item.
    account_id32(expected_coordinator_hotkey)
    incoming = _require_incoming_directory(
        incoming_dir,
        producer_uid=producer,
        producer_gid=producer_group,
    )
    processing = _require_owned_private_directory(processing_dir)
    processed = _require_owned_private_directory(processed_dir)
    quarantine = _require_owned_private_directory(quarantine_dir)
    receipts = _require_owned_private_directory(receipts_dir)
    workspace = _require_owned_private_directory(work_root)
    publication_directory = _require_owned_private_directory(publication_root)
    _require_disjoint_directories(
        (
            incoming,
            processing,
            processed,
            quarantine,
            receipts,
            workspace,
            publication_directory,
        )
    )
    _require_atomic_spool_filesystem((incoming, processing, processed, quarantine))
    results: list[SpoolResult] = []

    def process(claimed: Path, archive_sha256: str) -> None:
        try:
            _freeze_claimed_archive(
                claimed,
                archive_sha256=archive_sha256,
                producer_uid=producer,
                producer_gid=producer_group,
            )
        except ValueError as error:
            _quarantine_claimed_archive(claimed, quarantine, reason=type(error).__name__)
            return

        try:
            publication_result = import_public_pilot_archive(
                claimed,
                work_root=workspace,
                publication_root=publication_directory,
                config_path=config_path,
                lock_path=lock_path,
                public_origin=public_origin,
                expected_coordinator_hotkey=expected_coordinator_hotkey,
            )
        except InvalidPublicPilotArchive as error:
            _quarantine_claimed_archive(claimed, quarantine, reason=type(error).__name__)
            return

        receipt = PublicPilotPublicationReceipt(
            schema=PUBLICATION_RECEIPT_SCHEMA,
            archive_sha256=archive_sha256,
            pilot_id=publication_result.pilot_id,
            already_installed=publication_result.already_installed,
        )
        receipt_path = receipts / f"{archive_sha256}.json"
        receipt_bytes = canonical_json_bytes(receipt)
        if receipt_path.exists():
            existing_receipt = load_publication_receipt(receipt_path)
            if (
                existing_receipt.archive_sha256 != archive_sha256
                or existing_receipt.pilot_id != publication_result.pilot_id
            ):
                raise ValueError("pilot spool receipt conflicts with the installed archive")
        else:
            _write_new(receipt_path, receipt_bytes)
            _fsync_directory(receipts)

        retained = processed / claimed.name
        if retained.exists():
            if _archive_digest(retained) != archive_sha256:
                raise ValueError("pilot spool retained archive conflicts with the receipt")
            claimed.unlink()
        else:
            os.rename(claimed, retained)
        _fsync_directory(processing)
        _fsync_directory(processed)
        results.append(
            SpoolResult(
                archive_sha256=archive_sha256,
                pilot_id=publication_result.pilot_id,
                receipt_path=receipt_path,
            )
        )

    with _exclusive_spool_lock(spool_lock_path):
        # A claimed archive is the durable crash boundary. Always finish those
        # before accepting another producer handoff.
        for claimed in sorted(processing.iterdir(), key=lambda item: item.name):
            match = _ARCHIVE_NAME.fullmatch(claimed.name)
            if match is not None:
                process(claimed, match.group(1))

        for candidate in sorted(incoming.iterdir(), key=lambda item: item.name):
            match = _ARCHIVE_NAME.fullmatch(candidate.name)
            if match is None:
                continue
            claimed = processing / candidate.name
            if os.path.lexists(claimed):
                raise ValueError("pilot spool contains a conflicting claimed archive")
            try:
                os.rename(candidate, claimed)
            except FileNotFoundError:
                continue
            _fsync_directory(incoming)
            _fsync_directory(processing)
            process(claimed, match.group(1))
    return tuple(results)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Publish queued UMI pilot evidence")
    parser.add_argument("--incoming-dir", type=Path, required=True)
    parser.add_argument("--processing-dir", type=Path, required=True)
    parser.add_argument("--processed-dir", type=Path, required=True)
    parser.add_argument("--quarantine-dir", type=Path, required=True)
    parser.add_argument("--receipts-dir", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--publication-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--spool-lock", type=Path, required=True)
    parser.add_argument("--public-origin", required=True)
    parser.add_argument("--expected-coordinator-hotkey", required=True)
    parser.add_argument("--producer-uid", type=int, required=True)
    parser.add_argument("--producer-gid", type=int, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    results = consume_public_pilot_spool(
        incoming_dir=args.incoming_dir,
        processing_dir=args.processing_dir,
        processed_dir=args.processed_dir,
        quarantine_dir=args.quarantine_dir,
        receipts_dir=args.receipts_dir,
        work_root=args.work_root,
        publication_root=args.publication_root,
        config_path=args.config,
        lock_path=args.lock,
        spool_lock_path=args.spool_lock,
        public_origin=args.public_origin,
        expected_coordinator_hotkey=args.expected_coordinator_hotkey,
        producer_uid=args.producer_uid,
        producer_gid=args.producer_gid,
    )
    print(
        canonical_json_bytes(
            {
                "status": "public_pilot_spool_consumed",
                "archives": [
                    {
                        "archive_sha256": result.archive_sha256,
                        "pilot_id": result.pilot_id,
                        "receipt_path": str(result.receipt_path),
                    }
                    for result in results
                ],
            }
        ).decode()
    )


if __name__ == "__main__":
    main()
