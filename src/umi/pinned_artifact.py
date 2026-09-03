"""Race-free staging for content-pinned local executables and data files."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path


class PinnedArtifactError(RuntimeError):
    """A source artifact could not be copied into the private execution boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class PinnedArtifact:
    name: str
    source: Path
    expected_sha256: str
    maximum_bytes: int
    executable: bool = False


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short write while staging pinned artifact")
        offset += written


def _copy_verified(specification: PinnedArtifact, destination: Path) -> None:
    source_descriptor = -1
    destination_descriptor = -1
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    try:
        source_descriptor = os.open(
            os.fspath(specification.source),
            os.O_RDONLY | close_on_exec | no_follow,
        )
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise PinnedArtifactError(f"unsafe_{specification.name}") from error
        raise PinnedArtifactError(f"{specification.name}_unavailable") from error
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & 0o022
        ):
            raise PinnedArtifactError(f"unsafe_{specification.name}")
        if specification.executable and not before.st_mode & stat.S_IXUSR:
            raise PinnedArtifactError("binary_not_executable")
        if before.st_size <= 0 or before.st_size > specification.maximum_bytes:
            raise PinnedArtifactError(f"{specification.name}_size_limit")

        mode = 0o500 if specification.executable else 0o400
        try:
            destination_descriptor = os.open(
                os.fspath(destination),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | close_on_exec | no_follow,
                mode,
            )
        except OSError as error:
            raise PinnedArtifactError(f"{specification.name}_stage_failed") from error

        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(
                source_descriptor,
                min(1024 * 1024, specification.maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > specification.maximum_bytes:
                raise PinnedArtifactError(f"{specification.name}_size_limit")
            digest.update(chunk)
            _write_all(destination_descriptor, chunk)
        os.fsync(destination_descriptor)
        os.fchmod(destination_descriptor, mode)

        after = os.fstat(source_descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if total != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise PinnedArtifactError(f"{specification.name}_changed")
        if digest.hexdigest() != specification.expected_sha256:
            raise PinnedArtifactError(f"{specification.name}_hash_mismatch")

        staged = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_uid != os.getuid()
            or staged.st_nlink != 1
            or stat.S_IMODE(staged.st_mode) != mode
            or staged.st_size != total
        ):
            raise PinnedArtifactError(f"unsafe_staged_{specification.name}")
    except OSError as error:
        raise PinnedArtifactError(f"{specification.name}_unavailable") from error
    finally:
        if destination_descriptor >= 0:
            with suppress(OSError):
                os.close(destination_descriptor)
        if source_descriptor >= 0:
            with suppress(OSError):
                os.close(source_descriptor)


@contextmanager
def staged_pinned_artifacts(
    specifications: tuple[PinnedArtifact, ...],
) -> Iterator[Mapping[str, Path]]:
    """Yield private copies made from the exact file descriptors that were hashed."""

    if not specifications:
        raise ValueError("at least one pinned artifact is required")
    names = tuple(specification.name for specification in specifications)
    if len(set(names)) != len(names):
        raise ValueError("pinned artifact names must be unique")
    with tempfile.TemporaryDirectory(prefix="umi-pinned-artifacts-") as directory_text:
        directory = Path(directory_text)
        os.chmod(directory, 0o700)
        directory_status = directory.stat()
        if (
            not stat.S_ISDIR(directory_status.st_mode)
            or directory_status.st_uid != os.getuid()
            or stat.S_IMODE(directory_status.st_mode) != 0o700
        ):
            raise PinnedArtifactError("unsafe_stage_directory")
        staged: dict[str, Path] = {}
        for index, specification in enumerate(specifications):
            destination = directory / f"{index:02d}-{specification.name}"
            _copy_verified(specification, destination)
            staged[specification.name] = destination
        yield staged


__all__ = [
    "PinnedArtifact",
    "PinnedArtifactError",
    "staged_pinned_artifacts",
]
