"""Byte-verified preservation of model bundles, without loading model code.

The source directory and destination are operator-selected. Nothing is extracted
from an archive, fetched from a miner URL, imported, unpickled or executed here.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .open_competition import (
    BundleFile,
    CompetitionPolicy,
    ModelBundle,
    digest,
    validate_bundle_policy,
)
from .protocol import canonical_json_bytes


@contextmanager
def _directory(path: Path):
    if not path.is_absolute():
        raise ValueError("artifact directory must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _artifact(root_fd: int, record: BundleFile):
    parts = PurePosixPath(record.path).parts
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size != record.size_bytes
            ):
                raise ValueError("artifact must be a single-link regular file of the declared size")
            yield stream, info
    finally:
        os.close(parent)


def _check_tree(root_fd: int, bundle: ModelBundle) -> None:
    expected_files = {f.path for f in bundle.files}
    expected_dirs = {
        str(p) for f in bundle.files for p in PurePosixPath(f.path).parents if str(p) != "."
    }
    seen: set[str] = set()

    def walk(fd: int, prefix: str) -> None:
        with os.scandir(fd) as entries:
            for entry in entries:
                name = prefix + entry.name
                if entry.is_dir(follow_symlinks=False) and name in expected_dirs:
                    child = os.open(
                        entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                    )
                    try:
                        walk(child, name + "/")
                    finally:
                        os.close(child)
                elif entry.is_file(follow_symlinks=False) and name in expected_files:
                    seen.add(name)
                else:
                    raise ValueError("undeclared artifact, link, directory or special file")

    walk(root_fd, "")
    if seen != expected_files:
        raise ValueError("bundle is missing a declared artifact")


def _copy_verified(stream: BinaryIO, record: BundleFile, target: BinaryIO | None) -> None:
    before = os.fstat(stream.fileno())
    hasher = hashlib.sha256()
    total = 0
    while chunk := stream.read(min(1024 * 1024, record.size_bytes + 1 - total)):
        total += len(chunk)
        if total > record.size_bytes:
            raise ValueError("artifact grew while being verified")
        hasher.update(chunk)
        if target is not None:
            target.write(chunk)
    after = os.fstat(stream.fileno())
    if (
        total != record.size_bytes
        or hasher.hexdigest() != record.sha256
        or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise ValueError("artifact bytes do not match their immutable manifest")


def verify_bundle_directory(bundle: ModelBundle, root: Path, policy: CompetitionPolicy) -> str:
    validate_bundle_policy(bundle, policy)
    with _directory(root) as root_fd:
        _check_tree(root_fd, bundle)
        for record in bundle.files:
            with _artifact(root_fd, record) as (stream, _):
                _copy_verified(stream, record, None)
    return digest(bundle)


def preserve_bundle(
    bundle: ModelBundle,
    source: Path,
    archive: Path,
    policy: CompetitionPolicy,
) -> Path:
    """Copy and verify all model files, then atomically publish a content directory.

    A destination interrupted before rename is never a promotable archive.
    Retries verify the existing archive instead of overwriting it.
    """
    validate_bundle_policy(bundle, policy)
    if not archive.is_absolute() or archive.is_symlink():
        raise ValueError("archive must be an absolute non-symlink directory")
    archive.mkdir(mode=0o700, parents=True, exist_ok=True)
    if archive.stat().st_mode & 0o022:
        raise ValueError("archive must not be writable by other users")
    final = archive / digest(bundle)
    if final.exists() or final.is_symlink():
        verify_preserved_bundle(bundle, archive, policy)
        return final
    stage = Path(tempfile.mkdtemp(prefix=".pending-", dir=archive))
    try:
        model_root = stage / "model"
        model_root.mkdir(mode=0o700)
        with _directory(source) as root_fd:
            _check_tree(root_fd, bundle)
            for record in bundle.files:
                target = model_root / record.path
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with _artifact(root_fd, record) as (stream, _), target.open("xb") as output:
                    _copy_verified(stream, record, output)
                    output.flush()
                    os.fsync(output.fileno())
                target.chmod(0o400)
        with (stage / "manifest.json").open("xb") as manifest:
            manifest.write(canonical_json_bytes(bundle))
            manifest.flush()
            os.fsync(manifest.fileno())
        (stage / "manifest.json").chmod(0o400)
        verify_bundle_directory(bundle, model_root, policy)
        # fsync directory entries as well as file contents before publishing.
        for directory, _, _ in os.walk(stage, topdown=False):
            with _directory(Path(directory)) as directory_fd:
                os.fsync(directory_fd)
        try:
            stage.rename(final)
        except OSError:
            if not final.exists():
                raise
            verify_preserved_bundle(bundle, archive, policy)
        with _directory(archive) as archive_fd:
            os.fsync(archive_fd)
    finally:
        if stage.exists():
            # This is only the exact directory allocated above, never a caller
            # supplied path or an already published baseline.
            shutil.rmtree(stage)
    return final


def verify_preserved_bundle(
    bundle: ModelBundle,
    archive: Path,
    policy: CompetitionPolicy,
) -> str:
    with _directory(archive / digest(bundle)) as root_fd:
        manifest_fd = os.open(
            "manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd
        )
        with os.fdopen(manifest_fd, "rb") as manifest:
            info = os.fstat(manifest.fileno())
            expected = canonical_json_bytes(bundle)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size != len(expected)
                or manifest.read(len(expected) + 1) != expected
            ):
                raise ValueError("preserved manifest mismatch")
    return verify_bundle_directory(bundle, archive / digest(bundle) / "model", policy)
