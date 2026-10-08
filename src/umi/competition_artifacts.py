"""Byte-verified preservation of model bundles, without loading model code.

The source directory and destination are operator-selected. Nothing is extracted
from an archive, fetched from a miner URL, imported, unpickled or executed here.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .open_competition import (
    BundleFile,
    CompetitionPolicy,
    ModelBundle,
    digest,
    validate_bundle_policy,
)
from .private_files import lock_private_file
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
    Retries reuse the preserved verification receipt instead of overwriting it.
    """
    validate_bundle_policy(bundle, policy)
    if not archive.is_absolute() or archive.is_symlink():
        raise ValueError("archive must be an absolute non-symlink directory")
    archive.mkdir(mode=0o700, parents=True, exist_ok=True)
    if archive.stat().st_mode & 0o022:
        raise ValueError("archive must not be writable by other users")
    key = digest(bundle)
    lease = lock_private_file(archive / (".preserve-" + key + ".lock"))
    try:
        return _preserve_locked(bundle, source, archive, policy)
    finally:
        os.close(lease)


def _preserve_locked(bundle, source, archive, policy):
    key = digest(bundle)
    final = archive / key
    # This exact, per-manifest scratch directory is exclusively owned by the
    # lock above. A killed copy can be retried without accumulating orphan data.
    stage = archive / (".pending-" + key)
    if stage.exists() or stage.is_symlink():
        info = stage.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("unsafe interrupted artifact directory")
        shutil.rmtree(stage)
    if final.exists() or final.is_symlink():
        _verify_preserved_locked(bundle, archive, policy)
        return final
    stage.mkdir(mode=0o700)
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
        # Every output byte was verified while copying; do not reread weights.
        # fsync directory entries as well as file contents before publishing.
        for directory, _, _ in os.walk(stage, topdown=False):
            with _directory(Path(directory)) as directory_fd:
                os.fsync(directory_fd)
        try:
            stage.rename(final)
        except OSError:
            if not final.exists():
                raise
            _verify_preserved_locked(bundle, archive, policy)
        with _directory(archive) as archive_fd:
            os.fsync(archive_fd)
        _remember_preserved_verification(bundle, archive)
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
    validate_bundle_policy(bundle, policy)
    # Readers of already verified content do not contend with one another.
    expected = _preserved_verification_record(bundle, archive)
    if _has_preserved_verification(bundle, archive, expected):
        return digest(bundle)
    lease = lock_private_file(archive / (".preserve-" + digest(bundle) + ".lock"))
    try:
        return _verify_preserved_locked(bundle, archive, policy)
    finally:
        os.close(lease)


def _file_identity(info):
    # Nanosecond timestamps and inode numbers can exceed canonical JSON's
    # interoperable integer range; preserve their exact decimal representation.
    return [
        str(value)
        for value in (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
        )
    ]


def _preserved_verification_record(bundle, archive):
    """Inspect identity/metadata only; never reread verified weight content."""
    _preserved_manifest(bundle, archive)
    key = digest(bundle)
    with _directory(archive) as archive_fd, _directory(archive / key) as parent:
        archive_info = os.fstat(archive_fd)
        root = os.fstat(parent)
        manifest = os.stat("manifest.json", dir_fd=parent, follow_symlinks=False)
        with _directory(archive / key / "model") as model:
            _check_tree(model, bundle)
            records = []
            for record in bundle.files:
                with _artifact(model, record) as (_, info):
                    records.append([record.path, _file_identity(info)])
            return canonical_json_bytes(
                {
                    "schema": "umi-preserved-content-verification/2",
                    "model_sha256": key,
                    # Archive directory timestamps/link counts change when other
                    # models or receipts are added. Bind its stable identity only.
                    "archive_identity": [
                        str(v)
                        for v in (
                            archive_info.st_dev,
                            archive_info.st_ino,
                            archive_info.st_mode,
                            archive_info.st_uid,
                            archive_info.st_gid,
                        )
                    ],
                    "parent_identity": _file_identity(root),
                    "manifest_identity": _file_identity(manifest),
                    "model_directory_identity": _file_identity(os.fstat(model)),
                    "files": records,
                }
            )


def _remember_preserved_verification(bundle, archive, expected=None):
    """Called only after verified copy or full first-materialization verification."""
    expected = expected if expected is not None else _preserved_verification_record(bundle, archive)
    if len(expected) > 4 * 1024**2:
        raise ValueError("preserved verification exceeds its byte bound")
    with _directory(archive) as root:
        name = ".verification-" + secrets.token_hex(16) + ".tmp"
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root
        )
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(expected)
                output.flush()
                os.fchmod(output.fileno(), 0o400)
                os.fsync(output.fileno())
            os.rename(
                name, ".verified-" + digest(bundle) + ".json", src_dir_fd=root, dst_dir_fd=root
            )
            os.fsync(root)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=root)


def _verify_preserved_locked(bundle, archive, policy):
    expected = _preserved_verification_record(bundle, archive)
    if _has_preserved_verification(bundle, archive, expected):
        return digest(bundle)
    # Older archives receive one durable receipt; a failed verification is never remembered.
    verify_bundle_directory(bundle, archive / digest(bundle) / "model", policy)
    if _preserved_verification_record(bundle, archive) != expected:
        raise ValueError("preserved artifact changed during verification of its immutable manifest")
    _remember_preserved_verification(bundle, archive, expected)
    return digest(bundle)


def _different_preserved_materialization(prior, current):
    files = prior.get("files")
    if not isinstance(files, list) or len(files) != len(current["files"]):
        return False
    directory = prior.get("model_directory_identity")
    if (
        not isinstance(directory, list)
        or len(directory) != 9
        or not all(type(v) is str and v.isascii() and v.isdecimal() for v in directory)
    ):
        return False
    # Unlink/restore may recycle an inode. A changed directory generation still
    # requires full native verification; it never transfers old content trust.
    changed = directory != current["model_directory_identity"]
    for old, new in zip(files, current["files"], strict=True):
        if (
            not isinstance(old, list)
            or len(old) != 2
            or old[0] != new[0]
            or not isinstance(old[1], list)
            or len(old[1]) != 9
            or not all(type(v) is str and v.isascii() and v.isdecimal() for v in old[1])
        ):
            return False
        changed |= old[1][:2] != new[1][:2]
    return changed


def _has_preserved_verification(bundle, archive, expected):
    with _directory(archive) as root:
        root_info = os.fstat(root)
        if root_info.st_mode & 0o022:
            raise ValueError("archive must not be writable by other users")
        try:
            descriptor = os.open(
                ".verified-" + digest(bundle) + ".json",
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                dir_fd=root,
            )
        except FileNotFoundError:
            return False
        with os.fdopen(descriptor, "rb") as receipt:
            info = os.fstat(receipt.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != root_info.st_uid
                or stat.S_IMODE(info.st_mode) != 0o400
                or not 0 < info.st_size <= 4 * 1024**2
            ):
                raise ValueError("preserved verification receipt has unsafe metadata")
            raw = receipt.read(4 * 1024**2 + 1)
            if len(raw) != info.st_size:
                raise ValueError("preserved verification receipt changed while reading")
        if raw == expected:
            return True
        current = json.loads(expected)
        # Retained version-1 consumers stay valid for their exact unchanged
        # materialization. A mismatched old receipt never authorizes reuse.
        legacy = {k: v for k, v in current.items() if k != "archive_identity"}
        legacy["schema"] = "umi-preserved-content-verification/1"
        if raw == canonical_json_bytes(legacy):
            return True
        try:
            prior = json.loads(raw)
            archive_id = prior.get("archive_identity") if isinstance(prior, dict) else None
            copied = (
                isinstance(prior, dict)
                and prior.keys() == current.keys()
                and prior.get("schema") == current["schema"]
                and prior.get("model_sha256") == current["model_sha256"]
                and isinstance(archive_id, list)
                and len(archive_id) == 5
                and all(type(v) is str and v.isascii() and v.isdecimal() for v in archive_id)
                and (
                    archive_id[:2] != current["archive_identity"][:2]
                    or _different_preserved_materialization(prior, current)
                )
                and canonical_json_bytes(prior) == raw
            )
        except (ValueError, TypeError):
            copied = False
        if copied:
            # A copied archive or atomically replaced file is a new materialization.
            # The old receipt grants no trust: verify it once under its lock.
            return False
        raise ValueError("preserved artifact changed after verification of its immutable manifest")


def _preserved_manifest(bundle: ModelBundle, archive: Path) -> None:
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


def preserved_bundle_available(bundle: ModelBundle, archive: Path, policy: CompetitionPolicy):
    """Check readable, bounded inputs without hashing model weights in a health probe.

    Execution checks the retained immutable verification receipt before loading any model.
    Availability is not an integrity receipt or permission to execute.
    """
    validate_bundle_policy(bundle, policy)
    _preserved_manifest(bundle, archive)
    with _directory(archive / digest(bundle) / "model") as root_fd:
        _check_tree(root_fd, bundle)
        for record in bundle.files:
            with _artifact(root_fd, record):
                pass
