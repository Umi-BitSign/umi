"""Stage a signed host tree from a bounded, non-executable byte bundle.

The wire format is MAGIC followed by each manifest file's bytes, in manifest
order. Paths, lengths, modes and hashes come only from the separately signed
manifest. No archive entry, symlink, command or installer script is interpreted.
The complete tree is checked before a no-replace rename to its fixed revision.
Failed stages remain private for recovery; existing trees are never overwritten.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import secrets
import stat
from pathlib import Path

from . import competition_host_artifacts as artifacts
from .competition_host_anchor import _rename_noreplace
from .competition_host_switch import _root_directory
from .competition_host_upgrade import HostUpgradeError, _require_root_linux
from .competition_upgrade import _fingerprint, _open_without_links
from .protocol import canonical_json_bytes
from .validator_supervisor import ValidatorSupervisorConfig

HOST_BUNDLE_MAGIC = b"UMI-SUCCESSOR-HOST-BUNDLE-V1\0"
MAX_HOST_STAGE_SLOTS = 8
_CHUNK_BYTES = 1024 * 1024


def _read_exact(descriptor: int, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = os.read(descriptor, size - len(result))
        if not part:
            raise HostUpgradeError("host bundle is truncated")
        result.extend(part)
    return bytes(result)


def _validate_input_info(info: os.stat_result, expected_bytes: int) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) not in {0o400, 0o440, 0o444}
        or info.st_size != expected_bytes
    ):
        raise HostUpgradeError("host bundle is not an exact root-sealed regular file")


def _input(path: Path, expected_bytes: int) -> tuple[int, tuple[int, ...]]:
    descriptor = _open_without_links(path)
    try:
        info = os.fstat(descriptor)
        _validate_input_info(info, expected_bytes)
        return descriptor, _fingerprint(info)
    except BaseException:
        os.close(descriptor)
        raise


def _write_file(root: Path, record: artifacts.HostArtifactFile, bundle: int) -> None:
    path = root.joinpath(*record.path.split("/"))
    parent = _root_directory(path.parent)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        remaining = record.size_bytes
        hashed = hashlib.sha256()
        while remaining:
            chunk = _read_exact(bundle, min(_CHUNK_BYTES, remaining))
            hashed.update(chunk)
            pending = memoryview(chunk)
            while pending:
                written = os.write(descriptor, pending)
                if written <= 0:
                    raise HostUpgradeError("host bundle write made no progress")
                pending = pending[written:]
            remaining -= len(chunk)
        if hashed.hexdigest() != record.sha256:
            raise HostUpgradeError("host bundle file differs from its signed hash")
        os.fchmod(descriptor, record.mode)
        os.fsync(descriptor)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _directories(manifest: artifacts.SuccessorHostArtifactManifest) -> tuple[str, ...]:
    paths = {""}
    for record in manifest.files:
        parts = record.path.split("/")
        for index in range(1, len(parts)):
            paths.add("/".join(parts[:index]))
            if len(paths) > artifacts.MAX_HOST_DIRECTORIES:
                raise HostUpgradeError("host bundle directory count exceeds its bound")
    return tuple(sorted(paths, key=lambda value: (len(Path(value).parts), value)))


def _create_directories(root: Path, directories: tuple[str, ...]) -> None:
    for relative in directories:
        path = root / relative
        if relative:
            parent = _root_directory(path.parent)
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        descriptor = _root_directory(path)
        try:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _seal_directories(root: Path, directories: tuple[str, ...]) -> None:
    for relative in reversed(directories):
        path = root / relative
        descriptor = _root_directory(path)
        try:
            os.fchmod(descriptor, 0o555)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def stage_successor_host_bundle(
    bundle_path: Path,
    *,
    signed: artifacts.SignedSuccessorHostArtifact,
    config: ValidatorSupervisorConfig,
    expected_manifest_sha256: str,
) -> artifacts.VerifiedHostTree:
    """Stage or verify one exact host revision; never execute or switch it."""
    _require_root_linux()
    signed = artifacts.parse_signed_host_artifact(canonical_json_bytes(signed))
    config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
    artifacts.verify_host_artifact_authority(
        signed, config=config, expected_manifest_sha256=expected_manifest_sha256
    )
    if artifacts._current_platform() != signed.manifest.target_platform:
        raise HostUpgradeError("host bundle does not match the actual host architecture")
    directories = _directories(signed.manifest)
    root = artifacts._STAGE_PARENT
    target = root / signed.manifest.umi_git_revision
    for protected in (
        config.state_root,
        config.worker_state_root,
        config.release_root,
        config.operator_input_root,
        config.wallet.path,
    ):
        other = Path(protected)
        if root == other or root in other.parents or other in root.parents:
            raise HostUpgradeError("host stage overlaps an installed root")
    parent = _root_directory(root)
    bundle = -1
    try:
        try:
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostUpgradeError("host stage parent is busy") from None
        try:
            os.stat(target.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return artifacts.verify_staged_host_tree(
                signed,
                config=config,
                expected_manifest_sha256=expected_manifest_sha256,
                stage_root=target,
            )
        with os.scandir(parent) as entries:
            for count, _ in enumerate(entries, 1):
                if count >= MAX_HOST_STAGE_SLOTS:
                    raise HostUpgradeError("host stage slots exhausted; preserve retained stages")
        bundle, original = _input(
            bundle_path, len(HOST_BUNDLE_MAGIC) + signed.manifest.total_size_bytes
        )
        if _read_exact(bundle, len(HOST_BUNDLE_MAGIC)) != HOST_BUNDLE_MAGIC:
            raise HostUpgradeError("host bundle has the wrong format")
        stage_name = ".host-partial-" + secrets.token_hex(16)
        os.mkdir(stage_name, 0o700, dir_fd=parent)
        os.fsync(parent)
        stage = root / stage_name
        _create_directories(stage, directories)
        for record in signed.manifest.files:
            _write_file(stage, record, bundle)
        if os.read(bundle, 1) or _fingerprint(os.fstat(bundle)) != original:
            raise HostUpgradeError("host bundle changed during staging")
        named, named_identity = _input(
            bundle_path, len(HOST_BUNDLE_MAGIC) + signed.manifest.total_size_bytes
        )
        os.close(named)
        if named_identity != original:
            raise HostUpgradeError("host bundle was replaced during staging")
        _seal_directories(stage, directories)
        artifacts._read_tree(stage, signed.manifest)
        check_parent = _root_directory(root)
        try:
            before, after = os.fstat(parent), os.fstat(check_parent)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise HostUpgradeError("host stage parent was replaced")
        finally:
            os.close(check_parent)
        _rename_noreplace(parent, stage_name, target.name)
        os.fsync(parent)
        return artifacts.verify_staged_host_tree(
            signed,
            config=config,
            expected_manifest_sha256=expected_manifest_sha256,
            stage_root=target,
        )
    finally:
        if bundle >= 0:
            os.close(bundle)
        os.close(parent)
