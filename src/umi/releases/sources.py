"""Bounded local file reads and deterministic source archives."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import zipfile
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath

from .layout import (
    _FINALITY_SOURCE_DOMAIN,
    _TARGET_RE,
    MAX_RELEASE_FILE_BYTES,
    ShadowReleaseError,
)


def _fixed_source_tree_sha256(
    root: Path,
    *,
    domain: bytes,
    relative_paths: Sequence[str],
) -> str:
    digest = hashlib.sha256(domain)
    for relative in relative_paths:
        payload = _read_file(root / relative, label=f"source:{relative}")
        name = relative.encode()
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _canonical_source_bundle(
    root: Path,
    *,
    archive_root: str,
    required_files: Sequence[str],
    recursive_directories: Sequence[str],
) -> bytes:
    """Build a deterministic, unpackable archive of binary-corresponding source."""

    if (
        not root.is_absolute()
        or _TARGET_RE.fullmatch(archive_root) is None
        or not root.is_dir()
        or root.is_symlink()
    ):
        raise ShadowReleaseError("source_bundle_root_invalid")
    relative_paths = set(required_files)
    for directory_name in recursive_directories:
        directory = root / directory_name
        if not directory.exists():
            continue
        if not directory.is_dir() or directory.is_symlink():
            raise ShadowReleaseError("source_bundle_tree_unsafe")
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ShadowReleaseError("source_bundle_tree_unsafe")
            if path.is_file():
                relative_paths.add(path.relative_to(root).as_posix())
            elif not path.is_dir():
                raise ShadowReleaseError("source_bundle_tree_unsafe")

    payloads: dict[str, bytes] = {}
    for relative in sorted(relative_paths):
        normalized = PurePosixPath(relative)
        if normalized.is_absolute() or ".." in normalized.parts or "." in normalized.parts:
            raise ShadowReleaseError("source_bundle_path_invalid")
        payloads[relative] = _read_file(root / relative, label=f"source_bundle:{relative}")
    if not payloads:
        raise ShadowReleaseError("source_bundle_empty")

    manifest = "".join(
        f"{hashlib.sha256(payload).hexdigest()}  {relative}\n"
        for relative, payload in payloads.items()
    ).encode()
    archive_payloads = {
        f"{archive_root}/SOURCE-MANIFEST.sha256": manifest,
        **{f"{archive_root}/{relative}": payload for relative, payload in payloads.items()},
    }
    output = io.BytesIO()
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True
    ) as archive:
        for name, payload in archive_payloads.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o444) << 16
            archive.writestr(info, payload)
    bundle = output.getvalue()
    if not bundle or len(bundle) > MAX_RELEASE_FILE_BYTES:
        raise ShadowReleaseError("source_bundle_size_invalid")
    return bundle


def _rust_source_tree_sha256(
    root: Path,
    *,
    domain: bytes,
    required_files: Sequence[str],
) -> str:
    relative_paths = set(required_files)
    source_root = root / "src"
    if not source_root.is_dir() or source_root.is_symlink():
        raise ShadowReleaseError("rust_source_root_invalid")
    for path in source_root.rglob("*.rs"):
        if path.is_symlink() or not path.is_file():
            raise ShadowReleaseError("rust_source_tree_unsafe")
        relative_paths.add(path.relative_to(root).as_posix())
    if not any(value.startswith("src/") for value in relative_paths):
        raise ShadowReleaseError("rust_source_tree_empty")
    return _fixed_source_tree_sha256(
        root,
        domain=domain,
        relative_paths=tuple(sorted(relative_paths)),
    )


def _finality_source_tree_sha256(root: Path) -> str:
    """Bind every local input that can affect the patched finality binary."""

    relative_paths = {"Cargo.toml", "build.rs", "rust-toolchain.toml"}
    for subtree_name in ("src", "vendor"):
        subtree = root / subtree_name
        if not subtree.is_dir() or subtree.is_symlink():
            raise ShadowReleaseError(f"finality_{subtree_name}_root_invalid")
        for path in subtree.rglob("*"):
            if path.is_symlink():
                raise ShadowReleaseError("finality_source_tree_unsafe")
            if path.is_file():
                relative_paths.add(path.relative_to(root).as_posix())
            elif not path.is_dir():
                raise ShadowReleaseError("finality_source_tree_unsafe")
    cargo_config = root / ".cargo"
    if cargo_config.exists():
        if not cargo_config.is_dir() or cargo_config.is_symlink():
            raise ShadowReleaseError("finality_cargo_config_unsafe")
        for path in cargo_config.rglob("*"):
            if path.is_symlink():
                raise ShadowReleaseError("finality_source_tree_unsafe")
            if path.is_file():
                relative_paths.add(path.relative_to(root).as_posix())
            elif not path.is_dir():
                raise ShadowReleaseError("finality_source_tree_unsafe")
    return _fixed_source_tree_sha256(
        root,
        domain=_FINALITY_SOURCE_DOMAIN,
        relative_paths=tuple(sorted(relative_paths)),
    )


def _read_file(path: Path, *, label: str, maximum_bytes: int = MAX_RELEASE_FILE_BYTES) -> bytes:
    return _read_owned_file(
        path,
        label=label,
        maximum_bytes=maximum_bytes,
        executable=False,
        private=False,
    )


def _read_owned_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    executable: bool,
    private: bool,
) -> bytes:
    if not path.is_absolute():
        raise ShadowReleaseError(f"{label}_path_not_absolute")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError as error:
        raise ShadowReleaseError(f"{label}_unavailable") from error
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or mode & 0o022:
            raise ShadowReleaseError(f"{label}_unsafe")
        if executable and not mode & stat.S_IXUSR:
            raise ShadowReleaseError(f"{label}_not_executable")
        if private and mode not in {0o400, 0o600}:
            raise ShadowReleaseError(f"{label}_permissions_too_broad")
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            raise ShadowReleaseError(f"{label}_size_invalid")

        payload_parts: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ShadowReleaseError(f"{label}_size_invalid")
            payload_parts.append(chunk)
        after = os.fstat(descriptor)
        stable = (
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
            getattr(before, field) != getattr(after, field) for field in stable
        ):
            raise ShadowReleaseError(f"{label}_changed")
        return b"".join(payload_parts)
    except OSError as error:
        raise ShadowReleaseError(f"{label}_unavailable") from error
    finally:
        with suppress(OSError):
            os.close(descriptor)


def _read_executable(path: Path, *, label: str) -> bytes:
    return _read_owned_file(
        path,
        label=label,
        maximum_bytes=MAX_RELEASE_FILE_BYTES,
        executable=True,
        private=False,
    )


def _read_private_file(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    return _read_owned_file(
        path,
        label=label,
        maximum_bytes=maximum_bytes,
        executable=False,
        private=True,
    )
