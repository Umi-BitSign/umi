"""Deterministic license and notice closure for distributed Rust binaries."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from .protocol import canonical_json_bytes

RUST_LICENSE_CLOSURE_SCHEMA = "umi-rust-binary-license-closure/1"
RUST_LICENSE_RESOLUTION_PROFILE = "cargo-1.98.0-metadata-locked-offline-filter-platform/1"
RUST_SOURCE_CLOSURE_PROFILE = (
    "local-source-bundled;crates-io-by-lock-checksum;pinned-git-network-retrievable/1"
)

_CARGO_VERSION = "1.98.0"
_CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
_POLKADOT_SDK_REVISION = "cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a"
_POLKADOT_SDK_SOURCE = (
    "git+https://github.com/RaoFoundation/polkadot-sdk.git?"
    f"rev={_POLKADOT_SDK_REVISION}#{_POLKADOT_SDK_REVISION}"
)
_MAX_METADATA_BYTES = 64 * 1024 * 1024
_MAX_LICENSE_FILE_BYTES = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES = 64 * 1024 * 1024
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_LICENSE_FILE_RE = re.compile(
    r"^(?:LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|UNLICENSE)(?:[-._].*)?$",
    re.IGNORECASE,
)

# Cargo still accepts several legacy slash-separated declarations. Keeping an
# explicit table makes dependency changes require review instead of silently
# classifying a new expression.
_LICENSE_EXPRESSION_IDS: Mapping[str, tuple[str, ...]] = {
    "(MIT OR Apache-2.0) AND Unicode-3.0": (
        "Apache-2.0",
        "MIT",
        "Unicode-3.0",
    ),
    "Apache-2.0": ("Apache-2.0",),
    "Apache-2.0 / MIT": ("Apache-2.0", "MIT"),
    "Apache-2.0 OR BSL-1.0": ("Apache-2.0", "BSL-1.0"),
    "Apache-2.0 OR GPL-3.0": ("Apache-2.0", "GPL-3.0"),
    "Apache-2.0 OR MIT": ("Apache-2.0", "MIT"),
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT": (
        "Apache-2.0",
        "LLVM-exception",
        "MIT",
    ),
    "Apache-2.0/GPL-3.0": ("Apache-2.0", "GPL-3.0"),
    "Apache-2.0/MIT": ("Apache-2.0", "MIT"),
    "BSD-2-Clause": ("BSD-2-Clause",),
    "BSD-2-Clause OR Apache-2.0 OR MIT": (
        "Apache-2.0",
        "BSD-2-Clause",
        "MIT",
    ),
    "BSD-3-Clause": ("BSD-3-Clause",),
    "CC0-1.0": ("CC0-1.0",),
    "CC0-1.0 OR MIT-0 OR Apache-2.0": (
        "Apache-2.0",
        "CC0-1.0",
        "MIT-0",
    ),
    "GPL-3.0-or-later WITH Classpath-exception-2.0": (
        "Classpath-exception-2.0",
        "GPL-3.0-or-later",
    ),
    "MIT": ("MIT",),
    "MIT OR Apache-2.0": ("Apache-2.0", "MIT"),
    "MIT OR Apache-2.0 OR Zlib": ("Apache-2.0", "MIT", "Zlib"),
    "MIT/Apache-2.0": ("Apache-2.0", "MIT"),
    "Unlicense OR MIT": ("MIT", "Unlicense"),
    "Zlib": ("Zlib",),
    "Zlib OR Apache-2.0 OR MIT": ("Apache-2.0", "MIT", "Zlib"),
}


class RustLicenseClosureError(RuntimeError):
    """A stable Rust license-closure failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _safe_relative_to(path: Path, root: Path, *, reason: str) -> Path:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise RustLicenseClosureError(reason) from error
    if path.is_symlink() or any(part in {"", ".", ".."} for part in relative.parts):
        raise RustLicenseClosureError(reason)
    return relative


def _read_regular_file(path: Path, *, reason: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise RustLicenseClosureError(reason) from error
    try:
        opened = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_size <= 0
            or opened.st_size > _MAX_LICENSE_FILE_BYTES
        ):
            raise RustLicenseClosureError(reason)
        payload = b""
        while chunk := os.read(descriptor, min(1024 * 1024, opened.st_size - len(payload))):
            payload += chunk
        if len(payload) != opened.st_size:
            raise RustLicenseClosureError(reason)
        return payload
    except OSError as error:
        raise RustLicenseClosureError(reason) from error
    finally:
        os.close(descriptor)


def _cargo_metadata(manifest_path: Path, *, target_triple: str) -> dict[str, Any]:
    environment = {
        "CARGO_NET_OFFLINE": "true",
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    cargo_home = os.environ.get("CARGO_HOME")
    rustup_home = os.environ.get("RUSTUP_HOME")
    if cargo_home:
        environment["CARGO_HOME"] = cargo_home
    if rustup_home:
        environment["RUSTUP_HOME"] = rustup_home
    try:
        completed = subprocess.run(
            [
                "cargo",
                f"+{_CARGO_VERSION}",
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--filter-platform",
                target_triple,
                "--manifest-path",
                os.fspath(manifest_path),
            ],
            cwd=manifest_path.parent,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RustLicenseClosureError("rust_license_metadata_execution_failed") from error
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > _MAX_METADATA_BYTES
    ):
        raise RustLicenseClosureError("rust_license_metadata_execution_failed")
    try:
        document = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RustLicenseClosureError("rust_license_metadata_invalid") from error
    if not isinstance(document, dict):
        raise RustLicenseClosureError("rust_license_metadata_invalid")
    return document


def _lock_packages(lock_bytes: bytes) -> dict[tuple[str, str, str | None], dict[str, Any]]:
    try:
        document = tomllib.loads(lock_bytes.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RustLicenseClosureError("rust_license_cargo_lock_invalid") from error
    packages = document.get("package")
    if not isinstance(packages, list) or not packages:
        raise RustLicenseClosureError("rust_license_cargo_lock_invalid")
    result: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for item in packages:
        if not isinstance(item, dict):
            raise RustLicenseClosureError("rust_license_cargo_lock_invalid")
        name = item.get("name")
        version = item.get("version")
        source = item.get("source")
        checksum = item.get("checksum")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or (source is not None and not isinstance(source, str))
            or (
                checksum is not None
                and (not isinstance(checksum, str) or not _HEX32_RE.fullmatch(checksum))
            )
        ):
            raise RustLicenseClosureError("rust_license_cargo_lock_invalid")
        key = (name, version, source)
        if key in result:
            raise RustLicenseClosureError("rust_license_cargo_lock_ambiguous")
        result[key] = item
    return result


def _reachable_package_ids(metadata: Mapping[str, Any]) -> tuple[str, set[str]]:
    resolution = metadata.get("resolve")
    if not isinstance(resolution, dict) or not isinstance(resolution.get("root"), str):
        raise RustLicenseClosureError("rust_license_resolution_invalid")
    root = resolution["root"]
    raw_nodes = resolution.get("nodes")
    if not isinstance(raw_nodes, list):
        raise RustLicenseClosureError("rust_license_resolution_invalid")
    dependencies: dict[str, tuple[str, ...]] = {}
    for node in raw_nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise RustLicenseClosureError("rust_license_resolution_invalid")
        node_id = node["id"]
        raw_deps = node.get("deps")
        if node_id in dependencies or not isinstance(raw_deps, list):
            raise RustLicenseClosureError("rust_license_resolution_invalid")
        child_ids = []
        for dependency in raw_deps:
            if not isinstance(dependency, dict) or not isinstance(dependency.get("pkg"), str):
                raise RustLicenseClosureError("rust_license_resolution_invalid")
            child_ids.append(dependency["pkg"])
        dependencies[node_id] = tuple(child_ids)
    if root not in dependencies:
        raise RustLicenseClosureError("rust_license_resolution_invalid")
    reachable: set[str] = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        children = dependencies.get(package_id)
        if children is None:
            raise RustLicenseClosureError("rust_license_resolution_invalid")
        reachable.add(package_id)
        pending.extend(children)
    return root, reachable


def _license_file_paths(package_root: Path, license_file: object) -> tuple[Path, ...]:
    candidates: set[Path] = set()
    try:
        entries = tuple(package_root.iterdir())
    except OSError as error:
        raise RustLicenseClosureError("rust_license_package_source_unavailable") from error
    for path in entries:
        if path.is_symlink():
            raise RustLicenseClosureError("rust_license_package_source_unsafe")
        if path.is_file() and _LICENSE_FILE_RE.fullmatch(path.name):
            candidates.add(path)
    if license_file is not None:
        if not isinstance(license_file, str) or not license_file:
            raise RustLicenseClosureError("rust_license_file_path_invalid")
        explicit = Path(license_file)
        if not explicit.is_absolute():
            explicit = package_root / explicit
        explicit = Path(os.path.normpath(explicit))
        try:
            resolved_root = package_root.resolve(strict=True)
            resolved_explicit = explicit.resolve(strict=True)
        except OSError as error:
            raise RustLicenseClosureError("rust_license_file_path_invalid") from error
        _safe_relative_to(
            resolved_explicit,
            resolved_root,
            reason="rust_license_file_path_invalid",
        )
        if resolved_explicit != explicit:
            raise RustLicenseClosureError("rust_license_file_path_invalid")
        candidates.add(explicit)
    return tuple(sorted(candidates, key=lambda value: value.relative_to(package_root).as_posix()))


def _material_coverage(filename: str, license_expression: str) -> tuple[str, ...]:
    upper = filename.upper()
    covered: set[str] = set()
    if "MIT0" in upper:
        covered.add("MIT-0")
    elif "MIT" in upper:
        covered.add("MIT")
    if "APACHE" in upper:
        covered.add("Apache-2.0")
    if "CC0" in upper:
        covered.add("CC0-1.0")
    if "UNICODE" in upper:
        covered.add("Unicode-3.0")
    if "ZLIB" in upper:
        covered.add("Zlib")
    if upper == "UNLICENSE":
        covered.add("Unlicense")
    if "BOOST" in upper:
        covered.add("BSL-1.0")
    if "LLVM" in upper:
        covered.update(("Apache-2.0", "LLVM-exception"))
    if "GPL3" in upper:
        covered.add("GPL-3.0")
    expression_ids = set(_LICENSE_EXPRESSION_IDS[license_expression])
    if upper in {"LICENSE", "LICENSE.TXT", "LICENSE.MD"}:
        if len(expression_ids) == 1:
            covered.update(expression_ids)
        if license_expression == "GPL-3.0-or-later WITH Classpath-exception-2.0":
            covered.update(("Classpath-exception-2.0", "GPL-3.0", "GPL-3.0-or-later"))
    return tuple(sorted(covered))


def _source_locator(
    package: Mapping[str, Any],
    lock_package: Mapping[str, Any],
    *,
    repository_root: Path,
    package_root: Path,
) -> str:
    source = package.get("source")
    if source is None:
        relative = _safe_relative_to(
            package_root,
            repository_root,
            reason="rust_license_path_dependency_outside_repository",
        )
        return "repository:" + relative.as_posix()
    if source == _CRATES_IO_SOURCE:
        checksum = lock_package.get("checksum")
        if not isinstance(checksum, str) or not _HEX32_RE.fullmatch(checksum):
            raise RustLicenseClosureError("rust_license_registry_checksum_missing")
        return f"crates.io:sha256:{checksum}"
    if source == _POLKADOT_SDK_SOURCE:
        return f"git:https://github.com/RaoFoundation/polkadot-sdk.git@{_POLKADOT_SDK_REVISION}"
    raise RustLicenseClosureError("rust_license_dependency_source_unapproved")


def _validate_manifest_source_locator(
    *,
    source: str | None,
    checksum: str | None,
    locator: str,
) -> None:
    if source is None:
        prefix = "repository:"
        if not locator.startswith(prefix) or checksum is not None:
            raise RustLicenseClosureError("rust_license_source_locator_invalid")
        path = PurePosixPath(locator[len(prefix) :])
        if (
            not path.parts
            or path.is_absolute()
            or "." in path.parts
            or ".." in path.parts
            or "\\" in locator
        ):
            raise RustLicenseClosureError("rust_license_source_locator_invalid")
        return
    if source == _CRATES_IO_SOURCE:
        if (
            checksum is None
            or not _HEX32_RE.fullmatch(checksum)
            or locator != f"crates.io:sha256:{checksum}"
        ):
            raise RustLicenseClosureError("rust_license_source_locator_invalid")
        return
    if source == _POLKADOT_SDK_SOURCE:
        expected = f"git:https://github.com/RaoFoundation/polkadot-sdk.git@{_POLKADOT_SDK_REVISION}"
        if checksum is not None or locator != expected:
            raise RustLicenseClosureError("rust_license_source_locator_invalid")
        return
    raise RustLicenseClosureError("rust_license_dependency_source_unapproved")


def _git_checkout_root(package_root: Path) -> Path:
    for candidate in (package_root, *package_root.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RustLicenseClosureError("rust_license_git_checkout_invalid")


def _verify_polkadot_checkout(package_root: Path) -> tuple[Path, bytes]:
    checkout = _git_checkout_root(package_root)
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        revision = subprocess.run(
            ["git", "-C", os.fspath(checkout), "rev-parse", "HEAD"],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        status = subprocess.run(
            [
                "git",
                "-C",
                os.fspath(checkout),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RustLicenseClosureError("rust_license_git_checkout_invalid") from error
    if (
        revision.returncode != 0
        or revision.stdout != (_POLKADOT_SDK_REVISION + "\n").encode()
        or revision.stderr
        or status.returncode != 0
        or status.stdout
        or status.stderr
    ):
        raise RustLicenseClosureError("rust_license_git_checkout_invalid")
    license_path = checkout / "substrate" / "LICENSE-APACHE2"
    return checkout, _read_regular_file(
        license_path,
        reason="rust_license_git_license_missing",
    )


def _add_material(
    materials: dict[str, dict[str, Any]],
    payloads: dict[str, bytes],
    *,
    payload: bytes,
    package_key: str,
    filename: str,
    covers: Sequence[str],
) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    archive_path = f"LICENSES/{digest}.txt"
    source = {"filename": filename, "package": package_key}
    existing = materials.get(digest)
    if existing is None:
        materials[digest] = {
            "archive_path": archive_path,
            "covers_license_ids": sorted(set(covers)),
            "sha256": digest,
            "size_bytes": len(payload),
            "sources": [source],
        }
        payloads[archive_path] = payload
    else:
        if payloads[archive_path] != payload:
            raise RustLicenseClosureError("rust_license_material_digest_collision")
        existing["covers_license_ids"] = sorted(set(existing["covers_license_ids"]) | set(covers))
        existing["sources"].append(source)
        existing["sources"].sort(key=lambda item: (item["package"], item["filename"]))
    return digest


def _build_from_metadata(
    *,
    metadata: Mapping[str, Any],
    manifest_path: Path,
    repository_root: Path,
    target_triple: str,
    binary_name: str,
    expected_root_package: str,
) -> bytes:
    lock_path = manifest_path.parent / "Cargo.lock"
    lock_bytes = _read_regular_file(lock_path, reason="rust_license_cargo_lock_unavailable")
    lock_packages = _lock_packages(lock_bytes)
    root_id, reachable = _reachable_package_ids(metadata)
    raw_packages = metadata.get("packages")
    if not isinstance(raw_packages, list):
        raise RustLicenseClosureError("rust_license_metadata_invalid")
    package_by_id: dict[str, Mapping[str, Any]] = {}
    for package in raw_packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise RustLicenseClosureError("rust_license_metadata_invalid")
        if package["id"] in package_by_id:
            raise RustLicenseClosureError("rust_license_metadata_invalid")
        package_by_id[package["id"]] = package
    if set(package_by_id) != reachable:
        raise RustLicenseClosureError("rust_license_resolution_package_set_mismatch")
    root_package = package_by_id[root_id]
    if root_package.get("name") != expected_root_package:
        raise RustLicenseClosureError("rust_license_root_package_mismatch")

    materials: dict[str, dict[str, Any]] = {}
    payloads: dict[str, bytes] = {}
    package_records: list[dict[str, Any]] = []
    polkadot_license: bytes | None = None
    polkadot_checkout: Path | None = None
    all_ids: set[str] = set()
    for package_id in sorted(reachable):
        package = package_by_id[package_id]
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        manifest = package.get("manifest_path")
        expression = package.get("license")
        repository = package.get("repository")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or (source is not None and not isinstance(source, str))
            or not isinstance(manifest, str)
            or not Path(manifest).is_absolute()
            or (
                repository is not None
                and (not isinstance(repository, str) or len(repository) > 2_048)
            )
        ):
            raise RustLicenseClosureError("rust_license_package_metadata_invalid")
        if expression is None or not isinstance(expression, str) or not expression:
            raise RustLicenseClosureError("rust_license_expression_missing")
        license_ids = _LICENSE_EXPRESSION_IDS.get(expression)
        if license_ids is None:
            raise RustLicenseClosureError("rust_license_expression_unknown")
        all_ids.update(license_ids)
        package_root = Path(manifest).parent
        if not package_root.is_absolute() or package_root.is_symlink():
            raise RustLicenseClosureError("rust_license_package_source_unsafe")
        lock_key = (name, version, source)
        lock_package = lock_packages.get(lock_key)
        if lock_package is None:
            raise RustLicenseClosureError("rust_license_package_missing_from_lock")
        locator = _source_locator(
            package,
            lock_package,
            repository_root=repository_root,
            package_root=package_root,
        )
        package_key = f"{name}@{version}|{locator}"
        local_material: list[str] = []
        for path in _license_file_paths(package_root, package.get("license_file")):
            filename = path.relative_to(package_root).as_posix()
            payload = _read_regular_file(path, reason="rust_license_material_unavailable")
            local_material.append(
                _add_material(
                    materials,
                    payloads,
                    payload=payload,
                    package_key=package_key,
                    filename=filename,
                    covers=_material_coverage(filename, expression),
                )
            )
        if source == _POLKADOT_SDK_SOURCE:
            checkout, shared_license = _verify_polkadot_checkout(package_root)
            if polkadot_checkout is not None and checkout != polkadot_checkout:
                raise RustLicenseClosureError("rust_license_git_checkout_ambiguous")
            polkadot_checkout = checkout
            if polkadot_license is not None and shared_license != polkadot_license:
                raise RustLicenseClosureError("rust_license_git_license_mismatch")
            polkadot_license = shared_license
            local_material.append(
                _add_material(
                    materials,
                    payloads,
                    payload=shared_license,
                    package_key=package_key,
                    filename="substrate/LICENSE-APACHE2",
                    covers=("Apache-2.0",),
                )
            )
        package_records.append(
            {
                "cargo_checksum": lock_package.get("checksum"),
                "cargo_source": source,
                "license_expression": expression,
                "license_ids": list(license_ids),
                "name": name,
                "repository": repository,
                "source_license_material_sha256s": sorted(set(local_material)),
                "source_locator": locator,
                "version": version,
            }
        )

    repository_license = _read_regular_file(
        repository_root / "LICENSE",
        reason="rust_license_repository_license_missing",
    )
    _add_material(
        materials,
        payloads,
        payload=repository_license,
        package_key="repository:umi",
        filename="LICENSE",
        covers=("Apache-2.0",),
    )
    material_for_id: dict[str, str] = {}
    for license_id in sorted(all_ids):
        candidates = [
            digest for digest, item in materials.items() if license_id in item["covers_license_ids"]
        ]
        if not candidates:
            raise RustLicenseClosureError("rust_license_material_missing")
        material_for_id[license_id] = min(candidates)

    package_records.sort(key=lambda item: (item["name"], item["version"], item["source_locator"]))
    material_records = sorted(materials.values(), key=lambda item: item["sha256"])
    manifest = {
        "binary_name": binary_name,
        "cargo_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "license_id_material_sha256s": material_for_id,
        "license_materials": material_records,
        "packages": package_records,
        "resolution_profile": RUST_LICENSE_RESOLUTION_PROFILE,
        "schema": RUST_LICENSE_CLOSURE_SCHEMA,
        "source_closure_profile": RUST_SOURCE_CLOSURE_PROFILE,
        "target_triple": target_triple,
    }
    payloads["manifest.json"] = canonical_json_bytes(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in sorted(payloads.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o444) << 16
            archive.writestr(info, payload)
    bundle = output.getvalue()
    if not bundle or len(bundle) > _MAX_BUNDLE_BYTES:
        raise RustLicenseClosureError("rust_license_bundle_size_invalid")
    return bundle


def build_rust_license_closure(
    *,
    source_root: Path,
    repository_root: Path,
    target_triple: str,
    binary_name: str,
    expected_root_package: str,
) -> bytes:
    """Build a target-resolved license bundle from one locked Cargo graph."""

    manifest_path = source_root / "Cargo.toml"
    metadata = _cargo_metadata(manifest_path, target_triple=target_triple)
    return _build_from_metadata(
        metadata=metadata,
        manifest_path=manifest_path,
        repository_root=repository_root,
        target_triple=target_triple,
        binary_name=binary_name,
        expected_root_package=expected_root_package,
    )


def _read_bundle(payload: bytes) -> dict[str, bytes]:
    if not payload or len(payload) > _MAX_BUNDLE_BYTES:
        raise RustLicenseClosureError("rust_license_bundle_size_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            if archive.comment:
                raise RustLicenseClosureError("rust_license_bundle_invalid")
            result: dict[str, bytes] = {}
            for info in archive.infolist():
                path = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if (
                    info.is_dir()
                    or path.is_absolute()
                    or ".." in path.parts
                    or "." in path.parts
                    or "\\" in info.filename
                    or info.filename in result
                    or info.flag_bits & 0x1
                    or info.comment
                    or info.file_size <= 0
                    or info.file_size > _MAX_LICENSE_FILE_BYTES
                    or (mode and not stat.S_ISREG(mode))
                ):
                    raise RustLicenseClosureError("rust_license_bundle_invalid")
                result[info.filename] = archive.read(info)
    except RustLicenseClosureError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise RustLicenseClosureError("rust_license_bundle_invalid") from error
    return result


def verify_rust_license_closure(
    payload: bytes,
    *,
    cargo_lock_bytes: bytes,
    target_triple: str,
    binary_name: str,
) -> None:
    """Verify package, expression, material, and Cargo.lock bindings."""

    members = _read_bundle(payload)
    manifest_bytes = members.get("manifest.json")
    if manifest_bytes is None:
        raise RustLicenseClosureError("rust_license_manifest_missing")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RustLicenseClosureError("rust_license_manifest_invalid") from error
    if not isinstance(manifest, dict) or canonical_json_bytes(manifest) != manifest_bytes:
        raise RustLicenseClosureError("rust_license_manifest_invalid")
    expected_top = {
        "binary_name",
        "cargo_lock_sha256",
        "license_id_material_sha256s",
        "license_materials",
        "packages",
        "resolution_profile",
        "schema",
        "source_closure_profile",
        "target_triple",
    }
    if (
        set(manifest) != expected_top
        or manifest.get("schema") != RUST_LICENSE_CLOSURE_SCHEMA
        or manifest.get("resolution_profile") != RUST_LICENSE_RESOLUTION_PROFILE
        or manifest.get("source_closure_profile") != RUST_SOURCE_CLOSURE_PROFILE
        or manifest.get("target_triple") != target_triple
        or manifest.get("binary_name") != binary_name
        or manifest.get("cargo_lock_sha256") != hashlib.sha256(cargo_lock_bytes).hexdigest()
    ):
        raise RustLicenseClosureError("rust_license_manifest_binding_mismatch")
    lock_packages = _lock_packages(cargo_lock_bytes)
    packages = manifest.get("packages")
    materials = manifest.get("license_materials")
    material_by_id = manifest.get("license_id_material_sha256s")
    if (
        not isinstance(packages, list)
        or not packages
        or not isinstance(materials, list)
        or not materials
        or not isinstance(material_by_id, dict)
        or not material_by_id
    ):
        raise RustLicenseClosureError("rust_license_manifest_invalid")

    material_by_digest: dict[str, dict[str, Any]] = {}
    for item in materials:
        if not isinstance(item, dict) or set(item) != {
            "archive_path",
            "covers_license_ids",
            "sha256",
            "size_bytes",
            "sources",
        }:
            raise RustLicenseClosureError("rust_license_manifest_invalid")
        digest = item.get("sha256")
        archive_path = item.get("archive_path")
        covers = item.get("covers_license_ids")
        sources = item.get("sources")
        size = item.get("size_bytes")
        if (
            not isinstance(digest, str)
            or not _HEX32_RE.fullmatch(digest)
            or archive_path != f"LICENSES/{digest}.txt"
            or digest in material_by_digest
            or not isinstance(covers, list)
            or any(not isinstance(value, str) for value in covers)
            or not isinstance(sources, list)
            or not sources
            or any(
                not isinstance(source, dict)
                or set(source) != {"filename", "package"}
                or not isinstance(source["filename"], str)
                or not source["filename"]
                or not isinstance(source["package"], str)
                or not source["package"]
                for source in sources
            )
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            raise RustLicenseClosureError("rust_license_manifest_invalid")
        known_ids = {item for ids in _LICENSE_EXPRESSION_IDS.values() for item in ids}
        source_keys = [(value["package"], value["filename"]) for value in sources]
        if (
            covers != sorted(set(covers))
            or any(value not in known_ids for value in covers)
            or source_keys != sorted(source_keys)
            or len(source_keys) != len(set(source_keys))
        ):
            raise RustLicenseClosureError("rust_license_manifest_invalid")
        material = members.get(archive_path)
        if (
            material is None
            or len(material) != size
            or hashlib.sha256(material).hexdigest() != digest
        ):
            raise RustLicenseClosureError("rust_license_material_binding_mismatch")
        material_by_digest[digest] = item
    if set(members) != {"manifest.json", *(item["archive_path"] for item in materials)}:
        raise RustLicenseClosureError("rust_license_bundle_member_set_mismatch")

    package_sort_keys: list[tuple[str, str, str]] = []
    package_material: dict[str, set[str]] = {}
    expression_by_package: dict[str, str] = {}
    declared_ids: set[str] = set()
    for package in packages:
        if not isinstance(package, dict) or set(package) != {
            "cargo_checksum",
            "cargo_source",
            "license_expression",
            "license_ids",
            "name",
            "repository",
            "source_license_material_sha256s",
            "source_locator",
            "version",
        }:
            raise RustLicenseClosureError("rust_license_manifest_invalid")
        expression = package.get("license_expression")
        if expression is None or not isinstance(expression, str) or not expression:
            raise RustLicenseClosureError("rust_license_expression_missing")
        expected_ids = _LICENSE_EXPRESSION_IDS.get(expression)
        if expected_ids is None:
            raise RustLicenseClosureError("rust_license_expression_unknown")
        if package.get("license_ids") != list(expected_ids):
            raise RustLicenseClosureError("rust_license_expression_binding_mismatch")
        declared_ids.update(expected_ids)
        name = package.get("name")
        version = package.get("version")
        source = package.get("cargo_source")
        locator = package.get("source_locator")
        checksum = package.get("cargo_checksum")
        repository = package.get("repository")
        local_material = package.get("source_license_material_sha256s")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or (source is not None and not isinstance(source, str))
            or not isinstance(locator, str)
            or not locator
            or (
                checksum is not None
                and (not isinstance(checksum, str) or not _HEX32_RE.fullmatch(checksum))
            )
            or (repository is not None and not isinstance(repository, str))
            or not isinstance(local_material, list)
            or any(
                not isinstance(value, str) or not _HEX32_RE.fullmatch(value)
                for value in local_material
            )
        ):
            raise RustLicenseClosureError("rust_license_manifest_invalid")
        if local_material != sorted(set(local_material)) or any(
            value not in material_by_digest for value in local_material
        ):
            raise RustLicenseClosureError("rust_license_manifest_invalid")
        lock_package = lock_packages.get((name, version, source))
        if lock_package is None or lock_package.get("checksum") != checksum:
            raise RustLicenseClosureError("rust_license_package_lock_binding_mismatch")
        _validate_manifest_source_locator(
            source=source,
            checksum=checksum,
            locator=locator,
        )
        package_key = f"{name}@{version}|{locator}"
        package_material[package_key] = set(local_material)
        expression_by_package[package_key] = expression
        package_sort_keys.append((name, version, locator))
    if package_sort_keys != sorted(package_sort_keys) or len(set(package_sort_keys)) != len(
        package_sort_keys
    ):
        raise RustLicenseClosureError("rust_license_package_order_invalid")
    if set(material_by_id) != declared_ids:
        raise RustLicenseClosureError("rust_license_material_set_mismatch")
    root_records = [
        package
        for package in packages
        if package["name"] == binary_name and package["cargo_source"] is None
    ]
    if len(root_records) != 1:
        raise RustLicenseClosureError("rust_license_root_package_mismatch")

    for digest, material in material_by_digest.items():
        expected_coverage: set[str] = set()
        for source_record in material["sources"]:
            package_key = source_record["package"]
            filename = source_record["filename"]
            path = PurePosixPath(filename)
            if (
                path.is_absolute()
                or not path.parts
                or "." in path.parts
                or ".." in path.parts
                or "\\" in filename
            ):
                raise RustLicenseClosureError("rust_license_material_source_invalid")
            if package_key == "repository:umi":
                if filename != "LICENSE":
                    raise RustLicenseClosureError("rust_license_material_source_invalid")
                expected_coverage.add("Apache-2.0")
                continue
            expression = expression_by_package.get(package_key)
            if expression is None or digest not in package_material[package_key]:
                raise RustLicenseClosureError("rust_license_material_source_invalid")
            expected_coverage.update(_material_coverage(filename, expression))
        if material["covers_license_ids"] != sorted(expected_coverage):
            raise RustLicenseClosureError("rust_license_material_coverage_invalid")

    for license_id, digest in material_by_id.items():
        candidates = sorted(
            material_digest
            for material_digest, material in material_by_digest.items()
            if license_id in material["covers_license_ids"]
        )
        if (
            not isinstance(digest, str)
            or digest not in material_by_digest
            or license_id not in material_by_digest[digest]["covers_license_ids"]
            or not candidates
            or digest != candidates[0]
        ):
            raise RustLicenseClosureError("rust_license_material_set_mismatch")
