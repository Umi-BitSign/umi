"""Verify and extract a successor OCI archive without loading or running it.

This is a separate bundle format and signature domain from legacy bootstrap
releases. The caller supplies an empty private staging directory and is
responsible for cache quotas. Verification grants no activation authority.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_supervisor import (
    SUCCESSOR_STATE_SCHEMA_VERSION,
    SuccessorEntrypointProfile,
    SuccessorSupervisorReleaseTarget,
    _release_url_origin,
)
from .competition_upgrade import _fingerprint, _open_without_links
from .competition_worker import _open_directory_without_links, _verify_private_directory
from .crypto import verify_response_signature
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES,
    ValidatorSupervisorConfig,
)

SUCCESSOR_RELEASE_SCHEMA = "umi-successor-oci-release-manifest/1"
SUCCESSOR_BUNDLE_MAGIC = b"UMI-SUCCESSOR-OCI-BUNDLE-V1\0"
SUCCESSOR_RELEASE_SIGNATURE_DOMAIN = b"umi-successor-oci-release-v1\0"
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024
_ISSUER = object()
_STAGED_FILES = frozenset({"release-manifest.json", "release-signature.bin", "image.oci.tar"})
_BOUND_FIELDS = (
    "oci_repository",
    "oci_manifest_sha256",
    "target_platform",
    "umi_git_revision",
    "umi_source_tree_sha256",
    "entrypoint_profile",
    "state_schema_minimum",
    "state_schema_maximum",
)


class SuccessorReleaseError(ValueError):
    pass


class SuccessorOCIReleaseManifest(StrictProtocolModel):
    schema_: Literal[SUCCESSOR_RELEASE_SCHEMA] = Field(alias="schema")
    oci_repository: Annotated[str, Field(min_length=1, max_length=512)]
    oci_manifest_sha256: Hex32
    oci_archive_sha256: Hex32
    oci_archive_size_bytes: Annotated[int, Field(gt=0, le=MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES)]
    target_platform: Literal["linux/amd64", "linux/arm64"]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    umi_source_tree_sha256: Hex32
    entrypoint_profile: SuccessorEntrypointProfile
    state_schema_minimum: Annotated[int, Field(ge=1, le=2**53 - 1)]
    state_schema_maximum: Annotated[int, Field(ge=1, le=2**53 - 1)]

    @model_validator(mode="after")
    def supports_successor_state(self) -> Self:
        if (
            not self.state_schema_minimum
            <= SUCCESSOR_STATE_SCHEMA_VERSION
            <= self.state_schema_maximum
        ):
            raise ValueError("OCI release does not support successor state schema")
        return self


def successor_release_signature_digest(manifest: SuccessorOCIReleaseManifest) -> bytes:
    return hashlib.sha256(
        SUCCESSOR_RELEASE_SIGNATURE_DOMAIN + canonical_json_bytes(manifest)
    ).digest()


def _validated_target(target, config):
    target = SuccessorSupervisorReleaseTarget.model_validate_json(canonical_json_bytes(target))
    config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
    authority = next(
        (
            value
            for value in config.trusted_authorities
            if account_id32(value.hotkey) == account_id32(target.release_authority_hotkey)
        ),
        None,
    )
    if (
        authority is None
        or authority.signature_scheme != target.release_authority_signature_scheme
        or target.oci_repository not in config.allowed_oci_repositories
        or _release_url_origin(target.release_bundle_url) not in config.release_origins
        or target.target_platform != config.target_platform
    ):
        raise SuccessorReleaseError("release target exceeds installed authority or platform")
    return target, config


def _validate_stage_location(path: Path, target, config) -> None:
    root = Path(config.release_root)
    if path != root / "successor" / target.release_bundle_sha256:
        raise SuccessorReleaseError("OCI stage is not its configured content-addressed path")
    _verify_private_directory(root, "OCI release root")
    _verify_private_directory(path.parent, "OCI stage parent")


def _ancestor_paths(path: Path) -> tuple[Path, ...]:
    return tuple(reversed(path.parents))


def _ancestor_owner(info) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or info.st_mode & 0o022
    ):
        raise SuccessorReleaseError("OCI ancestor has unsafe ownership or write permissions")


def _ancestor_identity(path: Path) -> tuple[int, ...]:
    descriptor = _open_directory_without_links(path)
    try:
        info = os.fstat(descriptor)
        _ancestor_owner(info)
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    finally:
        os.close(descriptor)


def _stage_entries(descriptor: int) -> set[str]:
    names = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= len(_STAGED_FILES):
                raise SuccessorReleaseError("OCI stage exceeds its exact file set")
            names.add(entry.name)
    return names


def _verify_manifest(payload: bytes, signature: bytes, target):
    if not 0 < len(payload) <= MAX_RELEASE_MANIFEST_BYTES or len(signature) != 64:
        raise SuccessorReleaseError("release header is truncated or oversized")
    manifest = SuccessorOCIReleaseManifest.model_validate_json(payload)
    if canonical_json_bytes(manifest) != payload:
        raise SuccessorReleaseError("release manifest is not canonical")
    if hashlib.sha256(payload).hexdigest() != target.release_manifest_sha256 or any(
        getattr(manifest, name) != getattr(target, name) for name in _BOUND_FIELDS
    ):
        raise SuccessorReleaseError("release manifest does not match signed target")
    if not verify_response_signature(
        successor_release_signature_digest(manifest),
        hotkey_ss58=target.release_authority_hotkey,
        scheme=target.release_authority_signature_scheme,
        signature="0x" + signature.hex(),
    ):
        raise SuccessorReleaseError("release signature is invalid")
    return manifest


def _header(manifest: bytes, signature: bytes) -> bytes:
    return SUCCESSOR_BUNDLE_MAGIC + struct.pack(">I", len(manifest)) + manifest + signature


def _open_artifact(path: Path, *, readonly: bool) -> int:
    descriptor = _open_without_links(path)
    info = os.fstat(descriptor)
    modes = {0o400} if readonly else {0o400, 0o600}
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in modes
    ):
        os.close(descriptor)
        raise SuccessorReleaseError("release artifact is not a private unlinked regular file")
    return descriptor


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks, total = [], 0
    while total < size:
        chunk = os.read(descriptor, min(1024 * 1024, size - total))
        if not chunk:
            raise SuccessorReleaseError("release header is truncated")
        total += len(chunk)
        chunks.append(chunk)
    return b"".join(chunks)


def _verify_archive(descriptor: int, manifest, header: bytes, target) -> None:
    archive_hash, bundle_hash = hashlib.sha256(), hashlib.sha256(header)
    total = 0
    while chunk := os.read(
        descriptor, min(1024 * 1024, manifest.oci_archive_size_bytes + 1 - total)
    ):
        total += len(chunk)
        if total > manifest.oci_archive_size_bytes:
            raise SuccessorReleaseError("OCI archive exceeds signed size")
        archive_hash.update(chunk)
        bundle_hash.update(chunk)
    if (
        total != manifest.oci_archive_size_bytes
        or archive_hash.hexdigest() != manifest.oci_archive_sha256
        or total + len(header) != target.release_bundle_size_bytes
        or bundle_hash.hexdigest() != target.release_bundle_sha256
    ):
        raise SuccessorReleaseError("OCI archive or release bundle hash/size mismatch")


def _read_bundle(descriptor: int, target):
    if os.fstat(descriptor).st_size != target.release_bundle_size_bytes:
        raise SuccessorReleaseError("release bundle size differs from signed target")
    if _read_exact(descriptor, len(SUCCESSOR_BUNDLE_MAGIC)) != SUCCESSOR_BUNDLE_MAGIC:
        raise SuccessorReleaseError("release bundle magic is not the successor format")
    size = struct.unpack(">I", _read_exact(descriptor, 4))[0]
    if not 0 < size <= MAX_RELEASE_MANIFEST_BYTES:
        raise SuccessorReleaseError("release manifest size exceeds its bound")
    payload, signature = _read_exact(descriptor, size), _read_exact(descriptor, 64)
    manifest = _verify_manifest(payload, signature, target)
    header = _header(payload, signature)
    _verify_archive(descriptor, manifest, header, target)
    return payload, signature, len(header)


def _private_stage_descriptor(path: Path, *, mode: int) -> int:
    descriptor = _open_directory_without_links(path)
    info = os.fstat(descriptor)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
        os.close(descriptor)
        raise SuccessorReleaseError("OCI stage directory has unsafe ownership or mode")
    return descriptor


def _write_output(directory: int, name: str, chunks) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory,
    )
    try:
        for chunk in chunks:
            view = memoryview(chunk)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise SuccessorReleaseError("OCI stage write made no progress")
                view = view[count:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _archive_chunks(descriptor: int, expected_size: int):
    total = 0
    while chunk := os.read(descriptor, min(1024 * 1024, expected_size + 1 - total)):
        total += len(chunk)
        if total > expected_size:
            raise SuccessorReleaseError("source archive grew while staging")
        yield chunk
    if total != expected_size:
        raise SuccessorReleaseError("source archive shrank while staging")


def _staged_snapshot(path: Path, target):
    directory = _private_stage_descriptor(path, mode=0o500)
    opened = []
    try:
        directory_info = os.fstat(directory)
        if _stage_entries(directory) != _STAGED_FILES:
            raise SuccessorReleaseError("OCI stage does not contain its exact file set")
        descriptors, identities = {}, {path: _fingerprint(directory_info)}
        for name in sorted(_STAGED_FILES):
            descriptor = _open_artifact(path / name, readonly=True)
            opened.append(descriptor)
            descriptors[name] = descriptor
            identities[path / name] = _fingerprint(os.fstat(descriptor))
        manifest_fd, signature_fd = (
            descriptors["release-manifest.json"],
            descriptors["release-signature.bin"],
        )
        manifest_size = os.fstat(manifest_fd).st_size
        if (
            not 0 < manifest_size <= MAX_RELEASE_MANIFEST_BYTES
            or os.fstat(signature_fd).st_size != 64
        ):
            raise SuccessorReleaseError("staged release header size is invalid")
        payload, signature = _read_exact(manifest_fd, manifest_size), _read_exact(signature_fd, 64)
        manifest = _verify_manifest(payload, signature, target)
        archive = descriptors["image.oci.tar"]
        if os.fstat(archive).st_size != manifest.oci_archive_size_bytes:
            raise SuccessorReleaseError("staged OCI archive size mismatch")
        _verify_archive(archive, manifest, _header(payload, signature), target)
        for name, descriptor in descriptors.items():
            if _fingerprint(os.fstat(descriptor)) != identities[path / name]:
                raise SuccessorReleaseError("staged artifact changed while verifying")
        if _fingerprint(os.fstat(directory)) != identities[path]:
            raise SuccessorReleaseError("staged directory changed while verifying")
        return identities
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(directory)


@dataclass(frozen=True, slots=True)
class VerifiedSuccessorOCI:
    path: Path
    target: SuccessorSupervisorReleaseTarget
    _identities: dict[Path, tuple[int, ...]] = field(repr=False)
    _ancestors: dict[Path, tuple[int, ...]] = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    @property
    def archive_path(self) -> Path:
        return self.path / "image.oci.tar"

    def recheck(self) -> None:
        if (
            type(self) is not VerifiedSuccessorOCI
            or self._issuer is not _ISSUER
            or self._binding != _binding(self)
        ):
            raise SuccessorReleaseError("OCI staging capability is absent or altered")
        if tuple(self._ancestors) != _ancestor_paths(self.path):
            raise SuccessorReleaseError("OCI ancestor set changed")
        for path, expected in self._ancestors.items():
            if _ancestor_identity(path) != expected:
                raise SuccessorReleaseError("OCI ancestor changed")
        if _staged_snapshot(self.path, self.target) != self._identities:
            raise SuccessorReleaseError("verified OCI stage changed")


def _binding(value: VerifiedSuccessorOCI) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "path": str(value.path),
                "target": value.target.model_dump(mode="json", by_alias=True),
                "identities": {
                    str(path): [str(item) for item in identity]
                    for path, identity in value._identities.items()
                },
                "ancestors": {
                    str(path): [str(item) for item in identity]
                    for path, identity in value._ancestors.items()
                },
            }
        )
    ).hexdigest()


def verify_staged_successor_release(
    path: Path,
    *,
    target: SuccessorSupervisorReleaseTarget,
    config: ValidatorSupervisorConfig,
) -> VerifiedSuccessorOCI:
    target, config = _validated_target(target, config)
    _validate_stage_location(path, target, config)
    ancestors = {parent: _ancestor_identity(parent) for parent in _ancestor_paths(path)}
    identities = _staged_snapshot(path, target)
    result = VerifiedSuccessorOCI(path, target, identities, ancestors, _ISSUER)
    object.__setattr__(result, "_binding", _binding(result))
    result.recheck()
    return result


def extract_successor_release_bundle(
    bundle: Path,
    destination: Path,
    *,
    target: SuccessorSupervisorReleaseTarget,
    config: ValidatorSupervisorConfig,
) -> VerifiedSuccessorOCI:
    """Verify before writing, then extract into an existing empty private directory.

    No tar entries are interpreted here; the authenticated archive remains one
    opaque file for Podman. Interrupted staging is retained and must not be
    mistaken for a complete release. No existing file is replaced or removed.
    """
    target, config = _validated_target(target, config)
    _validate_stage_location(destination, target, config)
    for parent in _ancestor_paths(destination):
        _ancestor_identity(parent)
    source = _open_artifact(bundle, readonly=False)
    directory = None
    try:
        before = _fingerprint(os.fstat(source))
        payload, signature, offset = _read_bundle(source, target)
        if _fingerprint(os.fstat(source)) != before:
            raise SuccessorReleaseError("release bundle changed during verification")
        directory = _private_stage_descriptor(destination, mode=0o700)
        with os.scandir(directory) as entries:
            if next(entries, None) is not None:
                raise SuccessorReleaseError(
                    "OCI stage must be empty; refusing to replace artifacts"
                )
        _write_output(directory, "release-manifest.json", [payload])
        _write_output(directory, "release-signature.bin", [signature])
        os.lseek(source, offset, os.SEEK_SET)
        _write_output(
            directory,
            "image.oci.tar",
            _archive_chunks(source, target.release_bundle_size_bytes - offset),
        )
        if _fingerprint(os.fstat(source)) != before:
            raise SuccessorReleaseError("release bundle changed during extraction")
        os.fsync(directory)
        os.fchmod(directory, 0o500)
        os.fsync(directory)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(source)
    return verify_staged_successor_release(destination, target=target, config=config)
