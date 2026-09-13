"""Authenticate a staged replacement host tree without executing it.

Host artifacts have their own signature domain under the installed authority
set. A verified tree is only a staging capability. It is not operator consent,
a sandbox rehearsal, a stopped-state checkpoint, or permission to submit weights.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .competition_host_upgrade import HostUpgradeError, _require_root_linux
from .competition_upgrade import _fingerprint, _open_without_links
from .crypto import verify_response_signature
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    SupervisorDirectiveSignature,
    ValidatorSupervisorConfig,
)

HOST_ARTIFACT_SCHEMA = "umi-successor-host-artifact/1"
SIGNED_HOST_ARTIFACT_SCHEMA = "umi-signed-successor-host-artifact/1"
HOST_ARTIFACT_DOMAIN = b"umi-successor-host-artifact-v1\0"
MAX_HOST_MANIFEST_BYTES = 32 * 1024**2
MAX_HOST_FILES = 131072
MAX_HOST_DIRECTORIES = 131072
MAX_HOST_TREE_BYTES = 2 * 1024**3
_STAGE_PARENT = Path("/opt/umi-validator-supervisor-hosts")
_PART = re.compile(r"^[A-Za-z0-9_.+@-]{1,255}$")
_REQUIRED_FILES = {
    "src/umi/competition_host_upgrade.py",
    "src/umi/competition_host_artifacts.py",
    "src/umi/competition_supervisor.py",
    "src/umi/competition_supervisor_runtime.py",
    ".venv/bin/python",
    ".venv/bin/umi-competition-supervisor",
    "uv.lock",
    "pyproject.toml",
}
_ISSUER = object()


def _relative_parts(value: str) -> tuple[str, ...]:
    parts = tuple(value.split("/"))
    if not 1 <= len(parts) <= 32 or any(
        not _PART.fullmatch(item) or item in {".", ".."} for item in parts
    ):
        raise ValueError("host artifact path must be normalized and relative")
    return parts


class HostArtifactFile(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=0, le=256 * 1024**2)]
    mode: Literal[0o444, 0o555]

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        _relative_parts(value)
        return value


class SuccessorHostArtifactManifest(StrictProtocolModel):
    schema_: Literal[HOST_ARTIFACT_SCHEMA] = Field(alias="schema")
    channel_id: Hex32
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    target_platform: Literal["linux/amd64", "linux/arm64"]
    host_entrypoint_profile: Literal["umi-competition-supervisor-host/1"]
    total_size_bytes: Annotated[int, Field(gt=0, le=MAX_HOST_TREE_BYTES)]
    files: Annotated[list[HostArtifactFile], Field(min_length=1, max_length=MAX_HOST_FILES)]

    @model_validator(mode="after")
    def exact_tree(self) -> Self:
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("host artifact files must be uniquely path-sorted")
        if self.total_size_bytes != sum(item.size_bytes for item in self.files):
            raise ValueError("host artifact total size differs from file list")
        if not _REQUIRED_FILES.issubset(paths):
            raise ValueError("host artifact omits its fixed runtime entrypoint or source")
        executable = {item.path for item in self.files if item.mode == 0o555}
        if not {".venv/bin/python", ".venv/bin/umi-competition-supervisor"}.issubset(executable):
            raise ValueError("host artifact entrypoint and interpreter must be executable")
        path_set = set(paths)
        for value in paths:
            parts = _relative_parts(value)
            if any("/".join(parts[:index]) in path_set for index in range(1, len(parts))):
                raise ValueError("host artifact file shadows another file's directory")
        return self


class SignedSuccessorHostArtifact(StrictProtocolModel):
    schema_: Literal[SIGNED_HOST_ARTIFACT_SCHEMA] = Field(alias="schema")
    manifest: SuccessorHostArtifactManifest
    manifest_sha256: Hex32
    signatures: Annotated[list[SupervisorDirectiveSignature], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def digest_and_order(self) -> Self:
        if self.manifest_sha256 != host_artifact_manifest_sha256(self.manifest):
            raise ValueError("host artifact manifest digest mismatch")
        accounts = [account_id32(item.hotkey) for item in self.signatures]
        if accounts != sorted(set(accounts)):
            raise ValueError("host artifact signatures must be unique and AccountId32-sorted")
        return self


def host_artifact_manifest_sha256(manifest: SuccessorHostArtifactManifest) -> str:
    return hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()


def host_artifact_signature_digest(manifest: SuccessorHostArtifactManifest) -> bytes:
    return hashlib.sha256(HOST_ARTIFACT_DOMAIN + canonical_json_bytes(manifest)).digest()


def parse_signed_host_artifact(payload: bytes) -> SignedSuccessorHostArtifact:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_HOST_MANIFEST_BYTES:
        raise HostUpgradeError("host artifact manifest is missing or oversized")
    signed = SignedSuccessorHostArtifact.model_validate_json(payload)
    if canonical_json_bytes(signed) != payload:
        raise HostUpgradeError("host artifact manifest is not canonical")
    return signed


def verify_host_artifact_authority(
    signed: SignedSuccessorHostArtifact,
    *,
    config: ValidatorSupervisorConfig,
    expected_manifest_sha256: str,
) -> None:
    # Reparse to reject models constructed without validation or mutated in-process.
    signed = parse_signed_host_artifact(canonical_json_bytes(signed))
    if (
        signed.manifest_sha256 != expected_manifest_sha256
        or signed.manifest.channel_id != config.channel_id
        or signed.manifest.target_platform != config.target_platform
    ):
        raise HostUpgradeError(
            "host artifact differs from the approved channel, digest or platform"
        )
    authorities = {account_id32(item.hotkey): item for item in config.trusted_authorities}
    digest = host_artifact_signature_digest(signed.manifest)
    valid = set()
    for signature in signed.signatures:
        account = account_id32(signature.hotkey)
        authority = authorities.get(account)
        if authority is None or authority.signature_scheme != signature.signature_scheme:
            raise HostUpgradeError("host artifact signer is not in the installed authority set")
        if not verify_response_signature(
            digest,
            hotkey_ss58=authority.hotkey,
            scheme=authority.signature_scheme,
            signature=signature.signature,
        ):
            raise HostUpgradeError("host artifact signature is invalid")
        valid.add(account)
    if len(valid) < config.signature_threshold:
        raise HostUpgradeError("host artifact signature quorum is incomplete")


def _current_platform() -> str:
    _require_root_linux()
    machine = platform.machine()
    if machine in {"aarch64", "arm64"}:
        return "linux/arm64"
    if machine == "x86_64":
        return "linux/amd64"
    raise HostUpgradeError("unsupported replacement host architecture")


def _file_hash(descriptor: int, expected_size: int) -> str:
    hasher, total = hashlib.sha256(), 0
    while chunk := os.read(descriptor, min(1024 * 1024, expected_size + 1 - total)):
        total += len(chunk)
        if total > expected_size:
            raise HostUpgradeError("host artifact file exceeds its signed size")
        hasher.update(chunk)
    if total != expected_size:
        raise HostUpgradeError("host artifact file is truncated")
    return hasher.hexdigest()


def _immutable_owner(info: os.stat_result, mode: int, *, directory: bool) -> None:
    kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not kind_ok
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != mode
        or (not directory and info.st_nlink != 1)
    ):
        raise HostUpgradeError("staged host contains a mutable, linked or non-root-owned entry")


def _ancestor_paths(root: Path) -> tuple[Path, ...]:
    return tuple(reversed(root.parents))


def _ancestor_owner(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise HostUpgradeError("host ancestor is not a root-owned, non-writable directory")


def _ancestor_identity(path: Path) -> tuple[int, ...]:
    descriptor = (
        os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY)
        if path == Path("/")
        else _open_without_links(path)
    )
    try:
        info = os.fstat(descriptor)
        _ancestor_owner(info)
        # Unrelated entries may be installed under /opt. Retain the parent's
        # identity and access boundary, not its directory modification time.
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    finally:
        os.close(descriptor)


def _read_tree(root: Path, manifest: SuccessorHostArtifactManifest):
    files = {item.path: item for item in manifest.files}
    directories = {""}
    for name in files:
        parts = _relative_parts(name)
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        if len(directories) > MAX_HOST_DIRECTORIES:
            raise HostUpgradeError("host artifact directory set exceeds its bound")
    fingerprints = {}
    entries_by_path = {}
    pending = [(root, "")]
    observed_files = set()
    while pending:
        path, relative = pending.pop()
        directory = _open_without_links(path)
        try:
            before = os.fstat(directory)
            _immutable_owner(before, 0o555, directory=True)
            names = set()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if len(names) >= MAX_HOST_FILES * 2:
                        raise HostUpgradeError("staged host directory exceeds its entry bound")
                    names.add(entry.name)
                    key = relative + "/" + entry.name if relative else entry.name
                    info = entry.stat(follow_symlinks=False)
                    if key in directories:
                        _immutable_owner(info, 0o555, directory=True)
                        pending.append((path / entry.name, key))
                        continue
                    target = files.get(key)
                    if target is None:
                        raise HostUpgradeError("staged host contains an unsigned entry")
                    _immutable_owner(info, target.mode, directory=False)
                    descriptor = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=directory,
                    )
                    try:
                        identity = os.fstat(descriptor)
                        if _fingerprint(identity) != _fingerprint(info):
                            raise HostUpgradeError("staged host file changed while opening")
                        if _file_hash(descriptor, target.size_bytes) != target.sha256:
                            raise HostUpgradeError("staged host file hash mismatch")
                        if _fingerprint(os.fstat(descriptor)) != _fingerprint(identity):
                            raise HostUpgradeError("staged host file changed while hashing")
                        fingerprints[path / entry.name] = _fingerprint(identity)
                        observed_files.add(key)
                    finally:
                        os.close(descriptor)
            if _fingerprint(os.fstat(directory)) != _fingerprint(before):
                raise HostUpgradeError("staged host directory changed while reading")
            fingerprints[path] = _fingerprint(before)
            entries_by_path[path] = frozenset(names)
        finally:
            os.close(directory)
    if observed_files != set(files):
        raise HostUpgradeError("staged host is missing signed files")
    return fingerprints, entries_by_path


@dataclass(frozen=True, slots=True)
class VerifiedHostTree:
    path: Path
    manifest_sha256: str
    target_platform: str
    umi_git_revision: str
    _fingerprints: dict[Path, tuple[int, ...]] = field(repr=False)
    _entries: dict[Path, frozenset[str]] = field(repr=False)
    _ancestors: dict[Path, tuple[int, ...]] = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def recheck(self) -> None:
        if (
            type(self) is not VerifiedHostTree
            or self._issuer is not _ISSUER
            or self._binding != _tree_binding(self)
        ):
            raise HostUpgradeError("host tree capability is absent or altered")
        if tuple(self._ancestors) != _ancestor_paths(self.path):
            raise HostUpgradeError("verified host ancestor set changed")
        for path, expected in self._ancestors.items():
            if _ancestor_identity(path) != expected:
                raise HostUpgradeError("verified host ancestor changed")
        for path, expected in self._fingerprints.items():
            descriptor = _open_without_links(path)
            try:
                if _fingerprint(os.fstat(descriptor)) != expected:
                    raise HostUpgradeError("verified host tree changed")
                if path in self._entries:
                    with os.scandir(descriptor) as entries:
                        observed = set()
                        for entry in entries:
                            observed.add(entry.name)
                            if len(observed) > len(self._entries[path]):
                                raise HostUpgradeError("verified host tree gained an entry")
                    if observed != self._entries[path]:
                        raise HostUpgradeError("verified host tree entries changed")
            finally:
                os.close(descriptor)


def _tree_binding(tree: VerifiedHostTree) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "path": str(tree.path),
                "manifest": tree.manifest_sha256,
                "platform": tree.target_platform,
                "revision": tree.umi_git_revision,
                "files": {
                    str(path): [str(item) for item in value]
                    for path, value in tree._fingerprints.items()
                },
                "entries": {str(path): sorted(value) for path, value in tree._entries.items()},
                "ancestors": {
                    str(path): [str(item) for item in value]
                    for path, value in tree._ancestors.items()
                },
            }
        )
    ).hexdigest()


def verify_staged_host_tree(
    signed: SignedSuccessorHostArtifact,
    *,
    config: ValidatorSupervisorConfig,
    expected_manifest_sha256: str,
    stage_root: Path,
) -> VerifiedHostTree:
    """Hash every staged file, reject unsigned entries and return a local lease.

    Artifacts must be staged at their final versioned path, with copied regular
    interpreter files. Symlinks and relocation of an already-built venv are not
    supported. Every ancestor must remain root-owned and not group/world-writable.
    """
    signed = parse_signed_host_artifact(canonical_json_bytes(signed))
    config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
    verify_host_artifact_authority(
        signed, config=config, expected_manifest_sha256=expected_manifest_sha256
    )
    if _current_platform() != signed.manifest.target_platform:
        raise HostUpgradeError("staged host architecture differs from the actual host")
    if stage_root != _STAGE_PARENT / signed.manifest.umi_git_revision:
        raise HostUpgradeError("host stage is not at its fixed versioned installation path")
    for protected in (
        config.state_root,
        config.worker_state_root,
        config.release_root,
        config.operator_input_root,
        config.wallet.path,
    ):
        other = Path(protected)
        if stage_root == other or stage_root in other.parents or other in stage_root.parents:
            raise HostUpgradeError("host stage overlaps an installed state or wallet tree")
    ancestors = {path: _ancestor_identity(path) for path in _ancestor_paths(stage_root)}
    fingerprints, entries = _read_tree(stage_root, signed.manifest)
    tree = VerifiedHostTree(
        stage_root,
        signed.manifest_sha256,
        signed.manifest.target_platform,
        signed.manifest.umi_git_revision,
        fingerprints,
        entries,
        ancestors,
        _ISSUER,
    )
    object.__setattr__(tree, "_binding", _tree_binding(tree))
    tree.recheck()
    return tree
