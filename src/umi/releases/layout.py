"""Release schemas, artifact paths, limits, and stable failure codes."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Literal

RELEASE_INPUT_SCHEMA = "umi-live-shadow-release-input/1"

RELEASE_MANIFEST_SCHEMA = "umi-live-shadow-release-manifest/1"

RELEASE_UNSIGNED_MANIFEST_SCHEMA = "umi-live-shadow-release-unsigned-manifest/1"

RELEASE_INTENT_SCHEMA = "umi-live-shadow-release-intent/1"

RELEASE_AUTHORITY_SCHEMA = "umi-live-shadow-release-authority/1"

RELEASE_AUTHORITY_REQUEST_SCHEMA = "umi-live-shadow-release-authority-request/1"

FINAL_MANIFEST_AUTHORITY_SCHEMA = "umi-live-shadow-final-manifest-authority/1"

FINAL_MANIFEST_AUTHORITY_REQUEST_SCHEMA = "umi-live-shadow-final-manifest-authority-request/1"

RELEASE_RELATIVE_VALIDATOR_CONFIG_SCHEMA = "umi-validator-live-config-template/1"

RELEASE_RELATIVE_OPERATOR_CONFIG_SCHEMA = "umi-validator-live-operator-config-template/1"

SIGNED_PUBLISHER_CAPACITY_SCHEMA = "umi-signed-publisher-capacity/1"

CAPACITY_SIGNING_REQUEST_SCHEMA = "umi-publisher-capacity-signing-request/1"

RELEASE_BASELINE_PATCH_SCHEMA = "umi-live-shadow-release-baseline-patch/1"

VALIDATOR_COST_SCHEDULE_SCHEMA = "umi-validator-cost-schedule/1"

UV_TOOL_PROVENANCE_SCHEMA = "umi-uv-tool-provenance/1"

MEDIA_RUNTIME_CLOSURE_SCHEMA = "umi-media-runtime-closure/1"

MINER_FINALITY_BUILD_REPORT_SCHEMA = "umi-miner-finality-build-report/1"

RELEASE_RELATIVE_MINER_CONFIG_SCHEMA = "umi-miner-live-config-template/1"

RESOLVED_MINER_RELEASE_SCHEMA = "umi-resolved-miner-release/1"

DARWIN_MINER_TARGET = "aarch64-apple-darwin"

_DARWIN_ARM64_MACHO_MAGIC = b"\xcf\xfa\xed\xfe"

_DARWIN_ARM64_CPU_TYPE = 0x0100000C

_MACHO_EXECUTE_FILE_TYPE = 2

PINNED_UV_VERSION = "0.12.9"

PINNED_FFMPEG_VERSION = "8.0.1"

_PINNED_FFMPEG_SOURCE_SHA256 = "05ee0b03119b45c0bdb4df654b96802e909e0a752f72e4fe3794f487229e5a41"

_PYPI_REGISTRY = "https://pypi.org/simple"

_PINNED_UV_SOURCE_ARCHIVE_SHA256 = (
    "2523396a64a6a1ea358aff5b3d23acd5e371ee6b38013750d9de5648491fbd4a"
)

_PINNED_UV_LICENSE_SHA256 = "01b9a628dce02323aaa1e263192edc7368c19572471b7c035c673ec6205f724f"

_PINNED_UV_ARCHIVE_SHA256_BY_TARGET = {
    "aarch64-unknown-linux-musl": (
        "7eb9bf48516448c9db6a9e436d8e747ac9c8a9cac74717160a29918249b080a6"
    ),
    "x86_64-unknown-linux-musl": (
        "aa4b1f8770910f7c7c543c7acc980e4270e52e70750c996acef813ea1c7c2912"
    ),
}

_PINNED_UV_BINARY_SHA256_BY_TARGET = {
    "aarch64-unknown-linux-musl": (
        "8353b259b2486ab011aae51f8815f88b41648e2ee8fe68494a8379b9f59377c8"
    ),
    "x86_64-unknown-linux-musl": (
        "308d3841102bffca4acfe799e726db08846ee35f7408762a02349c42d1ba0a09"
    ),
}

_STATIC_MEDIA_TARGET_MACHINE = {
    "aarch64-unknown-linux-musl": 183,
    "x86_64-unknown-linux-musl": 62,
}

MAX_RELEASE_INPUT_BYTES = 2 * 1024 * 1024

MAX_RELEASE_FILE_BYTES = 256 * 1024 * 1024

MAX_WHEEL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024

MINIMUM_RELEASE_LEAD_BLOCKS = 360

MAXIMUM_RELEASE_LEAD_BLOCKS = (1 << 32) - 1

MAXIMUM_FINALIZED_HEAD_AGE_MS = 120_000

RELEASE_PROOF_TIMEOUT_SECONDS = 30.0

_TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")

_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")

_SIGNATURE_RE = re.compile(r"^0x[0-9a-f]{128}$")

_WALLET_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

_FINALITY_SOURCE_DOMAIN = b"umi-grandpa-finality-observer-source-v1\0"

_PROOF_SOURCE_DOMAIN = b"umi-substrate-proof-verifier-source-v1\0"

_RELEASE_INTENT_DOMAIN = b"umi-live-shadow-release-intent-v1\0"

_FINAL_MANIFEST_DOMAIN = b"umi-live-shadow-final-manifest-v1\0"

_CONFORMANCE_REPORT_PATH = "conformance-execution-report.json"

_REHEARSAL_PLACEHOLDER_LABELS = (
    "normalization",
    "frame-digest",
    "portable-timelock",
    "chain-schedule-and-calls",
    "authenticated-content-mirror",
)

_REHEARSAL_PLACEHOLDERS = frozenset(
    hashlib.sha256(("umi-rehearsal-placeholder-v1\0" + label).encode()).hexdigest()
    for label in _REHEARSAL_PLACEHOLDER_LABELS
)

_FORBIDDEN_OUTPUT_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "mnemonic",
        "password",
        "private_key",
        "secret",
        "token",
    }
)

_EXECUTABLE_ARTIFACT_LABELS = frozenset(
    {
        "ffmpeg_binary",
        "ffprobe_binary",
        "finality_verifier_binary",
        "storage_proof_verifier_binary",
        "uv_binary",
    }
)

_MINER_FINALITY_BINARY_LABEL_PREFIX = "miner_finality_verifier."

_MINER_FINALITY_REPORT_LABEL_PREFIX = "miner_finality_build_report."

_MINER_FINALITY_LICENSE_LABEL_PREFIX = "miner_finality_license_closure."

_PACKAGED_ARTIFACT_FILENAMES = {
    "python_wheel": "umi_subnet-0.1.0-py3-none-any.whl",
    "python_lockfile": "uv.lock",
    "uv_binary": "uv",
    "uv_license": "uv-LICENSE",
    "uv_provenance": "uv-provenance.json",
    "ffmpeg_binary": "ffmpeg",
    "ffprobe_binary": "ffprobe",
    "media_runtime_manifest": "media-runtime-closure.json",
    "media_runtime_license_bundle": "media-runtime-licenses.zip",
    "media_runtime_source_bundle": "media-runtime-source.zip",
    "runtime_metadata": "runtime-metadata.scale",
    "validator_capacity_set": "validator-capacity-set.json",
    "validator_cost_schedule": "validator-cost-schedule.json",
    "mirror_discovery_rule": "mirror-discovery-rule.json",
    "normalization_fixture_set": "normalization-fixtures.json",
    "frame_digest_fixture_set": "frame-digest-fixtures.json",
    "portable_envelope_fixture_set": "portable-envelope-fixtures.json",
    "chain_fixture_set": "chain-fixtures.json",
    "live_chain_fixture_set": "live-chain-fixtures.json",
    "storage_proof_fixture_set": "storage-proof-fixtures.json",
    "finality_fixture_set": "finality-fixtures.json",
    "storage_proof_verifier_binary": "umi-substrate-proof-verifier",
    "finality_verifier_binary": "umi-grandpa-finality-observer",
    "finality_chain_spec": "finney-chain-spec.json",
    "replay_finality_attestation": "capacity-baseline-finality-attestation.json",
    "replay_release_observation_chain_evidence": "capacity-baseline-chain-evidence.json",
    "storage_proof_cargo_lock": "storage-proof-Cargo.lock",
    "finality_cargo_lock": "finality-Cargo.lock",
    "storage_proof_source_bundle": "storage-proof-source.zip",
    "finality_source_bundle": "finality-source-and-vendor.zip",
    "storage_proof_license_closure": "storage-proof-third-party-licenses.zip",
    "finality_license_closure": "finality-third-party-licenses.zip",
    "storage_proof_source_tree": "storage-proof-source-tree.sha256",
    "finality_source_tree": "finality-source-tree.sha256",
    "umi_source_tree": "umi-source-tree.sha256",
    "repository_license": "LICENSE",
    "third_party_notices": "THIRD_PARTY_NOTICES.md",
    "pyproject": "pyproject.toml",
}


class ShadowReleaseError(RuntimeError):
    """A stable release-input, verification, or emission failure."""

    def __init__(self, reason_code: str) -> None:
        if not isinstance(reason_code, str) or not reason_code:
            raise ValueError("release reason code must be nonempty")
        self.reason_code = reason_code
        super().__init__(reason_code)


def _miner_finality_label(kind: Literal["binary", "report", "license"], target: str) -> str:
    prefixes = {
        "binary": _MINER_FINALITY_BINARY_LABEL_PREFIX,
        "report": _MINER_FINALITY_REPORT_LABEL_PREFIX,
        "license": _MINER_FINALITY_LICENSE_LABEL_PREFIX,
    }
    if target != DARWIN_MINER_TARGET:
        raise ShadowReleaseError("miner_finality_target_unsupported")
    return prefixes[kind] + target


def _artifact_is_executable(label: str) -> bool:
    return label in _EXECUTABLE_ARTIFACT_LABELS or label.startswith(
        _MINER_FINALITY_BINARY_LABEL_PREFIX
    )


def _artifact_filename(label: str) -> str:
    if label.startswith(_MINER_FINALITY_BINARY_LABEL_PREFIX):
        return "umi-grandpa-finality-observer"
    if label.startswith(_MINER_FINALITY_REPORT_LABEL_PREFIX):
        return "miner-finality-build-report.json"
    if label.startswith(_MINER_FINALITY_LICENSE_LABEL_PREFIX):
        return "finality-third-party-licenses.zip"
    try:
        return _PACKAGED_ARTIFACT_FILENAMES[label]
    except KeyError as error:
        raise ShadowReleaseError(f"packaged_artifact_label_unknown:{label}") from error


def _absolute_normal_path(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError(f"{label} path must be absolute and lexically normalized")
    return path


def _release_relative_path(value: str | PurePosixPath, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or "." in path.parts
        or path.as_posix() != str(value)
    ):
        raise ValueError(f"{label} path must be normalized and release-relative")
    return path


def _packaged_artifact_relative_path(label: str, digest: str) -> str:
    """Return the stable in-release path for one content-pinned input."""

    _reject_digest(digest, label)
    if label.startswith("control_disclosure."):
        filename = f"{label}.json"
    else:
        filename = _artifact_filename(label)
    return PurePosixPath("artifacts", "sha256", digest, filename).as_posix()


def _reject_digest(digest: str, label: str) -> None:
    try:
        raw = bytes.fromhex(digest)
    except ValueError as error:  # pragma: no cover - all callers derive SHA-256
        raise ShadowReleaseError(f"{label}_digest_invalid") from error
    if len(raw) != 32 or len(set(raw)) == 1 or digest in _REHEARSAL_PLACEHOLDERS:
        raise ShadowReleaseError(f"{label}_placeholder_digest")
