"""Release builder for the inactive SN78 live-shadow profile.

Preparation and ``--check`` are offline. Staging a public release starts the
exact hash-pinned smoldot sidecar over P2P, binds read-only storage proofs to
that independently finalized header, and packages the resulting observation.
An external authority must then sign the exact full-manifest digest before the
still-fresh stage can be finalized. This module has no wallet,
signature-generation, extrinsic, or weight-submission capability.

Publisher capacity signatures require two passes because the signed statement
contains the hash of the policy being released. ``--capacity-signing-dir``
captures the proof-backed issuance block and emits a canonical baselined
descriptor plus the exact statements and digests to sign. After those signatures
are placed in that descriptor, ``build_shadow_release`` verifies them and creates
the staged artifact set.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from .artifacts import (
    CapacityCadence,
    OneGroupLoss,
    PerWindowCapacity,
    PublisherCapacityStatement,
    RunwayTotals,
    publisher_capacity_digest,
    validate_publisher_capacity_statement,
)
from .canary import canary_count
from .chain_evidence import FinalizedSnapshotRef
from .conformance import (
    ConformanceBinaryPins,
    ConformanceError,
    ConformanceExecutionReport,
    ConformanceFixturePaths,
    FinalityFixtures,
    FinalitySelfTestReport,
    execute_conformance_suite,
)
from .crypto import verify_response_signature
from .encoding import account_id32
from .grandpa_finality import (
    CARGO_LOCK_SHA256 as FINALITY_CARGO_LOCK_SHA256,
)
from .grandpa_finality import (
    FIXTURE_SET_SHA256 as FINALITY_FIXTURE_SET_SHA256,
)
from .grandpa_finality import (
    SOURCE_REVISION as FINALITY_SOURCE_REVISION,
)
from .grandpa_finality import (
    SOURCE_TREE_SHA256 as FINALITY_SOURCE_TREE_SHA256,
)
from .grandpa_finality import (
    FinalityAttestation,
    GrandpaFinalityObserver,
)
from .pinned_artifact import PinnedArtifact, PinnedArtifactError, staged_pinned_artifacts
from .policy import (
    ChainRuntimePin,
    FinalityVerifierPin,
    LiveChainObservationPin,
    MediaRuntimePin,
    PolicyClock,
    PolicyImplementationPins,
    PolicyLimits,
    PolicyThresholds,
    PublisherControlGroup,
    PublisherRegistryEntry,
    ScoringPolicy,
    StorageProofVerifierPin,
    ValidatorRegistryEntry,
    activation_equivalence_digest,
    scoring_policy_hash,
)
from .protocol import PROTOCOL_VERSION, BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .release_chain_evidence import (
    RELEASE_OBSERVATION_EVIDENCE_PROFILE,
    RUNTIME_METADATA_AUTHENTICATION,
    RUNTIME_VERSION_AUTHENTICATION,
    ReleaseChainEvidenceError,
    collect_release_observation_evidence,
    replay_release_observation_evidence,
)
from .rust_license import (
    RustLicenseClosureError,
    build_rust_license_closure,
    verify_rust_license_closure,
)
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_chain import BittensorRawJsonRpc, FinalizedProofCollector, FinalizedRuntimePin
from .validator_live import (
    LIVE_SHADOW_MODE,
    LiveValidatorConfig,
    load_live_policy,
    validate_live_startup,
)
from .validator_live_ports import MirrorDiscoveryRule
from .validator_operator import LiveValidatorOperatorConfig
from .validator_transcript_ports import (
    ValidatorCapacitySetEvidence,
    VerifiedValidatorCapacitySet,
    validator_capacity_set_root,
)

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
_LIVE_CAPTURE_AUTHORITY = object()
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


class ArtifactPaths(StrictProtocolModel):
    """Absolute immutable inputs whose bytes are pinned in the release.

    The supplied finality attestation and release-observation evidence preserve
    the capacity-signing baseline for replay. They are never release authority.
    """

    python_wheel: str
    python_lockfile: str
    uv_binary: str
    uv_license: str
    uv_provenance: str
    ffmpeg_binary: str
    ffprobe_binary: str
    media_runtime_manifest: str
    media_runtime_license_bundle: str
    media_runtime_source_bundle: str
    runtime_metadata: str
    validator_capacity_set: str
    validator_cost_schedule: str
    mirror_discovery_rule: str
    normalization_fixture_set: str
    frame_digest_fixture_set: str
    portable_envelope_fixture_set: str
    chain_fixture_set: str
    live_chain_fixture_set: str
    storage_proof_fixture_set: str
    finality_fixture_set: str
    storage_proof_verifier_binary: str
    finality_verifier_binary: str
    finality_chain_spec: str
    finality_attestation: str
    release_observation_chain_evidence: str

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        values = [Path(value) for value in self.model_dump().values()]
        if any(not path.is_absolute() or path != Path(os.path.normpath(path)) for path in values):
            raise ValueError("release artifact paths must be absolute and lexically normalized")
        if len(set(values)) != len(values):
            raise ValueError("release artifact paths must be distinct")
        return self


class UvToolProvenance(StrictProtocolModel):
    """Reviewed origin and target binding for the packaged ``uv`` executable."""

    schema_: Literal[UV_TOOL_PROVENANCE_SCHEMA] = Field(alias="schema")
    tool: Literal["uv"]
    version: Literal[PINNED_UV_VERSION]
    target_triple: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")]
    binary_sha256: Hex32
    binary_archive_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    binary_archive_sha256: Hex32
    license_sha256: Hex32
    source_archive_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    source_archive_sha256: Hex32
    license_expression: Literal["Apache-2.0 OR MIT"]

    @model_validator(mode="after")
    def validate_origin(self) -> Self:
        prefix = f"/astral-sh/uv/releases/download/{PINNED_UV_VERSION}/"
        expected_paths = {
            self.binary_archive_url: prefix + f"uv-{self.target_triple}.tar.gz",
            self.source_archive_url: prefix + "source.tar.gz",
        }
        for value, expected_path in expected_paths.items():
            parsed = urlsplit(value)
            if (
                parsed.scheme != "https"
                or parsed.hostname != "github.com"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
                or parsed.query
                or parsed.fragment
                or parsed.path != expected_path
            ):
                raise ValueError("uv archive URL is outside the pinned upstream release")
        if (
            self.binary_archive_sha256
            != _PINNED_UV_ARCHIVE_SHA256_BY_TARGET.get(self.target_triple)
            or self.binary_sha256 != _PINNED_UV_BINARY_SHA256_BY_TARGET.get(self.target_triple)
            or self.source_archive_sha256 != _PINNED_UV_SOURCE_ARCHIVE_SHA256
            or self.license_sha256 != _PINNED_UV_LICENSE_SHA256
        ):
            raise ValueError("uv provenance does not match the reviewed upstream release")
        _reject_digest(self.binary_sha256, "uv_binary")
        _reject_digest(self.binary_archive_sha256, "uv_binary_archive")
        _reject_digest(self.license_sha256, "uv_license")
        _reject_digest(self.source_archive_sha256, "uv_source_archive")
        return self


class MediaRuntimeClosure(StrictProtocolModel):
    """Target-bound, redistributable static FFmpeg/FFprobe runtime contract."""

    schema_: Literal[MEDIA_RUNTIME_CLOSURE_SCHEMA] = Field(alias="schema")
    profile: Literal["target-bound-static-elf-media-runtime/1"]
    target_triple: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")]
    ffmpeg_binary_sha256: Hex32
    ffprobe_binary_sha256: Hex32
    ffmpeg_version: Literal[PINNED_FFMPEG_VERSION]
    ffmpeg_configuration: Annotated[str, Field(min_length=1, max_length=8_192)]
    linkage: Literal["static-elf-without-pt-interp-or-pt-dynamic"]
    runtime_dependencies: Annotated[list[str], Field(max_length=0)]
    license_expression: Annotated[str, Field(min_length=1, max_length=512)]
    license_bundle_sha256: Hex32
    corresponding_source_bundle_sha256: Hex32
    redistribution_reviewed: Literal[True]

    @model_validator(mode="after")
    def validate_closure(self) -> Self:
        if self.target_triple not in _STATIC_MEDIA_TARGET_MACHINE:
            raise ValueError("media runtime target is not a supported static Linux target")
        if any(
            "\n" in value or "\r" in value
            for value in (self.ffmpeg_version, self.license_expression)
        ):
            raise ValueError("media runtime text fields must be single-line")
        if any(
            marker in self.license_expression.casefold()
            for marker in ("placeholder", "replace", "reviewed spdx", "todo", "unknown")
        ):
            raise ValueError("media runtime license expression is unresolved")
        configuration_tokens = set(self.ffmpeg_configuration.split())
        if not {"--disable-shared", "--enable-static"}.issubset(configuration_tokens):
            raise ValueError("media runtime configuration is not a static build")
        _reject_digest(self.ffmpeg_binary_sha256, "ffmpeg_binary")
        _reject_digest(self.ffprobe_binary_sha256, "ffprobe_binary")
        _reject_digest(self.license_bundle_sha256, "media_runtime_license_bundle")
        _reject_digest(self.corresponding_source_bundle_sha256, "media_runtime_source_bundle")
        return self


class FinalityReplayBinding(StrictProtocolModel):
    """Exact one-record sidecar invocation used for the release observation."""

    maximum_records: Literal[1]
    startup_timeout_seconds: Annotated[int, Field(gt=0, le=3_600)]
    bootstrap_kind: Literal["grandpa_warp_sync_checkpoint"]
    bootstrap_block_number: Annotated[int, Field(ge=0)]
    bootstrap_block_hash: Hex32


class FinalizedReleaseObservation(StrictProtocolModel):
    """One coherent finalized-block runtime and topology observation."""

    network: Literal["finney"]
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    parent_hash: BlockHash
    state_root: BlockHash
    runtime_query_block_hash: BlockHash
    topology_query_block_hash: BlockHash
    runtime_metadata_sha256: Hex32
    finality_attestation_sha256: Hex32
    timestamp_ms: Annotated[int, Field(gt=0)]
    observed_at_ms: Annotated[int, Field(gt=0)]
    genesis_block_hash: BlockHash
    runtime_spec_version: Annotated[int, Field(gt=0)]
    transaction_version: Annotated[int, Field(gt=0)]
    state_version: Literal[1]
    subtensor_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    mechanism_count: Literal[1]
    commit_reveal_enabled: Literal[True]
    commit_reveal_version: Literal[4]
    subnet_active: Literal[True]
    translation_weights_active: Literal[False]
    target_block_interval_seconds: Literal[12]

    @model_validator(mode="after")
    def validate_times_and_hashes(self) -> Self:
        if self.timestamp_ms > self.observed_at_ms:
            raise ValueError("finalized block timestamp is after its observation")
        if self.block_hash == self.parent_hash:
            raise ValueError("finalized block cannot name itself as parent")
        if (
            self.runtime_query_block_hash != self.block_hash
            or self.topology_query_block_hash != self.block_hash
        ):
            raise ValueError("runtime and topology observations must use the finalized block")
        _reject_digest(self.runtime_metadata_sha256, "runtime_metadata")
        _reject_digest(self.finality_attestation_sha256, "finality_attestation")
        return self


class StorageProofReleaseInput(StrictProtocolModel):
    polkadot_sdk_revision: Literal["cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a"]
    source_root: str

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        _absolute_normal_path(self.source_root, "storage-proof source root")
        return self


class FinalityReleaseInput(StrictProtocolModel):
    source_root: str
    chain_spec_source_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    replay: FinalityReplayBinding

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        _absolute_normal_path(self.source_root, "finality source root")
        return self


class MinerFinalityTargetReleaseInput(StrictProtocolModel):
    """One native finality artifact admitted for miner request validation only."""

    target_triple: Literal[DARWIN_MINER_TARGET]
    binary_path: str
    build_report_path: str
    license_closure_path: str
    expected_binary_sha256: Hex32
    expected_build_report_sha256: Hex32
    expected_license_closure_sha256: Hex32

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        paths = (
            _absolute_normal_path(self.binary_path, "miner finality binary"),
            _absolute_normal_path(self.build_report_path, "miner finality build report"),
            _absolute_normal_path(self.license_closure_path, "miner finality license closure"),
        )
        if len(set(paths)) != len(paths):
            raise ValueError("miner finality artifact paths must be distinct")
        for label, digest in (
            ("miner finality binary", self.expected_binary_sha256),
            ("miner finality build report", self.expected_build_report_sha256),
            ("miner finality license closure", self.expected_license_closure_sha256),
        ):
            _reject_digest(digest, label)
        return self


class MinerFinalityBuildReport(StrictProtocolModel):
    """Native build and self-test record for an additive miner-only binary."""

    schema_: Literal[MINER_FINALITY_BUILD_REPORT_SCHEMA] = Field(alias="schema")
    role: Literal["miner-finality-only"]
    target_triple: Literal[DARWIN_MINER_TARGET]
    host_operating_system: Literal["darwin"]
    host_architecture: Literal["arm64"]
    binary_format: Literal["mach-o-64-arm64-executable"]
    binary_sha256: Hex32
    binary_size_bytes: Annotated[int, Field(gt=0, le=MAX_RELEASE_FILE_BYTES)]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    finality_source_revision: Annotated[str, Field(min_length=1, max_length=2_048)]
    finality_source_tree_sha256: Hex32
    finality_cargo_lock_sha256: Hex32
    finality_fixture_set_sha256: Hex32
    license_closure_sha256: Hex32
    self_test_output_sha256: Hex32
    self_test: FinalitySelfTestReport
    validator_runtime_supported: Literal[False]
    media_runtime_included: Literal[False]


class PublisherCapacityReleaseInput(StrictProtocolModel):
    """Capacity facts plus the administrator signature populated in pass two."""

    control_group_id: Hex32
    issued_block: Annotated[int, Field(gt=0)]
    issued_block_hash: BlockHash
    valid_from_block: Annotated[int, Field(gt=0)]
    valid_through_block: Annotated[int, Field(gt=0)]
    control_disclosure_path: str
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: str | None

    @model_validator(mode="after")
    def validate_values(self) -> Self:
        _absolute_normal_path(self.control_disclosure_path, "control disclosure")
        if self.signature is not None and _SIGNATURE_RE.fullmatch(self.signature) is None:
            raise ValueError("publisher capacity signature must be canonical 64-byte hex")
        return self


class OperatorReleaseInput(StrictProtocolModel):
    """Secret-free validator settings fixed in the signed public template."""

    validator_hotkey: str
    signature_scheme: Literal["sr25519", "ed25519"]
    maximum_transport_concurrency: Annotated[int, Field(ge=1, le=1_024)] = 32
    transport_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 90.0
    stage_port_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 30.0
    maximum_anchor_advances: Annotated[int, Field(ge=1, le=16)] = 4
    poll_seconds: Annotated[float, Field(ge=0.05, le=60)] = 1.0

    @model_validator(mode="after")
    def validate_operator(self) -> Self:
        account_id32(self.validator_hotkey)
        return self


class ReleaseAuthorityInput(StrictProtocolModel):
    """Dedicated public release signer; private key use stays outside this command."""

    authority_hotkey: str
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: str | None

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        account_id32(self.authority_hotkey)
        if self.signature is not None and _SIGNATURE_RE.fullmatch(self.signature) is None:
            raise ValueError("release authority signature must be canonical 64-byte hex")
        return self


class ReleaseRelativeValidatorConfig(StrictProtocolModel):
    """Secret-free signed validator template with release-relative inputs."""

    schema_: Literal[RELEASE_RELATIVE_VALIDATOR_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[LIVE_SHADOW_MODE]
    translation_weights_active: Literal[False]
    policy_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    scoring_policy_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    target_triple: Annotated[str, Field(min_length=1, max_length=128)]
    storage_proof_verifier_binary: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_verifier_binary: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_chain_spec_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    initial_minimum_finalized_block: Annotated[int, Field(ge=0)]
    signature_scheme: Literal["sr25519", "ed25519"]
    umi_revision: Annotated[str, Field(min_length=1, max_length=256)]
    maximum_transport_concurrency: Annotated[int, Field(ge=1, le=1_024)]
    transport_timeout_seconds: Annotated[float, Field(gt=0, le=300)]
    stage_port_timeout_seconds: Annotated[float, Field(gt=0, le=300)]
    maximum_anchor_advances: Annotated[int, Field(ge=1, le=16)]
    poll_seconds: Annotated[float, Field(ge=0.05, le=60)]

    @model_validator(mode="after")
    def validate_template(self) -> Self:
        account_id32(self.validator_hotkey)
        if _TARGET_RE.fullmatch(self.target_triple) is None:
            raise ValueError("target triple is not canonical")
        relative_paths = (
            self.policy_path,
            self.storage_proof_verifier_binary,
            self.finality_verifier_binary,
            self.finality_chain_spec_path,
        )
        if len(set(relative_paths)) != len(relative_paths):
            raise ValueError("release-relative validator paths must be distinct")
        for value in relative_paths:
            _release_relative_path(value, "validator template")
        return self


class ReleaseRelativeMinerConfig(StrictProtocolModel):
    """Signed paths needed by a miner on an additional release target."""

    schema_: Literal[RELEASE_RELATIVE_MINER_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    role: Literal["miner"]
    translation_weights_active: Literal[False]
    target_triple: Literal[DARWIN_MINER_TARGET]
    policy_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    scoring_policy_sha256: Hex32
    python_wheel: Annotated[str, Field(min_length=1, max_length=4_096)]
    python_lockfile: Annotated[str, Field(min_length=1, max_length=4_096)]
    pyproject: Annotated[str, Field(min_length=1, max_length=4_096)]
    mirror_discovery_rule_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_verifier_binary: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_chain_spec_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_build_report: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_license_closure: Annotated[str, Field(min_length=1, max_length=4_096)]
    initial_minimum_finalized_block: Annotated[int, Field(ge=0)]
    minimum_validator_transport_timeout_seconds: Annotated[float, Field(gt=0, le=300)]
    minimum_validator_transport_concurrency: Annotated[int, Field(ge=1, le=1_024)]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    umi_source_tree_sha256: Hex32
    umi_revision: Annotated[str, Field(min_length=1, max_length=256)]
    validator_runtime_supported: Literal[False]

    @model_validator(mode="after")
    def validate_template(self) -> Self:
        paths = (
            self.policy_path,
            self.python_wheel,
            self.python_lockfile,
            self.pyproject,
            self.mirror_discovery_rule_path,
            self.finality_verifier_binary,
            self.finality_chain_spec_path,
            self.finality_build_report,
            self.finality_license_closure,
        )
        if len(set(paths)) != len(paths):
            raise ValueError("release-relative miner paths must be distinct")
        for value in paths:
            _release_relative_path(value, "miner template")
        if self.umi_revision != (
            "git:" + self.umi_git_revision + ";source-tree-sha256:" + self.umi_source_tree_sha256
        ):
            raise ValueError("miner template UMI revision fields disagree")
        return self


class ResolvedMinerRelease(StrictProtocolModel):
    """Absolute, authenticated runtime paths for one supported miner target."""

    schema_: Literal[RESOLVED_MINER_RELEASE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    role: Literal["miner"]
    translation_weights_active: Literal[False]
    target_triple: Literal[DARWIN_MINER_TARGET]
    scoring_policy_sha256: Hex32
    policy_path: str
    python_wheel: str
    python_lockfile: str
    pyproject: str
    mirror_discovery_rule_path: str
    finality_verifier_binary: str
    finality_chain_spec_path: str
    finality_build_report: str
    finality_license_closure: str
    initial_minimum_finalized_block: Annotated[int, Field(ge=0)]
    minimum_validator_transport_timeout_seconds: Annotated[float, Field(gt=0, le=300)]
    minimum_validator_transport_concurrency: Annotated[int, Field(ge=1, le=1_024)]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    umi_source_tree_sha256: Hex32
    umi_revision: Annotated[str, Field(min_length=1, max_length=256)]
    validator_runtime_supported: Literal[False]

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        paths = (
            self.policy_path,
            self.python_wheel,
            self.python_lockfile,
            self.pyproject,
            self.mirror_discovery_rule_path,
            self.finality_verifier_binary,
            self.finality_chain_spec_path,
            self.finality_build_report,
            self.finality_license_closure,
        )
        normalized = [_absolute_normal_path(value, "resolved miner artifact") for value in paths]
        if len(set(normalized)) != len(normalized):
            raise ValueError("resolved miner artifact paths must be distinct")
        if self.umi_revision != (
            "git:" + self.umi_git_revision + ";source-tree-sha256:" + self.umi_source_tree_sha256
        ):
            raise ValueError("resolved miner UMI revision fields disagree")
        return self


class ReleaseRelativeOperatorConfig(StrictProtocolModel):
    """Secret-free signed operator template materialized on the validator host."""

    schema_: Literal[RELEASE_RELATIVE_OPERATOR_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[LIVE_SHADOW_MODE]
    network: Literal["finney"]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_capacity_set_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    mirror_discovery_rule_path: Annotated[str, Field(min_length=1, max_length=4_096)]

    @model_validator(mode="after")
    def validate_template(self) -> Self:
        account_id32(self.validator_hotkey)
        for value in (self.validator_capacity_set_path, self.mirror_discovery_rule_path):
            _release_relative_path(value, "operator template")
        if self.validator_capacity_set_path == self.mirror_discovery_rule_path:
            raise ValueError("release-relative operator paths must be distinct")
        return self


class OperatorMaterializationBindings(StrictProtocolModel):
    """Paths and wallet names supplied on the validator's own machine."""

    schema_: Literal["umi-validator-operator-local-bindings/1"] = Field(alias="schema")
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    state_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    wallet_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_hotkey_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    mirror_request_headers_path: Annotated[str, Field(min_length=1, max_length=4_096)]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        account_id32(self.validator_hotkey)
        if _WALLET_NAME_RE.fullmatch(self.wallet_name) is None:
            raise ValueError("wallet name is not canonical")
        if _WALLET_NAME_RE.fullmatch(self.wallet_hotkey_name) is None:
            raise ValueError("wallet hotkey name is not canonical")
        paths = (
            self.state_root,
            self.wallet_path,
            self.mirror_request_headers_path,
        )
        for value in paths:
            _absolute_normal_path(value, "operator local binding")
        if len(set(paths)) != len(paths):
            raise ValueError("operator local binding paths must be distinct")
        return self


class LiveShadowReleaseInput(StrictProtocolModel):
    """Complete canonical input for one public, weight-disabled release.

    ``observation`` is the replay-only baseline used to prepare publisher
    capacity signatures. A final release additionally requires a fresh direct
    P2P observation captured by :func:`collect_live_release_observation`.
    """

    schema_: Literal[RELEASE_INPUT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[LIVE_SHADOW_MODE]
    network: Literal["finney"]
    translation_weights_active: Literal[False]
    repository_root: str
    release_install_root: str
    target_triple: str
    activation_block: Annotated[int, Field(gt=0)]
    minimum_release_lead_blocks: Annotated[
        int,
        Field(ge=MINIMUM_RELEASE_LEAD_BLOCKS, le=MAXIMUM_RELEASE_LEAD_BLOCKS),
    ]
    maximum_finalized_head_age_ms: Literal[MAXIMUM_FINALIZED_HEAD_AGE_MS]
    minimum_publisher_collateral_alpha_rao: Annotated[int, Field(gt=0)]
    soak_start_window_index: Annotated[int, Field(ge=0)]
    clock: PolicyClock
    limits: PolicyLimits
    thresholds: PolicyThresholds
    observation: FinalizedReleaseObservation
    artifacts: ArtifactPaths
    storage_proof: StorageProofReleaseInput
    finality: FinalityReleaseInput
    miner_finality_targets: Annotated[
        list[MinerFinalityTargetReleaseInput], Field(max_length=4)
    ] = Field(default_factory=list, exclude_if=lambda value: not value)
    validator_registry: Annotated[list[ValidatorRegistryEntry], Field(min_length=4)]
    control_group_registry: Annotated[list[PublisherControlGroup], Field(min_length=3)]
    publisher_registry: Annotated[list[PublisherRegistryEntry], Field(min_length=3)]
    publisher_capacities: Annotated[list[PublisherCapacityReleaseInput], Field(min_length=3)]
    release_authority: ReleaseAuthorityInput
    operators: Annotated[list[OperatorReleaseInput], Field(min_length=4)]

    @model_validator(mode="after")
    def validate_release_bindings(self) -> Self:
        repository = _absolute_normal_path(self.repository_root, "repository root")
        install = _absolute_normal_path(self.release_install_root, "release install root")
        if repository == install or repository in install.parents or install in repository.parents:
            raise ValueError("release install root and source repository must be disjoint")
        if _TARGET_RE.fullmatch(self.target_triple) is None:
            raise ValueError("target triple is not canonical")
        if self.target_triple not in _STATIC_MEDIA_TARGET_MACHINE:
            raise ValueError("validator release target must be a supported static Linux target")
        miner_targets = [item.target_triple for item in self.miner_finality_targets]
        if miner_targets != sorted(miner_targets) or len(set(miner_targets)) != len(miner_targets):
            raise ValueError("miner finality targets must be unique and sorted")
        if self.target_triple in miner_targets:
            raise ValueError("primary validator target cannot be repeated as a miner target")
        if (
            self.clock != PolicyClock.launch()
            or self.limits != PolicyLimits.launch()
            or self.thresholds != PolicyThresholds.launch()
        ):
            raise ValueError("release parameters must match the version 0.1 launch profile")
        observation = self.observation
        if observation.block_number >= self.activation_block:
            raise ValueError("release observation must precede policy activation")
        if self.minimum_release_lead_blocks < self.clock.window_stride_blocks:
            raise ValueError("minimum release lead must cover at least one full window stride")
        required_lead = max(self.clock.anchor_blocks, self.minimum_release_lead_blocks)
        if self.activation_block - observation.block_number < required_lead:
            raise ValueError("policy activation does not provide the declared release lead")
        capacity_groups = [
            bytes.fromhex(item.control_group_id) for item in self.publisher_capacities
        ]
        known_groups = [
            bytes.fromhex(item.control_group_id) for item in self.control_group_registry
        ]
        if capacity_groups != sorted(capacity_groups) or len(set(capacity_groups)) != len(
            capacity_groups
        ):
            raise ValueError("publisher capacity entries must be unique and sorted by group ID")
        if set(capacity_groups) != set(known_groups):
            raise ValueError("publisher capacity entries must cover every control group exactly")
        operator_accounts = [account_id32(item.validator_hotkey) for item in self.operators]
        registry_accounts = [
            account_id32(item.validator_hotkey) for item in self.validator_registry
        ]
        if operator_accounts != sorted(operator_accounts) or len(set(operator_accounts)) != len(
            operator_accounts
        ):
            raise ValueError("operator entries must be unique and sorted by validator account")
        if operator_accounts != sorted(registry_accounts):
            raise ValueError("operator entries must cover every validator exactly")
        return self


class SignedPublisherCapacity(StrictProtocolModel):
    schema_: Literal[SIGNED_PUBLISHER_CAPACITY_SCHEMA] = Field(alias="schema")
    statement: PublisherCapacityStatement
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


class PublishedCostObservation(StrictProtocolModel):
    """One content-pinned public list-price observation."""

    source_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$")]
    url: Annotated[str, Field(min_length=1, max_length=2_048)]
    captured_at_ms: Annotated[int, Field(gt=0)]
    content_sha256: Hex32
    price_minor_units_per_window: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_public_source(self) -> Self:
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None:
            raise ValueError("cost observation URL must be a public HTTPS URL without userinfo")
        _reject_digest(self.content_sha256, "cost_observation_content")
        return self


class ValidatorCostClass(StrictProtocolModel):
    """One hardware/region class and its conservative full-window price."""

    hardware_class: Annotated[str, Field(min_length=1, max_length=256)]
    region_class: Annotated[str, Field(min_length=1, max_length=256)]
    cpu_core_count: Annotated[int, Field(gt=0)]
    accelerator_count: Annotated[int, Field(ge=0)]
    host_memory_bytes: Annotated[int, Field(gt=0)]
    accelerator_memory_bytes: Annotated[int, Field(ge=0)]
    provisioned_storage_bytes: Annotated[int, Field(gt=0)]
    unit_definition: Annotated[str, Field(min_length=1, max_length=1_024)]
    list_prices: Annotated[list[PublishedCostObservation], Field(min_length=3)]
    selected_price_minor_units_per_window: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_conservative_price(self) -> Self:
        if (self.accelerator_count == 0) != (self.accelerator_memory_bytes == 0):
            raise ValueError("accelerator count and memory must both be zero or positive")
        source_ids = [item.source_id for item in self.list_prices]
        if source_ids != sorted(source_ids) or len(set(source_ids)) != len(source_ids):
            raise ValueError("cost sources must be unique and sorted by source ID")
        hosts = [urlsplit(item.url).hostname for item in self.list_prices]
        if len(set(hosts)) != len(hosts):
            raise ValueError("cost sources must use distinct publication hosts")
        digests = [item.content_sha256 for item in self.list_prices]
        if len(set(digests)) != len(digests):
            raise ValueError("cost sources must carry distinct captured content")
        greatest = max(item.price_minor_units_per_window for item in self.list_prices)
        if self.selected_price_minor_units_per_window != greatest:
            raise ValueError("selected class price must be the greatest published list price")
        return self


class ValidatorCostSchedule(StrictProtocolModel):
    """Minimum reproducible cost schedule needed by the live shadow release."""

    schema_: Literal[VALIDATOR_COST_SCHEDULE_SCHEMA] = Field(alias="schema")
    reporting_currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")]
    currency_minor_units_per_major: Annotated[int, Field(gt=0)]
    class_price_rule: Literal["greatest-of-three-independent-list-prices/1"]
    tao_price_observation_rule: Annotated[str, Field(min_length=1, max_length=1_024)]
    executable_alpha_quote_function: Annotated[str, Field(min_length=1, max_length=1_024)]
    classes: Annotated[list[ValidatorCostClass], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_classes(self) -> Self:
        keys = [(item.hardware_class, item.region_class) for item in self.classes]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("validator cost classes must be unique and sorted")
        return self


class CapacitySigningRequest(StrictProtocolModel):
    schema_: Literal[CAPACITY_SIGNING_REQUEST_SCHEMA] = Field(alias="schema")
    control_group_id: Hex32
    administrator: str
    statement: PublisherCapacityStatement
    digest: Hex32


class ReleaseArtifactDigest(StrictProtocolModel):
    label: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$")]
    relative_path: Annotated[str, Field(min_length=1, max_length=512)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0)]
    install_mode: Literal["0444", "0555"]

    @model_validator(mode="after")
    def validate_relative_path(self) -> Self:
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            raise ValueError("packaged artifact path must be normalized and relative")
        expected = _packaged_artifact_relative_path(self.label, self.sha256)
        if self.relative_path != expected:
            raise ValueError("packaged artifact path does not match its label and SHA-256")
        expected_mode = "0555" if _artifact_is_executable(self.label) else "0444"
        if self.install_mode != expected_mode:
            raise ValueError("packaged artifact mode does not match its label")
        return self


class GeneratedReleaseArtifact(StrictProtocolModel):
    relative_path: Annotated[str, Field(min_length=1, max_length=512)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_relative_path(self) -> Self:
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            raise ValueError("generated artifact path must be normalized and relative")
        return self


class LiveShadowReleaseIntent(StrictProtocolModel):
    """Static release content signed before the final live observation."""

    schema_: Literal[RELEASE_INTENT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[LIVE_SHADOW_MODE]
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    target_triple: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")]
    activation_block: Annotated[int, Field(gt=0)]
    minimum_release_lead_blocks: Annotated[int, Field(ge=MINIMUM_RELEASE_LEAD_BLOCKS)]
    maximum_finalized_head_age_ms: Literal[MAXIMUM_FINALIZED_HEAD_AGE_MS]
    scoring_policy_sha256: Hex32
    activation_equivalence_digest: Hex32
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    observation_authentication_profile: Literal[
        "pinned-smoldot-finality-and-state-proof-verified-after-intent-signing/1"
    ]
    signed_artifacts: Annotated[list[GeneratedReleaseArtifact], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_artifacts(self) -> Self:
        paths = [item.relative_path for item in self.signed_artifacts]
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            raise ValueError("signed intent artifacts must be unique and sorted")
        if any(path.startswith("release-observation/") for path in paths):
            raise ValueError("live observation artifacts cannot be pre-signed")
        return self


class ReleaseAuthorityRequest(StrictProtocolModel):
    schema_: Literal[RELEASE_AUTHORITY_REQUEST_SCHEMA] = Field(alias="schema")
    authority_hotkey: str
    signature_scheme: Literal["sr25519", "ed25519"]
    intent: LiveShadowReleaseIntent
    digest: Hex32


class ReleaseAuthorityAttestation(StrictProtocolModel):
    schema_: Literal[RELEASE_AUTHORITY_SCHEMA] = Field(alias="schema")
    authority_hotkey: str
    signature_scheme: Literal["sr25519", "ed25519"]
    intent: LiveShadowReleaseIntent
    digest: Hex32
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


class UnsignedLiveShadowReleaseManifest(StrictProtocolModel):
    """Complete staged manifest before its fresh observation is authorized."""

    schema_: Literal[RELEASE_UNSIGNED_MANIFEST_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[LIVE_SHADOW_MODE]
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    activation_block: Annotated[int, Field(gt=0)]
    minimum_release_lead_blocks: Annotated[
        int,
        Field(ge=MINIMUM_RELEASE_LEAD_BLOCKS, le=MAXIMUM_RELEASE_LEAD_BLOCKS),
    ]
    maximum_finalized_head_age_ms: Literal[MAXIMUM_FINALIZED_HEAD_AGE_MS]
    release_observation_block: Annotated[int, Field(gt=0)]
    release_observation_block_hash: BlockHash
    release_observation_timestamp_ms: Annotated[int, Field(gt=0)]
    release_observation_observed_at_ms: Annotated[int, Field(gt=0)]
    scoring_policy_sha256: Hex32
    activation_equivalence_digest: Hex32
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    umi_source_tree_sha256: Hex32
    python_wheel_sha256: Hex32
    python_lockfile_sha256: Hex32
    pyproject_sha256: Hex32
    conformance_execution_report_sha256: Hex32
    observation_verification_profile: Literal[
        "direct-hash-pinned-smoldot-p2p-plus-layout-v1-release-observation-state/1"
    ]
    supplied_observation_role: Literal["capacity-signing-baseline-replay-only/1"]
    finality_evidence_class: Literal["verifier-attested-not-portable-offline-proof/1"]
    release_observation_state_evidence_profile: Literal[RELEASE_OBSERVATION_EVIDENCE_PROFILE]
    runtime_metadata_authentication: Literal[RUNTIME_METADATA_AUTHENTICATION]
    runtime_version_authentication: Literal[RUNTIME_VERSION_AUTHENTICATION]
    subtensor_revision_authentication: Literal[
        "operator-declared-source-map-not-chain-authenticated/1"
    ]
    target_block_interval_authentication: Literal[
        "policy-pinned-calibration-assumption-not-state-proven/1"
    ]
    operator_configuration_profile: Literal["release-relative-public-template/1"]
    artifact_packaging_profile: Literal["target-bound-static-runtime-closure/1"]
    release_authenticity_profile: Literal[
        "same-expected-hotkey-signed-static-intent-and-final-manifest/1"
    ]
    release_authority: ReleaseAuthorityAttestation
    public_artifacts_include_operator_configuration: Literal[True]
    external_artifacts: Annotated[list[ReleaseArtifactDigest], Field(min_length=1)]
    generated_artifacts: Annotated[list[GeneratedReleaseArtifact], Field(min_length=1)]
    publisher_capacity_statement_sha256s: Annotated[dict[str, Hex32], Field(min_length=3)]
    validator_hotkeys: Annotated[list[str], Field(min_length=4)]
    contains_private_material: Literal[False]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        labels = [item.label for item in self.external_artifacts]
        if labels != sorted(labels) or len(set(labels)) != len(labels):
            raise ValueError("external artifacts must be unique and sorted by label")
        packaged = [item.relative_path for item in self.external_artifacts]
        if len(set(packaged)) != len(packaged):
            raise ValueError("packaged artifact paths must be unique")
        generated = [item.relative_path for item in self.generated_artifacts]
        if generated != sorted(generated) or len(set(generated)) != len(generated):
            raise ValueError("generated artifacts must be unique and sorted by path")
        accounts = [account_id32(item) for item in self.validator_hotkeys]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("release validator hotkeys must be unique and sorted")
        if list(self.publisher_capacity_statement_sha256s) != sorted(
            self.publisher_capacity_statement_sha256s
        ):
            raise ValueError("publisher capacity digest map must be sorted")
        return self


class FinalManifestAuthorityRequest(StrictProtocolModel):
    """Exact full-manifest digest handed to the external release authority."""

    schema_: Literal[FINAL_MANIFEST_AUTHORITY_REQUEST_SCHEMA] = Field(alias="schema")
    authority_hotkey: str
    signature_scheme: Literal["sr25519", "ed25519"]
    unsigned_manifest: UnsignedLiveShadowReleaseManifest
    unsigned_manifest_sha256: Hex32
    digest: Hex32

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        account_id32(self.authority_hotkey)
        return self


class FinalManifestAuthorityAttestation(StrictProtocolModel):
    """Authority response embedded in the finalized public manifest."""

    schema_: Literal[FINAL_MANIFEST_AUTHORITY_SCHEMA] = Field(alias="schema")
    authority_hotkey: str
    signature_scheme: Literal["sr25519", "ed25519"]
    unsigned_manifest_sha256: Hex32
    digest: Hex32
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        account_id32(self.authority_hotkey)
        return self


class LiveShadowReleaseManifest(UnsignedLiveShadowReleaseManifest):
    """Final public manifest authenticated after its live observation."""

    schema_: Literal[RELEASE_MANIFEST_SCHEMA] = Field(alias="schema")
    final_manifest_authority: FinalManifestAuthorityAttestation


@dataclass(frozen=True, slots=True)
class PreparedShadowRelease:
    descriptor: LiveShadowReleaseInput
    descriptor_bytes: bytes
    umi_git_revision: str
    policy: ScoringPolicy
    external_artifacts: tuple[ReleaseArtifactDigest, ...]
    external_artifact_payloads: Mapping[str, bytes]
    conformance_report_bytes: bytes
    signing_requests: tuple[CapacitySigningRequest, ...]


@dataclass(frozen=True, slots=True)
class LiveReleaseObservationCapture:
    """Exact bytes captured from a direct pinned-smoldot and proof-collector run."""

    observation: FinalizedReleaseObservation
    finality_attestation: bytes
    chain_evidence: bytes
    _authority: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.observation, FinalizedReleaseObservation):
            raise TypeError("observation must be a FinalizedReleaseObservation")
        if not isinstance(self.finality_attestation, bytes) or not self.finality_attestation:
            raise TypeError("finality_attestation must be nonempty exact bytes")
        if not isinstance(self.chain_evidence, bytes) or not self.chain_evidence:
            raise TypeError("chain_evidence must be nonempty exact bytes")


@dataclass(frozen=True, slots=True)
class _CapturedFinalityPort:
    snapshot: FinalizedSnapshotRef

    async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
        return self.snapshot


@dataclass(frozen=True, slots=True)
class BuiltShadowRelease:
    policy: ScoringPolicy
    manifest: UnsignedLiveShadowReleaseManifest
    release_install_root: str
    files: Mapping[str, bytes]
    file_modes: Mapping[str, int]
    _authority: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class BuiltMinerFinalityArtifact:
    """Exact native miner-finality artifact bytes produced on the target host."""

    report: MinerFinalityBuildReport
    binary: bytes
    report_bytes: bytes
    license_closure: bytes


def load_release_input(path: str | Path) -> tuple[LiveShadowReleaseInput, bytes]:
    encoded = _read_file(Path(path), label="release_input", maximum_bytes=MAX_RELEASE_INPUT_BYTES)
    try:
        descriptor = LiveShadowReleaseInput.model_validate_json(encoded)
    except (ValidationError, ValueError) as error:
        raise ShadowReleaseError("release_input_invalid") from error
    if canonical_json_bytes(descriptor) != encoded:
        raise ShadowReleaseError("release_input_noncanonical")
    return descriptor, encoded


def prepare_shadow_release(
    descriptor: LiveShadowReleaseInput,
    *,
    descriptor_bytes: bytes | None = None,
    now_ms: int | None = None,
) -> PreparedShadowRelease:
    """Derive and validate every unsigned policy and release input."""

    return _prepare_shadow_release(
        descriptor,
        descriptor_bytes=descriptor_bytes,
        now_ms=now_ms,
        verify_replay_baseline=True,
    )


def _execute_exact_conformance(
    *,
    fixture_paths: ConformanceFixturePaths,
    binaries: ConformanceBinaryPins,
    expected_fixture_digests: Mapping[str, str],
    expected_binary_digests: Mapping[str, str],
) -> tuple[bytes, str]:
    """Execute, then bind, every fixture and executable selected for release."""

    try:
        execution = execute_conformance_suite(fixture_paths, binaries=binaries)
    except ConformanceError as error:
        raise ShadowReleaseError(f"conformance_execution_failed:{error.reason_code}") from error
    except Exception as error:
        raise ShadowReleaseError("conformance_execution_failed") from error
    if (
        execution.verified is not True
        or execution.report.fixture_sha256_by_category != dict(expected_fixture_digests)
        or execution.report.binary_sha256_by_name != dict(expected_binary_digests)
        or canonical_json_bytes(execution.report) != execution.canonical_report_bytes
        or hashlib.sha256(execution.canonical_report_bytes).hexdigest() != execution.report_sha256
    ):
        raise ShadowReleaseError("conformance_execution_binding_mismatch")
    _reject_digest(execution.report_sha256, "conformance_execution_report")
    return execution.canonical_report_bytes, execution.report_sha256


def _validate_uv_lock_source_policy(lock_bytes: bytes, pyproject_bytes: bytes) -> None:
    """Accept only the reviewed PyPI graph plus this repository's editable project."""

    try:
        document = tomllib.loads(lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ShadowReleaseError("python_lockfile_invalid") from error
    if (
        set(document) != {"version", "revision", "requires-python", "package"}
        or document.get("version") != 1
        or document.get("revision") != 3
        or not isinstance(document.get("package"), list)
        or not document["package"]
    ):
        raise ShadowReleaseError("python_lockfile_format_unsupported")

    project = _wheel_project_metadata(pyproject_bytes)
    project_name = canonicalize_name(_project_string(project, "name"))
    try:
        if SpecifierSet(document["requires-python"]) != SpecifierSet(
            _project_string(project, "requires-python")
        ):
            raise ShadowReleaseError("python_lockfile_requires_python_mismatch")
    except (InvalidSpecifier, TypeError) as error:
        raise ShadowReleaseError("python_lockfile_invalid") from error

    seen: set[tuple[str, str]] = set()
    project_records = 0
    for package in document["package"]:
        if not isinstance(package, dict):
            raise ShadowReleaseError("python_lockfile_invalid")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if (
            not isinstance(name, str)
            or canonicalize_name(name) != name
            or not isinstance(version, str)
            or not version
            or not isinstance(source, dict)
        ):
            raise ShadowReleaseError("python_lockfile_invalid")
        identity = (name, version)
        if identity in seen:
            raise ShadowReleaseError("python_lockfile_package_duplicate")
        seen.add(identity)

        if name == project_name:
            project_records += 1
            if source != {"editable": "."} or package.get("version") != _project_string(
                project, "version"
            ):
                raise ShadowReleaseError("python_lockfile_project_source_invalid")
            continue
        if source != {"registry": _PYPI_REGISTRY}:
            raise ShadowReleaseError("python_lockfile_source_policy_invalid")
        sdist = package.get("sdist")
        wheels = package.get("wheels")
        if not isinstance(sdist, dict) or not isinstance(wheels, list) or not wheels:
            raise ShadowReleaseError("python_lockfile_artifact_set_invalid")
        for artifact in (sdist, *wheels):
            if not isinstance(artifact, dict):
                raise ShadowReleaseError("python_lockfile_artifact_set_invalid")
            url = artifact.get("url")
            digest = artifact.get("hash")
            size = artifact.get("size")
            parsed = urlsplit(url) if isinstance(url, str) else None
            if (
                parsed is None
                or parsed.scheme != "https"
                or parsed.hostname != "files.pythonhosted.org"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
                or parsed.query
                or parsed.fragment
                or not parsed.path.startswith("/packages/")
                or not isinstance(digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size <= 0
            ):
                raise ShadowReleaseError("python_lockfile_artifact_source_invalid")
        metadata = package.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ShadowReleaseError("python_lockfile_invalid")
        requires_dist = metadata.get("requires-dist", [])
        if not isinstance(requires_dist, list) or any(
            not isinstance(item, dict) or "url" in item for item in requires_dist
        ):
            raise ShadowReleaseError("python_lockfile_requirement_source_invalid")
    if project_records != 1:
        raise ShadowReleaseError("python_lockfile_project_record_invalid")


def _run_pinned_uv_lock_check(
    uv_bytes: bytes,
    *,
    target_triple: str,
    pyproject_bytes: bytes,
    lock_bytes: bytes,
) -> None:
    """Run the packaged uv binary against only the packaged project and lock bytes."""

    temporary = Path(tempfile.mkdtemp(prefix="umi-release-uv-check-"))
    try:
        binary = temporary / "uv"
        project = temporary / "project"
        cache = temporary / "cache"
        project.mkdir(mode=0o700)
        cache.mkdir(mode=0o700)
        binary.write_bytes(uv_bytes)
        binary.chmod(0o500)
        (project / "pyproject.toml").write_bytes(pyproject_bytes)
        (project / "uv.lock").write_bytes(lock_bytes)
        environment = {
            "HOME": str(temporary),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(temporary),
            "UV_CACHE_DIR": str(cache),
            "UV_NO_CONFIG": "1",
            "UV_OFFLINE": "1",
            "UV_PYTHON_DOWNLOADS": "never",
        }
        version = subprocess.run(
            [str(binary), "--version"],
            cwd=project,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        simple_version = f"uv {PINNED_UV_VERSION}\n".encode()
        detailed_version = re.fullmatch(
            (
                rf"uv {re.escape(PINNED_UV_VERSION)} "
                rf"\([0-9a-f]{{7,40}} [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}} "
                rf"{re.escape(target_triple)}\)\n"
            ).encode(),
            version.stdout,
        )
        if (
            version.returncode != 0
            or (version.stdout != simple_version and detailed_version is None)
            or version.stderr
        ):
            raise ShadowReleaseError("uv_binary_version_mismatch")
        checked = subprocess.run(
            [
                str(binary),
                "lock",
                "--check",
                "--offline",
                "--python",
                sys.executable,
                "--project",
                str(project),
            ],
            cwd=project,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if checked.returncode != 0:
            raise ShadowReleaseError("python_lockfile_check_failed")
    except ShadowReleaseError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise ShadowReleaseError("uv_binary_execution_failed") from error
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def _static_elf_machine(payload: bytes, *, label: str) -> int:
    """Return an ELF64 little-endian machine after rejecting dynamic linkage."""

    if (
        len(payload) < 64
        or payload[:4] != b"\x7fELF"
        or payload[4] != 2
        or payload[5] != 1
        or payload[6] != 1
    ):
        raise ShadowReleaseError(f"{label}_not_static_elf")
    machine = int.from_bytes(payload[18:20], "little")
    program_offset = int.from_bytes(payload[32:40], "little")
    entry_size = int.from_bytes(payload[54:56], "little")
    entry_count = int.from_bytes(payload[56:58], "little")
    if (
        program_offset < 64
        or entry_size < 56
        or entry_count < 1
        or entry_count > 256
        or program_offset + entry_size * entry_count > len(payload)
    ):
        raise ShadowReleaseError(f"{label}_elf_headers_invalid")
    for index in range(entry_count):
        start = program_offset + index * entry_size
        program_type = int.from_bytes(payload[start : start + 4], "little")
        if program_type in {2, 3}:
            raise ShadowReleaseError(f"{label}_dynamic_linkage_forbidden")
    return machine


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


def _validate_darwin_arm64_executable(payload: bytes) -> None:
    if (
        len(payload) < 32
        or payload[:4] != _DARWIN_ARM64_MACHO_MAGIC
        or int.from_bytes(payload[4:8], "little") != _DARWIN_ARM64_CPU_TYPE
        or int.from_bytes(payload[12:16], "little") != _MACHO_EXECUTE_FILE_TYPE
    ):
        raise ShadowReleaseError("miner_finality_binary_target_mismatch")


def _parse_finality_self_test_output(
    payload: bytes,
    *,
    fixture_bytes: bytes,
) -> FinalitySelfTestReport:
    if not payload or len(payload) > 64 * 1024 or b"\n" in payload:
        raise ShadowReleaseError("miner_finality_self_test_output_invalid")
    try:
        fixture = FinalityFixtures.model_validate_json(fixture_bytes)
        report = FinalitySelfTestReport.model_validate_json(payload)
    except Exception as error:
        raise ShadowReleaseError("miner_finality_self_test_output_invalid") from error
    if (
        canonical_json_bytes(fixture) != fixture_bytes
        or canonical_json_bytes(report) != payload
        or report.fixture_canonical_sha256 != hashlib.sha256(fixture_bytes).hexdigest()
        or report.finney_checkpoint_canonical_sha256 != fixture.finney_checkpoint_fixture.sha256
    ):
        raise ShadowReleaseError("miner_finality_self_test_binding_mismatch")
    return report


def _validate_miner_finality_build_report(
    *,
    target: str,
    binary_bytes: bytes,
    report_bytes: bytes,
    license_closure_bytes: bytes,
    fixture_bytes: bytes,
    cargo_lock_bytes: bytes,
    source_tree_sha256: str,
    umi_git_revision: str,
) -> MinerFinalityBuildReport:
    if target != DARWIN_MINER_TARGET:
        raise ShadowReleaseError("miner_finality_target_unsupported")
    _validate_darwin_arm64_executable(binary_bytes)
    try:
        report = MinerFinalityBuildReport.model_validate_json(report_bytes)
    except Exception as error:
        raise ShadowReleaseError("miner_finality_build_report_invalid") from error
    if canonical_json_bytes(report) != report_bytes:
        raise ShadowReleaseError("miner_finality_build_report_noncanonical")
    self_test_bytes = canonical_json_bytes(report.self_test)
    _parse_finality_self_test_output(self_test_bytes, fixture_bytes=fixture_bytes)
    expected = (
        report.target_triple == target,
        report.binary_sha256 == hashlib.sha256(binary_bytes).hexdigest(),
        report.binary_size_bytes == len(binary_bytes),
        report.umi_git_revision == umi_git_revision,
        report.finality_source_revision == FINALITY_SOURCE_REVISION,
        report.finality_source_tree_sha256 == source_tree_sha256,
        report.finality_cargo_lock_sha256 == hashlib.sha256(cargo_lock_bytes).hexdigest(),
        report.finality_fixture_set_sha256 == hashlib.sha256(fixture_bytes).hexdigest(),
        report.license_closure_sha256 == hashlib.sha256(license_closure_bytes).hexdigest(),
        report.self_test_output_sha256 == hashlib.sha256(self_test_bytes).hexdigest(),
    )
    if not all(expected):
        raise ShadowReleaseError("miner_finality_build_report_binding_mismatch")
    try:
        verify_rust_license_closure(
            license_closure_bytes,
            cargo_lock_bytes=cargo_lock_bytes,
            target_triple=target,
            binary_name="umi-grandpa-finality-observer",
        )
    except RustLicenseClosureError as error:
        raise ShadowReleaseError(error.reason_code) from error
    return report


def _validate_distribution_zip(
    payload: bytes,
    *,
    label: str,
    required_names: set[str],
) -> dict[str, str]:
    """Reject unsafe or incomplete license/source bundles before they are signed."""

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            if archive.comment:
                raise ShadowReleaseError(f"{label}_archive_comment")
            infos = archive.infolist()
            if not infos or sum(item.file_size for item in infos) > MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise ShadowReleaseError(f"{label}_size_invalid")
            digests: dict[str, str] = {}
            for info in infos:
                path = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if (
                    info.is_dir()
                    or path.is_absolute()
                    or ".." in path.parts
                    or "." in path.parts
                    or "\\" in info.filename
                    or info.filename in digests
                    or info.flag_bits & 0x1
                    or info.comment
                    or info.file_size <= 0
                    or (mode and stat.S_ISLNK(mode))
                ):
                    raise ShadowReleaseError(f"{label}_archive_invalid")
                digest = hashlib.sha256()
                observed_size = 0
                with archive.open(info, "r") as source:
                    while chunk := source.read(1024 * 1024):
                        observed_size += len(chunk)
                        digest.update(chunk)
                if observed_size != info.file_size:
                    raise ShadowReleaseError(f"{label}_archive_invalid")
                digests[info.filename] = digest.hexdigest()
            if not required_names.issubset(digests):
                raise ShadowReleaseError(f"{label}_required_files_missing")
            return digests
    except ShadowReleaseError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ShadowReleaseError(f"{label}_archive_invalid") from error


def _zip_member(payload: bytes, *, name: str, maximum_bytes: int) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            info = archive.getinfo(name)
            if info.file_size > maximum_bytes:
                raise ShadowReleaseError("media_runtime_source_manifest_size_invalid")
            return archive.read(info)
    except ShadowReleaseError:
        raise
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ShadowReleaseError("media_runtime_source_bundle_archive_invalid") from error


def _validate_packaged_python_environment(
    *,
    target_triple: str,
    repository_lock_bytes: bytes | None,
    pyproject_bytes: bytes,
    lock_bytes: bytes,
    uv_bytes: bytes,
    uv_license_bytes: bytes,
    uv_provenance_bytes: bytes,
    execute_lock_check: bool = True,
) -> None:
    """Bind the exact repository graph to one reviewed, target-specific uv tool."""

    if repository_lock_bytes is not None and lock_bytes != repository_lock_bytes:
        raise ShadowReleaseError("python_lockfile_repository_mismatch")
    _validate_uv_lock_source_policy(lock_bytes, pyproject_bytes)
    try:
        provenance = UvToolProvenance.model_validate_json(uv_provenance_bytes)
    except Exception as error:
        raise ShadowReleaseError("uv_provenance_invalid") from error
    if canonical_json_bytes(provenance) != uv_provenance_bytes:
        raise ShadowReleaseError("uv_provenance_noncanonical")
    if (
        provenance.target_triple != target_triple
        or provenance.binary_sha256 != hashlib.sha256(uv_bytes).hexdigest()
        or provenance.license_sha256 != hashlib.sha256(uv_license_bytes).hexdigest()
    ):
        raise ShadowReleaseError("uv_provenance_binding_mismatch")
    if execute_lock_check:
        _run_pinned_uv_lock_check(
            uv_bytes,
            target_triple=target_triple,
            pyproject_bytes=pyproject_bytes,
            lock_bytes=lock_bytes,
        )


def _validate_packaged_media_runtime(
    *,
    target_triple: str,
    ffmpeg_bytes: bytes,
    ffprobe_bytes: bytes,
    manifest_bytes: bytes,
    license_bundle_bytes: bytes,
    source_bundle_bytes: bytes,
) -> None:
    """Verify a signed static media runtime and its redistribution materials."""

    try:
        closure = MediaRuntimeClosure.model_validate_json(manifest_bytes)
    except Exception as error:
        raise ShadowReleaseError("media_runtime_closure_invalid") from error
    if canonical_json_bytes(closure) != manifest_bytes:
        raise ShadowReleaseError("media_runtime_closure_noncanonical")
    if (
        closure.target_triple != target_triple
        or closure.ffmpeg_binary_sha256 != hashlib.sha256(ffmpeg_bytes).hexdigest()
        or closure.ffprobe_binary_sha256 != hashlib.sha256(ffprobe_bytes).hexdigest()
        or closure.license_bundle_sha256 != hashlib.sha256(license_bundle_bytes).hexdigest()
        or closure.corresponding_source_bundle_sha256
        != hashlib.sha256(source_bundle_bytes).hexdigest()
    ):
        raise ShadowReleaseError("media_runtime_closure_binding_mismatch")
    expected_machine = _STATIC_MEDIA_TARGET_MACHINE.get(target_triple)
    if expected_machine is None:
        raise ShadowReleaseError("media_runtime_target_unsupported")
    if (
        _static_elf_machine(ffmpeg_bytes, label="ffmpeg_binary") != expected_machine
        or _static_elf_machine(ffprobe_bytes, label="ffprobe_binary") != expected_machine
    ):
        raise ShadowReleaseError("media_runtime_target_mismatch")
    license_digests = _validate_distribution_zip(
        license_bundle_bytes,
        label="media_runtime_license_bundle",
        required_names={"LICENSES/FFmpeg.txt", "LICENSES/DEPENDENCIES.md"},
    )
    if any(
        len(PurePosixPath(name).parts) != 2 or not name.startswith("LICENSES/")
        for name in license_digests
    ):
        raise ShadowReleaseError("media_runtime_license_bundle_layout_invalid")
    source_digests = _validate_distribution_zip(
        source_bundle_bytes,
        label="media_runtime_source_bundle",
        required_names={"SOURCE-MANIFEST.sha256", "BUILD.md"},
    )
    if any(
        name not in {"SOURCE-MANIFEST.sha256", "BUILD.md"}
        and (len(PurePosixPath(name).parts) != 2 or not name.startswith("SOURCES/"))
        for name in source_digests
    ):
        raise ShadowReleaseError("media_runtime_source_bundle_layout_invalid")
    sources = sorted(name for name in source_digests if name.startswith("SOURCES/"))
    if not sources:
        raise ShadowReleaseError("media_runtime_source_bundle_sources_missing")
    if (
        source_digests.get(f"SOURCES/ffmpeg-{PINNED_FFMPEG_VERSION}.tar.xz")
        != _PINNED_FFMPEG_SOURCE_SHA256
    ):
        raise ShadowReleaseError("media_runtime_ffmpeg_source_mismatch")
    expected_manifest = "".join(f"{source_digests[name]}  {name}\n" for name in sources).encode(
        "ascii"
    )
    if (
        _zip_member(
            source_bundle_bytes,
            name="SOURCE-MANIFEST.sha256",
            maximum_bytes=4 * 1024 * 1024,
        )
        != expected_manifest
    ):
        raise ShadowReleaseError("media_runtime_source_manifest_mismatch")


def _verified_clean_repository_revision(repository_root: Path) -> str:
    """Return HEAD only when the release source and companion docs are committed."""

    environment = {
        "HOME": os.fspath(repository_root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*arguments: str, maximum_bytes: int = 4 * 1024 * 1024) -> bytes:
        try:
            result = subprocess.run(
                ["git", "-C", os.fspath(repository_root), *arguments],
                cwd=repository_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ShadowReleaseError("repository_revision_unavailable") from error
        if result.returncode != 0 or result.stderr or len(result.stdout) > maximum_bytes:
            raise ShadowReleaseError("repository_revision_unavailable")
        return result.stdout

    top = git("rev-parse", "--show-toplevel").decode("utf-8", "strict").rstrip("\n")
    if Path(top) != repository_root:
        raise ShadowReleaseError("repository_revision_root_mismatch")
    revision = git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii", "strict").strip()
    if _GIT_REVISION_RE.fullmatch(revision) is None:
        raise ShadowReleaseError("repository_revision_invalid")
    if git("status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"):
        raise ShadowReleaseError("repository_worktree_not_clean")

    tracked = {
        value.decode("utf-8", "strict")
        for value in git(
            "ls-files",
            "-z",
            "--",
            "src/umi",
            "docs",
            "pyproject.toml",
            "uv.lock",
            "README.md",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
        ).split(b"\0")
        if value
    }
    required = {
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        *(
            path.relative_to(repository_root).as_posix()
            for root in (repository_root / "src" / "umi", repository_root / "docs")
            for path in root.rglob("*")
            if path.is_file()
        ),
    }
    if any((repository_root / relative).is_symlink() for relative in required):
        raise ShadowReleaseError("repository_release_tree_unsafe")
    if not required.issubset(tracked):
        raise ShadowReleaseError("repository_release_file_untracked")
    return revision


def _prepare_shadow_release(
    descriptor: LiveShadowReleaseInput,
    *,
    descriptor_bytes: bytes | None,
    now_ms: int | None,
    verify_replay_baseline: bool,
) -> PreparedShadowRelease:
    """Shared preparation; only the first live pass may omit replay artifacts."""

    if not isinstance(descriptor, LiveShadowReleaseInput):
        raise TypeError("descriptor must be LiveShadowReleaseInput")
    if not isinstance(verify_replay_baseline, bool):
        raise TypeError("verify_replay_baseline must be a boolean")
    encoded_descriptor = descriptor_bytes or canonical_json_bytes(descriptor)
    if canonical_json_bytes(descriptor) != encoded_descriptor:
        raise ShadowReleaseError("release_input_bytes_mismatch")
    observed_now = int(time.time() * 1_000) if now_ms is None else now_ms
    if isinstance(observed_now, bool) or not isinstance(observed_now, int) or observed_now <= 0:
        raise ValueError("now_ms must be a positive integer")
    if descriptor.observation.observed_at_ms > observed_now + 300_000:
        raise ShadowReleaseError("observation_from_future")

    repository_root = Path(descriptor.repository_root)
    module_root = (repository_root / "src" / "umi").resolve()
    if module_root != Path(__file__).resolve().parent:
        raise ShadowReleaseError("repository_source_root_mismatch")
    umi_git_revision = _verified_clean_repository_revision(repository_root)
    pyproject = _read_file(
        repository_root / "pyproject.toml", label="pyproject", maximum_bytes=4 * 1024 * 1024
    )
    repository_lock = _read_file(
        repository_root / "uv.lock",
        label="repository_python_lockfile",
        maximum_bytes=32 * 1024 * 1024,
    )
    project_readme = _read_file(
        repository_root / "README.md",
        label="python_project_readme",
        maximum_bytes=4 * 1024 * 1024,
    )
    repository_license = _read_file(
        repository_root / "LICENSE",
        label="python_project_license",
        maximum_bytes=4 * 1024 * 1024,
    )
    third_party_notices = _read_file(
        repository_root / "THIRD_PARTY_NOTICES.md",
        label="third_party_notices",
        maximum_bytes=4 * 1024 * 1024,
    )

    artifacts = descriptor.artifacts
    external: dict[str, tuple[str, bytes]] = {}

    def read(label: str, value: str, maximum_bytes: int = MAX_RELEASE_FILE_BYTES) -> bytes:
        payload = _read_file(Path(value), label=label, maximum_bytes=maximum_bytes)
        external[label] = (_nonplaceholder_sha256(payload, label=label), payload)
        return payload

    wheel_bytes = read("python_wheel", artifacts.python_wheel)
    wheel_source_sha256 = _verify_wheel_matches_source(
        Path(artifacts.python_wheel),
        wheel_bytes,
        module_root,
        pyproject_bytes=pyproject,
        readme_bytes=project_readme,
        license_bytes=repository_license,
    )
    lock_bytes = read("python_lockfile", artifacts.python_lockfile, 32 * 1024 * 1024)
    uv_bytes = _read_executable(Path(artifacts.uv_binary), label="uv_binary")
    external["uv_binary"] = (
        _nonplaceholder_sha256(uv_bytes, label="uv_binary"),
        uv_bytes,
    )
    uv_license_bytes = read("uv_license", artifacts.uv_license, 4 * 1024 * 1024)
    uv_provenance_bytes = read("uv_provenance", artifacts.uv_provenance, 4 * 1024 * 1024)
    _validate_packaged_python_environment(
        target_triple=descriptor.target_triple,
        repository_lock_bytes=repository_lock,
        pyproject_bytes=pyproject,
        lock_bytes=lock_bytes,
        uv_bytes=uv_bytes,
        uv_license_bytes=uv_license_bytes,
        uv_provenance_bytes=uv_provenance_bytes,
    )
    ffmpeg_bytes = _read_executable(Path(artifacts.ffmpeg_binary), label="ffmpeg_binary")
    external["ffmpeg_binary"] = (
        _nonplaceholder_sha256(ffmpeg_bytes, label="ffmpeg_binary"),
        ffmpeg_bytes,
    )
    ffprobe_bytes = _read_executable(Path(artifacts.ffprobe_binary), label="ffprobe_binary")
    external["ffprobe_binary"] = (
        _nonplaceholder_sha256(ffprobe_bytes, label="ffprobe_binary"),
        ffprobe_bytes,
    )
    media_manifest_bytes = read(
        "media_runtime_manifest",
        artifacts.media_runtime_manifest,
        4 * 1024 * 1024,
    )
    media_license_bundle_bytes = read(
        "media_runtime_license_bundle",
        artifacts.media_runtime_license_bundle,
    )
    media_source_bundle_bytes = read(
        "media_runtime_source_bundle",
        artifacts.media_runtime_source_bundle,
    )
    _validate_packaged_media_runtime(
        target_triple=descriptor.target_triple,
        ffmpeg_bytes=ffmpeg_bytes,
        ffprobe_bytes=ffprobe_bytes,
        manifest_bytes=media_manifest_bytes,
        license_bundle_bytes=media_license_bundle_bytes,
        source_bundle_bytes=media_source_bundle_bytes,
    )
    metadata_bytes = read("runtime_metadata", artifacts.runtime_metadata, 32 * 1024 * 1024)
    capacity_bytes = read("validator_capacity_set", artifacts.validator_capacity_set)
    cost_schedule_bytes = read("validator_cost_schedule", artifacts.validator_cost_schedule)
    try:
        cost_schedule = ValidatorCostSchedule.model_validate_json(cost_schedule_bytes)
    except Exception as error:
        raise ShadowReleaseError("validator_cost_schedule_invalid") from error
    if canonical_json_bytes(cost_schedule) != cost_schedule_bytes:
        raise ShadowReleaseError("validator_cost_schedule_noncanonical")
    mirror_bytes = read("mirror_discovery_rule", artifacts.mirror_discovery_rule)
    try:
        mirror_rule = MirrorDiscoveryRule.model_validate_json(mirror_bytes)
    except Exception as error:
        raise ShadowReleaseError("mirror_discovery_rule_invalid") from error
    if canonical_json_bytes(mirror_rule) != mirror_bytes:
        raise ShadowReleaseError("mirror_discovery_rule_noncanonical")

    fixture_fields = (
        ("normalization_fixture_set", artifacts.normalization_fixture_set),
        ("frame_digest_fixture_set", artifacts.frame_digest_fixture_set),
        ("portable_envelope_fixture_set", artifacts.portable_envelope_fixture_set),
        ("chain_fixture_set", artifacts.chain_fixture_set),
        ("live_chain_fixture_set", artifacts.live_chain_fixture_set),
        ("storage_proof_fixture_set", artifacts.storage_proof_fixture_set),
        ("finality_fixture_set", artifacts.finality_fixture_set),
    )
    for label, path in fixture_fields:
        read(label, path)

    proof_binary = _read_executable(
        Path(artifacts.storage_proof_verifier_binary), label="storage_proof_verifier_binary"
    )
    external["storage_proof_verifier_binary"] = (
        _nonplaceholder_sha256(proof_binary, label="storage_proof_verifier_binary"),
        proof_binary,
    )
    finality_binary = _read_executable(
        Path(artifacts.finality_verifier_binary), label="finality_verifier_binary"
    )
    external["finality_verifier_binary"] = (
        _nonplaceholder_sha256(finality_binary, label="finality_verifier_binary"),
        finality_binary,
    )
    conformance_report_bytes, conformance_report_sha256 = _execute_exact_conformance(
        fixture_paths=ConformanceFixturePaths(
            normalization=Path(artifacts.normalization_fixture_set),
            media=Path(artifacts.frame_digest_fixture_set),
            timelock=Path(artifacts.portable_envelope_fixture_set),
            chain=Path(artifacts.chain_fixture_set),
            live_chain=Path(artifacts.live_chain_fixture_set),
            storage_proof=Path(artifacts.storage_proof_fixture_set),
            finality=Path(artifacts.finality_fixture_set),
        ),
        binaries=ConformanceBinaryPins(
            ffmpeg_path=Path(artifacts.ffmpeg_binary),
            ffmpeg_sha256=external["ffmpeg_binary"][0],
            ffprobe_path=Path(artifacts.ffprobe_binary),
            ffprobe_sha256=external["ffprobe_binary"][0],
            storage_proof_verifier_path=Path(artifacts.storage_proof_verifier_binary),
            storage_proof_verifier_sha256=external["storage_proof_verifier_binary"][0],
            finality_verifier_path=Path(artifacts.finality_verifier_binary),
            finality_verifier_sha256=external["finality_verifier_binary"][0],
        ),
        expected_fixture_digests={
            "normalization": external["normalization_fixture_set"][0],
            "media": external["frame_digest_fixture_set"][0],
            "timelock": external["portable_envelope_fixture_set"][0],
            "chain": external["chain_fixture_set"][0],
            "live_chain": external["live_chain_fixture_set"][0],
            "storage_proof": external["storage_proof_fixture_set"][0],
            "finality": external["finality_fixture_set"][0],
        },
        expected_binary_digests={
            "ffmpeg": external["ffmpeg_binary"][0],
            "ffprobe": external["ffprobe_binary"][0],
            "finality_verifier": external["finality_verifier_binary"][0],
            "storage_proof_verifier": external["storage_proof_verifier_binary"][0],
        },
    )
    chain_spec_bytes = read("finality_chain_spec", artifacts.finality_chain_spec, 64 * 1024 * 1024)
    finality_attestation_bytes: bytes | None = None
    release_observation_chain_evidence_bytes: bytes | None = None
    if verify_replay_baseline:
        finality_attestation_bytes = read(
            "replay_finality_attestation", artifacts.finality_attestation, 16 * 1024 * 1024
        )
        release_observation_chain_evidence_bytes = read(
            "replay_release_observation_chain_evidence",
            artifacts.release_observation_chain_evidence,
            128 * 1024 * 1024,
        )
    if hashlib.sha256(metadata_bytes).hexdigest() != descriptor.observation.runtime_metadata_sha256:
        raise ShadowReleaseError("runtime_metadata_observation_mismatch")
    if finality_attestation_bytes is not None and (
        hashlib.sha256(finality_attestation_bytes).hexdigest()
        != descriptor.observation.finality_attestation_sha256
    ):
        raise ShadowReleaseError("finality_attestation_digest_mismatch")
    for item in descriptor.publisher_capacities:
        read(f"control_disclosure.{item.control_group_id}", item.control_disclosure_path)

    proof_root = Path(descriptor.storage_proof.source_root)
    finality_root = Path(descriptor.finality.source_root)
    proof_source_sha256 = _rust_source_tree_sha256(
        proof_root,
        domain=_PROOF_SOURCE_DOMAIN,
        required_files=("Cargo.toml",),
    )
    proof_manifest = _read_file(proof_root / "Cargo.toml", label="storage_proof_cargo_manifest")
    if proof_manifest.count(descriptor.storage_proof.polkadot_sdk_revision.encode()) != 2:
        raise ShadowReleaseError("storage_proof_sdk_revision_mismatch")
    finality_source_sha256 = _finality_source_tree_sha256(finality_root)
    proof_lock = read("storage_proof_cargo_lock", str(proof_root / "Cargo.lock"))
    finality_lock = read("finality_cargo_lock", str(finality_root / "Cargo.lock"))
    proof_source_bundle = _canonical_source_bundle(
        proof_root,
        archive_root="substrate-proof-verifier",
        required_files=("Cargo.toml", "Cargo.lock", "README.md"),
        recursive_directories=("fixtures", "src"),
    )
    finality_source_bundle = _canonical_source_bundle(
        finality_root,
        archive_root="grandpa-finality-observer",
        required_files=(
            "Cargo.toml",
            "Cargo.lock",
            "README.md",
            "build.rs",
            "rust-toolchain.toml",
        ),
        recursive_directories=(".cargo", "fixtures", "src", "vendor"),
    )
    try:
        proof_license_closure = build_rust_license_closure(
            source_root=proof_root,
            repository_root=repository_root,
            target_triple=descriptor.target_triple,
            binary_name="umi-substrate-proof-verifier",
            expected_root_package="umi-substrate-proof-verifier",
        )
        finality_license_closure = build_rust_license_closure(
            source_root=finality_root,
            repository_root=repository_root,
            target_triple=descriptor.target_triple,
            binary_name="umi-grandpa-finality-observer",
            expected_root_package="umi-grandpa-finality-observer",
        )
    except RustLicenseClosureError as error:
        raise ShadowReleaseError(error.reason_code) from error
    external["storage_proof_source_bundle"] = (
        _nonplaceholder_sha256(proof_source_bundle, label="storage_proof_source_bundle"),
        proof_source_bundle,
    )
    external["finality_source_bundle"] = (
        _nonplaceholder_sha256(finality_source_bundle, label="finality_source_bundle"),
        finality_source_bundle,
    )
    external["storage_proof_license_closure"] = (
        _nonplaceholder_sha256(
            proof_license_closure,
            label="storage_proof_license_closure",
        ),
        proof_license_closure,
    )
    external["finality_license_closure"] = (
        _nonplaceholder_sha256(
            finality_license_closure,
            label="finality_license_closure",
        ),
        finality_license_closure,
    )
    proof_source_marker = proof_source_sha256.encode()
    finality_source_marker = finality_source_sha256.encode()
    external["storage_proof_source_tree"] = (
        _nonplaceholder_sha256(proof_source_marker, label="storage_proof_source_tree"),
        proof_source_marker,
    )
    external["finality_source_tree"] = (
        _nonplaceholder_sha256(finality_source_marker, label="finality_source_tree"),
        finality_source_marker,
    )
    if (
        finality_source_sha256 != FINALITY_SOURCE_TREE_SHA256
        or hashlib.sha256(finality_lock).hexdigest() != FINALITY_CARGO_LOCK_SHA256
        or external["finality_fixture_set"][0] != FINALITY_FIXTURE_SET_SHA256
    ):
        raise ShadowReleaseError("finality_python_adapter_pin_mismatch")

    miner_finality_sha256_by_target: dict[str, str] = {}
    for item in descriptor.miner_finality_targets:
        binary_label = _miner_finality_label("binary", item.target_triple)
        report_label = _miner_finality_label("report", item.target_triple)
        license_label = _miner_finality_label("license", item.target_triple)
        binary_bytes = _read_executable(Path(item.binary_path), label=binary_label)
        external[binary_label] = (
            _nonplaceholder_sha256(binary_bytes, label=binary_label),
            binary_bytes,
        )
        report_bytes = read(report_label, item.build_report_path, 4 * 1024 * 1024)
        license_closure_bytes = read(license_label, item.license_closure_path)
        if (
            hashlib.sha256(binary_bytes).hexdigest() != item.expected_binary_sha256
            or hashlib.sha256(report_bytes).hexdigest() != item.expected_build_report_sha256
            or hashlib.sha256(license_closure_bytes).hexdigest()
            != item.expected_license_closure_sha256
        ):
            raise ShadowReleaseError("miner_finality_input_digest_mismatch")
        _validate_miner_finality_build_report(
            target=item.target_triple,
            binary_bytes=binary_bytes,
            report_bytes=report_bytes,
            license_closure_bytes=license_closure_bytes,
            fixture_bytes=external["finality_fixture_set"][1],
            cargo_lock_bytes=finality_lock,
            source_tree_sha256=finality_source_sha256,
            umi_git_revision=umi_git_revision,
        )
        miner_finality_sha256_by_target[item.target_triple] = hashlib.sha256(
            binary_bytes
        ).hexdigest()

    source_sha256 = wheel_source_sha256
    _reject_digest(source_sha256, "umi_source_tree")
    umi_source_marker = source_sha256.encode()
    external["umi_source_tree"] = (
        _nonplaceholder_sha256(umi_source_marker, label="umi_source_tree"),
        umi_source_marker,
    )
    external["pyproject"] = (_nonplaceholder_sha256(pyproject, label="pyproject"), pyproject)
    external["repository_license"] = (
        _nonplaceholder_sha256(repository_license, label="repository_license"),
        repository_license,
    )
    external["third_party_notices"] = (
        _nonplaceholder_sha256(third_party_notices, label="third_party_notices"),
        third_party_notices,
    )
    _require_distinct_digests(external)

    try:
        capacity_evidence = ValidatorCapacitySetEvidence.model_validate_json(capacity_bytes)
    except Exception as error:
        raise ShadowReleaseError("validator_capacity_set_invalid") from error
    if canonical_json_bytes(capacity_evidence) != capacity_bytes:
        raise ShadowReleaseError("validator_capacity_set_noncanonical")
    _validate_capacity_cost_classes(
        capacity_evidence,
        cost_schedule,
        window_milliseconds=(
            descriptor.observation.target_block_interval_seconds
            * 1_000
            * descriptor.clock.window_stride_blocks
        ),
        maximum_capture_ms=descriptor.observation.observed_at_ms,
    )
    capacity_root = validator_capacity_set_root(capacity_evidence)
    _reject_digest(capacity_root, "validator_capacity_set_root")

    base = PolicyImplementationPins.local_rehearsal(
        ffmpeg_binary=artifacts.ffmpeg_binary,
        ffprobe_binary=artifacts.ffprobe_binary,
    )
    observation = descriptor.observation
    live_chain = LiveChainObservationPin(
        network="finney",
        genesis_block_hash=observation.genesis_block_hash[2:],
        runtime_spec_version=observation.runtime_spec_version,
        transaction_version=observation.transaction_version,
        state_version=observation.state_version,
        metadata_sha256=hashlib.sha256(metadata_bytes).hexdigest(),
        subtensor_revision=observation.subtensor_revision,
        live_chain_fixture_set_sha256=external["live_chain_fixture_set"][0],
    )
    proof_pin = StorageProofVerifierPin(
        protocol="umi-substrate-proof-verifier/1",
        polkadot_sdk_revision=descriptor.storage_proof.polkadot_sdk_revision,
        source_tree_sha256=proof_source_sha256,
        cargo_lock_sha256=hashlib.sha256(proof_lock).hexdigest(),
        proof_fixture_set_sha256=external["storage_proof_fixture_set"][0],
        release_sha256_by_target={
            descriptor.target_triple: hashlib.sha256(proof_binary).hexdigest()
        },
    )
    replay = descriptor.finality.replay
    finality_pin = FinalityVerifierPin(
        profile="smoldot-verifier-attested-finality/1",
        evidence_class="verifier_attested_finality",
        offline_finality_proof=False,
        source_revision=FINALITY_SOURCE_REVISION,
        source_tree_sha256=finality_source_sha256,
        cargo_lock_sha256=hashlib.sha256(finality_lock).hexdigest(),
        finality_fixture_set_sha256=external["finality_fixture_set"][0],
        release_sha256_by_target={
            descriptor.target_triple: hashlib.sha256(finality_binary).hexdigest(),
            **miner_finality_sha256_by_target,
        },
        chain_spec_source_revision=descriptor.finality.chain_spec_source_revision,
        chain_spec_sha256=hashlib.sha256(chain_spec_bytes).hexdigest(),
        expected_genesis_hash=observation.genesis_block_hash[2:],
        bootstrap_kind=replay.bootstrap_kind,
        bootstrap_block_number=replay.bootstrap_block_number,
        bootstrap_block_hash=replay.bootstrap_block_hash,
    )
    implementation = base.model_copy(
        update={
            "pin_profile": "live_shadow_calibration",
            "conformance_fixtures_verified": True,
            "conformance_execution_report_sha256": conformance_report_sha256,
            "umi_source_tree_sha256": source_sha256,
            "scoring": base.scoring.model_copy(
                update={
                    "normalization_fixture_set_sha256": external["normalization_fixture_set"][0]
                }
            ),
            "media": MediaRuntimePin(
                ffmpeg_binary_sha256=hashlib.sha256(ffmpeg_bytes).hexdigest(),
                ffprobe_binary_sha256=hashlib.sha256(ffprobe_bytes).hexdigest(),
                frame_digest_fixture_set_sha256=external["frame_digest_fixture_set"][0],
            ),
            "timelock": base.timelock.model_copy(
                update={
                    "portable_envelope_fixture_set_sha256": external[
                        "portable_envelope_fixture_set"
                    ][0]
                }
            ),
            "chain": ChainRuntimePin(
                reference_runtime_spec=449,
                subtensor_revision="71136ad1098a661c0d5477338b21557b9f9118e2",
                commit_reveal_version=4,
                mechanism_count=1,
                mechanism_id=0,
                chain_fixture_set_sha256=external["chain_fixture_set"][0],
            ),
            "rules": base.rules.model_copy(
                update={"mirror_discovery_rule_sha256": hashlib.sha256(mirror_bytes).hexdigest()}
            ),
            "live_chain": live_chain,
            "storage_proof_verifier": proof_pin,
            "finality_verifier": finality_pin,
        }
    )
    policy = ScoringPolicy.launch(
        translation_weights_active=False,
        activation_block=descriptor.activation_block,
        minimum_publisher_collateral_alpha_rao=(descriptor.minimum_publisher_collateral_alpha_rao),
        soak_start_window_index=descriptor.soak_start_window_index,
        validator_capacity_set_root=capacity_root,
        validator_cost_schedule_hash=hashlib.sha256(cost_schedule_bytes).hexdigest(),
        implementation_pins=implementation,
        validator_registry=descriptor.validator_registry,
        control_group_registry=descriptor.control_group_registry,
        publisher_registry=descriptor.publisher_registry,
    )
    try:
        VerifiedValidatorCapacitySet(policy, capacity_bytes)
    except Exception as error:
        raise ShadowReleaseError("validator_capacity_set_verification_failed") from error

    if verify_replay_baseline:
        assert finality_attestation_bytes is not None
        assert release_observation_chain_evidence_bytes is not None
        _verify_replay_finality_attestation(
            descriptor,
            finality_pin=finality_pin,
            attestation_bytes=finality_attestation_bytes,
        )
        try:
            proof_verifier = SubprocessStorageProofVerifier(
                binary_path=descriptor.artifacts.storage_proof_verifier_binary,
                expected_sha256=hashlib.sha256(proof_binary).hexdigest(),
                timeout_seconds=RELEASE_PROOF_TIMEOUT_SECONDS,
            )
            replayed_observation = replay_release_observation_evidence(
                release_observation_chain_evidence_bytes,
                metadata_bytes=metadata_bytes,
                verifier=proof_verifier,
                validator_registry=descriptor.validator_registry,
                publisher_registry=descriptor.publisher_registry,
                minimum_publisher_collateral_alpha_rao=(
                    descriptor.minimum_publisher_collateral_alpha_rao
                ),
            )
        except ReleaseChainEvidenceError as error:
            raise ShadowReleaseError(error.reason_code) from error
        except Exception as error:
            raise ShadowReleaseError("release_observation_chain_evidence_replay_failed") from error
        chain_observation = replayed_observation.evidence
        if (
            chain_observation.block_number != observation.block_number
            or chain_observation.block_hash != observation.block_hash
            or chain_observation.parent_hash != observation.parent_hash
            or chain_observation.state_root != observation.state_root
            or chain_observation.timestamp_ms != observation.timestamp_ms
            or chain_observation.finality_attestation_sha256
            != observation.finality_attestation_sha256
            or chain_observation.runtime.metadata_sha256 != observation.runtime_metadata_sha256
            or chain_observation.runtime.spec_version != observation.runtime_spec_version
            or chain_observation.runtime.transaction_version != observation.transaction_version
            or chain_observation.runtime.state_version != observation.state_version
        ):
            raise ShadowReleaseError("release_observation_chain_evidence_observation_mismatch")

    signing_requests = _capacity_signing_requests(descriptor, policy, external)
    external_records = tuple(
        ReleaseArtifactDigest(
            label=label,
            relative_path=_packaged_artifact_relative_path(label, digest),
            sha256=digest,
            size_bytes=len(payload),
            install_mode="0555" if _artifact_is_executable(label) else "0444",
        )
        for label, (digest, payload) in sorted(external.items())
    )
    # Construct both generated config models during offline preparation so
    # ``--check`` catches release-relative path bindings and live-config
    # invariants before a networked release attempt.
    _operator_artifacts(
        descriptor,
        scoring_policy_hash(policy),
        external_records,
        umi_git_revision=umi_git_revision,
        umi_source_tree_sha256=policy.implementation_pins.umi_source_tree_sha256,
    )
    return PreparedShadowRelease(
        descriptor=descriptor,
        descriptor_bytes=encoded_descriptor,
        umi_git_revision=umi_git_revision,
        policy=policy,
        external_artifacts=external_records,
        external_artifact_payloads=MappingProxyType(
            {record.relative_path: external[record.label][1] for record in external_records}
        ),
        conformance_report_bytes=conformance_report_bytes,
        signing_requests=signing_requests,
    )


async def collect_live_release_observation(
    prepared: PreparedShadowRelease,
) -> LiveReleaseObservationCapture:
    """Capture release authority directly from pinned smoldot and proven state.

    The public node used for storage reads is not trusted. Its header and every
    storage value must agree with the state root returned by the independently
    running smoldot light client, and all values are verified by the pinned Rust
    trie helper before this function returns.
    """

    if not isinstance(prepared, PreparedShadowRelease):
        raise TypeError("prepared must be PreparedShadowRelease")
    descriptor = prepared.descriptor
    pins = prepared.policy.implementation_pins
    finality_pin = pins.finality_verifier
    proof_pin = pins.storage_proof_verifier
    live_pin = pins.live_chain
    if finality_pin is None or proof_pin is None or live_pin is None:
        raise ShadowReleaseError("live_release_pins_missing")
    try:
        proof_digest = proof_pin.release_sha256_by_target[descriptor.target_triple]
        observer = GrandpaFinalityObserver.from_policy_pin(
            finality_pin,
            target_triple=descriptor.target_triple,
            binary_path=descriptor.artifacts.finality_verifier_binary,
            chain_spec_path=descriptor.artifacts.finality_chain_spec,
        )
        minimum_height = max(
            finality_pin.bootstrap_block_number + 1,
            descriptor.observation.block_number,
        )

        def capture_attestation() -> FinalityAttestation:
            records = tuple(
                observer.attestations(
                    minimum_finalized_block=minimum_height,
                    maximum_records=1,
                    startup_timeout_seconds=descriptor.finality.replay.startup_timeout_seconds,
                )
            )
            if len(records) != 1:
                raise ShadowReleaseError("live_finality_record_count_mismatch")
            return records[0]

        attestation = await asyncio.to_thread(capture_attestation)
    except ShadowReleaseError:
        raise
    except Exception as error:
        raise ShadowReleaseError("live_finality_capture_failed") from error

    block = attestation.block
    snapshot = FinalizedSnapshotRef(
        block_number=block.number,
        block_hash=block.hash,
        parent_hash=block.parent_hash,
        state_root=block.state_root,
    )
    verifier = SubprocessStorageProofVerifier(
        binary_path=descriptor.artifacts.storage_proof_verifier_binary,
        expected_sha256=proof_digest,
        timeout_seconds=RELEASE_PROOF_TIMEOUT_SECONDS,
    )
    client: Any | None = None
    try:
        import bittensor as bt

        client = bt.Client(descriptor.network)
        if await client.connect() is not client:
            raise ShadowReleaseError("live_release_rpc_connection_invalid")
        proofs = FinalizedProofCollector(
            BittensorRawJsonRpc(client),
            finality=_CapturedFinalityPort(snapshot),
            verifier=verifier,
        )
        confirmed_snapshot = await proofs.finalized_snapshot()
        if confirmed_snapshot != snapshot:
            raise ShadowReleaseError("live_release_finalized_snapshot_mismatch")
        capture = await _capture_release_observation_from_proofs(
            prepared,
            attestation=attestation,
            proofs=proofs,
            verifier=verifier,
            observed_at_ms=time.time_ns() // 1_000_000,
        )
    except ShadowReleaseError:
        raise
    except Exception as error:
        raise ShadowReleaseError("live_release_proof_collection_failed") from error
    finally:
        if client is not None:
            with suppress(Exception):
                await client.close()
    return capture


async def _capture_release_observation_from_proofs(
    prepared: PreparedShadowRelease,
    *,
    attestation: FinalityAttestation,
    proofs: Any,
    verifier: SubprocessStorageProofVerifier,
    observed_at_ms: int,
) -> LiveReleaseObservationCapture:
    """Assemble one capture after a direct observer invocation."""

    descriptor = prepared.descriptor
    live_pin = prepared.policy.implementation_pins.live_chain
    if live_pin is None:
        raise ShadowReleaseError("live_release_pins_missing")
    if isinstance(observed_at_ms, bool) or not isinstance(observed_at_ms, int):
        raise TypeError("observed_at_ms must be an integer")
    block = attestation.block
    finalized_head_age_ms = observed_at_ms - block.timestamp_ms
    if finalized_head_age_ms < 0:
        raise ShadowReleaseError("live_release_finalized_head_from_future")
    if finalized_head_age_ms > descriptor.maximum_finalized_head_age_ms:
        raise ShadowReleaseError("live_release_finalized_head_stale")
    snapshot = FinalizedSnapshotRef(
        block_number=block.number,
        block_hash=block.hash,
        parent_hash=block.parent_hash,
        state_root=block.state_root,
    )
    runtime_pin = FinalizedRuntimePin(
        metadata_sha256=live_pin.metadata_sha256,
        spec_version=live_pin.runtime_spec_version,
        transaction_version=live_pin.transaction_version,
        state_version=live_pin.state_version,
        ss58_prefix=42,
    )
    finality_bytes = attestation.canonical_bytes
    finality_digest = hashlib.sha256(finality_bytes).hexdigest()
    try:
        evidence_bytes = await collect_release_observation_evidence(
            snapshot=snapshot,
            timestamp_ms=block.timestamp_ms,
            finality_attestation_sha256=finality_digest,
            runtime_pin=runtime_pin,
            proofs=proofs,
            validator_registry=descriptor.validator_registry,
            publisher_registry=descriptor.publisher_registry,
        )
        replayed = replay_release_observation_evidence(
            evidence_bytes,
            metadata_bytes=_read_file(
                Path(descriptor.artifacts.runtime_metadata),
                label="runtime_metadata",
                maximum_bytes=32 * 1024 * 1024,
            ),
            verifier=verifier,
            validator_registry=descriptor.validator_registry,
            publisher_registry=descriptor.publisher_registry,
            minimum_publisher_collateral_alpha_rao=(
                descriptor.minimum_publisher_collateral_alpha_rao
            ),
        )
    except ReleaseChainEvidenceError as error:
        raise ShadowReleaseError(error.reason_code) from error
    except Exception as error:
        raise ShadowReleaseError("live_release_evidence_assembly_failed") from error
    evidence = replayed.evidence
    if (
        evidence.block_number != block.number
        or evidence.block_hash != block.hash
        or evidence.parent_hash != block.parent_hash
        or evidence.state_root != block.state_root
        or evidence.timestamp_ms != block.timestamp_ms
        or evidence.finality_attestation_sha256 != finality_digest
    ):
        raise ShadowReleaseError("live_release_evidence_finality_mismatch")
    observation = FinalizedReleaseObservation(
        network="finney",
        block_number=block.number,
        block_hash=block.hash,
        parent_hash=block.parent_hash,
        state_root=block.state_root,
        runtime_query_block_hash=block.hash,
        topology_query_block_hash=block.hash,
        runtime_metadata_sha256=evidence.runtime.metadata_sha256,
        finality_attestation_sha256=finality_digest,
        timestamp_ms=block.timestamp_ms,
        observed_at_ms=max(observed_at_ms, block.timestamp_ms),
        genesis_block_hash=f"0x{live_pin.genesis_block_hash}",
        runtime_spec_version=evidence.runtime.spec_version,
        transaction_version=evidence.runtime.transaction_version,
        state_version=evidence.runtime.state_version,
        subtensor_revision=live_pin.subtensor_revision,
        netuid=78,
        mechanism_id=0,
        mechanism_count=1,
        commit_reveal_enabled=True,
        commit_reveal_version=4,
        subnet_active=True,
        translation_weights_active=False,
        target_block_interval_seconds=descriptor.clock.target_block_interval_seconds,
    )
    capture = LiveReleaseObservationCapture(
        observation=observation,
        finality_attestation=finality_bytes,
        chain_evidence=evidence_bytes,
        _authority=_LIVE_CAPTURE_AUTHORITY,
    )
    _validate_authoritative_capture(prepared, capture)
    return capture


def build_shadow_release(
    descriptor: LiveShadowReleaseInput,
    *,
    live_capture: LiveReleaseObservationCapture,
    descriptor_bytes: bytes | None = None,
    now_ms: int | None = None,
) -> BuiltShadowRelease:
    """Verify a live capture and build every canonical public output byte."""

    prepared = prepare_shadow_release(
        descriptor,
        descriptor_bytes=descriptor_bytes,
        now_ms=now_ms,
    )
    _validate_authoritative_capture(prepared, live_capture, now_ms=now_ms)
    descriptor = prepared.descriptor
    policy = prepared.policy
    files: dict[str, bytes] = dict(prepared.external_artifact_payloads)
    files.update(
        {
            _CONFORMANCE_REPORT_PATH: prepared.conformance_report_bytes,
            "release-observation/chain-evidence.json": live_capture.chain_evidence,
            "release-observation/finality-attestation.json": live_capture.finality_attestation,
            "scoring-policy.json": canonical_json_bytes(policy),
        }
    )
    capacity_files, statement_hashes = _verified_publisher_capacity_artifacts(prepared)
    files.update(capacity_files)

    policy_hash = scoring_policy_hash(policy)
    operator_files = _operator_artifacts(
        descriptor,
        policy_hash,
        prepared.external_artifacts,
        umi_git_revision=prepared.umi_git_revision,
        umi_source_tree_sha256=policy.implementation_pins.umi_source_tree_sha256,
    )
    files.update(operator_files)
    authority = _verified_release_authority_attestation(prepared)
    _assert_no_private_material(files)

    packaged_paths = frozenset(prepared.external_artifact_payloads)
    generated = tuple(
        GeneratedReleaseArtifact(
            relative_path=relative,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        for relative, payload in sorted(files.items())
        if relative not in packaged_paths
    )
    external_by_label = {item.label: item for item in prepared.external_artifacts}
    release_observation = live_capture.observation
    manifest = UnsignedLiveShadowReleaseManifest(
        schema=RELEASE_UNSIGNED_MANIFEST_SCHEMA,
        protocol=PROTOCOL_VERSION,
        mode=LIVE_SHADOW_MODE,
        network="finney",
        netuid=78,
        mechanism_id=0,
        translation_weights_active=False,
        activation_block=descriptor.activation_block,
        minimum_release_lead_blocks=descriptor.minimum_release_lead_blocks,
        maximum_finalized_head_age_ms=descriptor.maximum_finalized_head_age_ms,
        release_observation_block=release_observation.block_number,
        release_observation_block_hash=release_observation.block_hash,
        release_observation_timestamp_ms=release_observation.timestamp_ms,
        release_observation_observed_at_ms=release_observation.observed_at_ms,
        scoring_policy_sha256=policy_hash,
        activation_equivalence_digest=activation_equivalence_digest(policy),
        umi_git_revision=prepared.umi_git_revision,
        umi_source_tree_sha256=policy.implementation_pins.umi_source_tree_sha256,
        python_wheel_sha256=external_by_label["python_wheel"].sha256,
        python_lockfile_sha256=external_by_label["python_lockfile"].sha256,
        pyproject_sha256=external_by_label["pyproject"].sha256,
        conformance_execution_report_sha256=(
            policy.implementation_pins.conformance_execution_report_sha256
        ),
        observation_verification_profile=(
            "direct-hash-pinned-smoldot-p2p-plus-layout-v1-release-observation-state/1"
        ),
        supplied_observation_role="capacity-signing-baseline-replay-only/1",
        finality_evidence_class="verifier-attested-not-portable-offline-proof/1",
        release_observation_state_evidence_profile=RELEASE_OBSERVATION_EVIDENCE_PROFILE,
        runtime_metadata_authentication=RUNTIME_METADATA_AUTHENTICATION,
        runtime_version_authentication=RUNTIME_VERSION_AUTHENTICATION,
        subtensor_revision_authentication=(
            "operator-declared-source-map-not-chain-authenticated/1"
        ),
        target_block_interval_authentication=(
            "policy-pinned-calibration-assumption-not-state-proven/1"
        ),
        operator_configuration_profile="release-relative-public-template/1",
        artifact_packaging_profile="target-bound-static-runtime-closure/1",
        release_authenticity_profile=(
            "same-expected-hotkey-signed-static-intent-and-final-manifest/1"
        ),
        release_authority=authority,
        public_artifacts_include_operator_configuration=True,
        external_artifacts=list(prepared.external_artifacts),
        generated_artifacts=list(generated),
        publisher_capacity_statement_sha256s=statement_hashes,
        validator_hotkeys=[item.validator_hotkey for item in descriptor.validator_registry],
        contains_private_material=False,
    )
    final_request = final_manifest_authority_request(manifest)
    files["release-manifest.unsigned.json"] = canonical_json_bytes(manifest)
    files["release-manifest-signing-request.json"] = canonical_json_bytes(final_request)
    _assert_no_private_material(files)
    file_modes = {
        relative: (0o555 if record.install_mode == "0555" else 0o444)
        for record in prepared.external_artifacts
        for relative in (record.relative_path,)
    }
    file_modes.update({relative: 0o444 for relative in files if relative not in file_modes})
    return BuiltShadowRelease(
        policy=policy,
        manifest=manifest,
        release_install_root=descriptor.release_install_root,
        files=MappingProxyType(dict(sorted(files.items()))),
        file_modes=MappingProxyType(dict(sorted(file_modes.items()))),
        _authority=_LIVE_CAPTURE_AUTHORITY,
    )


def _verified_publisher_capacity_artifacts(
    prepared: PreparedShadowRelease,
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Verify every supplied capacity signature without chain or network access."""

    descriptor = prepared.descriptor
    request_by_group = {item.control_group_id: item for item in prepared.signing_requests}
    capacity_by_group = {item.control_group_id: item for item in descriptor.publisher_capacities}
    files: dict[str, bytes] = {}
    statement_hashes: dict[str, str] = {}
    for group_id in sorted(request_by_group):
        request = request_by_group[group_id]
        release_input = capacity_by_group[group_id]
        if release_input.signature is None:
            raise ShadowReleaseError("publisher_capacity_signature_missing")
        signature_bytes = bytes.fromhex(release_input.signature[2:])
        if not verify_response_signature(
            bytes.fromhex(request.digest),
            hotkey_ss58=request.administrator,
            scheme=release_input.signature_scheme,
            signature=release_input.signature,
        ):
            raise ShadowReleaseError("publisher_capacity_signature_invalid")
        if len(signature_bytes) != 64:  # pragma: no cover - schema already narrows this
            raise ShadowReleaseError("publisher_capacity_signature_invalid")
        signed = SignedPublisherCapacity(
            schema=SIGNED_PUBLISHER_CAPACITY_SCHEMA,
            statement=request.statement,
            signature_scheme=release_input.signature_scheme,
            signature=release_input.signature,
        )
        relative = f"publisher-capacity/{group_id}.json"
        payload = canonical_json_bytes(signed)
        files[relative] = payload
        statement_hashes[group_id] = hashlib.sha256(
            canonical_json_bytes(request.statement)
        ).hexdigest()
    return files, statement_hashes


def release_authority_request(prepared: PreparedShadowRelease) -> ReleaseAuthorityRequest:
    """Build the exact static release intent for an external signing tool."""

    if not isinstance(prepared, PreparedShadowRelease):
        raise TypeError("prepared must be PreparedShadowRelease")
    policy = prepared.policy
    static_files = dict(prepared.external_artifact_payloads)
    static_files[_CONFORMANCE_REPORT_PATH] = prepared.conformance_report_bytes
    static_files["scoring-policy.json"] = canonical_json_bytes(policy)
    capacity_files, _statement_hashes = _verified_publisher_capacity_artifacts(prepared)
    static_files.update(capacity_files)
    static_files.update(
        _operator_artifacts(
            prepared.descriptor,
            scoring_policy_hash(policy),
            prepared.external_artifacts,
            umi_git_revision=prepared.umi_git_revision,
            umi_source_tree_sha256=policy.implementation_pins.umi_source_tree_sha256,
        )
    )
    signed_artifacts = [
        GeneratedReleaseArtifact(
            relative_path=relative,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        for relative, payload in sorted(static_files.items())
    ]
    descriptor = prepared.descriptor
    intent = LiveShadowReleaseIntent(
        schema=RELEASE_INTENT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        mode=LIVE_SHADOW_MODE,
        network="finney",
        netuid=78,
        mechanism_id=0,
        translation_weights_active=False,
        target_triple=descriptor.target_triple,
        activation_block=descriptor.activation_block,
        minimum_release_lead_blocks=descriptor.minimum_release_lead_blocks,
        maximum_finalized_head_age_ms=descriptor.maximum_finalized_head_age_ms,
        scoring_policy_sha256=scoring_policy_hash(policy),
        activation_equivalence_digest=activation_equivalence_digest(policy),
        umi_git_revision=prepared.umi_git_revision,
        observation_authentication_profile=(
            "pinned-smoldot-finality-and-state-proof-verified-after-intent-signing/1"
        ),
        signed_artifacts=signed_artifacts,
    )
    digest = hashlib.sha256(_RELEASE_INTENT_DOMAIN + canonical_json_bytes(intent)).hexdigest()
    authority = descriptor.release_authority
    return ReleaseAuthorityRequest(
        schema=RELEASE_AUTHORITY_REQUEST_SCHEMA,
        authority_hotkey=authority.authority_hotkey,
        signature_scheme=authority.signature_scheme,
        intent=intent,
        digest=digest,
    )


def _verified_release_authority_attestation(
    prepared: PreparedShadowRelease,
) -> ReleaseAuthorityAttestation:
    request = release_authority_request(prepared)
    authority = prepared.descriptor.release_authority
    if authority.signature is None:
        raise ShadowReleaseError("release_authority_signature_missing")
    if not verify_response_signature(
        bytes.fromhex(request.digest),
        hotkey_ss58=request.authority_hotkey,
        scheme=request.signature_scheme,
        signature=authority.signature,
    ):
        raise ShadowReleaseError("release_authority_signature_invalid")
    return ReleaseAuthorityAttestation(
        schema=RELEASE_AUTHORITY_SCHEMA,
        authority_hotkey=request.authority_hotkey,
        signature_scheme=request.signature_scheme,
        intent=request.intent,
        digest=request.digest,
        signature=authority.signature,
    )


def final_manifest_authority_request(
    manifest: UnsignedLiveShadowReleaseManifest,
) -> FinalManifestAuthorityRequest:
    """Create the domain-separated signing request for one exact staged manifest."""

    if not isinstance(manifest, UnsignedLiveShadowReleaseManifest) or isinstance(
        manifest, LiveShadowReleaseManifest
    ):
        raise TypeError("manifest must be an unsigned live-shadow manifest")
    payload = canonical_json_bytes(manifest)
    authority = manifest.release_authority
    return FinalManifestAuthorityRequest(
        schema=FINAL_MANIFEST_AUTHORITY_REQUEST_SCHEMA,
        authority_hotkey=authority.authority_hotkey,
        signature_scheme=authority.signature_scheme,
        unsigned_manifest=manifest,
        unsigned_manifest_sha256=hashlib.sha256(payload).hexdigest(),
        digest=hashlib.sha256(_FINAL_MANIFEST_DOMAIN + payload).hexdigest(),
    )


def _validate_authoritative_capture(
    prepared: PreparedShadowRelease,
    capture: LiveReleaseObservationCapture,
    *,
    now_ms: int | None = None,
) -> None:
    """Recheck a direct live capture before it can authorize public output."""

    if not isinstance(capture, LiveReleaseObservationCapture):
        raise TypeError("live_capture must be a LiveReleaseObservationCapture")
    if capture._authority is not _LIVE_CAPTURE_AUTHORITY:
        raise ShadowReleaseError("live_release_capture_not_direct")
    descriptor = prepared.descriptor
    baseline = descriptor.observation
    observation = capture.observation
    current_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if isinstance(current_ms, bool) or not isinstance(current_ms, int) or current_ms <= 0:
        raise ValueError("now_ms must be a positive integer")
    if observation.observed_at_ms > current_ms + 300_000:
        raise ShadowReleaseError("live_release_observation_from_future")
    capture_head_age_ms = observation.observed_at_ms - observation.timestamp_ms
    if capture_head_age_ms < 0:
        raise ShadowReleaseError("live_release_finalized_head_from_future")
    if capture_head_age_ms > descriptor.maximum_finalized_head_age_ms:
        raise ShadowReleaseError("live_release_finalized_head_stale")
    build_head_age_ms = current_ms - observation.timestamp_ms
    if build_head_age_ms < 0:
        raise ShadowReleaseError("live_release_finalized_head_from_future")
    if build_head_age_ms > descriptor.maximum_finalized_head_age_ms:
        raise ShadowReleaseError("live_release_capture_expired")
    if (
        observation.block_number < baseline.block_number
        or observation.timestamp_ms < baseline.timestamp_ms
    ):
        raise ShadowReleaseError("live_release_observation_precedes_signing_baseline")
    required_lead = max(descriptor.clock.anchor_blocks, descriptor.minimum_release_lead_blocks)
    if descriptor.activation_block - observation.block_number < required_lead:
        raise ShadowReleaseError("live_release_observation_has_insufficient_activation_lead")
    expected_common = (
        observation.network == baseline.network == "finney",
        observation.genesis_block_hash == baseline.genesis_block_hash,
        observation.runtime_metadata_sha256 == baseline.runtime_metadata_sha256,
        observation.runtime_spec_version == baseline.runtime_spec_version,
        observation.transaction_version == baseline.transaction_version,
        observation.state_version == baseline.state_version,
        observation.subtensor_revision == baseline.subtensor_revision,
        observation.netuid == baseline.netuid == 78,
        observation.mechanism_id == baseline.mechanism_id == 0,
        observation.mechanism_count == baseline.mechanism_count == 1,
        observation.commit_reveal_enabled is baseline.commit_reveal_enabled is True,
        observation.commit_reveal_version == baseline.commit_reveal_version == 4,
        observation.subnet_active is baseline.subnet_active is True,
        observation.translation_weights_active is baseline.translation_weights_active is False,
        observation.target_block_interval_seconds
        == baseline.target_block_interval_seconds
        == descriptor.clock.target_block_interval_seconds,
    )
    if not all(expected_common):
        raise ShadowReleaseError("live_release_observation_policy_mismatch")
    if (
        hashlib.sha256(capture.finality_attestation).hexdigest()
        != observation.finality_attestation_sha256
    ):
        raise ShadowReleaseError("live_release_finality_digest_mismatch")

    finality_pin = prepared.policy.implementation_pins.finality_verifier
    proof_pin = prepared.policy.implementation_pins.storage_proof_verifier
    if finality_pin is None or proof_pin is None:
        raise ShadowReleaseError("live_release_pins_missing")
    minimum_height = max(finality_pin.bootstrap_block_number + 1, baseline.block_number)
    try:
        observer = GrandpaFinalityObserver(
            binary_path=descriptor.artifacts.finality_verifier_binary,
            expected_binary_sha256=finality_pin.release_sha256_by_target[descriptor.target_triple],
            chain_spec_path=descriptor.artifacts.finality_chain_spec,
            expected_chain_spec_sha256=finality_pin.chain_spec_sha256,
            expected_genesis_hash=f"0x{finality_pin.expected_genesis_hash}",
            bootstrap_block_number=finality_pin.bootstrap_block_number,
            bootstrap_block_hash=f"0x{finality_pin.bootstrap_block_hash}",
        )
        parsed = observer.validate_attestation(
            capture.finality_attestation,
            minimum_finalized_block=minimum_height,
            maximum_records=1,
            startup_timeout_seconds=descriptor.finality.replay.startup_timeout_seconds,
            expected_sequence=0,
            previous_hash=None,
            previous_digest="0" * 64,
            previous_number=None,
            previous_timestamp_ms=None,
        )
    except Exception as error:
        raise ShadowReleaseError("live_release_finality_replay_invalid") from error
    if (
        parsed.block.number != observation.block_number
        or parsed.block.hash != observation.block_hash
        or parsed.block.parent_hash != observation.parent_hash
        or parsed.block.state_root != observation.state_root
        or parsed.block.timestamp_ms != observation.timestamp_ms
    ):
        raise ShadowReleaseError("live_release_finality_observation_mismatch")

    try:
        proof_digest = proof_pin.release_sha256_by_target[descriptor.target_triple]
        verifier = SubprocessStorageProofVerifier(
            binary_path=descriptor.artifacts.storage_proof_verifier_binary,
            expected_sha256=proof_digest,
            timeout_seconds=RELEASE_PROOF_TIMEOUT_SECONDS,
        )
        replayed = replay_release_observation_evidence(
            capture.chain_evidence,
            metadata_bytes=_read_file(
                Path(descriptor.artifacts.runtime_metadata),
                label="runtime_metadata",
                maximum_bytes=32 * 1024 * 1024,
            ),
            verifier=verifier,
            validator_registry=descriptor.validator_registry,
            publisher_registry=descriptor.publisher_registry,
            minimum_publisher_collateral_alpha_rao=(
                descriptor.minimum_publisher_collateral_alpha_rao
            ),
        )
    except ReleaseChainEvidenceError as error:
        raise ShadowReleaseError(error.reason_code) from error
    except Exception as error:
        raise ShadowReleaseError("live_release_evidence_replay_failed") from error
    evidence = replayed.evidence
    if (
        evidence.block_number != observation.block_number
        or evidence.block_hash != observation.block_hash
        or evidence.parent_hash != observation.parent_hash
        or evidence.state_root != observation.state_root
        or evidence.timestamp_ms != observation.timestamp_ms
        or evidence.finality_attestation_sha256 != observation.finality_attestation_sha256
        or evidence.runtime.metadata_sha256 != observation.runtime_metadata_sha256
        or evidence.runtime.spec_version != observation.runtime_spec_version
        or evidence.runtime.transaction_version != observation.transaction_version
        or evidence.runtime.state_version != observation.state_version
    ):
        raise ShadowReleaseError("live_release_chain_evidence_observation_mismatch")


def emit_shadow_release_signing_stage(build: BuiltShadowRelease, emit_dir: str | Path) -> None:
    """Atomically install a fresh unsigned-manifest stage for external signing."""

    if not isinstance(build, BuiltShadowRelease):
        raise TypeError("build must be BuiltShadowRelease")
    if build._authority is not _LIVE_CAPTURE_AUTHORITY:
        raise ShadowReleaseError("shadow_release_build_not_live_authorized")
    destination = _absolute_normal_path(emit_dir, "release signing-stage directory")
    final_destination = Path(build.release_install_root)
    if (
        destination == final_destination
        or destination in final_destination.parents
        or final_destination in destination.parents
    ):
        raise ShadowReleaseError("release_signing_stage_overlaps_protected_path")
    if destination.exists():
        raise ShadowReleaseError("emit_directory_exists")
    if set(build.file_modes) != set(build.files):
        raise ShadowReleaseError("release_file_mode_index_mismatch")
    parent = destination.parent
    if not parent.exists() or parent.is_symlink() or not parent.is_dir():
        raise ShadowReleaseError("emit_parent_invalid")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    try:
        for relative, payload in build.files.items():
            target = temporary / PurePosixPath(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(build.file_modes[relative])
        os.replace(temporary, destination)
    except Exception as error:
        shutil.rmtree(temporary, ignore_errors=True)
        if isinstance(error, ShadowReleaseError):
            raise
        raise ShadowReleaseError("release_signing_stage_emit_failed") from error


def _unsigned_manifest_from_final(
    manifest: LiveShadowReleaseManifest,
) -> UnsignedLiveShadowReleaseManifest:
    values = manifest.model_dump(mode="json", by_alias=True)
    values.pop("final_manifest_authority")
    values["schema"] = RELEASE_UNSIGNED_MANIFEST_SCHEMA
    return UnsignedLiveShadowReleaseManifest.model_validate(values)


def _validate_release_root(root: Path, label: str) -> None:
    try:
        root_status = root.lstat()
    except OSError as error:
        raise ShadowReleaseError(f"{label}_directory_unavailable") from error
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_status.st_mode)
        or root_status.st_uid != os.getuid()
        or stat.S_IMODE(root_status.st_mode) & 0o022
    ):
        raise ShadowReleaseError(f"{label}_directory_unsafe")


def verify_shadow_release_signing_stage(
    stage_dir: str | Path,
    *,
    expected_authority_hotkey: str,
    now_ms: int | None = None,
) -> tuple[UnsignedLiveShadowReleaseManifest, FinalManifestAuthorityRequest]:
    """Verify an exact, still-fresh stage before the final authority signs it."""

    current_ms = _finalization_clock_ms() if now_ms is None else now_ms
    if isinstance(current_ms, bool) or not isinstance(current_ms, int) or current_ms <= 0:
        raise ValueError("now_ms must be a positive integer")
    root = _absolute_normal_path(stage_dir, "release signing-stage directory")
    _validate_release_root(root, "release_signing_stage")
    account_id32(expected_authority_hotkey)
    manifest_bytes = _read_installed_release_file(
        root,
        "release-manifest.unsigned.json",
        maximum_bytes=4 * 1024 * 1024,
    )
    request_bytes = _read_installed_release_file(
        root,
        "release-manifest-signing-request.json",
        maximum_bytes=8 * 1024 * 1024,
    )
    try:
        manifest = UnsignedLiveShadowReleaseManifest.model_validate_json(manifest_bytes)
        request = FinalManifestAuthorityRequest.model_validate_json(request_bytes)
    except Exception as error:
        raise ShadowReleaseError("release_signing_stage_manifest_invalid") from error
    if (
        canonical_json_bytes(manifest) != manifest_bytes
        or canonical_json_bytes(request) != request_bytes
    ):
        raise ShadowReleaseError("release_signing_stage_manifest_noncanonical")
    expected_request = final_manifest_authority_request(manifest)
    if request != expected_request:
        raise ShadowReleaseError("release_final_authority_request_mismatch")
    _verify_unsigned_release_contents(
        root=root,
        manifest=manifest,
        expected_authority_hotkey=expected_authority_hotkey,
        metadata_paths={
            "release-manifest.unsigned.json",
            "release-manifest-signing-request.json",
        },
        now_ms=current_ms,
    )
    return manifest, request


def _load_authenticated_release_manifest(
    release_dir: str | Path,
    *,
    expected_authority_hotkey: str,
) -> tuple[Path, LiveShadowReleaseManifest, UnsignedLiveShadowReleaseManifest]:
    """Load a final manifest and verify its full-manifest authority signature."""

    root = _absolute_normal_path(release_dir, "release directory")
    _validate_release_root(root, "release")
    account_id32(expected_authority_hotkey)
    manifest_bytes = _read_installed_release_file(
        root,
        "release-manifest.json",
        maximum_bytes=8 * 1024 * 1024,
    )
    try:
        manifest = LiveShadowReleaseManifest.model_validate_json(manifest_bytes)
    except Exception as error:
        raise ShadowReleaseError("release_manifest_invalid") from error
    if canonical_json_bytes(manifest) != manifest_bytes:
        raise ShadowReleaseError("release_manifest_noncanonical")
    unsigned = _unsigned_manifest_from_final(manifest)
    request = final_manifest_authority_request(unsigned)
    final_authority = manifest.final_manifest_authority
    if account_id32(final_authority.authority_hotkey) != account_id32(
        expected_authority_hotkey
    ) or account_id32(request.authority_hotkey) != account_id32(expected_authority_hotkey):
        raise ShadowReleaseError("release_authority_untrusted")
    if (
        final_authority.signature_scheme != request.signature_scheme
        or final_authority.unsigned_manifest_sha256 != request.unsigned_manifest_sha256
        or final_authority.digest != request.digest
    ):
        raise ShadowReleaseError("release_final_authority_attestation_mismatch")
    if not verify_response_signature(
        bytes.fromhex(request.digest),
        hotkey_ss58=final_authority.authority_hotkey,
        scheme=final_authority.signature_scheme,
        signature=final_authority.signature,
    ):
        raise ShadowReleaseError("release_final_authority_signature_invalid")
    return root, manifest, unsigned


def verify_shadow_release_directory(
    release_dir: str | Path,
    *,
    expected_authority_hotkey: str,
    now_ms: int | None = None,
) -> LiveShadowReleaseManifest:
    """Verify one finalized public release and both authority signatures."""

    root, manifest, unsigned = _load_authenticated_release_manifest(
        release_dir,
        expected_authority_hotkey=expected_authority_hotkey,
    )
    _verify_unsigned_release_contents(
        root=root,
        manifest=unsigned,
        expected_authority_hotkey=expected_authority_hotkey,
        metadata_paths={"release-manifest.json"},
        now_ms=now_ms,
    )
    return manifest


def verify_miner_release_target(
    release_dir: str | Path,
    *,
    expected_authority_hotkey: str,
    target_triple: str,
    output_dir: str | Path,
) -> ResolvedMinerRelease:
    """Verify and privately materialize one signed native miner target."""

    if target_triple != DARWIN_MINER_TARGET:
        raise ShadowReleaseError("release_miner_finality_target_unsupported")
    root, _manifest, unsigned = _load_authenticated_release_manifest(
        release_dir,
        expected_authority_hotkey=expected_authority_hotkey,
    )
    payload_by_path = _verify_unsigned_release_contents(
        root=root,
        manifest=unsigned,
        expected_authority_hotkey=expected_authority_hotkey,
        metadata_paths={"release-manifest.json"},
        now_ms=None,
        miner_target=target_triple,
    )
    template_relative = f"miner-templates/{target_triple}.json"
    template_bytes = payload_by_path[template_relative]
    try:
        template = ReleaseRelativeMinerConfig.model_validate_json(template_bytes)
    except Exception as error:
        raise ShadowReleaseError("release_miner_template_invalid") from error
    if canonical_json_bytes(template) != template_bytes:
        raise ShadowReleaseError("release_miner_template_noncanonical")
    return _materialize_resolved_miner_release(
        release_root=root,
        destination=_absolute_normal_path(output_dir, "resolved miner output directory"),
        manifest=unsigned,
        template=template,
        payload_by_path=payload_by_path,
    )


def _replace_final_release_directory(source: Path, destination: Path) -> None:
    """Replace the release directory; tests may interrupt immediately beforehand."""

    os.replace(source, destination)


def _finalization_clock_ms() -> int:
    """Read the wall clock at a release-finalization freshness boundary."""

    return time.time_ns() // 1_000_000


def finalize_shadow_release(
    stage_dir: str | Path,
    *,
    final_authority: FinalManifestAuthorityAttestation,
    emit_dir: str | Path,
    expected_authority_hotkey: str,
) -> LiveShadowReleaseManifest:
    """Verify, authorize, and atomically finalize one still-fresh release stage."""

    if not isinstance(final_authority, FinalManifestAuthorityAttestation):
        raise TypeError("final_authority must be a FinalManifestAuthorityAttestation")
    current_ms = _finalization_clock_ms()
    if isinstance(current_ms, bool) or not isinstance(current_ms, int) or current_ms <= 0:
        raise ShadowReleaseError("finalization_clock_invalid")
    stage_root = _absolute_normal_path(stage_dir, "release signing-stage directory")
    destination = _absolute_normal_path(emit_dir, "final release directory")
    manifest, request = verify_shadow_release_signing_stage(
        stage_root,
        expected_authority_hotkey=expected_authority_hotkey,
        now_ms=current_ms,
    )
    if account_id32(final_authority.authority_hotkey) != account_id32(
        expected_authority_hotkey
    ) or account_id32(final_authority.authority_hotkey) != account_id32(request.authority_hotkey):
        raise ShadowReleaseError("release_authority_untrusted")
    if (
        final_authority.signature_scheme != request.signature_scheme
        or final_authority.unsigned_manifest_sha256 != request.unsigned_manifest_sha256
        or final_authority.digest != request.digest
    ):
        raise ShadowReleaseError("release_final_authority_attestation_mismatch")
    if not verify_response_signature(
        bytes.fromhex(request.digest),
        hotkey_ss58=final_authority.authority_hotkey,
        scheme=final_authority.signature_scheme,
        signature=final_authority.signature,
    ):
        raise ShadowReleaseError("release_final_authority_signature_invalid")

    manifest_values = manifest.model_dump(mode="json", by_alias=True)
    manifest_values["schema"] = RELEASE_MANIFEST_SCHEMA
    manifest_values["final_manifest_authority"] = final_authority.model_dump(
        mode="json", by_alias=True
    )
    finalized = LiveShadowReleaseManifest.model_validate(manifest_values)
    if destination.exists():
        raise ShadowReleaseError("final_release_directory_exists")
    try:
        resolved_stage = stage_root.resolve(strict=True)
        resolved_destination = destination.resolve(strict=False)
    except OSError as error:
        raise ShadowReleaseError("final_release_path_resolution_failed") from error
    if (
        destination == stage_root
        or destination in stage_root.parents
        or stage_root in destination.parents
        or resolved_destination == resolved_stage
        or resolved_destination in resolved_stage.parents
        or resolved_stage in resolved_destination.parents
    ):
        raise ShadowReleaseError("final_release_directory_overlaps_stage")
    parent = destination.parent
    if not parent.exists() or parent.is_symlink() or not parent.is_dir():
        raise ShadowReleaseError("final_release_parent_invalid")

    indexed = [
        (item.relative_path, 0o555 if item.install_mode == "0555" else 0o444)
        for item in manifest.external_artifacts
    ] + [(item.relative_path, 0o444) for item in manifest.generated_artifacts]
    payloads = {
        relative: _read_installed_release_file(
            stage_root,
            relative,
            maximum_bytes=MAX_RELEASE_FILE_BYTES,
        )
        for relative, _mode in indexed
    }
    payloads["release-manifest.json"] = canonical_json_bytes(finalized)
    modes = dict(indexed)
    modes["release-manifest.json"] = 0o444
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    try:
        for relative, payload in sorted(payloads.items()):
            target = temporary / PurePosixPath(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(modes[relative])
        verify_shadow_release_directory(
            temporary,
            expected_authority_hotkey=expected_authority_hotkey,
            now_ms=current_ms,
        )
        publication_ms = _finalization_clock_ms()
        if (
            isinstance(publication_ms, bool)
            or not isinstance(publication_ms, int)
            or publication_ms <= 0
        ):
            raise ShadowReleaseError("finalization_clock_invalid")
        publication_age_ms = publication_ms - finalized.release_observation_timestamp_ms
        if publication_age_ms < 0:
            raise ShadowReleaseError("release_observation_from_future")
        if publication_age_ms > finalized.maximum_finalized_head_age_ms:
            raise ShadowReleaseError("release_observation_expired")
        _replace_final_release_directory(temporary, destination)
    except Exception as error:
        shutil.rmtree(temporary, ignore_errors=True)
        if isinstance(error, ShadowReleaseError):
            raise
        raise ShadowReleaseError("final_release_emit_failed") from error
    return finalized


def _verify_unsigned_release_contents(
    *,
    root: Path,
    manifest: UnsignedLiveShadowReleaseManifest,
    expected_authority_hotkey: str,
    metadata_paths: set[str],
    now_ms: int | None,
    miner_target: str | None = None,
) -> dict[str, bytes]:
    if manifest.translation_weights_active is not False:
        raise ShadowReleaseError("release_weights_not_disabled")
    if (
        manifest.release_observation_block >= manifest.activation_block
        or manifest.activation_block - manifest.release_observation_block
        < manifest.minimum_release_lead_blocks
    ):
        raise ShadowReleaseError("release_observation_has_insufficient_activation_lead")
    authority = manifest.release_authority
    if account_id32(authority.authority_hotkey) != account_id32(expected_authority_hotkey):
        raise ShadowReleaseError("release_authority_untrusted")
    expected_digest = hashlib.sha256(
        _RELEASE_INTENT_DOMAIN + canonical_json_bytes(authority.intent)
    ).hexdigest()
    if authority.digest != expected_digest:
        raise ShadowReleaseError("release_authority_digest_mismatch")
    if not verify_response_signature(
        bytes.fromhex(expected_digest),
        hotkey_ss58=authority.authority_hotkey,
        scheme=authority.signature_scheme,
        signature=authority.signature,
    ):
        raise ShadowReleaseError("release_authority_signature_invalid")

    indexed = [
        GeneratedReleaseArtifact(
            relative_path=item.relative_path,
            sha256=item.sha256,
            size_bytes=item.size_bytes,
        )
        for item in manifest.external_artifacts
    ] + list(manifest.generated_artifacts)
    indexed_paths = [item.relative_path for item in indexed]
    if len(indexed_paths) != len(set(indexed_paths)):
        raise ShadowReleaseError("release_artifact_index_duplicate")
    expected_paths = set(indexed_paths) | metadata_paths
    if _installed_release_paths(root) != expected_paths:
        raise ShadowReleaseError("release_artifact_tree_mismatch")
    payload_by_path: dict[str, bytes] = {}
    external_paths = {item.relative_path: item for item in manifest.external_artifacts}
    for item in indexed:
        payload = _read_installed_release_file(
            root,
            item.relative_path,
            maximum_bytes=MAX_RELEASE_FILE_BYTES,
        )
        if len(payload) != item.size_bytes or hashlib.sha256(payload).hexdigest() != item.sha256:
            raise ShadowReleaseError("release_artifact_digest_mismatch")
        payload_by_path[item.relative_path] = payload
        external_record = external_paths.get(item.relative_path)
        expected_mode = (
            0o555
            if external_record is not None and external_record.install_mode == "0555"
            else 0o444
        )
        actual_mode = stat.S_IMODE((root / PurePosixPath(item.relative_path)).stat().st_mode)
        if actual_mode != expected_mode:
            raise ShadowReleaseError("release_artifact_mode_mismatch")
    for relative in metadata_paths:
        if stat.S_IMODE((root / PurePosixPath(relative)).stat().st_mode) != 0o444:
            raise ShadowReleaseError("release_manifest_mode_mismatch")

    intent = authority.intent
    stable_index = sorted(
        (item for item in indexed if not item.relative_path.startswith("release-observation/")),
        key=lambda item: item.relative_path,
    )
    if intent.signed_artifacts != stable_index:
        raise ShadowReleaseError("release_authority_coverage_mismatch")
    common_intent_values = (
        intent.protocol == manifest.protocol,
        intent.mode == manifest.mode,
        intent.network == manifest.network,
        intent.netuid == manifest.netuid,
        intent.mechanism_id == manifest.mechanism_id,
        intent.translation_weights_active is manifest.translation_weights_active is False,
        intent.target_triple in _STATIC_MEDIA_TARGET_MACHINE,
        intent.activation_block == manifest.activation_block,
        intent.minimum_release_lead_blocks == manifest.minimum_release_lead_blocks,
        intent.maximum_finalized_head_age_ms == manifest.maximum_finalized_head_age_ms,
        intent.scoring_policy_sha256 == manifest.scoring_policy_sha256,
        intent.activation_equivalence_digest == manifest.activation_equivalence_digest,
        intent.umi_git_revision == manifest.umi_git_revision,
    )
    if not all(common_intent_values):
        raise ShadowReleaseError("release_authority_manifest_mismatch")

    try:
        policy = ScoringPolicy.model_validate_json(payload_by_path["scoring-policy.json"])
    except Exception as error:
        raise ShadowReleaseError("release_policy_invalid") from error
    if canonical_json_bytes(policy) != payload_by_path["scoring-policy.json"]:
        raise ShadowReleaseError("release_policy_noncanonical")
    if (
        policy.translation_weights_active is not False
        or scoring_policy_hash(policy) != manifest.scoring_policy_sha256
        or activation_equivalence_digest(policy) != manifest.activation_equivalence_digest
    ):
        raise ShadowReleaseError("release_policy_manifest_mismatch")

    external = {item.label: item for item in manifest.external_artifacts}
    expected_labels = set(_PACKAGED_ARTIFACT_FILENAMES)
    pins = policy.implementation_pins
    finality_pin = pins.finality_verifier
    proof_pin = pins.storage_proof_verifier
    if finality_pin is None or proof_pin is None:
        raise ShadowReleaseError("release_live_pins_missing")
    primary_target = manifest.release_authority.intent.target_triple
    miner_targets = sorted(set(finality_pin.release_sha256_by_target) - {primary_target})
    if set(proof_pin.release_sha256_by_target) != {primary_target}:
        raise ShadowReleaseError("release_validator_target_scope_invalid")
    if any(target != DARWIN_MINER_TARGET for target in miner_targets):
        raise ShadowReleaseError("release_miner_finality_target_unsupported")
    for target in miner_targets:
        expected_labels.update(
            {
                _miner_finality_label("binary", target),
                _miner_finality_label("report", target),
                _miner_finality_label("license", target),
            }
        )
    expected_labels.update(
        f"control_disclosure.{item.control_group_id}" for item in policy.control_group_registry
    )
    if set(external) != expected_labels:
        raise ShadowReleaseError("release_required_artifact_set_mismatch")
    expected_generated_paths = {
        _CONFORMANCE_REPORT_PATH,
        "scoring-policy.json",
        "release-observation/chain-evidence.json",
        "release-observation/finality-attestation.json",
        *(
            f"publisher-capacity/{item.control_group_id}.json"
            for item in policy.control_group_registry
        ),
        *(
            f"operator-templates/{account_id32(item.validator_hotkey).hex()}{suffix}"
            for item in policy.validator_registry
            for suffix in (".operator-template.json", ".validator-template.json")
        ),
        *(f"miner-templates/{target}.json" for target in miner_targets),
    }
    if {item.relative_path for item in manifest.generated_artifacts} != expected_generated_paths:
        raise ShadowReleaseError("release_generated_artifact_set_mismatch")
    if (
        manifest.python_wheel_sha256 != external["python_wheel"].sha256
        or manifest.python_lockfile_sha256 != external["python_lockfile"].sha256
        or manifest.pyproject_sha256 != external["pyproject"].sha256
        or manifest.conformance_execution_report_sha256
        != policy.implementation_pins.conformance_execution_report_sha256
        or manifest.umi_source_tree_sha256 != policy.implementation_pins.umi_source_tree_sha256
        or payload_by_path[external["umi_source_tree"].relative_path]
        != manifest.umi_source_tree_sha256.encode()
    ):
        raise ShadowReleaseError("release_manifest_artifact_binding_mismatch")
    _verify_packaged_policy_bindings(
        manifest=manifest,
        policy=policy,
        external=external,
        payload_by_path=payload_by_path,
        execute_primary_tools=miner_target is None,
    )
    if miner_target is None:
        _verify_installed_release_observation(
            root=root,
            manifest=manifest,
            policy=policy,
            external=external,
            now_ms=now_ms,
        )
    elif miner_target != DARWIN_MINER_TARGET:
        raise ShadowReleaseError("release_miner_finality_target_unsupported")
    return payload_by_path


def _verify_packaged_policy_bindings(
    *,
    manifest: UnsignedLiveShadowReleaseManifest,
    policy: ScoringPolicy,
    external: Mapping[str, ReleaseArtifactDigest],
    payload_by_path: Mapping[str, bytes],
    execute_primary_tools: bool = True,
) -> None:
    """Reproduce every policy-to-package binding without builder-local paths."""

    pins = policy.implementation_pins
    live_pin = pins.live_chain
    proof_pin = pins.storage_proof_verifier
    finality_pin = pins.finality_verifier
    if live_pin is None or proof_pin is None or finality_pin is None:
        raise ShadowReleaseError("release_live_pins_missing")
    target = manifest.release_authority.intent.target_triple
    try:
        expected_digests = {
            "ffmpeg_binary": pins.media.ffmpeg_binary_sha256,
            "ffprobe_binary": pins.media.ffprobe_binary_sha256,
            "normalization_fixture_set": pins.scoring.normalization_fixture_set_sha256,
            "frame_digest_fixture_set": pins.media.frame_digest_fixture_set_sha256,
            "portable_envelope_fixture_set": (pins.timelock.portable_envelope_fixture_set_sha256),
            "chain_fixture_set": pins.chain.chain_fixture_set_sha256,
            "live_chain_fixture_set": live_pin.live_chain_fixture_set_sha256,
            "storage_proof_fixture_set": proof_pin.proof_fixture_set_sha256,
            "finality_fixture_set": finality_pin.finality_fixture_set_sha256,
            "storage_proof_verifier_binary": proof_pin.release_sha256_by_target[target],
            "finality_verifier_binary": finality_pin.release_sha256_by_target[target],
            "runtime_metadata": live_pin.metadata_sha256,
            "storage_proof_cargo_lock": proof_pin.cargo_lock_sha256,
            "finality_cargo_lock": finality_pin.cargo_lock_sha256,
            "finality_chain_spec": finality_pin.chain_spec_sha256,
            "validator_cost_schedule": policy.validator_cost_schedule_hash,
            "mirror_discovery_rule": pins.rules.mirror_discovery_rule_sha256,
        }
    except KeyError as error:
        raise ShadowReleaseError("release_target_artifact_binding_missing") from error
    if any(external[label].sha256 != digest for label, digest in expected_digests.items()):
        raise ShadowReleaseError("release_policy_artifact_binding_mismatch")

    def payload(label: str) -> bytes:
        return payload_by_path[external[label].relative_path]

    _validate_packaged_python_environment(
        target_triple=target,
        repository_lock_bytes=None,
        pyproject_bytes=payload("pyproject"),
        lock_bytes=payload("python_lockfile"),
        uv_bytes=payload("uv_binary"),
        uv_license_bytes=payload("uv_license"),
        uv_provenance_bytes=payload("uv_provenance"),
        execute_lock_check=execute_primary_tools,
    )
    _validate_packaged_media_runtime(
        target_triple=target,
        ffmpeg_bytes=payload("ffmpeg_binary"),
        ffprobe_bytes=payload("ffprobe_binary"),
        manifest_bytes=payload("media_runtime_manifest"),
        license_bundle_bytes=payload("media_runtime_license_bundle"),
        source_bundle_bytes=payload("media_runtime_source_bundle"),
    )
    try:
        verify_rust_license_closure(
            payload("storage_proof_license_closure"),
            cargo_lock_bytes=payload("storage_proof_cargo_lock"),
            target_triple=target,
            binary_name="umi-substrate-proof-verifier",
        )
        verify_rust_license_closure(
            payload("finality_license_closure"),
            cargo_lock_bytes=payload("finality_cargo_lock"),
            target_triple=target,
            binary_name="umi-grandpa-finality-observer",
        )
    except RustLicenseClosureError as error:
        raise ShadowReleaseError(error.reason_code) from error

    if (
        payload("storage_proof_source_tree") != proof_pin.source_tree_sha256.encode()
        or payload("finality_source_tree") != finality_pin.source_tree_sha256.encode()
        or payload("umi_source_tree") != pins.umi_source_tree_sha256.encode()
        or _umi_source_tree_sha256_from_wheel(payload("python_wheel"))
        != pins.umi_source_tree_sha256
    ):
        raise ShadowReleaseError("release_source_artifact_binding_mismatch")

    miner_targets = sorted(set(finality_pin.release_sha256_by_target) - {target})
    if set(proof_pin.release_sha256_by_target) != {target}:
        raise ShadowReleaseError("release_validator_target_scope_invalid")
    for miner_target in miner_targets:
        if miner_target != DARWIN_MINER_TARGET:
            raise ShadowReleaseError("release_miner_finality_target_unsupported")
        binary_label = _miner_finality_label("binary", miner_target)
        report_label = _miner_finality_label("report", miner_target)
        license_label = _miner_finality_label("license", miner_target)
        if external[binary_label].sha256 != finality_pin.release_sha256_by_target[miner_target]:
            raise ShadowReleaseError("release_miner_finality_policy_binding_mismatch")
        _validate_miner_finality_build_report(
            target=miner_target,
            binary_bytes=payload(binary_label),
            report_bytes=payload(report_label),
            license_closure_bytes=payload(license_label),
            fixture_bytes=payload("finality_fixture_set"),
            cargo_lock_bytes=payload("finality_cargo_lock"),
            source_tree_sha256=finality_pin.source_tree_sha256,
            umi_git_revision=manifest.umi_git_revision,
        )

    capacity_bytes = payload("validator_capacity_set")
    cost_schedule_bytes = payload("validator_cost_schedule")
    mirror_bytes = payload("mirror_discovery_rule")
    try:
        capacity_evidence = ValidatorCapacitySetEvidence.model_validate_json(capacity_bytes)
        cost_schedule = ValidatorCostSchedule.model_validate_json(cost_schedule_bytes)
        mirror_rule = MirrorDiscoveryRule.model_validate_json(mirror_bytes)
    except Exception as error:
        raise ShadowReleaseError("release_packaged_configuration_invalid") from error
    if (
        canonical_json_bytes(capacity_evidence) != capacity_bytes
        or canonical_json_bytes(cost_schedule) != cost_schedule_bytes
        or canonical_json_bytes(mirror_rule) != mirror_bytes
    ):
        raise ShadowReleaseError("release_packaged_configuration_noncanonical")
    try:
        VerifiedValidatorCapacitySet(policy, capacity_bytes)
        _validate_capacity_cost_classes(
            capacity_evidence,
            cost_schedule,
            window_milliseconds=(
                policy.clock.target_block_interval_seconds
                * 1_000
                * policy.clock.window_stride_blocks
            ),
            maximum_capture_ms=manifest.release_observation_observed_at_ms,
        )
    except ShadowReleaseError:
        raise
    except Exception as error:
        raise ShadowReleaseError("release_validator_capacity_binding_invalid") from error

    group_by_id = {item.control_group_id: item for item in policy.control_group_registry}
    expected_statement_hashes: dict[str, str] = {}
    for group_id, group in sorted(group_by_id.items()):
        relative = f"publisher-capacity/{group_id}.json"
        try:
            signed = SignedPublisherCapacity.model_validate_json(payload_by_path[relative])
        except Exception as error:
            raise ShadowReleaseError("release_publisher_capacity_invalid") from error
        if canonical_json_bytes(signed) != payload_by_path[relative]:
            raise ShadowReleaseError("release_publisher_capacity_noncanonical")
        if (
            signed.statement.control_group_id != group_id
            or account_id32(signed.statement.administrator) != account_id32(group.administrator)
            or signed.statement.control_disclosure_sha256
            != external[f"control_disclosure.{group_id}"].sha256
        ):
            raise ShadowReleaseError("release_publisher_capacity_binding_mismatch")
        try:
            validate_publisher_capacity_statement(signed.statement, policy)
        except Exception as error:
            raise ShadowReleaseError("release_publisher_capacity_statement_invalid") from error
        digest = publisher_capacity_digest(signed.statement)
        if not verify_response_signature(
            digest,
            hotkey_ss58=signed.statement.administrator,
            scheme=signed.signature_scheme,
            signature=signed.signature,
        ):
            raise ShadowReleaseError("release_publisher_capacity_signature_invalid")
        expected_statement_hashes[group_id] = hashlib.sha256(
            canonical_json_bytes(signed.statement)
        ).hexdigest()
    if expected_statement_hashes != manifest.publisher_capacity_statement_sha256s:
        raise ShadowReleaseError("release_publisher_capacity_digest_mismatch")

    validator_transport_timeouts: list[float] = []
    validator_transport_concurrency: list[int] = []
    for entry in policy.validator_registry:
        account_hex = account_id32(entry.validator_hotkey).hex()
        validator_path = f"operator-templates/{account_hex}.validator-template.json"
        operator_path = f"operator-templates/{account_hex}.operator-template.json"
        try:
            validator_template = ReleaseRelativeValidatorConfig.model_validate_json(
                payload_by_path[validator_path]
            )
            operator_template = ReleaseRelativeOperatorConfig.model_validate_json(
                payload_by_path[operator_path]
            )
        except Exception as error:
            raise ShadowReleaseError("release_operator_template_invalid") from error
        if (
            canonical_json_bytes(validator_template) != payload_by_path[validator_path]
            or canonical_json_bytes(operator_template) != payload_by_path[operator_path]
        ):
            raise ShadowReleaseError("release_operator_template_noncanonical")
        if (
            account_id32(validator_template.validator_hotkey)
            != account_id32(entry.validator_hotkey)
            or account_id32(operator_template.validator_hotkey)
            != account_id32(entry.validator_hotkey)
            or validator_template.policy_path != "scoring-policy.json"
            or validator_template.scoring_policy_sha256 != manifest.scoring_policy_sha256
            or validator_template.target_triple != target
            or validator_template.storage_proof_verifier_binary
            != external["storage_proof_verifier_binary"].relative_path
            or validator_template.finality_verifier_binary
            != external["finality_verifier_binary"].relative_path
            or validator_template.finality_chain_spec_path
            != external["finality_chain_spec"].relative_path
            or validator_template.initial_minimum_finalized_block != manifest.activation_block - 1
            or validator_template.umi_revision
            != (
                "git:"
                + manifest.umi_git_revision
                + ";source-tree-sha256:"
                + manifest.umi_source_tree_sha256
            )
            or operator_template.validator_capacity_set_path
            != external["validator_capacity_set"].relative_path
            or operator_template.mirror_discovery_rule_path
            != external["mirror_discovery_rule"].relative_path
        ):
            raise ShadowReleaseError("release_operator_template_binding_mismatch")
        validator_transport_timeouts.append(validator_template.transport_timeout_seconds)
        validator_transport_concurrency.append(validator_template.maximum_transport_concurrency)

    for miner_target in miner_targets:
        relative = f"miner-templates/{miner_target}.json"
        try:
            miner_template = ReleaseRelativeMinerConfig.model_validate_json(
                payload_by_path[relative]
            )
        except Exception as error:
            raise ShadowReleaseError("release_miner_template_invalid") from error
        if canonical_json_bytes(miner_template) != payload_by_path[relative]:
            raise ShadowReleaseError("release_miner_template_noncanonical")
        if (
            miner_template.target_triple != miner_target
            or miner_template.policy_path != "scoring-policy.json"
            or miner_template.scoring_policy_sha256 != manifest.scoring_policy_sha256
            or miner_template.python_wheel != external["python_wheel"].relative_path
            or miner_template.python_lockfile != external["python_lockfile"].relative_path
            or miner_template.pyproject != external["pyproject"].relative_path
            or miner_template.mirror_discovery_rule_path
            != external["mirror_discovery_rule"].relative_path
            or miner_template.finality_verifier_binary
            != external[_miner_finality_label("binary", miner_target)].relative_path
            or miner_template.finality_chain_spec_path
            != external["finality_chain_spec"].relative_path
            or miner_template.finality_build_report
            != external[_miner_finality_label("report", miner_target)].relative_path
            or miner_template.finality_license_closure
            != external[_miner_finality_label("license", miner_target)].relative_path
            or miner_template.initial_minimum_finalized_block != manifest.activation_block - 1
            or miner_template.minimum_validator_transport_timeout_seconds
            != min(validator_transport_timeouts)
            or miner_template.minimum_validator_transport_concurrency
            != min(validator_transport_concurrency)
            or miner_template.umi_git_revision != manifest.umi_git_revision
            or miner_template.umi_source_tree_sha256 != manifest.umi_source_tree_sha256
            or miner_template.umi_revision
            != (
                "git:"
                + manifest.umi_git_revision
                + ";source-tree-sha256:"
                + manifest.umi_source_tree_sha256
            )
        ):
            raise ShadowReleaseError("release_miner_template_binding_mismatch")

    if execute_primary_tools:
        _verify_packaged_conformance(
            manifest=manifest,
            policy=policy,
            external=external,
            payload_by_path=payload_by_path,
        )


def _verify_packaged_conformance(
    *,
    manifest: UnsignedLiveShadowReleaseManifest,
    policy: ScoringPolicy,
    external: Mapping[str, ReleaseArtifactDigest],
    payload_by_path: Mapping[str, bytes],
) -> None:
    """Rerun conformance from exact packaged bytes and compare its signed report."""

    expected_report_sha256 = policy.implementation_pins.conformance_execution_report_sha256
    report_bytes = payload_by_path[_CONFORMANCE_REPORT_PATH]
    if (
        expected_report_sha256 is None
        or manifest.conformance_execution_report_sha256 != expected_report_sha256
        or hashlib.sha256(report_bytes).hexdigest() != expected_report_sha256
    ):
        raise ShadowReleaseError("release_conformance_report_binding_mismatch")
    try:
        report = ConformanceExecutionReport.model_validate_json(report_bytes)
    except Exception as error:
        raise ShadowReleaseError("release_conformance_report_invalid") from error
    if canonical_json_bytes(report) != report_bytes:
        raise ShadowReleaseError("release_conformance_report_noncanonical")

    def payload(label: str) -> bytes:
        return payload_by_path[external[label].relative_path]

    temporary = Path(tempfile.mkdtemp(prefix="umi-release-conformance-"))
    try:
        staged: dict[str, Path] = {}
        labels = (
            "normalization_fixture_set",
            "frame_digest_fixture_set",
            "portable_envelope_fixture_set",
            "chain_fixture_set",
            "live_chain_fixture_set",
            "storage_proof_fixture_set",
            "finality_fixture_set",
            "ffmpeg_binary",
            "ffprobe_binary",
            "storage_proof_verifier_binary",
            "finality_verifier_binary",
        )
        for label in labels:
            target = temporary / _PACKAGED_ARTIFACT_FILENAMES[label]
            target.write_bytes(payload(label))
            target.chmod(0o700 if label in _EXECUTABLE_ARTIFACT_LABELS else 0o600)
            staged[label] = target
        rerun_bytes, rerun_sha256 = _execute_exact_conformance(
            fixture_paths=ConformanceFixturePaths(
                normalization=staged["normalization_fixture_set"],
                media=staged["frame_digest_fixture_set"],
                timelock=staged["portable_envelope_fixture_set"],
                chain=staged["chain_fixture_set"],
                live_chain=staged["live_chain_fixture_set"],
                storage_proof=staged["storage_proof_fixture_set"],
                finality=staged["finality_fixture_set"],
            ),
            binaries=ConformanceBinaryPins(
                ffmpeg_path=staged["ffmpeg_binary"],
                ffmpeg_sha256=external["ffmpeg_binary"].sha256,
                ffprobe_path=staged["ffprobe_binary"],
                ffprobe_sha256=external["ffprobe_binary"].sha256,
                storage_proof_verifier_path=staged["storage_proof_verifier_binary"],
                storage_proof_verifier_sha256=external["storage_proof_verifier_binary"].sha256,
                finality_verifier_path=staged["finality_verifier_binary"],
                finality_verifier_sha256=external["finality_verifier_binary"].sha256,
            ),
            expected_fixture_digests={
                "normalization": external["normalization_fixture_set"].sha256,
                "media": external["frame_digest_fixture_set"].sha256,
                "timelock": external["portable_envelope_fixture_set"].sha256,
                "chain": external["chain_fixture_set"].sha256,
                "live_chain": external["live_chain_fixture_set"].sha256,
                "storage_proof": external["storage_proof_fixture_set"].sha256,
                "finality": external["finality_fixture_set"].sha256,
            },
            expected_binary_digests={
                "ffmpeg": external["ffmpeg_binary"].sha256,
                "ffprobe": external["ffprobe_binary"].sha256,
                "finality_verifier": external["finality_verifier_binary"].sha256,
                "storage_proof_verifier": external["storage_proof_verifier_binary"].sha256,
            },
        )
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    if rerun_sha256 != expected_report_sha256 or rerun_bytes != report_bytes:
        raise ShadowReleaseError("release_conformance_report_reproduction_mismatch")


def _write_resolved_miner_artifact(
    directory_descriptor: int,
    *,
    filename: str,
    payload: bytes,
    mode: Literal[0o444, 0o555],
) -> None:
    """Write one direct child through an already verified private directory FD."""

    if not filename or "/" in filename or filename in {".", ".."}:
        raise ShadowReleaseError("resolved_miner_artifact_name_invalid")
    descriptor = -1
    try:
        descriptor = os.open(
            filename,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:  # pragma: no cover - an OS write invariant
                raise OSError("resolved miner artifact write made no progress")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
            or status.st_size != len(payload)
            or stat.S_IMODE(status.st_mode) != mode
        ):
            raise ShadowReleaseError("resolved_miner_artifact_unsafe")
    except ShadowReleaseError:
        raise
    except OSError as error:
        raise ShadowReleaseError("resolved_miner_artifact_emit_failed") from error
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _run_native_miner_finality_self_test(
    *,
    binary_path: Path,
    expected_binary_sha256: str,
    report: MinerFinalityBuildReport,
) -> None:
    """Execute an FD-verified private copy of the materialized native binary."""

    if sys.platform != "darwin" or platform.machine().casefold() not in {"arm64", "aarch64"}:
        raise ShadowReleaseError("miner_finality_native_host_required")
    try:
        with staged_pinned_artifacts(
            (
                PinnedArtifact(
                    name="miner_finality",
                    source=binary_path,
                    expected_sha256=expected_binary_sha256,
                    maximum_bytes=MAX_RELEASE_FILE_BYTES,
                    executable=True,
                ),
            )
        ) as staged:
            process = subprocess.run(
                [os.fspath(staged["miner_finality"]), "--conformance-self-test"],
                cwd=staged["miner_finality"].parent,
                env={"LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
    except (OSError, subprocess.SubprocessError, PinnedArtifactError) as error:
        raise ShadowReleaseError("miner_finality_self_test_failed") from error
    expected_output = canonical_json_bytes(report.self_test) + b"\n"
    if process.returncode != 0 or process.stdout != expected_output:
        raise ShadowReleaseError("miner_finality_self_test_reproduction_mismatch")


def _materialize_resolved_miner_release(
    *,
    release_root: Path,
    destination: Path,
    manifest: UnsignedLiveShadowReleaseManifest,
    template: ReleaseRelativeMinerConfig,
    payload_by_path: Mapping[str, bytes],
) -> ResolvedMinerRelease:
    """Create a fresh read-only runtime tree solely from authenticated bytes."""

    try:
        source_root = release_root.resolve(strict=True)
        parent = destination.parent
        parent_status = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise ShadowReleaseError("resolved_miner_output_parent_unavailable") from error
    parent_mode = stat.S_IMODE(parent_status.st_mode)
    if (
        parent.is_symlink()
        or resolved_parent != parent
        or not stat.S_ISDIR(parent_status.st_mode)
        or parent_status.st_uid != os.getuid()
        or parent_mode & 0o077
        or parent_mode & 0o300 != 0o300
    ):
        raise ShadowReleaseError("resolved_miner_output_parent_unsafe")
    try:
        for ancestor in (parent, *parent.parents):
            status = ancestor.lstat()
            mode = stat.S_IMODE(status.st_mode)
            root_sticky_boundary = status.st_uid == 0 and bool(mode & stat.S_ISVTX)
            if (
                ancestor.is_symlink()
                or not stat.S_ISDIR(status.st_mode)
                or (mode & 0o022 and not root_sticky_boundary)
            ):
                raise ShadowReleaseError("resolved_miner_output_parent_unsafe")
    except OSError as error:
        raise ShadowReleaseError("resolved_miner_output_parent_unavailable") from error
    prospective = destination.resolve(strict=False)
    if (
        destination == release_root
        or destination in release_root.parents
        or release_root in destination.parents
        or prospective == source_root
        or prospective in source_root.parents
        or source_root in prospective.parents
    ):
        raise ShadowReleaseError("resolved_miner_output_overlaps_release")

    fields = (
        ("policy_path", "scoring-policy.json", template.policy_path, 0o444),
        ("python_wheel", "umi-python-wheel.whl", template.python_wheel, 0o444),
        ("python_lockfile", "uv.lock", template.python_lockfile, 0o444),
        ("pyproject", "pyproject.toml", template.pyproject, 0o444),
        (
            "mirror_discovery_rule_path",
            "mirror-discovery-rule.json",
            template.mirror_discovery_rule_path,
            0o444,
        ),
        (
            "finality_verifier_binary",
            "umi-grandpa-finality-observer",
            template.finality_verifier_binary,
            0o555,
        ),
        (
            "finality_chain_spec_path",
            "finney-chain-spec.json",
            template.finality_chain_spec_path,
            0o444,
        ),
        (
            "finality_build_report",
            "miner-finality-build-report.json",
            template.finality_build_report,
            0o444,
        ),
        (
            "finality_license_closure",
            "finality-third-party-licenses.zip",
            template.finality_license_closure,
            0o444,
        ),
    )
    try:
        source_payloads = {
            field: payload_by_path[
                _release_relative_path(relative, "miner template artifact").as_posix()
            ]
            for field, _filename, relative, _mode in fields
        }
    except KeyError as error:
        raise ShadowReleaseError("release_miner_artifact_unavailable") from error
    output_paths = {field: destination / filename for field, filename, _relative, _mode in fields}
    resolved = ResolvedMinerRelease(
        schema=RESOLVED_MINER_RELEASE_SCHEMA,
        protocol=template.protocol,
        role="miner",
        translation_weights_active=False,
        target_triple=template.target_triple,
        scoring_policy_sha256=manifest.scoring_policy_sha256,
        **{field: os.fspath(output_paths[field]) for field, _name, _relative, _mode in fields},
        initial_minimum_finalized_block=template.initial_minimum_finalized_block,
        minimum_validator_transport_timeout_seconds=(
            template.minimum_validator_transport_timeout_seconds
        ),
        minimum_validator_transport_concurrency=(template.minimum_validator_transport_concurrency),
        umi_git_revision=template.umi_git_revision,
        umi_source_tree_sha256=template.umi_source_tree_sha256,
        umi_revision=template.umi_revision,
        validator_runtime_supported=False,
    )

    parent_descriptor = -1
    directory_descriptor = -1
    created_status: os.stat_result | None = None
    try:
        parent_descriptor = os.open(
            os.fspath(parent),
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_parent = os.fstat(parent_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_status.st_dev,
            parent_status.st_ino,
        ):
            raise ShadowReleaseError("resolved_miner_output_parent_changed")
        try:
            os.mkdir(destination.name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError as error:
            raise ShadowReleaseError("resolved_miner_output_directory_exists") from error
        created_status = os.stat(
            destination.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        directory_descriptor = os.open(
            destination.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened_status = os.fstat(directory_descriptor)
        if (
            (opened_status.st_dev, opened_status.st_ino)
            != (created_status.st_dev, created_status.st_ino)
            or not stat.S_ISDIR(opened_status.st_mode)
            or opened_status.st_uid != os.getuid()
            or stat.S_IMODE(opened_status.st_mode) != 0o700
        ):
            raise ShadowReleaseError("resolved_miner_output_directory_unsafe")

        for field, filename, _relative, mode in fields:
            _write_resolved_miner_artifact(
                directory_descriptor,
                filename=filename,
                payload=source_payloads[field],
                mode=mode,
            )

        staged_payloads: dict[str, bytes] = {}
        for field, filename, _relative, mode in fields:
            path = output_paths[field]
            status = os.stat(filename, dir_fd=directory_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != os.getuid()
                or status.st_nlink != 1
                or stat.S_IMODE(status.st_mode) != mode
            ):
                raise ShadowReleaseError("resolved_miner_artifact_unsafe")
            payload = _read_owned_file(
                path,
                label="resolved_miner_artifact",
                maximum_bytes=MAX_RELEASE_FILE_BYTES,
                executable=mode == 0o555,
                private=False,
            )
            if payload != source_payloads[field]:
                raise ShadowReleaseError("resolved_miner_artifact_changed")
            staged_payloads[field] = payload

        policy = ScoringPolicy.model_validate_json(staged_payloads["policy_path"])
        finality_pin = policy.implementation_pins.finality_verifier
        external = {item.label: item for item in manifest.external_artifacts}
        if finality_pin is None:
            raise ShadowReleaseError("release_miner_finality_runtime_binding_missing")
        try:
            fixture_bytes = payload_by_path[external["finality_fixture_set"].relative_path]
            cargo_lock_bytes = payload_by_path[external["finality_cargo_lock"].relative_path]
            expected_binary_sha256 = finality_pin.release_sha256_by_target[template.target_triple]
        except KeyError as error:
            raise ShadowReleaseError("release_miner_finality_runtime_binding_missing") from error
        report = _validate_miner_finality_build_report(
            target=template.target_triple,
            binary_bytes=staged_payloads["finality_verifier_binary"],
            report_bytes=staged_payloads["finality_build_report"],
            license_closure_bytes=staged_payloads["finality_license_closure"],
            fixture_bytes=fixture_bytes,
            cargo_lock_bytes=cargo_lock_bytes,
            source_tree_sha256=finality_pin.source_tree_sha256,
            umi_git_revision=manifest.umi_git_revision,
        )
        _run_native_miner_finality_self_test(
            binary_path=output_paths["finality_verifier_binary"],
            expected_binary_sha256=expected_binary_sha256,
            report=report,
        )
        _write_resolved_miner_artifact(
            directory_descriptor,
            filename="resolved-miner-release.json",
            payload=canonical_json_bytes(resolved),
            mode=0o444,
        )
        expected_names = {filename for _field, filename, _relative, _mode in fields} | {
            "resolved-miner-release.json"
        }
        if set(os.listdir(directory_descriptor)) != expected_names:
            raise ShadowReleaseError("resolved_miner_output_tree_mismatch")
        os.fsync(directory_descriptor)
        os.fchmod(directory_descriptor, 0o555)
        final_status = os.fstat(directory_descriptor)
        lexical_parent_status = parent.lstat()
        destination_status = os.stat(
            destination.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            (lexical_parent_status.st_dev, lexical_parent_status.st_ino)
            != (opened_parent.st_dev, opened_parent.st_ino)
            or parent.resolve(strict=True) != parent
            or (final_status.st_dev, final_status.st_ino)
            != (created_status.st_dev, created_status.st_ino)
            or (destination_status.st_dev, destination_status.st_ino)
            != (created_status.st_dev, created_status.st_ino)
            or stat.S_IMODE(final_status.st_mode) != 0o555
            or stat.S_IMODE(destination_status.st_mode) != 0o555
        ):
            raise ShadowReleaseError("resolved_miner_output_directory_changed")
        return resolved
    except ShadowReleaseError:
        raise
    except (OSError, ValidationError, ValueError, TypeError) as error:
        raise ShadowReleaseError("resolved_miner_output_emit_failed") from error
    finally:
        if directory_descriptor >= 0:
            with suppress(OSError):
                os.close(directory_descriptor)
        if parent_descriptor >= 0:
            with suppress(OSError):
                os.close(parent_descriptor)
        if created_status is not None and sys.exc_info()[0] is not None:
            try:
                current = destination.lstat()
                if (current.st_dev, current.st_ino) == (
                    created_status.st_dev,
                    created_status.st_ino,
                ):
                    destination.chmod(0o700)
                    shutil.rmtree(destination)
            except OSError:
                pass


def _verify_installed_release_observation(
    *,
    root: Path,
    manifest: UnsignedLiveShadowReleaseManifest,
    policy: ScoringPolicy,
    external: Mapping[str, ReleaseArtifactDigest],
    now_ms: int | None,
) -> None:
    finality_pin = policy.implementation_pins.finality_verifier
    proof_pin = policy.implementation_pins.storage_proof_verifier
    if finality_pin is None or proof_pin is None:
        raise ShadowReleaseError("release_live_pins_missing")
    target = manifest.release_authority.intent.target_triple

    def artifact_path(label: str) -> Path:
        return root / PurePosixPath(external[label].relative_path)

    finality_bytes = _read_installed_release_file(
        root,
        "release-observation/finality-attestation.json",
        maximum_bytes=16 * 1024 * 1024,
    )
    evidence_bytes = _read_installed_release_file(
        root,
        "release-observation/chain-evidence.json",
        maximum_bytes=128 * 1024 * 1024,
    )
    try:
        observer = GrandpaFinalityObserver.from_policy_pin(
            finality_pin,
            target_triple=target,
            binary_path=artifact_path("finality_verifier_binary"),
            chain_spec_path=artifact_path("finality_chain_spec"),
        )
        parsed = observer.validate_attestation(
            finality_bytes,
            minimum_finalized_block=manifest.release_observation_block,
            maximum_records=1,
            startup_timeout_seconds=30,
            expected_sequence=0,
            previous_hash=None,
            previous_digest="0" * 64,
            previous_number=None,
            previous_timestamp_ms=None,
        )
        proof_digest = proof_pin.release_sha256_by_target[target]
        verifier = SubprocessStorageProofVerifier(
            binary_path=artifact_path("storage_proof_verifier_binary"),
            expected_sha256=proof_digest,
            timeout_seconds=RELEASE_PROOF_TIMEOUT_SECONDS,
        )
        replayed = replay_release_observation_evidence(
            evidence_bytes,
            metadata_bytes=_read_installed_release_file(
                root,
                external["runtime_metadata"].relative_path,
                maximum_bytes=32 * 1024 * 1024,
            ),
            verifier=verifier,
            validator_registry=policy.validator_registry,
            publisher_registry=policy.publisher_registry,
            minimum_publisher_collateral_alpha_rao=(policy.minimum_publisher_collateral_alpha_rao),
        )
    except ShadowReleaseError:
        raise
    except Exception as error:
        raise ShadowReleaseError("release_observation_verification_failed") from error
    evidence = replayed.evidence
    live_pin = policy.implementation_pins.live_chain
    if live_pin is None:
        raise ShadowReleaseError("release_live_pins_missing")
    if (
        parsed.block.number != manifest.release_observation_block
        or parsed.block.hash != manifest.release_observation_block_hash
        or parsed.block.timestamp_ms != manifest.release_observation_timestamp_ms
        or evidence.block_number != parsed.block.number
        or evidence.block_hash != parsed.block.hash
        or evidence.parent_hash != parsed.block.parent_hash
        or evidence.state_root != parsed.block.state_root
        or evidence.timestamp_ms != parsed.block.timestamp_ms
        or evidence.finality_attestation_sha256 != hashlib.sha256(finality_bytes).hexdigest()
        or evidence.runtime.metadata_sha256 != live_pin.metadata_sha256
        or evidence.runtime.spec_version != live_pin.runtime_spec_version
        or evidence.runtime.transaction_version != live_pin.transaction_version
        or evidence.runtime.state_version != live_pin.state_version
    ):
        raise ShadowReleaseError("release_observation_manifest_mismatch")
    capture_age_ms = manifest.release_observation_observed_at_ms - parsed.block.timestamp_ms
    if capture_age_ms < 0:
        raise ShadowReleaseError("release_observation_from_future")
    if capture_age_ms > manifest.maximum_finalized_head_age_ms:
        raise ShadowReleaseError("release_observation_expired")
    if now_ms is not None:
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms <= 0:
            raise ValueError("now_ms must be a positive integer")
        current_age_ms = now_ms - parsed.block.timestamp_ms
        if current_age_ms < 0:
            raise ShadowReleaseError("release_observation_from_future")
        if current_age_ms > manifest.maximum_finalized_head_age_ms:
            raise ShadowReleaseError("release_observation_expired")


def _installed_release_paths(root: Path) -> set[str]:
    paths: set[str] = set()
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            path = directory_path / name
            try:
                status = path.lstat()
            except OSError as error:
                raise ShadowReleaseError("release_artifact_tree_unsafe") from error
            if (
                path.is_symlink()
                or not stat.S_ISDIR(status.st_mode)
                or status.st_uid != os.getuid()
                or stat.S_IMODE(status.st_mode) & 0o022
            ):
                raise ShadowReleaseError("release_artifact_tree_unsafe")
        for name in filenames:
            path = directory_path / name
            if path.is_symlink() or not path.is_file():
                raise ShadowReleaseError("release_artifact_tree_unsafe")
            paths.add(path.relative_to(root).as_posix())
    return paths


def _read_installed_release_file(
    root: Path,
    relative: str,
    *,
    maximum_bytes: int,
) -> bytes:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ShadowReleaseError("release_artifact_path_invalid")
    target = root / path
    current = root
    for part in path.parts[:-1]:
        current /= part
        try:
            status = current.lstat()
        except OSError as error:
            raise ShadowReleaseError("release_artifact_parent_unavailable") from error
        if current.is_symlink() or not stat.S_ISDIR(status.st_mode):
            raise ShadowReleaseError("release_artifact_parent_unsafe")
    return _read_owned_file(
        target,
        label="installed_release_artifact",
        maximum_bytes=maximum_bytes,
        executable=False,
        private=False,
    )


def materialize_private_operator_configs(
    release_dir: str | Path,
    local_bindings: OperatorMaterializationBindings,
    emit_dir: str | Path,
    *,
    expected_authority_hotkey: str,
) -> None:
    """Resolve signed public templates against operator-local private bindings."""

    release_root = _absolute_normal_path(release_dir, "release directory")
    destination = _absolute_normal_path(emit_dir, "materialized operator directory")
    if not isinstance(local_bindings, OperatorMaterializationBindings):
        raise TypeError("local_bindings must be OperatorMaterializationBindings")
    manifest = verify_shadow_release_directory(
        release_root,
        expected_authority_hotkey=expected_authority_hotkey,
    )
    if destination.exists():
        raise ShadowReleaseError("materialized_operator_directory_exists")
    protected_roots = (
        release_root,
        Path(local_bindings.state_root),
        Path(local_bindings.wallet_path),
        Path(local_bindings.mirror_request_headers_path),
    )
    if any(
        destination == root or destination in root.parents or root in destination.parents
        for root in protected_roots
    ):
        raise ShadowReleaseError("materialized_operator_directory_overlaps_input")

    validator_suffix = ".validator-template.json"
    operator_suffix = ".operator-template.json"
    prefixes = {
        f"operator-templates/{account_id32(hotkey).hex()}" for hotkey in manifest.validator_hotkeys
    }
    validator_paths = {prefix: prefix + validator_suffix for prefix in prefixes}
    operator_paths = {prefix: prefix + operator_suffix for prefix in prefixes}

    prefix = f"operator-templates/{account_id32(local_bindings.validator_hotkey).hex()}"
    if prefix not in validator_paths or prefix not in operator_paths:
        raise ShadowReleaseError("operator_template_for_hotkey_missing")
    validator_bytes = _read_installed_release_file(
        release_root,
        validator_paths[prefix],
        maximum_bytes=2 * 1024 * 1024,
    )
    operator_bytes = _read_installed_release_file(
        release_root,
        operator_paths[prefix],
        maximum_bytes=2 * 1024 * 1024,
    )
    try:
        validator_template = ReleaseRelativeValidatorConfig.model_validate_json(validator_bytes)
        operator_template = ReleaseRelativeOperatorConfig.model_validate_json(operator_bytes)
    except Exception as error:
        raise ShadowReleaseError("private_operator_template_invalid") from error
    if (
        canonical_json_bytes(validator_template) != validator_bytes
        or canonical_json_bytes(operator_template) != operator_bytes
    ):
        raise ShadowReleaseError("private_operator_template_noncanonical")
    expected_account = account_id32(local_bindings.validator_hotkey)
    if (
        account_id32(validator_template.validator_hotkey) != expected_account
        or account_id32(operator_template.validator_hotkey) != expected_account
    ):
        raise ShadowReleaseError("private_operator_template_hotkey_mismatch")

    validator_values = validator_template.model_dump(mode="json", by_alias=True)
    validator_values.update(
        {
            "schema": "umi-validator-live-config/1",
            "conformance_release_root": str(release_root),
            "state_root": local_bindings.state_root,
            "policy_path": str(release_root / validator_template.policy_path),
            "storage_proof_verifier_binary": str(
                release_root / validator_template.storage_proof_verifier_binary
            ),
            "finality_verifier_binary": str(
                release_root / validator_template.finality_verifier_binary
            ),
            "finality_chain_spec_path": str(
                release_root / validator_template.finality_chain_spec_path
            ),
        }
    )
    operator_values = operator_template.model_dump(mode="json", by_alias=True)
    operator_values.update(
        {
            "schema": "umi-validator-live-operator-config/1",
            "wallet_name": local_bindings.wallet_name,
            "wallet_hotkey_name": local_bindings.wallet_hotkey_name,
            "wallet_path": local_bindings.wallet_path,
            "mirror_request_headers_path": local_bindings.mirror_request_headers_path,
            "validator_capacity_set_path": str(
                release_root / operator_template.validator_capacity_set_path
            ),
            "mirror_discovery_rule_path": str(
                release_root / operator_template.mirror_discovery_rule_path
            ),
        }
    )
    operator_values.pop("validator_hotkey")
    try:
        live_config = LiveValidatorConfig.model_validate(validator_values)
        operator_config = LiveValidatorOperatorConfig.model_validate(operator_values)
        policy = load_live_policy(live_config)
        validate_live_startup(live_config, policy)
        VerifiedValidatorCapacitySet(
            policy,
            _read_file(
                Path(operator_config.validator_capacity_set_path),
                label="materialized_validator_capacity_set",
            ),
        )
        mirror_bytes = _read_file(
            Path(operator_config.mirror_discovery_rule_path),
            label="materialized_mirror_discovery_rule",
        )
        mirror_rule = MirrorDiscoveryRule.model_validate_json(mirror_bytes)
        if canonical_json_bytes(mirror_rule) != mirror_bytes:
            raise ShadowReleaseError("materialized_mirror_discovery_rule_noncanonical")
    except ShadowReleaseError:
        raise
    except Exception as error:
        raise ShadowReleaseError("materialized_operator_config_invalid") from error
    output = {
        f"{prefix}.validator.json": canonical_json_bytes(live_config),
        f"{prefix}.operator.json": canonical_json_bytes(operator_config),
    }

    parent = destination.parent
    if not parent.exists() or parent.is_symlink() or not parent.is_dir():
        raise ShadowReleaseError("materialized_operator_parent_invalid")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    try:
        temporary.chmod(0o700)
        for relative, payload in output.items():
            target = temporary / PurePosixPath(relative)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.parent.chmod(0o700)
            target.write_bytes(payload)
            target.chmod(0o600)
        os.replace(temporary, destination)
    except Exception as error:
        shutil.rmtree(temporary, ignore_errors=True)
        if isinstance(error, ShadowReleaseError):
            raise
        raise ShadowReleaseError("materialized_operator_emit_failed") from error


def emit_release_authority_request(
    prepared: PreparedShadowRelease,
    output_path: str | Path,
) -> ReleaseAuthorityRequest:
    """Write one static-intent request for a signer outside this process."""

    request = release_authority_request(prepared)
    destination = _absolute_normal_path(output_path, "release authority request")
    if destination.exists():
        raise ShadowReleaseError("release_authority_request_exists")
    parent = destination.parent
    if not parent.exists() or parent.is_symlink() or not parent.is_dir():
        raise ShadowReleaseError("release_authority_request_parent_invalid")
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.tmp-",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        payload = canonical_json_bytes(request)
        with os.fdopen(temporary_descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o444)
        os.replace(temporary, destination)
    except Exception as error:
        with suppress(OSError):
            os.close(temporary_descriptor)
        temporary.unlink(missing_ok=True)
        raise ShadowReleaseError("release_authority_request_emit_failed") from error
    return request


def emit_capacity_signing_requests(
    prepared: PreparedShadowRelease,
    emit_dir: str | Path,
    *,
    live_capture: LiveReleaseObservationCapture,
) -> tuple[CapacitySigningRequest, ...]:
    """Emit proof-backed baseline evidence and exact external signing requests."""

    if not isinstance(prepared, PreparedShadowRelease):
        raise TypeError("prepared must be PreparedShadowRelease")
    _validate_authoritative_capture(prepared, live_capture)
    destination = _absolute_normal_path(emit_dir, "capacity signing directory")
    baselined_artifacts = prepared.descriptor.artifacts.model_copy(
        update={
            "finality_attestation": str(
                destination / "release-observation" / "finality-attestation.json"
            ),
            "release_observation_chain_evidence": str(
                destination / "release-observation" / "chain-evidence.json"
            ),
        }
    )
    baselined_capacities = [
        item.model_copy(
            update={
                "issued_block": live_capture.observation.block_number,
                "issued_block_hash": live_capture.observation.block_hash,
                "valid_from_block": prepared.descriptor.activation_block,
                "signature": None,
            }
        )
        for item in prepared.descriptor.publisher_capacities
    ]
    baselined_descriptor = LiveShadowReleaseInput.model_validate(
        prepared.descriptor.model_copy(
            update={
                "artifacts": baselined_artifacts,
                "observation": live_capture.observation,
                "publisher_capacities": baselined_capacities,
                "release_authority": prepared.descriptor.release_authority.model_copy(
                    update={"signature": None}
                ),
            }
        ).model_dump(mode="json", by_alias=True)
    )
    baselined_descriptor_bytes = canonical_json_bytes(baselined_descriptor)
    external = {item.label: (item.sha256, b"") for item in prepared.external_artifacts}
    signing_requests = _capacity_signing_requests(
        baselined_descriptor,
        prepared.policy,
        external,
        issuance_observation=live_capture.observation,
        require_descriptor_issuance=True,
    )
    if destination.exists():
        raise ShadowReleaseError("emit_directory_exists")
    parent = destination.parent
    if not parent.exists() or parent.is_symlink() or not parent.is_dir():
        raise ShadowReleaseError("emit_parent_invalid")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    try:
        temporary.chmod(0o700)
        (temporary / "scoring-policy.json").write_bytes(canonical_json_bytes(prepared.policy))
        (temporary / "release-input.baselined.json").write_bytes(baselined_descriptor_bytes)
        observation_root = temporary / "release-observation"
        observation_root.mkdir(mode=0o700)
        (observation_root / "finality-attestation.json").write_bytes(
            live_capture.finality_attestation
        )
        (observation_root / "chain-evidence.json").write_bytes(live_capture.chain_evidence)
        (temporary / "release-baseline-patch.json").write_bytes(
            canonical_json_bytes(
                {
                    "artifact_replacements": {
                        "finality_attestation": baselined_artifacts.finality_attestation,
                        "release_observation_chain_evidence": (
                            baselined_artifacts.release_observation_chain_evidence
                        ),
                    },
                    "baselined_release_input": "release-input.baselined.json",
                    "baselined_release_input_sha256": hashlib.sha256(
                        baselined_descriptor_bytes
                    ).hexdigest(),
                    "observation": live_capture.observation.model_dump(mode="json", by_alias=True),
                    "publisher_capacity_replacements": [
                        {
                            "control_group_id": request.control_group_id,
                            "issued_block": live_capture.observation.block_number,
                            "issued_block_hash": live_capture.observation.block_hash,
                            "signature": None,
                            "valid_from_block": prepared.descriptor.activation_block,
                        }
                        for request in signing_requests
                    ],
                    "schema": RELEASE_BASELINE_PATCH_SCHEMA,
                }
            )
        )
        request_root = temporary / "publisher-capacity-signing"
        request_root.mkdir(mode=0o700)
        for request in signing_requests:
            (request_root / f"{request.control_group_id}.json").write_bytes(
                canonical_json_bytes(request)
            )
        for path in temporary.rglob("*"):
            if path.is_file():
                path.chmod(0o600)
            elif path.is_dir():
                path.chmod(0o700)
        os.replace(temporary, destination)
    except Exception as error:
        shutil.rmtree(temporary, ignore_errors=True)
        raise ShadowReleaseError("capacity_signing_emit_failed") from error
    return signing_requests


def _operator_artifacts(
    descriptor: LiveShadowReleaseInput,
    policy_hash: str,
    external: Sequence[ReleaseArtifactDigest],
    *,
    umi_git_revision: str,
    umi_source_tree_sha256: str,
) -> dict[str, bytes]:
    external_by_label = {item.label: item for item in external}

    def packaged(label: str) -> str:
        try:
            return external_by_label[label].relative_path
        except KeyError as error:
            raise ShadowReleaseError(f"operator_packaged_artifact_missing:{label}") from error

    files: dict[str, bytes] = {}
    for operator in descriptor.operators:
        account_hex = account_id32(operator.validator_hotkey).hex()
        live_config = ReleaseRelativeValidatorConfig(
            schema=RELEASE_RELATIVE_VALIDATOR_CONFIG_SCHEMA,
            protocol=PROTOCOL_VERSION,
            mode=LIVE_SHADOW_MODE,
            translation_weights_active=False,
            policy_path="scoring-policy.json",
            scoring_policy_sha256=policy_hash,
            validator_hotkey=operator.validator_hotkey,
            target_triple=descriptor.target_triple,
            storage_proof_verifier_binary=packaged("storage_proof_verifier_binary"),
            finality_verifier_binary=packaged("finality_verifier_binary"),
            finality_chain_spec_path=packaged("finality_chain_spec"),
            initial_minimum_finalized_block=descriptor.activation_block - 1,
            signature_scheme=operator.signature_scheme,
            umi_revision=(
                "git:" + umi_git_revision + ";source-tree-sha256:" + umi_source_tree_sha256
            ),
            maximum_transport_concurrency=operator.maximum_transport_concurrency,
            transport_timeout_seconds=operator.transport_timeout_seconds,
            stage_port_timeout_seconds=operator.stage_port_timeout_seconds,
            maximum_anchor_advances=operator.maximum_anchor_advances,
            poll_seconds=operator.poll_seconds,
        )
        operator_config = ReleaseRelativeOperatorConfig(
            schema=RELEASE_RELATIVE_OPERATOR_CONFIG_SCHEMA,
            protocol=PROTOCOL_VERSION,
            mode=LIVE_SHADOW_MODE,
            network="finney",
            validator_hotkey=operator.validator_hotkey,
            validator_capacity_set_path=packaged("validator_capacity_set"),
            mirror_discovery_rule_path=packaged("mirror_discovery_rule"),
        )
        files[f"operator-templates/{account_hex}.validator-template.json"] = canonical_json_bytes(
            live_config
        )
        files[f"operator-templates/{account_hex}.operator-template.json"] = canonical_json_bytes(
            operator_config
        )
    for item in descriptor.miner_finality_targets:
        target = item.target_triple
        miner_config = ReleaseRelativeMinerConfig(
            schema=RELEASE_RELATIVE_MINER_CONFIG_SCHEMA,
            protocol=PROTOCOL_VERSION,
            role="miner",
            translation_weights_active=False,
            target_triple=target,
            policy_path="scoring-policy.json",
            scoring_policy_sha256=policy_hash,
            python_wheel=packaged("python_wheel"),
            python_lockfile=packaged("python_lockfile"),
            pyproject=packaged("pyproject"),
            mirror_discovery_rule_path=packaged("mirror_discovery_rule"),
            finality_verifier_binary=packaged(_miner_finality_label("binary", target)),
            finality_chain_spec_path=packaged("finality_chain_spec"),
            finality_build_report=packaged(_miner_finality_label("report", target)),
            finality_license_closure=packaged(_miner_finality_label("license", target)),
            initial_minimum_finalized_block=descriptor.activation_block - 1,
            minimum_validator_transport_timeout_seconds=min(
                operator.transport_timeout_seconds for operator in descriptor.operators
            ),
            minimum_validator_transport_concurrency=min(
                operator.maximum_transport_concurrency for operator in descriptor.operators
            ),
            umi_git_revision=umi_git_revision,
            umi_source_tree_sha256=umi_source_tree_sha256,
            umi_revision=(
                "git:" + umi_git_revision + ";source-tree-sha256:" + umi_source_tree_sha256
            ),
            validator_runtime_supported=False,
        )
        files[f"miner-templates/{target}.json"] = canonical_json_bytes(miner_config)
    return files


def _capacity_signing_requests(
    descriptor: LiveShadowReleaseInput,
    policy: ScoringPolicy,
    external: Mapping[str, tuple[str, bytes]],
    *,
    issuance_observation: FinalizedReleaseObservation | None = None,
    require_descriptor_issuance: bool = True,
) -> tuple[CapacitySigningRequest, ...]:
    observation = issuance_observation or descriptor.observation
    group_by_id = {item.control_group_id: item for item in policy.control_group_registry}
    publishers_by_group: dict[str, list[str]] = {key: [] for key in group_by_id}
    for publisher in policy.publisher_registry:
        publishers_by_group[publisher.control_group_id].append(publisher.publisher_hotkey)
    window_seconds = policy.clock.window_stride_blocks * policy.clock.target_block_interval_seconds
    runway_seconds = policy.limits.challenge_supply_runway_days * 86_400
    scheduled_windows = (runway_seconds + window_seconds - 1) // window_seconds
    canaries = canary_count(
        policy.limits.emission_bearing_clips_per_batch,
        policy.thresholds.canary_fraction.fraction,
    )
    requests: list[CapacitySigningRequest] = []
    for item in descriptor.publisher_capacities:
        if item.valid_from_block != descriptor.activation_block:
            raise ShadowReleaseError("publisher_capacity_release_observation_mismatch")
        if require_descriptor_issuance and (
            item.issued_block != observation.block_number
            or item.issued_block_hash != observation.block_hash
        ):
            raise ShadowReleaseError("publisher_capacity_release_observation_mismatch")
        group = group_by_id[item.control_group_id]
        statement = PublisherCapacityStatement(
            schema="umi-publisher-capacity/1",
            control_group_id=item.control_group_id,
            administrator=group.administrator,
            publisher_hotkeys=sorted(publishers_by_group[item.control_group_id], key=account_id32),
            scoring_policy_hash=scoring_policy_hash(policy),
            activation_equivalence_digest=activation_equivalence_digest(policy),
            issued_block=observation.block_number,
            issued_block_hash=observation.block_hash,
            valid_from_block=item.valid_from_block,
            valid_through_block=item.valid_through_block,
            cadence=CapacityCadence(
                window_stride_blocks=policy.clock.window_stride_blocks,
                target_block_interval_seconds=policy.clock.target_block_interval_seconds,
                scheduled_windows=scheduled_windows,
            ),
            per_window_capacity=PerWindowCapacity(
                candidate_batches=policy.limits.max_candidate_batches_per_group,
                emission_bearing_clips=policy.limits.emission_bearing_clips_per_batch,
                canary_clips=canaries,
                delivered_clips=policy.limits.emission_bearing_clips_per_batch + canaries,
                maximum_retired_script_groups=(
                    policy.limits.emission_bearing_clips_per_batch + 2 * canaries
                ),
            ),
            runway_totals=RunwayTotals(
                candidate_batches=policy.limits.max_candidate_batches_per_group * scheduled_windows,
                delivered_clips=(policy.limits.emission_bearing_clips_per_batch + canaries)
                * scheduled_windows,
                maximum_retired_script_groups=(
                    policy.limits.emission_bearing_clips_per_batch + 2 * canaries
                )
                * scheduled_windows,
            ),
            one_group_loss=OneGroupLoss(
                minimum_remaining_groups=2,
                this_group_continues_at_declared_capacity=True,
            ),
            control_disclosure_sha256=external[f"control_disclosure.{item.control_group_id}"][0],
        )
        try:
            validate_publisher_capacity_statement(statement, policy)
        except Exception as error:
            raise ShadowReleaseError("publisher_capacity_statement_invalid") from error
        requests.append(
            CapacitySigningRequest(
                schema=CAPACITY_SIGNING_REQUEST_SCHEMA,
                control_group_id=item.control_group_id,
                administrator=group.administrator,
                statement=statement,
                digest=publisher_capacity_digest(statement).hex(),
            )
        )
    requests.sort(key=lambda request: bytes.fromhex(request.control_group_id))
    return tuple(requests)


def _verify_replay_finality_attestation(
    descriptor: LiveShadowReleaseInput,
    *,
    finality_pin: FinalityVerifierPin,
    attestation_bytes: bytes,
) -> None:
    """Parse the supplied baseline as replay data without granting it authority."""

    replay = descriptor.finality.replay
    try:
        binary_digest = finality_pin.release_sha256_by_target[descriptor.target_triple]
        observer = GrandpaFinalityObserver(
            binary_path=descriptor.artifacts.finality_verifier_binary,
            expected_binary_sha256=binary_digest,
            chain_spec_path=descriptor.artifacts.finality_chain_spec,
            expected_chain_spec_sha256=finality_pin.chain_spec_sha256,
            expected_genesis_hash=f"0x{finality_pin.expected_genesis_hash}",
            bootstrap_block_number=finality_pin.bootstrap_block_number,
            bootstrap_block_hash=f"0x{finality_pin.bootstrap_block_hash}",
        )
        attestation = observer.validate_attestation(
            attestation_bytes,
            minimum_finalized_block=descriptor.observation.block_number,
            maximum_records=replay.maximum_records,
            startup_timeout_seconds=replay.startup_timeout_seconds,
            expected_sequence=0,
            previous_hash=None,
            previous_digest="0" * 64,
            previous_number=None,
            previous_timestamp_ms=None,
        )
    except Exception as error:
        raise ShadowReleaseError("finality_attestation_invalid") from error
    observation = descriptor.observation
    if (
        attestation.block.number != observation.block_number
        or attestation.block.hash != observation.block_hash
        or attestation.block.parent_hash != observation.parent_hash
        or attestation.block.state_root != observation.state_root
        or attestation.block.timestamp_ms != observation.timestamp_ms
    ):
        raise ShadowReleaseError("finality_attestation_observation_mismatch")


def _validate_capacity_cost_classes(
    evidence: ValidatorCapacitySetEvidence,
    schedule: ValidatorCostSchedule,
    *,
    window_milliseconds: int,
    maximum_capture_ms: int,
) -> None:
    classes = {(item.hardware_class, item.region_class): item for item in schedule.classes}
    for signed in evidence.statements:
        statement = signed.statement
        selected = classes.get((statement.hardware_class, statement.region_class))
        if selected is None:
            raise ShadowReleaseError("validator_capacity_cost_class_missing")
        if any(item.captured_at_ms > maximum_capture_ms for item in selected.list_prices):
            raise ShadowReleaseError("validator_cost_observation_from_future")
        capacities = statement.capacities
        if capacities.cpu_core_milliseconds_per_window > (
            selected.cpu_core_count * window_milliseconds
        ):
            raise ShadowReleaseError("validator_cpu_capacity_exceeds_cost_class")
        if capacities.accelerator_milliseconds_per_window > (
            selected.accelerator_count * window_milliseconds
        ):
            raise ShadowReleaseError("validator_accelerator_capacity_exceeds_cost_class")
        if capacities.peak_host_memory_bytes > selected.host_memory_bytes:
            raise ShadowReleaseError("validator_host_memory_exceeds_cost_class")
        if capacities.peak_accelerator_memory_bytes > selected.accelerator_memory_bytes:
            raise ShadowReleaseError("validator_accelerator_memory_exceeds_cost_class")
        if capacities.retained_storage_bytes != selected.provisioned_storage_bytes:
            raise ShadowReleaseError("validator_storage_differs_from_cost_class")


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


def _strict_metadata_headers(
    payload: bytes,
    *,
    label: str,
    body_required: bool,
) -> tuple[dict[str, list[str]], bytes]:
    if not payload or b"\r" in payload or b"\x00" in payload:
        raise ShadowReleaseError(f"{label}_invalid")
    if body_required:
        header_bytes, separator, body = payload.partition(b"\n\n")
        if not separator:
            raise ShadowReleaseError(f"{label}_invalid")
    else:
        header_bytes = payload[:-1] if payload.endswith(b"\n") else payload
        body = b""
        if b"\n\n" in header_bytes:
            raise ShadowReleaseError(f"{label}_invalid")

    headers: dict[str, list[str]] = {}
    for line in header_bytes.split(b"\n"):
        if not line or line[:1] in {b" ", b"\t"} or b": " not in line:
            raise ShadowReleaseError(f"{label}_invalid")
        raw_name, raw_value = line.split(b": ", 1)
        try:
            name = raw_name.decode("ascii")
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ShadowReleaseError(f"{label}_invalid") from error
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name):
            raise ShadowReleaseError(f"{label}_invalid")
        headers.setdefault(name, []).append(value)
    return headers, body


def _single_metadata_header(headers: Mapping[str, list[str]], name: str, *, label: str) -> str:
    values = headers.get(name, [])
    if len(values) != 1:
        raise ShadowReleaseError(f"{label}_invalid")
    return values[0]


def _wheel_project_metadata(pyproject_bytes: bytes) -> Mapping[str, Any]:
    try:
        parsed = tomllib.loads(pyproject_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ShadowReleaseError("python_project_metadata_invalid") from error
    build_system = parsed.get("build-system")
    project = parsed.get("project")
    tool = parsed.get("tool")
    hatch = tool.get("hatch") if isinstance(tool, dict) else None
    build = hatch.get("build") if isinstance(hatch, dict) else None
    targets = build.get("targets") if isinstance(build, dict) else None
    wheel_config = targets.get("wheel") if isinstance(targets, dict) else None
    if (
        not isinstance(build_system, dict)
        or build_system.get("build-backend") != "hatchling.build"
        or build_system.get("requires") != ["hatchling==1.32.0"]
        or not isinstance(project, dict)
        or not isinstance(wheel_config, dict)
        or wheel_config.get("packages") != ["src/umi"]
    ):
        raise ShadowReleaseError("python_project_build_config_invalid")
    return project


def _project_string(project: Mapping[str, Any], name: str) -> str:
    value = project.get(name)
    if not isinstance(value, str) or not value:
        raise ShadowReleaseError("python_project_metadata_invalid")
    return value


def _project_string_list(project: Mapping[str, Any], name: str) -> list[str]:
    value = project.get(name)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ShadowReleaseError("python_project_metadata_invalid")
    return value


def _parsed_requirement(value: str) -> Requirement:
    try:
        return Requirement(value)
    except InvalidRequirement as error:
        raise ShadowReleaseError("python_project_requirement_invalid") from error


def _expected_project_requirements(project: Mapping[str, Any]) -> Counter[Requirement]:
    expected: Counter[Requirement] = Counter()
    for raw_requirement in _project_string_list(project, "dependencies"):
        requirement = _parsed_requirement(raw_requirement)
        if requirement.url is not None:
            raise ShadowReleaseError("python_project_requirement_unsupported")
        expected[requirement] += 1

    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or not optional:
        raise ShadowReleaseError("python_project_metadata_invalid")
    for extra, requirements in optional.items():
        if (
            not isinstance(extra, str)
            or canonicalize_name(extra) != extra
            or not isinstance(requirements, list)
            or not requirements
        ):
            raise ShadowReleaseError("python_project_metadata_invalid")
        for raw_requirement in requirements:
            if not isinstance(raw_requirement, str) or not raw_requirement:
                raise ShadowReleaseError("python_project_metadata_invalid")
            requirement = _parsed_requirement(raw_requirement)
            if requirement.marker is not None or requirement.url is not None:
                raise ShadowReleaseError("python_project_requirement_unsupported")
            expected[_parsed_requirement(f'{raw_requirement}; extra == "{extra}"')] += 1
    return expected


def _verify_core_metadata(
    payload: bytes,
    *,
    project: Mapping[str, Any],
    readme_bytes: bytes,
) -> None:
    headers, body = _strict_metadata_headers(
        payload,
        label="python_wheel_metadata",
        body_required=True,
    )
    allowed_headers = {
        "Description-Content-Type",
        "License-Expression",
        "License-File",
        "Metadata-Version",
        "Name",
        "Provides-Extra",
        "Requires-Dist",
        "Requires-Python",
        "Summary",
        "Version",
    }
    if set(headers) != allowed_headers:
        raise ShadowReleaseError("python_wheel_metadata_fields_mismatch")
    expected_singles = {
        "Description-Content-Type": "text/markdown",
        "License-Expression": _project_string(project, "license"),
        "Metadata-Version": "2.5",
        "Name": _project_string(project, "name"),
        "Summary": _project_string(project, "description"),
        "Version": _project_string(project, "version"),
    }
    for name, expected in expected_singles.items():
        if _single_metadata_header(headers, name, label="python_wheel_metadata") != expected:
            raise ShadowReleaseError("python_wheel_metadata_mismatch")

    if project.get("readme") != "README.md" or project.get("license-files") != ["LICENSE"]:
        raise ShadowReleaseError("python_project_metadata_invalid")
    if headers["License-File"] != ["LICENSE"] or body != readme_bytes:
        raise ShadowReleaseError("python_wheel_metadata_mismatch")
    try:
        actual_python = SpecifierSet(
            _single_metadata_header(headers, "Requires-Python", label="python_wheel_metadata")
        )
        expected_python = SpecifierSet(_project_string(project, "requires-python"))
    except InvalidSpecifier as error:
        raise ShadowReleaseError("python_wheel_metadata_invalid") from error
    if actual_python != expected_python:
        raise ShadowReleaseError("python_wheel_metadata_mismatch")

    actual_requirements: Counter[Requirement] = Counter()
    for value in headers["Requires-Dist"]:
        actual_requirements[_parsed_requirement(value)] += 1
    if actual_requirements != _expected_project_requirements(project):
        raise ShadowReleaseError("python_wheel_requirements_mismatch")

    optional = project["optional-dependencies"]
    expected_extras = Counter(canonicalize_name(value) for value in optional)
    actual_extras = Counter(canonicalize_name(value) for value in headers["Provides-Extra"])
    if actual_extras != expected_extras:
        raise ShadowReleaseError("python_wheel_extras_mismatch")


def _verify_wheel_metadata(payload: bytes) -> None:
    headers, body = _strict_metadata_headers(
        payload,
        label="python_wheel_wheel_metadata",
        body_required=False,
    )
    if body or set(headers) != {"Generator", "Root-Is-Purelib", "Tag", "Wheel-Version"}:
        raise ShadowReleaseError("python_wheel_wheel_metadata_mismatch")
    expected = {
        "Generator": "hatchling 1.32.0",
        "Root-Is-Purelib": "true",
        "Tag": "py3-none-any",
        "Wheel-Version": "1.0",
    }
    for name, value in expected.items():
        if (
            _single_metadata_header(
                headers,
                name,
                label="python_wheel_wheel_metadata",
            )
            != value
        ):
            raise ShadowReleaseError("python_wheel_wheel_metadata_mismatch")


def _expected_console_scripts(project: Mapping[str, Any]) -> bytes:
    scripts = project.get("scripts")
    if not isinstance(scripts, dict) or not scripts:
        raise ShadowReleaseError("python_project_scripts_invalid")
    lines = ["[console_scripts]"]
    for name, target in sorted(scripts.items()):
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name)
            or not isinstance(target, str)
            or not re.fullmatch(
                r"umi(?:\.[A-Za-z_][A-Za-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*",
                target,
            )
        ):
            raise ShadowReleaseError("python_project_scripts_invalid")
        lines.append(f"{name} = {target}")
    return ("\n".join(lines) + "\n").encode()


def _expected_record(
    ordered_names: Sequence[str],
    members: Mapping[str, bytes],
    *,
    record_name: str,
) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in ordered_names:
        if name == record_name:
            writer.writerow((name, "", ""))
            continue
        payload = members[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        writer.writerow((name, f"sha256={digest}", str(len(payload))))
    return output.getvalue().encode("utf-8")


def _verify_wheel_matches_source(
    wheel_path: Path,
    wheel_bytes: bytes,
    source_root: Path,
    *,
    pyproject_bytes: bytes,
    readme_bytes: bytes,
    license_bytes: bytes,
) -> str:
    project = _wheel_project_metadata(pyproject_bytes)
    project_name = _project_string(project, "name")
    version = _project_string(project, "version")
    wheel_distribution = canonicalize_name(project_name).replace("-", "_")
    if not re.fullmatch(r"[a-z0-9_]+", wheel_distribution) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._+!-]*", version
    ):
        raise ShadowReleaseError("python_project_metadata_invalid")
    expected_filename = f"{wheel_distribution}-{version}-py3-none-any.whl"
    if wheel_path.name != expected_filename:
        raise ShadowReleaseError("python_wheel_filename_mismatch")

    if not source_root.is_dir() or source_root.is_symlink():
        raise ShadowReleaseError("python_source_tree_unsafe")
    source_paths = sorted(
        source_root.rglob("*.py"),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    if any(path.is_symlink() or not path.is_file() for path in source_paths):
        raise ShadowReleaseError("python_source_tree_unsafe")
    if not source_paths:
        raise ShadowReleaseError("python_source_tree_empty")
    package_members = {
        "umi/" + path.relative_to(source_root).as_posix(): path.read_bytes()
        for path in source_paths
    }

    dist_info = f"{wheel_distribution}-{version}.dist-info"
    metadata_name = f"{dist_info}/METADATA"
    wheel_metadata_name = f"{dist_info}/WHEEL"
    entry_points_name = f"{dist_info}/entry_points.txt"
    license_name = f"{dist_info}/licenses/LICENSE"
    record_name = f"{dist_info}/RECORD"
    expected_order = [
        *sorted(package_members),
        metadata_name,
        wheel_metadata_name,
        entry_points_name,
        license_name,
        record_name,
    ]

    if (
        len(wheel_bytes) < 22
        or not wheel_bytes.startswith(b"PK\x03\x04")
        or wheel_bytes[-22:-18] != b"PK\x05\x06"
    ):
        raise ShadowReleaseError("python_wheel_container_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            if archive.comment:
                raise ShadowReleaseError("python_wheel_archive_comment")
            infos = archive.infolist()
            if not infos or sum(item.file_size for item in infos) > MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise ShadowReleaseError("python_wheel_size_limit")
            if [info.filename for info in infos] != expected_order:
                raise ShadowReleaseError("python_wheel_archive_layout_mismatch")
            archive_names: set[str] = set()
            members: dict[str, bytes] = {}
            for info in infos:
                name = PurePosixPath(info.filename)
                if (
                    info.is_dir()
                    or name.is_absolute()
                    or ".." in name.parts
                    or "\\" in info.filename
                    or info.filename in archive_names
                    or info.flag_bits & 0x1
                    or info.comment
                    or info.extra
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                ):
                    raise ShadowReleaseError("python_wheel_archive_member_invalid")
                archive_names.add(info.filename)
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise ShadowReleaseError("python_wheel_symlink")
                members[info.filename] = archive.read(info)
    except ShadowReleaseError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ShadowReleaseError("python_wheel_invalid") from error

    if any(members[name] != payload for name, payload in package_members.items()):
        raise ShadowReleaseError("python_wheel_source_mismatch")
    if members[license_name] != license_bytes:
        raise ShadowReleaseError("python_wheel_license_mismatch")
    _verify_core_metadata(members[metadata_name], project=project, readme_bytes=readme_bytes)
    _verify_wheel_metadata(members[wheel_metadata_name])
    if members[entry_points_name] != _expected_console_scripts(project):
        raise ShadowReleaseError("python_wheel_entry_points_mismatch")
    if members[record_name] != _expected_record(
        expected_order,
        members,
        record_name=record_name,
    ):
        raise ShadowReleaseError("python_wheel_record_mismatch")
    return _umi_source_tree_sha256_from_members({name: members[name] for name in package_members})


def _umi_source_tree_sha256_from_members(package_members: Mapping[str, bytes]) -> str:
    """Hash exact wheel-resident UMI modules with the runtime source-tree domain."""

    names = sorted(package_members)
    if not names:
        raise ShadowReleaseError("python_wheel_source_tree_empty")
    digest = hashlib.sha256(b"umi-source-tree-v1\0")
    for name in names:
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or len(path.parts) < 2
            or path.parts[0] != "umi"
            or path.suffix != ".py"
            or ".." in path.parts
            or "." in path.parts
            or path.as_posix() != name
        ):
            raise ShadowReleaseError("python_wheel_source_member_invalid")
        relative = PurePosixPath(*path.parts[1:]).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(hashlib.sha256(package_members[name]).digest())
    return digest.hexdigest()


def _umi_source_tree_sha256_from_wheel(wheel_bytes: bytes) -> str:
    """Recompute the UMI source pin directly from an installed wheel artifact."""

    if len(wheel_bytes) < 22 or not wheel_bytes.startswith(b"PK\x03\x04"):
        raise ShadowReleaseError("python_wheel_container_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            if archive.comment:
                raise ShadowReleaseError("python_wheel_archive_comment")
            infos = archive.infolist()
            if not infos or sum(item.file_size for item in infos) > MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise ShadowReleaseError("python_wheel_size_limit")
            seen: set[str] = set()
            package_members: dict[str, bytes] = {}
            for info in infos:
                path = PurePosixPath(info.filename)
                if (
                    info.is_dir()
                    or path.is_absolute()
                    or ".." in path.parts
                    or "\\" in info.filename
                    or info.filename in seen
                    or info.flag_bits & 0x1
                    or info.comment
                    or info.extra
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                ):
                    raise ShadowReleaseError("python_wheel_archive_member_invalid")
                seen.add(info.filename)
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise ShadowReleaseError("python_wheel_symlink")
                if len(path.parts) >= 2 and path.parts[0] == "umi" and path.suffix == ".py":
                    package_members[info.filename] = archive.read(info)
    except ShadowReleaseError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ShadowReleaseError("python_wheel_invalid") from error
    return _umi_source_tree_sha256_from_members(package_members)


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


def _nonplaceholder_sha256(payload: bytes, *, label: str) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    _reject_digest(digest, label)
    return digest


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


def _require_distinct_digests(artifacts: Mapping[str, tuple[str, bytes]]) -> None:
    by_digest: dict[str, str] = {}
    for label, (digest, _payload) in sorted(artifacts.items()):
        previous = by_digest.get(digest)
        if previous is not None:
            raise ShadowReleaseError(f"repeated_artifact_digest:{previous}:{label}")
        by_digest[digest] = label


def _assert_no_private_material(files: Mapping[str, bytes]) -> None:
    def inspect_value(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if isinstance(key, str) and key.lower() in _FORBIDDEN_OUTPUT_KEYS:
                    raise ShadowReleaseError("private_material_in_output")
                inspect_value(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect_value(nested)

    for relative, payload in files.items():
        if not relative.endswith(".json"):
            continue
        try:
            inspect_value(json.loads(payload))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ShadowReleaseError("generated_artifact_invalid") from error


def build_miner_finality_artifact(
    *,
    repository_root: str | Path,
    binary_path: str | Path,
) -> BuiltMinerFinalityArtifact:
    """Seal and test the native Darwin finality binary used by live miners."""

    if sys.platform != "darwin" or platform.machine().casefold() not in {"arm64", "aarch64"}:
        raise ShadowReleaseError("miner_finality_native_host_required")
    repository = _absolute_normal_path(repository_root, "repository root")
    source_root = repository / "rust" / "grandpa-finality-observer"
    if source_root.resolve(strict=False) != source_root or not source_root.is_dir():
        raise ShadowReleaseError("miner_finality_source_root_invalid")
    umi_git_revision = _verified_clean_repository_revision(repository)
    binary = _read_executable(
        _absolute_normal_path(binary_path, "miner finality binary"),
        label="miner_finality_verifier",
    )
    _validate_darwin_arm64_executable(binary)
    cargo_lock = _read_file(
        source_root / "Cargo.lock",
        label="miner_finality_cargo_lock",
        maximum_bytes=32 * 1024 * 1024,
    )
    fixture = _read_file(
        source_root / "fixtures" / "finality-v1.json",
        label="miner_finality_fixture",
        maximum_bytes=20 * 1024 * 1024,
    )
    source_tree_sha256 = _finality_source_tree_sha256(source_root)
    if (
        source_tree_sha256 != FINALITY_SOURCE_TREE_SHA256
        or hashlib.sha256(cargo_lock).hexdigest() != FINALITY_CARGO_LOCK_SHA256
        or hashlib.sha256(fixture).hexdigest() != FINALITY_FIXTURE_SET_SHA256
    ):
        raise ShadowReleaseError("miner_finality_source_pin_mismatch")
    try:
        with staged_pinned_artifacts(
            (
                PinnedArtifact(
                    name="miner_finality",
                    source=_absolute_normal_path(binary_path, "miner finality binary"),
                    expected_sha256=hashlib.sha256(binary).hexdigest(),
                    maximum_bytes=MAX_RELEASE_FILE_BYTES,
                    executable=True,
                ),
            )
        ) as staged:
            process = subprocess.run(
                [os.fspath(staged["miner_finality"]), "--conformance-self-test"],
                cwd=source_root,
                env={"LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
    except (OSError, subprocess.SubprocessError, PinnedArtifactError) as error:
        raise ShadowReleaseError("miner_finality_self_test_failed") from error
    if process.returncode != 0 or not process.stdout.endswith(b"\n"):
        raise ShadowReleaseError("miner_finality_self_test_failed")
    if process.stdout.count(b"\n") != 1:
        raise ShadowReleaseError("miner_finality_self_test_output_invalid")
    self_test_bytes = process.stdout[:-1]
    self_test = _parse_finality_self_test_output(self_test_bytes, fixture_bytes=fixture)
    try:
        license_closure = build_rust_license_closure(
            source_root=source_root,
            repository_root=repository,
            target_triple=DARWIN_MINER_TARGET,
            binary_name="umi-grandpa-finality-observer",
            expected_root_package="umi-grandpa-finality-observer",
        )
    except RustLicenseClosureError as error:
        raise ShadowReleaseError(error.reason_code) from error
    report = MinerFinalityBuildReport(
        schema=MINER_FINALITY_BUILD_REPORT_SCHEMA,
        role="miner-finality-only",
        target_triple=DARWIN_MINER_TARGET,
        host_operating_system="darwin",
        host_architecture="arm64",
        binary_format="mach-o-64-arm64-executable",
        binary_sha256=hashlib.sha256(binary).hexdigest(),
        binary_size_bytes=len(binary),
        umi_git_revision=umi_git_revision,
        finality_source_revision=FINALITY_SOURCE_REVISION,
        finality_source_tree_sha256=source_tree_sha256,
        finality_cargo_lock_sha256=hashlib.sha256(cargo_lock).hexdigest(),
        finality_fixture_set_sha256=hashlib.sha256(fixture).hexdigest(),
        license_closure_sha256=hashlib.sha256(license_closure).hexdigest(),
        self_test_output_sha256=hashlib.sha256(self_test_bytes).hexdigest(),
        self_test=self_test,
        validator_runtime_supported=False,
        media_runtime_included=False,
    )
    report_bytes = canonical_json_bytes(report)
    _validate_miner_finality_build_report(
        target=DARWIN_MINER_TARGET,
        binary_bytes=binary,
        report_bytes=report_bytes,
        license_closure_bytes=license_closure,
        fixture_bytes=fixture,
        cargo_lock_bytes=cargo_lock,
        source_tree_sha256=source_tree_sha256,
        umi_git_revision=umi_git_revision,
    )
    return BuiltMinerFinalityArtifact(
        report=report,
        binary=binary,
        report_bytes=report_bytes,
        license_closure=license_closure,
    )


def emit_miner_finality_artifact(
    artifact: BuiltMinerFinalityArtifact,
    output_dir: str | Path,
) -> None:
    """Atomically create one immutable directory for release input consumption."""

    if not isinstance(artifact, BuiltMinerFinalityArtifact):
        raise TypeError("artifact must be a BuiltMinerFinalityArtifact")
    destination = _absolute_normal_path(output_dir, "miner finality output directory")
    if destination.exists():
        raise ShadowReleaseError("miner_finality_output_directory_exists")
    parent = destination.parent
    if not parent.exists() or parent.is_symlink() or not parent.is_dir():
        raise ShadowReleaseError("miner_finality_output_parent_invalid")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    try:
        payloads = {
            "umi-grandpa-finality-observer": (artifact.binary, 0o555),
            "miner-finality-build-report.json": (artifact.report_bytes, 0o444),
            "finality-third-party-licenses.zip": (artifact.license_closure, 0o444),
        }
        for name, (payload, mode) in payloads.items():
            target = temporary / name
            target.write_bytes(payload)
            target.chmod(mode)
        temporary.chmod(0o555)
        os.replace(temporary, destination)
    except Exception as error:
        shutil.rmtree(temporary, ignore_errors=True)
        if isinstance(error, ShadowReleaseError):
            raise
        raise ShadowReleaseError("miner_finality_output_emit_failed") from error


def _summary(build: BuiltShadowRelease) -> bytes:
    request = final_manifest_authority_request(build.manifest)
    return canonical_json_bytes(
        {
            "activation_block": build.manifest.activation_block,
            "artifact_count": len(build.files),
            "final_manifest_signing_digest": request.digest,
            "minimum_release_lead_blocks": build.manifest.minimum_release_lead_blocks,
            "ok": True,
            "release_observation_block": build.manifest.release_observation_block,
            "release_observation_block_hash": build.manifest.release_observation_block_hash,
            "scoring_policy_sha256": build.manifest.scoring_policy_sha256,
            "staged": True,
            "translation_weights_active": False,
        }
    )


def _check_summary(prepared: PreparedShadowRelease) -> bytes:
    return canonical_json_bytes(
        {
            "live_observation_collected": False,
            "ok": True,
            "release_authority": False,
            "scoring_policy_sha256": scoring_policy_hash(prepared.policy),
            "translation_weights_active": False,
        }
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build an inactive UMI live-shadow release")
    parser.add_argument("release_input", type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="validate without writes or network")
    action.add_argument(
        "--stage-dir",
        type=Path,
        help="atomically create a fresh full-manifest signing stage",
    )
    action.add_argument(
        "--capacity-signing-dir",
        type=Path,
        help=(
            "collect a live proof-backed baseline and emit a private work tree of exact unsigned "
            "publisher-capacity signing requests"
        ),
    )
    action.add_argument(
        "--release-authority-request",
        type=Path,
        help="write the static release-intent digest for external signing",
    )
    arguments = parser.parse_args(argv)
    try:
        descriptor, encoded = load_release_input(arguments.release_input)
        if arguments.capacity_signing_dir is not None:
            prepared = _prepare_shadow_release(
                descriptor,
                descriptor_bytes=encoded,
                now_ms=None,
                verify_replay_baseline=False,
            )
            live_capture = asyncio.run(collect_live_release_observation(prepared))
            signing_requests = emit_capacity_signing_requests(
                prepared,
                arguments.capacity_signing_dir,
                live_capture=live_capture,
            )
            sys.stdout.buffer.write(
                canonical_json_bytes(
                    {
                        "live_observation_collected": True,
                        "ok": True,
                        "release_observation_block": live_capture.observation.block_number,
                        "release_observation_block_hash": live_capture.observation.block_hash,
                        "scoring_policy_sha256": scoring_policy_hash(prepared.policy),
                        "signing_request_count": len(signing_requests),
                    }
                )
                + b"\n"
            )
            return 0
        prepared = prepare_shadow_release(descriptor, descriptor_bytes=encoded)
        if arguments.release_authority_request is not None:
            request = emit_release_authority_request(
                prepared,
                arguments.release_authority_request,
            )
            sys.stdout.buffer.write(
                canonical_json_bytes(
                    {
                        "authority_hotkey": request.authority_hotkey,
                        "digest": request.digest,
                        "ok": True,
                        "release_authority_request": str(arguments.release_authority_request),
                    }
                )
                + b"\n"
            )
            return 0
        if arguments.check:
            _verified_publisher_capacity_artifacts(prepared)
            _verified_release_authority_attestation(prepared)
            sys.stdout.buffer.write(_check_summary(prepared) + b"\n")
            return 0
        live_capture = asyncio.run(collect_live_release_observation(prepared))
        build = build_shadow_release(
            descriptor,
            live_capture=live_capture,
            descriptor_bytes=encoded,
        )
        if arguments.stage_dir is not None:
            emit_shadow_release_signing_stage(build, arguments.stage_dir)
        sys.stdout.buffer.write(_summary(build) + b"\n")
        return 0
    except (ShadowReleaseError, ValidationError, ValueError, TypeError) as error:
        reason = error.reason_code if isinstance(error, ShadowReleaseError) else "invalid_release"
        sys.stderr.write(reason + "\n")
        return 2


def verify_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an installed UMI shadow release")
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("--expected-authority-hotkey", required=True)
    arguments = parser.parse_args(argv)
    try:
        manifest = verify_shadow_release_directory(
            arguments.release_dir,
            expected_authority_hotkey=arguments.expected_authority_hotkey,
        )
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "authority_hotkey": manifest.release_authority.authority_hotkey,
                    "ok": True,
                    "release_observation_block": manifest.release_observation_block,
                    "scoring_policy_sha256": manifest.scoring_policy_sha256,
                    "translation_weights_active": manifest.translation_weights_active,
                }
            )
            + b"\n"
        )
        return 0
    except (ShadowReleaseError, ValidationError, ValueError, TypeError) as error:
        reason = error.reason_code if isinstance(error, ShadowReleaseError) else "invalid_release"
        sys.stderr.write(reason + "\n")
        return 2


def miner_finality_artifact_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Seal a native Apple Silicon finality binary for a signed UMI release"
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        artifact = build_miner_finality_artifact(
            repository_root=arguments.repository_root,
            binary_path=arguments.binary,
        )
        emit_miner_finality_artifact(artifact, arguments.output_dir)
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "binary_sha256": artifact.report.binary_sha256,
                    "build_report_sha256": hashlib.sha256(artifact.report_bytes).hexdigest(),
                    "license_closure_sha256": hashlib.sha256(artifact.license_closure).hexdigest(),
                    "ok": True,
                    "output_dir": str(arguments.output_dir),
                    "target_triple": artifact.report.target_triple,
                    "validator_runtime_supported": False,
                }
            )
            + b"\n"
        )
        return 0
    except (ShadowReleaseError, ValidationError, ValueError, TypeError) as error:
        reason = error.reason_code if isinstance(error, ShadowReleaseError) else "invalid_release"
        sys.stderr.write(reason + "\n")
        return 2


def resolve_miner_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify and privately materialize one signed UMI native miner target"
    )
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("--expected-authority-hotkey", required=True)
    parser.add_argument("--target-triple", choices=[DARWIN_MINER_TARGET], required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        resolved = verify_miner_release_target(
            arguments.release_dir,
            expected_authority_hotkey=arguments.expected_authority_hotkey,
            target_triple=arguments.target_triple,
            output_dir=arguments.output_dir,
        )
        sys.stdout.buffer.write(canonical_json_bytes(resolved) + b"\n")
        return 0
    except (ShadowReleaseError, ValidationError, ValueError, TypeError) as error:
        reason = error.reason_code if isinstance(error, ShadowReleaseError) else "invalid_release"
        sys.stderr.write(reason + "\n")
        return 2


def finalize_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Finalize a freshly staged UMI shadow release with its authority signature"
    )
    parser.add_argument("stage_dir", type=Path)
    parser.add_argument("--signature-response", type=Path, required=True)
    parser.add_argument("--emit-dir", type=Path, required=True)
    parser.add_argument("--expected-authority-hotkey", required=True)
    arguments = parser.parse_args(argv)
    try:
        response_bytes = _read_file(
            _absolute_normal_path(
                arguments.signature_response,
                "final manifest signature response",
            ),
            label="final_manifest_signature_response",
            maximum_bytes=2 * 1024 * 1024,
        )
        final_authority = FinalManifestAuthorityAttestation.model_validate_json(response_bytes)
        if canonical_json_bytes(final_authority) != response_bytes:
            raise ShadowReleaseError("final_manifest_signature_response_noncanonical")
        manifest = finalize_shadow_release(
            arguments.stage_dir,
            final_authority=final_authority,
            emit_dir=arguments.emit_dir,
            expected_authority_hotkey=arguments.expected_authority_hotkey,
        )
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "authority_hotkey": manifest.final_manifest_authority.authority_hotkey,
                    "ok": True,
                    "release_observation_block": manifest.release_observation_block,
                    "scoring_policy_sha256": manifest.scoring_policy_sha256,
                    "translation_weights_active": manifest.translation_weights_active,
                }
            )
            + b"\n"
        )
        return 0
    except (ShadowReleaseError, ValidationError, ValueError, TypeError) as error:
        reason = error.reason_code if isinstance(error, ShadowReleaseError) else "invalid_release"
        sys.stderr.write(reason + "\n")
        return 2


def materialize_operator_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Materialize portable UMI operator templates at a local release path"
    )
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("--expected-authority-hotkey", required=True)
    parser.add_argument("--local-bindings", type=Path, required=True)
    parser.add_argument("--emit-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        verify_shadow_release_directory(
            arguments.release_dir,
            expected_authority_hotkey=arguments.expected_authority_hotkey,
        )
        bindings_bytes = _read_private_file(
            _absolute_normal_path(arguments.local_bindings, "operator local bindings"),
            label="operator_local_bindings",
            maximum_bytes=2 * 1024 * 1024,
        )
        local_bindings = OperatorMaterializationBindings.model_validate_json(bindings_bytes)
        if canonical_json_bytes(local_bindings) != bindings_bytes:
            raise ShadowReleaseError("operator_local_bindings_noncanonical")
        materialize_private_operator_configs(
            arguments.release_dir,
            local_bindings,
            arguments.emit_dir,
            expected_authority_hotkey=arguments.expected_authority_hotkey,
        )
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "emit_dir": str(arguments.emit_dir),
                    "ok": True,
                    "release_dir": str(arguments.release_dir),
                    "translation_weights_active": False,
                }
            )
            + b"\n"
        )
        return 0
    except (ShadowReleaseError, ValidationError, ValueError, TypeError) as error:
        reason = error.reason_code if isinstance(error, ShadowReleaseError) else "invalid_release"
        sys.stderr.write(reason + "\n")
        return 2


__all__ = [
    "ArtifactPaths",
    "BuiltMinerFinalityArtifact",
    "BuiltShadowRelease",
    "CapacitySigningRequest",
    "FinalManifestAuthorityAttestation",
    "FinalManifestAuthorityRequest",
    "FinalityReleaseInput",
    "FinalityReplayBinding",
    "FinalizedReleaseObservation",
    "LiveReleaseObservationCapture",
    "LiveShadowReleaseInput",
    "LiveShadowReleaseIntent",
    "LiveShadowReleaseManifest",
    "MinerFinalityBuildReport",
    "MinerFinalityTargetReleaseInput",
    "OperatorMaterializationBindings",
    "OperatorReleaseInput",
    "PreparedShadowRelease",
    "PublishedCostObservation",
    "PublisherCapacityReleaseInput",
    "ReleaseArtifactDigest",
    "ReleaseAuthorityAttestation",
    "ReleaseAuthorityInput",
    "ReleaseAuthorityRequest",
    "ReleaseRelativeMinerConfig",
    "ReleaseRelativeOperatorConfig",
    "ReleaseRelativeValidatorConfig",
    "ResolvedMinerRelease",
    "ShadowReleaseError",
    "SignedPublisherCapacity",
    "StorageProofReleaseInput",
    "UnsignedLiveShadowReleaseManifest",
    "ValidatorCostClass",
    "ValidatorCostSchedule",
    "build_miner_finality_artifact",
    "build_shadow_release",
    "collect_live_release_observation",
    "emit_capacity_signing_requests",
    "emit_miner_finality_artifact",
    "emit_release_authority_request",
    "emit_shadow_release_signing_stage",
    "final_manifest_authority_request",
    "finalize_main",
    "finalize_shadow_release",
    "load_release_input",
    "main",
    "materialize_operator_main",
    "materialize_private_operator_configs",
    "miner_finality_artifact_main",
    "prepare_shadow_release",
    "release_authority_request",
    "resolve_miner_main",
    "verify_main",
    "verify_miner_release_target",
    "verify_shadow_release_directory",
    "verify_shadow_release_signing_stage",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
