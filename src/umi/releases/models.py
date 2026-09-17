"""Typed release inputs and manifests; no release execution or signing."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing_extensions import Self

from ..artifacts import PublisherCapacityStatement
from ..chain_evidence import FinalizedSnapshotRef
from ..conformance import FinalitySelfTestReport
from ..encoding import account_id32
from ..policy import (
    PolicyClock,
    PolicyLimits,
    PolicyThresholds,
    PublisherControlGroup,
    PublisherRegistryEntry,
    ScoringPolicy,
    ValidatorRegistryEntry,
)
from ..protocol import PROTOCOL_VERSION, BlockHash, Hex32, StrictProtocolModel
from ..release_chain_evidence import (
    RELEASE_OBSERVATION_EVIDENCE_PROFILE,
    RUNTIME_METADATA_AUTHENTICATION,
    RUNTIME_VERSION_AUTHENTICATION,
)
from ..validator_live import LIVE_SHADOW_MODE
from .layout import (
    _PINNED_UV_ARCHIVE_SHA256_BY_TARGET,
    _PINNED_UV_BINARY_SHA256_BY_TARGET,
    _PINNED_UV_LICENSE_SHA256,
    _PINNED_UV_SOURCE_ARCHIVE_SHA256,
    _SIGNATURE_RE,
    _STATIC_MEDIA_TARGET_MACHINE,
    _TARGET_RE,
    _WALLET_NAME_RE,
    CAPACITY_SIGNING_REQUEST_SCHEMA,
    DARWIN_MINER_TARGET,
    FINAL_MANIFEST_AUTHORITY_REQUEST_SCHEMA,
    FINAL_MANIFEST_AUTHORITY_SCHEMA,
    MAX_RELEASE_FILE_BYTES,
    MAXIMUM_FINALIZED_HEAD_AGE_MS,
    MAXIMUM_RELEASE_LEAD_BLOCKS,
    MEDIA_RUNTIME_CLOSURE_SCHEMA,
    MINER_FINALITY_BUILD_REPORT_SCHEMA,
    MINIMUM_RELEASE_LEAD_BLOCKS,
    PINNED_FFMPEG_VERSION,
    PINNED_UV_VERSION,
    RELEASE_AUTHORITY_REQUEST_SCHEMA,
    RELEASE_AUTHORITY_SCHEMA,
    RELEASE_INPUT_SCHEMA,
    RELEASE_INTENT_SCHEMA,
    RELEASE_MANIFEST_SCHEMA,
    RELEASE_RELATIVE_MINER_CONFIG_SCHEMA,
    RELEASE_RELATIVE_OPERATOR_CONFIG_SCHEMA,
    RELEASE_RELATIVE_VALIDATOR_CONFIG_SCHEMA,
    RELEASE_UNSIGNED_MANIFEST_SCHEMA,
    RESOLVED_MINER_RELEASE_SCHEMA,
    SIGNED_PUBLISHER_CAPACITY_SCHEMA,
    UV_TOOL_PROVENANCE_SCHEMA,
    VALIDATOR_COST_SCHEDULE_SCHEMA,
    _absolute_normal_path,
    _artifact_is_executable,
    _packaged_artifact_relative_path,
    _reject_digest,
    _release_relative_path,
)


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
