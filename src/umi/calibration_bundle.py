"""Proof-bearing audit bundles for successful shadow-calibration windows.

The bundle is deliberately incapable of representing an activated or submitted
weight row.  Version 2 stores the raw inputs needed to replay the finalized
no-weight scan, typed journal receipts for every reached stage, the complete
inactive policy document, and a validator signature over the canonical
manifest.  Decoded call/event summaries are never accepted as chain evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import bittensor_core
from pydantic import Field, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, ObjectRef
from .chain_evidence import FinalizedSnapshotRef, StorageProofVerifier
from .encoding import account_id32
from .grandpa_finality import EVIDENCE_CLASS, RECORD_SCHEMA, GrandpaFinalityObserver
from .policy import SCORING_POLICY_MEDIA_TYPE, ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_chain import FinalizedRuntimePin, PinnedRuntimeContext
from .validator_chain_scan import (
    DecodedNoWeightInterval,
    ExtrinsicsRootVerifier,
    FinalityAttestationReplayBinding,
    FinalizedBlockScanEvidence,
    FinalizedBlockScanner,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    ScanLimits,
    VerifiedFinalizedBlockIdentity,
)
from .validator_journal import STAGE_RECEIPT_MEDIA_TYPE, StageReceipt

CALIBRATION_BUNDLE_SCHEMA = "umi-calibration-audit-bundle/2"
CALIBRATION_SCAN_SCHEMA = "umi-finalized-no-weight-scan/2"
CALIBRATION_TERMINAL_SCHEMA = "umi-calibration-no-weight-terminal/2"
CALIBRATION_STAGE_SCHEMA = "umi-calibration-stage-evidence/2"
CALIBRATION_TERMINAL = "calibration_no_weight"
VALIDATOR_TERMINAL_STAGE_SCHEMA = "umi-validator-calibration-terminal-stage/1"

CALIBRATION_SCAN_MEDIA_TYPE = "application/vnd.umi.finalized-no-weight-scan-v2+json"
CALIBRATION_TERMINAL_MEDIA_TYPE = "application/vnd.umi.calibration-no-weight-terminal-v2+json"
CALIBRATION_STAGE_MEDIA_TYPE = "application/vnd.umi.calibration-stage-evidence-v2+json"
CALIBRATION_POLICY_MEDIA_TYPE = SCORING_POLICY_MEDIA_TYPE
CALIBRATION_RECEIPT_MEDIA_TYPE = STAGE_RECEIPT_MEDIA_TYPE
CALIBRATION_FINALITY_MEDIA_TYPE = "application/vnd.umi.smol-dot-finality-attestation+json"
CALIBRATION_METADATA_MEDIA_TYPE = "application/vnd.umi.substrate-runtime-metadata"
CALIBRATION_RUNTIME_VERSION_MEDIA_TYPE = "application/vnd.umi.substrate-runtime-version+json"
CALIBRATION_EXTRINSIC_MEDIA_TYPE = "application/vnd.umi.substrate-extrinsic"
CALIBRATION_EVENTS_MEDIA_TYPE = "application/vnd.umi.substrate-system-events"
CALIBRATION_PROOF_NODE_MEDIA_TYPE = "application/vnd.umi.substrate-trie-proof-node"
VALIDATOR_TERMINAL_STAGE_MEDIA_TYPE = (
    "application/vnd.umi.validator-calibration-terminal-stage-v1+json"
)

STAGE_IDS = (
    "pool_and_selection",
    "assignment",
    "request_transcript",
    "sealed_response",
    "reveal_and_score",
    "weight_build",
    "commit_and_terminal_state",
)

MAX_CALIBRATION_BUNDLE_BYTES = 384 * 1024 * 1024
MAX_CALIBRATION_OBJECT_BYTES = 64 * 1024 * 1024
MAX_CALIBRATION_MANIFEST_BYTES = 4 * 1024 * 1024
_MANIFEST_DOMAIN = b"umi-calibration-bundle-manifest-v2\0"
_VALIDATOR_SCAN_CHAIN_DOMAIN = b"umi-validator-no-weight-semantic-chain-v1\0"
_HOOK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_LIVE_REVISION_KEYS = frozenset(
    {
        "target_triple",
        "storage_proof_verifier_sha256",
        "finality_verifier_sha256",
        "finality_chain_spec_sha256",
    }
)

Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Hex64 = Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]
BlockHash = Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
HexBytes = Annotated[str, Field(pattern=r"^[0-9a-f]*$")]
PositiveBlock = Annotated[int, Field(gt=0)]
NonNegative = Annotated[int, Field(ge=0)]
NonEmpty = Annotated[str, Field(min_length=1)]


class CalibrationObject(StrictProtocolModel):
    sha256: Hex32
    media_type: NonEmpty
    size_bytes: NonNegative

    @model_validator(mode="after")
    def validate_media_type(self) -> Self:
        if not self.media_type.strip():
            raise ValueError("calibration object media type must not be whitespace")
        return self

    @classmethod
    def from_bytes(cls, data: bytes, media_type: str) -> CalibrationObject:
        if not isinstance(data, bytes):
            raise TypeError("calibration object data must be exact bytes")
        return cls(
            sha256=hashlib.sha256(data).hexdigest(),
            media_type=media_type,
            size_bytes=len(data),
        )

    @classmethod
    def from_ref(cls, reference: ObjectRef) -> CalibrationObject:
        return cls.model_validate(reference.as_dict())


class FinalizedSnapshotObject(StrictProtocolModel):
    block_number: NonNegative
    block_hash: BlockHash
    parent_hash: BlockHash
    state_root: BlockHash

    @classmethod
    def from_evidence(cls, value: FinalizedSnapshotRef) -> FinalizedSnapshotObject:
        return cls(
            block_number=value.block_number,
            block_hash=value.block_hash,
            parent_hash=value.parent_hash,
            state_root=value.state_root,
        )

    def to_evidence(self) -> FinalizedSnapshotRef:
        return FinalizedSnapshotRef(**self.model_dump(mode="python"))


class RuntimePinObject(StrictProtocolModel):
    metadata_sha256: Hex32
    spec_version: Annotated[int, Field(gt=0)]
    transaction_version: Annotated[int, Field(gt=0)]
    state_version: Literal[1]
    ss58_prefix: Literal[42]

    @classmethod
    def from_evidence(cls, value: FinalizedRuntimePin) -> RuntimePinObject:
        return cls.model_validate(
            {
                "metadata_sha256": value.metadata_sha256,
                "spec_version": value.spec_version,
                "transaction_version": value.transaction_version,
                "state_version": value.state_version,
                "ss58_prefix": value.ss58_prefix,
            }
        )

    def to_evidence(self) -> FinalizedRuntimePin:
        return FinalizedRuntimePin(**self.model_dump(mode="python"))


class FinalityReplayBindingObject(StrictProtocolModel):
    minimum_finalized_block: NonNegative
    maximum_records: Annotated[int, Field(gt=0)]
    startup_timeout_seconds: Annotated[int, Field(gt=0)]
    expected_sequence: NonNegative
    previous_number: NonNegative | None
    previous_timestamp_ms: NonNegative | None
    previous_hash: BlockHash | None
    previous_digest: Hex32

    @classmethod
    def from_evidence(cls, value: FinalityAttestationReplayBinding) -> FinalityReplayBindingObject:
        return cls(
            minimum_finalized_block=value.minimum_finalized_block,
            maximum_records=value.maximum_records,
            startup_timeout_seconds=value.startup_timeout_seconds,
            expected_sequence=value.expected_sequence,
            previous_number=value.previous_number,
            previous_timestamp_ms=value.previous_timestamp_ms,
            previous_hash=value.previous_hash,
            previous_digest=value.previous_digest,
        )

    def to_evidence(self) -> FinalityAttestationReplayBinding:
        return FinalityAttestationReplayBinding(**self.model_dump(mode="python"))


class FinalizedBlockEvidenceObject(StrictProtocolModel):
    snapshot: FinalizedSnapshotObject
    parent_snapshot: FinalizedSnapshotObject
    extrinsics_root: BlockHash
    finality_verifier_sha256: Hex32
    finality_attestation_object: CalibrationObject
    finality_replay_binding: FinalityReplayBindingObject
    runtime_pin: RuntimePinObject
    runtime_metadata_object: CalibrationObject
    runtime_version_object: CalibrationObject
    body_sha256: Hex32
    extrinsics: list[CalibrationObject]
    event_storage_key_hex: HexBytes
    event_value_present: bool
    event_value_sha256: Hex32
    event_value_object: CalibrationObject | None
    event_proof_nodes: Annotated[list[CalibrationObject], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_typed_refs(self) -> Self:
        if self.finality_attestation_object.media_type != CALIBRATION_FINALITY_MEDIA_TYPE:
            raise ValueError("finality attestation has the wrong media type")
        if self.runtime_metadata_object.media_type != CALIBRATION_METADATA_MEDIA_TYPE:
            raise ValueError("runtime metadata has the wrong media type")
        if self.runtime_version_object.media_type != CALIBRATION_RUNTIME_VERSION_MEDIA_TYPE:
            raise ValueError("runtime version has the wrong media type")
        if any(item.media_type != CALIBRATION_EXTRINSIC_MEDIA_TYPE for item in self.extrinsics):
            raise ValueError("block body contains a non-extrinsic object")
        if any(
            item.media_type != CALIBRATION_PROOF_NODE_MEDIA_TYPE for item in self.event_proof_nodes
        ):
            raise ValueError("event proof contains an incorrectly typed object")
        if self.event_value_present != (self.event_value_object is not None):
            raise ValueError("event value presence marker and object disagree")
        if self.event_value_object is not None and (
            self.event_value_object.media_type != CALIBRATION_EVENTS_MEDIA_TYPE
        ):
            raise ValueError("System.Events value has the wrong media type")
        if not self.event_storage_key_hex:
            raise ValueError("System.Events storage key must not be empty")
        return self

    def referenced_objects(self) -> tuple[CalibrationObject, ...]:
        values = [
            self.finality_attestation_object,
            self.runtime_metadata_object,
            self.runtime_version_object,
            *self.extrinsics,
            *self.event_proof_nodes,
        ]
        if self.event_value_object is not None:
            values.append(self.event_value_object)
        return tuple(values)


class FinalizedNoWeightScanObject(StrictProtocolModel):
    schema_: Literal[CALIBRATION_SCAN_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    validator_account_id32: Hex32
    window_id: Hex32
    window_index: NonNegative
    scoring_policy_hash: Hex32
    policy_object: CalibrationObject
    announcement_block: PositiveBlock
    start_block: PositiveBlock
    start_block_hash: BlockHash
    end_block: PositiveBlock
    end_block_hash: BlockHash
    scanned_blocks: Annotated[int, Field(gt=1)]
    scanned_calls: NonNegative
    scanned_events: NonNegative
    blocks: Annotated[list[FinalizedBlockEvidenceObject], Field(min_length=2)]

    @model_validator(mode="after")
    def validate_interval_shape(self) -> Self:
        if self.policy_object.media_type != CALIBRATION_POLICY_MEDIA_TYPE:
            raise ValueError("scan policy reference has the wrong media type")
        if self.start_block != self.announcement_block:
            raise ValueError("no-weight scan must start at the policy-derived announcement block")
        numbers = [block.snapshot.block_number for block in self.blocks]
        if numbers != list(range(self.start_block, self.end_block + 1)):
            raise ValueError("no-weight scan evidence is not one exact complete interval")
        if self.scanned_blocks != len(self.blocks):
            raise ValueError("no-weight scan block count does not match its evidence")
        if (self.start_block_hash, self.end_block_hash) != (
            self.blocks[0].snapshot.block_hash,
            self.blocks[-1].snapshot.block_hash,
        ):
            raise ValueError("no-weight scan boundary hashes do not match its evidence")
        for previous, current in zip(self.blocks, self.blocks[1:], strict=False):
            if current.parent_snapshot != previous.snapshot:
                raise ValueError("no-weight scan parent identities are not contiguous")
        return self


class CalibrationStageEvidence(StrictProtocolModel):
    schema_: Literal[CALIBRATION_STAGE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    scoring_policy_hash: Hex32
    stage_id: Literal[
        "pool_and_selection",
        "assignment",
        "request_transcript",
        "sealed_response",
        "reveal_and_score",
        "weight_build",
        "commit_and_terminal_state",
    ]
    replay_hook_id: NonEmpty
    previous_stage_evidence_sha256: Hex32 | None
    receipt_object: CalibrationObject
    payload_objects: Annotated[list[CalibrationObject], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_stage(self) -> Self:
        if _HOOK_RE.fullmatch(self.replay_hook_id) is None:
            raise ValueError("stage replay-hook ID is not canonical")
        if self.receipt_object.media_type != CALIBRATION_RECEIPT_MEDIA_TYPE:
            raise ValueError("stage receipt has the wrong media type")
        digests = [bytes.fromhex(item.sha256) for item in self.payload_objects]
        if digests != sorted(digests) or len(set(digests)) != len(digests):
            raise ValueError("stage payload objects must be unique and sorted")
        return self


class CalibrationStageRecord(StrictProtocolModel):
    stage_id: Literal[
        "pool_and_selection",
        "assignment",
        "request_transcript",
        "sealed_response",
        "reveal_and_score",
        "weight_build",
        "commit_and_terminal_state",
    ]
    status: Literal["reached"]
    evidence_object: CalibrationObject

    @model_validator(mode="after")
    def validate_media_type(self) -> Self:
        if self.evidence_object.media_type != CALIBRATION_STAGE_MEDIA_TYPE:
            raise ValueError("stage record must reference typed stage evidence")
        return self


class CalibrationNoWeightTerminalEvidence(StrictProtocolModel):
    schema_: Literal[CALIBRATION_TERMINAL_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    bundle_mode: Literal["live_shadow_calibration"]
    terminal_classification: Literal[CALIBRATION_TERMINAL]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    weight_submission_performed: Literal[False]
    activation_evidence: Literal[False]
    overall_activation_ready: Literal[False]
    validator_account_id32: Hex32
    window_id: Hex32
    scoring_policy_hash: Hex32
    announcement_block: PositiveBlock
    weight_commit_close_block: PositiveBlock
    weight_commit_close_block_hash: BlockHash
    audit_release_block: PositiveBlock
    audit_release_block_hash: BlockHash
    no_weight_scan_object: CalibrationObject

    @model_validator(mode="after")
    def validate_terminal(self) -> Self:
        if (self.audit_release_block, self.audit_release_block_hash) != (
            self.weight_commit_close_block,
            self.weight_commit_close_block_hash,
        ):
            raise ValueError("audit release must equal finalized weight-commit close")
        if self.no_weight_scan_object.media_type != CALIBRATION_SCAN_MEDIA_TYPE:
            raise ValueError("terminal must reference the typed no-weight scan")
        return self


class ValidatorManifestSignature(StrictProtocolModel):
    scheme: Literal["sr25519", "ed25519"]
    account_id32: Hex32
    signed_digest: Hex32
    signature: Hex64


class CalibrationBundleManifest(StrictProtocolModel):
    schema_: Literal[CALIBRATION_BUNDLE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    bundle_mode: Literal["live_shadow_calibration"]
    terminal_classification: Literal[CALIBRATION_TERMINAL]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    weight_submission_performed: Literal[False]
    activation_evidence: Literal[False]
    overall_activation_ready: Literal[False]
    validator_account_id32: Hex32
    window_id: Hex32
    window_index: NonNegative
    scoring_policy_hash: Hex32
    policy_object: CalibrationObject
    software_revisions: dict[str, str]
    highest_stage: Literal["commit_and_terminal_state"]
    announcement_block: PositiveBlock
    weight_commit_close_block: PositiveBlock
    weight_commit_close_block_hash: BlockHash
    audit_release_block: PositiveBlock
    audit_release_block_hash: BlockHash
    reason_codes: Annotated[list[str], Field(max_length=0)]
    terminal_evidence_object: CalibrationObject
    no_weight_scan_object: CalibrationObject
    stages: Annotated[list[CalibrationStageRecord], Field(min_length=7, max_length=7)]
    objects: Annotated[list[CalibrationObject], Field(min_length=10)]
    audit_bundle_bytes: Annotated[int, Field(gt=0)]
    validator_signature: ValidatorManifestSignature

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if [stage.stage_id for stage in self.stages] != list(STAGE_IDS):
            raise ValueError("all calibration stages must be reached once in protocol order")
        if (self.audit_release_block, self.audit_release_block_hash) != (
            self.weight_commit_close_block,
            self.weight_commit_close_block_hash,
        ):
            raise ValueError("audit release must equal finalized weight-commit close")
        if self.weight_commit_close_block <= self.announcement_block:
            raise ValueError("calibration scan interval must contain more than one block")
        if self.validator_signature.account_id32 != self.validator_account_id32:
            raise ValueError("manifest signature account differs from the validator")
        if self.validator_signature.signed_digest != _manifest_digest(self).hex():
            raise ValueError("manifest signature digest does not reproduce")
        if self.policy_object.media_type != CALIBRATION_POLICY_MEDIA_TYPE:
            raise ValueError("manifest policy reference has the wrong media type")
        if self.terminal_evidence_object.media_type != CALIBRATION_TERMINAL_MEDIA_TYPE:
            raise ValueError("manifest terminal reference has the wrong media type")
        if self.no_weight_scan_object.media_type != CALIBRATION_SCAN_MEDIA_TYPE:
            raise ValueError("manifest scan reference has the wrong media type")
        table = [bytes.fromhex(item.sha256) for item in self.objects]
        if table != sorted(table) or len(set(table)) != len(table):
            raise ValueError("manifest object table must be unique and sorted")
        if not self.software_revisions or any(
            not key.strip() or not value.strip() for key, value in self.software_revisions.items()
        ):
            raise ValueError("software revisions must contain non-empty names and values")
        return self


@dataclass(frozen=True, slots=True)
class CalibrationObjectInput:
    data: bytes
    media_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("calibration object data must be exact bytes")
        if not isinstance(self.media_type, str) or not self.media_type.strip():
            raise ValueError("calibration object media type must not be empty")


@dataclass(frozen=True, slots=True)
class CalibrationStageInput:
    receipt_bytes: bytes
    objects: tuple[CalibrationObjectInput, ...]
    replay_hook_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_bytes, bytes) or not self.receipt_bytes:
            raise ValueError("stage input requires exact journal receipt bytes")
        if not self.objects or any(
            not isinstance(item, CalibrationObjectInput) for item in self.objects
        ):
            raise ValueError("stage input requires its exact typed receipt objects")
        if (
            not isinstance(self.replay_hook_id, str)
            or _HOOK_RE.fullmatch(self.replay_hook_id) is None
        ):
            raise ValueError("stage input replay-hook ID is invalid")


class FinalityReplayVerifier(Protocol):
    def __call__(
        self,
        *,
        identities: tuple[VerifiedFinalizedBlockIdentity, ...],
        attestations: tuple[bytes, ...],
        replay_bindings: tuple[FinalityAttestationReplayBinding, ...],
        policy: ScoringPolicy,
    ) -> bool: ...


class RuntimeContextFactory(Protocol):
    def __call__(
        self,
        *,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
        metadata_bytes: bytes,
        runtime_version_bytes: bytes,
    ) -> PinnedRuntimeContext: ...


class ManifestSignatureVerifier(Protocol):
    def __call__(
        self,
        *,
        account_id32: bytes,
        scheme: str,
        digest: bytes,
        signature: bytes,
    ) -> bool: ...


class StageReplayHook(Protocol):
    def __call__(
        self,
        *,
        policy: ScoringPolicy,
        evidence: CalibrationStageEvidence,
        receipt: StageReceipt,
        objects: Mapping[str, bytes],
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class GrandpaFinalityReplayVerifier:
    """Concrete replay adapter for canonical smoldot observer attestations."""

    observer: GrandpaFinalityObserver

    def __post_init__(self) -> None:
        if not isinstance(self.observer, GrandpaFinalityObserver):
            raise TypeError("observer must be a GrandpaFinalityObserver")

    def __call__(
        self,
        *,
        identities: tuple[VerifiedFinalizedBlockIdentity, ...],
        attestations: tuple[bytes, ...],
        replay_bindings: tuple[FinalityAttestationReplayBinding, ...],
        policy: ScoringPolicy,
    ) -> bool:
        if not (len(identities) == len(attestations) == len(replay_bindings) and identities):
            return False
        pin = policy.implementation_pins.finality_verifier
        if pin is None:
            return False
        if (
            self.observer.expected_binary_sha256 not in pin.release_sha256_by_target.values()
            or self.observer.expected_chain_spec_sha256 != pin.chain_spec_sha256
            or self.observer.expected_genesis_hash != f"0x{pin.expected_genesis_hash}"
            or self.observer.bootstrap_block_number != pin.bootstrap_block_number
            or self.observer.bootstrap_block_hash != f"0x{pin.bootstrap_block_hash}"
        ):
            return False
        for identity, encoded, binding in zip(
            identities, attestations, replay_bindings, strict=True
        ):
            try:
                accepted = self.observer.validate_attestation(
                    encoded,
                    minimum_finalized_block=binding.minimum_finalized_block,
                    maximum_records=binding.maximum_records,
                    startup_timeout_seconds=binding.startup_timeout_seconds,
                    expected_sequence=binding.expected_sequence,
                    previous_hash=binding.previous_hash,
                    previous_digest=binding.previous_digest,
                    previous_number=binding.previous_number,
                    previous_timestamp_ms=binding.previous_timestamp_ms,
                )
            except (TypeError, ValueError, RuntimeError):
                return False
            block = accepted.block
            if (
                block.number != identity.snapshot.block_number
                or block.hash != identity.snapshot.block_hash
                or block.parent_hash != identity.snapshot.parent_hash
                or block.state_root != identity.snapshot.state_root
                or block.extrinsics_root != identity.extrinsics_root
            ):
                return False
        return True


@dataclass(frozen=True, slots=True)
class CalibrationVerificationPorts:
    finality_verifier: FinalityReplayVerifier
    extrinsics_root_verifier: ExtrinsicsRootVerifier
    event_proof_verifier: StorageProofVerifier
    runtime_factory: RuntimeContextFactory
    signature_verifier: ManifestSignatureVerifier
    stage_replay_hooks: Mapping[str, StageReplayHook]
    target_triple: str
    storage_proof_verifier_sha256: str
    finality_verifier_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "finality_verifier",
            "extrinsics_root_verifier",
            "event_proof_verifier",
            "runtime_factory",
            "signature_verifier",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} must be callable")
        if not isinstance(self.stage_replay_hooks, Mapping):
            raise TypeError("stage_replay_hooks must be a mapping")
        if any(
            not isinstance(key, str) or _HOOK_RE.fullmatch(key) is None or not callable(value)
            for key, value in self.stage_replay_hooks.items()
        ):
            raise ValueError("stage replay hooks contain an invalid entry")
        if not isinstance(self.target_triple, str) or not self.target_triple:
            raise ValueError("verification target triple must be non-empty")
        for name in ("storage_proof_verifier_sha256", "finality_verifier_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError(f"{name} must be lowercase SHA-256 hexadecimal")


@dataclass(frozen=True, slots=True)
class VerifiedCalibrationBundle:
    manifest: CalibrationBundleManifest
    policy: ScoringPolicy
    terminal: CalibrationNoWeightTerminalEvidence
    no_weight_scan: FinalizedNoWeightScanObject
    replayed_interval: DecodedNoWeightInterval
    stages: tuple[CalibrationStageEvidence, ...]


@dataclass(slots=True)
class _PayloadTable:
    maximum_object_bytes: int
    values: dict[str, tuple[CalibrationObject, bytes]]

    def add(self, data: bytes, media_type: str) -> CalibrationObject:
        if len(data) > self.maximum_object_bytes:
            raise ValueError("calibration object exceeds its byte ceiling")
        reference = CalibrationObject.from_bytes(data, media_type)
        previous = self.values.setdefault(reference.sha256, (reference, data))
        if previous != (reference, data):
            raise RuntimeError("one object digest has conflicting bytes or media type")
        return reference


class _ReplayScanPort:
    def __init__(
        self,
        bodies: Mapping[int, RawFinalizedBlockBody],
        events: Mapping[int, RawFinalizedEventStorage],
        runtimes: Mapping[int, PinnedRuntimeContext],
    ) -> None:
        self._bodies = bodies
        self._events = events
        self._runtimes = runtimes

    async def block_body_at(self, identity: VerifiedFinalizedBlockIdentity):
        return self._bodies.get(identity.snapshot.block_number)

    async def event_storage_at(self, identity: VerifiedFinalizedBlockIdentity, storage_key: bytes):
        value = self._events.get(identity.snapshot.block_number)
        if value is not None and value.storage_key != storage_key:
            return None
        return value

    async def execution_runtime_at(self, identity: VerifiedFinalizedBlockIdentity):
        return self._runtimes.get(identity.snapshot.block_number)


def write_calibration_bundle(
    root: Path,
    *,
    policy: ScoringPolicy,
    window_id: str,
    window_index: int,
    software_revisions: Mapping[str, str],
    validator_account: str | bytes,
    weight_commit_close_snapshot: FinalizedSnapshotRef,
    audit_release_snapshot: FinalizedSnapshotRef,
    no_weight_scan: DecodedNoWeightInterval,
    stages: Sequence[CalibrationStageInput],
    signature_scheme: Literal["sr25519", "ed25519"],
    manifest_signer: Callable[[bytes], bytes],
    maximum_object_bytes: int = MAX_CALIBRATION_OBJECT_BYTES,
    maximum_bundle_bytes: int = MAX_CALIBRATION_BUNDLE_BYTES,
) -> Path:
    """Write one signed live-shadow bundle from proof-bearing scanner output."""

    _validate_write_inputs(
        root=root,
        policy=policy,
        weight_commit_close_snapshot=weight_commit_close_snapshot,
        audit_release_snapshot=audit_release_snapshot,
        maximum_object_bytes=maximum_object_bytes,
        maximum_bundle_bytes=maximum_bundle_bytes,
    )
    if not callable(manifest_signer):
        raise TypeError("manifest_signer must be callable")
    if signature_scheme not in {"sr25519", "ed25519"}:
        raise ValueError("manifest signature scheme is unsupported")
    if isinstance(window_index, bool) or not isinstance(window_index, int) or window_index < 0:
        raise ValueError("window index must be a nonnegative integer")
    policy_hash = scoring_policy_hash(policy)
    revisions = dict(software_revisions)
    _assert_live_policy_bindings(
        policy,
        revisions,
        no_weight_scan.evidence if isinstance(no_weight_scan, DecodedNoWeightInterval) else (),
    )
    announcement_block = policy.activation_block + window_index * policy.clock.window_stride_blocks
    account = account_id32(validator_account)
    if not isinstance(no_weight_scan, DecodedNoWeightInterval) or not no_weight_scan.evidence:
        raise TypeError("bundle requires a proof-bearing DecodedNoWeightInterval")
    if no_weight_scan.scan.start_snapshot.block_number != announcement_block:
        raise ValueError("no-weight scan must start at the policy-derived announcement block")
    if no_weight_scan.scan.end_snapshot != weight_commit_close_snapshot:
        raise ValueError("no-weight scan must end at finalized weight-commit close")
    if no_weight_scan.scan.scanned_blocks < 2:
        raise ValueError("one-block calibration scans are forbidden")
    if audit_release_snapshot != weight_commit_close_snapshot:
        raise ValueError("audit release must equal finalized weight-commit close")

    stage_inputs = tuple(stages)
    if len(stage_inputs) != len(STAGE_IDS) or any(
        not isinstance(item, CalibrationStageInput) for item in stage_inputs
    ):
        raise ValueError("bundle requires seven typed stage inputs")

    payloads = _PayloadTable(maximum_object_bytes, {})
    policy_bytes = canonical_json_bytes(policy)
    policy_ref = payloads.add(policy_bytes, CALIBRATION_POLICY_MEDIA_TYPE)
    block_objects = [_encode_block_evidence(item, payloads) for item in no_weight_scan.evidence]
    scan_object = FinalizedNoWeightScanObject.model_validate(
        {
            "schema": CALIBRATION_SCAN_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "netuid": 78,
            "mechanism_id": 0,
            "validator_account_id32": account.hex(),
            "window_id": window_id,
            "window_index": window_index,
            "scoring_policy_hash": policy_hash,
            "policy_object": policy_ref.model_dump(mode="json"),
            "announcement_block": announcement_block,
            "start_block": no_weight_scan.scan.start_snapshot.block_number,
            "start_block_hash": no_weight_scan.scan.start_snapshot.block_hash,
            "end_block": no_weight_scan.scan.end_snapshot.block_number,
            "end_block_hash": no_weight_scan.scan.end_snapshot.block_hash,
            "scanned_blocks": no_weight_scan.scan.scanned_blocks,
            "scanned_calls": no_weight_scan.scan.scanned_calls,
            "scanned_events": no_weight_scan.scan.scanned_events,
            "blocks": [item.model_dump(mode="json") for item in block_objects],
        }
    )
    scan_ref = payloads.add(canonical_json_bytes(scan_object), CALIBRATION_SCAN_MEDIA_TYPE)

    stage_records: list[CalibrationStageRecord] = []
    previous_stage_digest: str | None = None
    for expected_stage, stage_input in zip(STAGE_IDS, stage_inputs, strict=True):
        if stage_input.replay_hook_id != calibration_stage_replay_hook_id(policy, expected_stage):
            raise ValueError("stage replay hook is not pinned by the scoring policy")
        receipt = _parse_canonical(stage_input.receipt_bytes, StageReceipt, "stage receipt")
        if not isinstance(receipt, StageReceipt):
            raise RuntimeError("stage receipt parser returned the wrong model")
        if receipt.stage != expected_stage or receipt.window_id != window_id:
            raise ValueError("stage receipt order or window binding is invalid")
        receipt_ref = payloads.add(stage_input.receipt_bytes, CALIBRATION_RECEIPT_MEDIA_TYPE)
        supplied: dict[str, CalibrationObject] = {}
        for item in stage_input.objects:
            reference = payloads.add(item.data, item.media_type)
            if reference.sha256 in supplied:
                raise ValueError("stage input repeats one payload object")
            supplied[reference.sha256] = reference
        expected_payloads = {item.sha256: item for item in receipt.objects}
        if {digest: value.model_dump(mode="json") for digest, value in supplied.items()} != {
            digest: value.model_dump(mode="json") for digest, value in expected_payloads.items()
        }:
            raise ValueError("stage input objects do not reproduce its typed journal receipt")
        stage_evidence = CalibrationStageEvidence.model_validate(
            {
                "schema": CALIBRATION_STAGE_SCHEMA,
                "protocol": PROTOCOL_VERSION,
                "window_id": window_id,
                "scoring_policy_hash": policy_hash,
                "stage_id": expected_stage,
                "replay_hook_id": stage_input.replay_hook_id,
                "previous_stage_evidence_sha256": previous_stage_digest,
                "receipt_object": receipt_ref.model_dump(mode="json"),
                "payload_objects": [
                    item.model_dump(mode="json")
                    for item in sorted(supplied.values(), key=lambda ref: bytes.fromhex(ref.sha256))
                ],
            }
        )
        stage_ref = payloads.add(
            canonical_json_bytes(stage_evidence),
            CALIBRATION_STAGE_MEDIA_TYPE,
        )
        stage_records.append(
            CalibrationStageRecord(
                stage_id=expected_stage,
                status="reached",
                evidence_object=stage_ref,
            )
        )
        previous_stage_digest = stage_ref.sha256

    terminal = CalibrationNoWeightTerminalEvidence.model_validate(
        {
            "schema": CALIBRATION_TERMINAL_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "bundle_mode": "live_shadow_calibration",
            "terminal_classification": CALIBRATION_TERMINAL,
            "netuid": 78,
            "mechanism_id": 0,
            "translation_weights_active": False,
            "weight_submission_performed": False,
            "activation_evidence": False,
            "overall_activation_ready": False,
            "validator_account_id32": account.hex(),
            "window_id": window_id,
            "scoring_policy_hash": policy_hash,
            "announcement_block": announcement_block,
            "weight_commit_close_block": weight_commit_close_snapshot.block_number,
            "weight_commit_close_block_hash": weight_commit_close_snapshot.block_hash,
            "audit_release_block": audit_release_snapshot.block_number,
            "audit_release_block_hash": audit_release_snapshot.block_hash,
            "no_weight_scan_object": scan_ref.model_dump(mode="json"),
        }
    )
    terminal_ref = payloads.add(
        canonical_json_bytes(terminal),
        CALIBRATION_TERMINAL_MEDIA_TYPE,
    )

    object_table = sorted(
        (item[0] for item in payloads.values.values()),
        key=lambda item: bytes.fromhex(item.sha256),
    )
    base: dict[str, Any] = {
        "schema": CALIBRATION_BUNDLE_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "bundle_mode": "live_shadow_calibration",
        "terminal_classification": CALIBRATION_TERMINAL,
        "netuid": 78,
        "mechanism_id": 0,
        "translation_weights_active": False,
        "weight_submission_performed": False,
        "activation_evidence": False,
        "overall_activation_ready": False,
        "validator_account_id32": account.hex(),
        "window_id": window_id,
        "window_index": window_index,
        "scoring_policy_hash": policy_hash,
        "policy_object": policy_ref.model_dump(mode="json"),
        "software_revisions": dict(sorted(revisions.items())),
        "highest_stage": STAGE_IDS[-1],
        "announcement_block": announcement_block,
        "weight_commit_close_block": weight_commit_close_snapshot.block_number,
        "weight_commit_close_block_hash": weight_commit_close_snapshot.block_hash,
        "audit_release_block": audit_release_snapshot.block_number,
        "audit_release_block_hash": audit_release_snapshot.block_hash,
        "reason_codes": [],
        "terminal_evidence_object": terminal_ref.model_dump(mode="json"),
        "no_weight_scan_object": scan_ref.model_dump(mode="json"),
        "stages": [item.model_dump(mode="json") for item in stage_records],
        "objects": [item.model_dump(mode="json") for item in object_table],
    }
    object_bytes = sum(item.size_bytes for item in object_table)
    placeholder = {
        "scheme": signature_scheme,
        "account_id32": account.hex(),
        "signed_digest": "00" * 32,
        "signature": "0x" + "00" * 64,
    }
    manifest_size = _fixed_point_manifest_size(
        base,
        object_bytes=object_bytes,
        signature=placeholder,
    )
    total_bytes = manifest_size + object_bytes
    if manifest_size > MAX_CALIBRATION_MANIFEST_BYTES or total_bytes > maximum_bundle_bytes:
        raise ValueError("calibration bundle exceeds its byte ceiling")
    unsigned = {**base, "audit_bundle_bytes": total_bytes}
    digest = hashlib.sha256(_MANIFEST_DOMAIN + canonical_json_bytes(unsigned)).digest()
    signature = manifest_signer(digest)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("manifest signer must return one exact 64-byte signature")
    manifest = CalibrationBundleManifest.model_validate(
        {
            **unsigned,
            "validator_signature": {
                "scheme": signature_scheme,
                "account_id32": account.hex(),
                "signed_digest": digest.hex(),
                "signature": "0x" + signature.hex(),
            },
        }
    )
    encoded_manifest = canonical_json_bytes(manifest)
    if len(encoded_manifest) != manifest_size:
        raise RuntimeError("signed calibration manifest size did not converge")

    store = EvidenceStore(
        root,
        maximum_object_bytes=maximum_object_bytes,
        maximum_manifest_bytes=MAX_CALIBRATION_MANIFEST_BYTES,
        maximum_total_object_bytes=maximum_bundle_bytes,
    )
    for reference, data in payloads.values.values():
        stored = CalibrationObject.from_ref(store.add_bytes(data, reference.media_type))
        if stored != reference:
            raise RuntimeError("stored calibration object reference changed")
    return store.write_manifest(manifest.model_dump(mode="json", by_alias=True))


async def verify_calibration_bundle(
    root: Path,
    *,
    ports: CalibrationVerificationPorts,
    scan_limits: ScanLimits | None = None,
    maximum_object_bytes: int = MAX_CALIBRATION_OBJECT_BYTES,
    maximum_bundle_bytes: int = MAX_CALIBRATION_BUNDLE_BYTES,
) -> VerifiedCalibrationBundle:
    """Verify the signature, typed stages, finality and raw chain replay."""

    _validate_ceiling(maximum_object_bytes, MAX_CALIBRATION_OBJECT_BYTES, "object")
    _validate_ceiling(maximum_bundle_bytes, MAX_CALIBRATION_BUNDLE_BYTES, "bundle")
    if not isinstance(ports, CalibrationVerificationPorts):
        raise TypeError("ports must be CalibrationVerificationPorts")
    if not isinstance(root, Path) or not root.exists() or root.is_symlink() or not root.is_dir():
        raise ValueError("calibration bundle root must be a real existing directory")
    store = EvidenceStore(
        root,
        maximum_object_bytes=maximum_object_bytes,
        maximum_manifest_bytes=MAX_CALIBRATION_MANIFEST_BYTES,
        maximum_total_object_bytes=maximum_bundle_bytes,
    )
    raw_manifest, manifest_bytes = store.load_manifest_with_bytes()
    manifest = CalibrationBundleManifest.model_validate(raw_manifest)
    object_bytes = {
        item.sha256: store.read(item.model_dump(mode="json")) for item in manifest.objects
    }
    _require_exact_bundle_paths(root, set(object_bytes))
    calculated = len(manifest_bytes) + sum(item.size_bytes for item in manifest.objects)
    if calculated != manifest.audit_bundle_bytes or calculated > maximum_bundle_bytes:
        raise ValueError("calibration bundle byte accounting does not reproduce")
    digest = _manifest_digest(manifest)
    signature = bytes.fromhex(manifest.validator_signature.signature[2:])
    try:
        signature_ok = ports.signature_verifier(
            account_id32=bytes.fromhex(manifest.validator_account_id32),
            scheme=manifest.validator_signature.scheme,
            digest=digest,
            signature=signature,
        )
    except Exception as error:
        raise ValueError("validator manifest signature verification failed") from error
    if signature_ok is not True:
        raise ValueError("validator manifest signature verification failed")

    policy = _parse_canonical(
        object_bytes[manifest.policy_object.sha256],
        ScoringPolicy,
        "scoring policy",
    )
    if not isinstance(policy, ScoringPolicy):
        raise RuntimeError("policy parser returned the wrong model")
    if scoring_policy_hash(policy) != manifest.scoring_policy_hash:
        raise ValueError("manifest scoring-policy hash does not reproduce")
    _assert_live_policy_bindings(
        policy,
        manifest.software_revisions,
        (),
        ports=ports,
    )
    announcement = (
        policy.activation_block + manifest.window_index * policy.clock.window_stride_blocks
    )
    if announcement != manifest.announcement_block:
        raise ValueError("manifest announcement block is not policy-derived")

    scan = _parse_canonical(
        object_bytes[manifest.no_weight_scan_object.sha256],
        FinalizedNoWeightScanObject,
        "no-weight scan",
    )
    terminal = _parse_canonical(
        object_bytes[manifest.terminal_evidence_object.sha256],
        CalibrationNoWeightTerminalEvidence,
        "calibration terminal",
    )
    if not isinstance(scan, FinalizedNoWeightScanObject) or not isinstance(
        terminal, CalibrationNoWeightTerminalEvidence
    ):
        raise RuntimeError("typed terminal objects returned the wrong model")
    _verify_cross_bindings(manifest, policy, scan, terminal)

    stage_models: list[CalibrationStageEvidence] = []
    previous_digest: str | None = None
    for stage_record in manifest.stages:
        evidence = _parse_canonical(
            object_bytes[stage_record.evidence_object.sha256],
            CalibrationStageEvidence,
            "stage evidence",
        )
        if not isinstance(evidence, CalibrationStageEvidence):
            raise RuntimeError("stage evidence parser returned the wrong model")
        if (
            evidence.stage_id != stage_record.stage_id
            or evidence.window_id != manifest.window_id
            or evidence.scoring_policy_hash != manifest.scoring_policy_hash
            or evidence.previous_stage_evidence_sha256 != previous_digest
        ):
            raise ValueError("stage evidence chain or bundle binding is invalid")
        if evidence.replay_hook_id != calibration_stage_replay_hook_id(policy, evidence.stage_id):
            raise ValueError("stage replay hook is not pinned by the scoring policy")
        receipt = _parse_canonical(
            object_bytes[evidence.receipt_object.sha256],
            StageReceipt,
            "stage receipt",
        )
        if not isinstance(receipt, StageReceipt):
            raise RuntimeError("stage receipt parser returned the wrong model")
        if receipt.window_id != manifest.window_id or receipt.stage != evidence.stage_id:
            raise ValueError("stage receipt binding is invalid")
        expected_payloads = {item.sha256: item for item in receipt.objects}
        supplied_payloads = {item.sha256: item for item in evidence.payload_objects}
        if {key: value.model_dump(mode="json") for key, value in expected_payloads.items()} != {
            key: value.model_dump(mode="json") for key, value in supplied_payloads.items()
        }:
            raise ValueError("stage payload references do not reproduce their receipt")
        hook = ports.stage_replay_hooks.get(evidence.replay_hook_id)
        if hook is None:
            raise ValueError("required stage replay hook is unavailable")
        payload_map = {digest: object_bytes[digest] for digest in supplied_payloads}
        try:
            replayed = hook(
                policy=policy,
                evidence=evidence,
                receipt=receipt,
                objects=payload_map,
            )
        except Exception as error:
            raise ValueError("stage evidence replay failed") from error
        if replayed is not True:
            raise ValueError("stage evidence replay failed")
        stage_models.append(evidence)
        previous_digest = stage_record.evidence_object.sha256

    _verify_terminal_stage_scan_binding(
        manifest=manifest,
        scan=scan,
        terminal_stage=stage_models[-1],
        object_bytes=object_bytes,
    )

    replayed_interval = await replay_finalized_no_weight_scan(
        scan,
        object_bytes=object_bytes,
        policy=policy,
        ports=ports,
        scan_limits=scan_limits,
    )
    _require_exact_references(manifest, scan, terminal, tuple(stage_models))
    return VerifiedCalibrationBundle(
        manifest=manifest,
        policy=policy,
        terminal=terminal,
        no_weight_scan=scan,
        replayed_interval=replayed_interval,
        stages=tuple(stage_models),
    )


async def replay_finalized_no_weight_scan(
    scan: FinalizedNoWeightScanObject,
    *,
    object_bytes: Mapping[str, bytes],
    policy: ScoringPolicy,
    ports: CalibrationVerificationPorts,
    scan_limits: ScanLimits | None = None,
) -> DecodedNoWeightInterval:
    """Replay one typed proof-bearing no-weight scan outside a bundle wrapper.

    Incident and calibration bundles share this exact chain-evidence boundary so
    neither format can silently acquire a weaker finality, runtime, trie-proof, or
    extrinsics-root check.
    """

    if not isinstance(scan, FinalizedNoWeightScanObject):
        raise TypeError("scan must be FinalizedNoWeightScanObject")
    if not isinstance(object_bytes, Mapping):
        raise TypeError("object_bytes must be a digest-to-bytes mapping")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be ScoringPolicy")
    if not isinstance(ports, CalibrationVerificationPorts):
        raise TypeError("ports must be CalibrationVerificationPorts")

    identities: list[VerifiedFinalizedBlockIdentity] = []
    attestations: list[bytes] = []
    replay_bindings: list[FinalityAttestationReplayBinding] = []
    bodies: dict[int, RawFinalizedBlockBody] = {}
    events: dict[int, RawFinalizedEventStorage] = {}
    runtimes: dict[int, PinnedRuntimeContext] = {}
    pins: list[FinalizedRuntimePin] = []
    for block in scan.blocks:
        identity, attestation, binding, body, event_storage, runtime = _decode_block_evidence(
            block,
            object_bytes,
            ports.runtime_factory,
        )
        height = identity.snapshot.block_number
        identities.append(identity)
        attestations.append(attestation)
        replay_bindings.append(binding)
        bodies[height] = body
        events[height] = event_storage
        runtimes[height] = runtime
        pins.append(runtime.pin)
    _assert_replayed_chain_pins(
        policy,
        tuple(identities),
        tuple(runtimes.values()),
        expected_finality_verifier_sha256=ports.finality_verifier_sha256,
    )
    try:
        finality_ok = ports.finality_verifier(
            identities=tuple(identities),
            attestations=tuple(attestations),
            replay_bindings=tuple(replay_bindings),
            policy=policy,
        )
    except Exception as error:
        raise ValueError("smoldot finality attestation replay failed") from error
    if finality_ok is not True:
        raise ValueError("smoldot finality attestation replay failed")

    scanner = FinalizedBlockScanner(
        _ReplayScanPort(bodies, events, runtimes),
        extrinsics_root_verifier=ports.extrinsics_root_verifier,
        event_proof_verifier=ports.event_proof_verifier,
        supported_runtime_pins=tuple(dict.fromkeys(pins)),
        limits=scan_limits,
    )
    replayed_interval = await scanner.decode_no_weight_interval(
        tuple(identities),
        start_block=scan.start_block,
        end_block=scan.end_block,
        validator_account=bytes.fromhex(scan.validator_account_id32),
        netuid=scan.netuid,
        mechanism_id=scan.mechanism_id,
    )
    reproduced_counts = (
        replayed_interval.scan.scanned_blocks,
        replayed_interval.scan.scanned_calls,
        replayed_interval.scan.scanned_events,
    )
    if reproduced_counts != (scan.scanned_blocks, scan.scanned_calls, scan.scanned_events):
        raise ValueError("no-weight scan counts do not reproduce from raw evidence")
    return replayed_interval


def build_bittensor_runtime_context(
    *,
    snapshot: FinalizedSnapshotRef,
    pin: FinalizedRuntimePin,
    metadata_bytes: bytes,
    runtime_version_bytes: bytes,
) -> PinnedRuntimeContext:
    """Rebuild the production codec from exact pinned runtime artifacts."""

    version = _canonical_json_mapping(runtime_version_bytes, "runtime version")
    if (
        version.get("specVersion") != pin.spec_version
        or version.get("transactionVersion") != pin.transaction_version
        or version.get("stateVersion") != pin.state_version
    ):
        raise ValueError("runtime version bytes disagree with their pin")
    if hashlib.sha256(metadata_bytes).hexdigest() != pin.metadata_sha256:
        raise ValueError("runtime metadata bytes disagree with their pin")
    try:
        runtime = bittensor_core.Runtime(
            metadata_bytes,
            pin.spec_version,
            pin.transaction_version,
            ss58_format=pin.ss58_prefix,
        )
    except Exception as error:
        raise ValueError("runtime codec initialization failed") from error
    if runtime.spec_version != pin.spec_version or runtime.transaction_version != (
        pin.transaction_version
    ):
        raise ValueError("rebuilt runtime codec version mismatch")
    if runtime.constant("System", "SS58Prefix") != pin.ss58_prefix:
        raise ValueError("rebuilt runtime codec SS58 prefix mismatch")
    return PinnedRuntimeContext(
        snapshot=snapshot,
        pin=pin,
        metadata_bytes=metadata_bytes,
        runtime_version_bytes=runtime_version_bytes,
        _runtime=runtime,
    )


def calibration_stage_replay_hook_id(policy: ScoringPolicy, stage_id: str) -> str:
    """Return the only replay-hook ID eligible under ``policy`` for one stage."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if stage_id not in STAGE_IDS:
        raise ValueError("stage ID is not part of the calibration protocol")
    return f"umi-stage/{stage_id}/{policy.implementation_pins.umi_source_tree_sha256}"


def _encode_block_evidence(
    evidence: FinalizedBlockScanEvidence,
    payloads: _PayloadTable,
) -> FinalizedBlockEvidenceObject:
    finality_ref = payloads.add(evidence.finality_attestation, CALIBRATION_FINALITY_MEDIA_TYPE)
    _assert_attestation_header_binding(
        evidence.finality_attestation,
        evidence.identity,
        evidence.finality_replay_binding,
    )
    metadata_ref = payloads.add(evidence.runtime_metadata_bytes, CALIBRATION_METADATA_MEDIA_TYPE)
    version_ref = payloads.add(
        evidence.runtime_version_bytes,
        CALIBRATION_RUNTIME_VERSION_MEDIA_TYPE,
    )
    _assert_runtime_version_binding(evidence.runtime_version_bytes, evidence.runtime_pin)
    extrinsics = [
        payloads.add(item, CALIBRATION_EXTRINSIC_MEDIA_TYPE) for item in evidence.body.extrinsics
    ]
    event_value = None
    if evidence.event_storage.value is not None:
        event_value = payloads.add(evidence.event_storage.value, CALIBRATION_EVENTS_MEDIA_TYPE)
    proof_nodes = [
        payloads.add(item, CALIBRATION_PROOF_NODE_MEDIA_TYPE)
        for item in evidence.event_storage.proof
    ]
    return FinalizedBlockEvidenceObject(
        snapshot=FinalizedSnapshotObject.from_evidence(evidence.identity.snapshot),
        parent_snapshot=FinalizedSnapshotObject.from_evidence(evidence.identity.parent_snapshot),
        extrinsics_root=evidence.identity.extrinsics_root,
        finality_verifier_sha256=evidence.identity.finality_verifier_sha256,
        finality_attestation_object=finality_ref,
        finality_replay_binding=FinalityReplayBindingObject.from_evidence(
            evidence.finality_replay_binding
        ),
        runtime_pin=RuntimePinObject.from_evidence(evidence.runtime_pin),
        runtime_metadata_object=metadata_ref,
        runtime_version_object=version_ref,
        body_sha256=evidence.body.body_sha256,
        extrinsics=extrinsics,
        event_storage_key_hex=evidence.event_storage.storage_key.hex(),
        event_value_present=evidence.event_storage.value is not None,
        event_value_sha256=evidence.event_storage.value_sha256,
        event_value_object=event_value,
        event_proof_nodes=proof_nodes,
    )


def _decode_block_evidence(
    block: FinalizedBlockEvidenceObject,
    object_bytes: Mapping[str, bytes],
    runtime_factory: RuntimeContextFactory,
) -> tuple[
    VerifiedFinalizedBlockIdentity,
    bytes,
    FinalityAttestationReplayBinding,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    PinnedRuntimeContext,
]:
    attestation = object_bytes[block.finality_attestation_object.sha256]
    identity = VerifiedFinalizedBlockIdentity(
        snapshot=block.snapshot.to_evidence(),
        parent_snapshot=block.parent_snapshot.to_evidence(),
        extrinsics_root=block.extrinsics_root,
        finality_verifier_sha256=block.finality_verifier_sha256,
        finality_evidence_sha256=hashlib.sha256(attestation).hexdigest(),
    )
    binding = block.finality_replay_binding.to_evidence()
    _assert_attestation_header_binding(attestation, identity, binding)
    metadata = object_bytes[block.runtime_metadata_object.sha256]
    version = object_bytes[block.runtime_version_object.sha256]
    pin = block.runtime_pin.to_evidence()
    _assert_runtime_version_binding(version, pin)
    try:
        runtime = runtime_factory(
            snapshot=identity.parent_snapshot,
            pin=pin,
            metadata_bytes=metadata,
            runtime_version_bytes=version,
        )
    except Exception as error:
        raise ValueError("runtime replay factory failed") from error
    if (
        not isinstance(runtime, PinnedRuntimeContext)
        or runtime.snapshot != identity.parent_snapshot
        or runtime.pin != pin
        or runtime.metadata_bytes != metadata
        or runtime.runtime_version_bytes != version
    ):
        raise ValueError("runtime replay factory returned another pinned context")
    extrinsics = tuple(object_bytes[item.sha256] for item in block.extrinsics)
    body = RawFinalizedBlockBody(
        block_hash=identity.snapshot.block_hash,
        parent_hash=identity.snapshot.parent_hash,
        state_root=identity.snapshot.state_root,
        extrinsics_root=identity.extrinsics_root,
        extrinsics=extrinsics,
        body_sha256=block.body_sha256,
    )
    event_value = (
        object_bytes[block.event_value_object.sha256]
        if block.event_value_object is not None
        else None
    )
    event_storage = RawFinalizedEventStorage(
        block_hash=identity.snapshot.block_hash,
        state_root=identity.snapshot.state_root,
        storage_key=bytes.fromhex(block.event_storage_key_hex),
        value=event_value,
        proof=tuple(object_bytes[item.sha256] for item in block.event_proof_nodes),
        value_sha256=block.event_value_sha256,
    )
    return identity, attestation, binding, body, event_storage, runtime


def _assert_attestation_header_binding(
    encoded: bytes,
    identity: VerifiedFinalizedBlockIdentity,
    binding: FinalityAttestationReplayBinding | None = None,
) -> None:
    record = _canonical_json_mapping(encoded, "smoldot finality attestation")
    if (
        record.get("schema") != RECORD_SCHEMA
        or record.get("evidence_class") != EVIDENCE_CLASS
        or record.get("offline_finality_proof") is not False
    ):
        raise ValueError("finality object is not a canonical smoldot verifier attestation")
    block = record.get("block")
    if not isinstance(block, Mapping):
        raise ValueError("smoldot finality attestation omits its full header")
    expected = {
        "number": identity.snapshot.block_number,
        "hash": identity.snapshot.block_hash,
        "parent_hash": identity.snapshot.parent_hash,
        "state_root": identity.snapshot.state_root,
        "extrinsics_root": identity.extrinsics_root,
    }
    if any(block.get(key) != value for key, value in expected.items()):
        raise ValueError("smoldot finality attestation header disagrees with its scan identity")
    if not isinstance(block.get("scale_header"), str) or not block["scale_header"].startswith("0x"):
        raise ValueError("smoldot finality attestation omits the full SCALE header")
    if binding is not None and (
        record.get("sequence") != binding.expected_sequence
        or identity.snapshot.block_number < binding.minimum_finalized_block
        or record.get("previous_finalized_hash") != binding.previous_hash
        or record.get("previous_transcript_digest") != binding.previous_digest
    ):
        raise ValueError("smoldot finality attestation disagrees with its observer-run binding")


def _assert_runtime_version_binding(encoded: bytes, pin: FinalizedRuntimePin) -> None:
    version = _canonical_json_mapping(encoded, "runtime version")
    if (
        version.get("specVersion") != pin.spec_version
        or version.get("transactionVersion") != pin.transaction_version
        or version.get("stateVersion") != pin.state_version
    ):
        raise ValueError("runtime-version evidence disagrees with its pin")


def _verify_cross_bindings(
    manifest: CalibrationBundleManifest,
    policy: ScoringPolicy,
    scan: FinalizedNoWeightScanObject,
    terminal: CalibrationNoWeightTerminalEvidence,
) -> None:
    common = (
        manifest.validator_account_id32,
        manifest.window_id,
        manifest.scoring_policy_hash,
        manifest.netuid,
        manifest.mechanism_id,
    )
    if common != (
        scan.validator_account_id32,
        scan.window_id,
        scan.scoring_policy_hash,
        scan.netuid,
        scan.mechanism_id,
    ) or common != (
        terminal.validator_account_id32,
        terminal.window_id,
        terminal.scoring_policy_hash,
        terminal.netuid,
        terminal.mechanism_id,
    ):
        raise ValueError("manifest, scan, and terminal bindings disagree")
    if manifest.policy_object != scan.policy_object or manifest.scoring_policy_hash != (
        scoring_policy_hash(policy)
    ):
        raise ValueError("scan and manifest reference another scoring policy")
    if (
        scan.window_index != manifest.window_index
        or scan.announcement_block != manifest.announcement_block
        or terminal.announcement_block != manifest.announcement_block
    ):
        raise ValueError("policy-derived window boundaries disagree")
    if (scan.end_block, scan.end_block_hash) != (
        manifest.weight_commit_close_block,
        manifest.weight_commit_close_block_hash,
    ):
        raise ValueError("no-weight scan does not end at weight-commit close")
    if terminal.no_weight_scan_object != manifest.no_weight_scan_object:
        raise ValueError("terminal references another no-weight scan")


def _verify_terminal_stage_scan_binding(
    *,
    manifest: CalibrationBundleManifest,
    scan: FinalizedNoWeightScanObject,
    terminal_stage: CalibrationStageEvidence,
    object_bytes: Mapping[str, bytes],
) -> None:
    """Bind the terminal journal result to the independently replayed scan inputs."""

    matches = [
        item
        for item in terminal_stage.payload_objects
        if item.media_type == VALIDATOR_TERMINAL_STAGE_MEDIA_TYPE
    ]
    if len(matches) != 1 or len(terminal_stage.payload_objects) != 1:
        raise ValueError("terminal stage does not contain its unique typed scan binding")
    document = _canonical_json_mapping(
        object_bytes[matches[0].sha256],
        "validator terminal stage",
    )
    required = {
        "schema",
        "protocol",
        "window_id",
        "window_index",
        "scoring_policy_hash",
        "validator_account_id32",
        "announcement_block",
        "weight_commit_close_snapshot",
        "scanned_blocks",
        "scanned_calls",
        "scanned_events",
        "scan_evidence_chain_sha256",
        "translation_weights_active",
        "weight_submission_performed",
        "terminal_classification",
    }
    if set(document) != required:
        raise ValueError("validator terminal stage has an unexpected shape")
    close = document.get("weight_commit_close_snapshot")
    if not isinstance(close, Mapping):
        raise ValueError("validator terminal stage close snapshot is malformed")
    expected_close = scan.blocks[-1].snapshot.model_dump(mode="json")
    expected = {
        "schema": VALIDATOR_TERMINAL_STAGE_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "window_id": manifest.window_id,
        "window_index": manifest.window_index,
        "scoring_policy_hash": manifest.scoring_policy_hash,
        "validator_account_id32": manifest.validator_account_id32,
        "announcement_block": manifest.announcement_block,
        "scanned_blocks": scan.scanned_blocks,
        "scanned_calls": scan.scanned_calls,
        "scanned_events": scan.scanned_events,
        "translation_weights_active": False,
        "weight_submission_performed": False,
        "terminal_classification": CALIBRATION_TERMINAL,
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise ValueError("validator terminal stage and no-weight scan disagree")
    if dict(close) != expected_close:
        raise ValueError("validator terminal stage and scan close snapshot disagree")
    if document.get("scan_evidence_chain_sha256") != _scan_evidence_chain_sha256(scan):
        raise ValueError("validator terminal stage scan-evidence chain does not reproduce")


def _scan_evidence_chain_sha256(scan: FinalizedNoWeightScanObject) -> str:
    material = [
        {
            "snapshot": block.snapshot.model_dump(mode="json"),
            "parent_snapshot": block.parent_snapshot.model_dump(mode="json"),
            "extrinsics_root": block.extrinsics_root,
            "finality_verifier_sha256": block.finality_verifier_sha256,
            "runtime_pin": block.runtime_pin.model_dump(mode="json"),
            "body_sha256": block.body_sha256,
            "event_value_sha256": block.event_value_sha256,
        }
        for block in scan.blocks
    ]
    return hashlib.sha256(_VALIDATOR_SCAN_CHAIN_DOMAIN + canonical_json_bytes(material)).hexdigest()


def _assert_live_policy_bindings(
    policy: ScoringPolicy,
    revisions: Mapping[str, str],
    evidence: Sequence[FinalizedBlockScanEvidence],
    *,
    ports: CalibrationVerificationPorts | None = None,
) -> None:
    pins = policy.implementation_pins
    if (
        pins.pin_profile != "live_shadow_calibration"
        or pins.finality_verifier is None
        or pins.storage_proof_verifier is None
        or pins.live_chain is None
    ):
        raise ValueError("calibration bundle requires a fully pinned live-shadow policy")
    if not _LIVE_REVISION_KEYS.issubset(revisions):
        raise ValueError("calibration software revisions omit live verifier bindings")
    target = revisions["target_triple"]
    expected_finality = pins.finality_verifier.release_sha256_by_target.get(target)
    expected_proof = pins.storage_proof_verifier.release_sha256_by_target.get(target)
    if expected_finality is None or expected_proof is None:
        raise ValueError("calibration target triple is not pinned by the policy")
    expected = {
        "storage_proof_verifier_sha256": expected_proof,
        "finality_verifier_sha256": expected_finality,
        "finality_chain_spec_sha256": pins.finality_verifier.chain_spec_sha256,
    }
    if any(revisions.get(key) != value for key, value in expected.items()):
        raise ValueError("calibration verifier revisions disagree with the live policy")
    if ports is not None and (
        ports.target_triple != target
        or ports.storage_proof_verifier_sha256 != expected_proof
        or ports.finality_verifier_sha256 != expected_finality
    ):
        raise ValueError("active verification ports disagree with the signed live verifier pins")
    for item in evidence:
        if item.identity.finality_verifier_sha256 != expected_finality:
            raise ValueError("scan finality verifier digest disagrees with the live policy")
        live = pins.live_chain
        if (
            item.runtime_pin.metadata_sha256 != live.metadata_sha256
            or item.runtime_pin.spec_version != live.runtime_spec_version
            or item.runtime_pin.transaction_version != live.transaction_version
            or item.runtime_pin.state_version != live.state_version
        ):
            raise ValueError("scan runtime pin disagrees with the live policy")


def _assert_replayed_chain_pins(
    policy: ScoringPolicy,
    identities: tuple[VerifiedFinalizedBlockIdentity, ...],
    runtimes: tuple[PinnedRuntimeContext, ...],
    *,
    expected_finality_verifier_sha256: str,
) -> None:
    pins = policy.implementation_pins
    assert pins.finality_verifier is not None and pins.live_chain is not None
    if any(
        item.finality_verifier_sha256 != expected_finality_verifier_sha256 for item in identities
    ):
        raise ValueError("replayed finality identity is not policy-pinned")
    live = pins.live_chain
    if any(
        runtime.pin.metadata_sha256 != live.metadata_sha256
        or runtime.pin.spec_version != live.runtime_spec_version
        or runtime.pin.transaction_version != live.transaction_version
        or runtime.pin.state_version != live.state_version
        for runtime in runtimes
    ):
        raise ValueError("replayed runtime context is not policy-pinned")


def _require_exact_references(
    manifest: CalibrationBundleManifest,
    scan: FinalizedNoWeightScanObject,
    terminal: CalibrationNoWeightTerminalEvidence,
    stages: tuple[CalibrationStageEvidence, ...],
) -> None:
    references = {
        manifest.policy_object.sha256,
        manifest.no_weight_scan_object.sha256,
        manifest.terminal_evidence_object.sha256,
        terminal.no_weight_scan_object.sha256,
        scan.policy_object.sha256,
    }
    references.update(stage.evidence_object.sha256 for stage in manifest.stages)
    for stage in stages:
        references.add(stage.receipt_object.sha256)
        references.update(item.sha256 for item in stage.payload_objects)
    for block in scan.blocks:
        references.update(item.sha256 for item in block.referenced_objects())
    if references != {item.sha256 for item in manifest.objects}:
        raise ValueError("manifest object table is not the exact referenced-object union")


def _manifest_digest(value: CalibrationBundleManifest | Mapping[str, Any]) -> bytes:
    if isinstance(value, CalibrationBundleManifest):
        unsigned = value.model_dump(mode="json", by_alias=True)
    else:
        unsigned = dict(value)
    unsigned.pop("validator_signature", None)
    return hashlib.sha256(_MANIFEST_DOMAIN + canonical_json_bytes(unsigned)).digest()


def _canonical_json_mapping(data: bytes, label: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(decoded, Mapping) or canonical_json_bytes(decoded) != data:
        raise ValueError(f"{label} is not canonical JSON")
    return decoded


def _parse_canonical(
    data: bytes,
    model: type[StrictProtocolModel],
    label: str,
) -> StrictProtocolModel:
    decoded = _canonical_json_mapping(data, label)
    try:
        return model.model_validate(decoded)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is structurally invalid") from error


def _validate_write_inputs(
    *,
    root: Path,
    policy: ScoringPolicy,
    weight_commit_close_snapshot: FinalizedSnapshotRef,
    audit_release_snapshot: FinalizedSnapshotRef,
    maximum_object_bytes: int,
    maximum_bundle_bytes: int,
) -> None:
    _validate_ceiling(maximum_object_bytes, MAX_CALIBRATION_OBJECT_BYTES, "object")
    _validate_ceiling(maximum_bundle_bytes, MAX_CALIBRATION_BUNDLE_BYTES, "bundle")
    if not isinstance(root, Path):
        raise TypeError("calibration bundle root must be a Path")
    if root.exists() and (root.is_symlink() or not root.is_dir() or any(root.iterdir())):
        raise FileExistsError("calibration bundle output must be an empty directory")
    if not isinstance(policy, ScoringPolicy) or policy.translation_weights_active:
        raise ValueError("calibration bundle requires the exact inactive scoring policy")
    if not isinstance(weight_commit_close_snapshot, FinalizedSnapshotRef) or not isinstance(
        audit_release_snapshot, FinalizedSnapshotRef
    ):
        raise TypeError("release boundaries must be finalized snapshot references")


def _validate_ceiling(value: int, hard_maximum: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"calibration {label} ceiling must be an integer")
    if value <= 0 or value > hard_maximum:
        raise ValueError(f"calibration {label} ceiling exceeds its hard protocol bound")


def _fixed_point_manifest_size(
    base: Mapping[str, Any],
    *,
    object_bytes: int,
    signature: Mapping[str, Any],
) -> int:
    size = 1
    for _ in range(32):
        value = {
            **base,
            "audit_bundle_bytes": object_bytes + size,
            "validator_signature": signature,
        }
        next_size = len(canonical_json_bytes(value))
        if next_size == size:
            return size
        size = next_size
    raise RuntimeError("calibration manifest size did not reach a fixed point")


def _require_exact_bundle_paths(root: Path, expected_digests: set[str]) -> None:
    if {entry.name for entry in root.iterdir()} != {"manifest.json", "objects"}:
        raise ValueError("calibration bundle contains an unexpected top-level path")
    objects = root / "objects"
    if objects.is_symlink() or not objects.is_dir():
        raise ValueError("calibration objects path must be a real directory")
    if {entry.name for entry in objects.iterdir()} != expected_digests:
        raise ValueError("calibration object directory is not the exact manifest object set")


__all__ = [
    "CALIBRATION_BUNDLE_SCHEMA",
    "CALIBRATION_SCAN_MEDIA_TYPE",
    "CALIBRATION_SCAN_SCHEMA",
    "CALIBRATION_STAGE_MEDIA_TYPE",
    "CALIBRATION_STAGE_SCHEMA",
    "CALIBRATION_TERMINAL",
    "CALIBRATION_TERMINAL_MEDIA_TYPE",
    "CALIBRATION_TERMINAL_SCHEMA",
    "MAX_CALIBRATION_BUNDLE_BYTES",
    "MAX_CALIBRATION_OBJECT_BYTES",
    "STAGE_IDS",
    "CalibrationBundleManifest",
    "CalibrationNoWeightTerminalEvidence",
    "CalibrationObject",
    "CalibrationObjectInput",
    "CalibrationStageEvidence",
    "CalibrationStageInput",
    "CalibrationStageRecord",
    "CalibrationVerificationPorts",
    "FinalityReplayBindingObject",
    "FinalizedBlockEvidenceObject",
    "FinalizedNoWeightScanObject",
    "GrandpaFinalityReplayVerifier",
    "RuntimePinObject",
    "ValidatorManifestSignature",
    "VerifiedCalibrationBundle",
    "build_bittensor_runtime_context",
    "calibration_stage_replay_hook_id",
    "replay_finalized_no_weight_scan",
    "verify_calibration_bundle",
    "write_calibration_bundle",
]
