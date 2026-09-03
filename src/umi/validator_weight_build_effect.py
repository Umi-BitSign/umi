"""Proof-bound shadow weight construction for UMI protocol version 0.1.

This module is intentionally incapable of submitting weights.  It consumes one
authoritative reveal receipt, the atomically advanced protocol-state database,
an observed Section 10.3 schedule, and one historical finalized storage
snapshot at the observed commit-open block.  Scores and utilities are recomputed
from the durable rolling queue; neither a score nor a vector can enter through a
port.

The resulting stage receipt is self-contained for score, mapping, schedule, and
row replay.  Trie proofs are retained in full and the replay entry point requires
an explicit proof verifier, so digest integrity is never presented as storage
proof verification.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Any, Literal, Protocol

import bittensor as bt
import bittensor_core
from pydantic import Field, JsonValue, ValidationError, model_validator
from typing_extensions import Self

from .chain_evidence import FinalizedSnapshotRef, StorageEvidence
from .encoding import account_id32
from .policy import SCORING_POLICY_MEDIA_TYPE, ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .rolling import AssignmentScore, MinerScore, RollingScoreState, ScoredBatch, WeightBuild
from .validator_adapters import CompleteStageEffect, StageEffectResult, TerminalStageEffect
from .validator_chain import (
    DecodedStorageClaim,
    FinalizedRuntimePin,
    MultiStorageEvidence,
    MultiStorageProofVerifier,
    PinnedRuntimeContext,
    StorageClaim,
    StorageReadSpec,
    VerifiedStorageBatch,
    VerifiedStorageRead,
)
from .validator_chain_scan import VerifiedFinalizedBlockIdentity
from .validator_journal import (
    MAX_JOURNAL_OBJECT_BYTES,
    STAGE_RECEIPT_MEDIA_TYPE,
    StageJournalRecord,
    StageObjectInput,
    StageReceipt,
    ValidatorStageJournal,
)
from .validator_protocol_state import (
    ProtocolStateSnapshot,
    ValidatorProtocolStateStore,
)
from .validator_reveal_effect import (
    resolve_reveal_receipt,
    resolve_reveal_stage_record,
)
from .validator_state import StagePending, StageWorkItem, TerminalOutcome, WindowStage
from .validator_weight_schedule import (
    VerifiedWeightScheduleObservation,
    WeightCommitSchedule,
    WeightCommitSchedulePending,
    WeightScheduleIdentity,
    derive_weight_commit_schedule,
)
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

WEIGHT_BUILD_STAGE_SCHEMA = "umi-validator-weight-build-stage/1"
WEIGHT_BUILD_RESULT_SCHEMA = "umi-validator-weight-build-result/1"
WEIGHT_BUILD_STATE_SCHEMA = "umi-validator-weight-build-state/1"
WEIGHT_BUILD_SNAPSHOT_SCHEMA = "umi-validator-weight-build-snapshot/1"
WEIGHT_BUILD_PROOF_SCHEMA = "umi-validator-weight-build-proof/1"
WEIGHT_COMMIT_SCHEDULE_SCHEMA = "umi-validator-weight-commit-schedule/1"

REVEAL_STAGE_SCHEMA = "umi-validator-reveal-stage/1"
PROTOCOL_STATE_RESULT_SCHEMA = "umi-validator-protocol-state-result/1"

MAX_WEIGHT_BUILD_PROOF_BYTES = 128 * 1024 * 1024
MAX_WEIGHT_BUILD_STATE_BYTES = 128 * 1024 * 1024
MAX_WEIGHT_BUILD_ASSIGNMENTS = 262_144
MAX_WEIGHT_BUILD_ROOTS = 65_536
MAX_WEIGHT_BUILD_PROOF_BATCHES = 256
MAX_STORAGE_CLAIMS_PER_BATCH = 4_096
MAX_STORAGE_PROOF_NODES = 4_096
MAX_STORAGE_NODE_BYTES = 2 * 1024 * 1024
MAX_RUNTIME_METADATA_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_VERSION_BYTES = 64 * 1024
MAX_FINALITY_ATTESTATION_BYTES = 16 * 1024 * 1024
MAX_STORAGE_KEY_BYTES = 512
MAX_STORAGE_VALUE_BYTES = 16 * 1024 * 1024
MAX_PARAMETER_TEXT_BYTES = 512
_MAX_U64 = (1 << 64) - 1
_MAX_U16 = (1 << 16) - 1
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")

_PALLET = "SubtensorModule"
_NETWORKS_ADDED = "NetworksAdded"
_MECHANISM_COUNT = "MechanismCountCurrent"
_SUBNETWORK_N = "SubnetworkN"
_MIN_ALLOWED_WEIGHTS = "MinAllowedWeights"
_MAX_WEIGHTS_LIMIT = "MaxWeightsLimit"
_WEIGHTS_VERSION_KEY = "WeightsVersionKey"
_VALIDATOR_PERMIT = "ValidatorPermit"
_UIDS = "Uids"
_KEYS = "Keys"
_HOTKEY_SUCCESSOR = "HotkeySuccessor"
_HOTKEY_ROOT = "HotkeyRoot"
_WEIGHTS = "Weights"
_LAST_UPDATE = "LastUpdate"
_ACTIVITY_CUTOFF = "ActivityCutoffFactorMilli"
_TEMPO = "Tempo"


class WeightBuildEffectError(RuntimeError):
    """A shadow weight build cannot be reproduced safely."""


class WeightBuildBindingError(WeightBuildEffectError):
    """Typed evidence is valid in isolation but bound to another fact."""


class WeightBuildLimitError(WeightBuildEffectError):
    """Weight-build evidence exceeds a fail-closed local ceiling."""


class WeightBuildPending(StagePending, WeightBuildEffectError):
    """Finalized observations needed for the deterministic build are not ready."""


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BlockHash = Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
HexBytes = Annotated[str, Field(pattern=r"^0x(?:[0-9a-f]{2})*$")]
StorageParameter = int | str


class WeightBuildObjectRef(StrictProtocolModel):
    sha256: Hex32
    media_type: Literal[
        "application/json",
        "application/octet-stream",
        "application/vnd.umi.scoring-policy+json",
        "application/vnd.umi.validator-stage-receipt+json",
    ]
    size_bytes: Annotated[int, Field(ge=0, le=MAX_JOURNAL_OBJECT_BYTES)]


class _FractionValue(StrictProtocolModel):
    numerator: Annotated[
        str,
        Field(min_length=1, max_length=256, pattern=r"^-?(0|[1-9][0-9]*)$"),
    ]
    denominator: Annotated[
        str,
        Field(min_length=1, max_length=256, pattern=r"^[1-9][0-9]*$"),
    ]

    @property
    def fraction(self) -> Fraction:
        return Fraction(int(self.numerator), int(self.denominator))


class _AssignmentState(StrictProtocolModel):
    miner_root: Hex32
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)]
    request_leaf: Hex32
    stratum: Literal["fingerspelling", "short_utterance", "continuous"]
    canary: bool
    score: _FractionValue | None

    @model_validator(mode="after")
    def validate_score(self) -> Self:
        if self.canary != (self.score is None):
            raise ValueError("canary and score fields disagree")
        if self.score is not None and not 0 <= self.score.fraction <= 1:
            raise ValueError("assignment score is outside the unit interval")
        return self


class _BatchState(StrictProtocolModel):
    window_index: Annotated[int, Field(ge=0)]
    batch_rank: Hex32
    pool_leaf: Hex32
    challenge_ids: list[str]
    miner_roots: list[Hex32]
    assignments: Annotated[list[_AssignmentState], Field(max_length=MAX_WEIGHT_BUILD_ASSIGNMENTS)]


class WeightBuildStateEvidence(StrictProtocolModel):
    schema_: Literal[WEIGHT_BUILD_STATE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    state_digest: Hex32
    rolling_state_sha256: Hex32
    rolling_batches: list[_BatchState]


class _RuntimeEvidence(StrictProtocolModel):
    metadata_sha256: Hex32
    spec_version: Annotated[int, Field(gt=0)]
    transaction_version: Annotated[int, Field(gt=0)]
    state_version: Literal[1]
    ss58_prefix: Literal[42]
    metadata: HexBytes
    runtime_version: HexBytes

    @model_validator(mode="after")
    def validate_bytes(self) -> Self:
        metadata = _unhex(self.metadata, "runtime_metadata_invalid")
        version = _unhex(self.runtime_version, "runtime_version_invalid")
        if not metadata or len(metadata) > MAX_RUNTIME_METADATA_BYTES:
            raise ValueError("runtime metadata exceeds its byte ceiling")
        if not version or len(version) > MAX_RUNTIME_VERSION_BYTES:
            raise ValueError("runtime version exceeds its byte ceiling")
        if hashlib.sha256(metadata).hexdigest() != self.metadata_sha256:
            raise ValueError("runtime metadata digest does not reproduce")
        return self


class _FinalityIdentityEvidence(StrictProtocolModel):
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    parent_block_number: Annotated[int, Field(ge=0)]
    parent_block_hash: BlockHash
    parent_parent_hash: BlockHash
    parent_state_root: BlockHash
    state_root: BlockHash
    extrinsics_root: BlockHash
    finality_verifier_sha256: Hex32
    finality_evidence_sha256: Hex32

    @model_validator(mode="after")
    def validate_parent(self) -> Self:
        if self.parent_block_number + 1 != self.block_number:
            raise ValueError("finality parent is not adjacent")
        return self


class _StorageClaimEvidence(StrictProtocolModel):
    pallet: Annotated[str, Field(min_length=1, max_length=128)]
    item: Annotated[str, Field(min_length=1, max_length=128)]
    params: Annotated[list[StorageParameter], Field(max_length=4)]
    storage_key: HexBytes
    raw_value: HexBytes | None

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        key = _unhex(self.storage_key, "storage_key_invalid")
        if not key or len(key) > MAX_STORAGE_KEY_BYTES:
            raise ValueError("storage key exceeds its byte ceiling")
        if (
            self.raw_value is not None
            and len(_unhex(self.raw_value, "storage_value_invalid")) > MAX_STORAGE_VALUE_BYTES
        ):
            raise ValueError("storage value exceeds its byte ceiling")
        for value in self.params:
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError("storage parameter has another type")
            if isinstance(value, int) and value < 0:
                raise ValueError("storage integer parameter is negative")
            if isinstance(value, str) and len(value.encode()) > MAX_PARAMETER_TEXT_BYTES:
                raise ValueError("storage text parameter exceeds its byte ceiling")
        return self


class _StorageProofBatchEvidence(StrictProtocolModel):
    claims: Annotated[
        list[_StorageClaimEvidence],
        Field(min_length=1, max_length=MAX_STORAGE_CLAIMS_PER_BATCH),
    ]
    proof_nodes: Annotated[
        list[HexBytes],
        Field(min_length=1, max_length=MAX_STORAGE_PROOF_NODES),
    ]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        keys = [_unhex(item.storage_key, "storage_key_invalid") for item in self.claims]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("proof claims are not unique and sorted")
        nodes = [_unhex(item, "proof_node_invalid") for item in self.proof_nodes]
        if any(not node or len(node) > MAX_STORAGE_NODE_BYTES for node in nodes):
            raise ValueError("proof node is empty or oversized")
        if len(set(nodes)) != len(nodes):
            raise ValueError("proof batch contains duplicate nodes")
        return self


class WeightBuildProofEvidence(StrictProtocolModel):
    schema_: Literal[WEIGHT_BUILD_PROOF_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    chain_genesis_hash: Hex32
    timestamp_ms: Annotated[int, Field(ge=0)]
    identity: _FinalityIdentityEvidence
    finality_attestation: HexBytes
    runtime: _RuntimeEvidence
    requested_roots: Annotated[list[Hex32], Field(max_length=MAX_WEIGHT_BUILD_ROOTS)]
    proof_batches: Annotated[
        list[_StorageProofBatchEvidence],
        Field(min_length=1, max_length=MAX_WEIGHT_BUILD_PROOF_BATCHES),
    ]
    total_unique_storage_keys: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        attestation = _unhex(self.finality_attestation, "finality_attestation_invalid")
        if not attestation or len(attestation) > MAX_FINALITY_ATTESTATION_BYTES:
            raise ValueError("finality attestation exceeds its byte ceiling")
        if hashlib.sha256(attestation).hexdigest() != self.identity.finality_evidence_sha256:
            raise ValueError("finality attestation digest does not reproduce")
        if self.requested_roots != sorted(set(self.requested_roots)):
            raise ValueError("requested roots are not unique and sorted")
        keys = [claim.storage_key for batch in self.proof_batches for claim in batch.claims]
        if len(keys) != self.total_unique_storage_keys or len(set(keys)) != len(keys):
            raise ValueError("proof batches do not form one unique storage-key set")
        return self


class _ScheduleObservationEvidence(StrictProtocolModel):
    timestamp_ms: Annotated[int, Field(ge=0)]
    chain_genesis_hash: Hex32
    identity: _FinalityIdentityEvidence
    finality_attestation: HexBytes
    epoch_claim: _StorageClaimEvidence
    proof_nodes: Annotated[
        list[HexBytes],
        Field(min_length=1, max_length=MAX_STORAGE_PROOF_NODES),
    ]
    subnet_epoch_index: Annotated[int, Field(ge=0, le=_MAX_U64)]


class WeightCommitScheduleEvidence(StrictProtocolModel):
    schema_: Literal[WEIGHT_COMMIT_SCHEDULE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    netuid: Literal[78]
    window_id: Hex32
    scoring_policy_hash: Hex32
    runtime: _RuntimeEvidence
    reveal_round: Annotated[int, Field(gt=0)]
    reveal_time_ms: Annotated[int, Field(gt=0)]
    weight_commit_buffer_blocks: Annotated[int, Field(gt=0)]
    weight_commit_submission_blocks: Annotated[int, Field(gt=0)]
    observations: Annotated[list[_ScheduleObservationEvidence], Field(min_length=2)]
    reveal_observation_block: Annotated[int, Field(gt=0)]
    weight_commit_ready_height: Annotated[int, Field(gt=0)]
    base_epoch_block: Annotated[int, Field(gt=0)]
    base_epoch_index: Annotated[int, Field(ge=0)]
    weight_commit_open_block: Annotated[int, Field(gt=0)]
    weight_commit_open_block_hash: BlockHash
    weight_commit_epoch_index: Annotated[int, Field(gt=0)]
    weight_commit_close_block: Annotated[int, Field(gt=0)]
    weight_commit_close_block_hash: BlockHash
    weight_commit_close_state_root: BlockHash
    weight_commit_close_timestamp_ms: Annotated[int, Field(ge=0)]


class _RootMappingResult(StrictProtocolModel):
    miner_root: Hex32
    successor_hotkey: Hex32
    uid: Annotated[int, Field(ge=0, le=_MAX_U16)] | None
    status: Literal["eligible", "unresolved", "ineligible"]
    reason_code: str | None

    @model_validator(mode="after")
    def validate_reason(self) -> Self:
        if (self.status == "eligible") == (self.reason_code is not None):
            raise ValueError("mapping status and reason code disagree")
        if self.status == "eligible" and self.uid is None:
            raise ValueError("eligible mapping lacks a UID")
        if self.status != "eligible" and self.uid is not None:
            raise ValueError("ineligible mapping carries a UID")
        return self


class WeightBuildSnapshotEvidence(StrictProtocolModel):
    schema_: Literal[WEIGHT_BUILD_SNAPSHOT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    state_root: BlockHash
    runtime_metadata_sha256: Hex32
    runtime_spec_version: Annotated[int, Field(gt=0)]
    transaction_version: Annotated[int, Field(gt=0)]
    network_added: Literal[True]
    mechanism_count: Literal[1]
    uid_count: Annotated[int, Field(gt=0, le=65_536)]
    min_allowed_weights: Annotated[int, Field(gt=0, le=65_536)]
    maximum_weight_limit_u16: Annotated[int, Field(gt=0, le=_MAX_U16)]
    weights_version_key: Annotated[int, Field(ge=0, le=_MAX_U64)]
    validator_hotkey: Hex32
    validator_uid: Annotated[int, Field(ge=0, le=_MAX_U16)]
    validator_permit: Literal[True]
    existing_mechid0_row: list[list[int]]
    last_update: Annotated[int, Field(ge=0, le=_MAX_U64)]
    activity_cutoff_factor_milli: Annotated[int, Field(ge=0, le=_MAX_U64)]
    tempo: Annotated[int, Field(gt=0, le=_MAX_U16)]
    activity_cutoff_blocks: Annotated[int, Field(gt=0, le=_MAX_U64)]
    prior_row_classification: Literal["empty", "previous_row_active", "previous_row_inactive"]
    mappings: list[_RootMappingResult]
    proof_evidence_sha256: Hex32

    @model_validator(mode="after")
    def validate_rows(self) -> Self:
        uids = [item[0] for item in self.existing_mechid0_row]
        if uids != sorted(set(uids)):
            raise ValueError("existing row UIDs are not unique and sorted")
        if any(
            len(item) != 2 or not 0 <= item[0] <= _MAX_U16 or not 0 <= item[1] <= _MAX_U16
            for item in self.existing_mechid0_row
        ):
            raise ValueError("existing row weight is outside u16")
        roots = [item.miner_root for item in self.mappings]
        if roots != sorted(set(roots)):
            raise ValueError("mapping roots are not unique and sorted")
        active = self.last_update + self.activity_cutoff_blocks >= self.block_number
        expected = (
            "empty"
            if not self.existing_mechid0_row
            else "previous_row_active"
            if active
            else "previous_row_inactive"
        )
        if self.prior_row_classification != expected:
            raise ValueError("prior row classification does not reproduce")
        return self


class _MinerScoreResult(StrictProtocolModel):
    miner_root: Hex32
    assigned_clips: Annotated[int, Field(ge=0)]
    stratum_counts: dict[str, int]
    stratum_means: dict[str, _FractionValue]
    accuracy: _FractionValue
    eligible: bool
    utility: _FractionValue


class _VectorValue(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=_MAX_U16)] | None = None
    miner_root: Hex32 | None = None
    weight: _FractionValue

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (self.uid is None) == (self.miner_root is None):
            raise ValueError("vector value must identify exactly one root or UID")
        return self


class WeightBuildResultEvidence(StrictProtocolModel):
    schema_: Literal[WEIGHT_BUILD_RESULT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    protocol_state_digest: Hex32
    weight_build_block: Annotated[int, Field(gt=0)]
    weight_build_block_hash: BlockHash
    min_allowed_weights: Annotated[int, Field(gt=0)]
    maximum_weight_limit_u16: Annotated[int, Field(gt=0, le=_MAX_U16)]
    quality_floor: _FractionValue
    minimum_assigned_clips: Annotated[int, Field(gt=0)]
    minimum_clips_per_stratum: Annotated[int, Field(gt=0)]
    miner_scores: list[_MinerScoreResult]
    root_vector: list[_VectorValue]
    uid_vector: list[_VectorValue]
    quantized_row: list[list[int]]
    projected_row_sha256: Hex32
    terminal_reason_code: str | None
    translation_weights_active: Literal[False]

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        encoded = canonical_json_bytes(
            [{"uid": item[0], "value": item[1]} for item in self.quantized_row]
        )
        if hashlib.sha256(encoded).hexdigest() != self.projected_row_sha256:
            raise ValueError("projected row digest does not reproduce")
        if bool(self.quantized_row) == (self.terminal_reason_code is not None):
            raise ValueError("projected row and terminal reason disagree")
        return self


class WeightBuildStageManifest(StrictProtocolModel):
    schema_: Literal[WEIGHT_BUILD_STAGE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    reveal_stage_receipt: WeightBuildObjectRef
    reveal_stage_manifest: WeightBuildObjectRef
    protocol_transition_result: WeightBuildObjectRef
    policy_object: WeightBuildObjectRef
    protocol_state: WeightBuildObjectRef
    weight_commit_schedule: WeightBuildObjectRef
    weight_build_proof: WeightBuildObjectRef
    weight_build_snapshot: WeightBuildObjectRef
    weight_build_result: WeightBuildObjectRef


@dataclass(frozen=True, slots=True)
class WeightScheduleCapture:
    """Proof-bearing finalized interval supplied by a read-only schedule port."""

    observations: tuple[VerifiedWeightScheduleObservation, ...]
    identity: WeightScheduleIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.observations, tuple) or any(
            not isinstance(item, VerifiedWeightScheduleObservation) for item in self.observations
        ):
            raise TypeError("schedule observations must be a tuple of verified observations")
        if not isinstance(self.identity, WeightScheduleIdentity):
            raise TypeError("schedule identity must be WeightScheduleIdentity")


@dataclass(frozen=True, slots=True)
class VerifiedWeightBuildSnapshot:
    """One exact finalized state plus all proof-backed reads used by the build."""

    identity: VerifiedFinalizedBlockIdentity
    timestamp_ms: int
    chain_genesis_hash: str
    finality_attestation: bytes
    storage_batches: tuple[VerifiedStorageBatch, ...]
    requested_roots: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.identity, VerifiedFinalizedBlockIdentity):
            raise TypeError("snapshot identity must be VerifiedFinalizedBlockIdentity")
        _uint(self.timestamp_ms, "snapshot timestamp")
        _hex32(self.chain_genesis_hash, "snapshot chain genesis")
        if not isinstance(self.finality_attestation, bytes) or not self.finality_attestation:
            raise ValueError("snapshot finality attestation must be nonempty exact bytes")
        if len(self.finality_attestation) > MAX_FINALITY_ATTESTATION_BYTES:
            raise WeightBuildLimitError("snapshot finality attestation is oversized")
        if hashlib.sha256(self.finality_attestation).hexdigest() != (
            self.identity.finality_evidence_sha256
        ):
            raise ValueError("snapshot finality attestation digest does not reproduce")
        if not isinstance(self.storage_batches, tuple) or not self.storage_batches:
            raise ValueError("snapshot must contain proof-backed storage batches")
        if any(not isinstance(item, VerifiedStorageBatch) for item in self.storage_batches):
            raise TypeError("snapshot storage batches must be VerifiedStorageBatch values")
        if any(item.runtime.snapshot != self.identity.snapshot for item in self.storage_batches):
            raise ValueError("snapshot proof batch binds another finalized block")
        pins = {item.runtime.pin for item in self.storage_batches}
        if len(pins) != 1:
            raise ValueError("snapshot proof batches use different runtime identities")
        roots = tuple(account_id32(root) for root in self.requested_roots)
        if roots != tuple(sorted(set(roots))):
            raise ValueError("snapshot requested roots must be unique and sorted")
        object.__setattr__(self, "requested_roots", roots)

    @property
    def runtime(self) -> PinnedRuntimeContext:
        return self.storage_batches[0].runtime


class WeightSchedulePort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
    ) -> WeightScheduleCapture | Awaitable[WeightScheduleCapture]: ...


class WeightBuildSnapshotPort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
        positive_roots: tuple[bytes, ...],
        schedule: WeightCommitSchedule,
    ) -> VerifiedWeightBuildSnapshot | Awaitable[VerifiedWeightBuildSnapshot]: ...


@dataclass(frozen=True, slots=True)
class WeightBuildEffectPorts:
    schedule: WeightSchedulePort
    snapshot: WeightBuildSnapshotPort

    def __post_init__(self) -> None:
        if not callable(self.schedule) or not callable(self.snapshot):
            raise TypeError("weight-build ports must be callable")


@dataclass(frozen=True, slots=True)
class _DecodedSnapshot:
    evidence: WeightBuildSnapshotEvidence
    uid_by_root: dict[bytes, int | None]


@dataclass(frozen=True, slots=True)
class WeightBuildReplay:
    window_id: str
    schedule: WeightCommitSchedule
    snapshot: WeightBuildSnapshotEvidence
    result: WeightBuildResultEvidence
    weight_build: WeightBuild | None
    rolling_state: RollingScoreState


@dataclass(frozen=True, slots=True)
class ProofBackedWeightScheduleMaterial:
    """Minimal replayable schedule slice shared by terminal-stage adapters."""

    schedule: WeightCommitSchedule
    observations: tuple[VerifiedWeightScheduleObservation, ...]
    evidence: WeightCommitScheduleEvidence
    evidence_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.schedule, WeightCommitSchedule):
            raise TypeError("schedule material requires a complete schedule")
        if (
            not isinstance(self.observations, tuple)
            or not self.observations
            or any(
                not isinstance(item, VerifiedWeightScheduleObservation)
                for item in self.observations
            )
        ):
            raise TypeError("schedule material observations are invalid")
        if not isinstance(self.evidence, WeightCommitScheduleEvidence):
            raise TypeError("schedule material evidence has another type")
        if canonical_json_bytes(self.evidence) != self.evidence_bytes:
            raise ValueError("schedule material bytes are not canonical evidence")


@dataclass(frozen=True, slots=True)
class _RevealBinding:
    record: StageJournalRecord
    manifest_bytes: bytes
    transition_result_bytes: bytes
    source_objects: tuple[StageObjectInput, ...]


class ShadowWeightBuildEffect:
    """Complete ``WEIGHT_BUILD`` effect for the hard shadow-only policy."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        journal: ValidatorStageJournal,
        protocol_state: ValidatorProtocolStateStore,
        ports: WeightBuildEffectPorts,
        validator_hotkey: str | bytes,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("weight-build policy must be ScoringPolicy")
        if policy.translation_weights_active is not False:
            raise ValueError("this effect is shadow-only")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be ValidatorStageJournal")
        if not isinstance(protocol_state, ValidatorProtocolStateStore):
            raise TypeError("protocol_state must be ValidatorProtocolStateStore")
        if not isinstance(ports, WeightBuildEffectPorts):
            raise TypeError("ports must be WeightBuildEffectPorts")
        validator = account_id32(validator_hotkey)
        if validator not in {
            account_id32(item.validator_hotkey) for item in policy.validator_registry
        }:
            raise ValueError("weight-build validator is absent from the policy registry")
        if policy.implementation_pins.pin_profile != "live_shadow_calibration":
            raise ValueError("production weight build requires a live-shadow policy")
        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self.journal = journal
        self.protocol_state = protocol_state
        self.ports = ports
        self.validator_hotkey = validator

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        if not isinstance(work, StageWorkItem) or work.stage is not WindowStage.WEIGHT_BUILD:
            raise WeightBuildBindingError("weight_build_effect_received_wrong_stage")
        window = work.window.plan
        if window.scoring_policy_hash != self.policy_hash:
            raise WeightBuildBindingError("weight_build_policy_binding_mismatch")

        state = self.protocol_state.audit()
        reveal = _load_reveal_binding(self.journal, work, state, self.policy)
        rolling = state.rolling_scores
        scores = rolling.miner_scores(
            minimum_assigned_clips=self.policy.limits.minimum_assigned_clips,
            minimum_clips_per_stratum=self.policy.limits.minimum_clips_per_stratum,
            quality_floor=self.policy.thresholds.quality_floor.fraction,
        )
        positive_roots = tuple(score.miner_root for score in scores if score.utility > 0)

        capture = await _await_value(self.ports.schedule(work))
        if not isinstance(capture, WeightScheduleCapture):
            raise WeightBuildBindingError("weight_schedule_port_returned_another_type")
        _validate_schedule_identity(capture.identity, self.policy)
        reveal_time_ms = QUICKNET_GENESIS_MS + (window.reveal_round - 1) * QUICKNET_PERIOD_MS
        schedule_value = derive_weight_commit_schedule(
            capture.observations,
            identity=capture.identity,
            reveal_time_ms=reveal_time_ms,
            weight_commit_buffer_blocks=self.policy.clock.weight_commit_buffer_blocks,
            weight_commit_submission_blocks=self.policy.clock.weight_commit_submission_blocks,
        )
        if isinstance(schedule_value, WeightCommitSchedulePending):
            raise WeightBuildPending(schedule_value.reason_code)
        schedule, schedule_observations = _canonical_schedule_slice(
            capture.observations,
            schedule_value,
            identity=capture.identity,
            reveal_time_ms=reveal_time_ms,
            buffer_blocks=self.policy.clock.weight_commit_buffer_blocks,
            submission_blocks=self.policy.clock.weight_commit_submission_blocks,
        )

        snapshot = await _await_value(self.ports.snapshot(work, positive_roots, schedule))
        if not isinstance(snapshot, VerifiedWeightBuildSnapshot):
            raise WeightBuildBindingError("weight_snapshot_port_returned_another_type")
        if snapshot.requested_roots != positive_roots:
            raise WeightBuildBindingError("weight_snapshot_requested_roots_mismatch")
        if snapshot.identity.snapshot != schedule.weight_commit_open_block.snapshot:
            raise WeightBuildBindingError("weight_build_block_is_not_commit_open_block")
        if (
            snapshot.identity != schedule.weight_commit_open_block.identity
            or snapshot.timestamp_ms != schedule.weight_commit_open_block.timestamp_ms
            or snapshot.chain_genesis_hash != schedule.weight_commit_open_block.chain_genesis_hash
            or snapshot.finality_attestation
            != schedule.weight_commit_open_block.finality_attestation
            or snapshot.runtime.pin != schedule.weight_commit_open_block.runtime.pin
        ):
            raise WeightBuildBindingError("weight_build_snapshot_open_observation_mismatch")
        _validate_snapshot_identity(snapshot, capture.identity, self.policy)

        proof_model = _snapshot_proof_model(snapshot, work, self.policy_hash)
        proof_bytes = canonical_json_bytes(proof_model)
        if len(proof_bytes) > MAX_WEIGHT_BUILD_PROOF_BYTES:
            raise WeightBuildLimitError("weight_build_proof_size_limit")
        decoded = _decode_weight_snapshot(
            snapshot.storage_batches,
            requested_roots=positive_roots,
            validator_hotkey=self.validator_hotkey,
            block_number=snapshot.identity.snapshot.block_number,
            proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
            work=work,
            policy=self.policy,
        )

        minimum = decoded.evidence.min_allowed_weights
        terminal_reason: str | None = None
        built: WeightBuild | None = None
        if len(positive_roots) < minimum:
            terminal_reason = "positive_utilities_below_min_allowed_weights"
        else:
            resolved = sum(value is not None for value in decoded.uid_by_root.values())
            if resolved < minimum:
                terminal_reason = "resolved_destinations_below_min_allowed_weights"
            else:
                try:
                    built = rolling.build_weights(
                        minimum_assigned_clips=self.policy.limits.minimum_assigned_clips,
                        minimum_clips_per_stratum=self.policy.limits.minimum_clips_per_stratum,
                        quality_floor=self.policy.thresholds.quality_floor.fraction,
                        uid_by_root=decoded.uid_by_root,
                        minimum_positive_weights=minimum,
                        maximum_weight_limit_u16=decoded.evidence.maximum_weight_limit_u16,
                    )
                except ValueError as error:
                    raise WeightBuildBindingError(
                        "weight_normalization_or_quantization_failed"
                    ) from error

        state_model = _state_model(state, work)
        state_bytes = canonical_json_bytes(state_model)
        if len(state_bytes) > MAX_WEIGHT_BUILD_STATE_BYTES:
            raise WeightBuildLimitError("weight_build_state_size_limit")
        schedule_model = _schedule_model(
            schedule_observations,
            schedule,
            work=work,
            reveal_time_ms=reveal_time_ms,
            buffer_blocks=self.policy.clock.weight_commit_buffer_blocks,
            submission_blocks=self.policy.clock.weight_commit_submission_blocks,
        )
        schedule_bytes = canonical_json_bytes(schedule_model)
        snapshot_bytes = canonical_json_bytes(decoded.evidence)
        result_model = _result_model(
            state=state,
            scores=scores,
            built=built,
            terminal_reason=terminal_reason,
            snapshot=decoded.evidence,
            work=work,
            policy=self.policy,
        )
        result_bytes = canonical_json_bytes(result_model)

        policy_bytes = canonical_json_bytes(self.policy)
        reveal_receipt_bytes = reveal.record.receipt_bytes
        refs = {
            "reveal_stage_receipt": _object_ref(
                reveal_receipt_bytes,
                STAGE_RECEIPT_MEDIA_TYPE,
            ),
            "reveal_stage_manifest": _object_ref(reveal.manifest_bytes, "application/json"),
            "protocol_transition_result": _object_ref(
                reveal.transition_result_bytes,
                "application/json",
            ),
            "policy_object": _object_ref(policy_bytes, SCORING_POLICY_MEDIA_TYPE),
            "protocol_state": _object_ref(state_bytes, "application/json"),
            "weight_commit_schedule": _object_ref(schedule_bytes, "application/json"),
            "weight_build_proof": _object_ref(proof_bytes, "application/json"),
            "weight_build_snapshot": _object_ref(snapshot_bytes, "application/json"),
            "weight_build_result": _object_ref(result_bytes, "application/json"),
        }
        manifest = WeightBuildStageManifest(
            schema=WEIGHT_BUILD_STAGE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            operation_id=operation_id,
            window_id=window.window_id,
            window_index=window.window_index,
            scoring_policy_hash=self.policy_hash,
            **refs,
        )
        manifest_bytes = canonical_json_bytes(manifest)
        row_sha256 = result_model.projected_row_sha256
        objects = _unique_objects(
            (
                StageObjectInput(manifest_bytes, "application/json"),
                StageObjectInput(reveal_receipt_bytes, STAGE_RECEIPT_MEDIA_TYPE),
                StageObjectInput(reveal.manifest_bytes, "application/json"),
                StageObjectInput(reveal.transition_result_bytes, "application/json"),
                *reveal.source_objects,
                StageObjectInput(policy_bytes, SCORING_POLICY_MEDIA_TYPE),
                StageObjectInput(state_bytes, "application/json"),
                StageObjectInput(schedule_bytes, "application/json"),
                StageObjectInput(proof_bytes, "application/json"),
                StageObjectInput(snapshot_bytes, "application/json"),
                StageObjectInput(result_bytes, "application/json"),
            )
        )
        _preflight_journal_objects(self.journal, window.window_id, objects)
        metadata: dict[str, JsonValue] = {
            "weight_commit_schedule_sha256": hashlib.sha256(schedule_bytes).hexdigest(),
            "weight_commit_open_block": schedule.weight_commit_open_block.snapshot.block_number,
            "weight_commit_epoch_index": schedule.weight_commit_epoch_index,
            "weight_commit_close_block": schedule.weight_commit_close_block.snapshot.block_number,
            "weight_commit_close_block_hash": (
                schedule.weight_commit_close_block.snapshot.block_hash
            ),
            "weight_commit_close_state_root": (
                schedule.weight_commit_close_block.snapshot.state_root
            ),
            "weight_build_block": snapshot.identity.snapshot.block_number,
            "weight_build_block_hash": snapshot.identity.snapshot.block_hash,
            "projected_row_sha256": row_sha256,
            "translation_weights_active": False,
        }
        decision = (
            CompleteStageEffect()
            if terminal_reason is None
            else TerminalStageEffect(
                outcome=TerminalOutcome.SKIPPED,
                audit_release_block=schedule.weight_commit_close_block.snapshot.block_number,
                reason_code=terminal_reason,
            )
        )
        return StageEffectResult(
            operation_id=operation_id,
            window_id=window.window_id,
            stage=WindowStage.WEIGHT_BUILD,
            objects=objects,
            metadata=metadata,
            decision=decision,
        )


def replay_weight_build_stage_record(
    record: StageJournalRecord,
    journal: ValidatorStageJournal,
    *,
    verifier: MultiStorageProofVerifier,
) -> WeightBuildReplay:
    if not isinstance(record, StageJournalRecord):
        raise TypeError("record must be StageJournalRecord")
    payloads = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
    return replay_weight_build_stage_receipt(record.receipt, payloads, verifier=verifier)


def replay_weight_build_stage_receipt(
    receipt: StageReceipt,
    payloads: Mapping[str, bytes],
    *,
    verifier: MultiStorageProofVerifier,
) -> WeightBuildReplay:
    """Rebuild a projected row using only receipt payloads and a trie verifier."""

    if receipt.stage != WindowStage.WEIGHT_BUILD.value:
        raise WeightBuildBindingError("weight_build_replay_received_another_stage")
    objects = _ReceiptObjects(receipt, payloads)
    manifest, _manifest_bytes = objects.find_schema(
        WEIGHT_BUILD_STAGE_SCHEMA,
        WeightBuildStageManifest,
    )
    if manifest.window_id != receipt.window_id or manifest.operation_id != receipt.operation_id:
        raise WeightBuildBindingError("weight_build_manifest_receipt_mismatch")
    policy = _parse_canonical(
        objects.resolve(manifest.policy_object),
        ScoringPolicy,
        "weight-build policy",
    )
    if policy.translation_weights_active is not False:
        raise WeightBuildBindingError("weight_build_replay_policy_is_not_shadow")
    if scoring_policy_hash(policy) != manifest.scoring_policy_hash:
        raise WeightBuildBindingError("weight_build_replay_policy_hash_mismatch")
    state_model = _parse_canonical(
        objects.resolve(manifest.protocol_state),
        WeightBuildStateEvidence,
        "weight-build protocol state",
    )
    rolling = _rolling_from_state(state_model)
    _validate_reveal_graph_for_replay(objects, manifest, state_model)
    schedule_model = _parse_canonical(
        objects.resolve(manifest.weight_commit_schedule),
        WeightCommitScheduleEvidence,
        "weight commit schedule",
    )
    if (
        schedule_model.window_id != manifest.window_id
        or schedule_model.scoring_policy_hash != manifest.scoring_policy_hash
        or schedule_model.reveal_round <= 0
    ):
        raise WeightBuildBindingError("weight_schedule_manifest_binding_mismatch")
    _validate_schedule_model_policy(schedule_model, policy)
    schedule = _replay_schedule(schedule_model, verifier=verifier)
    proof_bytes = objects.resolve(manifest.weight_build_proof)
    proof_model = _parse_canonical(
        proof_bytes,
        WeightBuildProofEvidence,
        "weight-build proof",
    )
    if (
        proof_model.window_id != manifest.window_id
        or proof_model.window_index != manifest.window_index
        or proof_model.scoring_policy_hash != manifest.scoring_policy_hash
    ):
        raise WeightBuildBindingError("weight_build_proof_manifest_binding_mismatch")
    _validate_snapshot_proof_model_policy(proof_model, policy)
    snapshot = _replay_snapshot_proof(proof_bytes, verifier=verifier)
    summary = _parse_canonical(
        objects.resolve(manifest.weight_build_snapshot),
        WeightBuildSnapshotEvidence,
        "weight-build snapshot",
    )
    if hashlib.sha256(proof_bytes).hexdigest() != summary.proof_evidence_sha256:
        raise WeightBuildBindingError("weight_build_snapshot_proof_digest_mismatch")
    validator = bytes.fromhex(summary.validator_hotkey)
    decoded = _decode_weight_snapshot(
        snapshot.storage_batches,
        requested_roots=snapshot.requested_roots,
        validator_hotkey=validator,
        block_number=snapshot.identity.snapshot.block_number,
        proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
        work=None,
        policy=policy,
        window_id=manifest.window_id,
        window_index=manifest.window_index,
        scoring_policy_hash_value=manifest.scoring_policy_hash,
    )
    if decoded.evidence != summary:
        raise WeightBuildBindingError("weight_build_snapshot_summary_mismatch")
    result = _parse_canonical(
        objects.resolve(manifest.weight_build_result),
        WeightBuildResultEvidence,
        "weight-build result",
    )
    if (
        state_model.window_id != manifest.window_id
        or state_model.window_index != manifest.window_index
        or result.window_id != manifest.window_id
        or result.protocol_state_digest != state_model.state_digest
        or schedule.weight_commit_open_block.snapshot != snapshot.identity.snapshot
    ):
        raise WeightBuildBindingError("weight_build_replay_cross_object_binding_mismatch")

    scores = rolling.miner_scores(
        minimum_assigned_clips=policy.limits.minimum_assigned_clips,
        minimum_clips_per_stratum=policy.limits.minimum_clips_per_stratum,
        quality_floor=policy.thresholds.quality_floor.fraction,
    )
    if [_miner_score_model(item) for item in scores] != result.miner_scores:
        raise WeightBuildBindingError("weight_build_replay_score_mismatch")
    built: WeightBuild | None = None
    positive = tuple(item.miner_root for item in scores if item.utility > 0)
    reason: str | None = None
    if len(positive) < summary.min_allowed_weights:
        reason = "positive_utilities_below_min_allowed_weights"
    elif sum(value is not None for value in decoded.uid_by_root.values()) < (
        summary.min_allowed_weights
    ):
        reason = "resolved_destinations_below_min_allowed_weights"
    else:
        built = rolling.build_weights(
            minimum_assigned_clips=policy.limits.minimum_assigned_clips,
            minimum_clips_per_stratum=policy.limits.minimum_clips_per_stratum,
            quality_floor=policy.thresholds.quality_floor.fraction,
            uid_by_root=decoded.uid_by_root,
            minimum_positive_weights=summary.min_allowed_weights,
            maximum_weight_limit_u16=summary.maximum_weight_limit_u16,
        )
    expected_result = _result_model_from_values(
        state_digest=state_model.state_digest,
        scores=scores,
        built=built,
        terminal_reason=reason,
        snapshot=summary,
        window_id=manifest.window_id,
        window_index=manifest.window_index,
        policy_hash=manifest.scoring_policy_hash,
        policy=policy,
    )
    if expected_result != result:
        raise WeightBuildBindingError("weight_build_result_does_not_replay")
    _validate_receipt_metadata(
        receipt,
        schedule,
        snapshot,
        result,
        schedule_sha256=manifest.weight_commit_schedule.sha256,
    )
    return WeightBuildReplay(
        window_id=manifest.window_id,
        schedule=schedule,
        snapshot=summary,
        result=result,
        weight_build=built,
        rolling_state=rolling,
    )


async def _await_value(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase SHA-256 hexadecimal")
    return value


def _uint(value: object, label: str, *, maximum: int = _MAX_U64) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{label} must be an unsigned integer")
    return value


def _unhex(value: object, reason_code: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) % 2:
        raise WeightBuildBindingError(reason_code)
    try:
        return bytes.fromhex(value[2:])
    except ValueError as error:
        raise WeightBuildBindingError(reason_code) from error


def _hex(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("hex evidence requires exact bytes")
    return "0x" + value.hex()


def _object_ref(data: bytes, media_type: str) -> WeightBuildObjectRef:
    if not isinstance(data, bytes):
        raise TypeError("object reference requires exact bytes")
    return WeightBuildObjectRef(
        sha256=hashlib.sha256(data).hexdigest(),
        media_type=media_type,
        size_bytes=len(data),
    )


def _unique_objects(values: Sequence[StageObjectInput]) -> tuple[StageObjectInput, ...]:
    unique: dict[str, StageObjectInput] = {}
    for value in values:
        if not isinstance(value, StageObjectInput):
            raise TypeError("weight-build objects must be StageObjectInput values")
        digest = hashlib.sha256(value.data).hexdigest()
        prior = unique.setdefault(digest, value)
        if prior.media_type != value.media_type:
            raise WeightBuildBindingError("weight_build_object_media_type_conflict")
    return tuple(unique[key] for key in sorted(unique, key=bytes.fromhex))


def _preflight_journal_objects(
    journal: ValidatorStageJournal,
    window_id: str,
    objects: Sequence[StageObjectInput],
) -> None:
    sizes: dict[str, int] = {}
    for record in journal.load_window(window_id):
        for reference in record.receipt.objects:
            prior = sizes.setdefault(reference.sha256, reference.size_bytes)
            if prior != reference.size_bytes:
                raise WeightBuildBindingError("prior_journal_object_size_conflict")
    for item in objects:
        size = len(item.data)
        if size > journal.maximum_object_bytes:
            raise WeightBuildLimitError("weight_build_journal_object_size_limit")
        digest = hashlib.sha256(item.data).hexdigest()
        prior = sizes.setdefault(digest, size)
        if prior != size:
            raise WeightBuildBindingError("weight_build_object_size_conflict")
    if sum(sizes.values()) > journal.maximum_total_object_bytes:
        raise WeightBuildLimitError("weight_build_journal_total_size_limit")


def _fraction_model(value: Fraction) -> _FractionValue:
    if not isinstance(value, Fraction):
        raise TypeError("weight-build fractions must use exact Fraction values")
    return _FractionValue(numerator=str(value.numerator), denominator=str(value.denominator))


def _strict_json(data: bytes, label: str) -> Any:
    if not isinstance(data, bytes):
        raise TypeError(f"{label} must be exact bytes")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise WeightBuildBindingError(f"{label}_duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WeightBuildBindingError(f"{label}_invalid_json") from error


def _parse_canonical(data: bytes, model: type[Any], label: str) -> Any:
    decoded = _strict_json(data, label.replace(" ", "_"))
    try:
        value = model.model_validate(decoded)
    except (ValidationError, TypeError, ValueError) as error:
        raise WeightBuildBindingError(f"{label} is invalid") from error
    if canonical_json_bytes(value) != data:
        raise WeightBuildBindingError(f"{label} is not canonical JSON")
    return value


class _ReceiptObjects:
    def __init__(self, receipt: StageReceipt, payloads: Mapping[str, bytes]) -> None:
        if not isinstance(receipt, StageReceipt):
            raise TypeError("receipt must be StageReceipt")
        if not isinstance(payloads, Mapping):
            raise TypeError("payloads must be a mapping")
        expected = {item.sha256: item for item in receipt.objects}
        if set(payloads) != set(expected):
            raise WeightBuildBindingError("weight_build_receipt_object_graph_incomplete")
        self._payloads: dict[str, bytes] = {}
        self._references = expected
        for digest, reference in expected.items():
            data = payloads[digest]
            if not isinstance(data, bytes):
                raise TypeError("receipt payloads must be exact bytes")
            if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != digest:
                raise WeightBuildBindingError("weight_build_receipt_object_metadata_mismatch")
            self._payloads[digest] = data

    def resolve(self, reference: Any) -> bytes:
        try:
            normalized = WeightBuildObjectRef.model_validate(
                reference.model_dump(mode="json") if hasattr(reference, "model_dump") else reference
            )
        except (ValidationError, TypeError, ValueError) as error:
            raise WeightBuildBindingError("weight_build_object_reference_invalid") from error
        stored = self._references.get(normalized.sha256)
        if stored is None:
            raise WeightBuildBindingError("weight_build_referenced_object_missing")
        if stored.size_bytes != normalized.size_bytes or stored.media_type != normalized.media_type:
            raise WeightBuildBindingError("weight_build_referenced_object_metadata_mismatch")
        return self._payloads[normalized.sha256]

    def find_schema(self, schema: str, model: type[Any]) -> tuple[Any, bytes]:
        found: list[tuple[Any, bytes]] = []
        for digest, data in self._payloads.items():
            if self._references[digest].media_type != "application/json":
                continue
            decoded = _strict_json(data, "weight_build_receipt_object")
            if isinstance(decoded, dict) and decoded.get("schema") == schema:
                found.append((_parse_canonical(data, model, schema), data))
        if len(found) != 1:
            raise WeightBuildBindingError(f"receipt_requires_one_{schema.replace('/', '_')}")
        return found[0]


def _validate_schedule_identity(identity: WeightScheduleIdentity, policy: ScoringPolicy) -> None:
    pins = policy.implementation_pins
    live = pins.live_chain
    finality = pins.finality_verifier
    if live is None or finality is None:
        raise WeightBuildBindingError("weight_schedule_live_pins_missing")
    expected_runtime = FinalizedRuntimePin(
        metadata_sha256=live.metadata_sha256,
        spec_version=live.runtime_spec_version,
        transaction_version=live.transaction_version,
        state_version=live.state_version,
        ss58_prefix=42,
    )
    if (
        identity.netuid != policy.netuid
        or identity.chain_genesis_hash != live.genesis_block_hash
        or identity.runtime_pin != expected_runtime
        or identity.finality_verifier_sha256 not in set(finality.release_sha256_by_target.values())
    ):
        raise WeightBuildBindingError("weight_schedule_policy_identity_mismatch")


def _canonical_schedule_slice(
    observations: Sequence[VerifiedWeightScheduleObservation],
    schedule: WeightCommitSchedule,
    *,
    identity: WeightScheduleIdentity,
    reveal_time_ms: int,
    buffer_blocks: int,
    submission_blocks: int,
) -> tuple[WeightCommitSchedule, tuple[VerifiedWeightScheduleObservation, ...]]:
    ordered = tuple(observations)
    reveal_height = schedule.reveal_observation_block.snapshot.block_number
    close_height = schedule.weight_commit_close_block.snapshot.block_number
    start_height = reveal_height - 1
    selected = tuple(
        item for item in ordered if start_height <= item.snapshot.block_number <= close_height
    )
    if (
        not selected
        or selected[0].snapshot.block_number != start_height
        or selected[-1].snapshot.block_number != close_height
    ):
        raise WeightBuildBindingError("weight_schedule_canonical_history_missing")
    replayed = derive_weight_commit_schedule(
        selected,
        identity=identity,
        reveal_time_ms=reveal_time_ms,
        weight_commit_buffer_blocks=buffer_blocks,
        weight_commit_submission_blocks=submission_blocks,
    )
    if not isinstance(replayed, WeightCommitSchedule) or replayed != schedule:
        raise WeightBuildBindingError("weight_schedule_canonical_slice_mismatch")
    return replayed, selected


def materialize_weight_schedule_evidence(
    capture: WeightScheduleCapture,
    *,
    work: StageWorkItem,
    policy: ScoringPolicy,
) -> ProofBackedWeightScheduleMaterial | WeightCommitSchedulePending:
    """Derive the exact minimal schedule evidence for any stage of one window.

    The same proof-backed close boundary settles transcript incidents,
    reveal-time voids, and the ordinary shadow weight build.  Keeping the
    materialization here prevents those paths from implementing subtly
    different epoch or finality arithmetic.
    """

    if not isinstance(capture, WeightScheduleCapture):
        raise TypeError("schedule evidence requires WeightScheduleCapture")
    if not isinstance(work, StageWorkItem):
        raise TypeError("schedule evidence requires StageWorkItem")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("schedule evidence requires ScoringPolicy")
    if work.window.plan.scoring_policy_hash != scoring_policy_hash(policy):
        raise WeightBuildBindingError("weight_schedule_work_policy_mismatch")
    _validate_schedule_identity(capture.identity, policy)
    reveal_time_ms = QUICKNET_GENESIS_MS + (work.window.plan.reveal_round - 1) * QUICKNET_PERIOD_MS
    value = derive_weight_commit_schedule(
        capture.observations,
        identity=capture.identity,
        reveal_time_ms=reveal_time_ms,
        weight_commit_buffer_blocks=policy.clock.weight_commit_buffer_blocks,
        weight_commit_submission_blocks=policy.clock.weight_commit_submission_blocks,
    )
    if isinstance(value, WeightCommitSchedulePending):
        return value
    schedule, observations = _canonical_schedule_slice(
        capture.observations,
        value,
        identity=capture.identity,
        reveal_time_ms=reveal_time_ms,
        buffer_blocks=policy.clock.weight_commit_buffer_blocks,
        submission_blocks=policy.clock.weight_commit_submission_blocks,
    )
    model = _schedule_model(
        observations,
        schedule,
        work=work,
        reveal_time_ms=reveal_time_ms,
        buffer_blocks=policy.clock.weight_commit_buffer_blocks,
        submission_blocks=policy.clock.weight_commit_submission_blocks,
    )
    return ProofBackedWeightScheduleMaterial(
        schedule=schedule,
        observations=observations,
        evidence=model,
        evidence_bytes=canonical_json_bytes(model),
    )


def _runtime_model(runtime: PinnedRuntimeContext) -> _RuntimeEvidence:
    return _RuntimeEvidence(
        metadata_sha256=runtime.pin.metadata_sha256,
        spec_version=runtime.pin.spec_version,
        transaction_version=runtime.pin.transaction_version,
        state_version=runtime.pin.state_version,
        ss58_prefix=runtime.pin.ss58_prefix,
        metadata=_hex(runtime.metadata_bytes),
        runtime_version=_hex(runtime.runtime_version_bytes),
    )


def _identity_model(identity: VerifiedFinalizedBlockIdentity) -> _FinalityIdentityEvidence:
    return _FinalityIdentityEvidence(
        block_number=identity.snapshot.block_number,
        block_hash=identity.snapshot.block_hash,
        parent_block_number=identity.parent_snapshot.block_number,
        parent_block_hash=identity.parent_snapshot.block_hash,
        parent_parent_hash=identity.parent_snapshot.parent_hash,
        parent_state_root=identity.parent_snapshot.state_root,
        state_root=identity.snapshot.state_root,
        extrinsics_root=identity.extrinsics_root,
        finality_verifier_sha256=identity.finality_verifier_sha256,
        finality_evidence_sha256=identity.finality_evidence_sha256,
    )


def _canonical_param(value: Any) -> StorageParameter:
    if isinstance(value, bool):
        raise WeightBuildBindingError("storage_parameter_type_invalid")
    if isinstance(value, int):
        if value < 0:
            raise WeightBuildBindingError("storage_parameter_negative")
        return value
    if isinstance(value, bytes):
        try:
            return bt.sp_core.ss58_encode(account_id32(value))
        except Exception as error:
            raise WeightBuildBindingError("storage_account_parameter_invalid") from error
    if isinstance(value, str) and value and len(value.encode()) <= MAX_PARAMETER_TEXT_BYTES:
        return value
    raise WeightBuildBindingError("storage_parameter_type_invalid")


def _claim_model(read: DecodedStorageClaim) -> _StorageClaimEvidence:
    return _StorageClaimEvidence(
        pallet=read.spec.pallet,
        item=read.spec.item,
        params=[_canonical_param(value) for value in read.spec.params],
        storage_key=_hex(read.storage_key),
        raw_value=None if read.raw_value is None else _hex(read.raw_value),
    )


def _observation_model(
    item: VerifiedWeightScheduleObservation,
) -> _ScheduleObservationEvidence:
    read = item.subnet_epoch_index_read
    synthetic = DecodedStorageClaim(
        spec=StorageReadSpec(read.pallet, read.item, read.params),
        storage_key=read.evidence.storage_key,
        raw_value=read.evidence.value,
        decoded_value=read.decoded_value,
    )
    return _ScheduleObservationEvidence(
        timestamp_ms=item.timestamp_ms,
        chain_genesis_hash=item.chain_genesis_hash,
        identity=_identity_model(item.identity),
        finality_attestation=_hex(item.finality_attestation),
        epoch_claim=_claim_model(synthetic),
        proof_nodes=[_hex(node) for node in read.evidence.proof],
        subnet_epoch_index=item.subnet_epoch_index,
    )


def _schedule_model(
    observations: Sequence[VerifiedWeightScheduleObservation],
    schedule: WeightCommitSchedule,
    *,
    work: StageWorkItem,
    reveal_time_ms: int,
    buffer_blocks: int,
    submission_blocks: int,
) -> WeightCommitScheduleEvidence:
    plan = work.window.plan
    return WeightCommitScheduleEvidence(
        schema=WEIGHT_COMMIT_SCHEDULE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        netuid=78,
        window_id=plan.window_id,
        scoring_policy_hash=plan.scoring_policy_hash,
        runtime=_runtime_model(observations[0].runtime),
        reveal_round=plan.reveal_round,
        reveal_time_ms=reveal_time_ms,
        weight_commit_buffer_blocks=buffer_blocks,
        weight_commit_submission_blocks=submission_blocks,
        observations=[_observation_model(item) for item in observations],
        reveal_observation_block=schedule.reveal_observation_block.snapshot.block_number,
        weight_commit_ready_height=schedule.weight_commit_ready_height,
        base_epoch_block=schedule.base_epoch_block.snapshot.block_number,
        base_epoch_index=schedule.base_epoch_index,
        weight_commit_open_block=schedule.weight_commit_open_block.snapshot.block_number,
        weight_commit_open_block_hash=schedule.weight_commit_open_block.snapshot.block_hash,
        weight_commit_epoch_index=schedule.weight_commit_epoch_index,
        weight_commit_close_block=schedule.weight_commit_close_block.snapshot.block_number,
        weight_commit_close_block_hash=schedule.weight_commit_close_block.snapshot.block_hash,
        weight_commit_close_state_root=schedule.weight_commit_close_block.snapshot.state_root,
        weight_commit_close_timestamp_ms=schedule.weight_commit_close_block.timestamp_ms,
    )


def _runtime_from_model(
    model: _RuntimeEvidence,
    snapshot: FinalizedSnapshotRef,
) -> PinnedRuntimeContext:
    metadata = _unhex(model.metadata, "runtime_metadata_invalid")
    runtime_version = _unhex(model.runtime_version, "runtime_version_invalid")
    try:
        codec = bittensor_core.Runtime(
            metadata,
            model.spec_version,
            model.transaction_version,
            ss58_format=model.ss58_prefix,
        )
        if codec.constant("System", "SS58Prefix") != model.ss58_prefix:
            raise ValueError("wrong SS58 prefix")
        if (
            getattr(codec, "spec_version", model.spec_version) != model.spec_version
            or getattr(codec, "transaction_version", model.transaction_version)
            != model.transaction_version
        ):
            raise ValueError("runtime version disagreement")
    except Exception as error:
        raise WeightBuildBindingError("runtime_codec_initialization_failed") from error
    pin = FinalizedRuntimePin(
        metadata_sha256=model.metadata_sha256,
        spec_version=model.spec_version,
        transaction_version=model.transaction_version,
        state_version=model.state_version,
        ss58_prefix=model.ss58_prefix,
    )
    return PinnedRuntimeContext(
        snapshot=snapshot,
        pin=pin,
        metadata_bytes=metadata,
        runtime_version_bytes=runtime_version,
        _runtime=codec,
    )


def _identity_from_model(model: _FinalityIdentityEvidence) -> VerifiedFinalizedBlockIdentity:
    parent = FinalizedSnapshotRef(
        block_number=model.parent_block_number,
        block_hash=model.parent_block_hash,
        parent_hash=model.parent_parent_hash,
        state_root=model.parent_state_root,
    )
    snapshot = FinalizedSnapshotRef(
        block_number=model.block_number,
        block_hash=model.block_hash,
        parent_hash=model.parent_block_hash,
        state_root=model.state_root,
    )
    return VerifiedFinalizedBlockIdentity(
        snapshot=snapshot,
        parent_snapshot=parent,
        extrinsics_root=model.extrinsics_root,
        finality_verifier_sha256=model.finality_verifier_sha256,
        finality_evidence_sha256=model.finality_evidence_sha256,
    )


def _single_proof_adapter(verifier: MultiStorageProofVerifier):
    if not callable(verifier):
        raise TypeError("proof verifier must be callable")

    def verify(
        *,
        state_root: bytes,
        storage_key: bytes,
        expected_value: bytes | None,
        proof: tuple[bytes, ...],
    ) -> bool:
        return verifier(
            state_root=state_root,
            items=((storage_key, expected_value),),
            proof=proof,
        )

    return verify


def _replay_schedule(
    model: WeightCommitScheduleEvidence,
    *,
    verifier: MultiStorageProofVerifier,
) -> WeightCommitSchedule:
    if model.reveal_time_ms != QUICKNET_GENESIS_MS + (model.reveal_round - 1) * QUICKNET_PERIOD_MS:
        raise WeightBuildBindingError("weight_schedule_reveal_time_mismatch")
    observations: list[VerifiedWeightScheduleObservation] = []
    runtime_pin: FinalizedRuntimePin | None = None
    for entry in model.observations:
        identity = _identity_from_model(entry.identity)
        runtime = _runtime_from_model(model.runtime, identity.snapshot)
        if runtime_pin is None:
            runtime_pin = runtime.pin
        elif runtime.pin != runtime_pin:
            raise WeightBuildBindingError("weight_schedule_runtime_identity_mismatch")
        claim = entry.epoch_claim
        if (
            claim.pallet != "SubtensorModule"
            or claim.item != "SubnetEpochIndex"
            or claim.params != [78]
        ):
            raise WeightBuildBindingError("weight_schedule_epoch_claim_mismatch")
        key = _unhex(claim.storage_key, "weight_schedule_storage_key_invalid")
        raw = (
            None
            if claim.raw_value is None
            else _unhex(claim.raw_value, "weight_schedule_storage_value_invalid")
        )
        try:
            evidence = StorageEvidence(
                snapshot=identity.snapshot,
                storage_key=key,
                value=raw,
                proof=tuple(
                    _unhex(node, "weight_schedule_proof_node_invalid") for node in entry.proof_nodes
                ),
                verifier=_single_proof_adapter(verifier),
            )
            decoded = runtime.decode_storage(claim.pallet, claim.item, raw)
            read = VerifiedStorageRead(
                runtime=runtime,
                pallet=claim.pallet,
                item=claim.item,
                params=tuple(claim.params),
                evidence=evidence,
                decoded_value=decoded,
            )
            observation = VerifiedWeightScheduleObservation(
                identity=identity,
                timestamp_ms=entry.timestamp_ms,
                chain_genesis_hash=entry.chain_genesis_hash,
                finality_attestation=_unhex(
                    entry.finality_attestation,
                    "weight_schedule_finality_attestation_invalid",
                ),
                subnet_epoch_index_read=read,
            )
        except (TypeError, ValueError) as error:
            raise WeightBuildBindingError("weight_schedule_proof_verification_failed") from error
        if observation.subnet_epoch_index != entry.subnet_epoch_index:
            raise WeightBuildBindingError("weight_schedule_epoch_decode_mismatch")
        observations.append(observation)
    assert runtime_pin is not None
    first = observations[0]
    identity = WeightScheduleIdentity(
        chain_genesis_hash=first.chain_genesis_hash,
        finality_verifier_sha256=first.identity.finality_verifier_sha256,
        runtime_pin=runtime_pin,
        netuid=model.netuid,
    )
    result = derive_weight_commit_schedule(
        tuple(observations),
        identity=identity,
        reveal_time_ms=model.reveal_time_ms,
        weight_commit_buffer_blocks=model.weight_commit_buffer_blocks,
        weight_commit_submission_blocks=model.weight_commit_submission_blocks,
    )
    if not isinstance(result, WeightCommitSchedule):
        raise WeightBuildBindingError("weight_schedule_receipt_is_incomplete")
    if (
        result.reveal_observation_block.snapshot.block_number != model.reveal_observation_block
        or result.weight_commit_ready_height != model.weight_commit_ready_height
        or result.base_epoch_block.snapshot.block_number != model.base_epoch_block
        or result.base_epoch_index != model.base_epoch_index
        or result.weight_commit_open_block.snapshot.block_number != model.weight_commit_open_block
        or result.weight_commit_open_block.snapshot.block_hash
        != model.weight_commit_open_block_hash
        or result.weight_commit_epoch_index != model.weight_commit_epoch_index
        or result.weight_commit_close_block.snapshot.block_number != model.weight_commit_close_block
        or result.weight_commit_close_block.snapshot.block_hash
        != model.weight_commit_close_block_hash
        or result.weight_commit_close_block.snapshot.state_root
        != model.weight_commit_close_state_root
        or result.weight_commit_close_block.timestamp_ms != model.weight_commit_close_timestamp_ms
    ):
        raise WeightBuildBindingError("weight_schedule_fields_do_not_replay")
    start_height = result.reveal_observation_block.snapshot.block_number - 1
    if (
        observations[0].snapshot.block_number != start_height
        or observations[-1] is not result.weight_commit_close_block
    ):
        raise WeightBuildBindingError("weight_schedule_receipt_is_not_minimal")
    return result


def _snapshot_proof_model(
    snapshot: VerifiedWeightBuildSnapshot,
    work: StageWorkItem,
    policy_hash: str,
) -> WeightBuildProofEvidence:
    batches: list[_StorageProofBatchEvidence] = []
    seen: set[bytes] = set()
    for batch in snapshot.storage_batches:
        claims: list[_StorageClaimEvidence] = []
        for read in sorted(batch.reads, key=lambda item: item.storage_key):
            if read.storage_key in seen:
                raise WeightBuildBindingError("duplicate_weight_build_storage_key")
            seen.add(read.storage_key)
            try:
                decoded = batch.runtime.decode_storage(
                    read.spec.pallet,
                    read.spec.item,
                    read.raw_value,
                )
            except Exception as error:
                raise WeightBuildBindingError("weight_build_storage_decode_failed") from error
            if decoded != read.decoded_value:
                raise WeightBuildBindingError("weight_build_semantic_decode_mismatch")
            claims.append(_claim_model(read))
        if not claims:
            raise WeightBuildBindingError("weight_build_storage_batch_empty")
        batches.append(
            _StorageProofBatchEvidence(
                claims=claims,
                proof_nodes=[_hex(node) for node in batch.evidence.proof],
            )
        )
    plan = work.window.plan
    return WeightBuildProofEvidence(
        schema=WEIGHT_BUILD_PROOF_SCHEMA,
        protocol=PROTOCOL_VERSION,
        netuid=78,
        mechanism_id=0,
        window_id=plan.window_id,
        window_index=plan.window_index,
        scoring_policy_hash=policy_hash,
        chain_genesis_hash=snapshot.chain_genesis_hash,
        timestamp_ms=snapshot.timestamp_ms,
        identity=_identity_model(snapshot.identity),
        finality_attestation=_hex(snapshot.finality_attestation),
        runtime=_runtime_model(snapshot.runtime),
        requested_roots=[root.hex() for root in snapshot.requested_roots],
        proof_batches=batches,
        total_unique_storage_keys=len(seen),
    )


def _replay_snapshot_proof(
    proof_bytes: bytes,
    *,
    verifier: MultiStorageProofVerifier,
) -> VerifiedWeightBuildSnapshot:
    if not isinstance(proof_bytes, bytes) or not proof_bytes:
        raise TypeError("weight-build proof must be nonempty exact bytes")
    if len(proof_bytes) > MAX_WEIGHT_BUILD_PROOF_BYTES:
        raise WeightBuildLimitError("weight_build_proof_size_limit")
    model = _parse_canonical(
        proof_bytes,
        WeightBuildProofEvidence,
        "weight-build proof",
    )
    identity = _identity_from_model(model.identity)
    runtime = _runtime_from_model(model.runtime, identity.snapshot)
    batches: list[VerifiedStorageBatch] = []
    seen: set[bytes] = set()
    for batch_model in model.proof_batches:
        claims = tuple(
            StorageClaim(
                storage_key=_unhex(item.storage_key, "weight_build_storage_key_invalid"),
                value=(
                    None
                    if item.raw_value is None
                    else _unhex(item.raw_value, "weight_build_storage_value_invalid")
                ),
            )
            for item in batch_model.claims
        )
        try:
            evidence = MultiStorageEvidence(
                snapshot=identity.snapshot,
                claims=claims,
                proof=tuple(
                    _unhex(node, "weight_build_proof_node_invalid")
                    for node in batch_model.proof_nodes
                ),
                verifier=verifier,
            )
        except (TypeError, ValueError) as error:
            raise WeightBuildBindingError("weight_build_storage_proof_failed") from error
        reads: list[DecodedStorageClaim] = []
        claim_by_key = {item.storage_key: item for item in evidence.claims}
        for claim_model in batch_model.claims:
            spec = StorageReadSpec(
                claim_model.pallet,
                claim_model.item,
                tuple(claim_model.params),
            )
            expected_key = runtime.storage_key(spec.pallet, spec.item, spec.params)
            retained_key = _unhex(
                claim_model.storage_key,
                "weight_build_storage_key_invalid",
            )
            if expected_key != retained_key:
                raise WeightBuildBindingError("weight_build_storage_key_derivation_mismatch")
            if expected_key in seen:
                raise WeightBuildBindingError("duplicate_weight_build_storage_key")
            seen.add(expected_key)
            raw = claim_by_key[expected_key].value
            try:
                decoded = runtime.decode_storage(spec.pallet, spec.item, raw)
            except Exception as error:
                raise WeightBuildBindingError("weight_build_storage_decode_failed") from error
            reads.append(
                DecodedStorageClaim(
                    spec=spec,
                    storage_key=expected_key,
                    raw_value=raw,
                    decoded_value=decoded,
                )
            )
        batches.append(VerifiedStorageBatch(runtime=runtime, evidence=evidence, reads=tuple(reads)))
    if len(seen) != model.total_unique_storage_keys:
        raise WeightBuildBindingError("weight_build_storage_key_count_mismatch")
    return VerifiedWeightBuildSnapshot(
        identity=identity,
        timestamp_ms=model.timestamp_ms,
        chain_genesis_hash=model.chain_genesis_hash,
        finality_attestation=_unhex(
            model.finality_attestation,
            "weight_build_finality_attestation_invalid",
        ),
        storage_batches=tuple(batches),
        requested_roots=tuple(bytes.fromhex(root) for root in model.requested_roots),
    )


def _validate_snapshot_identity(
    snapshot: VerifiedWeightBuildSnapshot,
    schedule_identity: WeightScheduleIdentity,
    policy: ScoringPolicy,
) -> None:
    _validate_schedule_identity(schedule_identity, policy)
    if (
        snapshot.chain_genesis_hash != schedule_identity.chain_genesis_hash
        or snapshot.identity.finality_verifier_sha256 != schedule_identity.finality_verifier_sha256
        or snapshot.runtime.pin != schedule_identity.runtime_pin
    ):
        raise WeightBuildBindingError("weight_build_snapshot_identity_mismatch")


def _semantic_storage_key(read: DecodedStorageClaim) -> tuple[str, tuple[Any, ...]]:
    if read.spec.pallet != _PALLET:
        raise WeightBuildBindingError("weight_build_storage_pallet_mismatch")
    item = read.spec.item
    params = read.spec.params
    try:
        if item in {_UIDS, _HOTKEY_SUCCESSOR, _HOTKEY_ROOT}:
            if len(params) != 2 or params[0] != 78:
                raise ValueError
            return item, (78, account_id32(params[1]))
        if item == _KEYS:
            if len(params) != 2 or params[0] != 78:
                raise ValueError
            return item, (78, _uint(params[1], "UID", maximum=_MAX_U16))
        if item == _WEIGHTS:
            if len(params) != 3 or params[0] != 78 or params[1] != 0:
                raise ValueError
            return item, (78, 0, _uint(params[2], "validator UID", maximum=_MAX_U16))
        if item in {
            _NETWORKS_ADDED,
            _MECHANISM_COUNT,
            _SUBNETWORK_N,
            _MIN_ALLOWED_WEIGHTS,
            _MAX_WEIGHTS_LIMIT,
            _WEIGHTS_VERSION_KEY,
            _VALIDATOR_PERMIT,
            _LAST_UPDATE,
            _ACTIVITY_CUTOFF,
            _TEMPO,
        }:
            if params != (78,):
                raise ValueError
            return item, (78,)
    except (TypeError, ValueError) as error:
        raise WeightBuildBindingError("weight_build_storage_parameter_mismatch") from error
    raise WeightBuildBindingError("weight_build_unexpected_storage_item")


def _decoded_read_map(
    batches: Sequence[VerifiedStorageBatch],
) -> dict[tuple[str, tuple[Any, ...]], Any]:
    values: dict[tuple[str, tuple[Any, ...]], Any] = {}
    raw_keys: set[bytes] = set()
    for batch in batches:
        for read in batch.reads:
            if read.storage_key in raw_keys:
                raise WeightBuildBindingError("duplicate_weight_build_storage_key")
            raw_keys.add(read.storage_key)
            try:
                replayed = batch.runtime.decode_storage(
                    read.spec.pallet,
                    read.spec.item,
                    read.raw_value,
                )
            except Exception as error:
                raise WeightBuildBindingError("weight_build_storage_decode_failed") from error
            if replayed != read.decoded_value:
                raise WeightBuildBindingError("weight_build_semantic_decode_mismatch")
            key = _semantic_storage_key(read)
            if key in values:
                raise WeightBuildBindingError("duplicate_weight_build_semantic_read")
            values[key] = read.decoded_value
    return values


def _required(
    values: Mapping[tuple[str, tuple[Any, ...]], Any],
    item: str,
    params: tuple[Any, ...],
) -> Any:
    try:
        return values[(item, params)]
    except KeyError as error:
        raise WeightBuildBindingError("required_weight_build_storage_read_missing") from error


def _strict_account(value: Any, reason_code: str) -> bytes:
    try:
        return account_id32(value)
    except Exception as error:
        raise WeightBuildBindingError(reason_code) from error


def _optional_account(value: Any, reason_code: str) -> bytes | None:
    return None if value is None else _strict_account(value, reason_code)


def _strict_uint_value(
    value: Any,
    reason_code: str,
    *,
    maximum: int = _MAX_U64,
    positive: bool = False,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < (1 if positive else 0)
        or value > maximum
    ):
        raise WeightBuildBindingError(reason_code)
    return value


def _uint_vector(value: Any, reason_code: str) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        raise WeightBuildBindingError(reason_code)
    return tuple(_strict_uint_value(item, reason_code) for item in value)


def _bool_vector(value: Any, reason_code: str) -> tuple[bool, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, bool) for item in value):
        raise WeightBuildBindingError(reason_code)
    return tuple(value)


def _weight_row(value: Any) -> list[list[int]]:
    if not isinstance(value, (list, tuple)):
        raise WeightBuildBindingError("existing_weight_row_invalid")
    row: list[list[int]] = []
    for item in value:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise WeightBuildBindingError("existing_weight_row_invalid")
        uid = _strict_uint_value(item[0], "existing_weight_uid_invalid", maximum=_MAX_U16)
        weight = _strict_uint_value(
            item[1],
            "existing_weight_value_invalid",
            maximum=_MAX_U16,
        )
        row.append([uid, weight])
    if [item[0] for item in row] != sorted({item[0] for item in row}):
        raise WeightBuildBindingError("existing_weight_row_not_canonical")
    return row


def _decode_weight_snapshot(
    batches: Sequence[VerifiedStorageBatch],
    *,
    requested_roots: Sequence[bytes],
    validator_hotkey: bytes,
    block_number: int,
    proof_sha256: str,
    work: StageWorkItem | None,
    policy: ScoringPolicy,
    window_id: str | None = None,
    window_index: int | None = None,
    scoring_policy_hash_value: str | None = None,
) -> _DecodedSnapshot:
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be ScoringPolicy")
    validator = account_id32(validator_hotkey)
    roots = tuple(account_id32(root) for root in requested_roots)
    if roots != tuple(sorted(set(roots))):
        raise WeightBuildBindingError("weight_build_requested_roots_not_canonical")
    if work is not None:
        plan = work.window.plan
        expected_window_id = plan.window_id
        expected_window_index = plan.window_index
        expected_policy_hash = plan.scoring_policy_hash
    else:
        if window_id is None or window_index is None or scoring_policy_hash_value is None:
            raise TypeError("receipt replay requires explicit window bindings")
        expected_window_id = window_id
        expected_window_index = window_index
        expected_policy_hash = scoring_policy_hash_value
    if expected_policy_hash != scoring_policy_hash(policy):
        raise WeightBuildBindingError("weight_build_snapshot_policy_hash_mismatch")

    values = _decoded_read_map(batches)
    network_added = _required(values, _NETWORKS_ADDED, (78,))
    if network_added is not True:
        raise WeightBuildBindingError("weight_build_subnet_not_active")
    mechanism_count = _strict_uint_value(
        _required(values, _MECHANISM_COUNT, (78,)),
        "mechanism_count_invalid",
        maximum=_MAX_U16,
        positive=True,
    )
    if mechanism_count != 1:
        raise WeightBuildBindingError("weight_build_mechanism_topology_mismatch")
    uid_count = _strict_uint_value(
        _required(values, _SUBNETWORK_N, (78,)),
        "subnetwork_uid_count_invalid",
        maximum=65_536,
        positive=True,
    )
    minimum = _strict_uint_value(
        _required(values, _MIN_ALLOWED_WEIGHTS, (78,)),
        "min_allowed_weights_invalid",
        maximum=65_536,
        positive=True,
    )
    if minimum > uid_count:
        raise WeightBuildBindingError("min_allowed_weights_exceeds_uid_count")
    maximum_limit = _strict_uint_value(
        _required(values, _MAX_WEIGHTS_LIMIT, (78,)),
        "maximum_weight_limit_invalid",
        maximum=_MAX_U16,
        positive=True,
    )
    version_key = _strict_uint_value(
        _required(values, _WEIGHTS_VERSION_KEY, (78,)),
        "weights_version_key_invalid",
    )
    permits = _bool_vector(
        _required(values, _VALIDATOR_PERMIT, (78,)),
        "validator_permit_vector_invalid",
    )
    updates = _uint_vector(
        _required(values, _LAST_UPDATE, (78,)),
        "last_update_vector_invalid",
    )
    if len(permits) < uid_count or len(updates) < uid_count:
        raise WeightBuildBindingError("metagraph_vector_shorter_than_uid_count")
    validator_uid_raw = _required(values, _UIDS, (78, validator))
    if validator_uid_raw is None:
        raise WeightBuildBindingError("validator_uid_unresolved")
    validator_uid = _strict_uint_value(
        validator_uid_raw,
        "validator_uid_invalid",
        maximum=_MAX_U16,
    )
    if validator_uid >= uid_count:
        raise WeightBuildBindingError("validator_uid_out_of_range")
    validator_key = _strict_account(
        _required(values, _KEYS, (78, validator_uid)),
        "validator_key_invalid",
    )
    if validator_key != validator:
        raise WeightBuildBindingError("validator_uid_inverse_mismatch")
    if not permits[validator_uid]:
        raise WeightBuildBindingError("validator_permit_missing")
    existing_row = _weight_row(_required(values, _WEIGHTS, (78, 0, validator_uid)))
    if any(item[0] >= uid_count for item in existing_row):
        raise WeightBuildBindingError("existing_weight_uid_out_of_range")
    cutoff_factor = _strict_uint_value(
        _required(values, _ACTIVITY_CUTOFF, (78,)),
        "activity_cutoff_factor_invalid",
    )
    tempo = _strict_uint_value(
        _required(values, _TEMPO, (78,)),
        "tempo_invalid",
        maximum=_MAX_U16,
        positive=True,
    )
    last_update = updates[validator_uid]
    cutoff_blocks = max(1, cutoff_factor * tempo // 1000)
    if cutoff_blocks > _MAX_U64:
        raise WeightBuildBindingError("activity_cutoff_blocks_overflow")
    if cutoff_blocks > policy.clock.window_stride_blocks:
        raise WeightBuildBindingError("activity_cutoff_exceeds_window_stride")

    expected: set[tuple[str, tuple[Any, ...]]] = {
        (_NETWORKS_ADDED, (78,)),
        (_MECHANISM_COUNT, (78,)),
        (_SUBNETWORK_N, (78,)),
        (_MIN_ALLOWED_WEIGHTS, (78,)),
        (_MAX_WEIGHTS_LIMIT, (78,)),
        (_WEIGHTS_VERSION_KEY, (78,)),
        (_VALIDATOR_PERMIT, (78,)),
        (_LAST_UPDATE, (78,)),
        (_ACTIVITY_CUTOFF, (78,)),
        (_TEMPO, (78,)),
        (_UIDS, (78, validator)),
        (_KEYS, (78, validator_uid)),
        (_WEIGHTS, (78, 0, validator_uid)),
    }
    mappings: list[_RootMappingResult] = []
    uid_by_root: dict[bytes, int | None] = {}
    seen_eligible_uids: set[int] = set()
    for root in roots:
        successor_key = (_HOTKEY_SUCCESSOR, (78, root))
        expected.add(successor_key)
        successor_value = _required(values, *successor_key)
        successor = (
            _optional_account(
                successor_value,
                "miner_successor_hotkey_invalid",
            )
            or root
        )
        uid_key = (_UIDS, (78, successor))
        expected.add(uid_key)
        uid_value = _required(values, *uid_key)
        status: Literal["eligible", "unresolved", "ineligible"]
        reason: str | None
        uid: int | None = None
        if uid_value is None:
            status = "unresolved"
            reason = "uid_unresolved"
        else:
            parsed_uid = _strict_uint_value(
                uid_value,
                "miner_uid_invalid",
                maximum=_MAX_U16,
            )
            key_key = (_KEYS, (78, parsed_uid))
            root_key = (_HOTKEY_ROOT, (78, successor))
            expected.update((key_key, root_key))
            registered = _strict_account(
                _required(values, *key_key),
                "miner_registration_key_invalid",
            )
            recorded_root = _optional_account(
                _required(values, *root_key),
                "miner_recorded_root_invalid",
            )
            if parsed_uid >= uid_count:
                status = "ineligible"
                reason = "uid_out_of_range"
            elif registered != successor:
                status = "ineligible"
                reason = "uid_inverse_mismatch"
            elif (successor == root and recorded_root not in {None, root}) or (
                successor != root and recorded_root != root
            ):
                status = "ineligible"
                reason = "root_successor_mismatch"
            elif permits[parsed_uid]:
                status = "ineligible"
                reason = "destination_has_validator_permit"
            elif parsed_uid in seen_eligible_uids:
                raise WeightBuildBindingError("positive_roots_resolve_to_duplicate_uid")
            else:
                status = "eligible"
                reason = None
                uid = parsed_uid
                seen_eligible_uids.add(uid)
        uid_by_root[root] = uid
        mappings.append(
            _RootMappingResult(
                miner_root=root.hex(),
                successor_hotkey=successor.hex(),
                uid=uid,
                status=status,
                reason_code=reason,
            )
        )
    if set(values) != expected:
        missing = expected.difference(values)
        extra = set(values).difference(expected)
        reason = (
            "weight_build_storage_read_set_missing"
            if missing
            else "weight_build_storage_read_set_has_extras"
        )
        raise WeightBuildBindingError(f"{reason}:{len(missing)}:{len(extra)}")

    classification: Literal["empty", "previous_row_active", "previous_row_inactive"]
    if not existing_row:
        classification = "empty"
    elif last_update + cutoff_blocks >= block_number:
        classification = "previous_row_active"
    else:
        classification = "previous_row_inactive"
    runtime = batches[0].runtime
    evidence = WeightBuildSnapshotEvidence(
        schema=WEIGHT_BUILD_SNAPSHOT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        netuid=78,
        mechanism_id=0,
        window_id=expected_window_id,
        window_index=expected_window_index,
        scoring_policy_hash=expected_policy_hash,
        block_number=block_number,
        block_hash=runtime.snapshot.block_hash,
        state_root=runtime.snapshot.state_root,
        runtime_metadata_sha256=runtime.pin.metadata_sha256,
        runtime_spec_version=runtime.pin.spec_version,
        transaction_version=runtime.pin.transaction_version,
        network_added=True,
        mechanism_count=1,
        uid_count=uid_count,
        min_allowed_weights=minimum,
        maximum_weight_limit_u16=maximum_limit,
        weights_version_key=version_key,
        validator_hotkey=validator.hex(),
        validator_uid=validator_uid,
        validator_permit=True,
        existing_mechid0_row=existing_row,
        last_update=last_update,
        activity_cutoff_factor_milli=cutoff_factor,
        tempo=tempo,
        activity_cutoff_blocks=cutoff_blocks,
        prior_row_classification=classification,
        mappings=mappings,
        proof_evidence_sha256=proof_sha256,
    )
    return _DecodedSnapshot(evidence=evidence, uid_by_root=uid_by_root)


def _protocol_rolling_object(rolling: RollingScoreState) -> dict[str, Any]:
    return {
        "batches": [
            {
                "window_index": batch.window_index,
                "batch_rank": bytes(batch.batch_rank).hex()
                if isinstance(batch.batch_rank, bytes)
                else batch.batch_rank,
                "pool_leaf": bytes(batch.pool_leaf).hex()
                if isinstance(batch.pool_leaf, bytes)
                else batch.pool_leaf,
                "challenge_ids": list(batch.challenge_ids),
                "miner_roots": [account_id32(root).hex() for root in batch.miner_roots],
                "assignments": [
                    {
                        "miner_root": assignment.root.hex(),
                        "challenge_id": assignment.challenge_id,
                        "request_leaf": assignment.leaf.hex(),
                        "stratum": assignment.stratum,
                        "canary": assignment.canary,
                        "score": (
                            None
                            if assignment.score is None
                            else [
                                str(assignment.score.numerator),
                                str(assignment.score.denominator),
                            ]
                        ),
                    }
                    for assignment in batch.assignments
                ],
            }
            for batch in rolling.batches
        ]
    }


def _batch_state(batch: ScoredBatch) -> _BatchState:
    return _BatchState(
        window_index=batch.window_index,
        batch_rank=(
            batch.batch_rank.hex() if isinstance(batch.batch_rank, bytes) else batch.batch_rank
        ),
        pool_leaf=(
            batch.pool_leaf.hex() if isinstance(batch.pool_leaf, bytes) else batch.pool_leaf
        ),
        challenge_ids=list(batch.challenge_ids),
        miner_roots=[account_id32(root).hex() for root in batch.miner_roots],
        assignments=[
            _AssignmentState(
                miner_root=assignment.root.hex(),
                challenge_id=assignment.challenge_id,
                request_leaf=assignment.leaf.hex(),
                stratum=assignment.stratum,
                canary=assignment.canary,
                score=(None if assignment.score is None else _fraction_model(assignment.score)),
            )
            for assignment in batch.assignments
        ],
    )


def _state_model(
    state: ProtocolStateSnapshot,
    work: StageWorkItem,
) -> WeightBuildStateEvidence:
    plan = work.window.plan
    if (
        state.last_window_index != plan.window_index
        or state.last_window_id is None
        or state.last_window_id.hex() != plan.window_id
    ):
        raise WeightBuildBindingError("protocol_state_has_not_atomically_advanced_window")
    rolling_digest = hashlib.sha256(
        canonical_json_bytes(_protocol_rolling_object(state.rolling_scores))
    ).hexdigest()
    return WeightBuildStateEvidence(
        schema=WEIGHT_BUILD_STATE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=plan.window_id,
        window_index=plan.window_index,
        state_digest=state.state_digest.hex(),
        rolling_state_sha256=rolling_digest,
        rolling_batches=[_batch_state(batch) for batch in state.rolling_scores.batches],
    )


def _rolling_from_state(model: WeightBuildStateEvidence) -> RollingScoreState:
    batches: list[ScoredBatch] = []
    total_assignments = 0
    for batch in model.rolling_batches:
        total_assignments += len(batch.assignments)
        if total_assignments > MAX_WEIGHT_BUILD_ASSIGNMENTS:
            raise WeightBuildLimitError("weight_build_assignment_count_limit")
        batches.append(
            ScoredBatch(
                window_index=batch.window_index,
                batch_rank=bytes.fromhex(batch.batch_rank),
                pool_leaf=bytes.fromhex(batch.pool_leaf),
                challenge_ids=tuple(batch.challenge_ids),
                miner_roots=tuple(bytes.fromhex(root) for root in batch.miner_roots),
                assignments=tuple(
                    AssignmentScore(
                        miner_root=bytes.fromhex(item.miner_root),
                        challenge_id=item.challenge_id,
                        request_leaf=bytes.fromhex(item.request_leaf),
                        stratum=item.stratum,
                        canary=item.canary,
                        score=None if item.score is None else item.score.fraction,
                    )
                    for item in batch.assignments
                ),
            )
        )
    try:
        rolling = RollingScoreState(tuple(batches))
    except (TypeError, ValueError) as error:
        raise WeightBuildBindingError("weight_build_rolling_state_invalid") from error
    reproduced = hashlib.sha256(canonical_json_bytes(_protocol_rolling_object(rolling))).hexdigest()
    if reproduced != model.rolling_state_sha256:
        raise WeightBuildBindingError("weight_build_rolling_state_digest_mismatch")
    return rolling


def _completed_stage_digest(work: StageWorkItem, stage: WindowStage) -> str:
    matches = [item for item in work.completed_evidence if item.stage is stage]
    if len(matches) != 1:
        raise WeightBuildBindingError(f"work_requires_one_{stage.value}_evidence_digest")
    if matches[0].window_id != work.window.plan.window_id:
        raise WeightBuildBindingError("completed_stage_evidence_window_mismatch")
    return matches[0].evidence_sha256


def _transition_result_fields(
    data: bytes,
    *,
    window_id: str,
    window_index: int,
    state: ProtocolStateSnapshot,
    transition_operation_id: str | None = None,
    transition_evidence_sha256: str | None = None,
) -> dict[str, Any]:
    value = _strict_json(data, "protocol_transition_result")
    if not isinstance(value, dict) or value.get("schema") != PROTOCOL_STATE_RESULT_SCHEMA:
        raise WeightBuildBindingError("protocol_transition_result_schema_mismatch")
    try:
        state_value = value["state"]
        rolling_value = value["rolling"]
    except KeyError as error:
        raise WeightBuildBindingError("protocol_transition_result_incomplete") from error
    if not isinstance(state_value, dict) or not isinstance(rolling_value, dict):
        raise WeightBuildBindingError("protocol_transition_result_incomplete")
    expected_rolling = hashlib.sha256(
        canonical_json_bytes(_protocol_rolling_object(state.rolling_scores))
    ).hexdigest()
    if (
        value.get("window_id") != window_id
        or value.get("window_index") != window_index
        or state_value.get("state_digest") != state.state_digest.hex()
        or rolling_value.get("state_sha256") != expected_rolling
    ):
        raise WeightBuildBindingError("protocol_transition_result_state_mismatch")
    if transition_operation_id is not None and value.get("operation_id") != (
        transition_operation_id
    ):
        raise WeightBuildBindingError("protocol_transition_operation_mismatch")
    if transition_evidence_sha256 is not None and value.get("evidence_digest") != (
        transition_evidence_sha256
    ):
        raise WeightBuildBindingError("protocol_transition_evidence_mismatch")
    if canonical_json_bytes(value) != data:
        raise WeightBuildBindingError("protocol_transition_result_noncanonical")
    return value


def _load_reveal_binding(
    journal: ValidatorStageJournal,
    work: StageWorkItem,
    state: ProtocolStateSnapshot,
    policy: ScoringPolicy,
) -> _RevealBinding:
    expected = _completed_stage_digest(work, WindowStage.REVEAL_AND_SCORE)
    try:
        record = journal.load(work.window.plan.window_id, WindowStage.REVEAL_AND_SCORE)
    except Exception as error:
        raise WeightBuildBindingError("authoritative_reveal_receipt_unavailable") from error
    if record.evidence_sha256 != expected:
        raise WeightBuildBindingError("authoritative_reveal_receipt_digest_mismatch")
    payloads = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
    if set(payloads) != {item.sha256 for item in record.receipt.objects}:
        raise WeightBuildBindingError("authoritative_reveal_object_graph_incomplete")
    try:
        resolved = resolve_reveal_stage_record(record, journal)
    except Exception as error:
        raise WeightBuildBindingError("authoritative_reveal_receipt_does_not_replay") from error
    manifest = resolved.manifest
    manifest_bytes = canonical_json_bytes(manifest)
    plan = work.window.plan
    if (
        record.receipt.window_id != plan.window_id
        or record.receipt.operation_id != manifest.operation_id
        or manifest.window_id != plan.window_id
        or manifest.window_index != plan.window_index
        or manifest.scoring_policy_hash != scoring_policy_hash(policy)
        or resolved.policy != policy
    ):
        raise WeightBuildBindingError("authoritative_reveal_manifest_binding_mismatch")

    def resolve(reference: Any, label: str) -> bytes:
        try:
            data = payloads[reference.sha256]
        except KeyError as error:
            raise WeightBuildBindingError(f"{label}_missing") from error
        if (
            len(data) != reference.size_bytes
            or hashlib.sha256(data).hexdigest() != reference.sha256
        ):
            raise WeightBuildBindingError(f"{label}_metadata_mismatch")
        return data

    transition_bytes = resolve(
        manifest.protocol_transition_result,
        "protocol_transition_result",
    )
    _transition_result_fields(
        transition_bytes,
        window_id=plan.window_id,
        window_index=plan.window_index,
        state=state,
        transition_operation_id=manifest.transition_operation_id,
        transition_evidence_sha256=manifest.transition_evidence_sha256,
    )
    if (
        resolved.result.window_id != plan.window_id
        or resolved.result.window_index != plan.window_index
        or resolved.result.scoring_policy_hash != scoring_policy_hash(policy)
        or resolved.result.void_reason_codes
        or resolved.resulting_protocol_state_digest != state.state_digest.hex()
    ):
        raise WeightBuildBindingError("reveal_result_not_valid_for_weight_build")
    source_objects = tuple(
        StageObjectInput(payloads[item.sha256], item.media_type) for item in record.receipt.objects
    )
    return _RevealBinding(
        record=record,
        manifest_bytes=manifest_bytes,
        transition_result_bytes=transition_bytes,
        source_objects=source_objects,
    )


def _miner_score_model(score: MinerScore) -> _MinerScoreResult:
    return _MinerScoreResult(
        miner_root=account_id32(score.miner_root).hex(),
        assigned_clips=score.assigned_clips,
        stratum_counts={name: count for name, count in score.stratum_counts},
        stratum_means={name: _fraction_model(value) for name, value in score.stratum_means},
        accuracy=_fraction_model(score.accuracy),
        eligible=score.eligible,
        utility=_fraction_model(score.utility),
    )


def _projected_row_sha256(row: Sequence[Sequence[int]]) -> str:
    return hashlib.sha256(
        canonical_json_bytes([{"uid": item[0], "value": item[1]} for item in row])
    ).hexdigest()


def _result_model_from_values(
    *,
    state_digest: str,
    scores: Sequence[MinerScore],
    built: WeightBuild | None,
    terminal_reason: str | None,
    snapshot: WeightBuildSnapshotEvidence,
    window_id: str,
    window_index: int,
    policy_hash: str,
    policy: ScoringPolicy,
) -> WeightBuildResultEvidence:
    if (built is None) != (terminal_reason is not None):
        raise WeightBuildBindingError("weight_build_result_state_invalid")
    root_vector = (
        []
        if built is None
        else [
            _VectorValue(miner_root=root.hex(), weight=_fraction_model(weight))
            for root, weight in built.root_vector
        ]
    )
    uid_vector = (
        []
        if built is None
        else [
            _VectorValue(uid=uid, weight=_fraction_model(weight))
            for uid, weight in built.uid_vector
        ]
    )
    row = [] if built is None else [[uid, value] for uid, value in built.quantized_row]
    return WeightBuildResultEvidence(
        schema=WEIGHT_BUILD_RESULT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=window_id,
        window_index=window_index,
        scoring_policy_hash=policy_hash,
        protocol_state_digest=state_digest,
        weight_build_block=snapshot.block_number,
        weight_build_block_hash=snapshot.block_hash,
        min_allowed_weights=snapshot.min_allowed_weights,
        maximum_weight_limit_u16=snapshot.maximum_weight_limit_u16,
        quality_floor=_fraction_model(policy.thresholds.quality_floor.fraction),
        minimum_assigned_clips=policy.limits.minimum_assigned_clips,
        minimum_clips_per_stratum=policy.limits.minimum_clips_per_stratum,
        miner_scores=[_miner_score_model(item) for item in scores],
        root_vector=root_vector,
        uid_vector=uid_vector,
        quantized_row=row,
        projected_row_sha256=_projected_row_sha256(row),
        terminal_reason_code=terminal_reason,
        translation_weights_active=False,
    )


def _result_model(
    *,
    state: ProtocolStateSnapshot,
    scores: Sequence[MinerScore],
    built: WeightBuild | None,
    terminal_reason: str | None,
    snapshot: WeightBuildSnapshotEvidence,
    work: StageWorkItem,
    policy: ScoringPolicy,
) -> WeightBuildResultEvidence:
    plan = work.window.plan
    return _result_model_from_values(
        state_digest=state.state_digest.hex(),
        scores=scores,
        built=built,
        terminal_reason=terminal_reason,
        snapshot=snapshot,
        window_id=plan.window_id,
        window_index=plan.window_index,
        policy_hash=plan.scoring_policy_hash,
        policy=policy,
    )


def _effect_metadata(receipt: StageReceipt) -> Mapping[str, Any]:
    metadata = receipt.metadata
    if metadata.get("schema") == "umi-validator-adapter-result/1":
        value = metadata.get("metadata")
        if not isinstance(value, dict):
            raise WeightBuildBindingError("weight_build_receipt_metadata_invalid")
        return value
    return metadata


def _validate_receipt_metadata(
    receipt: StageReceipt,
    schedule: WeightCommitSchedule,
    snapshot: VerifiedWeightBuildSnapshot,
    result: WeightBuildResultEvidence,
    *,
    schedule_sha256: str,
) -> None:
    metadata = _effect_metadata(receipt)
    expected = {
        "weight_commit_schedule_sha256": schedule_sha256,
        "weight_commit_open_block": schedule.weight_commit_open_block.snapshot.block_number,
        "weight_commit_epoch_index": schedule.weight_commit_epoch_index,
        "weight_commit_close_block": schedule.weight_commit_close_block.snapshot.block_number,
        "weight_commit_close_block_hash": schedule.weight_commit_close_block.snapshot.block_hash,
        "weight_commit_close_state_root": schedule.weight_commit_close_block.snapshot.state_root,
        "weight_build_block": snapshot.identity.snapshot.block_number,
        "weight_build_block_hash": snapshot.identity.snapshot.block_hash,
        "projected_row_sha256": result.projected_row_sha256,
        "translation_weights_active": False,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise WeightBuildBindingError(f"weight_build_receipt_metadata_{key}_mismatch")


def _validate_schedule_model_policy(
    model: WeightCommitScheduleEvidence,
    policy: ScoringPolicy,
) -> None:
    pins = policy.implementation_pins
    live = pins.live_chain
    finality = pins.finality_verifier
    if live is None or finality is None:
        raise WeightBuildBindingError("weight_schedule_live_pins_missing")
    if (
        model.netuid != policy.netuid
        or model.runtime.metadata_sha256 != live.metadata_sha256
        or model.runtime.spec_version != live.runtime_spec_version
        or model.runtime.transaction_version != live.transaction_version
        or model.runtime.state_version != live.state_version
        or any(item.chain_genesis_hash != live.genesis_block_hash for item in model.observations)
        or any(
            item.identity.finality_verifier_sha256
            not in set(finality.release_sha256_by_target.values())
            for item in model.observations
        )
    ):
        raise WeightBuildBindingError("weight_schedule_policy_identity_mismatch")


def _validate_snapshot_proof_model_policy(
    model: WeightBuildProofEvidence,
    policy: ScoringPolicy,
) -> None:
    pins = policy.implementation_pins
    live = pins.live_chain
    finality = pins.finality_verifier
    if live is None or finality is None:
        raise WeightBuildBindingError("weight_build_live_pins_missing")
    if (
        model.netuid != policy.netuid
        or model.mechanism_id != policy.mechanism_id
        or model.chain_genesis_hash != live.genesis_block_hash
        or model.runtime.metadata_sha256 != live.metadata_sha256
        or model.runtime.spec_version != live.runtime_spec_version
        or model.runtime.transaction_version != live.transaction_version
        or model.runtime.state_version != live.state_version
        or model.identity.finality_verifier_sha256
        not in set(finality.release_sha256_by_target.values())
    ):
        raise WeightBuildBindingError("weight_build_proof_policy_identity_mismatch")


def _validate_transition_bytes_from_state_evidence(
    data: bytes,
    *,
    state: WeightBuildStateEvidence,
    transition_operation_id: str,
    transition_evidence_sha256: str,
) -> None:
    value = _strict_json(data, "protocol_transition_result")
    if not isinstance(value, dict) or value.get("schema") != PROTOCOL_STATE_RESULT_SCHEMA:
        raise WeightBuildBindingError("protocol_transition_result_schema_mismatch")
    state_value = value.get("state")
    rolling_value = value.get("rolling")
    if not isinstance(state_value, dict) or not isinstance(rolling_value, dict):
        raise WeightBuildBindingError("protocol_transition_result_incomplete")
    if (
        value.get("operation_id") != transition_operation_id
        or value.get("evidence_digest") != transition_evidence_sha256
        or value.get("window_id") != state.window_id
        or value.get("window_index") != state.window_index
        or state_value.get("state_digest") != state.state_digest
        or rolling_value.get("state_sha256") != state.rolling_state_sha256
    ):
        raise WeightBuildBindingError("protocol_transition_result_state_mismatch")
    if canonical_json_bytes(value) != data:
        raise WeightBuildBindingError("protocol_transition_result_noncanonical")


def _validate_reveal_graph_for_replay(
    objects: _ReceiptObjects,
    manifest: WeightBuildStageManifest,
    state: WeightBuildStateEvidence,
) -> None:
    reveal_receipt_bytes = objects.resolve(manifest.reveal_stage_receipt)
    reveal_receipt = _parse_canonical(
        reveal_receipt_bytes,
        StageReceipt,
        "nested reveal stage receipt",
    )
    if (
        reveal_receipt.stage != WindowStage.REVEAL_AND_SCORE.value
        or reveal_receipt.window_id != manifest.window_id
    ):
        raise WeightBuildBindingError("nested_reveal_receipt_binding_mismatch")
    for reference in reveal_receipt.objects:
        objects.resolve(reference)
    reveal_manifest_bytes = objects.resolve(manifest.reveal_stage_manifest)
    nested_payloads = {
        reference.sha256: objects.resolve(reference) for reference in reveal_receipt.objects
    }
    policy = _parse_canonical(
        objects.resolve(manifest.policy_object),
        ScoringPolicy,
        "weight-build policy",
    )
    try:
        resolved = resolve_reveal_receipt(policy, reveal_receipt, nested_payloads)
    except Exception as error:
        raise WeightBuildBindingError("nested_reveal_receipt_does_not_replay") from error
    reveal_manifest = resolved.manifest
    if canonical_json_bytes(reveal_manifest) != reveal_manifest_bytes:
        raise WeightBuildBindingError("nested_reveal_manifest_object_mismatch")
    nested_refs = {item.sha256 for item in reveal_receipt.objects}
    if (
        manifest.reveal_stage_manifest.sha256 not in nested_refs
        or reveal_manifest.operation_id != reveal_receipt.operation_id
        or reveal_manifest.window_id != manifest.window_id
        or reveal_manifest.window_index != manifest.window_index
        or reveal_manifest.scoring_policy_hash != manifest.scoring_policy_hash
        or reveal_manifest.protocol_transition_result.sha256
        != manifest.protocol_transition_result.sha256
    ):
        raise WeightBuildBindingError("nested_reveal_manifest_binding_mismatch")
    transition = objects.resolve(reveal_manifest.protocol_transition_result)
    if transition != objects.resolve(manifest.protocol_transition_result):
        raise WeightBuildBindingError("nested_protocol_transition_object_mismatch")
    _validate_transition_bytes_from_state_evidence(
        transition,
        state=state,
        transition_operation_id=reveal_manifest.transition_operation_id,
        transition_evidence_sha256=reveal_manifest.transition_evidence_sha256,
    )
    if (
        resolved.result.window_id != manifest.window_id
        or resolved.result.window_index != manifest.window_index
        or resolved.result.scoring_policy_hash != manifest.scoring_policy_hash
        or resolved.result.void_reason_codes
        or resolved.resulting_protocol_state_digest != state.state_digest
    ):
        raise WeightBuildBindingError("nested_reveal_result_not_weight_eligible")


def resolve_weight_build_close_snapshot(
    *,
    policy: ScoringPolicy,
    receipt: StageJournalRecord,
    objects: Mapping[str, bytes],
    verifier: MultiStorageProofVerifier,
) -> FinalizedSnapshotRef:
    """Resolve the exact proof-backed shared close from one weight-build receipt.

    This is the narrow terminal-stage handoff.  It replays the complete stage,
    including every storage proof, before returning the close snapshot.
    """

    replay = replay_weight_build_stage_receipt(receipt.receipt, objects, verifier=verifier)
    manifest_objects = _ReceiptObjects(receipt.receipt, objects)
    manifest, _ = manifest_objects.find_schema(
        WEIGHT_BUILD_STAGE_SCHEMA,
        WeightBuildStageManifest,
    )
    retained_policy = _parse_canonical(
        manifest_objects.resolve(manifest.policy_object),
        ScoringPolicy,
        "weight-build policy",
    )
    if retained_policy != policy:
        raise WeightBuildBindingError("weight_build_close_policy_mismatch")
    return replay.schedule.weight_commit_close_block.snapshot


@dataclass(frozen=True, slots=True)
class ProofBackedWeightBuildCloseResolver:
    """Inject a pinned trie verifier into the terminal effect's narrow port."""

    verifier: MultiStorageProofVerifier

    def __post_init__(self) -> None:
        if not callable(self.verifier):
            raise TypeError("weight-build close resolver requires a proof verifier")

    def __call__(
        self,
        *,
        policy: ScoringPolicy,
        receipt: StageJournalRecord,
        objects: Mapping[str, bytes],
    ) -> FinalizedSnapshotRef:
        return resolve_weight_build_close_snapshot(
            policy=policy,
            receipt=receipt,
            objects=objects,
            verifier=self.verifier,
        )


@dataclass(frozen=True, slots=True)
class ProofBackedWeightBuildReplayHook:
    """Calibration-bundle hook that authenticates and reproduces the row."""

    verifier: MultiStorageProofVerifier

    def __post_init__(self) -> None:
        if not callable(self.verifier):
            raise TypeError("weight-build replay hook requires a proof verifier")

    def __call__(
        self,
        *,
        policy: ScoringPolicy,
        evidence: Any,
        receipt: StageReceipt,
        objects: Mapping[str, bytes],
    ) -> bool:
        if (
            not isinstance(policy, ScoringPolicy)
            or getattr(evidence, "stage_id", None) != WindowStage.WEIGHT_BUILD.value
            or getattr(evidence, "window_id", None) != receipt.window_id
        ):
            return False
        replay = replay_weight_build_stage_receipt(
            receipt,
            objects,
            verifier=self.verifier,
        )
        manifest_objects = _ReceiptObjects(receipt, objects)
        manifest, _ = manifest_objects.find_schema(
            WEIGHT_BUILD_STAGE_SCHEMA,
            WeightBuildStageManifest,
        )
        retained_policy = _parse_canonical(
            manifest_objects.resolve(manifest.policy_object),
            ScoringPolicy,
            "weight-build policy",
        )
        return retained_policy == policy and replay.window_id == receipt.window_id


__all__ = [
    "WEIGHT_BUILD_PROOF_SCHEMA",
    "WEIGHT_BUILD_RESULT_SCHEMA",
    "WEIGHT_BUILD_SNAPSHOT_SCHEMA",
    "WEIGHT_BUILD_STAGE_SCHEMA",
    "WEIGHT_BUILD_STATE_SCHEMA",
    "WEIGHT_COMMIT_SCHEDULE_SCHEMA",
    "ProofBackedWeightBuildCloseResolver",
    "ProofBackedWeightBuildReplayHook",
    "ProofBackedWeightScheduleMaterial",
    "ShadowWeightBuildEffect",
    "VerifiedWeightBuildSnapshot",
    "WeightBuildBindingError",
    "WeightBuildEffectError",
    "WeightBuildEffectPorts",
    "WeightBuildLimitError",
    "WeightBuildPending",
    "WeightBuildProofEvidence",
    "WeightBuildReplay",
    "WeightBuildResultEvidence",
    "WeightBuildSnapshotEvidence",
    "WeightBuildStageManifest",
    "WeightBuildStateEvidence",
    "WeightCommitScheduleEvidence",
    "WeightScheduleCapture",
    "materialize_weight_schedule_evidence",
    "replay_weight_build_stage_receipt",
    "replay_weight_build_stage_record",
    "resolve_weight_build_close_snapshot",
]
