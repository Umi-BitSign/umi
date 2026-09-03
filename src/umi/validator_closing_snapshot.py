"""Proof-backed complete closing-block snapshots for the live shadow validator.

The pool selector must not trust an SDK metagraph or a node's decoded query
responses.  This module derives the complete SN78 closing snapshot from raw
storage values authenticated to one independently finalized state root.  It
also retains every runtime byte, storage claim, trie proof and finality replay
input needed by an auditor to repeat the storage half of the collection.

The collector is deliberately read-only.  It has no signer, wallet, call
composition, submission, or generic mutation capability.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Annotated, Any, Literal, Protocol

import bittensor as bt
import bittensor_core
from pydantic import Field, model_validator
from typing_extensions import Self

from .chain_evidence import FinalizedSnapshotRef
from .encoding import account_id32
from .grandpa_finality_supervisor import parse_finality_acceptance_receipt
from .policy import (
    LiveChainObservationPin,
    ScoringPolicy,
    require_live_chain_observation,
    scoring_policy_hash,
)
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_chain import (
    DecodedStorageClaim,
    FinalizedProofCollector,
    FinalizedRuntimePin,
    MultiStorageEvidence,
    MultiStorageProofVerifier,
    PinnedRuntimeContext,
    StorageClaim,
    StorageReadSpec,
    VerifiedStorageBatch,
)
from .validator_chain_scan import FinalityAttestationReplayBinding
from .validator_plans import VerifiedFinalizedBlock
from .validator_pool_effect import (
    ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE,
    ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA,
    CLOSING_SNAPSHOT_PROOF_PROFILE,
    CLOSING_SNAPSHOT_SCHEMA,
    MAX_CLOSING_PROOF_BYTES,
    AnnouncementValidatorSnapshot,
    ClosingNeuron,
    ClosingPublisherState,
    ClosingSnapshot,
    ClosingValidatorState,
    VerifiedClosingSnapshot,
)
from .validator_state import StageWorkItem, WindowPlan, WindowStage

CLOSING_SNAPSHOT_EVIDENCE_SCHEMA = "umi-validator-closing-snapshot-evidence/1"
CLOSING_SNAPSHOT_COLLECTOR_REVISION = "umi-closing-snapshot-collector/1"
ANNOUNCEMENT_VALIDATOR_EVIDENCE_SCHEMA = "umi-announcement-validator-evidence/1"
ANNOUNCEMENT_VALIDATOR_COLLECTOR_REVISION = "umi-announcement-validator-collector/1"

MAX_STORAGE_KEYS_PER_PROOF = 512
MAX_PROOF_BATCHES = 32
MAX_PROOF_NODES_PER_BATCH = 4_096
MAX_RUNTIME_METADATA_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_VERSION_BYTES = 64 * 1024
MAX_FINALITY_ATTESTATION_BYTES = 16 * 1024 * 1024
MAX_STORAGE_VALUE_BYTES = 16 * 1024 * 1024
MAX_STORAGE_KEY_BYTES = 512
MAX_PARAMETER_TEXT_BYTES = 512
MAX_UIDS = 65_536

_HEX32_PATTERN = r"^[0-9a-f]{64}$"
_BLOCK_HASH_PATTERN = r"^0x[0-9a-f]{64}$"
_HEX_BYTES_PATTERN = r"^0x(?:[0-9a-f]{2})*$"

Hex32 = Annotated[str, Field(pattern=_HEX32_PATTERN)]
BlockHash = Annotated[str, Field(pattern=_BLOCK_HASH_PATTERN)]
HexBytes = Annotated[str, Field(pattern=_HEX_BYTES_PATTERN)]
StorageParameter = int | str


class ClosingSnapshotCollectorError(RuntimeError):
    """Stable fail-closed error at the complete closing-snapshot boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"closing snapshot collection failed: {reason_code}")


class ClosingFinalityPort(Protocol):
    """The exact-height read surface supplied by the durable finality store."""

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None: ...

    async def verified_scan_interval(self, start_height: int, end_height: int) -> Any: ...

    async def verified_acceptance_time_at(self, height: int) -> int | None: ...

    async def verified_acceptance_receipt_at(self, height: int) -> bytes | None: ...


class ClosingRuntimePinEvidence(StrictProtocolModel):
    metadata_sha256: Hex32
    spec_version: Annotated[int, Field(gt=0)]
    transaction_version: Annotated[int, Field(gt=0)]
    state_version: Literal[1]
    ss58_prefix: Literal[42]
    metadata: HexBytes
    runtime_version: HexBytes

    @model_validator(mode="after")
    def validate_exact_bytes(self) -> Self:
        metadata = _unhex(self.metadata, "runtime_metadata_invalid")
        version = _unhex(self.runtime_version, "runtime_version_invalid")
        if not metadata or len(metadata) > MAX_RUNTIME_METADATA_BYTES:
            raise ValueError("runtime metadata exceeds its byte ceiling")
        if not version or len(version) > MAX_RUNTIME_VERSION_BYTES:
            raise ValueError("runtime version exceeds its byte ceiling")
        if hashlib.sha256(metadata).hexdigest() != self.metadata_sha256:
            raise ValueError("runtime metadata does not reproduce its digest")
        return self


class ClosingFinalityEvidence(StrictProtocolModel):
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    parent_block_number: Annotated[int, Field(ge=0)]
    parent_block_hash: BlockHash
    parent_parent_hash: BlockHash
    parent_state_root: BlockHash
    state_root: BlockHash
    extrinsics_root: BlockHash
    timestamp_ms: Annotated[int, Field(ge=0)]
    finality_verifier_sha256: Hex32
    finality_attestation_sha256: Hex32
    finality_attestation: HexBytes
    accepted_at_unix_ms: Annotated[int, Field(gt=0)]
    acceptance_receipt_sha256: Hex32
    acceptance_receipt: HexBytes
    replay_binding: dict[str, int | str | None]

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        if self.parent_block_number + 1 != self.block_number:
            raise ValueError("closing finality parent is not adjacent")
        raw = _unhex(self.finality_attestation, "finality_attestation_invalid")
        if not raw or len(raw) > MAX_FINALITY_ATTESTATION_BYTES:
            raise ValueError("finality attestation exceeds its byte ceiling")
        if hashlib.sha256(raw).hexdigest() != self.finality_attestation_sha256:
            raise ValueError("finality attestation does not reproduce its digest")
        acceptance_bytes = _unhex(
            self.acceptance_receipt,
            "finality_acceptance_receipt_invalid",
        )
        if hashlib.sha256(acceptance_bytes).hexdigest() != self.acceptance_receipt_sha256:
            raise ValueError("finality acceptance receipt does not reproduce its digest")
        try:
            acceptance = parse_finality_acceptance_receipt(acceptance_bytes)
        except ValueError as error:
            raise ValueError("finality acceptance receipt is invalid") from error
        if (
            acceptance.height != self.block_number
            or acceptance.block_hash != self.block_hash
            or acceptance.evidence_sha256 != self.finality_attestation_sha256
            or acceptance.accepted_at_unix_ms != self.accepted_at_unix_ms
        ):
            raise ValueError("finality acceptance receipt disagrees with the attestation")
        required = {
            "minimum_finalized_block",
            "maximum_records",
            "startup_timeout_seconds",
            "expected_sequence",
            "previous_number",
            "previous_timestamp_ms",
            "previous_hash",
            "previous_digest",
        }
        if set(self.replay_binding) != required:
            raise ValueError("finality replay binding has another shape")
        return self


class ClosingStorageClaimEvidence(StrictProtocolModel):
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
        if self.raw_value is not None:
            raw = _unhex(self.raw_value, "storage_value_invalid")
            if len(raw) > MAX_STORAGE_VALUE_BYTES:
                raise ValueError("storage value exceeds its byte ceiling")
        for value in self.params:
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError("storage parameter has another type")
            if isinstance(value, int) and value < 0:
                raise ValueError("storage integer parameter must be nonnegative")
            if isinstance(value, str) and len(value.encode("utf-8")) > MAX_PARAMETER_TEXT_BYTES:
                raise ValueError("storage text parameter exceeds its byte ceiling")
        return self


class ClosingStorageProofBatchEvidence(StrictProtocolModel):
    claims: Annotated[
        list[ClosingStorageClaimEvidence],
        Field(min_length=1, max_length=MAX_STORAGE_KEYS_PER_PROOF),
    ]
    proof_nodes: Annotated[
        list[HexBytes],
        Field(min_length=1, max_length=MAX_PROOF_NODES_PER_BATCH),
    ]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        keys = [_unhex(item.storage_key, "storage_key_invalid") for item in self.claims]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("proof-batch claims must be unique and sorted by storage key")
        nodes = [_unhex(item, "proof_node_invalid") for item in self.proof_nodes]
        if any(not node for node in nodes) or len(set(nodes)) != len(nodes):
            raise ValueError("proof nodes must be nonempty and unique")
        return self


class ClosingSnapshotProofEvidence(StrictProtocolModel):
    schema_: Literal[CLOSING_SNAPSHOT_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    proof_profile: Literal[CLOSING_SNAPSHOT_PROOF_PROFILE]
    collector_revision: Literal[CLOSING_SNAPSHOT_COLLECTOR_REVISION]
    netuid: Literal[78]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    closing_block: Annotated[int, Field(gt=0)]
    finality: ClosingFinalityEvidence
    live_chain_observation: LiveChainObservationPin
    runtime: ClosingRuntimePinEvidence
    proof_batches: Annotated[
        list[ClosingStorageProofBatchEvidence],
        Field(min_length=1, max_length=MAX_PROOF_BATCHES),
    ]
    total_unique_storage_keys: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_complete_index(self) -> Self:
        if self.closing_block != self.finality.block_number:
            raise ValueError("finality evidence names another closing block")
        keys = [item.storage_key for batch in self.proof_batches for item in batch.claims]
        if len(keys) != self.total_unique_storage_keys or len(set(keys)) != len(keys):
            raise ValueError("closing proof batches do not form one unique storage-key set")
        return self


class AnnouncementValidatorProofEvidence(StrictProtocolModel):
    schema_: Literal[ANNOUNCEMENT_VALIDATOR_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    proof_profile: Literal[ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE]
    collector_revision: Literal[ANNOUNCEMENT_VALIDATOR_COLLECTOR_REVISION]
    netuid: Literal[78]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    announcement_block: Annotated[int, Field(gt=0)]
    finality: ClosingFinalityEvidence
    live_chain_observation: LiveChainObservationPin
    runtime: ClosingRuntimePinEvidence
    proof_batches: Annotated[
        list[ClosingStorageProofBatchEvidence],
        Field(min_length=1, max_length=MAX_PROOF_BATCHES),
    ]
    total_unique_storage_keys: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_complete_index(self) -> Self:
        if self.announcement_block != self.finality.block_number:
            raise ValueError("finality evidence names another announcement block")
        keys = [item.storage_key for batch in self.proof_batches for item in batch.claims]
        if len(keys) != self.total_unique_storage_keys or len(set(keys)) != len(keys):
            raise ValueError("announcement proof batches do not form one unique storage-key set")
        return self


@dataclass(frozen=True, slots=True)
class ReplayedClosingStorage:
    """Storage claims independently reconstructed from retained proof evidence."""

    evidence: ClosingSnapshotProofEvidence
    runtime: PinnedRuntimeContext
    reads: tuple[DecodedStorageClaim, ...]


@dataclass(frozen=True, slots=True)
class ReplayedAnnouncementValidatorStorage:
    """Announcement-block validator claims reconstructed from retained proofs."""

    evidence: AnnouncementValidatorProofEvidence
    runtime: PinnedRuntimeContext
    reads: tuple[DecodedStorageClaim, ...]


class ProofCollectorPort(Protocol):
    async def pinned_runtime(
        self,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext: ...

    async def storage_reads(
        self,
        runtime: PinnedRuntimeContext,
        specs: Sequence[StorageReadSpec],
    ) -> VerifiedStorageBatch: ...


class ProofBackedClosingSnapshotCollector:
    """Produce one complete, policy-bound SN78 closing snapshot."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        finality: ClosingFinalityPort,
        proofs: ProofCollectorPort | FinalizedProofCollector,
        maximum_storage_keys_per_proof: int = MAX_STORAGE_KEYS_PER_PROOF,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("closing snapshot policy must be ScoringPolicy")
        if policy.implementation_pins.pin_profile != "live_shadow_calibration":
            raise ValueError("closing snapshot collection requires a live-shadow policy")
        if policy.implementation_pins.live_chain is None:
            raise ValueError("closing snapshot policy lacks a live-chain runtime pin")
        for name in (
            "verified_block_at",
            "verified_scan_interval",
            "verified_acceptance_time_at",
            "verified_acceptance_receipt_at",
        ):
            if not callable(getattr(finality, name, None)):
                raise TypeError(
                    "finality must provide exact-height block, scan, and acceptance evidence"
                )
        if not callable(getattr(proofs, "pinned_runtime", None)) or not callable(
            getattr(proofs, "storage_reads", None)
        ):
            raise TypeError("proofs must provide pinned runtime and storage multiproofs")
        if (
            isinstance(maximum_storage_keys_per_proof, bool)
            or not isinstance(maximum_storage_keys_per_proof, int)
            or not 1 <= maximum_storage_keys_per_proof <= MAX_STORAGE_KEYS_PER_PROOF
        ):
            raise ValueError("storage keys per proof must be in [1, 512]")
        self.policy = policy
        self.finality = finality
        self.proofs = proofs
        self.maximum_storage_keys_per_proof = maximum_storage_keys_per_proof
        self.policy_hash = scoring_policy_hash(policy)

    async def __call__(self, work: StageWorkItem) -> VerifiedClosingSnapshot:
        if not isinstance(work, StageWorkItem):
            raise TypeError("closing snapshot work must be StageWorkItem")
        if work.stage is not WindowStage.POOL_AND_SELECTION:
            raise ClosingSnapshotCollectorError("wrong_stage")
        window = work.window.plan
        if window.scoring_policy_hash != self.policy_hash:
            raise ClosingSnapshotCollectorError("policy_binding_mismatch")
        if window.closing_block <= 0:
            raise ClosingSnapshotCollectorError("closing_block_invalid")

        (
            announcement_snapshot,
            announcement_snapshot_bytes,
            announcement_proof_bytes,
        ) = await self.collect_announcement_validators(window)

        block = await self.finality.verified_block_at(window.closing_block)
        interval = await self.finality.verified_scan_interval(
            window.closing_block,
            window.closing_block,
        )
        accepted_at = await self.finality.verified_acceptance_time_at(window.closing_block)
        acceptance_receipt = await self.finality.verified_acceptance_receipt_at(
            window.closing_block
        )
        if block is None or interval is None:
            raise ClosingSnapshotCollectorError("closing_finality_unavailable")
        identity, attestation, replay_binding, interval_acceptance = _one_finality_record(
            interval,
            reason_prefix="closing",
        )
        if (
            accepted_at is None
            or acceptance_receipt is None
            or acceptance_receipt != interval_acceptance
        ):
            raise ClosingSnapshotCollectorError("closing_acceptance_evidence_unavailable")
        acceptance = _acceptance(
            acceptance_receipt,
            identity=identity,
            attestation=attestation,
            reason_prefix="closing",
        )
        if accepted_at != acceptance.accepted_at_unix_ms:
            raise ClosingSnapshotCollectorError("closing_acceptance_time_mismatch")
        self._validate_finality(
            block,
            identity,
            attestation,
            window.closing_block,
            reason_prefix="closing",
        )

        live = self.policy.implementation_pins.live_chain
        if live is None:  # pragma: no cover - constructor narrows this
            raise ClosingSnapshotCollectorError("live_chain_pin_missing")
        require_live_chain_observation(self.policy, block.chain_observation)
        runtime_pin = FinalizedRuntimePin(
            metadata_sha256=live.metadata_sha256,
            spec_version=live.runtime_spec_version,
            transaction_version=live.transaction_version,
            state_version=live.state_version,
            ss58_prefix=42,
        )
        runtime = await self.proofs.pinned_runtime(identity.snapshot, runtime_pin)
        if runtime.snapshot != identity.snapshot or runtime.pin != runtime_pin:
            raise ClosingSnapshotCollectorError("runtime_snapshot_mismatch")

        batches: list[VerifiedStorageBatch] = []
        base = await self._read_chunks(
            runtime,
            (
                StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
                StorageReadSpec("SubtensorModule", "SubnetworkN", (78,)),
                StorageReadSpec("SubtensorModule", "ValidatorPermit", (78,)),
            ),
        )
        batches.extend(base)
        base_values = _lookup(base)
        if _bool(_get(base_values, "SubtensorModule", "NetworksAdded", (78,))) is not True:
            raise ClosingSnapshotCollectorError("subnet_not_added")
        uid_count = _uint(
            _get(base_values, "SubtensorModule", "SubnetworkN", (78,)),
            "subnetwork_n_invalid",
            maximum=MAX_UIDS,
        )
        if uid_count == 0:
            raise ClosingSnapshotCollectorError("subnet_empty")
        permits_value = _get(base_values, "SubtensorModule", "ValidatorPermit", (78,))
        if (
            isinstance(permits_value, (str, bytes, bytearray))
            or not isinstance(permits_value, Sequence)
            or len(permits_value) != uid_count
            or any(not isinstance(value, bool) for value in permits_value)
        ):
            raise ClosingSnapshotCollectorError("validator_permit_vector_invalid")
        permits = tuple(permits_value)

        keys_batches = await self._read_chunks(
            runtime,
            tuple(
                StorageReadSpec("SubtensorModule", "Keys", (78, uid)) for uid in range(uid_count)
            ),
        )
        batches.extend(keys_batches)
        keys_lookup = _lookup(keys_batches)
        hotkeys = tuple(
            _account(
                _get(keys_lookup, "SubtensorModule", "Keys", (78, uid)),
                "uid_hotkey_invalid",
            )
            for uid in range(uid_count)
        )
        if len({account_id32(value) for value in hotkeys}) != uid_count:
            raise ClosingSnapshotCollectorError("uid_hotkey_duplicate")

        dynamic_specs: list[StorageReadSpec] = []
        for hotkey in hotkeys:
            dynamic_specs.extend(
                (
                    StorageReadSpec("SubtensorModule", "Uids", (78, hotkey)),
                    StorageReadSpec("SubtensorModule", "Axons", (78, hotkey)),
                    StorageReadSpec("SubtensorModule", "HotkeyRoot", (78, hotkey)),
                    StorageReadSpec("SubtensorModule", "HotkeySuccessor", (78, hotkey)),
                )
            )
        registry_accounts = {
            *(entry.publisher_hotkey for entry in self.policy.publisher_registry),
            *(entry.validator_hotkey for entry in self.policy.validator_registry),
        }
        for hotkey in registry_accounts:
            dynamic_specs.append(StorageReadSpec("SubtensorModule", "Uids", (78, hotkey)))
        for entry in self.policy.publisher_registry:
            dynamic_specs.extend(
                (
                    StorageReadSpec("SubtensorModule", "Owner", (entry.publisher_hotkey,)),
                    StorageReadSpec(
                        "SubtensorModule",
                        "MinerCollateral",
                        (78, entry.publisher_hotkey, entry.owner_coldkey),
                    ),
                    StorageReadSpec(
                        "Commitments",
                        "CommitmentOf",
                        (78, entry.publisher_hotkey),
                    ),
                )
            )
        dynamic_batches = await self._read_chunks(runtime, tuple(dynamic_specs))
        batches.extend(dynamic_batches)
        values = _lookup((*base, *keys_batches, *dynamic_batches))

        uid_by_account: dict[bytes, int] = {}
        neurons: list[ClosingNeuron] = []
        for uid, hotkey in enumerate(hotkeys):
            inverse = _optional_uint(
                _get(values, "SubtensorModule", "Uids", (78, hotkey)),
                "uid_inverse_invalid",
                maximum=MAX_UIDS - 1,
            )
            if inverse != uid:
                raise ClosingSnapshotCollectorError("uid_inverse_mismatch")
            account = account_id32(hotkey)
            uid_by_account[account] = uid
            root_value = _get(values, "SubtensorModule", "HotkeyRoot", (78, hotkey))
            root = hotkey if root_value is None else _account(root_value, "hotkey_root_invalid")
            successor = _get(
                values,
                "SubtensorModule",
                "HotkeySuccessor",
                (78, hotkey),
            )
            if successor is not None:
                _account(successor, "hotkey_successor_invalid")
            neurons.append(
                ClosingNeuron(
                    uid=uid,
                    hotkey=hotkey,
                    root=root,
                    registered=True,
                    validator_permit=permits[uid],
                    serving_url=_serving_url(
                        _get(values, "SubtensorModule", "Axons", (78, hotkey))
                    ),
                )
            )

        publishers: list[ClosingPublisherState] = []
        for entry in self.policy.publisher_registry:
            publisher_account = account_id32(entry.publisher_hotkey)
            inverse = _optional_uint(
                _get(values, "SubtensorModule", "Uids", (78, entry.publisher_hotkey)),
                "publisher_uid_invalid",
                maximum=MAX_UIDS - 1,
            )
            registered = (
                inverse is not None
                and inverse < uid_count
                and account_id32(hotkeys[inverse]) == publisher_account
            )
            owner = _account(
                _get(values, "SubtensorModule", "Owner", (entry.publisher_hotkey,)),
                "publisher_owner_invalid",
            )
            collateral = _collateral(
                _get(
                    values,
                    "SubtensorModule",
                    "MinerCollateral",
                    (78, entry.publisher_hotkey, entry.owner_coldkey),
                )
            )
            anchor_digest, anchor_block = _commitment_anchor(
                _get(
                    values,
                    "Commitments",
                    "CommitmentOf",
                    (78, entry.publisher_hotkey),
                )
            )
            publishers.append(
                ClosingPublisherState(
                    publisher_hotkey=entry.publisher_hotkey,
                    owner_coldkey=owner,
                    control_group_id=entry.control_group_id,
                    registered=registered,
                    locked_collateral_alpha_rao=collateral[0],
                    minimum_locked_collateral_alpha_rao=collateral[1],
                    pool_manifest_sha256=anchor_digest,
                    anchor_inclusion_block=anchor_block,
                )
            )
        publishers.sort(key=lambda item: account_id32(item.publisher_hotkey))

        validators: list[ClosingValidatorState] = []
        for entry in self.policy.validator_registry:
            uid = _optional_uint(
                _get(values, "SubtensorModule", "Uids", (78, entry.validator_hotkey)),
                "validator_uid_invalid",
                maximum=MAX_UIDS - 1,
            )
            registered = (
                uid is not None
                and uid < uid_count
                and account_id32(hotkeys[uid]) == account_id32(entry.validator_hotkey)
            )
            validators.append(
                ClosingValidatorState(
                    validator_hotkey=entry.validator_hotkey,
                    validator_permit=bool(registered and permits[uid]),
                )
            )
        validators.sort(key=lambda item: account_id32(item.validator_hotkey))

        proof_batches = [_proof_batch(batch) for batch in batches]
        all_storage_keys = [claim.storage_key for batch in proof_batches for claim in batch.claims]
        if len(set(all_storage_keys)) != len(all_storage_keys):
            raise ClosingSnapshotCollectorError("duplicate_proven_storage_key")
        proof_model = ClosingSnapshotProofEvidence(
            schema=CLOSING_SNAPSHOT_EVIDENCE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            proof_profile=CLOSING_SNAPSHOT_PROOF_PROFILE,
            collector_revision=CLOSING_SNAPSHOT_COLLECTOR_REVISION,
            netuid=78,
            window_id=window.window_id,
            window_index=window.window_index,
            scoring_policy_hash=self.policy_hash,
            closing_block=window.closing_block,
            finality=ClosingFinalityEvidence(
                block_number=identity.snapshot.block_number,
                block_hash=identity.snapshot.block_hash,
                parent_block_number=identity.parent_snapshot.block_number,
                parent_block_hash=identity.parent_snapshot.block_hash,
                parent_parent_hash=identity.parent_snapshot.parent_hash,
                parent_state_root=identity.parent_snapshot.state_root,
                state_root=identity.snapshot.state_root,
                extrinsics_root=identity.extrinsics_root,
                timestamp_ms=block.timestamp_ms,
                finality_verifier_sha256=identity.finality_verifier_sha256,
                finality_attestation_sha256=identity.finality_evidence_sha256,
                finality_attestation=_hex(attestation),
                accepted_at_unix_ms=acceptance.accepted_at_unix_ms,
                acceptance_receipt_sha256=hashlib.sha256(acceptance_receipt).hexdigest(),
                acceptance_receipt=_hex(acceptance_receipt),
                replay_binding=asdict(replay_binding),
            ),
            live_chain_observation=live,
            runtime=ClosingRuntimePinEvidence(
                metadata_sha256=runtime.pin.metadata_sha256,
                spec_version=runtime.pin.spec_version,
                transaction_version=runtime.pin.transaction_version,
                state_version=runtime.pin.state_version,
                ss58_prefix=runtime.pin.ss58_prefix,
                metadata=_hex(runtime.metadata_bytes),
                runtime_version=_hex(runtime.runtime_version_bytes),
            ),
            proof_batches=proof_batches,
            total_unique_storage_keys=len(all_storage_keys),
        )
        proof_bytes = canonical_json_bytes(proof_model)
        if len(proof_bytes) > MAX_CLOSING_PROOF_BYTES:
            raise ClosingSnapshotCollectorError("closing_proof_evidence_limit")
        snapshot = ClosingSnapshot(
            schema=CLOSING_SNAPSHOT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            proof_profile=CLOSING_SNAPSHOT_PROOF_PROFILE,
            collector_revision=CLOSING_SNAPSHOT_COLLECTOR_REVISION,
            proof_evidence_sha256=hashlib.sha256(proof_bytes).hexdigest(),
            netuid=78,
            window_id=window.window_id,
            window_index=window.window_index,
            scoring_policy_hash=self.policy_hash,
            closing_block=window.closing_block,
            closing_block_hash=identity.snapshot.block_hash,
            closing_block_timestamp_ms=block.timestamp_ms,
            accepted_at_unix_ms=acceptance.accepted_at_unix_ms,
            complete_publisher_registry=True,
            complete_validator_registry=True,
            complete_uid_snapshot=True,
            publishers=publishers,
            validators=validators,
            neurons=neurons,
        )
        return VerifiedClosingSnapshot(
            snapshot=snapshot,
            snapshot_bytes=canonical_json_bytes(snapshot),
            proof_evidence_bytes=proof_bytes,
            announcement_snapshot=announcement_snapshot,
            announcement_snapshot_bytes=announcement_snapshot_bytes,
            announcement_proof_evidence_bytes=announcement_proof_bytes,
        )

    async def collect_announcement_validators(
        self,
        window: WindowPlan,
    ) -> tuple[AnnouncementValidatorSnapshot, bytes, bytes]:
        """Collect the announcement authority without waiting for closing block.

        Availability certification must finish before ``proposal_close_block``.
        This entry point deliberately shares the exact finality, runtime, storage
        proof, and snapshot construction used by the later closing collector.
        The caller remains responsible for proving that its current finalized
        head is still inside the proposal interval.
        """

        if not isinstance(window, WindowPlan):
            raise TypeError("announcement window must be WindowPlan")
        if window.scoring_policy_hash != self.policy_hash:
            raise ClosingSnapshotCollectorError("policy_binding_mismatch")
        height = window.announcement_block
        block = await self.finality.verified_block_at(height)
        interval = await self.finality.verified_scan_interval(height, height)
        accepted_at = await self.finality.verified_acceptance_time_at(height)
        acceptance_receipt = await self.finality.verified_acceptance_receipt_at(height)
        if block is None or interval is None:
            raise ClosingSnapshotCollectorError("announcement_finality_unavailable")
        identity, attestation, replay_binding, interval_acceptance = _one_finality_record(
            interval,
            reason_prefix="announcement",
        )
        if (
            accepted_at is None
            or acceptance_receipt is None
            or acceptance_receipt != interval_acceptance
        ):
            raise ClosingSnapshotCollectorError("announcement_acceptance_evidence_unavailable")
        acceptance = _acceptance(
            acceptance_receipt,
            identity=identity,
            attestation=attestation,
            reason_prefix="announcement",
        )
        if accepted_at != acceptance.accepted_at_unix_ms:
            raise ClosingSnapshotCollectorError("announcement_acceptance_time_mismatch")
        self._validate_finality(
            block,
            identity,
            attestation,
            height,
            reason_prefix="announcement",
        )

        live = self.policy.implementation_pins.live_chain
        if live is None:  # pragma: no cover - constructor narrows this
            raise ClosingSnapshotCollectorError("live_chain_pin_missing")
        require_live_chain_observation(self.policy, block.chain_observation)
        runtime_pin = FinalizedRuntimePin(
            metadata_sha256=live.metadata_sha256,
            spec_version=live.runtime_spec_version,
            transaction_version=live.transaction_version,
            state_version=live.state_version,
            ss58_prefix=42,
        )
        runtime = await self.proofs.pinned_runtime(identity.snapshot, runtime_pin)
        if runtime.snapshot != identity.snapshot or runtime.pin != runtime_pin:
            raise ClosingSnapshotCollectorError("announcement_runtime_snapshot_mismatch")

        batches: list[VerifiedStorageBatch] = []
        base = await self._read_chunks(
            runtime,
            (
                StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
                StorageReadSpec("SubtensorModule", "SubnetworkN", (78,)),
                StorageReadSpec("SubtensorModule", "ValidatorPermit", (78,)),
            ),
        )
        batches.extend(base)
        base_values = _lookup(base)
        if _bool(_get(base_values, "SubtensorModule", "NetworksAdded", (78,))) is not True:
            raise ClosingSnapshotCollectorError("announcement_subnet_not_added")
        uid_count = _uint(
            _get(base_values, "SubtensorModule", "SubnetworkN", (78,)),
            "announcement_subnetwork_n_invalid",
            maximum=MAX_UIDS,
        )
        permits_value = _get(base_values, "SubtensorModule", "ValidatorPermit", (78,))
        if (
            uid_count == 0
            or isinstance(permits_value, (str, bytes, bytearray))
            or not isinstance(permits_value, Sequence)
            or len(permits_value) != uid_count
            or any(not isinstance(value, bool) for value in permits_value)
        ):
            raise ClosingSnapshotCollectorError("announcement_validator_permit_vector_invalid")
        permits = tuple(permits_value)

        uid_batches = await self._read_chunks(
            runtime,
            tuple(
                StorageReadSpec("SubtensorModule", "Uids", (78, entry.validator_hotkey))
                for entry in self.policy.validator_registry
            ),
        )
        batches.extend(uid_batches)
        uid_values = _lookup(uid_batches)
        registry_uids: dict[bytes, int | None] = {}
        for entry in self.policy.validator_registry:
            registry_uids[account_id32(entry.validator_hotkey)] = _optional_uint(
                _get(
                    uid_values,
                    "SubtensorModule",
                    "Uids",
                    (78, entry.validator_hotkey),
                ),
                "announcement_validator_uid_invalid",
                maximum=MAX_UIDS - 1,
            )
        key_uids = sorted(
            {uid for uid in registry_uids.values() if uid is not None and uid < uid_count}
        )
        key_batches: tuple[VerifiedStorageBatch, ...] = ()
        if key_uids:
            key_batches = await self._read_chunks(
                runtime,
                tuple(StorageReadSpec("SubtensorModule", "Keys", (78, uid)) for uid in key_uids),
            )
            batches.extend(key_batches)
        key_values = _lookup(key_batches)

        validators: list[ClosingValidatorState] = []
        for entry in self.policy.validator_registry:
            account = account_id32(entry.validator_hotkey)
            uid = registry_uids[account]
            registered = False
            if uid is not None and uid < uid_count:
                hotkey = _account(
                    _get(key_values, "SubtensorModule", "Keys", (78, uid)),
                    "announcement_uid_hotkey_invalid",
                )
                registered = account_id32(hotkey) == account
            validators.append(
                ClosingValidatorState(
                    validator_hotkey=entry.validator_hotkey,
                    validator_permit=bool(registered and uid is not None and permits[uid]),
                )
            )
        validators.sort(key=lambda item: account_id32(item.validator_hotkey))

        proof_batches = [_proof_batch(batch) for batch in batches]
        storage_keys = [claim.storage_key for batch in proof_batches for claim in batch.claims]
        if len(set(storage_keys)) != len(storage_keys):
            raise ClosingSnapshotCollectorError("announcement_duplicate_proven_storage_key")
        proof = AnnouncementValidatorProofEvidence(
            schema=ANNOUNCEMENT_VALIDATOR_EVIDENCE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            proof_profile=ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE,
            collector_revision=ANNOUNCEMENT_VALIDATOR_COLLECTOR_REVISION,
            netuid=78,
            window_id=window.window_id,
            window_index=window.window_index,
            scoring_policy_hash=self.policy_hash,
            announcement_block=height,
            finality=_finality_evidence(
                block=block,
                identity=identity,
                attestation=attestation,
                replay_binding=replay_binding,
                acceptance_receipt=acceptance_receipt,
            ),
            live_chain_observation=live,
            runtime=ClosingRuntimePinEvidence(
                metadata_sha256=runtime.pin.metadata_sha256,
                spec_version=runtime.pin.spec_version,
                transaction_version=runtime.pin.transaction_version,
                state_version=runtime.pin.state_version,
                ss58_prefix=runtime.pin.ss58_prefix,
                metadata=_hex(runtime.metadata_bytes),
                runtime_version=_hex(runtime.runtime_version_bytes),
            ),
            proof_batches=proof_batches,
            total_unique_storage_keys=len(storage_keys),
        )
        proof_bytes = canonical_json_bytes(proof)
        if len(proof_bytes) > MAX_CLOSING_PROOF_BYTES:
            raise ClosingSnapshotCollectorError("announcement_proof_evidence_limit")
        snapshot = AnnouncementValidatorSnapshot(
            schema=ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            proof_profile=ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE,
            collector_revision=ANNOUNCEMENT_VALIDATOR_COLLECTOR_REVISION,
            proof_evidence_sha256=hashlib.sha256(proof_bytes).hexdigest(),
            netuid=78,
            window_id=window.window_id,
            window_index=window.window_index,
            scoring_policy_hash=self.policy_hash,
            announcement_block=height,
            announcement_block_hash=identity.snapshot.block_hash,
            announcement_block_timestamp_ms=block.timestamp_ms,
            complete_validator_registry=True,
            validators=validators,
        )
        return snapshot, canonical_json_bytes(snapshot), proof_bytes

    async def _read_chunks(
        self,
        runtime: PinnedRuntimeContext,
        specs: Sequence[StorageReadSpec],
    ) -> tuple[VerifiedStorageBatch, ...]:
        unique: dict[bytes, StorageReadSpec] = {}
        for spec in specs:
            key = runtime.storage_key(spec.pallet, spec.item, spec.params)
            prior = unique.get(key)
            if prior is not None and prior != spec:
                raise ClosingSnapshotCollectorError("storage_key_alias")
            unique[key] = spec
        ordered = tuple(spec for _key, spec in sorted(unique.items()))
        batches: list[VerifiedStorageBatch] = []
        for offset in range(0, len(ordered), self.maximum_storage_keys_per_proof):
            batch = await self.proofs.storage_reads(
                runtime,
                ordered[offset : offset + self.maximum_storage_keys_per_proof],
            )
            if not isinstance(batch, VerifiedStorageBatch):
                raise ClosingSnapshotCollectorError("storage_proof_batch_invalid")
            batches.append(batch)
        if not batches:
            raise ClosingSnapshotCollectorError("storage_proof_batch_empty")
        if len(batches) > MAX_PROOF_BATCHES:
            raise ClosingSnapshotCollectorError("storage_proof_batch_limit")
        return tuple(batches)

    def _validate_finality(
        self,
        block: VerifiedFinalizedBlock,
        identity: Any,
        attestation: bytes,
        expected_height: int,
        *,
        reason_prefix: str,
    ) -> None:
        if not isinstance(block, VerifiedFinalizedBlock):
            raise ClosingSnapshotCollectorError(f"{reason_prefix}_finality_block_invalid")
        if block.height != expected_height or identity.snapshot.block_number != expected_height:
            raise ClosingSnapshotCollectorError(f"{reason_prefix}_finality_height_mismatch")
        if (
            block.block_hash != identity.snapshot.block_hash
            or block.state_root != identity.snapshot.state_root
            or block.finality_verifier_sha256 != identity.finality_verifier_sha256
            or block.finality_evidence_sha256 != identity.finality_evidence_sha256
            or block.finality_evidence != attestation
            or hashlib.sha256(attestation).hexdigest() != identity.finality_evidence_sha256
            or block.scoring_policy_hash != self.policy_hash
        ):
            raise ClosingSnapshotCollectorError(f"{reason_prefix}_finality_binding_mismatch")


def replay_closing_snapshot_storage(
    proof_evidence_bytes: bytes,
    *,
    verifier: MultiStorageProofVerifier,
) -> ReplayedClosingStorage:
    """Rebuild the runtime and authenticate every retained closing storage claim.

    GRANDPA attestation verification remains the responsibility of the pinned
    finality verifier.  The exact attestation and its full replay binding are in
    this object; this function independently covers runtime pinning, storage-key
    derivation, trie membership/absence and strict value decoding.
    """

    if not isinstance(proof_evidence_bytes, bytes) or not proof_evidence_bytes:
        raise TypeError("closing proof evidence must be nonempty exact bytes")
    if len(proof_evidence_bytes) > MAX_CLOSING_PROOF_BYTES:
        raise ClosingSnapshotCollectorError("closing_proof_evidence_limit")
    try:
        evidence = ClosingSnapshotProofEvidence.model_validate_json(proof_evidence_bytes)
    except Exception as error:
        raise ClosingSnapshotCollectorError("closing_proof_evidence_invalid") from error
    if canonical_json_bytes(evidence) != proof_evidence_bytes:
        raise ClosingSnapshotCollectorError("closing_proof_evidence_noncanonical")
    metadata = _unhex(evidence.runtime.metadata, "runtime_metadata_invalid")
    runtime_version = _unhex(evidence.runtime.runtime_version, "runtime_version_invalid")
    try:
        codec = bittensor_core.Runtime(
            metadata,
            evidence.runtime.spec_version,
            evidence.runtime.transaction_version,
            ss58_format=evidence.runtime.ss58_prefix,
        )
    except Exception as error:
        raise ClosingSnapshotCollectorError("runtime_codec_initialization_failed") from error
    if codec.constant("System", "SS58Prefix") != 42:
        raise ClosingSnapshotCollectorError("runtime_ss58_prefix_mismatch")
    snapshot = FinalizedSnapshotRef(
        block_number=evidence.finality.block_number,
        block_hash=evidence.finality.block_hash,
        parent_hash=evidence.finality.parent_block_hash,
        state_root=evidence.finality.state_root,
    )
    pin = FinalizedRuntimePin(
        metadata_sha256=evidence.runtime.metadata_sha256,
        spec_version=evidence.runtime.spec_version,
        transaction_version=evidence.runtime.transaction_version,
        state_version=evidence.runtime.state_version,
        ss58_prefix=evidence.runtime.ss58_prefix,
    )
    runtime = PinnedRuntimeContext(
        snapshot=snapshot,
        pin=pin,
        metadata_bytes=metadata,
        runtime_version_bytes=runtime_version,
        _runtime=codec,
    )
    reads: list[DecodedStorageClaim] = []
    seen: set[bytes] = set()
    for batch_model in evidence.proof_batches:
        claims = tuple(
            StorageClaim(
                storage_key=_unhex(item.storage_key, "storage_key_invalid"),
                value=(
                    None
                    if item.raw_value is None
                    else _unhex(item.raw_value, "storage_value_invalid")
                ),
            )
            for item in batch_model.claims
        )
        try:
            authenticated = MultiStorageEvidence(
                snapshot=snapshot,
                claims=claims,
                proof=tuple(_unhex(node, "proof_node_invalid") for node in batch_model.proof_nodes),
                verifier=verifier,
            )
        except (TypeError, ValueError) as error:
            raise ClosingSnapshotCollectorError("storage_proof_verification_failed") from error
        claim_by_key = {item.storage_key: item for item in authenticated.claims}
        for item in batch_model.claims:
            spec = StorageReadSpec(item.pallet, item.item, tuple(item.params))
            expected_key = runtime.storage_key(spec.pallet, spec.item, spec.params)
            raw = claim_by_key[_unhex(item.storage_key, "storage_key_invalid")].value
            if expected_key != _unhex(item.storage_key, "storage_key_invalid"):
                raise ClosingSnapshotCollectorError("storage_key_derivation_mismatch")
            if expected_key in seen:
                raise ClosingSnapshotCollectorError("duplicate_proven_storage_key")
            seen.add(expected_key)
            reads.append(
                DecodedStorageClaim(
                    spec=spec,
                    storage_key=expected_key,
                    raw_value=raw,
                    decoded_value=runtime.decode_storage(spec.pallet, spec.item, raw),
                )
            )
    if len(reads) != evidence.total_unique_storage_keys:
        raise ClosingSnapshotCollectorError("closing_storage_key_count_mismatch")
    reads.sort(key=lambda item: item.storage_key)
    return ReplayedClosingStorage(evidence=evidence, runtime=runtime, reads=tuple(reads))


def replay_announcement_validator_storage(
    proof_evidence_bytes: bytes,
    *,
    verifier: MultiStorageProofVerifier,
) -> ReplayedAnnouncementValidatorStorage:
    """Authenticate every retained announcement-block validator storage claim."""

    if not isinstance(proof_evidence_bytes, bytes) or not proof_evidence_bytes:
        raise TypeError("announcement proof evidence must be nonempty exact bytes")
    if len(proof_evidence_bytes) > MAX_CLOSING_PROOF_BYTES:
        raise ClosingSnapshotCollectorError("announcement_proof_evidence_limit")
    try:
        evidence = AnnouncementValidatorProofEvidence.model_validate_json(proof_evidence_bytes)
    except Exception as error:
        raise ClosingSnapshotCollectorError("announcement_proof_evidence_invalid") from error
    if canonical_json_bytes(evidence) != proof_evidence_bytes:
        raise ClosingSnapshotCollectorError("announcement_proof_evidence_noncanonical")
    metadata = _unhex(evidence.runtime.metadata, "announcement_runtime_metadata_invalid")
    runtime_version = _unhex(
        evidence.runtime.runtime_version,
        "announcement_runtime_version_invalid",
    )
    try:
        codec = bittensor_core.Runtime(
            metadata,
            evidence.runtime.spec_version,
            evidence.runtime.transaction_version,
            ss58_format=evidence.runtime.ss58_prefix,
        )
    except Exception as error:
        raise ClosingSnapshotCollectorError(
            "announcement_runtime_codec_initialization_failed"
        ) from error
    if codec.constant("System", "SS58Prefix") != 42:
        raise ClosingSnapshotCollectorError("announcement_runtime_ss58_prefix_mismatch")
    snapshot = FinalizedSnapshotRef(
        block_number=evidence.finality.block_number,
        block_hash=evidence.finality.block_hash,
        parent_hash=evidence.finality.parent_block_hash,
        state_root=evidence.finality.state_root,
    )
    pin = FinalizedRuntimePin(
        metadata_sha256=evidence.runtime.metadata_sha256,
        spec_version=evidence.runtime.spec_version,
        transaction_version=evidence.runtime.transaction_version,
        state_version=evidence.runtime.state_version,
        ss58_prefix=evidence.runtime.ss58_prefix,
    )
    runtime = PinnedRuntimeContext(
        snapshot=snapshot,
        pin=pin,
        metadata_bytes=metadata,
        runtime_version_bytes=runtime_version,
        _runtime=codec,
    )
    reads: list[DecodedStorageClaim] = []
    seen: set[bytes] = set()
    for batch_model in evidence.proof_batches:
        claims = tuple(
            StorageClaim(
                storage_key=_unhex(item.storage_key, "announcement_storage_key_invalid"),
                value=(
                    None
                    if item.raw_value is None
                    else _unhex(item.raw_value, "announcement_storage_value_invalid")
                ),
            )
            for item in batch_model.claims
        )
        try:
            authenticated = MultiStorageEvidence(
                snapshot=snapshot,
                claims=claims,
                proof=tuple(
                    _unhex(node, "announcement_proof_node_invalid")
                    for node in batch_model.proof_nodes
                ),
                verifier=verifier,
            )
        except (TypeError, ValueError) as error:
            raise ClosingSnapshotCollectorError(
                "announcement_storage_proof_verification_failed"
            ) from error
        claim_by_key = {item.storage_key: item for item in authenticated.claims}
        for item in batch_model.claims:
            spec = StorageReadSpec(item.pallet, item.item, tuple(item.params))
            expected_key = runtime.storage_key(spec.pallet, spec.item, spec.params)
            encoded_key = _unhex(item.storage_key, "announcement_storage_key_invalid")
            if expected_key != encoded_key:
                raise ClosingSnapshotCollectorError("announcement_storage_key_derivation_mismatch")
            if expected_key in seen:
                raise ClosingSnapshotCollectorError("announcement_duplicate_proven_storage_key")
            seen.add(expected_key)
            raw = claim_by_key[encoded_key].value
            reads.append(
                DecodedStorageClaim(
                    spec=spec,
                    storage_key=expected_key,
                    raw_value=raw,
                    decoded_value=runtime.decode_storage(spec.pallet, spec.item, raw),
                )
            )
    if len(reads) != evidence.total_unique_storage_keys:
        raise ClosingSnapshotCollectorError("announcement_storage_key_count_mismatch")
    reads.sort(key=lambda item: item.storage_key)
    return ReplayedAnnouncementValidatorStorage(
        evidence=evidence,
        runtime=runtime,
        reads=tuple(reads),
    )


def validate_replayed_announcement_validator_snapshot(
    snapshot_bytes: bytes,
    replayed: ReplayedAnnouncementValidatorStorage,
    *,
    policy: ScoringPolicy,
) -> AnnouncementValidatorSnapshot:
    """Rebuild the announcement validator set from authenticated storage reads."""

    if not isinstance(snapshot_bytes, bytes) or not snapshot_bytes:
        raise TypeError("announcement snapshot must be nonempty exact bytes")
    if not isinstance(replayed, ReplayedAnnouncementValidatorStorage):
        raise TypeError("announcement replay storage has another type")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("announcement replay policy must be ScoringPolicy")
    try:
        snapshot = AnnouncementValidatorSnapshot.model_validate_json(snapshot_bytes)
    except ValueError as error:
        raise ClosingSnapshotCollectorError("announcement_snapshot_invalid") from error
    if canonical_json_bytes(snapshot) != snapshot_bytes:
        raise ClosingSnapshotCollectorError("announcement_snapshot_noncanonical")
    evidence = replayed.evidence
    policy_hash = scoring_policy_hash(policy)
    live = policy.implementation_pins.live_chain
    if (
        live is None
        or evidence.scoring_policy_hash != policy_hash
        or evidence.live_chain_observation != live
        or evidence.runtime.metadata_sha256 != live.metadata_sha256
        or evidence.runtime.spec_version != live.runtime_spec_version
        or evidence.runtime.transaction_version != live.transaction_version
        or evidence.runtime.state_version != live.state_version
        or snapshot.window_id != evidence.window_id
        or snapshot.window_index != evidence.window_index
        or snapshot.scoring_policy_hash != policy_hash
        or snapshot.announcement_block != evidence.announcement_block
        or snapshot.announcement_block_hash != evidence.finality.block_hash
        or snapshot.proof_evidence_sha256
        != hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    ):
        raise ClosingSnapshotCollectorError("announcement_snapshot_policy_binding_mismatch")

    values = {
        (read.spec.pallet, read.spec.item, read.spec.params): read.decoded_value
        for read in replayed.reads
    }
    if len(values) != len(replayed.reads):
        raise ClosingSnapshotCollectorError("announcement_duplicate_storage_read")
    if _bool(_get(values, "SubtensorModule", "NetworksAdded", (78,))) is not True:
        raise ClosingSnapshotCollectorError("announcement_subnet_not_added")
    uid_count = _uint(
        _get(values, "SubtensorModule", "SubnetworkN", (78,)),
        "announcement_subnetwork_n_invalid",
        maximum=MAX_UIDS,
    )
    permits_value = _get(values, "SubtensorModule", "ValidatorPermit", (78,))
    if (
        uid_count == 0
        or isinstance(permits_value, (str, bytes, bytearray))
        or not isinstance(permits_value, Sequence)
        or len(permits_value) != uid_count
        or any(not isinstance(value, bool) for value in permits_value)
    ):
        raise ClosingSnapshotCollectorError("announcement_validator_permit_vector_invalid")
    permits = tuple(permits_value)

    validators: list[ClosingValidatorState] = []
    required_specs = {
        ("SubtensorModule", "NetworksAdded", (78,)),
        ("SubtensorModule", "SubnetworkN", (78,)),
        ("SubtensorModule", "ValidatorPermit", (78,)),
    }
    for entry in policy.validator_registry:
        uid_spec = ("SubtensorModule", "Uids", (78, entry.validator_hotkey))
        required_specs.add(uid_spec)
        uid = _optional_uint(
            _get(values, *uid_spec),
            "announcement_validator_uid_invalid",
            maximum=MAX_UIDS - 1,
        )
        registered = False
        if uid is not None and uid < uid_count:
            key_spec = ("SubtensorModule", "Keys", (78, uid))
            required_specs.add(key_spec)
            registered = account_id32(
                _account(
                    _get(values, *key_spec),
                    "announcement_uid_hotkey_invalid",
                )
            ) == account_id32(entry.validator_hotkey)
        validators.append(
            ClosingValidatorState(
                validator_hotkey=entry.validator_hotkey,
                validator_permit=bool(registered and uid is not None and permits[uid]),
            )
        )
    validators.sort(key=lambda item: account_id32(item.validator_hotkey))
    if set(values) != required_specs:
        raise ClosingSnapshotCollectorError("announcement_storage_read_set_mismatch")
    expected = AnnouncementValidatorSnapshot(
        schema=ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        proof_profile=ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE,
        collector_revision=ANNOUNCEMENT_VALIDATOR_COLLECTOR_REVISION,
        proof_evidence_sha256=hashlib.sha256(canonical_json_bytes(evidence)).hexdigest(),
        netuid=78,
        window_id=evidence.window_id,
        window_index=evidence.window_index,
        scoring_policy_hash=policy_hash,
        announcement_block=evidence.announcement_block,
        announcement_block_hash=evidence.finality.block_hash,
        announcement_block_timestamp_ms=evidence.finality.timestamp_ms,
        complete_validator_registry=True,
        validators=validators,
    )
    if snapshot != expected:
        raise ClosingSnapshotCollectorError("announcement_snapshot_storage_mismatch")
    return snapshot


def validate_replayed_closing_snapshot(
    snapshot_bytes: bytes,
    replayed: ReplayedClosingStorage,
    *,
    policy: ScoringPolicy,
) -> ClosingSnapshot:
    """Rebuild every published closing row from authenticated storage reads."""

    if not isinstance(snapshot_bytes, bytes) or not snapshot_bytes:
        raise TypeError("closing snapshot must be nonempty exact bytes")
    if not isinstance(replayed, ReplayedClosingStorage):
        raise TypeError("replayed storage must be ReplayedClosingStorage")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("closing replay policy must be ScoringPolicy")
    try:
        snapshot = ClosingSnapshot.model_validate_json(snapshot_bytes)
    except ValueError as error:
        raise ClosingSnapshotCollectorError("closing_snapshot_invalid") from error
    if canonical_json_bytes(snapshot) != snapshot_bytes:
        raise ClosingSnapshotCollectorError("closing_snapshot_noncanonical")
    evidence = replayed.evidence
    policy_hash = scoring_policy_hash(policy)
    live = policy.implementation_pins.live_chain
    if (
        live is None
        or evidence.scoring_policy_hash != policy_hash
        or evidence.live_chain_observation != live
        or evidence.runtime.metadata_sha256 != live.metadata_sha256
        or evidence.runtime.spec_version != live.runtime_spec_version
        or evidence.runtime.transaction_version != live.transaction_version
        or evidence.runtime.state_version != live.state_version
        or snapshot.window_id != evidence.window_id
        or snapshot.window_index != evidence.window_index
        or snapshot.scoring_policy_hash != policy_hash
        or snapshot.closing_block != evidence.closing_block
        or snapshot.closing_block_hash != evidence.finality.block_hash
        or snapshot.proof_evidence_sha256
        != hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    ):
        raise ClosingSnapshotCollectorError("closing_snapshot_policy_binding_mismatch")

    values = {
        (read.spec.pallet, read.spec.item, read.spec.params): read.decoded_value
        for read in replayed.reads
    }
    if len(values) != len(replayed.reads):
        raise ClosingSnapshotCollectorError("duplicate_storage_read")
    if _bool(_get(values, "SubtensorModule", "NetworksAdded", (78,))) is not True:
        raise ClosingSnapshotCollectorError("subnet_not_added")
    uid_count = _uint(
        _get(values, "SubtensorModule", "SubnetworkN", (78,)),
        "subnetwork_n_invalid",
        maximum=MAX_UIDS,
    )
    permits_value = _get(values, "SubtensorModule", "ValidatorPermit", (78,))
    if (
        uid_count == 0
        or isinstance(permits_value, (str, bytes, bytearray))
        or not isinstance(permits_value, Sequence)
        or len(permits_value) != uid_count
        or any(not isinstance(item, bool) for item in permits_value)
    ):
        raise ClosingSnapshotCollectorError("validator_permit_vector_invalid")
    permits = tuple(permits_value)
    hotkeys = tuple(
        _account(
            _get(values, "SubtensorModule", "Keys", (78, uid)),
            "uid_hotkey_invalid",
        )
        for uid in range(uid_count)
    )
    if len({account_id32(item) for item in hotkeys}) != uid_count:
        raise ClosingSnapshotCollectorError("uid_hotkey_duplicate")

    neurons: list[ClosingNeuron] = []
    for uid, hotkey in enumerate(hotkeys):
        inverse = _optional_uint(
            _get(values, "SubtensorModule", "Uids", (78, hotkey)),
            "uid_inverse_invalid",
            maximum=MAX_UIDS - 1,
        )
        if inverse != uid:
            raise ClosingSnapshotCollectorError("uid_inverse_mismatch")
        root_value = _get(values, "SubtensorModule", "HotkeyRoot", (78, hotkey))
        root = hotkey if root_value is None else _account(root_value, "hotkey_root_invalid")
        successor = _get(values, "SubtensorModule", "HotkeySuccessor", (78, hotkey))
        if successor is not None:
            _account(successor, "hotkey_successor_invalid")
        neurons.append(
            ClosingNeuron(
                uid=uid,
                hotkey=hotkey,
                root=root,
                registered=True,
                validator_permit=permits[uid],
                serving_url=_serving_url(_get(values, "SubtensorModule", "Axons", (78, hotkey))),
            )
        )

    publishers: list[ClosingPublisherState] = []
    for entry in policy.publisher_registry:
        inverse = _optional_uint(
            _get(values, "SubtensorModule", "Uids", (78, entry.publisher_hotkey)),
            "publisher_uid_invalid",
            maximum=MAX_UIDS - 1,
        )
        registered = (
            inverse is not None
            and inverse < uid_count
            and account_id32(hotkeys[inverse]) == account_id32(entry.publisher_hotkey)
        )
        collateral = _collateral(
            _get(
                values,
                "SubtensorModule",
                "MinerCollateral",
                (78, entry.publisher_hotkey, entry.owner_coldkey),
            )
        )
        anchor, anchor_block = _commitment_anchor(
            _get(values, "Commitments", "CommitmentOf", (78, entry.publisher_hotkey))
        )
        publishers.append(
            ClosingPublisherState(
                publisher_hotkey=entry.publisher_hotkey,
                owner_coldkey=_account(
                    _get(values, "SubtensorModule", "Owner", (entry.publisher_hotkey,)),
                    "publisher_owner_invalid",
                ),
                control_group_id=entry.control_group_id,
                registered=registered,
                locked_collateral_alpha_rao=collateral[0],
                minimum_locked_collateral_alpha_rao=collateral[1],
                pool_manifest_sha256=anchor,
                anchor_inclusion_block=anchor_block,
            )
        )
    publishers.sort(key=lambda item: account_id32(item.publisher_hotkey))

    validators: list[ClosingValidatorState] = []
    for entry in policy.validator_registry:
        uid = _optional_uint(
            _get(values, "SubtensorModule", "Uids", (78, entry.validator_hotkey)),
            "validator_uid_invalid",
            maximum=MAX_UIDS - 1,
        )
        registered = (
            uid is not None
            and uid < uid_count
            and account_id32(hotkeys[uid]) == account_id32(entry.validator_hotkey)
        )
        validators.append(
            ClosingValidatorState(
                validator_hotkey=entry.validator_hotkey,
                validator_permit=bool(registered and permits[uid]),
            )
        )
    validators.sort(key=lambda item: account_id32(item.validator_hotkey))
    expected = ClosingSnapshot(
        schema=CLOSING_SNAPSHOT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        proof_profile=CLOSING_SNAPSHOT_PROOF_PROFILE,
        collector_revision=CLOSING_SNAPSHOT_COLLECTOR_REVISION,
        proof_evidence_sha256=hashlib.sha256(canonical_json_bytes(evidence)).hexdigest(),
        netuid=78,
        window_id=evidence.window_id,
        window_index=evidence.window_index,
        scoring_policy_hash=policy_hash,
        closing_block=evidence.closing_block,
        closing_block_hash=evidence.finality.block_hash,
        closing_block_timestamp_ms=evidence.finality.timestamp_ms,
        accepted_at_unix_ms=evidence.finality.accepted_at_unix_ms,
        complete_publisher_registry=True,
        complete_validator_registry=True,
        complete_uid_snapshot=True,
        publishers=publishers,
        validators=validators,
        neurons=neurons,
    )
    if snapshot != expected:
        raise ClosingSnapshotCollectorError("closing_snapshot_storage_mismatch")
    return snapshot


def _one_finality_record(
    interval: Any,
    *,
    reason_prefix: str,
) -> tuple[Any, bytes, FinalityAttestationReplayBinding, bytes]:
    identities = getattr(interval, "identities", None)
    attestations = getattr(interval, "attestations", None)
    bindings = getattr(interval, "replay_bindings", None)
    acceptance_receipts = getattr(interval, "acceptance_receipts", None)
    if (
        not isinstance(identities, tuple)
        or not isinstance(attestations, tuple)
        or not isinstance(bindings, tuple)
        or not isinstance(acceptance_receipts, tuple)
        or len(identities) != 1
        or len(attestations) != 1
        or len(bindings) != 1
        or len(acceptance_receipts) != 1
        or not isinstance(attestations[0], bytes)
        or not isinstance(bindings[0], FinalityAttestationReplayBinding)
        or not isinstance(acceptance_receipts[0], bytes)
    ):
        raise ClosingSnapshotCollectorError(f"{reason_prefix}_finality_interval_invalid")
    return identities[0], attestations[0], bindings[0], acceptance_receipts[0]


def _acceptance(
    payload: bytes,
    *,
    identity: Any,
    attestation: bytes,
    reason_prefix: str,
) -> Any:
    try:
        receipt = parse_finality_acceptance_receipt(payload)
    except ValueError as error:
        raise ClosingSnapshotCollectorError(
            f"{reason_prefix}_acceptance_receipt_invalid"
        ) from error
    if (
        receipt.height != identity.snapshot.block_number
        or receipt.block_hash != identity.snapshot.block_hash
        or receipt.evidence_sha256 != hashlib.sha256(attestation).hexdigest()
    ):
        raise ClosingSnapshotCollectorError(f"{reason_prefix}_acceptance_receipt_binding_mismatch")
    return receipt


def _finality_evidence(
    *,
    block: VerifiedFinalizedBlock,
    identity: Any,
    attestation: bytes,
    replay_binding: FinalityAttestationReplayBinding,
    acceptance_receipt: bytes,
) -> ClosingFinalityEvidence:
    receipt = _acceptance(
        acceptance_receipt,
        identity=identity,
        attestation=attestation,
        reason_prefix="finality",
    )
    return ClosingFinalityEvidence(
        block_number=identity.snapshot.block_number,
        block_hash=identity.snapshot.block_hash,
        parent_block_number=identity.parent_snapshot.block_number,
        parent_block_hash=identity.parent_snapshot.block_hash,
        parent_parent_hash=identity.parent_snapshot.parent_hash,
        parent_state_root=identity.parent_snapshot.state_root,
        state_root=identity.snapshot.state_root,
        extrinsics_root=identity.extrinsics_root,
        timestamp_ms=block.timestamp_ms,
        finality_verifier_sha256=identity.finality_verifier_sha256,
        finality_attestation_sha256=identity.finality_evidence_sha256,
        finality_attestation=_hex(attestation),
        accepted_at_unix_ms=receipt.accepted_at_unix_ms,
        acceptance_receipt_sha256=hashlib.sha256(acceptance_receipt).hexdigest(),
        acceptance_receipt=_hex(acceptance_receipt),
        replay_binding=asdict(replay_binding),
    )


def _proof_batch(batch: VerifiedStorageBatch) -> ClosingStorageProofBatchEvidence:
    if not isinstance(batch, VerifiedStorageBatch):
        raise ClosingSnapshotCollectorError("storage_proof_batch_invalid")
    reads = sorted(batch.reads, key=lambda item: item.storage_key)
    return ClosingStorageProofBatchEvidence(
        claims=[
            ClosingStorageClaimEvidence(
                pallet=read.spec.pallet,
                item=read.spec.item,
                params=list(read.spec.params),
                storage_key=_hex(read.storage_key),
                raw_value=None if read.raw_value is None else _hex(read.raw_value),
            )
            for read in reads
        ],
        proof_nodes=[_hex(node) for node in batch.evidence.proof],
    )


def _lookup(
    batches: Sequence[VerifiedStorageBatch],
) -> dict[tuple[str, str, tuple[Any, ...]], Any]:
    values: dict[tuple[str, str, tuple[Any, ...]], Any] = {}
    for batch in batches:
        for read in batch.reads:
            key = (read.spec.pallet, read.spec.item, read.spec.params)
            if key in values:
                raise ClosingSnapshotCollectorError("duplicate_storage_read")
            values[key] = read.decoded_value
    return values


def _get(
    values: Mapping[tuple[str, str, tuple[Any, ...]], Any],
    pallet: str,
    item: str,
    params: tuple[Any, ...],
) -> Any:
    key = (pallet, item, params)
    if key not in values:
        raise ClosingSnapshotCollectorError("required_storage_read_missing")
    return values[key]


def _account(value: Any, reason: str) -> str:
    try:
        raw = account_id32(value)
        return bt.sp_core.ss58_encode(raw)
    except Exception as error:
        raise ClosingSnapshotCollectorError(reason) from error


def _uint(value: Any, reason: str, *, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ClosingSnapshotCollectorError(reason)
    return value


def _optional_uint(value: Any, reason: str, *, maximum: int) -> int | None:
    return None if value is None else _uint(value, reason, maximum=maximum)


def _bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ClosingSnapshotCollectorError("boolean_storage_value_invalid")
    return value


def _collateral(value: Any) -> tuple[int, int]:
    if value is None:
        return 0, 0
    if not isinstance(value, Mapping) or set(value) != {
        "locked",
        "drain_ratio",
        "min_locked",
        "earned",
    }:
        raise ClosingSnapshotCollectorError("publisher_collateral_invalid")
    locked = _uint(value["locked"], "publisher_collateral_locked_invalid")
    minimum = _uint(value["min_locked"], "publisher_collateral_floor_invalid")
    return locked, minimum


def _commitment_anchor(value: Any) -> tuple[str | None, int | None]:
    """Return only a canonical one-Sha256 commitment; malformed anchors are absent."""

    if not isinstance(value, Mapping) or set(value) != {"deposit", "block", "info"}:
        return None, None
    block = value.get("block")
    info = value.get("info")
    if (
        isinstance(block, bool)
        or not isinstance(block, int)
        or block < 0
        or not isinstance(info, Mapping)
        or set(info) != {"fields"}
    ):
        return None, None
    fields = info.get("fields")
    if (
        isinstance(fields, (str, bytes, bytearray))
        or not isinstance(fields, Sequence)
        or len(fields) != 1
        or not isinstance(fields[0], Mapping)
        or set(fields[0]) != {"Sha256"}
    ):
        return None, None
    try:
        digest = _digest(fields[0]["Sha256"])
    except ClosingSnapshotCollectorError:
        return None, None
    return digest, block


def _digest(value: Any) -> str:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str) and value.startswith("0x"):
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError as error:
            raise ClosingSnapshotCollectorError("commitment_digest_invalid") from error
    else:
        raise ClosingSnapshotCollectorError("commitment_digest_invalid")
    if len(raw) != 32:
        raise ClosingSnapshotCollectorError("commitment_digest_invalid")
    return raw.hex()


def _serving_url(value: Any) -> str | None:
    if value is None:
        return None
    required = {
        "block",
        "version",
        "ip",
        "port",
        "ip_type",
        "protocol",
        "placeholder1",
        "placeholder2",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        return None
    ip_value = value.get("ip")
    port = value.get("port")
    ip_type = value.get("ip_type")
    if (
        isinstance(ip_value, bool)
        or not isinstance(ip_value, int)
        or ip_value <= 0
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65_535
        or ip_type not in (4, 6)
    ):
        return None
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return None
    if address.version != ip_type or address.is_unspecified:
        return None
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    # AxonInfo carries only an IP address and port. UMI assigns HTTPS semantics
    # to every eligible serving record so bearer-like video delivery URLs never
    # cross the public validator-to-miner hop in cleartext.
    return f"https://{host}:{port}"


def _hex(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("binary evidence value must be bytes")
    return "0x" + value.hex()


def _unhex(value: str, reason: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ClosingSnapshotCollectorError(reason)
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as error:
        raise ClosingSnapshotCollectorError(reason) from error
    if value != "0x" + raw.hex():
        raise ClosingSnapshotCollectorError(reason)
    return raw


__all__ = [
    "ANNOUNCEMENT_VALIDATOR_COLLECTOR_REVISION",
    "ANNOUNCEMENT_VALIDATOR_EVIDENCE_SCHEMA",
    "CLOSING_SNAPSHOT_COLLECTOR_REVISION",
    "CLOSING_SNAPSHOT_EVIDENCE_SCHEMA",
    "AnnouncementValidatorProofEvidence",
    "ClosingFinalityEvidence",
    "ClosingRuntimePinEvidence",
    "ClosingSnapshotCollectorError",
    "ClosingSnapshotProofEvidence",
    "ClosingStorageClaimEvidence",
    "ClosingStorageProofBatchEvidence",
    "ProofBackedClosingSnapshotCollector",
    "ReplayedAnnouncementValidatorStorage",
    "ReplayedClosingStorage",
    "replay_announcement_validator_storage",
    "replay_closing_snapshot_storage",
    "validate_replayed_announcement_validator_snapshot",
    "validate_replayed_closing_snapshot",
]
