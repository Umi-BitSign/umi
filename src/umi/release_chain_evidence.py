"""Proof-backed release-observation state for an inactive UMI live-shadow release.

The release descriptor chooses a candidate policy.  This module checks the
chain facts used by that policy against one storage proof rooted in an
independently finalized Finney header.  It has no wallet, signing, call
composition, or submission surface.

Runtime metadata and the transaction version are content-pinned inputs.  The
Substrate state root does not commit to the result of the runtime metadata and
version RPCs.  The evidence model labels those inputs accordingly.  The runtime
spec version is also checked against ``System.LastRuntimeUpgrade`` and state
version 1 is enforced by the trie verifier.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Protocol

import bittensor_core
from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .chain_evidence import FinalizedSnapshotRef
from .encoding import account_id32
from .policy import PublisherRegistryEntry, ValidatorRegistryEntry
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_chain import (
    FinalizedRuntimePin,
    PinnedRuntimeContext,
    StorageReadSpec,
    VerifiedStorageBatch,
)

RELEASE_OBSERVATION_EVIDENCE_SCHEMA = "umi-live-shadow-release-observation-chain-evidence/1"
RELEASE_OBSERVATION_EVIDENCE_PROFILE = (
    "owned-finality-layout-v1-release-observation-storage-proof/1"
)
RUNTIME_METADATA_AUTHENTICATION = "external-content-pin-decoder-input/1"
RUNTIME_VERSION_AUTHENTICATION = "proof-backed-spec-plus-content-pinned-rpc-version/1"

MAX_RELEASE_CHAIN_EVIDENCE_BYTES = 128 * 1024 * 1024
MAX_RELEASE_STORAGE_BATCHES = 32
MAX_RELEASE_STORAGE_CLAIMS = 4_096
MAX_RELEASE_PROOF_NODES = 4_096
MAX_RELEASE_STORAGE_KEY_BYTES = 512
MAX_RELEASE_STORAGE_VALUE_BYTES = 16 * 1024 * 1024
MAX_RELEASE_PROOF_NODE_BYTES = 2 * 1024 * 1024
MAX_RELEASE_RUNTIME_VERSION_BYTES = 64 * 1024
MAX_RELEASE_UIDS = 65_536

_BLOCK_HASH_PATTERN = r"^0x[0-9a-f]{64}$"
_HEX32_PATTERN = r"^[0-9a-f]{64}$"
_HEX_BYTES_PATTERN = r"^0x(?:[0-9a-f]{2})*$"

BlockHash = Annotated[str, Field(pattern=_BLOCK_HASH_PATTERN)]
Hex32 = Annotated[str, Field(pattern=_HEX32_PATTERN)]
HexBytes = Annotated[str, Field(pattern=_HEX_BYTES_PATTERN)]
StorageParameter = int | str

_BASE_SPECS = (
    StorageReadSpec("System", "LastRuntimeUpgrade", ()),
    StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
    StorageReadSpec("SubtensorModule", "SubtokenEnabled", (78,)),
    StorageReadSpec("SubtensorModule", "FirstEmissionBlockNumber", (78,)),
    StorageReadSpec("SubtensorModule", "MechanismCountCurrent", (78,)),
    StorageReadSpec("SubtensorModule", "CommitRevealWeightsEnabled", (78,)),
    StorageReadSpec("SubtensorModule", "CommitRevealWeightsVersion", ()),
    StorageReadSpec("SubtensorModule", "SubnetworkN", (78,)),
    StorageReadSpec("SubtensorModule", "ValidatorPermit", (78,)),
)


class ReleaseChainEvidenceError(RuntimeError):
    """A stable failure while collecting or replaying release-observation evidence."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ReleaseStorageClaim(StrictProtocolModel):
    pallet: Annotated[str, Field(min_length=1, max_length=128)]
    item: Annotated[str, Field(min_length=1, max_length=128)]
    params: Annotated[list[StorageParameter], Field(max_length=4)]
    storage_key: HexBytes
    raw_value: HexBytes | None

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        key = _unhex(self.storage_key, "release_observation_storage_key_invalid")
        if not key or len(key) > MAX_RELEASE_STORAGE_KEY_BYTES:
            raise ValueError("release-observation storage key exceeds its byte limit")
        if self.raw_value is not None:
            raw = _unhex(self.raw_value, "release_observation_storage_value_invalid")
            if len(raw) > MAX_RELEASE_STORAGE_VALUE_BYTES:
                raise ValueError("release-observation storage value exceeds its byte limit")
        for value in self.params:
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError("release-observation storage parameter has another type")
            if isinstance(value, int) and value < 0:
                raise ValueError("release-observation storage parameter is negative")
            if isinstance(value, str) and len(value.encode()) > 512:
                raise ValueError("release-observation storage parameter exceeds its byte limit")
        return self


class ReleaseStorageProofBatch(StrictProtocolModel):
    claims: Annotated[
        list[ReleaseStorageClaim],
        Field(min_length=1, max_length=MAX_RELEASE_STORAGE_CLAIMS),
    ]
    proof_nodes: Annotated[
        list[HexBytes],
        Field(min_length=1, max_length=MAX_RELEASE_PROOF_NODES),
    ]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        keys = [
            _unhex(item.storage_key, "release_observation_storage_key_invalid")
            for item in self.claims
        ]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("release-observation proof claims must be unique and sorted")
        nodes = [
            _unhex(item, "release_observation_proof_node_invalid") for item in self.proof_nodes
        ]
        if any(not item or len(item) > MAX_RELEASE_PROOF_NODE_BYTES for item in nodes) or len(
            set(nodes)
        ) != len(nodes):
            raise ValueError("release-observation proof nodes are invalid")
        return self


class ReleaseRuntimeEvidence(StrictProtocolModel):
    metadata_sha256: Hex32
    spec_version: Annotated[int, Field(gt=0)]
    transaction_version: Annotated[int, Field(gt=0)]
    state_version: Literal[1]
    ss58_prefix: Literal[42]
    runtime_version: HexBytes
    metadata_authentication: Literal[RUNTIME_METADATA_AUTHENTICATION]
    version_authentication: Literal[RUNTIME_VERSION_AUTHENTICATION]

    @model_validator(mode="after")
    def validate_runtime_version(self) -> Self:
        raw = _unhex(self.runtime_version, "release_observation_runtime_version_invalid")
        if not raw or len(raw) > MAX_RELEASE_RUNTIME_VERSION_BYTES:
            raise ValueError("release-observation runtime version exceeds its byte limit")
        version = _canonical_mapping(raw, "release_observation_runtime_version")
        if (
            _uint(version.get("specVersion"), "release_observation_runtime_spec_version_invalid")
            != self.spec_version
            or _uint(
                version.get("transactionVersion"),
                "release_observation_runtime_transaction_version_invalid",
            )
            != self.transaction_version
            or _uint(
                version.get("stateVersion"),
                "release_observation_runtime_state_version_invalid",
                maximum=255,
            )
            != self.state_version
        ):
            raise ValueError("release-observation runtime version fields disagree")
        return self


class ReleaseObservationChainEvidence(StrictProtocolModel):
    schema_: Literal[RELEASE_OBSERVATION_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    evidence_profile: Literal[RELEASE_OBSERVATION_EVIDENCE_PROFILE]
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    parent_hash: BlockHash
    state_root: BlockHash
    timestamp_ms: Annotated[int, Field(gt=0)]
    finality_attestation_sha256: Hex32
    runtime: ReleaseRuntimeEvidence
    proof_batches: Annotated[
        list[ReleaseStorageProofBatch],
        Field(min_length=1, max_length=MAX_RELEASE_STORAGE_BATCHES),
    ]
    total_unique_storage_keys: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_complete_index(self) -> Self:
        if self.block_hash == self.parent_hash:
            raise ValueError("release-observation block cannot name itself as parent")
        keys = [claim.storage_key for batch in self.proof_batches for claim in batch.claims]
        if len(keys) != self.total_unique_storage_keys or len(set(keys)) != len(keys):
            raise ValueError("release-observation proofs do not form one unique storage-key set")
        return self


@dataclass(frozen=True, slots=True)
class ReplayedReleaseObservationState:
    evidence: ReleaseObservationChainEvidence
    values: Mapping[tuple[str, str, tuple[StorageParameter, ...]], Any]


class ReleaseStorageProofVerifier(Protocol):
    def verify_many(
        self,
        *,
        state_root: bytes,
        items: tuple[tuple[bytes, bytes | None], ...],
        proof: tuple[bytes, ...],
    ) -> bool: ...


class ReleaseProofCollector(Protocol):
    async def pinned_runtime(
        self,
        snapshot: Any,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext: ...

    async def storage_reads(
        self,
        runtime: PinnedRuntimeContext,
        specs: Sequence[StorageReadSpec],
    ) -> VerifiedStorageBatch: ...


async def collect_release_observation_evidence(
    *,
    snapshot: FinalizedSnapshotRef,
    timestamp_ms: int,
    finality_attestation_sha256: str,
    runtime_pin: FinalizedRuntimePin,
    proofs: ReleaseProofCollector,
    validator_registry: Sequence[ValidatorRegistryEntry],
    publisher_registry: Sequence[PublisherRegistryEntry],
) -> bytes:
    """Collect the minimal proof set later consumed by the release builder."""

    if not isinstance(snapshot, FinalizedSnapshotRef):
        raise TypeError("release-observation snapshot must be FinalizedSnapshotRef")
    if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, int) or timestamp_ms <= 0:
        raise ValueError("release-observation timestamp must be a positive integer")
    if not isinstance(finality_attestation_sha256, str) or len(finality_attestation_sha256) != 64:
        raise ValueError("finality attestation digest must be lowercase SHA-256 hexadecimal")
    try:
        attestation_digest = bytes.fromhex(finality_attestation_sha256)
    except ValueError as error:
        raise ValueError(
            "finality attestation digest must be lowercase SHA-256 hexadecimal"
        ) from error
    if finality_attestation_sha256 != attestation_digest.hex():
        raise ValueError("finality attestation digest must be lowercase SHA-256 hexadecimal")
    if not isinstance(runtime_pin, FinalizedRuntimePin):
        raise TypeError("release-observation runtime pin must be FinalizedRuntimePin")
    if not callable(getattr(proofs, "pinned_runtime", None)) or not callable(
        getattr(proofs, "storage_reads", None)
    ):
        raise TypeError("release-observation proof collector has another shape")

    runtime = await proofs.pinned_runtime(snapshot, runtime_pin)
    if runtime.snapshot != snapshot or runtime.pin != runtime_pin:
        raise ReleaseChainEvidenceError("release_observation_collector_runtime_mismatch")
    batches: list[VerifiedStorageBatch] = []
    base = await proofs.storage_reads(runtime, _BASE_SPECS)
    batches.append(_verified_batch(base, runtime))
    base_values = _batch_values((base,))
    uid_count = _uint(
        base_values[("SubtensorModule", "SubnetworkN", (78,))],
        "release_observation_subnetwork_n_invalid",
        maximum=MAX_RELEASE_UIDS,
    )

    registry_hotkeys = tuple(
        sorted(
            {
                *(item.validator_hotkey for item in validator_registry),
                *(item.publisher_hotkey for item in publisher_registry),
            },
            key=account_id32,
        )
    )
    uid_specs = tuple(
        StorageReadSpec("SubtensorModule", "Uids", (78, hotkey)) for hotkey in registry_hotkeys
    )
    uid_batch = await proofs.storage_reads(runtime, uid_specs)
    batches.append(_verified_batch(uid_batch, runtime))
    uid_values = _batch_values((uid_batch,))

    dynamic: list[StorageReadSpec] = []
    for hotkey in registry_hotkeys:
        uid = _uint(
            uid_values[("SubtensorModule", "Uids", (78, hotkey))],
            "release_observation_registry_uid_invalid",
            maximum=MAX_RELEASE_UIDS - 1,
        )
        if uid >= uid_count:
            raise ReleaseChainEvidenceError("release_observation_registry_uid_invalid")
        dynamic.append(StorageReadSpec("SubtensorModule", "Keys", (78, uid)))
    for entry in publisher_registry:
        dynamic.extend(
            (
                StorageReadSpec("SubtensorModule", "Owner", (entry.publisher_hotkey,)),
                StorageReadSpec(
                    "SubtensorModule",
                    "MinerCollateral",
                    (78, entry.publisher_hotkey, entry.owner_coldkey),
                ),
            )
        )
    dynamic_batch = await proofs.storage_reads(runtime, tuple(dynamic))
    batches.append(_verified_batch(dynamic_batch, runtime))

    models = [_proof_batch(batch) for batch in batches]
    storage_keys = [claim.storage_key for batch in models for claim in batch.claims]
    if len(storage_keys) != len(set(storage_keys)):
        raise ReleaseChainEvidenceError("release_observation_collector_storage_key_duplicate")
    evidence = ReleaseObservationChainEvidence(
        schema=RELEASE_OBSERVATION_EVIDENCE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        evidence_profile=RELEASE_OBSERVATION_EVIDENCE_PROFILE,
        network="finney",
        netuid=78,
        mechanism_id=0,
        block_number=snapshot.block_number,
        block_hash=snapshot.block_hash,
        parent_hash=snapshot.parent_hash,
        state_root=snapshot.state_root,
        timestamp_ms=timestamp_ms,
        finality_attestation_sha256=finality_attestation_sha256,
        runtime=ReleaseRuntimeEvidence(
            metadata_sha256=runtime.pin.metadata_sha256,
            spec_version=runtime.pin.spec_version,
            transaction_version=runtime.pin.transaction_version,
            state_version=runtime.pin.state_version,
            ss58_prefix=runtime.pin.ss58_prefix,
            runtime_version="0x" + runtime.runtime_version_bytes.hex(),
            metadata_authentication=RUNTIME_METADATA_AUTHENTICATION,
            version_authentication=RUNTIME_VERSION_AUTHENTICATION,
        ),
        proof_batches=models,
        total_unique_storage_keys=len(storage_keys),
    )
    return canonical_json_bytes(evidence)


def replay_release_observation_evidence(
    evidence_bytes: bytes,
    *,
    metadata_bytes: bytes,
    verifier: ReleaseStorageProofVerifier,
    validator_registry: Sequence[ValidatorRegistryEntry],
    publisher_registry: Sequence[PublisherRegistryEntry],
    minimum_publisher_collateral_alpha_rao: int,
) -> ReplayedReleaseObservationState:
    """Authenticate and decode every chain fact needed by a release policy."""

    if not isinstance(evidence_bytes, bytes) or not evidence_bytes:
        raise TypeError("release-observation chain evidence must be nonempty exact bytes")
    if len(evidence_bytes) > MAX_RELEASE_CHAIN_EVIDENCE_BYTES:
        raise ReleaseChainEvidenceError("release_observation_chain_evidence_limit")
    if not isinstance(metadata_bytes, bytes) or not metadata_bytes:
        raise TypeError("runtime metadata must be nonempty exact bytes")
    if not callable(getattr(verifier, "verify_many", None)):
        raise TypeError("release-observation proof verifier must provide verify_many")
    if isinstance(minimum_publisher_collateral_alpha_rao, bool) or not isinstance(
        minimum_publisher_collateral_alpha_rao, int
    ):
        raise TypeError("publisher collateral floor must be an integer")
    if minimum_publisher_collateral_alpha_rao <= 0:
        raise ValueError("publisher collateral floor must be positive")
    try:
        evidence = ReleaseObservationChainEvidence.model_validate_json(evidence_bytes)
    except (ValidationError, ValueError) as error:
        raise ReleaseChainEvidenceError("release_observation_chain_evidence_invalid") from error
    if canonical_json_bytes(evidence) != evidence_bytes:
        raise ReleaseChainEvidenceError("release_observation_chain_evidence_noncanonical")
    if hashlib.sha256(metadata_bytes).hexdigest() != evidence.runtime.metadata_sha256:
        raise ReleaseChainEvidenceError("release_observation_runtime_metadata_mismatch")

    runtime_version = _unhex(
        evidence.runtime.runtime_version,
        "release_observation_runtime_version_invalid",
    )
    try:
        codec = bittensor_core.Runtime(
            metadata_bytes,
            evidence.runtime.spec_version,
            evidence.runtime.transaction_version,
            ss58_format=evidence.runtime.ss58_prefix,
        )
        if codec.constant("System", "SS58Prefix") != 42:
            raise ReleaseChainEvidenceError("release_observation_runtime_ss58_prefix_mismatch")
    except ReleaseChainEvidenceError:
        raise
    except Exception as error:
        raise ReleaseChainEvidenceError(
            "release_observation_runtime_codec_initialization_failed"
        ) from error

    runtime = PinnedRuntimeContext(
        snapshot=FinalizedSnapshotRef(
            block_number=evidence.block_number,
            block_hash=evidence.block_hash,
            parent_hash=evidence.parent_hash,
            state_root=evidence.state_root,
        ),
        pin=FinalizedRuntimePin(
            metadata_sha256=evidence.runtime.metadata_sha256,
            spec_version=evidence.runtime.spec_version,
            transaction_version=evidence.runtime.transaction_version,
            state_version=evidence.runtime.state_version,
            ss58_prefix=evidence.runtime.ss58_prefix,
        ),
        metadata_bytes=metadata_bytes,
        runtime_version_bytes=runtime_version,
        _runtime=codec,
    )

    decoded: dict[tuple[str, str, tuple[StorageParameter, ...]], Any] = {}
    seen_keys: set[bytes] = set()
    state_root = bytes.fromhex(evidence.state_root[2:])
    for batch in evidence.proof_batches:
        claims: list[tuple[bytes, bytes | None]] = []
        pending_decodes: list[tuple[bytes, StorageReadSpec, bytes | None]] = []
        for claim in batch.claims:
            storage_key = _unhex(claim.storage_key, "release_observation_storage_key_invalid")
            raw_value = (
                None
                if claim.raw_value is None
                else _unhex(claim.raw_value, "release_observation_storage_value_invalid")
            )
            spec = StorageReadSpec(claim.pallet, claim.item, tuple(claim.params))
            if runtime.storage_key(spec.pallet, spec.item, spec.params) != storage_key:
                raise ReleaseChainEvidenceError(
                    "release_observation_storage_key_derivation_mismatch"
                )
            if storage_key in seen_keys:
                raise ReleaseChainEvidenceError("release_observation_storage_key_duplicate")
            seen_keys.add(storage_key)
            key = (spec.pallet, spec.item, spec.params)
            if key in decoded:
                raise ReleaseChainEvidenceError("release_observation_storage_spec_duplicate")
            claims.append((storage_key, raw_value))
            pending_decodes.append((storage_key, spec, raw_value))
        proof = tuple(
            _unhex(item, "release_observation_proof_node_invalid") for item in batch.proof_nodes
        )
        try:
            verified = verifier.verify_many(
                state_root=state_root,
                items=tuple(claims),
                proof=proof,
            )
        except Exception as error:
            raise ReleaseChainEvidenceError("release_observation_storage_proof_failed") from error
        if verified is not True:
            raise ReleaseChainEvidenceError("release_observation_storage_proof_not_verified")
        for _storage_key, spec, raw_value in pending_decodes:
            key = (spec.pallet, spec.item, spec.params)
            try:
                decoded[key] = runtime.decode_storage(spec.pallet, spec.item, raw_value)
            except Exception as error:
                raise ReleaseChainEvidenceError(
                    "release_observation_storage_value_decode_failed"
                ) from error

    _validate_release_state(
        evidence,
        decoded,
        validator_registry=validator_registry,
        publisher_registry=publisher_registry,
        minimum_publisher_collateral_alpha_rao=minimum_publisher_collateral_alpha_rao,
    )
    return ReplayedReleaseObservationState(evidence=evidence, values=decoded)


def _validate_release_state(
    evidence: ReleaseObservationChainEvidence,
    values: Mapping[tuple[str, str, tuple[StorageParameter, ...]], Any],
    *,
    validator_registry: Sequence[ValidatorRegistryEntry],
    publisher_registry: Sequence[PublisherRegistryEntry],
    minimum_publisher_collateral_alpha_rao: int,
) -> None:
    def get(spec: StorageReadSpec) -> Any:
        key = (spec.pallet, spec.item, spec.params)
        if key not in values:
            raise ReleaseChainEvidenceError("release_observation_required_storage_read_missing")
        return values[key]

    upgrade = get(_BASE_SPECS[0])
    if not isinstance(upgrade, Mapping):
        raise ReleaseChainEvidenceError("release_observation_last_runtime_upgrade_invalid")
    spec_version = upgrade.get("spec_version", upgrade.get("specVersion"))
    if _uint(spec_version, "release_observation_last_runtime_spec_invalid") != (
        evidence.runtime.spec_version
    ):
        raise ReleaseChainEvidenceError("release_observation_runtime_spec_proof_mismatch")
    if _strict_bool(get(_BASE_SPECS[1]), "release_observation_networks_added_invalid") is not True:
        raise ReleaseChainEvidenceError("release_observation_subnet_not_registered")
    # Root governance may disable TAO-side pool injection after the owner's
    # one-shot start call. That does not undo participant-side subnet startup.
    # Preserve and type-check the independent flag without treating it as the
    # launch-state signal; FirstEmissionBlockNumber carries that signal.
    _strict_bool(get(_BASE_SPECS[2]), "release_observation_subtoken_enabled_invalid")
    first_emission = _uint(
        get(_BASE_SPECS[3]),
        "release_observation_first_emission_block_invalid",
    )
    if first_emission == 0 or first_emission > evidence.block_number:
        raise ReleaseChainEvidenceError("release_observation_subnet_not_active")
    if _uint(get(_BASE_SPECS[4]), "release_observation_mechanism_count_invalid") != 1:
        raise ReleaseChainEvidenceError("release_observation_mechanism_topology_mismatch")
    if (
        _strict_bool(
            get(_BASE_SPECS[5]),
            "release_observation_commit_reveal_enabled_invalid",
        )
        is not True
    ):
        raise ReleaseChainEvidenceError("release_observation_commit_reveal_disabled")
    if _uint(get(_BASE_SPECS[6]), "release_observation_commit_reveal_version_invalid") != 4:
        raise ReleaseChainEvidenceError("release_observation_commit_reveal_version_mismatch")
    uid_count = _uint(
        get(_BASE_SPECS[7]),
        "release_observation_subnetwork_n_invalid",
        maximum=MAX_RELEASE_UIDS,
    )
    permits = get(_BASE_SPECS[8])
    if (
        uid_count == 0
        or isinstance(permits, (str, bytes, bytearray))
        or not isinstance(permits, Sequence)
        or len(permits) != uid_count
        or any(not isinstance(value, bool) for value in permits)
    ):
        raise ReleaseChainEvidenceError("release_observation_validator_permit_vector_invalid")

    expected = set(_BASE_SPECS)
    registered_uids: dict[bytes, int] = {}
    for entry in validator_registry:
        hotkey = entry.validator_hotkey
        uid_spec = StorageReadSpec("SubtensorModule", "Uids", (78, hotkey))
        uid = _registered_uid(get(uid_spec), hotkey, uid_count, values)
        expected.update(
            {
                uid_spec,
                StorageReadSpec("SubtensorModule", "Keys", (78, uid)),
            }
        )
        account = account_id32(hotkey)
        if account in registered_uids or permits[uid] is not True:
            raise ReleaseChainEvidenceError("release_observation_validator_registry_mismatch")
        registered_uids[account] = uid

    for entry in publisher_registry:
        hotkey = entry.publisher_hotkey
        uid_spec = StorageReadSpec("SubtensorModule", "Uids", (78, hotkey))
        uid = _registered_uid(get(uid_spec), hotkey, uid_count, values)
        owner_spec = StorageReadSpec("SubtensorModule", "Owner", (hotkey,))
        collateral_spec = StorageReadSpec(
            "SubtensorModule",
            "MinerCollateral",
            (78, hotkey, entry.owner_coldkey),
        )
        expected.update(
            {
                uid_spec,
                StorageReadSpec("SubtensorModule", "Keys", (78, uid)),
                owner_spec,
                collateral_spec,
            }
        )
        account = account_id32(hotkey)
        if account in registered_uids or permits[uid] is not False:
            raise ReleaseChainEvidenceError("release_observation_publisher_registry_mismatch")
        registered_uids[account] = uid
        if account_id32(get(owner_spec)) != account_id32(entry.owner_coldkey):
            raise ReleaseChainEvidenceError("release_observation_publisher_owner_mismatch")
        collateral = get(collateral_spec)
        if not isinstance(collateral, Mapping):
            raise ReleaseChainEvidenceError("release_observation_publisher_collateral_invalid")
        locked = _uint(collateral.get("locked"), "release_observation_publisher_collateral_invalid")
        minimum = _uint(
            collateral.get("min_locked"),
            "release_observation_publisher_collateral_invalid",
        )
        if (
            locked < minimum_publisher_collateral_alpha_rao
            or minimum < minimum_publisher_collateral_alpha_rao
        ):
            raise ReleaseChainEvidenceError("release_observation_publisher_collateral_below_floor")

    if set(values) != {(spec.pallet, spec.item, spec.params) for spec in expected}:
        raise ReleaseChainEvidenceError("release_observation_storage_claim_set_mismatch")


def _registered_uid(
    value: Any,
    hotkey: str,
    uid_count: int,
    values: Mapping[tuple[str, str, tuple[StorageParameter, ...]], Any],
) -> int:
    uid = _uint(value, "release_observation_registry_uid_invalid", maximum=MAX_RELEASE_UIDS - 1)
    if uid >= uid_count:
        raise ReleaseChainEvidenceError("release_observation_registry_uid_invalid")
    key = ("SubtensorModule", "Keys", (78, uid))
    if key not in values or account_id32(values[key]) != account_id32(hotkey):
        raise ReleaseChainEvidenceError("release_observation_registry_inverse_mismatch")
    return uid


def _verified_batch(
    batch: VerifiedStorageBatch,
    runtime: PinnedRuntimeContext,
) -> VerifiedStorageBatch:
    if not isinstance(batch, VerifiedStorageBatch) or batch.runtime != runtime:
        raise ReleaseChainEvidenceError("release_observation_collector_proof_batch_invalid")
    return batch


def _batch_values(
    batches: Sequence[VerifiedStorageBatch],
) -> dict[tuple[str, str, tuple[StorageParameter, ...]], Any]:
    values: dict[tuple[str, str, tuple[StorageParameter, ...]], Any] = {}
    for batch in batches:
        for read in batch.reads:
            key = (read.spec.pallet, read.spec.item, read.spec.params)
            if key in values:
                raise ReleaseChainEvidenceError(
                    "release_observation_collector_storage_spec_duplicate"
                )
            values[key] = read.decoded_value
    return values


def _proof_batch(batch: VerifiedStorageBatch) -> ReleaseStorageProofBatch:
    claims = sorted(batch.reads, key=lambda read: read.storage_key)
    return ReleaseStorageProofBatch(
        claims=[
            ReleaseStorageClaim(
                pallet=read.spec.pallet,
                item=read.spec.item,
                params=list(read.spec.params),
                storage_key="0x" + read.storage_key.hex(),
                raw_value=None if read.raw_value is None else "0x" + read.raw_value.hex(),
            )
            for read in claims
        ],
        proof_nodes=["0x" + node.hex() for node in batch.evidence.proof],
    )


def _canonical_mapping(raw: bytes, reason: str) -> Mapping[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if key in output:
                raise ReleaseChainEvidenceError(reason + "_duplicate_key")
            output[key] = value
        return output

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseChainEvidenceError(reason + "_invalid") from error
    if not isinstance(value, Mapping) or canonical_json_bytes(dict(value)) != raw:
        raise ReleaseChainEvidenceError(reason + "_noncanonical")
    return value


def _strict_bool(value: Any, reason: str) -> bool:
    if not isinstance(value, bool):
        raise ReleaseChainEvidenceError(reason)
    return value


def _uint(value: Any, reason: str, *, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ReleaseChainEvidenceError(reason)
    return value


def _unhex(value: str, reason: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ReleaseChainEvidenceError(reason)
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as error:
        raise ReleaseChainEvidenceError(reason) from error
    if value != "0x" + raw.hex():
        raise ReleaseChainEvidenceError(reason)
    return raw


__all__ = [
    "MAX_RELEASE_CHAIN_EVIDENCE_BYTES",
    "RELEASE_OBSERVATION_EVIDENCE_PROFILE",
    "RELEASE_OBSERVATION_EVIDENCE_SCHEMA",
    "RUNTIME_METADATA_AUTHENTICATION",
    "RUNTIME_VERSION_AUTHENTICATION",
    "ReleaseChainEvidenceError",
    "ReleaseObservationChainEvidence",
    "ReleaseRuntimeEvidence",
    "ReleaseStorageClaim",
    "ReleaseStorageProofBatch",
    "ReplayedReleaseObservationState",
    "collect_release_observation_evidence",
    "replay_release_observation_evidence",
]
