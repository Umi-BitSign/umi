"""Proof-bound, read-only derivation of the Section 10.3 weight window.

The input boundary accepts only finalized block identities emitted by the owned
finality verifier and ``SubnetEpochIndex`` reads authenticated by a Substrate
storage proof.  This module has no wallet, call-composition, signing, submission,
or best-head interface.  In particular, it never predicts a tempo boundary.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, fields
from typing import Literal

from .chain_evidence import NETUID
from .validator_chain import FinalizedRuntimePin, PinnedRuntimeContext, VerifiedStorageRead
from .validator_chain_scan import VerifiedFinalizedBlockIdentity

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_U64 = (1 << 64) - 1

SUBNET_EPOCH_PALLET = "SubtensorModule"
SUBNET_EPOCH_STORAGE_ITEM = "SubnetEpochIndex"


class WeightScheduleError(RuntimeError):
    """A stable fail-closed schedule-input or derivation failure."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class WeightScheduleLimits:
    """Hard bounds applied before schedule evidence is traversed."""

    maximum_observations: int = 4_096
    maximum_finality_evidence_bytes: int = 4 * 1024 * 1024
    maximum_storage_proof_nodes: int = 4_096
    maximum_storage_proof_node_bytes: int = 2 * 1024 * 1024
    maximum_storage_proof_bytes: int = 32 * 1024 * 1024
    maximum_total_evidence_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{item.name} must be a positive integer")
        if self.maximum_storage_proof_node_bytes > self.maximum_storage_proof_bytes:
            raise ValueError("one proof node cannot exceed the complete proof-byte limit")
        if self.maximum_finality_evidence_bytes > self.maximum_total_evidence_bytes:
            raise ValueError("one finality object cannot exceed the aggregate evidence limit")
        if self.maximum_storage_proof_bytes > self.maximum_total_evidence_bytes:
            raise ValueError("one storage proof cannot exceed the aggregate evidence limit")


@dataclass(frozen=True, slots=True)
class WeightScheduleIdentity:
    """Policy-pinned chain, finality-verifier, runtime, and subnet identity."""

    chain_genesis_hash: str
    finality_verifier_sha256: str
    runtime_pin: FinalizedRuntimePin
    netuid: int = NETUID

    def __post_init__(self) -> None:
        _hex32(self.chain_genesis_hash, "chain_genesis_hash")
        _hex32(self.finality_verifier_sha256, "finality_verifier_sha256")
        if not isinstance(self.runtime_pin, FinalizedRuntimePin):
            raise TypeError("runtime_pin must be a FinalizedRuntimePin")
        if self.netuid != NETUID:
            raise ValueError("UMI version 0.1 weight schedules are pinned to SN78")


@dataclass(frozen=True, slots=True)
class VerifiedWeightScheduleObservation:
    """One verifier-owned finalized block with a proof-backed epoch index.

    ``identity`` and ``finality_attestation`` are obtained from the durable
    GRANDPA verifier.  ``subnet_epoch_index_read`` is constructed by the
    finalized proof collector under the content-pinned runtime.  The semantic
    decode is repeated here so a hand-built ``VerifiedStorageRead`` cannot alter
    the epoch value after its raw proof was checked.
    """

    identity: VerifiedFinalizedBlockIdentity
    timestamp_ms: int
    chain_genesis_hash: str
    finality_attestation: bytes
    subnet_epoch_index_read: VerifiedStorageRead

    def __post_init__(self) -> None:
        if not isinstance(self.identity, VerifiedFinalizedBlockIdentity):
            raise TypeError("identity must be a VerifiedFinalizedBlockIdentity")
        _uint(self.timestamp_ms, "timestamp_ms")
        _hex32(self.chain_genesis_hash, "chain_genesis_hash")
        if not isinstance(self.finality_attestation, bytes) or not self.finality_attestation:
            raise ValueError("finality_attestation must contain exact verifier-owned bytes")
        if hashlib.sha256(self.finality_attestation).hexdigest() != (
            self.identity.finality_evidence_sha256
        ):
            raise ValueError("finality attestation does not match the finalized identity")
        read = self.subnet_epoch_index_read
        if not isinstance(read, VerifiedStorageRead):
            raise TypeError("subnet_epoch_index_read must be a VerifiedStorageRead")
        if read.runtime.snapshot != self.identity.snapshot:
            raise ValueError("epoch proof and finalized identity use different snapshots")
        if read.pallet != SUBNET_EPOCH_PALLET or read.item != SUBNET_EPOCH_STORAGE_ITEM:
            raise ValueError("epoch proof names the wrong runtime storage item")
        if read.params != (NETUID,):
            raise ValueError("epoch proof is not bound to SN78")
        try:
            decoded = read.runtime.decode_storage(read.pallet, read.item, read.evidence.value)
        except Exception as error:
            raise ValueError("epoch proof cannot be decoded under its pinned runtime") from error
        if decoded != read.decoded_value:
            raise ValueError("epoch semantic decode disagrees with the proof-backed raw value")
        _uint(decoded, "subnet_epoch_index")

    @property
    def snapshot(self):
        """The exact finalized snapshot used by this observation."""

        return self.identity.snapshot

    @property
    def runtime(self) -> PinnedRuntimeContext:
        return self.subnet_epoch_index_read.runtime

    @property
    def subnet_epoch_index(self) -> int:
        value = self.subnet_epoch_index_read.decoded_value
        if isinstance(value, bool) or not isinstance(value, int):  # constructor already checks
            raise AssertionError("validated epoch value changed type")
        return value

    @property
    def storage_proof_sha256(self) -> str:
        evidence = self.subnet_epoch_index_read.evidence
        digest = hashlib.sha256()
        digest.update(len(evidence.proof).to_bytes(4, "big"))
        for node in evidence.proof:
            digest.update(len(node).to_bytes(8, "big"))
            digest.update(node)
        return digest.hexdigest()


PendingReason = Literal[
    "reveal_observation_pending",
    "base_epoch_observation_pending",
    "epoch_transition_pending",
    "close_observation_pending",
]


@dataclass(frozen=True, slots=True)
class WeightCommitSchedulePending:
    """A valid prefix whose next required finalized observation is absent."""

    reason_code: PendingReason
    next_required_height: int | None
    reveal_observation_block: VerifiedWeightScheduleObservation | None = None
    weight_commit_ready_height: int | None = None
    base_epoch_block: VerifiedWeightScheduleObservation | None = None
    weight_commit_open_block: VerifiedWeightScheduleObservation | None = None

    def __post_init__(self) -> None:
        if self.reason_code not in {
            "reveal_observation_pending",
            "base_epoch_observation_pending",
            "epoch_transition_pending",
            "close_observation_pending",
        }:
            raise ValueError("unknown schedule pending reason")
        if self.next_required_height is not None:
            _uint(self.next_required_height, "next_required_height")


@dataclass(frozen=True, slots=True)
class WeightCommitSchedule:
    """The complete observed Section 10.3 commit interval."""

    reveal_observation_block: VerifiedWeightScheduleObservation
    weight_commit_ready_height: int
    base_epoch_block: VerifiedWeightScheduleObservation
    base_epoch_index: int
    weight_commit_open_block: VerifiedWeightScheduleObservation
    weight_commit_epoch_index: int
    weight_commit_close_block: VerifiedWeightScheduleObservation

    def __post_init__(self) -> None:
        _uint(self.weight_commit_ready_height, "weight_commit_ready_height")
        _uint(self.base_epoch_index, "base_epoch_index")
        _uint(self.weight_commit_epoch_index, "weight_commit_epoch_index")
        if self.base_epoch_block.snapshot.block_number + 1 != self.weight_commit_ready_height:
            raise ValueError("base epoch block must immediately precede the ready height")
        if self.base_epoch_block.subnet_epoch_index != self.base_epoch_index:
            raise ValueError("base epoch index does not match its proof-backed block")
        if self.weight_commit_open_block.snapshot.block_number < self.weight_commit_ready_height:
            raise ValueError("weight commit opened before the ready height")
        if self.weight_commit_open_block.subnet_epoch_index != self.weight_commit_epoch_index:
            raise ValueError("commit epoch index does not match its proof-backed open block")
        if self.weight_commit_epoch_index <= self.base_epoch_index:
            raise ValueError("commit epoch must be greater than the observed base epoch")
        if self.weight_commit_close_block.snapshot.block_number <= (
            self.weight_commit_open_block.snapshot.block_number
        ):
            raise ValueError("commit close block must follow the open block")


WeightCommitScheduleResult = WeightCommitSchedule | WeightCommitSchedulePending


def derive_weight_commit_schedule(
    observations: Sequence[VerifiedWeightScheduleObservation],
    *,
    identity: WeightScheduleIdentity,
    reveal_time_ms: int,
    weight_commit_buffer_blocks: int,
    weight_commit_submission_blocks: int,
    limits: WeightScheduleLimits | None = None,
) -> WeightCommitScheduleResult:
    """Derive the observed commit interval, or return its valid pending prefix.

    The supplied interval must begin before ``reveal_time_ms`` so the first
    finalized block at or after reveal is actually proven.  It must then contain
    every height without a gap through its newest observation.  Missing future
    observations produce a pending value; missing history or inconsistent proof
    identity is a fail-closed error.
    """

    if not isinstance(identity, WeightScheduleIdentity):
        raise TypeError("identity must be a WeightScheduleIdentity")
    _uint(reveal_time_ms, "reveal_time_ms")
    _positive_uint(weight_commit_buffer_blocks, "weight_commit_buffer_blocks")
    _positive_uint(weight_commit_submission_blocks, "weight_commit_submission_blocks")
    active_limits = limits or WeightScheduleLimits()
    if not isinstance(active_limits, WeightScheduleLimits):
        raise TypeError("limits must be a WeightScheduleLimits")
    if isinstance(observations, (str, bytes, bytearray)) or not isinstance(observations, Sequence):
        raise TypeError("observations must be a sequence")
    if len(observations) > active_limits.maximum_observations:
        raise WeightScheduleError("observation_count_limit")
    ordered = tuple(observations)
    if any(not isinstance(item, VerifiedWeightScheduleObservation) for item in ordered):
        raise TypeError("observations must contain VerifiedWeightScheduleObservation values")
    _validate_observation_interval(ordered, identity=identity, limits=active_limits)

    if not ordered:
        return WeightCommitSchedulePending(
            reason_code="reveal_observation_pending",
            next_required_height=None,
        )
    if ordered[0].timestamp_ms >= reveal_time_ms:
        raise WeightScheduleError("reveal_boundary_history_missing")

    reveal_position = next(
        (index for index, item in enumerate(ordered) if item.timestamp_ms >= reveal_time_ms),
        None,
    )
    if reveal_position is None:
        return WeightCommitSchedulePending(
            reason_code="reveal_observation_pending",
            next_required_height=_increment_height(ordered[-1].snapshot.block_number),
        )
    reveal = ordered[reveal_position]
    ready_height = _add_height(
        reveal.snapshot.block_number,
        weight_commit_buffer_blocks,
        reason_code="weight_commit_ready_height_overflow",
    )
    base_height = ready_height - 1
    by_height = {item.snapshot.block_number: item for item in ordered}
    base = by_height.get(base_height)
    if base is None:
        return WeightCommitSchedulePending(
            reason_code="base_epoch_observation_pending",
            next_required_height=_increment_height(ordered[-1].snapshot.block_number),
            reveal_observation_block=reveal,
            weight_commit_ready_height=ready_height,
        )

    open_block = next(
        (
            item
            for item in ordered
            if item.snapshot.block_number >= ready_height
            and item.subnet_epoch_index > base.subnet_epoch_index
        ),
        None,
    )
    if open_block is None:
        return WeightCommitSchedulePending(
            reason_code="epoch_transition_pending",
            next_required_height=_increment_height(ordered[-1].snapshot.block_number),
            reveal_observation_block=reveal,
            weight_commit_ready_height=ready_height,
            base_epoch_block=base,
        )

    close_height_threshold = _add_height(
        open_block.snapshot.block_number,
        weight_commit_submission_blocks,
        reason_code="weight_commit_close_height_overflow",
    )
    close_block = next(
        (
            item
            for item in ordered
            if item.snapshot.block_number > open_block.snapshot.block_number
            and (
                item.snapshot.block_number > close_height_threshold
                or item.subnet_epoch_index != open_block.subnet_epoch_index
            )
        ),
        None,
    )
    if close_block is None:
        return WeightCommitSchedulePending(
            reason_code="close_observation_pending",
            next_required_height=_increment_height(ordered[-1].snapshot.block_number),
            reveal_observation_block=reveal,
            weight_commit_ready_height=ready_height,
            base_epoch_block=base,
            weight_commit_open_block=open_block,
        )
    return WeightCommitSchedule(
        reveal_observation_block=reveal,
        weight_commit_ready_height=ready_height,
        base_epoch_block=base,
        base_epoch_index=base.subnet_epoch_index,
        weight_commit_open_block=open_block,
        weight_commit_epoch_index=open_block.subnet_epoch_index,
        weight_commit_close_block=close_block,
    )


def _validate_observation_interval(
    observations: tuple[VerifiedWeightScheduleObservation, ...],
    *,
    identity: WeightScheduleIdentity,
    limits: WeightScheduleLimits,
) -> None:
    evidence_bytes = 0
    prior: VerifiedWeightScheduleObservation | None = None
    for item in observations:
        if item.chain_genesis_hash != identity.chain_genesis_hash:
            raise WeightScheduleError("chain_identity_mismatch")
        if item.identity.finality_verifier_sha256 != identity.finality_verifier_sha256:
            raise WeightScheduleError("finality_verifier_mismatch")
        if item.runtime.pin != identity.runtime_pin:
            raise WeightScheduleError("runtime_identity_mismatch")
        finality_size = len(item.finality_attestation)
        if finality_size > limits.maximum_finality_evidence_bytes:
            raise WeightScheduleError("finality_evidence_size_limit")
        proof = item.subnet_epoch_index_read.evidence.proof
        if len(proof) > limits.maximum_storage_proof_nodes:
            raise WeightScheduleError("storage_proof_node_count_limit")
        proof_bytes = 0
        for node in proof:
            if len(node) > limits.maximum_storage_proof_node_bytes:
                raise WeightScheduleError("storage_proof_node_size_limit")
            proof_bytes += len(node)
            if proof_bytes > limits.maximum_storage_proof_bytes:
                raise WeightScheduleError("storage_proof_size_limit")
        evidence_bytes += finality_size + proof_bytes
        if evidence_bytes > limits.maximum_total_evidence_bytes:
            raise WeightScheduleError("total_evidence_size_limit")
        if prior is not None:
            if item.snapshot.block_number != prior.snapshot.block_number + 1:
                raise WeightScheduleError("finalized_observation_gap")
            if item.identity.parent_snapshot != prior.snapshot:
                raise WeightScheduleError("finalized_parent_identity_mismatch")
            if item.timestamp_ms < prior.timestamp_ms:
                raise WeightScheduleError("finalized_timestamp_regression")
            if item.subnet_epoch_index < prior.subnet_epoch_index:
                raise WeightScheduleError("subnet_epoch_index_regression")
        prior = item


def _hex32(value: object, field: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be 32 bytes encoded as lowercase hexadecimal")
    return value


def _uint(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _MAX_U64:
        raise ValueError(f"{field} must be a nonnegative u64")
    return value


def _positive_uint(value: object, field: str) -> int:
    result = _uint(value, field)
    if result == 0:
        raise ValueError(f"{field} must be positive")
    return result


def _add_height(height: int, delta: int, *, reason_code: str) -> int:
    result = height + delta
    if result > _MAX_U64:
        raise WeightScheduleError(reason_code)
    return result


def _increment_height(height: int) -> int:
    if height == _MAX_U64:
        raise WeightScheduleError("observation_height_exhausted")
    return height + 1


__all__ = [
    "SUBNET_EPOCH_PALLET",
    "SUBNET_EPOCH_STORAGE_ITEM",
    "VerifiedWeightScheduleObservation",
    "WeightCommitSchedule",
    "WeightCommitSchedulePending",
    "WeightCommitScheduleResult",
    "WeightScheduleError",
    "WeightScheduleIdentity",
    "WeightScheduleLimits",
    "derive_weight_commit_schedule",
]
