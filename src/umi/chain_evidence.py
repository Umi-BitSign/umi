"""Fail-closed chain evidence and pure Section 10 call construction.

This module deliberately has no compose, sign, submit, or broadcast operation.  It
turns already-pinned observations into immutable evidence and unsigned generated
calls.  A caller must perform finality, storage-proof, signing, inclusion, and
terminal-state work outside this boundary.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Protocol

import bittensor as bt
import bittensor_core

from .encoding import account_id32, raw_sha256

NETUID = 78
MECHANISM_ID = 0
COMMIT_REVEAL_VERSION = 4

_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WEIGHT_CALL_NAMES = frozenset(
    {
        "batch_commit_weights",
        "batch_reveal_weights",
        "batch_set_weights",
        "commit_crv3_mechanism_weights",
        "commit_mechanism_weights",
        "commit_timelocked_mechanism_weights",
        "commit_timelocked_weights",
        "commit_weights",
        "reveal_mechanism_weights",
        "reveal_weights",
        "set_mechanism_weights",
        "set_weights",
    }
)
_WEIGHT_EVENT_NAMES = frozenset(
    {
        "BatchWeightsCompleted",
        "CRV3WeightsCommitted",
        "CRV3WeightsRevealed",
        "TimelockedWeightsCommitted",
        "TimelockedWeightsRevealed",
        "WeightsCommitted",
        "WeightsRevealed",
        "WeightsSet",
    }
)
_REQUIRED_CHILD_CALLS = frozenset(
    {
        ("Multisig", "as_multi"),
        ("Multisig", "as_multi_threshold_1"),
        ("Proxy", "proxy"),
        ("Proxy", "proxy_announced"),
        ("Scheduler", "schedule"),
        ("Scheduler", "schedule_after"),
        ("Scheduler", "schedule_named"),
        ("Scheduler", "schedule_named_after"),
        ("Sudo", "sudo"),
        ("Sudo", "sudo_as"),
        ("Sudo", "sudo_unchecked_weight"),
        ("Utility", "as_derivative"),
        ("Utility", "batch"),
        ("Utility", "batch_all"),
        ("Utility", "dispatch_as"),
        ("Utility", "dispatch_as_fallible"),
        ("Utility", "force_batch"),
        ("Utility", "if_else"),
        ("Utility", "with_weight"),
    }
)


def _strict_uint(value: int, *, field: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f"{field} is out of range")
    return value


def _positive_uint(value: int, *, field: str, maximum: int | None = None) -> int:
    _strict_uint(value, field=field, maximum=maximum)
    if value == 0:
        raise ValueError(f"{field} must be positive")
    return value


def _block_hash(value: str, *, field: str) -> str:
    if not isinstance(value, str) or _BLOCK_HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a 0x-prefixed lowercase 32-byte hash")
    return value


def _sha256(value: str, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be 32 bytes encoded as lowercase hexadecimal")
    return value


def _nonempty(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.isspace():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _proof_root(value: str | bytes) -> str:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError("proof verifier returned a state root with the wrong length")
        return "0x" + value.hex()
    return _block_hash(value, field="proof-derived state root")


@dataclass(frozen=True, slots=True)
class FinalizedSnapshotRef:
    """A block header reference the evidence collector has established as finalized."""

    block_number: int
    block_hash: str
    parent_hash: str
    state_root: str

    def __post_init__(self) -> None:
        _strict_uint(self.block_number, field="block_number")
        _block_hash(self.block_hash, field="block_hash")
        _block_hash(self.parent_hash, field="parent_hash")
        _block_hash(self.state_root, field="state_root")
        if self.block_hash == self.parent_hash:
            raise ValueError("a finalized block cannot name itself as its parent")


class StorageProofVerifier(Protocol):
    """Verify storage proof bytes and return the state root derived from them."""

    def __call__(
        self,
        *,
        block_hash: str,
        storage_key: bytes,
        expected_value: bytes | None,
        proof: tuple[bytes, ...],
    ) -> str | bytes: ...


@dataclass(frozen=True, slots=True, init=False)
class StorageEvidence:
    """One verified storage value or absence proof at a finalized state root.

    Direct construction still requires ``verifier``.  A boolean verifier is not
    accepted: the callback must return the root reconstructed from the proof, and
    that root must equal the snapshot header's state root.
    """

    snapshot: FinalizedSnapshotRef
    storage_key: bytes
    value: bytes | None
    proof: tuple[bytes, ...]
    verified_state_root: str

    def __init__(
        self,
        *,
        snapshot: FinalizedSnapshotRef,
        storage_key: bytes,
        value: bytes | None,
        proof: Sequence[bytes],
        verifier: StorageProofVerifier,
    ) -> None:
        if not isinstance(snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        if not isinstance(storage_key, bytes) or not storage_key:
            raise ValueError("storage_key must be non-empty bytes")
        if value is not None and not isinstance(value, bytes):
            raise TypeError("value must be bytes or None")
        if isinstance(proof, (bytes, bytearray)):
            raise TypeError("proof must be a sequence of encoded proof nodes")
        proof_tuple = tuple(proof)
        if not proof_tuple or any(not isinstance(node, bytes) or not node for node in proof_tuple):
            raise ValueError("proof must contain non-empty byte nodes")
        if not callable(verifier):
            raise TypeError("verifier must be callable")
        try:
            derived_root = verifier(
                block_hash=snapshot.block_hash,
                storage_key=storage_key,
                expected_value=value,
                proof=proof_tuple,
            )
        except Exception as error:
            raise ValueError("storage proof verification failed") from error
        if isinstance(derived_root, bool):
            raise ValueError("proof verifier must return the proof-derived state root")
        verified_root = _proof_root(derived_root)
        if verified_root != snapshot.state_root:
            raise ValueError("storage proof state root does not match the finalized header")

        object.__setattr__(self, "snapshot", snapshot)
        object.__setattr__(self, "storage_key", storage_key)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "proof", proof_tuple)
        object.__setattr__(self, "verified_state_root", verified_root)


@dataclass(frozen=True, slots=True)
class WeightScheduleSnapshot:
    """All schedule inputs read at one block for ``get_encrypted_commit_v2``."""

    block_number: int
    block_hash: str
    tempo: int
    last_epoch_block: int
    pending_epoch_at: int
    subnet_epoch_index: int
    blocks_since_last_step: int
    reveal_period_epochs: int
    block_time: float

    def __post_init__(self) -> None:
        _strict_uint(self.block_number, field="block_number")
        _block_hash(self.block_hash, field="block_hash")
        _positive_uint(self.tempo, field="tempo", maximum=(1 << 16) - 1)
        _strict_uint(self.last_epoch_block, field="last_epoch_block")
        _strict_uint(self.pending_epoch_at, field="pending_epoch_at")
        _strict_uint(self.subnet_epoch_index, field="subnet_epoch_index")
        _strict_uint(self.blocks_since_last_step, field="blocks_since_last_step")
        _positive_uint(self.reveal_period_epochs, field="reveal_period_epochs")
        if isinstance(self.block_time, bool) or not isinstance(self.block_time, (int, float)):
            raise TypeError("block_time must be a finite number")
        if not math.isfinite(self.block_time) or self.block_time <= 0:
            raise ValueError("block_time must be a positive finite number")
        if self.last_epoch_block > self.block_number:
            raise ValueError("last_epoch_block cannot be after the schedule snapshot")
        if self.blocks_since_last_step > self.block_number:
            raise ValueError("blocks_since_last_step cannot exceed the current block")


@dataclass(frozen=True, slots=True)
class BuiltCRv4WeightCommit:
    """Unsigned CRv4 ciphertext and generated raw call built without chain I/O."""

    schedule: WeightScheduleSnapshot
    netuid: int
    uids: tuple[int, ...]
    weights: tuple[int, ...]
    weights_version_key: int
    hotkey_public_key: bytes
    ciphertext: bytes
    reveal_round: int
    raw_call: Any


def build_crv4_weight_commit(
    *,
    schedule: WeightScheduleSnapshot,
    uids: Sequence[int],
    weights: Sequence[int],
    weights_version_key: int,
    hotkey_public_key: bytes,
    netuid: int = NETUID,
) -> BuiltCRv4WeightCommit:
    """Build, but never compose or submit, one mechanism-aware CRv4 call.

    All mutable schedule state comes from ``schedule``.  This function performs
    no best-head query and offers no mechanism or commit-reveal version override.
    """

    if not isinstance(schedule, WeightScheduleSnapshot):
        raise TypeError("schedule must be a WeightScheduleSnapshot")
    if netuid != NETUID:
        raise ValueError("UMI version 0.1 weight calls are pinned to SN78")
    uid_tuple = tuple(uids)
    weight_tuple = tuple(weights)
    if not uid_tuple or len(uid_tuple) != len(weight_tuple):
        raise ValueError("uids and weights must be non-empty parallel sequences")
    if len(set(uid_tuple)) != len(uid_tuple):
        raise ValueError("uids must be unique")
    for uid in uid_tuple:
        _strict_uint(uid, field="uid", maximum=(1 << 16) - 1)
    for weight in weight_tuple:
        _positive_uint(weight, field="quantized weight", maximum=(1 << 16) - 1)
    _strict_uint(weights_version_key, field="weights_version_key", maximum=(1 << 64) - 1)
    if not isinstance(hotkey_public_key, bytes) or len(hotkey_public_key) != 32:
        raise ValueError("hotkey_public_key must be exactly 32 bytes")

    ciphertext, reveal_round = bittensor_core.get_encrypted_commit_v2(
        uids=list(uid_tuple),
        weights=list(weight_tuple),
        version_key=weights_version_key,
        last_epoch_block=schedule.last_epoch_block,
        pending_epoch_at=schedule.pending_epoch_at,
        subnet_epoch_index=schedule.subnet_epoch_index,
        tempo=schedule.tempo,
        blocks_since_last_step=schedule.blocks_since_last_step,
        current_block=schedule.block_number,
        subnet_reveal_period_epochs=schedule.reveal_period_epochs,
        block_time=schedule.block_time,
        hotkey=hotkey_public_key,
    )
    if not isinstance(ciphertext, bytes) or not ciphertext:
        raise ValueError("bittensor_core returned an invalid ciphertext")
    _positive_uint(reveal_round, field="reveal_round", maximum=(1 << 64) - 1)
    raw_call = bt.calls.SubtensorModule.commit_timelocked_mechanism_weights(
        netuid=netuid,
        mecid=MECHANISM_ID,
        commit=ciphertext,
        reveal_round=reveal_round,
        commit_reveal_version=COMMIT_REVEAL_VERSION,
    )
    return BuiltCRv4WeightCommit(
        schedule=schedule,
        netuid=netuid,
        uids=uid_tuple,
        weights=weight_tuple,
        weights_version_key=weights_version_key,
        hotkey_public_key=hotkey_public_key,
        ciphertext=ciphertext,
        reveal_round=reveal_round,
        raw_call=raw_call,
    )


def build_sha256_commitment_call(
    digest: str | bytes,
    *,
    netuid: int = NETUID,
) -> Any:
    """Build an unsigned ``Commitments.set_commitment`` with one SHA-256 field."""

    if netuid != NETUID:
        raise ValueError("UMI version 0.1 commitments are pinned to SN78")
    digest_bytes = raw_sha256(digest, field="commitment digest")
    return bt.calls.Commitments.set_commitment(
        netuid=netuid,
        info={"fields": [{"Sha256": digest_bytes}]},
    )


@dataclass(frozen=True, slots=True)
class FinalizedCallRecord:
    """One node in a completely decoded finalized extrinsic call tree.

    ``call_path`` is empty for the outer call.  Child paths append their zero-based
    position in the parent's decoded call arguments.  ``effective_origin`` is the
    origin after wrapper semantics such as proxy, multisig, derivative, dispatch-as,
    or sudo have been applied; it is intentionally distinct from the outer
    extrinsic signer.
    """

    snapshot: FinalizedSnapshotRef
    extrinsic_index: int
    call_hash: str
    module: str
    function: str
    successful: bool
    recursive_decode_complete: bool
    declared_child_count: int
    call_path: tuple[int, ...]
    signer_account_id32: str | bytes | None = None
    effective_origin_account_id32: str | bytes | None = None
    netuid: int | None = None
    mechanism_id: int | None = None
    children: tuple[FinalizedCallRecord, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        _strict_uint(self.extrinsic_index, field="extrinsic_index")
        _block_hash(self.call_hash, field="call_hash")
        _nonempty(self.module, field="module")
        _nonempty(self.function, field="function")
        if not isinstance(self.successful, bool):
            raise TypeError("successful must be a boolean")
        if not isinstance(self.recursive_decode_complete, bool):
            raise TypeError("recursive_decode_complete must be a boolean")
        _strict_uint(self.declared_child_count, field="declared_child_count")
        path = tuple(self.call_path)
        if any(
            isinstance(index, bool) or not isinstance(index, int) or index < 0 for index in path
        ):
            raise ValueError("call_path must contain non-negative integer indexes")
        object.__setattr__(self, "call_path", path)
        if self.signer_account_id32 is not None:
            object.__setattr__(self, "signer_account_id32", account_id32(self.signer_account_id32))
        if self.effective_origin_account_id32 is not None:
            object.__setattr__(
                self,
                "effective_origin_account_id32",
                account_id32(self.effective_origin_account_id32),
            )
        elif not path and self.signer_account_id32 is not None:
            object.__setattr__(
                self,
                "effective_origin_account_id32",
                self.signer_account_id32,
            )
        if self.netuid is not None:
            _strict_uint(self.netuid, field="netuid", maximum=(1 << 16) - 1)
        if self.mechanism_id is not None:
            _strict_uint(self.mechanism_id, field="mechanism_id", maximum=(1 << 8) - 1)
        children = tuple(self.children)
        object.__setattr__(self, "children", children)
        if len(children) != self.declared_child_count:
            raise ValueError("decoded children do not match declared_child_count")
        for index, child in enumerate(children):
            if not isinstance(child, FinalizedCallRecord):
                raise TypeError("children must be FinalizedCallRecord nodes")
            if child.snapshot != self.snapshot or child.extrinsic_index != self.extrinsic_index:
                raise ValueError("every child call must bind the same finalized extrinsic")
            if child.call_path != (*path, index):
                raise ValueError("child call paths must be complete and position-derived")
            if child.signer_account_id32 is not None:
                raise ValueError("only the outer call may carry the extrinsic signer")


@dataclass(frozen=True, slots=True)
class FinalizedEventRecord:
    """One decoded event in a finalized block."""

    snapshot: FinalizedSnapshotRef
    event_index: int
    payload_sha256: str
    module: str
    event: str
    extrinsic_index: int | None = None
    account_id32: str | bytes | None = None
    netuid: int | None = None
    mechanism_id: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        _strict_uint(self.event_index, field="event_index")
        _sha256(self.payload_sha256, field="payload_sha256")
        _nonempty(self.module, field="module")
        _nonempty(self.event, field="event")
        if self.extrinsic_index is not None:
            _strict_uint(self.extrinsic_index, field="extrinsic_index")
        if self.account_id32 is not None:
            object.__setattr__(self, "account_id32", account_id32(self.account_id32))
        if self.netuid is not None:
            _strict_uint(self.netuid, field="netuid", maximum=(1 << 16) - 1)
        if self.mechanism_id is not None:
            _strict_uint(self.mechanism_id, field="mechanism_id", maximum=(1 << 8) - 1)


@dataclass(frozen=True, slots=True)
class FinalizedBlockRecord:
    """Complete recursively decoded calls and events for one finalized block."""

    snapshot: FinalizedSnapshotRef
    extrinsic_count: int
    event_count: int
    calls: tuple[FinalizedCallRecord, ...]
    events: tuple[FinalizedEventRecord, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        _strict_uint(self.extrinsic_count, field="extrinsic_count")
        _strict_uint(self.event_count, field="event_count")
        calls = tuple(self.calls)
        events = tuple(self.events)
        object.__setattr__(self, "calls", calls)
        object.__setattr__(self, "events", events)
        if any(call.snapshot != self.snapshot for call in calls):
            raise ValueError("every call must bind the block snapshot")
        if any(call.call_path for call in calls):
            raise ValueError("the block call array must contain only outer call-tree roots")
        if any(event.snapshot != self.snapshot for event in events):
            raise ValueError("every event must bind the block snapshot")
        if sorted(call.extrinsic_index for call in calls) != list(range(self.extrinsic_count)):
            raise ValueError("call records do not cover every outer extrinsic exactly once")
        if sorted(event.event_index for event in events) != list(range(self.event_count)):
            raise ValueError("event records do not cover every event exactly once")
        if any(
            event.extrinsic_index is not None and event.extrinsic_index >= self.extrinsic_count
            for event in events
        ):
            raise ValueError("an event refers to an absent extrinsic")


@dataclass(frozen=True, slots=True)
class ShadowNoWeightScan:
    """Result of a complete, contiguous finalized interval scan."""

    start_snapshot: FinalizedSnapshotRef
    end_snapshot: FinalizedSnapshotRef
    validator_account_id32: bytes
    netuid: int
    mechanism_id: int
    scanned_blocks: int
    scanned_calls: int
    scanned_events: int


def _walk_call_tree(root: FinalizedCallRecord) -> tuple[FinalizedCallRecord, ...]:
    nodes: list[FinalizedCallRecord] = []
    pending = [root]
    while pending:
        node = pending.pop()
        if not node.recursive_decode_complete:
            raise ValueError("call tree contains incomplete recursive decoding evidence")
        if (node.module, node.function) in _REQUIRED_CHILD_CALLS and not node.children:
            raise ValueError("known dispatch wrapper lacks recursively decoded child calls")
        nodes.append(node)
        pending.extend(reversed(node.children))
    return tuple(nodes)


def assert_shadow_no_weight_interval(
    blocks: Sequence[FinalizedBlockRecord],
    *,
    start_block: int,
    end_block: int,
    validator_account: str | bytes,
    netuid: int = NETUID,
    mechanism_id: int = MECHANISM_ID,
) -> ShadowNoWeightScan:
    """Require a complete interval with no validator weight call or commit event."""

    _strict_uint(start_block, field="start_block")
    _strict_uint(end_block, field="end_block")
    if end_block < start_block:
        raise ValueError("end_block cannot precede start_block")
    if netuid != NETUID or mechanism_id != MECHANISM_ID:
        raise ValueError("the shadow scan is pinned to SN78 MechId 0")
    account = account_id32(validator_account)
    ordered = tuple(blocks)
    expected_heights = tuple(range(start_block, end_block + 1))
    if tuple(block.snapshot.block_number for block in ordered) != expected_heights:
        raise ValueError("finalized interval is incomplete, duplicated, or out of order")
    for previous, current in pairwise(ordered):
        if current.snapshot.parent_hash != previous.snapshot.block_hash:
            raise ValueError("finalized interval does not form one contiguous header chain")

    decoded_calls: list[FinalizedCallRecord] = []
    for block in ordered:
        block_calls: list[FinalizedCallRecord] = []
        for root_call in block.calls:
            block_calls.extend(_walk_call_tree(root_call))
        decoded_calls.extend(block_calls)
        for call in block_calls:
            if call.module != "SubtensorModule" or call.function not in _WEIGHT_CALL_NAMES:
                continue
            if call.effective_origin_account_id32 is None:
                raise ValueError("weight call lacks a decoded effective origin")
            if call.netuid is None:
                raise ValueError("validator weight call lacks a decoded target netuid")
            effective_mechanism = 0 if call.mechanism_id is None else call.mechanism_id
            if (
                call.effective_origin_account_id32 == account
                and call.netuid == netuid
                and effective_mechanism == mechanism_id
            ):
                raise ValueError("shadow interval contains a validator weight call")
        for event in block.events:
            if event.module != "SubtensorModule" or event.event not in _WEIGHT_EVENT_NAMES:
                continue
            if event.account_id32 is None:
                raise ValueError("weight event lacks a decoded account")
            if event.account_id32 != account:
                continue
            if event.netuid is None:
                raise ValueError("validator weight event lacks a decoded target netuid")
            effective_mechanism = 0 if event.mechanism_id is None else event.mechanism_id
            if event.netuid == netuid and effective_mechanism == mechanism_id:
                raise ValueError("shadow interval contains a validator weight event")

    return ShadowNoWeightScan(
        start_snapshot=ordered[0].snapshot,
        end_snapshot=ordered[-1].snapshot,
        validator_account_id32=account,
        netuid=netuid,
        mechanism_id=mechanism_id,
        scanned_blocks=len(ordered),
        scanned_calls=len(decoded_calls),
        scanned_events=sum(len(block.events) for block in ordered),
    )


@dataclass(frozen=True, slots=True)
class RuntimeSpecPin:
    spec_version: int
    metadata_sha256: str
    mechanism_count: int = 1
    commit_reveal_version: int = COMMIT_REVEAL_VERSION

    def __post_init__(self) -> None:
        _positive_uint(self.spec_version, field="spec_version")
        _sha256(self.metadata_sha256, field="metadata_sha256")
        if self.mechanism_count != 1:
            raise ValueError("UMI version 0.1 requires exactly one mechanism")
        if self.commit_reveal_version != COMMIT_REVEAL_VERSION:
            raise ValueError("UMI version 0.1 requires commit-reveal version 4")


@dataclass(frozen=True, slots=True)
class RuntimeSpecObservation:
    snapshot: FinalizedSnapshotRef
    spec_version: int
    metadata_sha256: str
    mechanism_count: int
    commit_reveal_enabled: bool
    commit_reveal_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        _positive_uint(self.spec_version, field="spec_version")
        _sha256(self.metadata_sha256, field="metadata_sha256")
        _positive_uint(self.mechanism_count, field="mechanism_count")
        if not isinstance(self.commit_reveal_enabled, bool):
            raise TypeError("commit_reveal_enabled must be a boolean")
        _strict_uint(self.commit_reveal_version, field="commit_reveal_version")


@dataclass(frozen=True, slots=True)
class CorePin:
    revision: str
    content_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.revision, field="core revision")
        _sha256(self.content_sha256, field="core content_sha256")


@dataclass(frozen=True, slots=True)
class CoreObservation:
    revision: str
    content_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.revision, field="core revision")
        _sha256(self.content_sha256, field="core content_sha256")


def require_runtime_spec_pin(
    observation: RuntimeSpecObservation,
    pin: RuntimeSpecPin,
) -> None:
    """Fail unless the finalized runtime observation matches every required pin."""

    if not isinstance(observation, RuntimeSpecObservation) or not isinstance(pin, RuntimeSpecPin):
        raise TypeError("runtime observation and pin have the wrong type")
    if not observation.commit_reveal_enabled:
        raise ValueError("commit-reveal weights are not enabled")
    expected = (
        pin.spec_version,
        pin.metadata_sha256,
        pin.mechanism_count,
        pin.commit_reveal_version,
    )
    actual = (
        observation.spec_version,
        observation.metadata_sha256,
        observation.mechanism_count,
        observation.commit_reveal_version,
    )
    if actual != expected:
        raise ValueError("runtime observation does not match the Section 10 pin")


def require_core_pin(observation: CoreObservation, pin: CorePin) -> None:
    """Fail unless the core revision and content digest both match."""

    if not isinstance(observation, CoreObservation) or not isinstance(pin, CorePin):
        raise TypeError("core observation and pin have the wrong type")
    if (observation.revision, observation.content_sha256) != (
        pin.revision,
        pin.content_sha256,
    ):
        raise ValueError("bittensor core does not match the Section 10 pin")


__all__ = [
    "COMMIT_REVEAL_VERSION",
    "MECHANISM_ID",
    "NETUID",
    "BuiltCRv4WeightCommit",
    "CoreObservation",
    "CorePin",
    "FinalizedBlockRecord",
    "FinalizedCallRecord",
    "FinalizedEventRecord",
    "FinalizedSnapshotRef",
    "RuntimeSpecObservation",
    "RuntimeSpecPin",
    "ShadowNoWeightScan",
    "StorageEvidence",
    "StorageProofVerifier",
    "WeightScheduleSnapshot",
    "assert_shadow_no_weight_interval",
    "build_crv4_weight_commit",
    "build_sha256_commitment_call",
    "require_core_pin",
    "require_runtime_spec_pin",
]
