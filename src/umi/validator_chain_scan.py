"""Proof-bound finalized block decoding for shadow no-weight scans.

The scanner deliberately does not choose or trust finality.  Its input is a
sequence of :class:`VerifiedFinalizedBlockIdentity` values produced by an
independent finality verifier.  A narrow read-only port supplies block bodies,
the ``System.Events`` storage value and the runtime that executed each block.
The body is checked against the finalized header's extrinsics root and the event
bytes are checked against the finalized state root before either is decoded.

There is no wallet, signing, composition, submission or broadcast capability in
this module.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from itertools import pairwise
from typing import Any, Protocol, runtime_checkable

import bittensor_core

from .chain_evidence import (
    MECHANISM_ID,
    NETUID,
    FinalizedBlockRecord,
    FinalizedCallRecord,
    FinalizedEventRecord,
    FinalizedSnapshotRef,
    ShadowNoWeightScan,
    StorageEvidence,
    StorageProofVerifier,
    assert_shadow_no_weight_interval,
)
from .encoding import account_id32
from .validator_chain import FinalizedRuntimePin, PinnedRuntimeContext

_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CALL_INDEX_RE = re.compile(r"^0x[0-9a-f]{4}$")
_EVENT_INDEX_RE = re.compile(r"^[0-9a-f]{4}$")
_MAX_U16 = (1 << 16) - 1
_MAX_U8 = (1 << 8) - 1
_GLOBAL_MAX_SUBNET_COUNT = 4_096

_BODY_DOMAIN = b"umi-finalized-block-body-v1\0"
_EVENT_PAYLOAD_DOMAIN = b"umi-finalized-event-payload-v1\0"

_SAME_ORIGIN_WRAPPERS = frozenset(
    {
        ("Utility", "batch"),
        ("Utility", "batch_all"),
        ("Utility", "force_batch"),
        ("Utility", "if_else"),
    }
)
_ROOT_ORIGIN_WRAPPERS = frozenset(
    {
        ("Scheduler", "schedule"),
        ("Scheduler", "schedule_after"),
        ("Scheduler", "schedule_named"),
        ("Scheduler", "schedule_named_after"),
        ("Sudo", "sudo"),
        ("Sudo", "sudo_unchecked_weight"),
        ("Utility", "with_weight"),
    }
)
_KNOWN_WRAPPERS = frozenset(
    {
        *_SAME_ORIGIN_WRAPPERS,
        *_ROOT_ORIGIN_WRAPPERS,
        ("Multisig", "as_multi"),
        ("Multisig", "as_multi_threshold_1"),
        ("Proxy", "proxy"),
        ("Proxy", "proxy_announced"),
        ("Sudo", "sudo_as"),
        ("Utility", "as_derivative"),
        ("Utility", "dispatch_as"),
        ("Utility", "dispatch_as_fallible"),
    }
)

# Every validator weight call in the pinned publication runtime.  An exact
# runtime metadata pin makes this closed list meaningful: an upgrade cannot add
# another variant without first becoming an unsupported runtime.
_WEIGHT_CALLS_IMPLICIT_MECHANISM = frozenset(
    {
        "batch_commit_weights",
        "batch_reveal_weights",
        "batch_set_weights",
        "commit_timelocked_weights",
        "commit_weights",
        "reveal_weights",
        "set_weights",
    }
)
_WEIGHT_CALLS_EXPLICIT_MECHANISM = frozenset(
    {
        "commit_crv3_mechanism_weights",
        "commit_mechanism_weights",
        "commit_timelocked_mechanism_weights",
        "reveal_mechanism_weights",
        "set_mechanism_weights",
    }
)
_WEIGHT_CALLS = _WEIGHT_CALLS_IMPLICIT_MECHANISM | _WEIGHT_CALLS_EXPLICIT_MECHANISM
_BATCH_NETUID_CALLS = frozenset({"batch_commit_weights", "batch_set_weights"})

_WEIGHT_EVENTS = frozenset(
    {
        "BatchWeightsCompleted",
        "CRV3WeightsCommitted",
        "CRV3WeightsRevealed",
        "TimelockedWeightsCommitted",
        "TimelockedWeightsRevealed",
        "WeightsBatchRevealed",
        "WeightsCommitted",
        "WeightsRevealed",
        "WeightsSet",
    }
)


class ValidatorChainScanError(RuntimeError):
    """A stable fail-closed error raised while collecting or decoding a scan."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ExtrinsicsRootVerifier(Protocol):
    """Verify the exact ordered extrinsic vector against a finalized header root."""

    def __call__(
        self,
        *,
        expected_root: bytes,
        extrinsics: tuple[bytes, ...],
        state_version: int,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class ScanLimits:
    maximum_interval_blocks: int = 1_024
    maximum_extrinsics_per_block: int = 4_096
    maximum_events_per_block: int = 65_536
    maximum_extrinsic_bytes: int = 16 * 1024 * 1024
    maximum_block_body_bytes: int = 64 * 1024 * 1024
    maximum_event_storage_bytes: int = 64 * 1024 * 1024
    maximum_total_wire_bytes: int = 512 * 1024 * 1024
    maximum_event_proof_nodes: int = 4_096
    maximum_event_proof_node_bytes: int = 2 * 1024 * 1024
    maximum_event_proof_bytes: int = 32 * 1024 * 1024
    maximum_call_depth: int = 32
    maximum_call_nodes_per_extrinsic: int = 16_384
    maximum_children_per_call: int = 4_096
    maximum_batch_netuids: int = 4_096

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{item.name} must be a positive integer")
        if self.maximum_extrinsic_bytes > self.maximum_block_body_bytes:
            raise ValueError("one extrinsic cannot exceed the complete block-body limit")
        if self.maximum_event_proof_node_bytes > self.maximum_event_proof_bytes:
            raise ValueError("one proof node cannot exceed the complete proof limit")


@dataclass(frozen=True, slots=True)
class VerifiedFinalizedBlockIdentity:
    """A complete header identity already accepted by an independent verifier.

    ``parent_snapshot`` is required because the parent-state runtime executes
    the child block.  This is important at runtime-upgrade boundaries: decoding
    the block with post-upgrade metadata would be incorrect.
    """

    snapshot: FinalizedSnapshotRef
    parent_snapshot: FinalizedSnapshotRef
    extrinsics_root: str
    finality_verifier_sha256: str
    finality_evidence_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, FinalizedSnapshotRef) or not isinstance(
            self.parent_snapshot, FinalizedSnapshotRef
        ):
            raise TypeError("finalized identities require snapshot references")
        if self.snapshot.block_number == 0:
            raise ValueError("the genesis block has no parent execution runtime")
        if self.parent_snapshot.block_number + 1 != self.snapshot.block_number:
            raise ValueError("parent snapshot height is not adjacent")
        if self.snapshot.parent_hash != self.parent_snapshot.block_hash:
            raise ValueError("parent snapshot does not match the finalized header")
        _block_hash(self.extrinsics_root, "extrinsics_root_invalid")
        _sha256(self.finality_verifier_sha256, "finality_verifier_digest_invalid")
        _sha256(self.finality_evidence_sha256, "finality_evidence_digest_invalid")


@dataclass(frozen=True, slots=True)
class RawFinalizedBlockBody:
    """Exact block-body bytes returned for one requested finalized hash."""

    block_hash: str
    parent_hash: str
    state_root: str
    extrinsics_root: str
    extrinsics: tuple[bytes, ...]
    body_sha256: str

    def __post_init__(self) -> None:
        _block_hash(self.block_hash, "block_body_hash_invalid")
        _block_hash(self.parent_hash, "block_body_parent_invalid")
        _block_hash(self.state_root, "block_body_state_root_invalid")
        _block_hash(self.extrinsics_root, "block_body_extrinsics_root_invalid")
        if isinstance(self.extrinsics, (bytes, bytearray, str)) or not isinstance(
            self.extrinsics, tuple
        ):
            raise TypeError("extrinsics must be a tuple of exact bytes")
        if any(not isinstance(extrinsic, bytes) or not extrinsic for extrinsic in self.extrinsics):
            raise ValueError("every extrinsic must be non-empty exact bytes")
        _sha256(self.body_sha256, "block_body_digest_invalid")
        if finalized_block_body_sha256(self.extrinsics) != self.body_sha256:
            raise ValueError("block body digest does not match its exact bytes")


@dataclass(frozen=True, slots=True)
class RawFinalizedEventStorage:
    """Exact proof-carrying ``System.Events`` storage bytes at one block hash."""

    block_hash: str
    state_root: str
    storage_key: bytes
    value: bytes | None
    proof: tuple[bytes, ...]
    value_sha256: str

    def __post_init__(self) -> None:
        _block_hash(self.block_hash, "event_block_hash_invalid")
        _block_hash(self.state_root, "event_state_root_invalid")
        if not isinstance(self.storage_key, bytes) or not self.storage_key:
            raise ValueError("event storage key must be non-empty bytes")
        if self.value is not None and not isinstance(self.value, bytes):
            raise TypeError("event storage value must be bytes or None")
        if isinstance(self.proof, (bytes, bytearray, str)) or not isinstance(self.proof, tuple):
            raise TypeError("event proof must be a tuple of exact nodes")
        if not self.proof or any(not isinstance(node, bytes) or not node for node in self.proof):
            raise ValueError("event proof must contain non-empty exact nodes")
        _sha256(self.value_sha256, "event_storage_digest_invalid")
        expected = hashlib.sha256(self.value or b"").hexdigest()
        if expected != self.value_sha256:
            raise ValueError("event storage digest does not match its exact bytes")


@runtime_checkable
class FinalizedBlockScanPort(Protocol):
    """Narrow, read-only byte/runtime port; it has no finality-selection method."""

    async def block_body_at(
        self, identity: VerifiedFinalizedBlockIdentity
    ) -> RawFinalizedBlockBody | None:
        """Fetch the exact body for ``identity.snapshot.block_hash``."""

    async def event_storage_at(
        self,
        identity: VerifiedFinalizedBlockIdentity,
        storage_key: bytes,
    ) -> RawFinalizedEventStorage | None:
        """Fetch exact ``System.Events`` bytes and proof at the requested hash."""

    async def execution_runtime_at(
        self, identity: VerifiedFinalizedBlockIdentity
    ) -> PinnedRuntimeContext | None:
        """Return the content-pinned runtime at ``identity.parent_snapshot``."""


@dataclass(frozen=True, slots=True)
class DecodedNoWeightInterval:
    blocks: tuple[FinalizedBlockRecord, ...]
    scan: ShadowNoWeightScan
    evidence: tuple[FinalizedBlockScanEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.blocks:
            raise ValueError("decoded interval cannot be empty")
        if self.scan.start_snapshot != self.blocks[0].snapshot:
            raise ValueError("scan start does not match decoded blocks")
        if self.scan.end_snapshot != self.blocks[-1].snapshot:
            raise ValueError("scan end does not match decoded blocks")
        if self.evidence:
            if len(self.evidence) != len(self.blocks):
                raise ValueError("scan evidence must form a bijection with decoded blocks")
            if tuple(item.decoded_block for item in self.evidence) != self.blocks:
                raise ValueError("scan evidence decoded records do not match the interval")


@dataclass(frozen=True, slots=True)
class CapturedFinalizedBlockInterval:
    """A complete proof-bound interval without a policy-specific assertion."""

    blocks: tuple[FinalizedBlockRecord, ...]
    evidence: tuple[FinalizedBlockScanEvidence, ...]

    def __post_init__(self) -> None:
        if not self.blocks or len(self.blocks) != len(self.evidence):
            raise ValueError("captured finalized interval must form one nonempty bijection")
        if tuple(item.decoded_block for item in self.evidence) != self.blocks:
            raise ValueError("captured evidence does not match the decoded interval")
        for previous, current in pairwise(self.blocks):
            if (
                current.snapshot.block_number != previous.snapshot.block_number + 1
                or current.snapshot.parent_hash != previous.snapshot.block_hash
            ):
                raise ValueError("captured finalized interval is not contiguous")


@dataclass(frozen=True, slots=True)
class FinalityAttestationReplayBinding:
    """Observer-run inputs needed to revalidate one persisted attestation."""

    minimum_finalized_block: int
    maximum_records: int
    startup_timeout_seconds: int
    expected_sequence: int
    previous_number: int | None
    previous_timestamp_ms: int | None
    previous_hash: str | None = None
    previous_digest: str = "0" * 64

    def __post_init__(self) -> None:
        for name in (
            "minimum_finalized_block",
            "expected_sequence",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        for name in ("maximum_records", "startup_timeout_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("previous_number", "previous_timestamp_ms"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be None or a nonnegative integer")
        if (self.previous_number is None) != (self.previous_timestamp_ms is None):
            raise ValueError("previous finalized number and timestamp must be present together")
        if self.previous_hash is not None:
            _block_hash(self.previous_hash, "finality_previous_hash_invalid")
        _sha256(self.previous_digest, "finality_previous_digest_invalid")
        has_previous = self.previous_number is not None
        if has_previous != (self.previous_hash is not None):
            raise ValueError("previous finalized identity must be present together")
        if self.expected_sequence == 0:
            if has_previous or self.previous_digest != "0" * 64:
                raise ValueError("sequence zero must use the observer transcript genesis")
        elif not has_previous or self.previous_digest == "0" * 64:
            raise ValueError("nonzero sequence requires the prior transcript identity")


@dataclass(frozen=True, slots=True)
class FinalizedCommitmentCallBinding:
    """Typed semantic decode of one root ``Commitments.set_commitment`` call."""

    extrinsic_index: int
    call_hash: str
    netuid: int
    field_sha256: str

    def __post_init__(self) -> None:
        _uint(self.extrinsic_index, "commitment_extrinsic_index_invalid")
        _block_hash(self.call_hash, "commitment_call_hash_invalid")
        _uint(self.netuid, "commitment_netuid_invalid", maximum=_MAX_U16)
        _sha256(self.field_sha256, "commitment_field_invalid")


@dataclass(frozen=True, slots=True)
class FinalizedBlockScanEvidence:
    """Exact replay inputs retained for one decoded finalized block.

    The runtime codec object itself is intentionally excluded: it is rebuilt
    from the pinned metadata during bundle verification.  The canonical
    finality attestation is supplied by the independent finality observer and
    is hash-bound to ``identity`` before any evidence can be emitted.
    """

    identity: VerifiedFinalizedBlockIdentity
    finality_attestation: bytes
    finality_replay_binding: FinalityAttestationReplayBinding
    runtime_pin: FinalizedRuntimePin
    runtime_metadata_bytes: bytes
    runtime_version_bytes: bytes
    body: RawFinalizedBlockBody
    event_storage: RawFinalizedEventStorage
    decoded_block: FinalizedBlockRecord
    commitment_calls: tuple[FinalizedCommitmentCallBinding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.identity, VerifiedFinalizedBlockIdentity):
            raise TypeError("scan evidence identity is invalid")
        if not isinstance(self.finality_attestation, bytes) or not self.finality_attestation:
            raise ValueError("scan evidence requires a canonical finality attestation")
        if hashlib.sha256(self.finality_attestation).hexdigest() != (
            self.identity.finality_evidence_sha256
        ):
            raise ValueError("finality attestation digest does not match the verified identity")
        if not isinstance(self.finality_replay_binding, FinalityAttestationReplayBinding):
            raise TypeError("scan evidence finality replay binding is invalid")
        if not isinstance(self.runtime_pin, FinalizedRuntimePin):
            raise TypeError("scan evidence runtime pin is invalid")
        if not isinstance(self.runtime_metadata_bytes, bytes) or not self.runtime_metadata_bytes:
            raise ValueError("scan evidence requires exact runtime metadata bytes")
        if hashlib.sha256(self.runtime_metadata_bytes).hexdigest() != (
            self.runtime_pin.metadata_sha256
        ):
            raise ValueError("runtime metadata digest does not match its pin")
        if not isinstance(self.runtime_version_bytes, bytes) or not self.runtime_version_bytes:
            raise ValueError("scan evidence requires exact runtime-version bytes")
        if not isinstance(self.body, RawFinalizedBlockBody):
            raise TypeError("scan evidence body is invalid")
        if not isinstance(self.event_storage, RawFinalizedEventStorage):
            raise TypeError("scan evidence event storage is invalid")
        if not isinstance(self.decoded_block, FinalizedBlockRecord):
            raise TypeError("scan evidence decoded block is invalid")
        commitments = tuple(self.commitment_calls)
        object.__setattr__(self, "commitment_calls", commitments)
        if any(not isinstance(item, FinalizedCommitmentCallBinding) for item in commitments):
            raise TypeError("scan evidence commitment bindings are invalid")
        if len({item.extrinsic_index for item in commitments}) != len(commitments):
            raise ValueError("scan evidence commitment bindings contain duplicate indexes")
        calls = {item.extrinsic_index: item for item in self.decoded_block.calls}
        for commitment in commitments:
            call = calls.get(commitment.extrinsic_index)
            if (
                call is None
                or call.module != "Commitments"
                or call.function != "set_commitment"
                or call.call_hash != commitment.call_hash
            ):
                raise ValueError("commitment binding disagrees with the decoded root call")
        if self.decoded_block.snapshot != self.identity.snapshot:
            raise ValueError("scan evidence decoded block uses another finalized identity")
        if (
            self.body.block_hash != self.identity.snapshot.block_hash
            or self.event_storage.block_hash != self.identity.snapshot.block_hash
        ):
            raise ValueError("scan evidence raw objects use another finalized block")


def finalized_block_body_sha256(extrinsics: Sequence[bytes]) -> str:
    """Digest an exact ordered block-body vector with unambiguous framing."""

    if isinstance(extrinsics, (bytes, bytearray, str)) or not isinstance(extrinsics, Sequence):
        raise TypeError("extrinsics must be a sequence")
    values = tuple(extrinsics)
    if any(not isinstance(value, bytes) or not value for value in values):
        raise ValueError("every extrinsic must be non-empty exact bytes")
    if len(values) > (1 << 32) - 1 or any(len(value) > (1 << 32) - 1 for value in values):
        raise ValueError("block-body framing exceeds U32")
    digest = hashlib.sha256()
    digest.update(_BODY_DOMAIN)
    digest.update(len(values).to_bytes(4, "big"))
    for value in values:
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()


def _event_payload_sha256(raw_events: bytes, event_index: int) -> str:
    digest = hashlib.sha256()
    digest.update(_EVENT_PAYLOAD_DOMAIN)
    digest.update(event_index.to_bytes(4, "big"))
    digest.update(hashlib.sha256(raw_events).digest())
    return digest.hexdigest()


class FinalizedBlockScanner:
    """Decode proof-bound finalized blocks under an explicit runtime allowlist."""

    def __init__(
        self,
        port: FinalizedBlockScanPort,
        *,
        extrinsics_root_verifier: ExtrinsicsRootVerifier,
        event_proof_verifier: StorageProofVerifier,
        supported_runtime_pins: Sequence[FinalizedRuntimePin],
        limits: ScanLimits | None = None,
    ) -> None:
        if not isinstance(port, FinalizedBlockScanPort):
            raise TypeError("port must implement FinalizedBlockScanPort")
        if not callable(extrinsics_root_verifier):
            raise TypeError("extrinsics_root_verifier must be callable")
        if not callable(event_proof_verifier):
            raise TypeError("event_proof_verifier must be callable")
        if isinstance(supported_runtime_pins, (bytes, bytearray, str)) or not isinstance(
            supported_runtime_pins, Sequence
        ):
            raise TypeError("supported_runtime_pins must be a sequence")
        pins = tuple(supported_runtime_pins)
        if not pins or any(not isinstance(pin, FinalizedRuntimePin) for pin in pins):
            raise ValueError("supported_runtime_pins must contain runtime pins")
        identities = {
            (pin.spec_version, pin.transaction_version, pin.metadata_sha256) for pin in pins
        }
        if len(identities) != len(pins):
            raise ValueError("supported runtime pins must be unique")
        self._port = port
        self._extrinsics_root_verifier = extrinsics_root_verifier
        self._event_proof_verifier = event_proof_verifier
        self._supported_runtime_pins = pins
        self._limits = limits or ScanLimits()

    async def decode_block(self, identity: VerifiedFinalizedBlockIdentity) -> FinalizedBlockRecord:
        """Fetch, authenticate and completely decode one finalized block."""

        block, _wire_bytes, _evidence = await self._decode_block_with_wire_bytes(identity)
        return block

    async def _decode_block_with_wire_bytes(
        self,
        identity: VerifiedFinalizedBlockIdentity,
        *,
        finality_attestation: bytes | None = None,
        finality_replay_binding: FinalityAttestationReplayBinding | None = None,
    ) -> tuple[FinalizedBlockRecord, int, FinalizedBlockScanEvidence | None]:
        if not isinstance(identity, VerifiedFinalizedBlockIdentity):
            raise TypeError("identity must be a VerifiedFinalizedBlockIdentity")
        runtime = await self._required_runtime(identity)
        body = await self._required_body(identity, state_version=runtime.pin.state_version)
        events_raw = await self._required_events(identity, runtime)

        decoded_extrinsics = tuple(
            self._decode_extrinsic(runtime, raw, index) for index, raw in enumerate(body.extrinsics)
        )
        commitment_calls = tuple(
            binding
            for index, decoded in enumerate(decoded_extrinsics)
            if (binding := _commitment_call_binding(decoded, index)) is not None
        )
        decoded_events = self._decode_events(runtime, events_raw.value)
        if len(decoded_events) > self._limits.maximum_events_per_block:
            raise ValidatorChainScanError("event_count_limit")
        statuses = _extrinsic_statuses(decoded_events, len(decoded_extrinsics))

        calls = tuple(
            self._build_call_tree(
                identity.snapshot,
                extrinsic_index=index,
                decoded_extrinsic=decoded,
                successful=statuses[index],
            )
            for index, decoded in enumerate(decoded_extrinsics)
        )
        raw_event_bytes = events_raw.value or b""
        events = tuple(
            self._build_event_record(
                identity.snapshot,
                event_index=index,
                decoded_event=decoded,
                raw_event_bytes=raw_event_bytes,
                calls=calls,
            )
            for index, decoded in enumerate(decoded_events)
        )
        block = FinalizedBlockRecord(
            snapshot=identity.snapshot,
            extrinsic_count=len(body.extrinsics),
            event_count=len(events),
            calls=calls,
            events=events,
        )
        wire_bytes = (
            sum(len(raw) for raw in body.extrinsics)
            + (0 if events_raw.value is None else len(events_raw.value))
            + sum(len(node) for node in events_raw.proof)
        )
        evidence = None
        if finality_attestation is not None:
            if finality_replay_binding is None:
                raise ValueError("finality replay binding is required with an attestation")
            evidence = FinalizedBlockScanEvidence(
                identity=identity,
                finality_attestation=finality_attestation,
                finality_replay_binding=finality_replay_binding,
                runtime_pin=runtime.pin,
                runtime_metadata_bytes=runtime.metadata_bytes,
                runtime_version_bytes=runtime.runtime_version_bytes,
                body=body,
                event_storage=events_raw,
                decoded_block=block,
                commitment_calls=commitment_calls,
            )
        return block, wire_bytes, evidence

    async def decode_blocks(
        self,
        identities: Sequence[VerifiedFinalizedBlockIdentity],
        *,
        start_block: int,
        end_block: int,
    ) -> tuple[FinalizedBlockRecord, ...]:
        """Decode one exact, complete finalized interval without selecting finality."""

        ordered = self._validate_interval(identities, start_block=start_block, end_block=end_block)
        blocks: list[FinalizedBlockRecord] = []
        total_bytes = 0
        for identity in ordered:
            block, wire_bytes, _evidence = await self._decode_block_with_wire_bytes(identity)
            total_bytes += wire_bytes
            if total_bytes > self._limits.maximum_total_wire_bytes:
                raise ValidatorChainScanError("scan_wire_bytes_limit")
            blocks.append(block)
        return tuple(blocks)

    async def decode_no_weight_interval(
        self,
        identities: Sequence[VerifiedFinalizedBlockIdentity],
        *,
        start_block: int,
        end_block: int,
        validator_account: str | bytes,
        netuid: int = NETUID,
        mechanism_id: int = MECHANISM_ID,
    ) -> DecodedNoWeightInterval:
        """Decode a complete interval and require no target validator weight activity."""

        blocks = await self.decode_blocks(
            identities,
            start_block=start_block,
            end_block=end_block,
        )
        account = _account(validator_account, "validator_account_invalid")
        _assert_extended_weight_events_absent(
            blocks,
            validator_account=account,
            netuid=netuid,
            mechanism_id=mechanism_id,
        )
        try:
            scan = assert_shadow_no_weight_interval(
                blocks,
                start_block=start_block,
                end_block=end_block,
                validator_account=account,
                netuid=netuid,
                mechanism_id=mechanism_id,
            )
        except (TypeError, ValueError) as error:
            raise ValidatorChainScanError("shadow_no_weight_assertion_failed") from error
        return DecodedNoWeightInterval(blocks=blocks, scan=scan)

    async def capture_no_weight_interval(
        self,
        identities: Sequence[VerifiedFinalizedBlockIdentity],
        *,
        finality_attestations: Sequence[bytes],
        finality_replay_bindings: Sequence[FinalityAttestationReplayBinding],
        start_block: int,
        end_block: int,
        validator_account: str | bytes,
        netuid: int = NETUID,
        mechanism_id: int = MECHANISM_ID,
    ) -> DecodedNoWeightInterval:
        """Decode and retain every exact input needed for independent replay.

        ``finality_attestations`` come from the independent smoldot observer;
        this scanner does not select a head or infer finality.  It only binds
        each persisted attestation to the already verified identity digest.
        """

        captured = await self.capture_blocks(
            identities,
            finality_attestations=finality_attestations,
            finality_replay_bindings=finality_replay_bindings,
            start_block=start_block,
            end_block=end_block,
        )
        block_tuple = captured.blocks
        account = _account(validator_account, "validator_account_invalid")
        _assert_extended_weight_events_absent(
            block_tuple,
            validator_account=account,
            netuid=netuid,
            mechanism_id=mechanism_id,
        )
        try:
            scan = assert_shadow_no_weight_interval(
                block_tuple,
                start_block=start_block,
                end_block=end_block,
                validator_account=account,
                netuid=netuid,
                mechanism_id=mechanism_id,
            )
        except (TypeError, ValueError) as error:
            raise ValidatorChainScanError("shadow_no_weight_assertion_failed") from error
        return DecodedNoWeightInterval(
            blocks=block_tuple,
            scan=scan,
            evidence=captured.evidence,
        )

    async def capture_blocks(
        self,
        identities: Sequence[VerifiedFinalizedBlockIdentity],
        *,
        finality_attestations: Sequence[bytes],
        finality_replay_bindings: Sequence[FinalityAttestationReplayBinding],
        start_block: int,
        end_block: int,
    ) -> CapturedFinalizedBlockInterval:
        """Decode and retain one generic, independently replayable interval."""

        ordered = self._validate_interval(
            identities,
            start_block=start_block,
            end_block=end_block,
        )
        if isinstance(finality_attestations, (bytes, bytearray, str)) or not isinstance(
            finality_attestations, Sequence
        ):
            raise TypeError("finality_attestations must be a sequence")
        attestations = tuple(finality_attestations)
        if len(attestations) != len(ordered) or any(
            not isinstance(item, bytes) or not item for item in attestations
        ):
            raise ValidatorChainScanError("finality_evidence_count_mismatch")
        if isinstance(finality_replay_bindings, (bytes, bytearray, str)) or not isinstance(
            finality_replay_bindings, Sequence
        ):
            raise TypeError("finality_replay_bindings must be a sequence")
        bindings = tuple(finality_replay_bindings)
        if len(bindings) != len(ordered) or any(
            not isinstance(item, FinalityAttestationReplayBinding) for item in bindings
        ):
            raise ValidatorChainScanError("finality_replay_binding_count_mismatch")

        blocks: list[FinalizedBlockRecord] = []
        evidence: list[FinalizedBlockScanEvidence] = []
        total_bytes = 0
        for identity, attestation, binding in zip(ordered, attestations, bindings, strict=True):
            try:
                block, wire_bytes, captured = await self._decode_block_with_wire_bytes(
                    identity,
                    finality_attestation=attestation,
                    finality_replay_binding=binding,
                )
            except ValueError as error:
                raise ValidatorChainScanError("finality_evidence_mismatch") from error
            assert captured is not None
            total_bytes += wire_bytes + len(attestation)
            if total_bytes > self._limits.maximum_total_wire_bytes:
                raise ValidatorChainScanError("scan_wire_bytes_limit")
            blocks.append(block)
            evidence.append(captured)
        try:
            return CapturedFinalizedBlockInterval(
                blocks=tuple(blocks),
                evidence=tuple(evidence),
            )
        except (TypeError, ValueError) as error:
            raise ValidatorChainScanError("captured_interval_invalid") from error

    def _validate_interval(
        self,
        identities: Sequence[VerifiedFinalizedBlockIdentity],
        *,
        start_block: int,
        end_block: int,
    ) -> tuple[VerifiedFinalizedBlockIdentity, ...]:
        start = _uint(start_block, "scan_start_block_invalid")
        end = _uint(end_block, "scan_end_block_invalid")
        if end < start:
            raise ValidatorChainScanError("scan_interval_invalid")
        expected_count = end - start + 1
        if expected_count > self._limits.maximum_interval_blocks:
            raise ValidatorChainScanError("scan_block_count_limit")
        if isinstance(identities, (bytes, bytearray, str)) or not isinstance(identities, Sequence):
            raise TypeError("identities must be a sequence")
        ordered = tuple(identities)
        if any(not isinstance(item, VerifiedFinalizedBlockIdentity) for item in ordered):
            raise TypeError("identities must contain verified finalized block identities")
        if tuple(item.snapshot.block_number for item in ordered) != tuple(range(start, end + 1)):
            raise ValidatorChainScanError("scan_interval_incomplete")
        for previous, current in pairwise(ordered):
            if current.parent_snapshot != previous.snapshot:
                raise ValidatorChainScanError("scan_parent_identity_mismatch")
        return ordered

    async def _required_body(
        self,
        identity: VerifiedFinalizedBlockIdentity,
        *,
        state_version: int,
    ) -> RawFinalizedBlockBody:
        try:
            body = await self._port.block_body_at(identity)
        except Exception as error:
            raise ValidatorChainScanError("block_body_fetch_failed") from error
        if not isinstance(body, RawFinalizedBlockBody):
            raise ValidatorChainScanError("block_body_missing")
        snapshot = identity.snapshot
        if (
            body.block_hash != snapshot.block_hash
            or body.parent_hash != snapshot.parent_hash
            or body.state_root != snapshot.state_root
            or body.extrinsics_root != identity.extrinsics_root
        ):
            raise ValidatorChainScanError("block_body_identity_mismatch")
        if len(body.extrinsics) > self._limits.maximum_extrinsics_per_block:
            raise ValidatorChainScanError("extrinsic_count_limit")
        total = 0
        for raw in body.extrinsics:
            if len(raw) > self._limits.maximum_extrinsic_bytes:
                raise ValidatorChainScanError("extrinsic_size_limit")
            total += len(raw)
            if total > self._limits.maximum_block_body_bytes:
                raise ValidatorChainScanError("block_body_size_limit")
        try:
            verified = self._extrinsics_root_verifier(
                expected_root=bytes.fromhex(identity.extrinsics_root[2:]),
                extrinsics=body.extrinsics,
                state_version=state_version,
            )
        except ValidatorChainScanError:
            raise
        except Exception as error:
            raise ValidatorChainScanError("extrinsics_root_verification_failed") from error
        if verified is not True:
            raise ValidatorChainScanError("extrinsics_root_verification_failed")
        return body

    async def _required_runtime(
        self, identity: VerifiedFinalizedBlockIdentity
    ) -> PinnedRuntimeContext:
        try:
            runtime = await self._port.execution_runtime_at(identity)
        except Exception as error:
            raise ValidatorChainScanError("execution_runtime_fetch_failed") from error
        if not isinstance(runtime, PinnedRuntimeContext):
            raise ValidatorChainScanError("execution_runtime_missing")
        if runtime.snapshot != identity.parent_snapshot:
            raise ValidatorChainScanError("execution_runtime_snapshot_mismatch")
        if runtime.pin not in self._supported_runtime_pins:
            raise ValidatorChainScanError("execution_runtime_unsupported")
        return runtime

    async def _required_events(
        self,
        identity: VerifiedFinalizedBlockIdentity,
        runtime: PinnedRuntimeContext,
    ) -> RawFinalizedEventStorage:
        try:
            storage_key = runtime.storage_key("System", "Events")
            raw = await self._port.event_storage_at(identity, storage_key)
        except Exception as error:
            raise ValidatorChainScanError("event_storage_fetch_failed") from error
        if not isinstance(raw, RawFinalizedEventStorage):
            raise ValidatorChainScanError("event_storage_missing")
        if raw.block_hash != identity.snapshot.block_hash or raw.state_root != (
            identity.snapshot.state_root
        ):
            raise ValidatorChainScanError("event_storage_identity_mismatch")
        if raw.storage_key != storage_key:
            raise ValidatorChainScanError("event_storage_key_mismatch")
        if raw.value is not None and len(raw.value) > self._limits.maximum_event_storage_bytes:
            raise ValidatorChainScanError("event_storage_size_limit")
        if len(raw.proof) > self._limits.maximum_event_proof_nodes:
            raise ValidatorChainScanError("event_proof_node_count_limit")
        proof_bytes = 0
        for node in raw.proof:
            if len(node) > self._limits.maximum_event_proof_node_bytes:
                raise ValidatorChainScanError("event_proof_node_size_limit")
            proof_bytes += len(node)
            if proof_bytes > self._limits.maximum_event_proof_bytes:
                raise ValidatorChainScanError("event_proof_size_limit")
        if len(set(raw.proof)) != len(raw.proof):
            raise ValidatorChainScanError("event_proof_duplicate_node")
        try:
            StorageEvidence(
                snapshot=identity.snapshot,
                storage_key=storage_key,
                value=raw.value,
                proof=raw.proof,
                verifier=self._event_proof_verifier,
            )
        except (TypeError, ValueError) as error:
            raise ValidatorChainScanError("event_proof_verification_failed") from error
        return raw

    def _decode_extrinsic(
        self,
        runtime: PinnedRuntimeContext,
        raw: bytes,
        extrinsic_index: int,
    ) -> Mapping[str, Any]:
        try:
            decoded = runtime._runtime.decode_extrinsic(raw, True)
        except Exception as error:
            raise ValidatorChainScanError("extrinsic_decode_incomplete") from error
        mapping = _mapping(decoded, "extrinsic_decode_invalid")
        expected_hash = "0x" + hashlib.blake2b(raw, digest_size=32).hexdigest()
        if mapping.get("extrinsic_hash") != expected_hash:
            raise ValidatorChainScanError("extrinsic_hash_mismatch")
        length = mapping.get("extrinsic_length")
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValidatorChainScanError("extrinsic_length_invalid")
        if not _is_call(mapping.get("call")):
            raise ValidatorChainScanError("outer_call_missing")
        _uint(extrinsic_index, "extrinsic_index_invalid")
        return mapping

    def _decode_events(
        self,
        runtime: PinnedRuntimeContext,
        raw: bytes | None,
    ) -> tuple[Mapping[str, Any], ...]:
        try:
            decoded = runtime.decode_storage("System", "Events", raw)
        except Exception as error:
            raise ValidatorChainScanError("event_decode_incomplete") from error
        if isinstance(decoded, (str, bytes, bytearray)) or not isinstance(decoded, Sequence):
            raise ValidatorChainScanError("event_decode_invalid")
        events = tuple(_mapping(item, "event_decode_invalid") for item in decoded)
        # Every record must contain the full flattened shape emitted by the
        # pinned codec.  Unknown event names are fine; structurally partial
        # records are not.
        for item in events:
            if not isinstance(item.get("phase"), str):
                raise ValidatorChainScanError("event_phase_invalid")
            if not isinstance(item.get("module_id"), str) or not item["module_id"]:
                raise ValidatorChainScanError("event_module_invalid")
            if not isinstance(item.get("event_id"), str) or not item["event_id"]:
                raise ValidatorChainScanError("event_name_invalid")
            nested = _mapping(item.get("event"), "event_payload_invalid")
            nested_index = nested.get("event_index")
            if not isinstance(nested_index, str) or _EVENT_INDEX_RE.fullmatch(nested_index) is None:
                raise ValidatorChainScanError("event_index_invalid")
            _uint(item.get("event_index"), "event_pallet_index_invalid", maximum=_MAX_U8)
            if (
                nested.get("module_id") != item["module_id"]
                or nested.get("event_id") != item["event_id"]
            ):
                raise ValidatorChainScanError("event_payload_mismatch")
            if nested.get("attributes") != item.get("attributes"):
                raise ValidatorChainScanError("event_attribute_mismatch")
            if "topics" not in item:
                raise ValidatorChainScanError("event_topics_missing")
            if isinstance(item["topics"], (str, bytes, bytearray)) or not isinstance(
                item["topics"], Sequence
            ):
                raise ValidatorChainScanError("event_topics_invalid")
        return events

    def _build_call_tree(
        self,
        snapshot: FinalizedSnapshotRef,
        *,
        extrinsic_index: int,
        decoded_extrinsic: Mapping[str, Any],
        successful: bool,
    ) -> FinalizedCallRecord:
        signer = None
        if "address" in decoded_extrinsic:
            signer = _account(decoded_extrinsic["address"], "extrinsic_signer_invalid")
        budget = [0]
        return self._build_call_node(
            snapshot,
            extrinsic_index=extrinsic_index,
            decoded_call=_mapping(decoded_extrinsic["call"], "outer_call_invalid"),
            path=(),
            signer=signer,
            effective_origin=signer,
            successful=successful,
            budget=budget,
        )

    def _build_call_node(
        self,
        snapshot: FinalizedSnapshotRef,
        *,
        extrinsic_index: int,
        decoded_call: Mapping[str, Any],
        path: tuple[int, ...],
        signer: bytes | None,
        effective_origin: bytes | None,
        successful: bool,
        budget: list[int],
    ) -> FinalizedCallRecord:
        if len(path) > self._limits.maximum_call_depth:
            raise ValidatorChainScanError("call_depth_limit")
        budget[0] += 1
        if budget[0] > self._limits.maximum_call_nodes_per_extrinsic:
            raise ValidatorChainScanError("call_node_count_limit")
        module, function, call_hash, args = _decoded_call_parts(decoded_call)
        child_values = _wrapper_children(module, function, args)
        if len(child_values) > self._limits.maximum_children_per_call:
            raise ValidatorChainScanError("call_child_count_limit")
        child_origin = _wrapper_child_origin(
            module,
            function,
            args,
            effective_origin,
            maximum_signatories=self._limits.maximum_children_per_call,
        )
        children = tuple(
            self._build_call_node(
                snapshot,
                extrinsic_index=extrinsic_index,
                decoded_call=child,
                path=(*path, index),
                signer=None,
                effective_origin=(
                    child_origin[index] if isinstance(child_origin, tuple) else child_origin
                ),
                successful=successful,
                budget=budget,
            )
            for index, child in enumerate(child_values)
        )
        netuid, mechanism_id = _weight_call_target(module, function, args, self._limits)
        return FinalizedCallRecord(
            snapshot=snapshot,
            extrinsic_index=extrinsic_index,
            call_hash=call_hash,
            module=module,
            function=function,
            successful=successful,
            recursive_decode_complete=True,
            declared_child_count=len(children),
            call_path=path,
            signer_account_id32=signer,
            effective_origin_account_id32=effective_origin,
            netuid=netuid,
            mechanism_id=mechanism_id,
            children=children,
        )

    def _build_event_record(
        self,
        snapshot: FinalizedSnapshotRef,
        *,
        event_index: int,
        decoded_event: Mapping[str, Any],
        raw_event_bytes: bytes,
        calls: tuple[FinalizedCallRecord, ...],
    ) -> FinalizedEventRecord:
        module = decoded_event["module_id"]
        event = decoded_event["event_id"]
        phase = decoded_event["phase"]
        extrinsic_index: int | None = None
        if phase == "ApplyExtrinsic":
            extrinsic_index = _uint(
                decoded_event.get("extrinsic_idx"),
                "event_extrinsic_index_invalid",
            )
            if extrinsic_index >= len(calls):
                raise ValidatorChainScanError("event_extrinsic_index_missing")
        elif decoded_event.get("extrinsic_idx") is not None:
            raise ValidatorChainScanError("non_apply_event_has_extrinsic_index")

        event_account = None
        netuid = None
        mechanism_id = None
        if module == "SubtensorModule" and event in _WEIGHT_EVENTS:
            event_account, netuid, mechanism_id = _weight_event_target(
                event,
                decoded_event.get("attributes"),
                extrinsic_index=extrinsic_index,
                calls=calls,
                limits=self._limits,
            )
        return FinalizedEventRecord(
            snapshot=snapshot,
            event_index=event_index,
            payload_sha256=_event_payload_sha256(raw_event_bytes, event_index),
            module=module,
            event=event,
            extrinsic_index=extrinsic_index,
            account_id32=event_account,
            netuid=netuid,
            mechanism_id=mechanism_id,
        )


def _block_hash(value: Any, reason: str) -> str:
    if not isinstance(value, str) or _BLOCK_HASH_RE.fullmatch(value) is None:
        raise ValidatorChainScanError(reason)
    return value


def _sha256(value: Any, reason: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValidatorChainScanError(reason)
    return value


def _uint(value: Any, reason: str, *, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValidatorChainScanError(reason)
    return value


def _mapping(value: Any, reason: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValidatorChainScanError(reason)
    return value


def _account(value: Any, reason: str) -> bytes:
    try:
        return account_id32(value)
    except (TypeError, ValueError) as error:
        raise ValidatorChainScanError(reason) from error


def _is_call(value: Any) -> bool:
    return isinstance(value, Mapping) and all(
        key in value
        for key in ("call_index", "call_module", "call_function", "call_args", "call_hash")
    )


def _decoded_call_parts(
    decoded: Mapping[str, Any],
) -> tuple[str, str, str, Mapping[str, Any]]:
    module = decoded.get("call_module")
    function = decoded.get("call_function")
    call_hash = decoded.get("call_hash")
    call_index = decoded.get("call_index")
    if not isinstance(module, str) or not module:
        raise ValidatorChainScanError("call_module_invalid")
    if not isinstance(function, str) or not function:
        raise ValidatorChainScanError("call_function_invalid")
    _block_hash(call_hash, "call_hash_invalid")
    if not isinstance(call_index, str) or _CALL_INDEX_RE.fullmatch(call_index) is None:
        raise ValidatorChainScanError("call_index_invalid")
    raw_args = decoded.get("call_args")
    if isinstance(raw_args, (str, bytes, bytearray)) or not isinstance(raw_args, Sequence):
        raise ValidatorChainScanError("call_args_invalid")
    args: dict[str, Any] = {}
    for raw_arg in raw_args:
        arg = _mapping(raw_arg, "call_arg_invalid")
        name = arg.get("name")
        type_name = arg.get("type")
        if not isinstance(name, str) or not name or name in args:
            raise ValidatorChainScanError("call_arg_name_invalid")
        if not isinstance(type_name, str) or not type_name or "value" not in arg:
            raise ValidatorChainScanError("call_arg_shape_invalid")
        args[name] = arg["value"]
    return module, function, call_hash, args


def _commitment_call_binding(
    decoded_extrinsic: Mapping[str, Any],
    extrinsic_index: int,
) -> FinalizedCommitmentCallBinding | None:
    call = _mapping(decoded_extrinsic.get("call"), "outer_call_invalid")
    module, function, call_hash, args = _decoded_call_parts(call)
    if (module, function) != ("Commitments", "set_commitment"):
        return None
    if set(args) != {"netuid", "info"}:
        return None
    try:
        netuid = _uint(args["netuid"], "commitment_netuid_invalid", maximum=_MAX_U16)
        info = _mapping(args["info"], "commitment_info_invalid")
    except ValidatorChainScanError:
        return None
    if set(info) != {"fields"}:
        return None
    fields = info["fields"]
    if (
        isinstance(fields, (str, bytes, bytearray))
        or not isinstance(fields, Sequence)
        or len(fields) != 1
    ):
        return None
    try:
        field = _mapping(fields[0], "commitment_field_invalid")
    except ValidatorChainScanError:
        return None
    if set(field) != {"Sha256"}:
        return None
    raw_digest = field["Sha256"]
    if isinstance(raw_digest, bytes):
        digest = raw_digest
    elif isinstance(raw_digest, str) and re.fullmatch(r"0x[0-9a-f]{64}", raw_digest) is not None:
        digest = bytes.fromhex(raw_digest[2:])
    else:
        return None
    if len(digest) != 32:
        return None
    return FinalizedCommitmentCallBinding(
        extrinsic_index=extrinsic_index,
        call_hash=call_hash,
        netuid=netuid,
        field_sha256=digest.hex(),
    )


def _all_nested_calls(value: Any) -> tuple[Mapping[str, Any], ...]:
    found: list[Mapping[str, Any]] = []
    pending = [value]
    while pending:
        item = pending.pop()
        if _is_call(item):
            found.append(_mapping(item, "nested_call_invalid"))
            continue
        if isinstance(item, Mapping):
            pending.extend(reversed(tuple(item.values())))
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            pending.extend(reversed(tuple(item)))
    return tuple(found)


def _required_call(args: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = args.get(name)
    if not _is_call(value):
        raise ValidatorChainScanError("dispatch_wrapper_child_missing")
    return _mapping(value, "dispatch_wrapper_child_invalid")


def _required_call_list(args: Mapping[str, Any], name: str) -> tuple[Mapping[str, Any], ...]:
    value = args.get(name)
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValidatorChainScanError("dispatch_wrapper_children_missing")
    calls = tuple(_mapping(item, "dispatch_wrapper_child_invalid") for item in value)
    if not calls or any(not _is_call(item) for item in calls):
        raise ValidatorChainScanError("dispatch_wrapper_child_invalid")
    return calls


def _wrapper_children(
    module: str,
    function: str,
    args: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    wrapper = (module, function)
    discovered = tuple(call for value in args.values() for call in _all_nested_calls(value))
    if wrapper not in _KNOWN_WRAPPERS:
        if discovered:
            raise ValidatorChainScanError("unknown_dispatch_wrapper")
        return ()
    if wrapper in {
        ("Utility", "batch"),
        ("Utility", "batch_all"),
        ("Utility", "force_batch"),
    }:
        expected = _required_call_list(args, "calls")
    elif wrapper == ("Utility", "if_else"):
        expected = (_required_call(args, "main"), _required_call(args, "fallback"))
    else:
        expected = (_required_call(args, "call"),)
    if tuple(id(call) for call in discovered) != tuple(id(call) for call in expected):
        raise ValidatorChainScanError("dispatch_wrapper_children_incomplete")
    return expected


def _wrapper_child_origin(
    module: str,
    function: str,
    args: Mapping[str, Any],
    origin: bytes | None,
    *,
    maximum_signatories: int,
) -> bytes | tuple[bytes | None, ...] | None:
    wrapper = (module, function)
    if wrapper not in _KNOWN_WRAPPERS:
        return origin
    if wrapper in _SAME_ORIGIN_WRAPPERS:
        return origin
    if wrapper in _ROOT_ORIGIN_WRAPPERS:
        return None
    if wrapper in {("Proxy", "proxy"), ("Proxy", "proxy_announced")}:
        return _account(args.get("real"), "proxy_real_account_invalid")
    if wrapper == ("Sudo", "sudo_as"):
        return _account(args.get("who"), "sudo_as_account_invalid")
    if wrapper == ("Utility", "as_derivative"):
        index = _uint(args.get("index"), "derivative_index_invalid", maximum=_MAX_U16)
        if origin is None:
            return None
        return hashlib.blake2b(
            b"modlpy/utilisuba" + origin + index.to_bytes(2, "little"),
            digest_size=32,
        ).digest()
    if wrapper in {
        ("Utility", "dispatch_as"),
        ("Utility", "dispatch_as_fallible"),
    }:
        return _origin_caller(args.get("as_origin"))
    if wrapper in {
        ("Multisig", "as_multi"),
        ("Multisig", "as_multi_threshold_1"),
    }:
        if origin is None:
            return None
        raw_others = args.get("other_signatories")
        if isinstance(raw_others, (str, bytes, bytearray)) or not isinstance(raw_others, Sequence):
            raise ValidatorChainScanError("multisig_signatories_invalid")
        if not raw_others or len(raw_others) > maximum_signatories:
            raise ValidatorChainScanError("multisig_signatories_invalid")
        others = tuple(_account(value, "multisig_signatory_invalid") for value in raw_others)
        if origin in others or len(set(others)) != len(others):
            raise ValidatorChainScanError("multisig_signatories_invalid")
        threshold = (
            1
            if function == "as_multi_threshold_1"
            else _uint(args.get("threshold"), "multisig_threshold_invalid", maximum=_MAX_U16)
        )
        if threshold == 0 or threshold > len(others) + 1:
            raise ValidatorChainScanError("multisig_threshold_invalid")
        try:
            derived, _ordered = bittensor_core.multisig_account_id([origin, *others], threshold)
        except Exception as error:
            raise ValidatorChainScanError("multisig_account_derivation_failed") from error
        if not isinstance(derived, bytes) or len(derived) != 32:
            raise ValidatorChainScanError("multisig_account_derivation_failed")
        return derived
    raise ValidatorChainScanError("dispatch_wrapper_origin_unsupported")


def _origin_caller(value: Any) -> bytes | None:
    if isinstance(value, str):
        if value.lower() in {"root", "none"}:
            return None
        raise ValidatorChainScanError("dispatch_origin_invalid")
    mapping = _mapping(value, "dispatch_origin_invalid")
    if len(mapping) != 1:
        raise ValidatorChainScanError("dispatch_origin_invalid")
    name, payload = next(iter(mapping.items()))
    if name.lower() == "signed":
        return _account(payload, "dispatch_origin_account_invalid")
    if name.lower() == "system":
        return _origin_caller(payload)
    if name.lower() in {"root", "none"} and payload in (None, {}, (), []):
        return None
    raise ValidatorChainScanError("dispatch_origin_unsupported")


def _weight_call_target(
    module: str,
    function: str,
    args: Mapping[str, Any],
    limits: ScanLimits,
) -> tuple[int | None, int | None]:
    if module != "SubtensorModule" or function not in _WEIGHT_CALLS:
        return None, None
    if function in _BATCH_NETUID_CALLS:
        values = _netuid_list(args.get("netuids"), limits)
        # FinalizedCallRecord is a target-scan shape rather than a general
        # multi-target call schema.  Prefer SN78 when present so the downstream
        # Section 10 assertion cannot miss it; otherwise retain the first exact
        # decoded target.  The decoder has already validated the whole list.
        netuid = NETUID if NETUID in values else values[0]
    else:
        netuid = _uint(args.get("netuid"), "weight_call_netuid_invalid", maximum=_MAX_U16)
    mechanism = 0
    if function in _WEIGHT_CALLS_EXPLICIT_MECHANISM:
        mechanism = _uint(
            args.get("mecid"),
            "weight_call_mechanism_invalid",
            maximum=_MAX_U8,
        )
    return netuid, mechanism


def _netuid_list(value: Any, limits: ScanLimits) -> tuple[int, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValidatorChainScanError("weight_call_netuids_invalid")
    values = tuple(_uint(item, "weight_call_netuid_invalid", maximum=_MAX_U16) for item in value)
    if not values or len(values) > limits.maximum_batch_netuids or len(set(values)) != len(values):
        raise ValidatorChainScanError("weight_call_netuids_invalid")
    return values


def _extrinsic_statuses(
    events: Sequence[Mapping[str, Any]],
    extrinsic_count: int,
) -> tuple[bool, ...]:
    statuses: dict[int, bool] = {}
    for event in events:
        if event.get("module_id") != "System" or event.get("event_id") not in {
            "ExtrinsicSuccess",
            "ExtrinsicFailed",
        }:
            continue
        if event.get("phase") != "ApplyExtrinsic":
            raise ValidatorChainScanError("extrinsic_status_phase_invalid")
        index = _uint(event.get("extrinsic_idx"), "extrinsic_status_index_invalid")
        if index >= extrinsic_count or index in statuses:
            raise ValidatorChainScanError("extrinsic_status_coverage_invalid")
        statuses[index] = event["event_id"] == "ExtrinsicSuccess"
    if sorted(statuses) != list(range(extrinsic_count)):
        raise ValidatorChainScanError("extrinsic_status_coverage_invalid")
    return tuple(statuses[index] for index in range(extrinsic_count))


def _attributes_positional_or_named(
    attributes: Any,
) -> tuple[Mapping[str, Any] | None, tuple[Any, ...] | None]:
    if isinstance(attributes, Mapping):
        return _mapping(attributes, "weight_event_attributes_invalid"), None
    if isinstance(attributes, Sequence) and not isinstance(attributes, (str, bytes, bytearray)):
        return None, tuple(attributes)
    raise ValidatorChainScanError("weight_event_attributes_invalid")


def _field(
    named: Mapping[str, Any] | None,
    positional: tuple[Any, ...] | None,
    *,
    aliases: tuple[str, ...],
    index: int,
) -> Any:
    if named is not None:
        present = [alias for alias in aliases if alias in named]
        if len(present) != 1:
            raise ValidatorChainScanError("weight_event_field_missing")
        return named[present[0]]
    if positional is None or index >= len(positional):
        raise ValidatorChainScanError("weight_event_field_missing")
    return positional[index]


def _storage_index_target(value: Any) -> tuple[int, int]:
    index = _uint(value, "weight_event_storage_index_invalid", maximum=_MAX_U16)
    netuid = index % _GLOBAL_MAX_SUBNET_COUNT
    mechanism = index // _GLOBAL_MAX_SUBNET_COUNT
    if mechanism > 15:
        raise ValidatorChainScanError("weight_event_storage_index_invalid")
    return netuid, mechanism


def _plain_netuid(value: Any) -> tuple[int, int]:
    return _uint(value, "weight_event_netuid_invalid", maximum=_MAX_U16), 0


def _weight_event_target(
    event: str,
    attributes: Any,
    *,
    extrinsic_index: int | None,
    calls: tuple[FinalizedCallRecord, ...],
    limits: ScanLimits,
) -> tuple[bytes, int, int]:
    named, positional = _attributes_positional_or_named(attributes)
    account: bytes | None = None
    if event in {
        "CRV3WeightsCommitted",
        "TimelockedWeightsCommitted",
        "WeightsCommitted",
        "WeightsRevealed",
    }:
        account = _account(
            _field(named, positional, aliases=("who", "hotkey", "account"), index=0),
            "weight_event_account_invalid",
        )
        target = _storage_index_target(
            _field(
                named,
                positional,
                aliases=("netuid", "netuid_index", "network"),
                index=1,
            )
        )
    elif event == "TimelockedWeightsRevealed":
        target = _storage_index_target(
            _field(
                named,
                positional,
                aliases=("netuid", "netuid_index", "network"),
                index=0,
            )
        )
        account = _account(
            _field(named, positional, aliases=("who", "hotkey", "account"), index=1),
            "weight_event_account_invalid",
        )
    elif event == "CRV3WeightsRevealed":
        target = _plain_netuid(_field(named, positional, aliases=("netuid", "network"), index=0))
        account = _account(
            _field(named, positional, aliases=("who", "hotkey", "account"), index=1),
            "weight_event_account_invalid",
        )
    elif event == "WeightsBatchRevealed":
        account = _account(
            _field(named, positional, aliases=("who", "hotkey", "account"), index=0),
            "weight_event_account_invalid",
        )
        target = _plain_netuid(_field(named, positional, aliases=("netuid", "network"), index=1))
    elif event == "BatchWeightsCompleted":
        raw_netuids = _field(
            named,
            positional,
            aliases=("netuids", "networks"),
            index=0,
        )
        values = _netuid_list(raw_netuids, limits)
        target = (NETUID if NETUID in values else values[0], 0)
        account = _account(
            _field(named, positional, aliases=("who", "hotkey", "account"), index=1),
            "weight_event_account_invalid",
        )
    elif event == "WeightsSet":
        target = _storage_index_target(
            _field(
                named,
                positional,
                aliases=("netuid", "netuid_index", "network"),
                index=0,
            )
        )
        account = _unique_weight_origin(calls, extrinsic_index)
    else:  # pragma: no cover - guarded by the closed event set
        raise ValidatorChainScanError("weight_event_unsupported")
    if account is None:
        raise ValidatorChainScanError("weight_event_account_unattributed")
    return account, target[0], target[1]


def _unique_weight_origin(
    calls: tuple[FinalizedCallRecord, ...],
    extrinsic_index: int | None,
) -> bytes:
    if extrinsic_index is None:
        raise ValidatorChainScanError("weight_event_extrinsic_missing")
    root = calls[extrinsic_index]
    origins: set[bytes] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if node.module == "SubtensorModule" and node.function in _WEIGHT_CALLS:
            if node.effective_origin_account_id32 is None:
                raise ValidatorChainScanError("weight_event_account_unattributed")
            origins.add(node.effective_origin_account_id32)
        pending.extend(node.children)
    if len(origins) != 1:
        raise ValidatorChainScanError("weight_event_account_unattributed")
    return next(iter(origins))


def _assert_extended_weight_events_absent(
    blocks: Sequence[FinalizedBlockRecord],
    *,
    validator_account: bytes,
    netuid: int,
    mechanism_id: int,
) -> None:
    # ``WeightsBatchRevealed`` is present in the publication runtime but the
    # legacy chain-evidence assertion predates it.  Check it here; the parent
    # module can later expand its closed event set without weakening this scan.
    for block in blocks:
        for event in block.events:
            if event.module != "SubtensorModule" or event.event != "WeightsBatchRevealed":
                continue
            if (
                event.account_id32 == validator_account
                and event.netuid == netuid
                and event.mechanism_id == mechanism_id
            ):
                raise ValidatorChainScanError("shadow_interval_weight_event")


__all__ = [
    "CapturedFinalizedBlockInterval",
    "DecodedNoWeightInterval",
    "ExtrinsicsRootVerifier",
    "FinalityAttestationReplayBinding",
    "FinalizedBlockScanEvidence",
    "FinalizedBlockScanPort",
    "FinalizedBlockScanner",
    "FinalizedCommitmentCallBinding",
    "RawFinalizedBlockBody",
    "RawFinalizedEventStorage",
    "ScanLimits",
    "ValidatorChainScanError",
    "VerifiedFinalizedBlockIdentity",
    "finalized_block_body_sha256",
]
