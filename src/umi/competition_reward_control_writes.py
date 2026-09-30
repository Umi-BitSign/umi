"""Authenticate complete historical blocks before following control writes.

The mutable commitment slot does not preserve intervening revocations. This
reader pairs a native historical slot proof with the complete ordered body,
parent execution runtime and child-state event proof. It grants no reward or
transaction authority. The caller still needs a complete history and a fresh
current control observation before execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .chain_evidence import FinalizedBlockRecord, FinalizedSnapshotRef
from .competition_chain_state import _runtime_execution_evidence
from .competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .encoding import account_id32
from .finalized_ancestry import MAXIMUM_HEADER_BYTES, encode_rpc_header
from .grandpa_finality import _decode_header
from .open_competition import digest
from .protocol import canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext
from .validator_chain import FinalizedProofCollector, ProofCollectionLimits
from .validator_chain_scan import (
    FinalizedBlockScanner,
    FinalizedCommitmentCallBinding,
    ScanLimits,
    VerifiedFinalizedBlockIdentity,
)
from .validator_chain_scan_port import LiveFinalizedBlockScanPort

_ISSUER = object()
MAX_WRITE_EVIDENCE_BYTES = 256 * 1024**2


@dataclass(frozen=True, slots=True)
class ControlWrite:
    extrinsic_index: int
    decision_sha256: str


@dataclass(frozen=True, slots=True)
class OwnedRewardControlWrites:
    slot: OwnedHistoricalRewardControl
    writes: tuple[ControlWrite, ...]
    unresolved_extrinsics: tuple[int, ...]
    evidence: bytes = field(repr=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: OwnedRewardControlWrites) -> str:
    return digest(
        {
            "slot": value.slot.evidence_sha256,
            "config": value.slot.chain_config_sha256,
            "writes": [[w.extrinsic_index, w.decision_sha256] for w in value.writes],
            "unresolved": list(value.unresolved_extrinsics),
            "evidence": hashlib.sha256(value.evidence).hexdigest(),
        }
    )


def validate_control_writes(
    value: OwnedRewardControlWrites,
    *,
    expected_control_hotkey: str,
    expected_chain_config_sha256: str,
) -> None:
    if (
        type(value) is not OwnedRewardControlWrites
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
    ):
        raise ValueError("control writes lack the selected native block proof")
    validate_historical_reward_control(
        value.slot,
        expected_control_hotkey=expected_control_hotkey,
        expected_chain_config_sha256=expected_chain_config_sha256,
    )


def _select_writes(
    block: FinalizedBlockRecord,
    bindings: tuple[FinalizedCommitmentCallBinding, ...],
    hotkey: str,
) -> tuple[tuple[ControlWrite, ...], tuple[int, ...]]:
    """Outer success never proves which child of a wrapper actually ran."""
    account = account_id32(hotkey)
    arguments = {b.extrinsic_index: b for b in bindings}
    writes, unresolved = [], set()
    for outer in block.calls:
        pending = [outer]
        while pending:
            call = pending.pop()
            pending.extend(call.children)
            if call.module != "Commitments" or call.effective_origin_account_id32 not in (
                None,
                account,
            ):
                continue
            if call.call_path or call.effective_origin_account_id32 is None:
                unresolved.add(outer.extrinsic_index)
                continue
            if not outer.successful:
                continue
            binding = arguments.get(outer.extrinsic_index)
            if binding is None or binding.call_hash != outer.call_hash:
                unresolved.add(outer.extrinsic_index)
            elif binding.netuid == 78:
                writes.append(ControlWrite(outer.extrinsic_index, binding.field_sha256))
    return tuple(writes), tuple(sorted(unresolved))


class _BlockPort(LiveFinalizedBlockScanPort):
    def __init__(self, provider, runtime):
        # Block events are much larger than account/weight values. Keep their
        # collector separate, sharing the owned RPC lifecycle and verifier.
        limits = ScanLimits()
        proofs = FinalizedProofCollector(
            provider._proofs._rpc,
            finality=provider._proofs._finality,
            verifier=provider._proofs._verifier,
            limits=ProofCollectionLimits(
                maximum_storage_keys=1,
                maximum_storage_value_bytes=limits.maximum_event_storage_bytes,
                maximum_storage_values_bytes=limits.maximum_event_storage_bytes,
                maximum_proof_nodes=limits.maximum_event_proof_nodes,
                maximum_proof_node_bytes=limits.maximum_event_proof_node_bytes,
                maximum_proof_bytes=limits.maximum_event_proof_bytes,
            ),
        )
        super().__init__(
            rpc=provider._registration_rpc,
            proofs=proofs,
            runtime_pin=runtime.pin,
            limits=limits,
        )
        self.runtime = runtime
        self.body = self.events = None

    async def execution_runtime_at(self, identity):
        if self.runtime.snapshot != identity.parent_snapshot:
            raise ValueError("control block execution runtime is not its parent")
        return self.runtime

    async def block_body_at(self, identity):
        self.body = await super().block_body_at(identity)
        return self.body

    async def event_storage_at(self, identity, storage_key):
        self.events = await super().event_storage_at(identity, storage_key)
        return self.events


def _control_block_identity(
    provider: HistoricalRewardControlProvider,
    slot: OwnedHistoricalRewardControl,
    encoded: str,
    parent_encoded: str,
) -> VerifiedFinalizedBlockIdentity:
    validate_historical_reward_control(
        slot,
        expected_control_hotkey=slot.control_hotkey,
        expected_chain_config_sha256=digest(provider.config),
    )
    if encoded != json.loads(slot.evidence)["finality"]["block"]["scale_header"]:
        raise ValueError("control block differs from its independently proved slot")
    header = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
    parent = _decode_header(parent_encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
    if (parent["number"], parent["hash"]) != (
        slot.snapshot.block_number - 1,
        slot.snapshot.parent_hash,
    ):
        raise ValueError("control block parent differs from authenticated child")
    parent_ref = FinalizedSnapshotRef(
        parent["number"], parent["hash"], parent["parent_hash"], parent["state_root"]
    )
    return VerifiedFinalizedBlockIdentity(
        slot.snapshot,
        parent_ref,
        header["extrinsics_root"],
        provider.config.finality_pin.release_sha256_by_target[provider.config.target_triple],
        slot.evidence_sha256,
    )


def _proved_writes(
    slot: OwnedHistoricalRewardControl,
    block: FinalizedBlockRecord,
    bindings: tuple[FinalizedCommitmentCallBinding, ...],
    evidence: bytes,
) -> OwnedRewardControlWrites:
    if block.snapshot != slot.snapshot:
        raise ValueError("control block differs from proved slot")
    writes, unresolved = _select_writes(block, bindings, slot.control_hotkey)
    height = slot.snapshot.block_number
    if not unresolved and (
        (
            writes
            and (slot.committed_at_block, slot.control_sha256)
            != (height, writes[-1].decision_sha256)
        )
        or (not writes and slot.committed_at_block == height)
    ):
        raise ValueError("control block writes differ from proved post-state")
    if type(evidence) is not bytes or not 0 < len(evidence) <= MAX_WRITE_EVIDENCE_BYTES:
        raise ValueError("control block evidence exceeds its byte bound")
    result = OwnedRewardControlWrites(slot, writes, unresolved, evidence, _issuer=_ISSUER)
    object.__setattr__(result, "_binding", _binding(result))
    return result


async def capture_control_writes(
    provider: HistoricalRewardControlProvider, hotkey: str, height: int
) -> OwnedRewardControlWrites:
    if not isinstance(provider, HistoricalRewardControlProvider):
        raise TypeError("control writes require the historical native provider")
    slot = await provider.capture_control_at(hotkey, height)
    async with provider._lock:
        if provider._closed or not provider._owned or provider._registration_rpc is None:
            raise ValueError("control write provider is not running")
        validate_historical_reward_control(
            slot,
            expected_control_hotkey=hotkey,
            expected_chain_config_sha256=digest(provider.config),
        )
        raw_slot = json.loads(slot.evidence)
        encoded = raw_slot["finality"]["block"]["scale_header"]
        # Authenticate against the current owned descendant again after the
        # slot capture released its collection lock. Ancestry is not an
        # original observer attestation, and the evidence says so explicitly.
        await provider._resolve_control_header(slot.snapshot, encoded)
        parent_encoded = encode_rpc_header(
            await provider._registration_rpc.request(
                "chain_getHeader", (slot.snapshot.parent_hash,)
            )
        )
        identity = _control_block_identity(provider, slot, encoded, parent_encoded)
        parent_ref = identity.parent_snapshot
        runtime = await provider._runtime_context(parent_ref)
        provider._validate_runtime_context(runtime, parent_ref)
        if runtime.storage_codec_mode not in {"exact_runtime", "executed_runtime/1"}:
            raise ValueError("control calls require the actual parent execution runtime")
        port = _BlockPort(provider, runtime)
        verifier = provider._proofs._verifier
        scanner = FinalizedBlockScanner(
            port,
            extrinsics_root_verifier=verifier.verify_extrinsics_root,
            event_proof_verifier=verifier,
            supported_runtime_pins=(runtime.pin,),
        )
        block, bindings = await scanner.decode_block_commitments(identity)
        evidence = canonical_json_bytes(
            {
                "schema": "umi-historical-control-writes/1",
                "finality_provenance": "owned_finalized_ancestry",
                "slot_evidence_sha256": slot.evidence_sha256,
                "header": encoded,
                "parent_header": parent_encoded,
                "extrinsics": [raw.hex() for raw in port.body.extrinsics],
                "runtime_metadata": runtime.metadata_bytes.hex(),
                "runtime_version": runtime.runtime_version_bytes.hex(),
                "runtime_execution": _runtime_execution_evidence(runtime)
                if isinstance(runtime, ExecutedRuntimeContext)
                else None,
                "events": {
                    "key": port.events.storage_key.hex(),
                    "value": None if port.events.value is None else port.events.value.hex(),
                    "proof": [raw.hex() for raw in port.events.proof],
                },
                "chain_submission_authorized": False,
            }
        )
        return _proved_writes(slot, block, bindings, evidence)
