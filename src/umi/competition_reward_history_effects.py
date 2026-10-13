"""Shared pure control history effects; callers establish header authority."""

from __future__ import annotations

from dataclasses import dataclass

from .chain_evidence import FinalizedBlockRecord, FinalizedSnapshotRef
from .encoding import account_id32
from .finalized_ancestry import MAXIMUM_HEADER_BYTES
from .grandpa_finality import _decode_header
from .validator_chain_scan import FinalizedCommitmentCallBinding, VerifiedFinalizedBlockIdentity

MAX_WRITE_EVIDENCE_BYTES = 256 * 1024**2


@dataclass(frozen=True, slots=True)
class ControlWrite:
    extrinsic_index: int
    decision_sha256: str


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


def control_block_identity(
    snapshot: FinalizedSnapshotRef,
    encoded: str,
    parent_encoded: str,
    *,
    slot_header: str,
    finality_sha256: str,
    evidence_sha256: str,
) -> VerifiedFinalizedBlockIdentity:
    """Derive the parent identity only from an already authenticated child."""
    if encoded != slot_header:
        raise ValueError("control block differs from its independently proved slot")
    header = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
    parent = _decode_header(parent_encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
    if (parent["number"], parent["hash"]) != (
        snapshot.block_number - 1,
        snapshot.parent_hash,
    ):
        raise ValueError("control block parent differs from authenticated child")
    parent_ref = FinalizedSnapshotRef(
        parent["number"], parent["hash"], parent["parent_hash"], parent["state_root"]
    )
    return VerifiedFinalizedBlockIdentity(
        snapshot,
        parent_ref,
        header["extrinsics_root"],
        finality_sha256,
        evidence_sha256,
    )


def checked_control_effects(
    snapshot,
    hotkey,
    control_sha256,
    committed_at_block,
    block,
    bindings,
):
    if block.snapshot != snapshot:
        raise ValueError("control block differs from proved slot")
    writes, unresolved = _select_writes(block, bindings, hotkey)
    height = snapshot.block_number
    if not unresolved and (
        (writes and (committed_at_block, control_sha256) != (height, writes[-1].decision_sha256))
        or (not writes and committed_at_block == height)
    ):
        raise ValueError("control block writes differ from proved post-state")
    return writes, unresolved
