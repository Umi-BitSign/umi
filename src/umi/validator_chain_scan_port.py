"""Production read-only collection port for finalized block scans.

The owned smoldot observer chooses finality.  This adapter only fetches exact
objects by the already verified block hashes and delegates every state claim to
``FinalizedProofCollector``.  It has no wallet, call-composition, submission, or
broadcast capability.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .validator_chain import (
    FinalizedProofCollector,
    FinalizedRuntimePin,
    PinnedRuntimeContext,
    RawJsonRpc,
)
from .validator_chain_scan import (
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    ScanLimits,
    VerifiedFinalizedBlockIdentity,
    finalized_block_body_sha256,
)

_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_BYTES_RE = re.compile(r"^0x(?:[0-9a-f]{2})*$")
_MAX_BLOCK_NUMBER = (1 << 64) - 1


class LiveFinalizedBlockScanPortError(RuntimeError):
    """A stable fail-closed collection error at the raw RPC boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class LiveFinalizedBlockScanPort:
    """Fetch proof-bearing scan inputs at verifier-attested block identities."""

    def __init__(
        self,
        *,
        rpc: RawJsonRpc,
        proofs: FinalizedProofCollector,
        runtime_pin: FinalizedRuntimePin,
        limits: ScanLimits | None = None,
    ) -> None:
        if not callable(getattr(rpc, "request", None)):
            raise TypeError("rpc must implement RawJsonRpc")
        if not isinstance(proofs, FinalizedProofCollector):
            raise TypeError("proofs must be a FinalizedProofCollector")
        if not isinstance(runtime_pin, FinalizedRuntimePin):
            raise TypeError("runtime_pin must be a FinalizedRuntimePin")
        if limits is not None and not isinstance(limits, ScanLimits):
            raise TypeError("limits must be ScanLimits or None")
        self._rpc = rpc
        self._proofs = proofs
        self._runtime_pin = runtime_pin
        self._limits = limits or ScanLimits()

    async def block_body_at(
        self,
        identity: VerifiedFinalizedBlockIdentity,
    ) -> RawFinalizedBlockBody | None:
        """Fetch one exact ordered body and bind its header to ``identity``."""

        _identity(identity)
        try:
            response = await self._rpc.request(
                "chain_getBlock",
                (identity.snapshot.block_hash,),
            )
        except Exception as error:
            raise LiveFinalizedBlockScanPortError("block_body_rpc_failed") from error
        if response is None:
            return None
        outer = _mapping(response, "block_response_invalid")
        if set(outer).difference({"block", "justifications"}):
            raise LiveFinalizedBlockScanPortError("block_response_invalid")
        block = _mapping(outer.get("block"), "block_response_invalid")
        if set(block) != {"header", "extrinsics"}:
            raise LiveFinalizedBlockScanPortError("block_response_invalid")
        header = _mapping(block.get("header"), "block_header_invalid")
        _require_header_identity(header, identity)

        raw_extrinsics = block.get("extrinsics")
        if (
            isinstance(raw_extrinsics, (str, bytes, bytearray))
            or not isinstance(raw_extrinsics, Sequence)
            or len(raw_extrinsics) > self._limits.maximum_extrinsics_per_block
        ):
            raise LiveFinalizedBlockScanPortError("block_extrinsics_invalid")
        extrinsics: list[bytes] = []
        total_bytes = 0
        for raw in raw_extrinsics:
            value = _hex_bytes(raw, "block_extrinsic_invalid", allow_empty=False)
            if len(value) > self._limits.maximum_extrinsic_bytes:
                raise LiveFinalizedBlockScanPortError("block_extrinsic_size_limit")
            total_bytes += len(value)
            if total_bytes > self._limits.maximum_block_body_bytes:
                raise LiveFinalizedBlockScanPortError("block_body_size_limit")
            extrinsics.append(value)
        exact = tuple(extrinsics)
        return RawFinalizedBlockBody(
            block_hash=identity.snapshot.block_hash,
            parent_hash=identity.snapshot.parent_hash,
            state_root=identity.snapshot.state_root,
            extrinsics_root=identity.extrinsics_root,
            extrinsics=exact,
            body_sha256=finalized_block_body_sha256(exact),
        )

    async def event_storage_at(
        self,
        identity: VerifiedFinalizedBlockIdentity,
        storage_key: bytes,
    ) -> RawFinalizedEventStorage | None:
        """Fetch and authenticate exact ``System.Events`` bytes at the child state."""

        _identity(identity)
        if not isinstance(storage_key, bytes) or not storage_key:
            raise ValueError("storage_key must be non-empty exact bytes")
        try:
            evidence = await self._proofs.storage_evidence(identity.snapshot, storage_key)
        except Exception as error:
            raise LiveFinalizedBlockScanPortError("event_storage_proof_failed") from error
        return RawFinalizedEventStorage(
            block_hash=identity.snapshot.block_hash,
            state_root=identity.snapshot.state_root,
            storage_key=evidence.storage_key,
            value=evidence.value,
            proof=evidence.proof,
            value_sha256=hashlib.sha256(evidence.value or b"").hexdigest(),
        )

    async def execution_runtime_at(
        self,
        identity: VerifiedFinalizedBlockIdentity,
    ) -> PinnedRuntimeContext | None:
        """Build the parent-state runtime that executed the finalized child block."""

        _identity(identity)
        try:
            return await self._proofs.pinned_runtime(
                identity.parent_snapshot,
                self._runtime_pin,
            )
        except Exception as error:
            raise LiveFinalizedBlockScanPortError("execution_runtime_proof_failed") from error


def _identity(value: object) -> VerifiedFinalizedBlockIdentity:
    if not isinstance(value, VerifiedFinalizedBlockIdentity):
        raise TypeError("identity must be a VerifiedFinalizedBlockIdentity")
    return value


def _mapping(value: Any, reason_code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LiveFinalizedBlockScanPortError(reason_code)
    return value


def _block_hash(value: Any, reason_code: str) -> str:
    if not isinstance(value, str) or _BLOCK_HASH_RE.fullmatch(value) is None:
        raise LiveFinalizedBlockScanPortError(reason_code)
    return value


def _block_number(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise LiveFinalizedBlockScanPortError("block_header_number_invalid")
    try:
        result = int(value, 16)
    except ValueError as error:
        raise LiveFinalizedBlockScanPortError("block_header_number_invalid") from error
    if result < 0 or result > _MAX_BLOCK_NUMBER:
        raise LiveFinalizedBlockScanPortError("block_header_number_invalid")
    return result


def _hex_bytes(value: Any, reason_code: str, *, allow_empty: bool) -> bytes:
    if not isinstance(value, str) or _HEX_BYTES_RE.fullmatch(value) is None:
        raise LiveFinalizedBlockScanPortError(reason_code)
    result = bytes.fromhex(value[2:])
    if not result and not allow_empty:
        raise LiveFinalizedBlockScanPortError(reason_code)
    return result


def _require_header_identity(
    header: Mapping[str, Any],
    identity: VerifiedFinalizedBlockIdentity,
) -> None:
    required = {"number", "parentHash", "stateRoot", "extrinsicsRoot", "digest"}
    if set(header) != required:
        raise LiveFinalizedBlockScanPortError("block_header_invalid")
    if _block_number(header.get("number")) != identity.snapshot.block_number:
        raise LiveFinalizedBlockScanPortError("block_header_number_mismatch")
    expected = (
        ("parentHash", identity.snapshot.parent_hash, "block_header_parent_mismatch"),
        ("stateRoot", identity.snapshot.state_root, "block_header_state_root_mismatch"),
        ("extrinsicsRoot", identity.extrinsics_root, "block_header_extrinsics_root_mismatch"),
    )
    for field, value, reason_code in expected:
        if _block_hash(header.get(field), reason_code) != value:
            raise LiveFinalizedBlockScanPortError(reason_code)
    digest = _mapping(header.get("digest"), "block_header_digest_invalid")
    logs = digest.get("logs")
    if (
        set(digest) != {"logs"}
        or isinstance(logs, (str, bytes, bytearray))
        or not isinstance(logs, Sequence)
    ):
        raise LiveFinalizedBlockScanPortError("block_header_digest_invalid")
    for log in logs:
        _hex_bytes(log, "block_header_digest_invalid", allow_empty=False)


__all__ = [
    "LiveFinalizedBlockScanPort",
    "LiveFinalizedBlockScanPortError",
]
