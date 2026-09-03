"""Finalized-header and storage-proof collection for the live validator.

The high-level Bittensor SDK decodes storage values, but version 11.1.0 does
not expose storage proofs through its public client contract.  This module
keeps the required raw JSON-RPC escape hatch behind a narrow interface.  It
does not trust a node's decoded value: a caller-supplied trie verifier must
verify the claim against the finalized header's state root before
:class:`StorageEvidence` can be returned.

This module is read-only.  It has no wallet, signing, call composition, or
submission surface.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from typing import Any, Protocol
from urllib.parse import urlsplit

import bittensor_core
from websockets.asyncio.client import connect as websocket_connect
from websockets.exceptions import PayloadTooBig

from .chain_evidence import FinalizedSnapshotRef, StorageEvidence, StorageProofVerifier
from .protocol import canonical_json_bytes

_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_RE = re.compile(r"^0x(?:[0-9a-f]{2})*$")
_MAX_BLOCK_NUMBER = (1 << 64) - 1
_MIB = 1024 * 1024
_MAXIMUM_RPC_REQUEST_BYTES = 2 * _MIB
_MAXIMUM_RPC_RESPONSE_BYTES = 136 * _MIB
_RPC_RESPONSE_LIMITS = {
    "chain_getBlock": 130 * _MIB,
    "chain_getBlockHash": _MIB,
    "chain_getHeader": _MIB,
    "state_getMetadata": 33 * _MIB,
    "state_getReadProof": 65 * _MIB,
    "state_getRuntimeVersion": _MIB,
    "state_getStorageAt": 129 * _MIB,
}


class ValidatorChainError(RuntimeError):
    """A stable, non-sensitive failure while collecting finalized evidence."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class RawJsonRpc(Protocol):
    """The only raw-node capability required by the proof collector."""

    async def request(self, method: str, params: Sequence[Any]) -> Any:
        """Return the JSON-RPC result for ``method`` and ``params``."""


class VerifiedFinalizedSnapshotPort(Protocol):
    """Owned-finality source for the state root used by proof collection."""

    async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
        """Return the newest independently verified finalized snapshot."""


class MultiStorageProofVerifier(Protocol):
    """Verify several storage claims carried by one Substrate multiproof."""

    def __call__(
        self,
        *,
        state_root: bytes,
        items: tuple[tuple[bytes, bytes | None], ...],
        proof: tuple[bytes, ...],
    ) -> bool: ...


class BittensorRawJsonRpc:
    """Issue bounded, read-only JSON-RPC requests to a Bittensor endpoint.

    Bittensor 11.1.0 configures its internal WebSocket with a four-gibibyte
    message ceiling.  Proof validation happens after that client receives and
    decodes JSON, so using its private raw-RPC method would expose the operator to
    an avoidable allocation attack.  This adapter opens one UMI-owned connection
    per request, disables ambient proxies, and applies a method-specific
    decompressed-message ceiling before JSON parsing.  Finney's public endpoint
    requires per-message deflate negotiation; ``websockets`` applies
    ``max_size`` to the reconstructed message before returning it to this code.

    The accepted method set is exactly the read-only surface used by
    :class:`FinalizedProofCollector` and the finalized block scanner.  It has no
    wallet, signing, composition, or submission capability.
    """

    def __init__(
        self,
        client: Any,
        *,
        connect_factory: Any = websocket_connect,
        open_timeout_seconds: float = 15.0,
        request_timeout_seconds: float = 60.0,
    ) -> None:
        endpoint = getattr(client, "endpoint", None)
        if not isinstance(endpoint, str):
            raise ValidatorChainError("proof_rpc_endpoint_unavailable")
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "wss"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValidatorChainError("proof_rpc_endpoint_invalid")
        if not callable(connect_factory):
            raise TypeError("connect_factory must be callable")
        for name, value in (
            ("open_timeout_seconds", open_timeout_seconds),
            ("request_timeout_seconds", request_timeout_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be a positive number")
        self._endpoint = endpoint
        self._connect_factory = connect_factory
        self._open_timeout_seconds = float(open_timeout_seconds)
        self._request_timeout_seconds = float(request_timeout_seconds)

    async def request(self, method: str, params: Sequence[Any]) -> Any:
        if method not in _RPC_RESPONSE_LIMITS:
            raise ValidatorChainError("proof_rpc_method_forbidden")
        if isinstance(params, (str, bytes, bytearray)) or not isinstance(params, Sequence):
            raise TypeError("JSON-RPC params must be a sequence")
        try:
            request_bytes = canonical_json_bytes(
                {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": list(params),
                }
            )
        except Exception as error:
            raise ValidatorChainError("proof_rpc_request_invalid") from error
        if len(request_bytes) > _MAXIMUM_RPC_REQUEST_BYTES:
            raise ValidatorChainError("proof_rpc_request_limit")

        response_limit = _RPC_RESPONSE_LIMITS[method]
        if response_limit > _MAXIMUM_RPC_RESPONSE_BYTES:
            raise AssertionError("RPC response ceiling exceeds the global hard limit")
        try:
            connection = self._connect_factory(
                self._endpoint,
                compression="deflate",
                proxy=None,
                open_timeout=self._open_timeout_seconds,
                close_timeout=5.0,
                max_size=response_limit,
                max_queue=1,
                write_limit=64 * 1024,
            )
            async with connection as websocket:
                await asyncio.wait_for(
                    websocket.send(request_bytes.decode("ascii")),
                    timeout=self._request_timeout_seconds,
                )
                raw_response = await asyncio.wait_for(
                    websocket.recv(),
                    timeout=self._request_timeout_seconds,
                )
            if not isinstance(raw_response, str) or not raw_response.isascii():
                raise ValidatorChainError("proof_rpc_response_invalid")
            if len(raw_response) > response_limit:
                raise ValidatorChainError("proof_rpc_response_limit")
            try:
                response = json.loads(
                    raw_response,
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_reject_json_constant,
                )
            except (TypeError, ValueError) as error:
                raise ValidatorChainError("proof_rpc_response_invalid") from error
            if not isinstance(response, Mapping):
                raise ValidatorChainError("proof_rpc_response_invalid")
            if response.get("jsonrpc") != "2.0" or response.get("id") != 1:
                raise ValidatorChainError("proof_rpc_response_invalid")
            if set(response) == {"jsonrpc", "id", "error"}:
                raise ValidatorChainError("proof_rpc_error")
            if set(response) != {"jsonrpc", "id", "result"}:
                raise ValidatorChainError("proof_rpc_response_invalid")
            return response["result"]
        except ValidatorChainError:
            raise
        except PayloadTooBig as error:
            raise ValidatorChainError("proof_rpc_response_limit") from error
        except Exception as error:
            raise ValidatorChainError("proof_rpc_failed") from error


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant: {value}")


@dataclass(frozen=True, slots=True)
class ProofCollectionLimits:
    """Local denial-of-service bounds for one storage proof."""

    maximum_storage_key_bytes: int = 512
    maximum_storage_keys: int = 512
    maximum_storage_value_bytes: int = 16 * 1024 * 1024
    maximum_storage_values_bytes: int = 64 * 1024 * 1024
    maximum_runtime_metadata_bytes: int = 16 * 1024 * 1024
    maximum_proof_nodes: int = 4_096
    maximum_proof_node_bytes: int = 2 * 1024 * 1024
    maximum_proof_bytes: int = 32 * 1024 * 1024

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{item.name} must be a positive integer")
        if self.maximum_proof_node_bytes > self.maximum_proof_bytes:
            raise ValueError("one proof node cannot exceed the complete proof-byte ceiling")
        if self.maximum_storage_value_bytes > self.maximum_storage_values_bytes:
            raise ValueError(
                "one storage value cannot exceed the complete storage-value byte ceiling"
            )


def _mapping(value: Any, reason_code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidatorChainError(reason_code)
    return value


def _hash(value: Any, reason_code: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidatorChainError(reason_code)
    return value


def _block_number(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValidatorChainError("finalized_header_number_invalid")
    try:
        number = int(value, 16)
    except ValueError as error:
        raise ValidatorChainError("finalized_header_number_invalid") from error
    if number < 0 or number > _MAX_BLOCK_NUMBER:
        raise ValidatorChainError("finalized_header_number_invalid")
    return number


def _bytes_from_hex(value: Any, reason_code: str) -> bytes:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        raise ValidatorChainError(reason_code)
    return bytes.fromhex(value[2:])


def _strict_uint(value: Any, reason_code: str, *, maximum: int = _MAX_BLOCK_NUMBER) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise ValidatorChainError(reason_code)
    return value


@dataclass(frozen=True, slots=True)
class FinalizedRuntimePin:
    """Runtime metadata identity accepted for storage key construction and decode."""

    metadata_sha256: str
    spec_version: int
    transaction_version: int
    state_version: int = 1
    ss58_prefix: int = 42

    def __post_init__(self) -> None:
        if (
            not isinstance(self.metadata_sha256, str)
            or _SHA256_RE.fullmatch(self.metadata_sha256) is None
        ):
            raise ValueError("metadata_sha256 must be lowercase SHA-256 hexadecimal")
        for item in fields(self):
            if item.name == "metadata_sha256":
                continue
            value = getattr(self, item.name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{item.name} must be a non-negative integer")
        if self.spec_version == 0 or self.transaction_version == 0:
            raise ValueError("runtime versions must be positive")
        if self.state_version != 1:
            raise ValueError("UMI proof verification requires Substrate state version 1")
        if self.ss58_prefix != 42:
            raise ValueError("UMI version 0.1 requires the Bittensor SS58 prefix")


@dataclass(frozen=True, slots=True)
class PinnedRuntimeContext:
    """Content-pinned runtime codec bound to one finalized snapshot."""

    snapshot: FinalizedSnapshotRef
    pin: FinalizedRuntimePin
    metadata_bytes: bytes
    runtime_version_bytes: bytes
    _runtime: Any

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        if not isinstance(self.pin, FinalizedRuntimePin):
            raise TypeError("pin must be a FinalizedRuntimePin")
        if not isinstance(self.metadata_bytes, bytes) or not self.metadata_bytes:
            raise ValueError("metadata_bytes must be non-empty bytes")
        if not isinstance(self.runtime_version_bytes, bytes) or not self.runtime_version_bytes:
            raise ValueError("runtime_version_bytes must be non-empty bytes")
        if hashlib.sha256(self.metadata_bytes).hexdigest() != self.pin.metadata_sha256:
            raise ValueError("runtime metadata does not match its pin")

    @property
    def metadata_sha256(self) -> str:
        return self.pin.metadata_sha256

    def storage_key(self, pallet: str, item: str, params: Sequence[Any] = ()) -> bytes:
        if not isinstance(pallet, str) or not pallet:
            raise ValueError("storage pallet must be a non-empty string")
        if not isinstance(item, str) or not item:
            raise ValueError("storage item must be a non-empty string")
        if isinstance(params, (str, bytes, bytearray)) or not isinstance(params, Sequence):
            raise TypeError("storage params must be a sequence")
        try:
            key = self._runtime.storage_key(pallet, item, list(params))
        except Exception as error:
            raise ValidatorChainError("storage_key_construction_failed") from error
        if not isinstance(key, bytes) or not key:
            raise ValidatorChainError("storage_key_invalid")
        return key

    def decode_storage(self, pallet: str, item: str, raw_value: bytes | None) -> Any:
        try:
            entry = self._runtime.storage_entry(pallet, item)
            if raw_value is None:
                if entry.modifier == "Optional":
                    return None
                if entry.modifier != "Default":
                    raise ValidatorChainError("storage_modifier_unsupported")
                encoded = entry.default_bytes
            else:
                encoded = raw_value
            return self._runtime.decode(entry.value_type, encoded, strict=True)
        except ValidatorChainError:
            raise
        except Exception as error:
            raise ValidatorChainError("storage_value_decode_failed") from error


@dataclass(frozen=True, slots=True)
class VerifiedStorageRead:
    """Proof-backed raw storage plus its content-pinned semantic decode."""

    runtime: PinnedRuntimeContext
    pallet: str
    item: str
    params: tuple[Any, ...]
    evidence: StorageEvidence
    decoded_value: Any

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, PinnedRuntimeContext):
            raise TypeError("runtime must be a PinnedRuntimeContext")
        if self.evidence.snapshot != self.runtime.snapshot:
            raise ValueError("storage evidence and runtime use different finalized snapshots")
        expected_key = self.runtime.storage_key(self.pallet, self.item, self.params)
        if self.evidence.storage_key != expected_key:
            raise ValueError("storage evidence uses a different runtime-derived key")


@dataclass(frozen=True, slots=True)
class StorageClaim:
    """One canonical raw storage membership or absence claim."""

    storage_key: bytes
    value: bytes | None

    def __post_init__(self) -> None:
        if not isinstance(self.storage_key, bytes) or not self.storage_key:
            raise ValueError("storage claim key must be non-empty bytes")
        if self.value is not None and not isinstance(self.value, bytes):
            raise TypeError("storage claim value must be bytes or None")


@dataclass(frozen=True, slots=True, init=False)
class MultiStorageEvidence:
    """Several sorted storage claims authenticated by one shared trie proof."""

    snapshot: FinalizedSnapshotRef
    claims: tuple[StorageClaim, ...]
    proof: tuple[bytes, ...]
    verified_state_root: str

    def __init__(
        self,
        *,
        snapshot: FinalizedSnapshotRef,
        claims: Sequence[StorageClaim],
        proof: Sequence[bytes],
        verifier: MultiStorageProofVerifier,
    ) -> None:
        if not isinstance(snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        if isinstance(claims, (bytes, bytearray, str)) or not isinstance(claims, Sequence):
            raise TypeError("claims must be a sequence of StorageClaim values")
        claim_tuple = tuple(claims)
        if not claim_tuple or any(not isinstance(claim, StorageClaim) for claim in claim_tuple):
            raise ValueError("claims must contain StorageClaim values")
        keys = [claim.storage_key for claim in claim_tuple]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("storage claims must be unique and sorted by raw key")
        if isinstance(proof, (bytes, bytearray, str)) or not isinstance(proof, Sequence):
            raise TypeError("proof must be a sequence of encoded proof nodes")
        proof_tuple = tuple(proof)
        if not proof_tuple or any(not isinstance(node, bytes) or not node for node in proof_tuple):
            raise ValueError("proof must contain non-empty byte nodes")
        if len(set(proof_tuple)) != len(proof_tuple):
            raise ValueError("storage multiproof contains a duplicate node")
        if not callable(verifier):
            raise TypeError("verifier must be callable")
        try:
            verified = verifier(
                state_root=bytes.fromhex(snapshot.state_root[2:]),
                items=tuple((claim.storage_key, claim.value) for claim in claim_tuple),
                proof=proof_tuple,
            )
        except Exception as error:
            raise ValueError("storage multiproof verification failed") from error
        if verified is not True:
            raise ValueError("storage multiproof verifier did not affirm the proof")
        object.__setattr__(self, "snapshot", snapshot)
        object.__setattr__(self, "claims", claim_tuple)
        object.__setattr__(self, "proof", proof_tuple)
        object.__setattr__(self, "verified_state_root", snapshot.state_root)


@dataclass(frozen=True, slots=True)
class StorageReadSpec:
    """One named runtime storage value requested in a shared proof batch."""

    pallet: str
    item: str
    params: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.pallet, str) or not self.pallet:
            raise ValueError("storage pallet must be a non-empty string")
        if not isinstance(self.item, str) or not self.item:
            raise ValueError("storage item must be a non-empty string")
        if not isinstance(self.params, tuple):
            raise TypeError("storage params must be a tuple")


@dataclass(frozen=True, slots=True)
class DecodedStorageClaim:
    spec: StorageReadSpec
    storage_key: bytes
    raw_value: bytes | None
    decoded_value: Any


@dataclass(frozen=True, slots=True)
class VerifiedStorageBatch:
    """Named semantic decodes backed by exactly one shared multiproof."""

    runtime: PinnedRuntimeContext
    evidence: MultiStorageEvidence
    reads: tuple[DecodedStorageClaim, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, PinnedRuntimeContext):
            raise TypeError("runtime must be a PinnedRuntimeContext")
        if not isinstance(self.evidence, MultiStorageEvidence):
            raise TypeError("evidence must be MultiStorageEvidence")
        if self.evidence.snapshot != self.runtime.snapshot:
            raise ValueError("storage evidence and runtime use different finalized snapshots")
        if not self.reads or len(self.reads) != len(self.evidence.claims):
            raise ValueError("decoded reads must form a bijection with storage claims")
        claim_by_key = {claim.storage_key: claim for claim in self.evidence.claims}
        if len(claim_by_key) != len(self.reads):
            raise ValueError("decoded reads contain duplicate storage keys")
        for read in self.reads:
            key = self.runtime.storage_key(read.spec.pallet, read.spec.item, read.spec.params)
            if read.storage_key != key:
                raise ValueError("decoded read uses a different runtime-derived key")
            claim = claim_by_key.get(key)
            if claim is None or claim.value != read.raw_value:
                raise ValueError("decoded read does not match its proven raw storage claim")


class FinalizedProofCollector:
    """Collect raw storage proofs at an independently verified finalized head."""

    def __init__(
        self,
        rpc: RawJsonRpc,
        *,
        finality: VerifiedFinalizedSnapshotPort,
        verifier: StorageProofVerifier,
        limits: ProofCollectionLimits | None = None,
    ) -> None:
        if not callable(getattr(rpc, "request", None)):
            raise TypeError("rpc must implement RawJsonRpc")
        if not callable(getattr(finality, "verified_finalized_snapshot", None)):
            raise TypeError("finality must implement VerifiedFinalizedSnapshotPort")
        if not callable(verifier):
            raise TypeError("verifier must be callable")
        self._rpc = rpc
        self._finality = finality
        self._verifier = verifier
        self._limits = limits or ProofCollectionLimits()

    async def finalized_snapshot(self) -> FinalizedSnapshotRef:
        """Cross-check RPC header data against the owned smoldot-finalized head."""

        try:
            snapshot = await self._finality.verified_finalized_snapshot()
        except Exception as error:
            raise ValidatorChainError("owned_finality_unavailable") from error
        if not isinstance(snapshot, FinalizedSnapshotRef):
            raise ValidatorChainError("owned_finalized_snapshot_invalid")
        try:
            header = _mapping(
                await self._rpc.request("chain_getHeader", (snapshot.block_hash,)),
                "finalized_header_invalid",
            )
            number = _block_number(header.get("number"))
            if number != snapshot.block_number:
                raise ValidatorChainError("finalized_header_number_mismatch")
            canonical_hash = _hash(
                await self._rpc.request("chain_getBlockHash", (number,)),
                "finalized_block_hash_invalid",
            )
            if canonical_hash != snapshot.block_hash:
                raise ValidatorChainError("finalized_block_hash_mismatch")
            parent_hash = _hash(
                header.get("parentHash"),
                "finalized_parent_hash_invalid",
            )
            if parent_hash != snapshot.parent_hash:
                raise ValidatorChainError("finalized_parent_hash_mismatch")
            state_root = _hash(
                header.get("stateRoot"),
                "finalized_state_root_invalid",
            )
            if state_root != snapshot.state_root:
                raise ValidatorChainError("finalized_state_root_mismatch")
            return snapshot
        except ValidatorChainError:
            raise
        except Exception as error:
            raise ValidatorChainError("finalized_snapshot_rpc_failed") from error

    async def pinned_runtime(
        self,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext:
        """Load and content-check the exact runtime codec at ``snapshot``."""

        if not isinstance(snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        if not isinstance(pin, FinalizedRuntimePin):
            raise TypeError("pin must be a FinalizedRuntimePin")
        try:
            version = _mapping(
                await self._rpc.request(
                    "state_getRuntimeVersion",
                    (snapshot.block_hash,),
                ),
                "runtime_version_invalid",
            )
            spec_version = _strict_uint(version.get("specVersion"), "runtime_spec_version_invalid")
            transaction_version = _strict_uint(
                version.get("transactionVersion"),
                "runtime_transaction_version_invalid",
            )
            state_version = _strict_uint(
                version.get("stateVersion"),
                "runtime_state_version_invalid",
                maximum=255,
            )
            if (
                spec_version != pin.spec_version
                or transaction_version != pin.transaction_version
                or state_version != pin.state_version
            ):
                raise ValidatorChainError("runtime_version_pin_mismatch")

            metadata = _bytes_from_hex(
                await self._rpc.request("state_getMetadata", (snapshot.block_hash,)),
                "runtime_metadata_invalid",
            )
            if not metadata:
                raise ValidatorChainError("runtime_metadata_invalid")
            if len(metadata) > self._limits.maximum_runtime_metadata_bytes:
                raise ValidatorChainError("runtime_metadata_limit")
            if hashlib.sha256(metadata).hexdigest() != pin.metadata_sha256:
                raise ValidatorChainError("runtime_metadata_pin_mismatch")
            try:
                runtime = bittensor_core.Runtime(
                    metadata,
                    spec_version,
                    transaction_version,
                    ss58_format=pin.ss58_prefix,
                )
            except Exception as error:
                raise ValidatorChainError("runtime_codec_initialization_failed") from error
            if runtime.spec_version != spec_version or runtime.transaction_version != (
                transaction_version
            ):
                raise ValidatorChainError("runtime_codec_version_mismatch")
            try:
                ss58_prefix = runtime.constant("System", "SS58Prefix")
            except Exception as error:
                raise ValidatorChainError("runtime_ss58_prefix_unavailable") from error
            if ss58_prefix != pin.ss58_prefix:
                raise ValidatorChainError("runtime_ss58_prefix_mismatch")
            return PinnedRuntimeContext(
                snapshot=snapshot,
                pin=pin,
                metadata_bytes=metadata,
                runtime_version_bytes=canonical_json_bytes(dict(version)),
                _runtime=runtime,
            )
        except ValidatorChainError:
            raise
        except Exception as error:
            raise ValidatorChainError("runtime_metadata_rpc_failed") from error

    async def storage_evidence(
        self,
        snapshot: FinalizedSnapshotRef,
        storage_key: bytes,
    ) -> StorageEvidence:
        """Read one raw value and require a proof to ``snapshot.state_root``."""

        if not isinstance(snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        if not isinstance(storage_key, bytes) or not storage_key:
            raise ValueError("storage_key must be non-empty bytes")
        if len(storage_key) > self._limits.maximum_storage_key_bytes:
            raise ValidatorChainError("storage_key_limit")
        key_hex = "0x" + storage_key.hex()

        try:
            raw_value = await self._rpc.request(
                "state_getStorageAt",
                (key_hex, snapshot.block_hash),
            )
            value = (
                None if raw_value is None else _bytes_from_hex(raw_value, "storage_value_invalid")
            )
            if value is not None and len(value) > self._limits.maximum_storage_value_bytes:
                raise ValidatorChainError("storage_value_limit")

            nodes = await self._read_proof(snapshot, (key_hex,))

            try:
                return StorageEvidence(
                    snapshot=snapshot,
                    storage_key=storage_key,
                    value=value,
                    proof=nodes,
                    verifier=self._verifier,
                )
            except (TypeError, ValueError) as error:
                raise ValidatorChainError("storage_proof_verification_failed") from error
        except ValidatorChainError:
            raise
        except Exception as error:
            raise ValidatorChainError("storage_proof_rpc_failed") from error

    async def storage_evidence_many(
        self,
        snapshot: FinalizedSnapshotRef,
        storage_keys: Sequence[bytes],
    ) -> MultiStorageEvidence:
        """Collect several raw values and authenticate them with one multiproof."""

        if not isinstance(snapshot, FinalizedSnapshotRef):
            raise TypeError("snapshot must be a FinalizedSnapshotRef")
        if isinstance(storage_keys, (str, bytes, bytearray)) or not isinstance(
            storage_keys, Sequence
        ):
            raise TypeError("storage_keys must be a sequence")
        keys = tuple(storage_keys)
        if not keys:
            raise ValueError("storage_keys must not be empty")
        if len(keys) > self._limits.maximum_storage_keys:
            raise ValidatorChainError("storage_key_count_limit")
        if any(not isinstance(key, bytes) or not key for key in keys):
            raise ValueError("storage keys must be non-empty bytes")
        if any(len(key) > self._limits.maximum_storage_key_bytes for key in keys):
            raise ValidatorChainError("storage_key_limit")
        if len(set(keys)) != len(keys):
            raise ValueError("storage keys must be unique")
        ordered_keys = tuple(sorted(keys))
        key_hexes = tuple("0x" + key.hex() for key in ordered_keys)

        try:
            claims: list[StorageClaim] = []
            total_value_bytes = 0
            for key, key_hex in zip(ordered_keys, key_hexes, strict=True):
                raw_value = await self._rpc.request(
                    "state_getStorageAt",
                    (key_hex, snapshot.block_hash),
                )
                value = (
                    None
                    if raw_value is None
                    else _bytes_from_hex(raw_value, "storage_value_invalid")
                )
                if value is not None:
                    if len(value) > self._limits.maximum_storage_value_bytes:
                        raise ValidatorChainError("storage_value_limit")
                    total_value_bytes += len(value)
                    if total_value_bytes > self._limits.maximum_storage_values_bytes:
                        raise ValidatorChainError("storage_values_size_limit")
                claims.append(StorageClaim(storage_key=key, value=value))
            proof = await self._read_proof(snapshot, key_hexes)
            verify_many = getattr(self._verifier, "verify_many", None)
            if not callable(verify_many):
                raise ValidatorChainError("storage_multi_proof_verifier_unavailable")
            try:
                return MultiStorageEvidence(
                    snapshot=snapshot,
                    claims=claims,
                    proof=proof,
                    verifier=verify_many,
                )
            except (TypeError, ValueError) as error:
                raise ValidatorChainError("storage_proof_verification_failed") from error
        except ValidatorChainError:
            raise
        except Exception as error:
            raise ValidatorChainError("storage_proof_rpc_failed") from error

    async def _read_proof(
        self,
        snapshot: FinalizedSnapshotRef,
        key_hexes: Sequence[str],
    ) -> tuple[bytes, ...]:
        response = _mapping(
            await self._rpc.request(
                "state_getReadProof",
                (list(key_hexes), snapshot.block_hash),
            ),
            "storage_proof_invalid",
        )
        proof_at = _hash(response.get("at"), "storage_proof_block_invalid")
        if proof_at != snapshot.block_hash:
            raise ValidatorChainError("storage_proof_block_mismatch")
        raw_nodes = response.get("proof")
        if (
            isinstance(raw_nodes, (str, bytes, bytearray))
            or not isinstance(raw_nodes, Sequence)
            or not raw_nodes
        ):
            raise ValidatorChainError("storage_proof_invalid")
        if len(raw_nodes) > self._limits.maximum_proof_nodes:
            raise ValidatorChainError("storage_proof_node_limit")

        nodes: list[bytes] = []
        proof_bytes = 0
        for raw_node in raw_nodes:
            node = _bytes_from_hex(raw_node, "storage_proof_node_invalid")
            if not node:
                raise ValidatorChainError("storage_proof_node_invalid")
            if len(node) > self._limits.maximum_proof_node_bytes:
                raise ValidatorChainError("storage_proof_node_size_limit")
            proof_bytes += len(node)
            if proof_bytes > self._limits.maximum_proof_bytes:
                raise ValidatorChainError("storage_proof_size_limit")
            nodes.append(node)
        if len(set(nodes)) != len(nodes):
            raise ValidatorChainError("storage_proof_duplicate_node")
        return tuple(nodes)

    async def storage_read(
        self,
        runtime: PinnedRuntimeContext,
        pallet: str,
        item: str,
        params: Sequence[Any] = (),
    ) -> VerifiedStorageRead:
        """Construct, prove, and decode one named storage key at one runtime."""

        if not isinstance(runtime, PinnedRuntimeContext):
            raise TypeError("runtime must be a PinnedRuntimeContext")
        param_tuple = tuple(params)
        key = runtime.storage_key(pallet, item, param_tuple)
        evidence = await self.storage_evidence(runtime.snapshot, key)
        decoded = runtime.decode_storage(pallet, item, evidence.value)
        return VerifiedStorageRead(
            runtime=runtime,
            pallet=pallet,
            item=item,
            params=param_tuple,
            evidence=evidence,
            decoded_value=decoded,
        )

    async def storage_reads(
        self,
        runtime: PinnedRuntimeContext,
        specs: Sequence[StorageReadSpec],
    ) -> VerifiedStorageBatch:
        """Construct, multiprove, and decode named values at one runtime snapshot."""

        if not isinstance(runtime, PinnedRuntimeContext):
            raise TypeError("runtime must be a PinnedRuntimeContext")
        if isinstance(specs, (str, bytes, bytearray)) or not isinstance(specs, Sequence):
            raise TypeError("specs must be a sequence")
        spec_tuple = tuple(specs)
        if not spec_tuple or any(not isinstance(spec, StorageReadSpec) for spec in spec_tuple):
            raise ValueError("specs must contain StorageReadSpec values")
        keyed = [
            (
                runtime.storage_key(spec.pallet, spec.item, spec.params),
                spec,
            )
            for spec in spec_tuple
        ]
        if len({key for key, _spec in keyed}) != len(keyed):
            raise ValueError("storage read specs resolve to duplicate keys")
        keyed.sort(key=lambda item: item[0])
        evidence = await self.storage_evidence_many(
            runtime.snapshot,
            tuple(key for key, _spec in keyed),
        )
        claim_by_key = {claim.storage_key: claim for claim in evidence.claims}
        reads = tuple(
            DecodedStorageClaim(
                spec=spec,
                storage_key=key,
                raw_value=claim_by_key[key].value,
                decoded_value=runtime.decode_storage(
                    spec.pallet,
                    spec.item,
                    claim_by_key[key].value,
                ),
            )
            for key, spec in keyed
        )
        return VerifiedStorageBatch(runtime=runtime, evidence=evidence, reads=reads)


__all__ = [
    "BittensorRawJsonRpc",
    "DecodedStorageClaim",
    "FinalizedProofCollector",
    "FinalizedRuntimePin",
    "MultiStorageEvidence",
    "MultiStorageProofVerifier",
    "PinnedRuntimeContext",
    "ProofCollectionLimits",
    "RawJsonRpc",
    "StorageClaim",
    "StorageReadSpec",
    "ValidatorChainError",
    "VerifiedFinalizedSnapshotPort",
    "VerifiedStorageBatch",
    "VerifiedStorageRead",
]
