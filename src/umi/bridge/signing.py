"""Read-only signing evidence for future versioned bridge attempts.

The legacy SDK observation remains explicitly unproven. This reader authenticates
only the runtime, account nonce and timestamp at that observation's owned head.
It cannot sign, submit, resolve old attempts or authorize a reward policy. The
versioned journal and qualified release must opt in before the bridge uses it.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from ..chain import _header_hash
from ..chain_evidence import FinalizedSnapshotRef, StorageProofVerifier
from ..concurrency import await_owned_task
from ..encoding import account_id32, datetime_to_unix_ms
from ..protocol import canonical_json_bytes
from ..runtime_metadata import (
    MAX_CODE_BYTES,
    ExecutedRuntimeContext,
    RuntimeMetadataExecutor,
    collect_executed_runtime,
)
from ..validator_chain import (
    FinalizedProofCollector,
    ProofCollectionLimits,
    RawJsonRpc,
    StorageReadSpec,
    VerifiedStorageBatch,
)
from .policy import _require
from .selection import RegistrationBridgeObservation


class FinalizedIdentity(Protocol):
    number: int
    block_hash: str


class BridgeFinality(Protocol):
    async def read_finalized_identity(self) -> FinalizedIdentity: ...


class _SnapshotPort:
    """Derive the state root by hashing a header against an owned identity."""

    def __init__(self, finality: BridgeFinality, rpc: RawJsonRpc):
        self.finality, self.rpc = finality, rpc

    async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
        owned = await self.finality.read_finalized_identity()
        _require(type(owned.number) is int and owned.number > 0, "bridge_owned_head_invalid")
        header = await self.rpc.request("chain_getHeader", (owned.block_hash,))
        _require(isinstance(header, Mapping), "bridge_signing_header_invalid")
        number = header.get("number")
        if isinstance(number, str) and number.startswith("0x"):
            number = int(number, 16)
        _require(
            _header_hash({**header, "number": number}, "bridge signing header") == owned.block_hash,
            "bridge_signing_header_mismatch",
        )
        _require(type(number) is int and number == owned.number, "bridge_signing_height_mismatch")
        return FinalizedSnapshotRef(
            block_number=number,
            block_hash=owned.block_hash,
            parent_hash=header["parentHash"],
            state_root=header["stateRoot"],
        )


@dataclass(frozen=True, slots=True)
class BridgeSigningState:
    """Verified account/runtime data, with no authority to retry a transaction."""

    validator_hotkey: str
    runtime: ExecutedRuntimeContext
    batch: VerifiedStorageBatch
    nonce: int = field(init=False)
    timestamp_ms: int = field(init=False)

    def __post_init__(self):
        account_id32(self.validator_hotkey)
        _require(
            type(self.runtime) is ExecutedRuntimeContext
            and isinstance(self.batch, VerifiedStorageBatch)
            and self.batch.runtime is self.runtime,
            "bridge_signing_runtime_binding_invalid",
        )
        expected = {
            StorageReadSpec("System", "Account", (self.validator_hotkey,)),
            StorageReadSpec("Timestamp", "Now"),
        }
        _require(
            len(self.batch.reads) == 2 and {r.spec for r in self.batch.reads} == expected,
            "bridge_signing_account_proof_invalid",
        )
        # Re-decode the proven bytes; do not grant authority to a caller's
        # substituted decoded_value in an otherwise well-formed batch.
        account = self._value("System", "Account")
        _require(isinstance(account, dict), "bridge_signing_nonce_invalid")
        nonce = account.get("nonce")
        _require(type(nonce) is int and 0 <= nonce < 2**32, "bridge_signing_nonce_invalid")
        timestamp = self._value("Timestamp", "Now")
        _require(type(timestamp) is int and timestamp > 0, "bridge_signing_timestamp_invalid")
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "timestamp_ms", timestamp)

    def _value(self, pallet: str, item: str):
        read = next(r for r in self.batch.reads if (r.spec.pallet, r.spec.item) == (pallet, item))
        return self.runtime.decode_storage(pallet, item, read.raw_value)


def signing_state_digest(state: BridgeSigningState) -> str:
    """Commit to the captured proof inputs without hex-expanding runtime code."""
    runtime = state.runtime
    snapshot = runtime.snapshot
    digest = hashlib.sha256(b"umi-bridge-signing-state-v1\0")

    def bind(value: bytes):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    bind(
        canonical_json_bytes(
            {
                "validator_hotkey": state.validator_hotkey,
                "nonce": state.nonce,
                "timestamp_ms": state.timestamp_ms,
                "block_number": snapshot.block_number,
                "block_hash": snapshot.block_hash,
                "parent_hash": snapshot.parent_hash,
                "state_root": snapshot.state_root,
                "executor_sha256": runtime.executor_sha256,
            }
        )
    )
    bind(runtime.metadata_bytes)
    bind(runtime.runtime_version_bytes)
    bind(runtime.code_evidence.storage_key)
    bind(runtime.code_evidence.value)
    bind(len(runtime.code_evidence.proof).to_bytes(8, "big"))
    for node in runtime.code_evidence.proof:
        bind(node)
    bind(len(state.batch.evidence.claims).to_bytes(8, "big"))
    for claim in state.batch.evidence.claims:
        bind(claim.storage_key)
        bind(b"\x00" if claim.value is None else b"\x01" + claim.value)
    bind(len(state.batch.evidence.proof).to_bytes(8, "big"))
    for node in state.batch.evidence.proof:
        bind(node)
    return digest.hexdigest()


class BridgeSigningStateReader:
    """Collect bounded proofs without borrowing the SDK's nonce or metadata.

    The release owner supplies its owned finality reader, bounded read-only RPC,
    pinned proof verifier and pinned runtime executor. There is no JSON input
    adapter or permissive fallback. That owner retains these resources until
    every capture has drained, and separately authorizes the installed pins.
    """

    def __init__(
        self,
        *,
        finality: BridgeFinality,
        rpc: RawJsonRpc,
        verifier: StorageProofVerifier,
        runtime_executor: RuntimeMetadataExecutor,
        clock: Callable[[], datetime] | None = None,
        timeout_seconds: float = 60,
    ):
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise ValueError("bridge signing capture timeout must be in (0, 60]")
        self._timeout = timeout_seconds
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._executor = runtime_executor
        self._snapshots = _SnapshotPort(finality, rpc)
        self._lock = asyncio.Lock()
        self._proofs = FinalizedProofCollector(
            rpc,
            finality=self._snapshots,
            verifier=verifier,
            limits=ProofCollectionLimits(
                maximum_storage_keys=2,
                maximum_storage_value_bytes=512,
                maximum_storage_values_bytes=1024,
                maximum_proof_node_bytes=2 * 1024**2,
                maximum_proof_bytes=8 * 1024**2,
            ),
        )
        self._code_proofs = FinalizedProofCollector(
            rpc,
            finality=self._snapshots,
            verifier=verifier,
            limits=ProofCollectionLimits(
                maximum_storage_keys=1,
                maximum_storage_value_bytes=MAX_CODE_BYTES,
                maximum_storage_values_bytes=MAX_CODE_BYTES,
                maximum_proof_node_bytes=MAX_CODE_BYTES,
                maximum_proof_bytes=MAX_CODE_BYTES + 1024**2,
            ),
        )

    async def capture(self, observation: RegistrationBridgeObservation) -> BridgeSigningState:
        # Freeze the caller's mutable Pydantic lists before the first await.
        observation = RegistrationBridgeObservation.model_validate_json(
            observation.model_dump_json()
        )
        return await self._read_owned(observation.validator_hotkey, observation)

    async def read(self, validator_hotkey: str) -> BridgeSigningState:
        """Choose an owned head before the caller collects its SDK roster.

        The caller must read the remaining bridge state at this exact returned
        snapshot and recheck freshness before signing. No SDK observation is
        promoted to finality authority by this method.
        """
        account_id32(validator_hotkey)
        return await self._read_owned(validator_hotkey, None)

    async def _read_owned(self, validator_hotkey, observation):
        task = asyncio.create_task(self._capture_with_timeout(validator_hotkey, observation))
        return await await_owned_task(task, on_cancel=task.cancel)

    async def _capture_with_timeout(self, validator_hotkey, observation):
        return await asyncio.wait_for(self._capture(validator_hotkey, observation), self._timeout)

    async def _capture(self, validator_hotkey, observation):
        async with self._lock:
            ref = await self._snapshots.verified_finalized_snapshot()
            if observation is not None:
                _require(
                    (ref.block_number, ref.block_hash)
                    == (observation.block_number, observation.block_hash),
                    "bridge_signing_observation_changed",
                )
            runtime = await collect_executed_runtime(self._code_proofs, self._executor, ref)
            batch = await self._proofs.storage_reads(
                runtime,
                (
                    StorageReadSpec("System", "Account", (validator_hotkey,)),
                    StorageReadSpec("Timestamp", "Now"),
                ),
            )
            state = BridgeSigningState(validator_hotkey, runtime, batch)
            if observation is not None:
                _require(
                    state.timestamp_ms == observation.block_timestamp_ms,
                    "bridge_signing_timestamp_mismatch",
                )
            newest = await self._snapshots.finality.read_finalized_identity()
            _require(
                type(newest.number) is int
                and ref.block_number <= newest.number < ref.block_number + 8
                and (newest.number != ref.block_number or newest.block_hash == ref.block_hash),
                "bridge_signing_finality_changed",
            )
            _require(
                0 <= datetime_to_unix_ms(self._clock()) - state.timestamp_ms <= 120_000,
                "bridge_signing_snapshot_stale",
            )
            return state
