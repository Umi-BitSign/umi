from __future__ import annotations

import hashlib
from typing import Any

import pytest

from umi.chain_evidence import FinalizedSnapshotRef, StorageEvidence
from umi.validator_chain import FinalizedRuntimePin, PinnedRuntimeContext
from umi.validator_chain_scan import VerifiedFinalizedBlockIdentity, finalized_block_body_sha256
from umi.validator_chain_scan_port import (
    LiveFinalizedBlockScanPort,
    LiveFinalizedBlockScanPortError,
)


def _hash(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


PARENT = FinalizedSnapshotRef(
    block_number=41,
    block_hash=_hash(41),
    parent_hash=_hash(40),
    state_root=_hash(141),
)
CHILD = FinalizedSnapshotRef(
    block_number=42,
    block_hash=_hash(42),
    parent_hash=PARENT.block_hash,
    state_root=_hash(142),
)
IDENTITY = VerifiedFinalizedBlockIdentity(
    snapshot=CHILD,
    parent_snapshot=PARENT,
    extrinsics_root=_hash(242),
    finality_verifier_sha256="fa" * 32,
    finality_evidence_sha256="fb" * 32,
)
PIN = FinalizedRuntimePin(
    metadata_sha256="aa" * 32,
    spec_version=452,
    transaction_version=1,
)


class FakeRpc:
    def __init__(self) -> None:
        self.response: Any = {
            "block": {
                "header": {
                    "number": "0x2a",
                    "parentHash": PARENT.block_hash,
                    "stateRoot": CHILD.state_root,
                    "extrinsicsRoot": IDENTITY.extrinsics_root,
                    "digest": {"logs": ["0x0102"]},
                },
                "extrinsics": ["0x0102", "0xaabbcc"],
            },
            "justifications": None,
        }
        self.calls: list[tuple[str, list[Any]]] = []

    async def request(self, method: str, params: list[Any] | tuple[Any, ...]) -> Any:
        self.calls.append((method, list(params)))
        return self.response


class FakeProofs:
    def __init__(self) -> None:
        self.storage_calls: list[tuple[FinalizedSnapshotRef, bytes]] = []
        self.runtime_calls: list[tuple[FinalizedSnapshotRef, FinalizedRuntimePin]] = []
        self.runtime = object.__new__(PinnedRuntimeContext)

    async def storage_evidence(
        self,
        snapshot: FinalizedSnapshotRef,
        storage_key: bytes,
    ) -> StorageEvidence:
        self.storage_calls.append((snapshot, storage_key))
        return object.__new__(StorageEvidence)

    async def pinned_runtime(
        self,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext:
        self.runtime_calls.append((snapshot, pin))
        return self.runtime


def _port(rpc: FakeRpc, proofs: FakeProofs) -> LiveFinalizedBlockScanPort:
    # Production requires the exact collector type. Tests construct without
    # calling its initializer so only this port's narrow delegation is exercised.
    from umi.validator_chain import FinalizedProofCollector

    collector = object.__new__(FinalizedProofCollector)
    collector.storage_evidence = proofs.storage_evidence  # type: ignore[method-assign]
    collector.pinned_runtime = proofs.pinned_runtime  # type: ignore[method-assign]
    return LiveFinalizedBlockScanPort(rpc=rpc, proofs=collector, runtime_pin=PIN)


@pytest.mark.asyncio
async def test_body_is_requested_by_verified_hash_and_bound_to_exact_header() -> None:
    rpc = FakeRpc()
    port = _port(rpc, FakeProofs())
    body = await port.block_body_at(IDENTITY)

    assert body is not None
    assert rpc.calls == [("chain_getBlock", [CHILD.block_hash])]
    assert body.extrinsics == (b"\x01\x02", b"\xaa\xbb\xcc")
    assert body.body_sha256 == finalized_block_body_sha256(body.extrinsics)
    assert body.block_hash == CHILD.block_hash


@pytest.mark.asyncio
async def test_body_rejects_header_drift_unknown_fields_and_malformed_hex() -> None:
    rpc = FakeRpc()
    port = _port(rpc, FakeProofs())

    rpc.response["block"]["header"]["stateRoot"] = _hash(999)
    with pytest.raises(LiveFinalizedBlockScanPortError) as mismatch:
        await port.block_body_at(IDENTITY)
    assert mismatch.value.reason_code == "block_header_state_root_mismatch"

    rpc = FakeRpc()
    rpc.response["block"]["header"]["unexpected"] = 1
    with pytest.raises(LiveFinalizedBlockScanPortError) as unknown:
        await _port(rpc, FakeProofs()).block_body_at(IDENTITY)
    assert unknown.value.reason_code == "block_header_invalid"

    rpc = FakeRpc()
    rpc.response["block"]["extrinsics"] = ["0xAA"]
    with pytest.raises(LiveFinalizedBlockScanPortError) as malformed:
        await _port(rpc, FakeProofs()).block_body_at(IDENTITY)
    assert malformed.value.reason_code == "block_extrinsic_invalid"


@pytest.mark.asyncio
async def test_missing_body_remains_missing_without_fabricated_evidence() -> None:
    rpc = FakeRpc()
    rpc.response = None
    assert await _port(rpc, FakeProofs()).block_body_at(IDENTITY) is None


@pytest.mark.asyncio
async def test_event_and_parent_runtime_delegate_to_proof_collector() -> None:
    rpc = FakeRpc()
    proofs = FakeProofs()
    port = _port(rpc, proofs)

    evidence = object.__new__(StorageEvidence)
    object.__setattr__(evidence, "snapshot", CHILD)
    object.__setattr__(evidence, "storage_key", b"events")
    object.__setattr__(evidence, "value", b"event-bytes")
    object.__setattr__(evidence, "proof", (b"proof-node",))
    object.__setattr__(evidence, "verified_state_root", CHILD.state_root)

    async def storage_evidence(snapshot: FinalizedSnapshotRef, storage_key: bytes):
        proofs.storage_calls.append((snapshot, storage_key))
        return evidence

    # The collector object is intentionally private to the port; replace only
    # its bound test double method after construction.
    port._proofs.storage_evidence = storage_evidence  # type: ignore[method-assign]

    raw = await port.event_storage_at(IDENTITY, b"events")
    runtime = await port.execution_runtime_at(IDENTITY)

    assert raw is not None
    assert raw.value == b"event-bytes"
    assert raw.value_sha256 == hashlib.sha256(b"event-bytes").hexdigest()
    assert proofs.storage_calls == [(CHILD, b"events")]
    assert runtime is proofs.runtime
    assert proofs.runtime_calls == [(PARENT, PIN)]


@pytest.mark.asyncio
async def test_proof_failures_are_stable_and_do_not_return_unverified_bytes() -> None:
    rpc = FakeRpc()
    proofs = FakeProofs()
    port = _port(rpc, proofs)

    async def failed(*_args: Any, **_kwargs: Any) -> StorageEvidence:
        raise RuntimeError("untrusted endpoint")

    port._proofs.storage_evidence = failed  # type: ignore[method-assign]
    with pytest.raises(LiveFinalizedBlockScanPortError) as error:
        await port.event_storage_at(IDENTITY, b"events")
    assert error.value.reason_code == "event_storage_proof_failed"
