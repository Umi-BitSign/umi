from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.validator_chain import (
    BittensorRawJsonRpc,
    FinalizedProofCollector,
    FinalizedRuntimePin,
    ProofCollectionLimits,
    StorageReadSpec,
    ValidatorChainError,
)


def _hash(byte: int) -> str:
    return "0x" + f"{byte:02x}" * 32


class FakeRpc:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, list[Any]]] = []

    async def request(self, method: str, params) -> Any:
        self.calls.append((method, list(params)))
        value = self.responses[method]
        if isinstance(value, Exception):
            raise value
        return value


class FakeFinality:
    def __init__(self, snapshot: FinalizedSnapshotRef | None = None) -> None:
        self.snapshot = snapshot or FinalizedSnapshotRef(
            block_number=42,
            block_hash=_hash(1),
            parent_hash=_hash(2),
            state_root=_hash(3),
        )
        self.calls = 0

    async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
        self.calls += 1
        return self.snapshot


class FakeMultiRpc(FakeRpc):
    def __init__(self, responses: dict[str, Any], storage: dict[str, str | None]) -> None:
        super().__init__(responses)
        self.storage = storage

    async def request(self, method: str, params) -> Any:
        self.calls.append((method, list(params)))
        if method == "state_getStorageAt":
            return self.storage[params[0]]
        value = self.responses[method]
        if isinstance(value, Exception):
            raise value
        return value


class FakeMultiVerifier:
    def __init__(self) -> None:
        self.single_calls: list[dict[str, Any]] = []
        self.multi_calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs) -> bool:
        self.single_calls.append(kwargs)
        return True

    def verify_many(self, **kwargs) -> bool:
        self.multi_calls.append(kwargs)
        return True


class FakeStorageEntry:
    def __init__(self, *, modifier: str = "Default") -> None:
        self.modifier = modifier
        self.default_bytes = b"default"
        self.value_type = "FixtureType"


class FakeRuntime:
    def __init__(
        self,
        metadata: bytes,
        spec_version: int,
        transaction_version: int,
        *,
        ss58_format: int,
    ) -> None:
        assert metadata == b"metadata"
        assert ss58_format == 42
        self.spec_version = spec_version
        self.transaction_version = transaction_version

    def constant(self, pallet: str, item: str) -> int:
        assert (pallet, item) == ("System", "SS58Prefix")
        return 42

    def storage_key(self, pallet: str, item: str, params: list[Any]) -> bytes:
        return f"{pallet}.{item}:{params!r}".encode()

    def storage_entry(self, _pallet: str, item: str) -> FakeStorageEntry:
        return FakeStorageEntry(modifier="Optional" if item == "OptionalItem" else "Default")

    def decode(self, type_name: str, data: bytes, *, strict: bool) -> tuple[str, bytes]:
        assert type_name == "FixtureType"
        assert strict is True
        return ("decoded", data)


def _rpc(*, value: str | None = "0x76616c7565", proof=None) -> FakeRpc:
    block_hash = _hash(1)
    return FakeRpc(
        {
            "chain_getFinalizedHead": block_hash,
            "chain_getHeader": {
                "number": "0x2a",
                "parentHash": _hash(2),
                "stateRoot": _hash(3),
            },
            "chain_getBlockHash": block_hash,
            "state_getStorageAt": value,
            "state_getReadProof": {
                "at": block_hash,
                "proof": proof or ["0x0102", "0xaabbcc"],
            },
        }
    )


def _collector(
    rpc: FakeRpc,
    *,
    verifier: Any,
    limits: ProofCollectionLimits | None = None,
    finality: FakeFinality | None = None,
) -> FinalizedProofCollector:
    return FinalizedProofCollector(
        rpc,
        finality=finality or FakeFinality(),
        verifier=verifier,
        limits=limits,
    )


@pytest.mark.asyncio
async def test_pinned_runtime_builds_keys_and_decodes_only_matching_metadata(monkeypatch) -> None:
    rpc = _rpc()
    rpc.responses.update(
        {
            "state_getRuntimeVersion": {
                "specVersion": 452,
                "transactionVersion": 1,
                "stateVersion": 1,
                "specName": "node-subtensor",
            },
            "state_getMetadata": "0x" + b"metadata".hex(),
        }
    )
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", FakeRuntime)
    pin = FinalizedRuntimePin(
        metadata_sha256=hashlib.sha256(b"metadata").hexdigest(),
        spec_version=452,
        transaction_version=1,
    )
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    snapshot = await collector.finalized_snapshot()
    runtime = await collector.pinned_runtime(snapshot, pin)
    read = await collector.storage_read(runtime, "Pallet", "Item", (78,))

    assert runtime.metadata_bytes == b"metadata"
    assert b'"specVersion":452' in runtime.runtime_version_bytes
    assert read.evidence.storage_key == b"Pallet.Item:[78]"
    assert read.evidence.value == b"value"
    assert read.decoded_value == ("decoded", b"value")

    rpc.responses["state_getStorageAt"] = None
    default_read = await collector.storage_read(runtime, "Pallet", "Item")
    assert default_read.evidence.value is None
    assert default_read.decoded_value == ("decoded", b"default")
    optional_read = await collector.storage_read(runtime, "Pallet", "OptionalItem")
    assert optional_read.evidence.value is None
    assert optional_read.decoded_value is None


@pytest.mark.asyncio
async def test_runtime_metadata_and_version_pins_fail_closed(monkeypatch) -> None:
    rpc = _rpc()
    rpc.responses.update(
        {
            "state_getRuntimeVersion": {
                "specVersion": 452,
                "transactionVersion": 1,
                "stateVersion": 1,
            },
            "state_getMetadata": "0x" + b"metadata".hex(),
        }
    )
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", FakeRuntime)
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    snapshot = await collector.finalized_snapshot()

    wrong_version = FinalizedRuntimePin(
        metadata_sha256=hashlib.sha256(b"metadata").hexdigest(),
        spec_version=451,
        transaction_version=1,
    )
    with pytest.raises(ValidatorChainError) as version_error:
        await collector.pinned_runtime(snapshot, wrong_version)
    assert version_error.value.reason_code == "runtime_version_pin_mismatch"

    wrong_metadata = FinalizedRuntimePin(
        metadata_sha256=hashlib.sha256(b"other").hexdigest(),
        spec_version=452,
        transaction_version=1,
    )
    with pytest.raises(ValidatorChainError) as metadata_error:
        await collector.pinned_runtime(snapshot, wrong_metadata)
    assert metadata_error.value.reason_code == "runtime_metadata_pin_mismatch"


@pytest.mark.asyncio
async def test_collects_cross_checked_finalized_header_and_verified_storage() -> None:
    rpc = _rpc()
    observed: dict[str, Any] = {}

    def verifier(**kwargs):
        observed.update(kwargs)
        return True

    collector = _collector(rpc, verifier=verifier)
    snapshot = await collector.finalized_snapshot()
    evidence = await collector.storage_evidence(snapshot, b"\x12key")

    assert snapshot.block_number == 42
    assert snapshot.block_hash == _hash(1)
    assert snapshot.parent_hash == _hash(2)
    assert snapshot.state_root == _hash(3)
    assert evidence.value == b"value"
    assert evidence.proof == (b"\x01\x02", b"\xaa\xbb\xcc")
    assert evidence.verified_state_root == snapshot.state_root
    assert observed == {
        "state_root": bytes.fromhex(snapshot.state_root[2:]),
        "storage_key": b"\x12key",
        "expected_value": b"value",
        "proof": (b"\x01\x02", b"\xaa\xbb\xcc"),
    }
    assert rpc.calls == [
        ("chain_getHeader", [_hash(1)]),
        ("chain_getBlockHash", [42]),
        ("state_getStorageAt", ["0x126b6579", _hash(1)]),
        ("state_getReadProof", [["0x126b6579"], _hash(1)]),
    ]


@pytest.mark.asyncio
async def test_storage_absence_is_proved_instead_of_default_decoded() -> None:
    rpc = _rpc(value=None)
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    snapshot = await collector.finalized_snapshot()
    evidence = await collector.storage_evidence(snapshot, b"missing")
    assert evidence.value is None


@pytest.mark.asyncio
async def test_storage_multiproof_canonicalizes_keys_and_verifies_all_claims_once() -> None:
    base = _rpc()
    rpc = FakeMultiRpc(
        base.responses,
        {
            "0x61": "0x76616c75652d61",
            "0x62": None,
        },
    )
    verifier = FakeMultiVerifier()
    collector = _collector(rpc, verifier=verifier)
    snapshot = await collector.finalized_snapshot()
    evidence = await collector.storage_evidence_many(snapshot, (b"b", b"a"))

    assert tuple((claim.storage_key, claim.value) for claim in evidence.claims) == (
        (b"a", b"value-a"),
        (b"b", None),
    )
    assert evidence.proof == (b"\x01\x02", b"\xaa\xbb\xcc")
    assert verifier.single_calls == []
    assert verifier.multi_calls == [
        {
            "state_root": bytes.fromhex(snapshot.state_root[2:]),
            "items": ((b"a", b"value-a"), (b"b", None)),
            "proof": (b"\x01\x02", b"\xaa\xbb\xcc"),
        }
    ]
    assert rpc.calls[-3:] == [
        ("state_getStorageAt", ["0x61", snapshot.block_hash]),
        ("state_getStorageAt", ["0x62", snapshot.block_hash]),
        ("state_getReadProof", [["0x61", "0x62"], snapshot.block_hash]),
    ]


@pytest.mark.asyncio
async def test_named_storage_batch_decodes_one_shared_multiproof(monkeypatch) -> None:
    base = _rpc()
    base.responses.update(
        {
            "state_getRuntimeVersion": {
                "specVersion": 452,
                "transactionVersion": 1,
                "stateVersion": 1,
            },
            "state_getMetadata": "0x" + b"metadata".hex(),
        }
    )
    item_key = b"Pallet.Item:[78]"
    optional_key = b"Pallet.OptionalItem:[]"
    rpc = FakeMultiRpc(
        base.responses,
        {
            "0x" + item_key.hex(): "0x76616c7565",
            "0x" + optional_key.hex(): None,
        },
    )
    verifier = FakeMultiVerifier()
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", FakeRuntime)
    collector = _collector(rpc, verifier=verifier)
    snapshot = await collector.finalized_snapshot()
    runtime = await collector.pinned_runtime(
        snapshot,
        FinalizedRuntimePin(
            metadata_sha256=hashlib.sha256(b"metadata").hexdigest(),
            spec_version=452,
            transaction_version=1,
        ),
    )
    batch = await collector.storage_reads(
        runtime,
        (
            StorageReadSpec("Pallet", "OptionalItem"),
            StorageReadSpec("Pallet", "Item", (78,)),
        ),
    )

    by_item = {read.spec.item: read for read in batch.reads}
    assert by_item["Item"].decoded_value == ("decoded", b"value")
    assert by_item["OptionalItem"].decoded_value is None
    assert len(verifier.multi_calls) == 1
    assert len(batch.evidence.proof) == 2


@pytest.mark.asyncio
async def test_storage_multiproof_rejects_missing_capability_duplicates_and_total_limits() -> None:
    snapshot_rpc = _rpc()
    collector = _collector(snapshot_rpc, verifier=lambda **_kwargs: True)
    snapshot = await collector.finalized_snapshot()
    with pytest.raises(ValidatorChainError) as capability:
        await collector.storage_evidence_many(snapshot, (b"a", b"b"))
    assert capability.value.reason_code == "storage_multi_proof_verifier_unavailable"

    base = _rpc(proof=["0x01", "0x01"])
    duplicate_rpc = FakeMultiRpc(base.responses, {"0x61": "0x01", "0x62": "0x02"})
    collector = _collector(duplicate_rpc, verifier=FakeMultiVerifier())
    snapshot = await collector.finalized_snapshot()
    with pytest.raises(ValidatorChainError) as duplicate:
        await collector.storage_evidence_many(snapshot, (b"a", b"b"))
    assert duplicate.value.reason_code == "storage_proof_duplicate_node"

    base = _rpc()
    limited_rpc = FakeMultiRpc(base.responses, {"0x61": "0x0102", "0x62": "0x0304"})
    collector = _collector(
        limited_rpc,
        verifier=FakeMultiVerifier(),
        limits=ProofCollectionLimits(
            maximum_storage_value_bytes=2,
            maximum_storage_values_bytes=3,
        ),
    )
    snapshot = await collector.finalized_snapshot()
    with pytest.raises(ValidatorChainError) as total:
        await collector.storage_evidence_many(snapshot, (b"a", b"b"))
    assert total.value.reason_code == "storage_values_size_limit"


@pytest.mark.asyncio
async def test_storage_multiproof_requires_literal_true_from_verifier() -> None:
    class NonAffirmingVerifier:
        def __call__(self, **_kwargs):
            return None

        def verify_many(self, **_kwargs):
            return None

    base = _rpc()
    rpc = FakeMultiRpc(base.responses, {"0x61": "0x01", "0x62": "0x02"})
    collector = _collector(rpc, verifier=NonAffirmingVerifier())
    snapshot = await collector.finalized_snapshot()
    with pytest.raises(ValidatorChainError) as caught:
        await collector.storage_evidence_many(snapshot, (b"a", b"b"))
    assert caught.value.reason_code == "storage_proof_verification_failed"


@pytest.mark.asyncio
async def test_finalized_snapshot_rejects_rpc_disagreement_with_owned_finality() -> None:
    rpc = _rpc()
    rpc.responses["chain_getBlockHash"] = _hash(9)
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    with pytest.raises(ValidatorChainError) as mismatch:
        await collector.finalized_snapshot()
    assert mismatch.value.reason_code == "finalized_block_hash_mismatch"

    rpc = _rpc()
    rpc.responses["chain_getHeader"] = {"number": "42"}
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    with pytest.raises(ValidatorChainError) as invalid:
        await collector.finalized_snapshot()
    assert invalid.value.reason_code == "finalized_header_number_invalid"

    rpc = _rpc()
    rpc.responses["chain_getHeader"]["parentHash"] = _hash(8)
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    with pytest.raises(ValidatorChainError) as parent:
        await collector.finalized_snapshot()
    assert parent.value.reason_code == "finalized_parent_hash_mismatch"

    rpc = _rpc()
    rpc.responses["chain_getHeader"]["stateRoot"] = _hash(8)
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    with pytest.raises(ValidatorChainError) as state_root:
        await collector.finalized_snapshot()
    assert state_root.value.reason_code == "finalized_state_root_mismatch"


@pytest.mark.asyncio
async def test_finalized_snapshot_requires_an_affirmative_owned_finality_result() -> None:
    class FailingFinality:
        async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
            raise ConnectionError("smoldot observer unavailable")

    collector = FinalizedProofCollector(
        _rpc(),
        finality=FailingFinality(),
        verifier=lambda **_kwargs: True,
    )
    with pytest.raises(ValidatorChainError) as unavailable:
        await collector.finalized_snapshot()
    assert unavailable.value.reason_code == "owned_finality_unavailable"
    assert isinstance(unavailable.value.__cause__, ConnectionError)

    class InvalidFinality:
        async def verified_finalized_snapshot(self):
            return {"provider_claim": "finalized"}

    collector = FinalizedProofCollector(
        _rpc(),
        finality=InvalidFinality(),  # type: ignore[arg-type]
        verifier=lambda **_kwargs: True,
    )
    with pytest.raises(ValidatorChainError) as invalid:
        await collector.finalized_snapshot()
    assert invalid.value.reason_code == "owned_finalized_snapshot_invalid"


@pytest.mark.asyncio
async def test_storage_proof_is_bound_to_requested_block_and_state_root() -> None:
    rpc = _rpc()
    collector = _collector(rpc, verifier=lambda **_kwargs: True)
    snapshot = await collector.finalized_snapshot()
    rpc.responses["state_getReadProof"]["at"] = _hash(8)
    with pytest.raises(ValidatorChainError) as wrong_block:
        await collector.storage_evidence(snapshot, b"key")
    assert wrong_block.value.reason_code == "storage_proof_block_mismatch"

    rpc = _rpc()

    def reject(**_kwargs):
        raise ValueError("invalid trie proof")

    collector = _collector(rpc, verifier=reject)
    snapshot = await collector.finalized_snapshot()
    with pytest.raises(ValidatorChainError) as wrong_root:
        await collector.storage_evidence(snapshot, b"key")
    assert wrong_root.value.reason_code == "storage_proof_verification_failed"
    assert isinstance(wrong_root.value.__cause__, ValueError)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("limits", "proof", "storage_key", "value", "reason_code"),
    [
        (
            ProofCollectionLimits(maximum_storage_key_bytes=2),
            None,
            b"key",
            "0x01",
            "storage_key_limit",
        ),
        (
            ProofCollectionLimits(maximum_storage_value_bytes=1),
            None,
            b"k",
            "0x0102",
            "storage_value_limit",
        ),
        (
            ProofCollectionLimits(maximum_proof_nodes=1),
            ["0x01", "0x02"],
            b"k",
            "0x01",
            "storage_proof_node_limit",
        ),
        (
            ProofCollectionLimits(maximum_proof_node_bytes=1, maximum_proof_bytes=2),
            ["0x0102"],
            b"k",
            "0x01",
            "storage_proof_node_size_limit",
        ),
        (
            ProofCollectionLimits(maximum_proof_node_bytes=2, maximum_proof_bytes=2),
            ["0x0102", "0x03"],
            b"k",
            "0x01",
            "storage_proof_size_limit",
        ),
    ],
)
async def test_proof_collection_limits_fail_closed(
    limits: ProofCollectionLimits,
    proof: list[str] | None,
    storage_key: bytes,
    value: str,
    reason_code: str,
) -> None:
    rpc = _rpc(value=value, proof=proof)
    collector = _collector(
        rpc,
        verifier=lambda **_kwargs: True,
        limits=limits,
    )
    snapshot = await collector.finalized_snapshot()
    with pytest.raises(ValidatorChainError) as caught:
        await collector.storage_evidence(snapshot, storage_key)
    assert caught.value.reason_code == reason_code


@pytest.mark.asyncio
async def test_malformed_proof_never_reaches_verifier() -> None:
    rpc = _rpc(proof=["0x"])
    collector = _collector(
        rpc,
        verifier=lambda **_kwargs: pytest.fail("malformed proof reached verifier"),
    )
    snapshot = await collector.finalized_snapshot()
    with pytest.raises(ValidatorChainError) as caught:
        await collector.storage_evidence(snapshot, b"key")
    assert caught.value.reason_code == "storage_proof_node_invalid"


class _FakeWebSocket:
    def __init__(self, response: str | bytes | Exception) -> None:
        self.response = response
        self.sent: list[str] = []

    async def send(self, value: str) -> None:
        self.sent.append(value)

    async def recv(self) -> str | bytes:
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _FakeConnection:
    def __init__(self, socket: _FakeWebSocket) -> None:
        self.socket = socket

    async def __aenter__(self) -> _FakeWebSocket:
        return self.socket

    async def __aexit__(self, *_args: object) -> None:
        return None


class _FakeConnect:
    def __init__(self, response: str | bytes | Exception) -> None:
        self.socket = _FakeWebSocket(response)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, endpoint: str, **kwargs: Any) -> _FakeConnection:
        self.calls.append((endpoint, kwargs))
        return _FakeConnection(self.socket)


class _RpcClient:
    endpoint = "wss://entrypoint-finney.opentensor.ai:443"


@pytest.mark.asyncio
async def test_bittensor_adapter_owns_a_bounded_connection() -> None:
    response = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"number": "0x2a"}},
        separators=(",", ":"),
    )
    connect = _FakeConnect(response)
    rpc = BittensorRawJsonRpc(_RpcClient(), connect_factory=connect)

    assert await rpc.request("chain_getHeader", (_hash(1),)) == {"number": "0x2a"}
    assert len(connect.calls) == 1
    endpoint, kwargs = connect.calls[0]
    assert endpoint == _RpcClient.endpoint
    assert kwargs["compression"] == "deflate"
    assert kwargs["proxy"] is None
    assert kwargs["max_size"] == 1024 * 1024
    assert kwargs["max_queue"] == 1
    assert json.loads(connect.socket.sent[0]) == {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "chain_getHeader",
        "params": [_hash(1)],
    }


@pytest.mark.asyncio
async def test_bittensor_adapter_rejects_forbidden_methods_before_connecting() -> None:
    connect = _FakeConnect(AssertionError("must not connect"))
    rpc = BittensorRawJsonRpc(_RpcClient(), connect_factory=connect)
    with pytest.raises(ValidatorChainError) as forbidden:
        await rpc.request("author_submitExtrinsic", ("0x00",))
    assert forbidden.value.reason_code == "proof_rpc_method_forbidden"
    assert connect.calls == []


@pytest.mark.asyncio
async def test_bittensor_adapter_rejects_oversized_response_before_json_parse() -> None:
    connect = _FakeConnect("{" + "x" * (1024 * 1024))
    rpc = BittensorRawJsonRpc(_RpcClient(), connect_factory=connect)
    with pytest.raises(ValidatorChainError) as oversized:
        await rpc.request("chain_getBlockHash", (42,))
    assert oversized.value.reason_code == "proof_rpc_response_limit"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "reason_code"),
    [
        (
            '{"id":1,"id":1,"jsonrpc":"2.0","result":null}',
            "proof_rpc_response_invalid",
        ),
        ('{"id":2,"jsonrpc":"2.0","result":null}', "proof_rpc_response_invalid"),
        ('{"error":{"code":-1},"id":1,"jsonrpc":"2.0"}', "proof_rpc_error"),
        (b'{"id":1,"jsonrpc":"2.0","result":null}', "proof_rpc_response_invalid"),
    ],
)
async def test_bittensor_adapter_rejects_ambiguous_or_invalid_responses(
    response: str | bytes,
    reason_code: str,
) -> None:
    rpc = BittensorRawJsonRpc(_RpcClient(), connect_factory=_FakeConnect(response))
    with pytest.raises(ValidatorChainError) as invalid:
        await rpc.request("chain_getBlockHash", (42,))
    assert invalid.value.reason_code == reason_code


def test_bittensor_adapter_rejects_missing_or_unsafe_endpoint() -> None:
    with pytest.raises(ValidatorChainError) as missing:
        BittensorRawJsonRpc(object())
    assert missing.value.reason_code == "proof_rpc_endpoint_unavailable"

    for endpoint in (
        "ws://entrypoint-finney.opentensor.ai:443",
        "wss://user@example.invalid",
        "wss://example.invalid/?token=secret",
    ):
        client = type("Client", (), {"endpoint": endpoint})()
        with pytest.raises(ValidatorChainError) as invalid:
            BittensorRawJsonRpc(client)
        assert invalid.value.reason_code == "proof_rpc_endpoint_invalid"


def test_limits_are_strict_and_consistent() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        ProofCollectionLimits(maximum_proof_nodes=0)
    with pytest.raises(ValueError, match="complete proof-byte"):
        ProofCollectionLimits(maximum_proof_node_bytes=3, maximum_proof_bytes=2)

    defaults = ProofCollectionLimits()
    assert replace(defaults, maximum_proof_nodes=1).maximum_proof_nodes == 1
