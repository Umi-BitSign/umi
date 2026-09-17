from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from websockets.exceptions import PayloadTooBig

from umi.competition_weight_rpc import WeightProofRpc
from umi.validator_chain import ValidatorChainError


@pytest.fixture
def sockets(monkeypatch):
    state = SimpleNamespace(connections=[], calls=[], response=None, blocked=False)
    started = asyncio.Event()

    class Connection:
        def __init__(self, kwargs):
            self.kwargs = kwargs
            self.closed = False
            self.busy = False
            self.request = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            self.closed = True

        async def send(self, raw):
            assert not self.closed and not self.busy
            self.request = json.loads(raw)
            assert self.request["id"] == 1
            self.busy = True
            state.calls.append(self.request)
            started.set()

        async def recv(self):
            try:
                if state.blocked:
                    await asyncio.Event().wait()
                await asyncio.sleep(0)
                if isinstance(state.response, Exception):
                    raise state.response
                if state.response is not None:
                    return state.response
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": self.request["params"]})
            finally:
                self.busy = False

    def connect(endpoint, **kwargs):
        assert endpoint == "wss://proofs.example.org"
        assert kwargs["proxy"] is None and kwargs["compression"] == "deflate"
        assert kwargs["max_queue"] == 1 and kwargs["write_limit"] == 64 * 1024
        connection = Connection(kwargs)
        state.connections.append(connection)
        return connection

    monkeypatch.setattr("umi.competition_chain.websocket_connect", connect)
    return state, started


@pytest.fixture
def rpc():
    return WeightProofRpc(
        SimpleNamespace(rpc_url="wss://proofs.example.org", collection_timeout_seconds=120)
    )


async def test_many_weight_reads_reuse_one_socket(rpc, sockets):
    state, _ = sockets
    for i in range(512):
        assert await rpc.request("state_getStorageAt", [i, "same-block"]) == [i, "same-block"]
    assert len(state.calls) == 512 and len(state.connections) == 1
    assert not state.connections[0].closed
    await rpc.aclose()
    assert state.connections[0].closed
    with pytest.raises(ValueError, match="closed"):
        await rpc.request("state_getStorageAt", [])


async def test_methods_keep_original_separate_receive_limits(rpc, sockets):
    state, _ = sockets
    methods = (
        "state_getStorageAt",
        "state_getReadProof",
        "state_getMetadata",
        "state_getRuntimeVersion",
        "chain_getHeader",
        "chain_getBlockHash",
    )
    for _ in range(3):
        for method in methods:
            await rpc.request(method, [])
    assert len(state.connections) == 6
    assert [c.kwargs["max_size"] for c in state.connections] == [
        129 * 1024**2,
        65 * 1024**2,
        33 * 1024**2,
        1024**2,
        1024**2,
        1024**2,
    ]
    assert all(c.kwargs["open_timeout"] == 15 for c in state.connections)
    await rpc.aclose()
    assert all(c.closed for c in state.connections)


async def test_runtime_and_regular_collectors_never_share_sockets(rpc, sockets):
    state, _ = sockets
    runtime = WeightProofRpc(rpc.config)
    for _ in range(2):
        await rpc.request("state_getStorageAt", ["weight"])
        await runtime.request("state_getStorageAt", ["runtime-code"])
    assert len(state.connections) == 2
    await rpc.aclose()
    assert state.connections[0].closed and not state.connections[1].closed
    await runtime.aclose()
    assert all(c.closed for c in state.connections)


@pytest.mark.parametrize(
    "response,reason",
    [
        ('{"jsonrpc":"2.0","id":2,"result":null}', "proof_rpc_response_invalid"),
        ('{"jsonrpc":"2.0","id":1,"result":null,"result":false}', "proof_rpc_response_invalid"),
        ('{"jsonrpc":"2.0","id":1,"error":{"code":429}}', "proof_rpc_error"),
        (ConnectionError("disconnected"), "proof_rpc_failed"),
        (PayloadTooBig(10, 1), "proof_rpc_response_limit"),
    ],
)
async def test_invalid_response_discards_socket_without_retry(rpc, sockets, response, reason):
    state, _ = sockets
    state.response = response
    with pytest.raises(ValidatorChainError, match=reason):
        await rpc.request("state_getStorageAt", [])
    assert len(state.calls) == 1 and len(state.connections) == 1
    assert state.connections[0].closed
    state.response = None
    assert await rpc.request("state_getStorageAt", [2]) == [2]
    assert len(state.connections) == 2
    await rpc.aclose()


async def test_exclusive_socket_keeps_concurrent_request_ids_unambiguous(rpc, sockets):
    state, _ = sockets
    values = await asyncio.gather(*(rpc.request("state_getStorageAt", [i]) for i in range(30)))
    assert values == [[i] for i in range(30)]
    assert len(state.connections) == 1
    await rpc.aclose()


async def test_cancellation_discards_socket_and_allows_later_request(rpc, sockets):
    state, started = sockets
    state.blocked = True
    task = asyncio.create_task(rpc.request("state_getStorageAt", [1]))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.connections[0].closed and not state.connections[0].busy
    state.blocked = False
    assert await rpc.request("state_getStorageAt", [2]) == [2]
    assert len(state.connections) == 2
    await rpc.aclose()


async def test_close_during_read_closes_lease_when_returned(rpc, sockets):
    state, started = sockets
    state.blocked = True
    task = asyncio.create_task(rpc.request("state_getStorageAt", [1]))
    await asyncio.wait_for(started.wait(), 1)
    await rpc.aclose()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(c.closed for c in state.connections)


@pytest.mark.parametrize("method", ["author_submitExtrinsic", "state_getKeys", "bogus"])
async def test_unneeded_rpc_methods_are_rejected_without_network(rpc, sockets, method):
    state, _ = sockets
    with pytest.raises(ValidatorChainError, match="proof_rpc_method_forbidden"):
        await rpc.request(method, [])
    assert not state.connections
    await rpc.aclose()


async def test_shorter_collection_deadline_is_preserved(sockets):
    state, _ = sockets
    rpc = WeightProofRpc(
        SimpleNamespace(rpc_url="wss://proofs.example.org", collection_timeout_seconds=7)
    )
    await rpc.request("state_getReadProof", [])
    assert state.connections[0].kwargs["open_timeout"] == 7
    await rpc.aclose()


async def test_full_uid_mapping_batch_needs_two_value_requests(rpc, monkeypatch):
    block = "0x" + "ab" * 32
    keys = tuple(i.to_bytes(2, "big") for i in range(512))
    calls = []
    original = rpc.request

    async def response(method, params):
        if method == "state_queryStorageAt":
            calls.append(params)
            return [{"block": block, "changes": [[key, "0x00"] for key in params[0]]}]
        return await original(method, params)

    monkeypatch.setattr(rpc, "request", response)
    async with rpc.read_batch(block, keys):
        for key in keys:
            assert await rpc.request("state_getStorageAt", ["0x" + key.hex(), block]) == "0x00"
        with pytest.raises(ValueError, match="differs"):
            await rpc.request("state_getStorageAt", ["0xffff", block])
        with pytest.raises(ValueError, match="differs"):
            await rpc.request("state_getStorageAt", ["0x0000", "0x" + "cd" * 32])
        with pytest.raises(ValueError, match="unavailable"):
            async with rpc.read_batch(block, keys):
                pass
    assert len(calls) == 2 and all(len(params[0]) == 256 for params in calls)
    assert rpc._batch_values is None
    await rpc.aclose()


@pytest.mark.parametrize(
    "case",
    [
        "block",
        "missing",
        "duplicate",
        "extra",
        "malformed",
        "value_type",
        "value_hex",
        "value_size",
    ],
)
async def test_batch_rejects_unbound_incomplete_and_oversized_values(rpc, monkeypatch, case):
    block = "0x" + "ab" * 32
    result = [{"block": block, "changes": [["0x61", None], ["0x62", "0x00"]]}]
    if case == "block":
        result[0]["block"] = "0x" + "cd" * 32
    elif case == "missing":
        result[0]["changes"].pop()
    elif case == "duplicate":
        result[0]["changes"][1][0] = "0x61"
    elif case == "extra":
        result[0]["changes"][1][0] = "0x63"
    elif case == "malformed":
        result[0]["changes"][1] = ["0x62"]
    elif case == "value_type":
        result[0]["changes"][1][1] = 0
    elif case == "value_hex":
        result[0]["changes"][1][1] = "0x0g"
    else:
        result[0]["changes"][1][1] = "0x" + "00" * 65537

    async def response(method, params):
        assert method == "state_queryStorageAt"
        return result

    monkeypatch.setattr(rpc, "request", response)
    with pytest.raises(ValueError):
        async with rpc.read_batch(block, (b"a", b"b")):
            pytest.fail("invalid untrusted values reached proof collection")
    assert rpc._batch_values is None
    await rpc.aclose()


async def test_batch_preserves_absence_and_clears_on_consumer_failure(rpc, monkeypatch):
    block = "0x" + "ab" * 32
    original = rpc.request

    async def response(method, params):
        if method == "state_queryStorageAt":
            return [{"block": block, "changes": [["0x61", None], ["0x62", "0x"]]}]
        return await original(method, params)

    monkeypatch.setattr(rpc, "request", response)
    with pytest.raises(RuntimeError, match="proof rejected"):
        async with rpc.read_batch(block, (b"a", b"b")):
            assert await rpc.request("state_getStorageAt", ["0x61", block]) is None
            assert await rpc.request("state_getStorageAt", ["0x62", block]) == "0x"
            raise RuntimeError("proof rejected")
    assert rpc._batch_values is None
    await rpc.aclose()


async def test_cancelled_batch_drops_partial_values(rpc, monkeypatch):
    started = asyncio.Event()

    async def response(method, params):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(rpc, "request", response)

    async def read():
        async with rpc.read_batch("0x" + "ab" * 32, (b"a",)):
            pytest.fail("cancelled batch must not complete")

    task = asyncio.create_task(read())
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert rpc._batch_values is None
    await rpc.aclose()
