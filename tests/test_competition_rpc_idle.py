"""Real WebSocket lifecycle checks for persistent read-only RPC pools."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed
from websockets.protocol import State

from umi import competition_chain
from umi.competition_proof_rpc import FailoverProofRpc
from umi.competition_weight_rpc import WeightProofRpc
from umi.validator_chain import ValidatorChainError

PRIMARY = "wss://primary.example"
BACKUPS = ("wss://backup-one.example", "wss://backup-two.example")


@pytest.fixture
async def loopback_rpc(monkeypatch):
    state = SimpleNamespace(sockets=[], received=[], dials=[], drop_response=False)

    async def handler(socket):
        state.sockets.append(socket)
        try:
            async for raw in socket:
                request = json.loads(raw)
                state.received.append(request)
                if state.drop_response:
                    state.drop_response = False
                    await socket.close(code=1011, reason="test disconnect")
                else:
                    await socket.send(
                        json.dumps({"jsonrpc": "2.0", "id": 1, "result": request["params"]})
                    )
        except ConnectionClosed:
            pass

    async with serve(handler, "127.0.0.1", 0) as server:
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"

        def local_connect(endpoint, **kwargs):
            state.dials.append((endpoint, kwargs))
            return connect(url, **kwargs)

        monkeypatch.setattr(competition_chain, "websocket_connect", local_connect)
        yield state


def client(consumer, *, backups=False):
    config = SimpleNamespace(
        rpc_url=PRIMARY,
        proof_rpc_fallback_urls=BACKUPS if backups else (),
        collection_timeout_seconds=5,
    )
    if consumer == "weight":
        return WeightProofRpc(config)
    transports = tuple(
        competition_chain._RegistrationRpc(
            SimpleNamespace(rpc_url=endpoint, collection_timeout_seconds=5), persistent=True
        )
        for endpoint in (PRIMARY, *config.proof_rpc_fallback_urls)
    )
    return FailoverProofRpc(transports, timeout_seconds=5) if backups else transports[0]


def pool(rpc, method):
    transport = rpc._rpc if isinstance(rpc, WeightProofRpc) else rpc
    if isinstance(transport, FailoverProofRpc):
        transport = transport.transports[0]
    pools = (
        transport._persistent_pools
        if isinstance(transport, competition_chain._RegistrationRpc)
        else transport._pools
    )
    return pools[method]


def params(method, number):
    return (number,) if method == "chain_getBlockHash" else ("0x" + f"{number:064x}",)


@pytest.mark.parametrize("consumer", ["registration", "weight"])
@pytest.mark.parametrize("method", ["chain_getHeader", "chain_getBlockHash"])
@pytest.mark.parametrize("closure", [1000, 1011, "abort"])
async def test_idle_closed_socket_reopens_before_read(loopback_rpc, consumer, method, closure):
    state = loopback_rpc
    rpc = client(consumer)
    try:
        assert await rpc.request(method, params(method, 1)) == list(params(method, 1))
        retained = pool(rpc, method).idle[0][1]
        assert retained.state is State.OPEN
        if closure == "abort":
            state.sockets[0].transport.abort()
        else:
            await state.sockets[0].close(code=closure, reason="test idle expiry")
        await asyncio.wait_for(retained.wait_closed(), 5)
        assert retained.state is State.CLOSED
        assert await rpc.request(method, params(method, 2)) == list(params(method, 2))
        assert len(state.dials) == 2
        assert state.dials[0] == state.dials[1]
        assert retained is not pool(rpc, method).idle[0][1]
        assert await rpc.request(method, params(method, 3)) == list(params(method, 3))
        assert len(state.dials) == 2
        assert [r["params"] for r in state.received] == [list(params(method, n)) for n in (1, 2, 3)]
    finally:
        await rpc.aclose()


@pytest.mark.parametrize("consumer", ["registration", "weight"])
async def test_idle_replacement_preserves_separate_method_limits(loopback_rpc, consumer):
    state = loopback_rpc
    rpc = client(consumer)
    try:
        for method in ("state_getMetadata", "chain_getHeader"):
            await rpc.request(method, params(method, 1))
        metadata = pool(rpc, "state_getMetadata").idle[0][1]
        header = pool(rpc, "chain_getHeader").idle[0][1]
        await state.sockets[0].close()
        await metadata.wait_closed()
        await rpc.request("chain_getHeader", params("chain_getHeader", 2))
        assert len(state.dials) == 2
        assert pool(rpc, "chain_getHeader").idle[0][1] is header
        await rpc.request("state_getMetadata", params("state_getMetadata", 2))
        assert [kw["max_size"] for _, kw in state.dials] == [33 * 1024**2, 1024**2, 33 * 1024**2]
        assert state.dials[0] == state.dials[2]
    finally:
        await rpc.aclose()


@pytest.mark.parametrize("consumer", ["registration", "weight"])
@pytest.mark.parametrize("during", ["send", "recv"])
@pytest.mark.parametrize("backups", [False, True])
async def test_close_after_checkout_preserves_existing_failure_or_failover(
    loopback_rpc, monkeypatch, consumer, during, backups
):
    state = loopback_rpc
    rpc = client(consumer, backups=backups)
    method = "chain_getHeader"
    try:
        await rpc.request(method, params(method, 1))
        retained = pool(rpc, method).idle[0][1]
        assert retained.state is State.OPEN
        if during == "send":
            send = retained.send

            async def close_before_send(raw):
                # Lease checkout has already accepted this OPEN socket.
                assert retained.state is State.OPEN
                await retained.close(code=1011, reason="test send race")
                return await send(raw)

            monkeypatch.setattr(retained, "send", close_before_send)
        else:
            state.drop_response = True
        if backups:
            assert await rpc.request(method, params(method, 2)) == list(params(method, 2))
            assert [endpoint for endpoint, _ in state.dials] == [PRIMARY, BACKUPS[0]]
            assert state.received[-1]["params"] == list(params(method, 2))
        else:
            with pytest.raises(ValidatorChainError) as caught:
                await rpc.request(method, params(method, 2))
            assert caught.value.reason_code == "proof_rpc_failed"
            assert caught.value.rpc_transport_error == "connection_closed"
            assert isinstance(caught.value.__cause__, ConnectionClosed)
            assert len(state.dials) == 1
            assert not pool(rpc, method).idle
            assert await rpc.request(method, params(method, 3)) == list(params(method, 3))
            assert [endpoint for endpoint, _ in state.dials] == [PRIMARY, PRIMARY]
        assert retained.state is State.CLOSED
        assert not pool(rpc, method).idle or pool(rpc, method).idle[0][1] is not retained
        expected = [list(params(method, 1))]
        if during == "recv":
            expected.append(list(params(method, 2)))
        expected.append(list(params(method, 2 if backups else 3)))
        assert [r["params"] for r in state.received] == expected
    finally:
        await rpc.aclose()


async def test_cancellation_during_stale_cleanup_detaches_lease(monkeypatch):
    started = asyncio.Event()
    old = SimpleNamespace(state=State.CLOSING)
    closed = []

    class ClosingContext:
        async def __aexit__(self, *args):
            closed.append(old)
            started.set()
            await asyncio.Future()

    monkeypatch.setattr(
        competition_chain,
        "websocket_connect",
        lambda *args, **kwargs: pytest.fail("dialed after cancellation"),
    )
    connections = competition_chain._BatchConnections(1)
    connections.idle.append((ClosingContext(), old))
    leases = []

    async def checkout():
        async with connections.lease() as lease:
            leases.append(lease)
            async with lease.connect(PRIMARY):
                pytest.fail("yielded stale socket")

    task = asyncio.create_task(checkout())
    try:
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert leases[0].connection is None
        assert not connections.idle
        assert closed == [old]
        async with connections.lease() as lease:
            assert lease.connection is None
    finally:
        if not task.done():
            task.cancel()
        await connections.close()
