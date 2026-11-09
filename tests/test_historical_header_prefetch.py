"""Parallel retrieval cannot replace owned, ordered ancestry verification."""

import asyncio
import json

import pytest

from umi.historical_header_prefetch import HistoricalHeaderPrefetch
from umi.historical_header_recovery import HistoricalHeaderRecovery, HistoricalHeaderRecoveryPending

from .test_competition_chain import pooled_sockets as pooled_sockets
from .test_historical_header_recovery import chain_config as chain_config
from .test_historical_header_recovery import policy as policy
from .test_historical_header_recovery import walk as walk


class Transport:
    historical_header_prefetch_concurrency = 4

    def __init__(self, walk):
        self.walk = walk
        self.calls = []
        self.active = self.peak = 0

    async def request(self, method, params):
        self.calls.append((method, params))
        self.active += 1
        self.peak = max(self.active, self.peak)
        try:
            await asyncio.sleep(0.001)
            if method == "chain_getBlockHash":
                return self.walk.by_height[params[0]]
            assert method == "chain_getHeader"
            return self.walk.headers[params[0]]
        finally:
            self.active -= 1


@pytest.fixture(autouse=True)
def short_parallel_interval(monkeypatch):
    monkeypatch.setattr(HistoricalHeaderPrefetch, "minimum_distance", 8)


async def complete(service, w, transport):
    for _ in range(100):
        try:
            return await service.recover(w.anchor, w.target, transport.request)
        except HistoricalHeaderRecoveryPending:
            continue
    pytest.fail("owned ancestry did not finish")


async def test_parallel_headers_verify_in_order_and_retain_exact_serial_result(walk):
    w = walk
    transport = Transport(w)
    service = HistoricalHeaderRecovery(w.connect)
    assert (await complete(service, w, transport)).snapshot == w.target
    assert 1 < transport.peak <= 4
    assert transport.active == 0
    with w.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone()[0] == 40
    # Restart checks the retained hints without even a height-lookup RPC.
    before = len(transport.calls)
    restarted = HistoricalHeaderRecovery(w.connect, batch_size=9)
    assert (await complete(restarted, w, transport)).snapshot == w.target
    assert len(transport.calls) == before


@pytest.mark.parametrize("failure", ["other_fork", "unavailable", "malformed_hash"])
async def test_speculative_lookup_falls_back_to_exact_committed_parent(walk, failure):
    class FailingTransport(Transport):
        async def request(self, method, params):
            if method == "chain_getBlockHash":
                if failure == "unavailable":
                    raise OSError("height lookup unavailable")
                return walk.target.block_hash if failure == "other_fork" else "0x00"
            return await super().request(method, params)

    transport = FailingTransport(walk)
    service = HistoricalHeaderRecovery(walk.connect)
    assert (await complete(service, walk, transport)).snapshot == walk.target
    assert transport.active == 0
    assert service.telemetry.latest["completed_links"] == 40


async def test_bad_prefetched_parent_cannot_checkpoint_future_or_invalid_links(walk):
    bad_height = walk.anchor.height - 4

    class CorruptTransport(Transport):
        async def request(self, method, params):
            if method == "chain_getHeader" and params == (walk.by_height[bad_height],):
                return walk.headers[walk.target.block_hash]
            return await super().request(method, params)

    transport = CorruptTransport(walk)
    service = HistoricalHeaderRecovery(walk.connect)
    with pytest.raises(ValueError, match="committed parent"):
        await service.recover(walk.anchor, walk.target, transport.request)
    with walk.connect() as db:
        hashes = {row[0] for row in db.execute("SELECT hash FROM historical_header_hints")}
    assert hashes == {walk.by_height[h] for h in range(bad_height + 1, walk.anchor.height)}
    assert transport.active == 0
    assert service.telemetry.latest["state"] == "repair_required"


async def test_malformed_committed_header_is_not_retried_as_an_availability_failure(walk):
    class MalformedTransport(Transport):
        bad_calls = 0

        async def request(self, method, params):
            if method == "chain_getHeader" and params == (walk.by_height[walk.anchor.height - 4],):
                self.bad_calls += 1
                return {"number": "malformed"}
            return await super().request(method, params)

    transport = MalformedTransport(walk)
    service = HistoricalHeaderRecovery(walk.connect)
    with pytest.raises(ValueError):
        await service.recover(walk.anchor, walk.target, transport.request)
    assert transport.bad_calls == 1
    assert service.telemetry.latest["completed_links"] == 3
    assert transport.active == 0


async def test_repeated_cancellation_drains_parallel_fetches_before_owner_release(walk):
    entered, cleanup, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    active = 0

    class BlockingTransport(Transport):
        async def request(self, method, params):
            nonlocal active
            if method == "chain_getHeader" and params[0] in {
                walk.by_height[h] for h in range(walk.target.block_number, walk.anchor.height - 3)
            }:
                active += 1
                if active == 4:
                    entered.set()
                try:
                    await asyncio.Future()
                finally:
                    cleanup.set()
                    await release.wait()
                    active -= 1
            return await super().request(method, params)

    transport = BlockingTransport(walk)
    service = HistoricalHeaderRecovery(walk.connect)
    task = asyncio.create_task(service.recover(walk.anchor, walk.target, transport.request))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        await asyncio.wait_for(cleanup.wait(), 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and service._lock.locked()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        assert active == transport.active == 0
        assert not service._lock.locked()
        assert service._retained_hints is None
        assert service.telemetry.latest["completed_links"] == 3
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_bounded_pass_drains_future_fetches_and_restart_keeps_verified_links(walk):
    transport = Transport(walk)
    service = HistoricalHeaderRecovery(walk.connect, batch_size=7)
    with pytest.raises(HistoricalHeaderRecoveryPending):
        await service.recover(walk.anchor, walk.target, transport.request)
    assert transport.active == 0
    with walk.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone()[0] == 7
    restarted = HistoricalHeaderRecovery(walk.connect)
    assert (await complete(restarted, walk, transport)).snapshot == walk.target
    assert transport.active == 0


async def test_generic_callback_keeps_serial_hash_only_requests(walk):
    service = HistoricalHeaderRecovery(walk.connect)
    assert (await service.recover(walk.anchor, walk.target, walk.request)).snapshot == walk.target
    assert len(walk.calls) == len(set(walk.calls)) == 40


@pytest.mark.parametrize("method", ["chain_getHeader", "chain_getBlockHash"])
async def test_selected_transport_bounds_queued_header_reads_and_drains_cancellation(
    chain_config, pooled_sockets, method
):
    from umi.competition_chain import _RegistrationRpc

    state, entered = pooled_sockets
    state.blocked, state.started_after = True, 4
    transport = _RegistrationRpc(chain_config, persistent=True)
    tasks = [
        asyncio.create_task(transport.request(method, ("0x" + f"{i:064x}",))) for i in range(8)
    ]
    try:
        await asyncio.wait_for(entered.wait(), 5)
        await asyncio.sleep(0)
        assert state.requests == len(state.connections) == 4
        assert all(connection.max_size == 1024**2 for connection in state.connections)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await transport.aclose()
    assert all(connection.closed and not connection.socket.busy for connection in state.connections)


async def test_native_transport_and_ordered_recovery_over_real_websockets(
    chain_config, walk, monkeypatch
):
    from websockets.asyncio.client import connect
    from websockets.asyncio.server import serve
    from websockets.protocol import State

    from umi.competition_chain import _RegistrationRpc

    sockets, ceilings = [], []
    active = peak = 0

    async def handler(socket):
        nonlocal active, peak
        sockets.append(socket)
        async for raw in socket:
            request = json.loads(raw)
            assert request["id"] == 1
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.005)
                method, arg = request["method"], request["params"][0]
                if method == "chain_getBlockHash":
                    result = walk.by_height[arg]
                else:
                    assert method == "chain_getHeader"
                    result = walk.headers[arg]
                await socket.send(json.dumps(dict(jsonrpc="2.0", id=1, result=result)))
            finally:
                active -= 1

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]

        def routed(endpoint, **kwargs):
            assert endpoint == chain_config.rpc_url
            ceilings.append(kwargs["max_size"])
            return connect(f"ws://127.0.0.1:{port}", **kwargs)

        monkeypatch.setattr("umi.competition_chain.websocket_connect", routed)
        transport = _RegistrationRpc(chain_config, persistent=True)
        try:
            service = HistoricalHeaderRecovery(walk.connect)
            assert (await complete(service, walk, transport)).snapshot == walk.target
        finally:
            await transport.aclose()
    assert 1 < peak <= 4
    assert active == 0 and all(socket.state is State.CLOSED for socket in sockets)
    assert ceilings and set(ceilings) == {1024**2}
