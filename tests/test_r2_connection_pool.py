"""Qualify real connection reuse and cancellation without production R2 access."""

import asyncio

import httpx
import pytest

from umi.r2_multipart import R2MultipartClient

from .test_r2_multipart import AT, KEY, signer


class Transport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.requests = []
        self.closes = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.release.set()

    async def handle_async_request(self, request):
        self.requests.append(request)
        self.entered.set()
        await self.release.wait()
        return httpx.Response(200, headers={"Content-Length": "7", "ETag": '"generation"'})

    async def aclose(self):
        self.closes += 1


@pytest.mark.asyncio
async def test_nested_and_concurrent_scopes_close_only_after_last_borrower():
    transport = Transport()
    client = R2MultipartClient(signer(), transport=transport)
    async with client.connection_scope():
        async with client.connection_scope():
            heads = await asyncio.gather(*(client.head(KEY, at=AT) for _ in range(8)))
            assert all(head.etag == "generation" for head in heads)
        assert transport.closes == 0
        entered, release = asyncio.Event(), asyncio.Event()

        async def another_scope():
            async with client.connection_scope():
                entered.set()
                await release.wait()
                await client.head(KEY, at=AT)

        task = asyncio.create_task(another_scope())
        await entered.wait()
    assert transport.closes == 0
    release.set()
    await task
    assert transport.closes == 1
    assert len(transport.requests) == 9
    assert len({r.headers["authorization"] for r in transport.requests}) == 1


@pytest.mark.asyncio
async def test_repeated_cancellation_waits_for_active_response_then_closes():
    transport = Transport()
    transport.release.clear()
    client = R2MultipartClient(signer(), transport=transport)
    closing = asyncio.Event()
    requests = []

    async def owner():
        async with client.connection_scope():
            requests.append(asyncio.create_task(client.head(KEY, at=AT)))
            await transport.entered.wait()
            closing.set()

    task = asyncio.create_task(owner())
    await closing.wait()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    assert transport.closes == 0
    with pytest.raises(RuntimeError, match="draining"):
        await client.head(KEY, at=AT)
    transport.release.set()
    assert (await requests[0]).etag == "generation"
    with pytest.raises(asyncio.CancelledError):
        await task
    assert transport.closes == 1


@pytest.mark.asyncio
async def test_unscoped_compatibility_and_failed_mutation_are_not_retried():
    transport = Transport()
    client = R2MultipartClient(signer(), transport=transport)
    await client.head(KEY, at=AT)
    await client.head(KEY, at=AT)
    assert transport.closes == 2
    attempts = []

    async def failed(request):
        attempts.append(request.method)
        raise httpx.ReadError("provider disconnected after receiving request", request=request)

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(failed))
    async with client.connection_scope():
        with pytest.raises(OSError, match="transport unavailable"):
            await client.create(KEY, at=AT)
    assert attempts == ["POST"]


@pytest.mark.asyncio
async def test_scope_refuses_cross_loop_use_before_transport_access():
    transport = Transport()
    client = R2MultipartClient(signer(), transport=transport)
    async with client.connection_scope():
        with pytest.raises(RuntimeError, match="another event loop"):
            await asyncio.to_thread(lambda: asyncio.run(client.head(KEY, at=AT)))
        assert not transport.requests
        assert (await client.head(KEY, at=AT)).etag == "generation"
    assert transport.closes == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("peer_closes", [False, True])
async def test_real_http_keepalive_reuse_and_peer_close(monkeypatch, peer_closes):
    connections = []
    tasks = set()
    requests = []

    async def serve(reader, writer):
        connections.append(writer)
        task = asyncio.current_task()
        tasks.add(task)
        try:
            while True:
                try:
                    raw = await reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError:
                    break
                requests.append(raw)
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nETag: "generation"\r\n\r\n')
                await writer.drain()
                if peer_closes:
                    break
        finally:
            writer.close()
            await writer.wait_closed()
            tasks.discard(task)

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr(
        type(signer()), "object_url", lambda *_a, **_k: f"http://127.0.0.1:{port}/object"
    )
    try:
        client = R2MultipartClient(signer())
        async with client.connection_scope():
            for _ in range(3):
                assert (await client.head(KEY, at=AT)).etag == "generation"
                # Let a peer-initiated idle close reach the client's socket.
                await asyncio.sleep(0.01)
        await asyncio.sleep(0)
        assert len(requests) == 3
        assert all(raw.startswith(b"HEAD /object HTTP/1.1") for raw in requests)
        assert len(connections) == (3 if peer_closes else 1)
    finally:
        server.close()
        await server.wait_closed()
        for writer in connections:
            writer.close()
        if tasks:
            await asyncio.gather(*tasks)
