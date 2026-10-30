"""Real transport recovery after cancellation at connection cleanup.

The raw-cancellation arm reproduces the dependency failure; the owned-scope arm
must serve the next request with the same one-connection pool. No live services
or database files are used. The pause only selects a real cleanup checkpoint.
"""

import asyncio

import httpx
import pytest
from httpcore._async.http11 import AsyncHTTP11Connection

from umi.competition_cohort_observation import observe_http
from umi.concurrency import wait_for_owned


@pytest.mark.parametrize("failure_stage", ["eof", "body_error", "headers_error"])
@pytest.mark.parametrize("scoped", [False, True], ids=["raw_reproducer", "owned_scope"])
async def test_cleanup_cancellation_recovers_real_connection_pool(
    monkeypatch, failure_stage, scoped
):
    closing, release = asyncio.Event(), asyncio.Event()
    paused = False
    original_close = AsyncHTTP11Connection._response_closed

    async def paused_close(connection):
        nonlocal paused
        if not paused:
            paused = True
            closing.set()
            # This is inside HTTPCore's existing AnyIO shield. Raw asyncio
            # cancellation bypasses that shield; cooperative cancellation does not.
            await release.wait()
        await original_close(connection)

    monkeypatch.setattr(AsyncHTTP11Connection, "_response_closed", paused_close)
    handlers = set()
    received = 0

    async def serve(reader, writer):
        nonlocal received
        try:
            await reader.readuntil(b"\r\n\r\n")
            received += 1
            if received == 1 and failure_stage == "headers_error":
                raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            else:
                length = b"10" if received == 1 and failure_stage == "body_error" else b"2"
                raw = (
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                    + length
                    + b"\r\n\r\n{}"
                )
            writer.write(raw)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    def connect(reader, writer):
        task = asyncio.create_task(serve(reader, writer))
        handlers.add(task)
        task.add_done_callback(handlers.discard)

    server = await asyncio.start_server(connect, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    async with (
        server,
        httpx.AsyncClient(trust_env=False, limits=httpx.Limits(max_connections=1)) as client,
    ):

        async def consume():
            async with client.stream("GET", origin, timeout=2) as response:
                return await response.aread()

        wait = observe_http if scoped else wait_for_owned
        request = asyncio.create_task(wait(consume(), timeout=10))
        try:
            await asyncio.wait_for(closing.wait(), 2)
            request.cancel()
            await asyncio.sleep(0)
            if scoped:
                for _ in range(3):
                    request.cancel()
                    await asyncio.sleep(0)
                assert not request.done(), "transport cleanup must remain owned"
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(request, 2)

            if scoped:
                response = await client.get(origin, timeout=1)
                assert response.status_code == 200 and response.content == b"{}"
                assert received == 2
                assert not client._transport._pool._requests
            else:
                with pytest.raises(httpx.PoolTimeout):
                    await client.get(origin, timeout=0.05)
                assert received == 1, "leaked slot prevents even a second connection"
        finally:
            release.set()
            request.cancel()
            await asyncio.gather(request, return_exceptions=True)
            if handlers:
                await asyncio.gather(*handlers)
