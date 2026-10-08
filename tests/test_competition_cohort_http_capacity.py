"""Real connection-pool contention: remote waits must leave control traffic room."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_review_boot import _http_limits


@pytest.mark.parametrize("remote_slots", [8, 16, 32, None])
async def test_waiting_translates_leave_capacity_for_owner_history(remote_slots):
    config = SimpleNamespace(
        endpoint=SimpleNamespace(concurrency=remote_slots),
        benchmark=SimpleNamespace(concurrency=4),
    )
    slots = remote_slots or config.benchmark.concurrency
    entered, release = asyncio.Event(), asyncio.Event()
    waiting = 0
    connections = set()

    async def serve(reader, writer):
        nonlocal waiting
        task = asyncio.current_task()
        connections.add(task)
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            if request.split(b" ", 2)[1] == b"/translate":
                waiting += 1
                if waiting == slots:
                    entered.set()
                await release.wait()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            connections.discard(task)

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    async with (
        server,
        httpx.AsyncClient(trust_env=False, limits=_http_limits(config), timeout=2400) as client,
    ):
        translates = [asyncio.create_task(client.get(origin + "/translate")) for _ in range(slots)]
        try:
            await asyncio.wait_for(entered.wait(), timeout=120)
            response = await asyncio.wait_for(client.get(origin + "/history"), timeout=120)
            assert response.status_code == 200
            assert not release.is_set()
            assert all(not task.done() for task in translates)
        finally:
            release.set()
            await asyncio.wait_for(asyncio.gather(*translates), timeout=120)
            while connections:
                await asyncio.gather(*tuple(connections))


def test_model_only_host_keeps_existing_http_budget():
    limits = _http_limits(SimpleNamespace(endpoint=None, benchmark=None))
    assert limits.max_connections == 16
    assert limits.max_keepalive_connections == 8
