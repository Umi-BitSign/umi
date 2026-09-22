"""Exercise actual serving defaults with idle HTTP/1.1 keep-alive sockets."""

import asyncio
import socket
import time
from contextlib import AsyncExitStack

import httpx
import pytest
import uvicorn

from umi import competition_rounds as rounds
from umi import competition_service_supervision as supervision
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_rounds import chain_config as chain_config
from .test_competition_rounds import policy as policy
from .test_competition_rounds import preparation as preparation
from .test_competition_rounds import setup as setup


@pytest.mark.asyncio
async def test_serving_defaults_admit_native_query_with_four_idle_keepalive_sockets(
    setup, monkeypatch
):
    s = setup
    assert (await s.coordinator.cycle())["prepared"] == 1
    captured = {}

    def capture(app, **options):
        captured.update(app=app, **options)

    # Capture the exact public serving entry point's options, then run its
    # native app on a reserved loopback socket. Only fixture finality is used.
    monkeypatch.setattr(supervision, "serve_with_finality_supervision", capture)
    monkeypatch.setattr(rounds, "create_round_app", lambda *a, **kw: s.app)
    rounds.serve_rounds(s.config, s.policy)
    options = {**captured, "host": "127.0.0.1", "port": 0, "lifespan": "off", "log_level": "error"}
    server = uvicorn.Server(uvicorn.Config(**options))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(captured["backlog"])
    port = listener.getsockname()[1]
    serving = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if serving.done():
                    await serving
                    raise AssertionError("socket server exited before startup")
                await asyncio.sleep(0.005)

        async def query(client, *, stale=False):
            worker = s.workers[0]
            query = rounds.RoundQuery(
                schema="umi-round-query/1",
                policy_sha256=digest(s.policy),
                hotkey=worker.config.evaluator_hotkey,
                nonce_unix_ns=str(time.time_ns() - (31_000_000_000 if stale else 0)),
            )
            signed = rounds.SignedRoundQuery(
                query=query, signature=sign_object(query, worker.wallet)
            )
            response = await client.post(
                rounds.ROUTE,
                content=canonical_json_bytes(signed),
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                reply = rounds.RoundReply.model_validate_json(response.content)
                assert reply.query_sha256 == digest(query)
                assert len(reply.proposals) == 1
            return response.status_code

        async with AsyncExitStack() as stack:
            clients = [
                await stack.enter_async_context(
                    httpx.AsyncClient(
                        base_url=f"http://127.0.0.1:{port}",
                        trust_env=False,
                        timeout=2,
                        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
                    )
                )
                for _ in range(5)
            ]
            for count, client in enumerate(clients[:4], 1):
                status = await query(client)
                assert status == 200, (
                    f"idle keep-alive connection {count} starved admission: {status}"
                )
                assert len(server.server_state.connections) == count
            # Four completed native requests now occupy four idle connections;
            # a fifth independent evaluator connection must still reach the app.
            assert await query(clients[4]) == 200
            assert len(server.server_state.connections) == 5
            assert await query(clients[4], stale=True) == 401
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, timeout=5)
        listener.close()
