"""Real sockets exercise the explicit local connection, never a public service."""

from __future__ import annotations

import asyncio
import copy
import socket
from contextlib import asynccontextmanager

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from starlette.responses import RedirectResponse

from umi.competition_settlement_transport import (
    ROUTE,
    SettlementSigningClient,
    _settlement_connection,
    attach_settlement_route,
    request_settlement,
)

from .test_competition_settlement_delivery import (
    chain_config as chain_config,
)
from .test_competition_settlement_delivery import (
    package,
    signed_query,
)
from .test_competition_settlement_delivery import (
    package_limits as package_limits,
)
from .test_competition_settlement_delivery import (
    policy as policy,
)
from .test_competition_settlement_delivery import (
    release_identity as release_identity,
)
from .test_competition_settlement_delivery import (
    replay_limits as replay_limits,
)
from .test_competition_settlement_delivery import (
    setup as setup,
)
from .test_competition_settlement_delivery import (
    signing_setup as signing_setup,
)


@asynccontextmanager
async def listening(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            if task.done():
                await task
                raise AssertionError("fixture server exited")
            await asyncio.sleep(0.01)
        assert server.started
        yield port
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=3)
        sock.close()


@pytest.mark.parametrize("port", [True, False, 0, -1, 65536, 1.5, "8000", "localhost"])
def test_only_literal_integer_loopback_ports(port):
    with pytest.raises(ValueError, match="loopback port"):
        _settlement_connection("https://rounds.example", port, None)


def test_public_identity_and_local_transport_are_not_substitutable():
    assert _settlement_connection("https://rounds.example", None, None) == "https://rounds.example"
    assert _settlement_connection("https://rounds.example", 8000, None) == "http://127.0.0.1:8000"
    with pytest.raises(ValueError):
        _settlement_connection("http://rounds.example", 8000, None)
    with pytest.raises(ValueError, match="alternate HTTP transport"):
        _settlement_connection("https://rounds.example", 8000, httpx.MockTransport(lambda _: None))


@pytest.mark.asyncio
@pytest.mark.parametrize("replay_limits", [5_000_000, 256 * 1024**2], indirect=True)
async def test_native_local_discovery_votes_and_package(setup, tmp_path, monkeypatch):
    s = setup
    assert (await s.coordinator.cycle())["settlement_prepared"] == 1
    app = FastAPI()
    attach_settlement_route(app, s.queue)
    # An ambient proxy must not see local settlement traffic.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    async with listening(app) as port:
        for i, signer in enumerate(s.signers):
            worker = copy.copy(signer.worker)
            worker.config = copy.copy(worker.config)
            worker.config.state_directory = str(tmp_path / f"local-signer-{i}")
            client = SettlementSigningClient(
                worker,
                "https://rounds.example",
                signer.cutoffs,
                s.store,
                limits=s.limits,
                loopback_port=port,
            )
            # The shared fixture isolates execution quality; transport, signatures,
            # certificates, current finality and replay remain native validators.
            monkeypatch.setattr(client.signer, "_local_evidence", signer._local_evidence)
            assert await client.sync_once() == {"endorsed": 1, "held": 0}
            assert client.signer.journal.get("source", "origin") == {
                "origin": "https://rounds.example",
                "settlement_loopback_port": port,
            }
            # Restart with the same pin is allowed; changing/removing it fails closed.
            SettlementSigningClient(
                worker,
                client.origin,
                signer.cutoffs,
                s.store,
                limits=s.limits,
                loopback_port=port,
            )
            for other in (None, port % 65535 + 1):
                with pytest.raises(ValueError):
                    SettlementSigningClient(
                        worker,
                        client.origin,
                        signer.cutoffs,
                        s.store,
                        limits=s.limits,
                        loopback_port=other,
                    )
        prepared, verified = package(s)
        assert len(verified.settlement_certificate.signatures) == 2
        assert verified.retained_settlement == s.settlement
        assert not prepared.chain_submission_authorized


@pytest.mark.asyncio
async def test_local_connection_rejects_redirects_closed_ports_and_expired_queries(setup):
    s = setup
    redirect_app = FastAPI()

    @redirect_app.post(ROUTE)
    async def redirect():
        return RedirectResponse("https://rounds.example" + ROUTE, status_code=302)

    async with listening(redirect_app) as port:
        with pytest.raises(ValueError, match="request rejected"):
            await request_settlement("https://rounds.example", signed_query(s), loopback_port=port)
    # No fallback to the public coordinator when the pinned listener is absent.
    with pytest.raises(ValueError, match="request failed"):
        await request_settlement("https://rounds.example", signed_query(s), loopback_port=port)
    app = FastAPI()
    attach_settlement_route(app, s.queue)
    async with listening(app) as port:
        with pytest.raises(ValueError, match="request rejected"):
            await request_settlement(
                "https://rounds.example",
                signed_query(s, offset=-31_000_000_000),
                loopback_port=port,
            )
