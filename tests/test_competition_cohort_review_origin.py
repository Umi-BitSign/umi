"""Private loopback delivery without DNS, proxy traversal or weaker evidence."""

import asyncio
import errno
import socket
from contextlib import asynccontextmanager, contextmanager

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from starlette.responses import RedirectResponse

from umi.competition_cohort_review_http import (
    CohortReviewPeerConfig,
    PhaseReviewHTTPClient,
    PhaseReviewHTTPUnavailable,
    phase_review_routes,
)
from umi.competition_cohort_review_origin import private_review_origin
from umi.protocol import StrictProtocolModel, canonical_json_bytes

from .test_open_competition import wallet

ACCEPTED = (
    "https://owner.example",
    "https://owner.example:8443/",
    "https://127.0.0.1:18090",
    "http://127.0.0.1:18090",
    "http://127.0.0.1:80/",
    "http://[::1]:19579",
    "http://[::1]:65535/",
)
REJECTED = (
    "http://owner.example:18090",
    "http://localhost:18090",
    "http://127.0.0.1",
    "http://[::1]",
    "http://0.0.0.0:18090",
    "http://192.168.1.1:18090",
    "http://127.0.0.2:18090",
    "http://127.1:18090",
    "http://2130706433:18090",
    "http://[::ffff:127.0.0.1]:18090",
    "http://[0:0:0:0:0:0:0:1]:18090",
    "http://[::1%25lo]:18090",
    "http://127.0.0.1:0",
    "http://127.0.0.1:65536",
    "http://127.0.0.1:018090",
    "http://user:secret@127.0.0.1:18090",
    "http://127.0.0.1:18090/path",
    "http://127.0.0.1:18090//",
    "http://127.0.0.1:18090?query=1",
    "http://127.0.0.1:18090?",
    "http://127.0.0.1:18090#fragment",
    "http://127.0.0.1:18090#",
    "http://127.0.0.1:18090\n",
    "https://user:secret@owner.example",
    "https://owner.example/path",
    "https://owner.example?query=1",
    "https://owner.example#fragment",
)
TOKEN = "private-review-token-" * 3


class ReviewRequest(StrictProtocolModel):
    challenge: str


@pytest.mark.parametrize("origin", ACCEPTED)
async def test_private_peer_and_client_accept_explicit_origin_without_rewriting_config(origin):
    peer = CohortReviewPeerConfig(
        signer=wallet("Charlie").hotkey.ss58_address,
        origin=origin,
        token_file="/private/reviewer-token",
    )
    raw = canonical_json_bytes(peer)
    assert CohortReviewPeerConfig.model_validate_json(raw).origin == origin
    assert canonical_json_bytes(CohortReviewPeerConfig.model_validate_json(raw)) == raw
    async with httpx.AsyncClient(trust_env=False) as client:
        exchange = PhaseReviewHTTPClient(client, origin, token=TOKEN, path="/review")
        assert exchange.url == str(private_review_origin(origin).copy_with(path="/review"))


@pytest.mark.parametrize("origin", REJECTED)
async def test_private_peer_and_client_reject_unsafe_origin_before_sending(origin):
    with pytest.raises(ValueError):
        private_review_origin(origin)
    with pytest.raises(ValueError):
        CohortReviewPeerConfig(
            signer=wallet("Charlie").hotkey.ss58_address,
            origin=origin,
            token_file="/private/reviewer-token",
        )
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(ValueError):
            PhaseReviewHTTPClient(client, origin, token=TOKEN, path="/review")


@asynccontextmanager
async def local_listener(app, host):
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    with socket.socket(family) as listener:
        try:
            listener.bind((host, 0))
        except OSError as error:
            if host == "::1" and error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                pytest.skip("IPv6 loopback is unavailable")
            raise
        port = listener.getsockname()[1]

        class Server(uvicorn.Server):
            @contextmanager
            def capture_signals(self):
                yield

        server = Server(uvicorn.Config(app, log_config=None, access_log=False, lifespan="off"))
        task = asyncio.create_task(server.serve(sockets=[listener]))

        async def started():
            while not server.started:
                if task.done():
                    await task
                    raise AssertionError("private listener exited before startup")
                await asyncio.sleep(0.01)

        try:
            await asyncio.wait_for(started(), 5)
            yield f"http://{'[::1]' if host == '::1' else host}:{port}"
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 5)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_real_loopback_preserves_auth_bounds_redirect_refusal_and_proxy_isolation(
    host, monkeypatch
):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    entered, release = asyncio.Event(), asyncio.Event()
    calls, redirected = [], []

    class Exporter:
        maximum_bytes = 4096
        timeout_seconds = 2

        async def respond(self, request):
            calls.append(request.challenge)
            if request.challenge == "delayed":
                entered.set()
                await release.wait()
            return canonical_json_bytes(request)

    app = FastAPI()
    app.include_router(
        phase_review_routes(Exporter(), token=TOKEN, path="/review", request_model=ReviewRequest)
    )

    @app.post("/redirect")
    async def redirect():
        return RedirectResponse("/stolen", status_code=307)

    @app.post("/stolen")
    async def stolen():
        redirected.append(True)
        return {}

    async with (
        local_listener(app, host) as origin,
        httpx.AsyncClient(trust_env=False, follow_redirects=True) as client,
    ):
        wrong = PhaseReviewHTTPClient(client, origin, token="wrong-token-" * 4, path="/review")
        with pytest.raises(PhaseReviewHTTPUnavailable) as error:
            await wrong(ReviewRequest(challenge="unauthorized"))
        assert error.value.reason_code == "phase_owner_http_401"
        assert calls == []
        exchange = PhaseReviewHTTPClient(
            client, origin, token=TOKEN, path="/review", maximum_bytes=1024, timeout_seconds=2
        )
        request = ReviewRequest(challenge="exact-bytes")
        assert await exchange(request) == canonical_json_bytes(request)
        delayed = asyncio.create_task(exchange(ReviewRequest(challenge="delayed")))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert not delayed.done()
        finally:
            release.set()
            result = await delayed
        assert result == canonical_json_bytes(ReviewRequest(challenge="delayed"))
        with pytest.raises(ValueError, match="byte bound"):
            await exchange(ReviewRequest(challenge="x" * 2000))
        redirecting = PhaseReviewHTTPClient(client, origin, token=TOKEN, path="/redirect")
        with pytest.raises(PhaseReviewHTTPUnavailable) as error:
            await redirecting(request)
        assert error.value.reason_code == "phase_owner_http_307"
        assert redirected == []
