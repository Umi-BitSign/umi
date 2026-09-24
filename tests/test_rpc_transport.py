from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from functools import partial
from types import SimpleNamespace

import pytest
from bittensor._transport.errors import SubstrateRequestException
from bittensor._transport.rpc import RpcSession
from websockets.asyncio.server import serve
from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

from umi import rpc_bittensor, rpc_transport
from umi.competition_chain import _RegistrationRpc
from umi.competition_weight_rpc import WeightProofRpc

PRIMARY = "wss://original.example"
PAID = "wss://paid.example/rpc"
BACKUPS = ("wss://backup-one.example", "wss://backup-two.example")
TOKEN = "private-example-token"


@pytest.fixture
def route(tmp_path, monkeypatch):
    key = tmp_path / "provider.key"
    key.write_text(TOKEN + "\n")
    key.chmod(0o600)
    path = tmp_path / "transport.json"
    path.write_text(
        json.dumps(
            {
                "schema": "umi-rpc-transport/1",
                "routes": [
                    {
                        "source": PRIMARY,
                        "endpoint": PAID,
                        "authorization_file": key.name,
                    }
                ],
            }
        )
    )
    path.chmod(0o600)
    monkeypatch.setenv(rpc_transport.CONFIG_ENV, str(path))
    return path, key


def test_routes_are_opt_in_and_do_not_send_headers_to_backups(route, monkeypatch):
    calls = []
    monkeypatch.setattr(
        rpc_transport, "connect", lambda endpoint, **kwargs: calls.append((endpoint, kwargs))
    )
    monkeypatch.setattr(
        rpc_transport,
        "_PrivateConnect",
        lambda endpoint, **kwargs: calls.append((endpoint, kwargs)),
    )
    for endpoint in (PRIMARY, *BACKUPS):
        rpc_transport.websocket_connect(endpoint, max_size=123, proxy=None)
    assert [x[0] for x in calls] == [PAID, *BACKUPS]
    assert calls[0][1]["additional_headers"] == {"Authorization": TOKEN}
    assert all("additional_headers" not in c[1] for c in calls[1:])
    assert all(c[1]["max_size"] == 123 and c[1]["proxy"] is None for c in calls)
    monkeypatch.delenv(rpc_transport.CONFIG_ENV)
    rpc_transport.websocket_connect(PRIMARY, max_size=12)
    assert calls[-1] == (PRIMARY, {"max_size": 12})


@pytest.mark.parametrize("status", [301, 307, 401, 429, 503])
async def test_authenticated_handshake_never_redirects_or_logs_credentials(route, caplog, status):
    caplog.set_level(logging.DEBUG)
    connection = rpc_transport.websocket_connect(PRIMARY)
    assert connection.additional_headers == {"Authorization": TOKEN}
    connection.logger.debug("Authorization: %s", TOKEN)
    response = Response(
        status,
        TOKEN,
        Headers({"Location": "wss://other.example/" + TOKEN, "Retry-After": "15"}),
        body=TOKEN.encode(),
    )
    rejected = connection.process_redirect(InvalidStatus(response))
    assert isinstance(rejected, InvalidStatus)
    assert rejected.response.status_code == status
    assert dict(rejected.response.headers) == {"retry-after": "15"}
    assert TOKEN not in caplog.text + str(rejected)


@pytest.mark.parametrize("fault", ["missing", "public", "symlink", "newline", "oversize"])
def test_bad_credentials_fail_without_exposing_contents(route, fault):
    _, key = route
    if fault == "missing":
        key.unlink()
    elif fault == "public":
        key.chmod(0o644)
    elif fault == "symlink":
        target = key.with_suffix(".other")
        key.rename(target)
        key.symlink_to(target)
    elif fault == "newline":
        key.write_text(TOKEN + "\nInjected: header")
    else:
        key.write_text(TOKEN * 4096)
    with pytest.raises(ValueError, match="rpc_transport_credential_unavailable") as caught:
        rpc_transport.websocket_connect(PRIMARY)
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "ws://plain.example",
        "wss://user:secret@example.org",
        "wss://example.org?token=secret",
        "wss://example.org#secret",
    ],
)
def test_route_rejects_credential_urls_and_plaintext(route, endpoint):
    path, _ = route
    data = json.loads(path.read_text())
    data["routes"][0]["endpoint"] = endpoint
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="rpc_transport_configuration_invalid"):
        rpc_transport.load_routes(path)


async def test_native_proof_failover_preserves_block_and_header_isolation(route, monkeypatch):
    calls = []

    @asynccontextmanager
    async def paid(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        raise InvalidStatus(Response(429, "limited", Headers()))
        yield

    @asynccontextmanager
    async def backup(endpoint, **kwargs):
        calls.append((endpoint, kwargs))

        class Socket:
            async def send(self, payload):
                self.request = json.loads(payload)

            async def recv(self):
                assert self.request["params"] == ["0xkey", "0xblock"]
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x01"})

        yield Socket()

    monkeypatch.setattr(rpc_transport, "_PrivateConnect", paid)
    monkeypatch.setattr(rpc_transport, "connect", backup)
    config = SimpleNamespace(
        rpc_url=PRIMARY, proof_rpc_fallback_urls=BACKUPS, collection_timeout_seconds=15
    )
    rpc = WeightProofRpc(config)
    try:
        assert await rpc.request("state_getStorageAt", ["0xkey", "0xblock"]) == "0x01"
    finally:
        await rpc.aclose()
    assert [c[0] for c in calls] == [PAID, BACKUPS[0]]
    assert calls[0][1]["additional_headers"] == {"Authorization": TOKEN}
    assert "additional_headers" not in calls[1][1]


@pytest.mark.parametrize("persistent", [False, True])
async def test_registration_reads_use_private_route(route, monkeypatch, persistent):
    calls = []

    @asynccontextmanager
    async def paid(endpoint, **kwargs):
        calls.append((endpoint, kwargs))

        class Socket:
            async def send(self, payload):
                pass

            async def recv(self):
                return '{"jsonrpc":"2.0","id":1,"result":null}'

        yield Socket()

    monkeypatch.setattr(rpc_transport, "_PrivateConnect", paid)
    rpc = _RegistrationRpc(
        SimpleNamespace(rpc_url=PRIMARY, collection_timeout_seconds=15), persistent=persistent
    )
    try:
        assert await rpc.request("chain_getHeader", ["0xblock"]) is None
    finally:
        await rpc.aclose()
    assert calls[0][0] == PAID and calls[0][1]["additional_headers"] == {"Authorization": TOKEN}


async def test_pinned_sdk_uses_same_routes_and_retains_both_backups(route):
    client = rpc_bittensor.rpc_client(
        PRIMARY, fallback_endpoints=list(BACKUPS), archive_endpoints=[], retry_forever=False
    )
    backend = client._substrate
    assert backend.endpoint == PRIMARY and backend.fallback_endpoints == list(BACKUPS)
    interface = backend._interface(PRIMARY, list(BACKUPS))
    assert interface._session._urls == [PRIMARY, *BACKUPS]
    assert interface._session._connect is rpc_bittensor._sdk_connect
    assert not interface._session._retry_forever


async def test_sdk_dial_preserves_pinned_limits(route, monkeypatch):
    calls = []
    socket = object()

    async def connect(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        return socket

    monkeypatch.setattr(rpc_bittensor, "websocket_connect", connect)
    assert await rpc_bittensor._sdk_connect(PRIMARY) is socket
    assert calls == [(PRIMARY, {"max_size": 2**32, "write_limit": 2**16, "proxy": None})]


@pytest.mark.parametrize("consumer", ["native", "sdk_read", "sdk_submission"])
async def test_sentinel_throttle_fails_over_without_replaying_submissions(
    route, monkeypatch, consumer
):
    paid_calls, backup_calls = [], []

    async def paid(ws):
        request = json.loads(await ws.recv())
        paid_calls.append(request)
        await ws.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "-1",
                    "result": None,
                    "error": {"code": 429, "message": TOKEN},
                }
            )
        )
        await ws.wait_closed()

    async def backup(ws):
        async for raw in ws:
            request = json.loads(raw)
            backup_calls.append(request)
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": "0x01"}))

    original_connect = rpc_transport.connect
    private_connect = rpc_transport._PrivateConnect
    async with serve(paid, "127.0.0.1", 0) as first, serve(backup, "127.0.0.1", 0) as second:
        primary_url = f"ws://127.0.0.1:{first.sockets[0].getsockname()[1]}"
        backup_url = f"ws://127.0.0.1:{second.sockets[0].getsockname()[1]}"
        monkeypatch.setattr(
            rpc_transport,
            "_PrivateConnect",
            lambda endpoint, **kw: private_connect(primary_url, **kw),
        )
        monkeypatch.setattr(
            rpc_transport, "connect", lambda endpoint, **kw: original_connect(backup_url, **kw)
        )
        if consumer == "native":
            client = WeightProofRpc(
                SimpleNamespace(
                    rpc_url=PRIMARY, proof_rpc_fallback_urls=BACKUPS, collection_timeout_seconds=15
                )
            )
            try:
                assert await client.request("state_getStorageAt", ["key", "block"]) == "0x01"
            finally:
                await client.aclose()
        else:
            async with RpcSession(
                PRIMARY, fallback_urls=list(BACKUPS), connect_factory=rpc_bittensor._sdk_connect
            ) as session:
                if consumer == "sdk_submission":
                    with pytest.raises(SubstrateRequestException, match="may already be"):
                        await asyncio.wait_for(
                            session.request("author_submitExtrinsic", ["0xsigned"]), 5
                        )
                else:
                    assert (
                        await asyncio.wait_for(
                            session.request("state_getStorageAt", ["key", "block"]), 5
                        )
                        == "0x01"
                    )
        assert len(paid_calls) == 1
        if consumer == "sdk_submission":
            assert not backup_calls
        else:
            assert len(backup_calls) == 1
            assert backup_calls[0] == paid_calls[0]
        with pytest.raises(InvalidStatus) as blocked:
            rpc_transport.websocket_connect(PRIMARY)
        assert blocked.value.response.status_code == 429
        assert TOKEN not in str(blocked.value)


@pytest.mark.parametrize(
    "payload",
    [
        '{"jsonrpc":"2.0","id":99,"result":"unchanged"}',
        '{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}',
        '{"jsonrpc":"2.0","id":1,"result":"data","error":{"code":429}}',
        '{"jsonrpc":"2.0","id":1,"error":{"code":"429"}}',
        "not-json",
    ],
)
async def test_non_throttle_frames_are_not_rewritten(payload):
    async def handler(ws):
        await ws.send(payload)
        await ws.wait_closed()

    async with serve(handler, "127.0.0.1", 0) as server:
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        async with rpc_transport._PrivateConnect(
            url,
            proxy=None,
            create_connection=partial(rpc_transport._PrivateConnection, rpc_endpoint=PAID),
        ) as ws:
            assert await ws.recv() == payload
