"""Local sidecar routing leaves retained chain and journal identities intact."""

from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from websockets.asyncio.server import serve

from umi import rpc_bittensor, rpc_transport
from umi.competition_chain import (
    CompetitionChainConfig,
    FinalizedRegistrationProvider,
    _RegistrationRpc,
)
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_chain import policy as policy

PRIMARY = "wss://archive.chain.opentensor.ai:443"
BACKUPS = ("wss://entrypoint-finney.opentensor.ai:443", "wss://backup.example")
LOCAL = "ws://127.0.0.1:9955"


@pytest.fixture
def local_route(tmp_path, monkeypatch):
    path = tmp_path / "transport.json"
    path.write_text(
        json.dumps(
            {
                "schema": "umi-rpc-transport/1",
                "routes": [{"source": PRIMARY, "endpoint": LOCAL, "authorization_file": None}],
            }
        )
    )
    path.chmod(0o600)
    monkeypatch.setenv(rpc_transport.CONFIG_ENV, str(path))
    return path


@pytest.mark.parametrize(
    "endpoint",
    [
        "ws://example.org:9955",
        "ws://0.0.0.0:9955",
        "ws://localhost:9955",
        "ws://127.0.0.2:9955",
        "ws://127.1:9955",
        "ws://[::1]:9955",
        "ws://127.0.0.1:9956",
        "ws://127.0.0.1:9955/other",
        "ws://127.0.0.1:9955?upstream=remote",
        "ws://127.0.0.1:9955#fragment",
        "ws://user:secret@127.0.0.1:9955",
        "ws://127.0.0.1:9955\n",
    ],
)
def test_only_exact_operator_loopback_target_is_allowed(local_route, endpoint):
    value = json.loads(local_route.read_text())
    value["routes"][0]["endpoint"] = endpoint
    local_route.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="rpc_transport_configuration_invalid"):
        rpc_transport.load_routes(local_route)


def test_loopback_does_not_become_signed_or_source_identity(local_route, chain_config):
    value = json.loads(local_route.read_text())
    value["routes"][0]["source"] = LOCAL
    local_route.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="rpc_transport_configuration_invalid"):
        rpc_transport.load_routes(local_route)
    value = chain_config.model_dump(mode="json", by_alias=True)
    value["rpc_url"] = LOCAL
    with pytest.raises(ValueError, match="credential-free wss"):
        CompetitionChainConfig.model_validate_json(json.dumps(value))


def test_retained_route_repeat_read_restart_and_rollback_do_not_rewrite(local_route):
    original = local_route.read_bytes()
    before = local_route.stat()
    for _ in range(3):
        assert rpc_transport.load_routes(local_route)[PRIMARY].endpoint == LOCAL
        assert local_route.read_bytes() == original
        assert local_route.stat().st_ino == before.st_ino
    value = json.loads(original)
    value["routes"][0]["endpoint"] = PRIMARY
    local_route.write_text(json.dumps(value))
    assert rpc_transport.load_routes(local_route)[PRIMARY].endpoint == PRIMARY
    local_route.write_bytes(original)
    assert rpc_transport.load_routes(local_route)[PRIMARY].endpoint == LOCAL


async def test_native_route_keeps_block_arguments_and_unrouted_backups(local_route, monkeypatch):
    calls = []

    @asynccontextmanager
    async def selected(endpoint, **kwargs):
        calls.append((endpoint, kwargs))

        class Socket:
            async def send(self, payload):
                self.request = json.loads(payload)

            async def recv(self):
                assert self.request["params"] == ["0xoriginal-finalized-hash"]
                return '{"jsonrpc":"2.0","id":1,"result":null}'

        yield Socket()

    monkeypatch.setattr(rpc_transport, "_PrivateConnect", selected)
    rpc = _RegistrationRpc(SimpleNamespace(rpc_url=PRIMARY, collection_timeout_seconds=15))
    try:
        assert await rpc.request("chain_getHeader", ["0xoriginal-finalized-hash"]) is None
    finally:
        await rpc.aclose()
    assert calls[0][0] == LOCAL
    assert calls[0][1]["additional_headers"] == {}
    assert calls[0][1]["proxy"] is None
    routes = rpc_transport.load_routes(local_route)
    assert all(endpoint not in routes for endpoint in BACKUPS)
    client = rpc_bittensor.rpc_client(PRIMARY, fallback_endpoints=list(BACKUPS), retry_forever=True)
    backend = client._substrate
    assert backend.endpoint == PRIMARY
    assert backend.fallback_endpoints == list(BACKUPS)
    assert backend.retry_forever
    await client.close()


async def test_sidecar_wire_envelopes_remain_exact(local_route, monkeypatch):
    payloads = [
        '{"jsonrpc":"2.0","id":17,"result":null}',
        '{"jsonrpc":"2.0","method":"chain_newHead","params":{"subscription":"owned","result":{"number":"0x1"}}}',
        "not-json",
    ]

    async def handler(ws):
        assert await ws.recv() == "one unchanged request"
        for value in payloads:
            await ws.send(value)
        await ws.wait_closed()

    original = rpc_transport._PrivateConnect
    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]

        def dial(endpoint, **kwargs):
            assert endpoint == LOCAL
            return original(f"ws://127.0.0.1:{port}", **kwargs)

        monkeypatch.setattr(rpc_transport, "_PrivateConnect", dial)
        async with rpc_transport.websocket_connect(PRIMARY) as ws:
            await ws.send("one unchanged request")
            for payload in payloads:
                assert await ws.recv() == payload


async def test_retained_native_cache_reopens_twice_without_signed_config_migration(
    local_route, chain, monkeypatch
):
    # Exercise actual supported native reopen with isolated fixture state only.
    # The operator route is selected separately from the immutable config.
    original = canonical_json_bytes(chain.config)
    original_binding = chain.provider._cache_binding_hash()
    first = await chain.provider.collect()

    def retained_rows():
        with sqlite3.connect(chain.provider._path) as db:
            return {
                table: db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                for table in ("binding", "captures", "artifacts", "observed_head")
            }

    before = retained_rows()
    for _ in range(2):
        provider = FinalizedRegistrationProvider(
            chain.config,
            chain.policy,
            finality=chain.finality,
            proofs=chain.proofs,
            now_ms=lambda: chain.clock.now,
        )
        assert provider._cache_binding_hash() == original_binding
        assert await provider.collect() == first
        assert retained_rows() == before
        assert canonical_json_bytes(provider.config) == original
    assert canonical_json_bytes(chain.config) == original
