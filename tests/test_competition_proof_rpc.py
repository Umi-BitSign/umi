from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import ssl
import subprocess
from http import HTTPStatus
from types import SimpleNamespace

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from umi.competition_chain import (
    CompetitionChainConfig,
    FinalizedRegistrationProvider,
    _PrefetchRpc,
    _RegistrationRpc,
)
from umi.competition_proof_rpc import FailoverProofRpc
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_chain import FinalizedProofCollector, ValidatorChainError

from .test_competition_chain import _HEIGHT, _hash
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_chain import policy as policy

FALLBACK = "wss://backup-a.example"
SECOND_BACKUP = "wss://backup-b.example"


def with_fallback(config):
    return config.model_copy(update={"proof_rpc_fallback_urls": (FALLBACK, SECOND_BACKUP)})


def tables(path):
    with sqlite3.connect(path) as db:
        return {
            table: db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            for table in ("captures", "artifacts", "observed_head")
        }


async def test_adding_explicit_fallback_preserves_captures_artifacts_and_highwater(chain):
    capture = await chain.provider.collect()
    before = tables(chain.provider._path)
    old_binding = chain.provider._cache_binding_hash()
    config = with_fallback(chain.config)
    provider = FinalizedRegistrationProvider(
        config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )
    assert tables(provider._path) == before
    assert await provider.collect() == capture
    with sqlite3.connect(provider._path) as db:
        rows = db.execute(
            "SELECT digest,previous,body FROM proof_rpc_transport_bindings"
        ).fetchall()
        assert len(rows) == 1 and rows[0][1] == old_binding
        assert json.loads(rows[0][2])["rpc_url"] == chain.config.rpc_url
        assert json.loads(rows[0][2])["proof_rpc_fallback_urls"] == [FALLBACK, SECOND_BACKUP]
    again = FinalizedRegistrationProvider(
        config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )
    assert tables(again._path) == before
    with sqlite3.connect(again._path) as db:
        assert (
            db.execute("SELECT digest,previous,body FROM proof_rpc_transport_bindings").fetchall()
            == rows
        )
    # Old binaries/configs cannot reopen the new binding or silently remove its history.
    with pytest.raises(ValueError, match="another chain configuration"):
        FinalizedRegistrationProvider(
            chain.config, chain.policy, finality=chain.finality, proofs=chain.proofs
        )


@pytest.mark.parametrize(
    "change",
    [
        "rpc_url",
        "proof_binary_sha256",
        "minimum_finalized_block",
        "chain_pin",
        "collection_timeout_seconds",
    ],
)
def test_fallback_addition_cannot_launder_an_unrelated_binding_change(chain, change):
    before = tables(chain.provider._path)
    value = getattr(chain.config, change)
    if change == "rpc_url":
        value = "wss://another-primary.example"
    elif change == "proof_binary_sha256":
        value = "ab" * 32
    elif change == "chain_pin":
        value = value.model_copy(update={"metadata_sha256": "ab" * 32})
    else:
        value += 1
    config = with_fallback(chain.config).model_copy(update={change: value})
    with pytest.raises(ValueError, match="another chain configuration"):
        FinalizedRegistrationProvider(
            config, chain.policy, finality=chain.finality, proofs=chain.proofs
        )
    assert tables(chain.provider._path) == before


def test_legacy_signed_config_bytes_unchanged_and_legacy_cache_adopted(chain):
    assert "proof_rpc_fallback_urls" not in json.loads(canonical_json_bytes(chain.config))
    with sqlite3.connect(chain.provider._path) as db:
        db.execute("UPDATE binding SET digest=?", (digest(chain.config),))
    FinalizedRegistrationProvider(
        with_fallback(chain.config), chain.policy, finality=chain.finality, proofs=chain.proofs
    )


@pytest.mark.parametrize(
    "urls",
    [
        ("ws://insecure.example",),
        ("wss://user:secret@example.org",),
        ("wss://example.org/?secret=value",),
        ("wss://example.org/#x",),
        (FALLBACK, FALLBACK),
        tuple(f"wss://{i}.example" for i in range(3)),
        (FALLBACK,),
    ],
)
def test_fallback_urls_are_explicit_bounded_and_credential_free(chain_config, urls):
    with pytest.raises(ValueError):
        CompetitionChainConfig.model_validate_json(
            canonical_json_bytes(chain_config.model_copy(update={"proof_rpc_fallback_urls": urls}))
        )


def test_primary_cannot_also_be_a_fallback(chain_config):
    with pytest.raises(ValueError, match="unique"):
        CompetitionChainConfig.model_validate_json(
            canonical_json_bytes(
                chain_config.model_copy(
                    update={"proof_rpc_fallback_urls": (chain_config.rpc_url, SECOND_BACKUP)}
                )
            )
        )


@pytest.fixture
async def wire(chain, tmp_path, monkeypatch):
    """Actual TLS WebSocket and HTTP handshake; only chain facts/verifier are fixtures."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("TLS socket qualification requires openssl")
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    tls_config = tmp_path / "tls.cnf"
    tls_config.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n[SAN]\nsubjectAltName=IP:127.0.0.1\n"
    )
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-config",
            str(tls_config),
            "-extensions",
            "SAN",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        check=True,
        timeout=10,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(cert_path, key_path)
    client_tls = ssl.create_default_context(cafile=str(cert_path))
    state = SimpleNamespace(
        primary_status=429,
        primary_rpc_error=False,
        fallback_rpc_error=False,
        second_rpc_error=False,
        malformed=False,
        handshakes=[],
        reads=[],
        sockets=[],
        block=False,
        started=asyncio.Event(),
        release=asyncio.Event(),
    )

    async def handshake(connection, request):
        state.handshakes.append(request.path)
        if request.path == "/primary" and state.primary_status:
            response = connection.respond(HTTPStatus(state.primary_status), "fixture unavailable\n")
            response.headers["Retry-After"] = "10"
            return response

    async def handler(socket):
        state.sockets.append(socket)
        async for raw in socket:
            request = json.loads(raw)
            state.reads.append((socket.request.path, request["method"], request["params"]))
            state.started.set()
            if state.block:
                await state.release.wait()
            if state.malformed:
                await socket.send('{"jsonrpc":"2.0","id":99,"result":{}}')
                continue
            unavailable = {
                "/primary": state.primary_rpc_error,
                "/fallback": state.fallback_rpc_error,
                "/second-backup": state.second_rpc_error,
            }[socket.request.path]
            if unavailable:
                response = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32000, "message": "fixture state unavailable"},
                }
            else:
                result = await chain.rpc.request(request["method"], request["params"])
                response = {"jsonrpc": "2.0", "id": 1, "result": result}
            await socket.send(json.dumps(response))

    async with serve(
        handler, "127.0.0.1", 0, ssl=server_tls, process_request=handshake, close_timeout=0.2
    ) as server:
        port = server.sockets[0].getsockname()[1]

        def local_connect(endpoint, **kwargs):
            assert endpoint in (chain.config.rpc_url, FALLBACK, SECOND_BACKUP)
            assert kwargs["proxy"] is None and kwargs["max_queue"] == 1
            route = (
                "primary"
                if endpoint == chain.config.rpc_url
                else ("fallback" if endpoint == FALLBACK else "second-backup")
            )
            return connect(f"wss://127.0.0.1:{port}/{route}", ssl=client_tls, **kwargs)

        monkeypatch.setattr("umi.competition_chain.websocket_connect", local_connect)
        transports = tuple(
            _RegistrationRpc(chain.config.model_copy(update={"rpc_url": url}), persistent=True)
            for url in (chain.config.rpc_url, FALLBACK, SECOND_BACKUP)
        )
        router = FailoverProofRpc(transports, timeout_seconds=15)
        try:
            yield state, router
        finally:
            state.release.set()
            await router.aclose()


def provider_for_wire(chain, router):
    prefetch = _PrefetchRpc(router)
    proofs = FinalizedProofCollector(prefetch, finality=chain.finality, verifier=chain.verifier)
    provider = FinalizedRegistrationProvider(
        with_fallback(chain.config),
        chain.policy,
        finality=chain.finality,
        proofs=proofs,
        now_ms=lambda: chain.clock.now,
    )
    provider._registration_rpc = router
    provider._prefetch = prefetch
    return provider


async def test_real_tls_429_falls_back_with_native_finality_and_proof_checks(chain, wire):
    state, router = wire
    provider = provider_for_wire(chain, router)
    capture = await provider.collect()
    assert capture.snapshot.block == _HEIGHT
    assert len(capture.snapshot.registrations) == 2
    assert len(chain.verifier.checked) == 3
    assert state.handshakes.count("/primary") == 1  # Retry-After applies to later methods too.
    assert all(path == "/fallback" for path, _, _ in state.reads)
    assert "chain_getFinalizedHead" not in {method for _, method, _ in state.reads}
    assert all(
        tuple(params) == (chain.finality.ref.block_hash,)
        for _, method, params in state.reads
        if method == "chain_getHeader"
    )
    await provider.aclose()
    assert all(socket.close_code is not None for socket in state.sockets)


@pytest.mark.parametrize("mutation", ["genesis", "root", "metadata", "proof", "timestamp"])
async def test_fallback_cannot_relax_native_chain_or_proof_validation(chain, wire, mutation):
    state, router = wire
    if mutation == "genesis":
        chain.finality.genesis = _hash(99)
    elif mutation == "root":
        chain.rpc.header_root = _hash(99)
    elif mutation == "metadata":
        chain.rpc.metadata = b"wrong"
    elif mutation == "proof":
        chain.rpc.bad_proof = True
    else:
        chain.rpc.values[("Timestamp", "Now", ())] += 1
    provider = provider_for_wire(chain, router)
    with pytest.raises((ValueError, RuntimeError)):
        await provider.collect()
    assert tables(provider._path)["captures"] == []
    assert "/second-backup" not in state.handshakes
    await provider.aclose()


async def test_real_tls_primary_archive_is_tried_first_and_no_new_block_selected(chain, wire):
    state, router = wire
    state.primary_status = 0
    result = await router.request("chain_getHeader", (chain.finality.ref.block_hash,))
    assert result["stateRoot"] == chain.finality.ref.state_root
    assert state.handshakes == ["/primary"]
    state.primary_rpc_error = True
    result = await router.request("chain_getHeader", (chain.finality.ref.block_hash,))
    assert result["stateRoot"] == chain.finality.ref.state_root
    assert state.reads[-2][1:] == state.reads[-1][1:]
    state.fallback_rpc_error = True
    state.second_rpc_error = True
    with pytest.raises(ValidatorChainError, match="proof_rpc_error"):
        await router.request("chain_getHeader", (chain.finality.ref.block_hash,))
    assert state.reads[-2][1:] == state.reads[-1][1:]


async def test_real_tls_malformed_protocol_is_terminal_without_endpoint_retry(chain, wire):
    state, router = wire
    state.primary_status = 0
    state.malformed = True
    with pytest.raises(ValidatorChainError, match="proof_rpc_response_invalid"):
        await router.request("chain_getHeader", (chain.finality.ref.block_hash,))
    assert state.handshakes == ["/primary"]


async def test_real_tls_second_backup_only_when_first_cannot_serve_exact_state(chain, wire):
    state, router = wire
    state.fallback_rpc_error = True
    result = await router.request("chain_getHeader", (chain.finality.ref.block_hash,))
    assert result["stateRoot"] == chain.finality.ref.state_root
    assert state.handshakes == ["/primary", "/fallback", "/second-backup"]
    assert state.reads[-2][1:] == state.reads[-1][1:]


@pytest.mark.parametrize("all_throttled", [False, True])
async def test_concurrent_requests_share_retry_after_and_do_not_burst_providers(
    caplog, all_throttled
):
    class Transport:
        bulk_storage_reads = False

        def __init__(self, throttled):
            self.calls = 0
            self.throttled = throttled

        async def request(self, *args):
            self.calls += 1
            await asyncio.sleep(0)
            if self.throttled:
                cause = RuntimeError("private-provider-detail")
                cause.response = SimpleNamespace(
                    headers={"Retry-After": "10", "private-header": "secret"}
                )
                raise ValidatorChainError("proof_rpc_rate_limited") from cause
            return args

    transports = (Transport(True), Transport(True), Transport(all_throttled))
    router = FailoverProofRpc(transports, timeout_seconds=15)
    now = 1000.0
    router._now = lambda: now
    results = await asyncio.gather(
        *(router.request("chain_getHeader", ("fixed",)) for _ in range(32)), return_exceptions=True
    )
    assert [t.calls for t in transports] == [1, 1, 1 if all_throttled else 32]
    assert (
        all(
            isinstance(r, ValidatorChainError) and r.reason_code == "proof_rpc_rate_limited"
            for r in results
        )
        if all_throttled
        else all(r == ("chain_getHeader", ("fixed",)) for r in results)
    )
    now += 9.9
    await asyncio.gather(router.request("chain_getHeader", ("fixed",)), return_exceptions=True)
    assert transports[0].calls == transports[1].calls == 1
    now += 0.2
    await asyncio.gather(router.request("chain_getHeader", ("fixed",)), return_exceptions=True)
    assert transports[0].calls == transports[1].calls == 2
    assert all(record.message == "competition_proof_rpc_throttled" for record in caplog.records)
    assert "private-provider-detail" not in caplog.text and "secret" not in caplog.text


async def test_transport_failure_cooldown_is_not_mislabeled_as_throttling():
    class Transport:
        bulk_storage_reads = False
        calls = 0

        async def request(self, *args):
            self.calls += 1
            raise ValidatorChainError("proof_rpc_failed")

    transports = (Transport(), Transport(), Transport())
    router = FailoverProofRpc(transports, timeout_seconds=15)
    for _ in range(2):
        with pytest.raises(ValidatorChainError, match="proof_rpc_failed"):
            await router.request("chain_getHeader", ("fixed",))
    assert [t.calls for t in transports] == [1, 1, 1]


async def test_forbidden_methods_and_bad_parameters_never_fail_over_even_during_cooldown():
    class Transport:
        bulk_storage_reads = False

        async def request(self, *args):
            pytest.fail("invalid request reached a transport")

    router = FailoverProofRpc((Transport(), Transport(), Transport()), timeout_seconds=15)
    router._cooldown_until = [float("inf")] * 3
    with pytest.raises(ValidatorChainError, match="proof_rpc_method_forbidden"):
        await router.request("author_submitExtrinsic", ("0x00",))
    with pytest.raises(TypeError, match="params must be a sequence"):
        await router.request("chain_getHeader", "wrong")


@pytest.mark.parametrize(
    "header,expected", [("10", 10), ("NaN", 10), ("invalid", 10), ("-1", 1), ("7200", 3600)]
)
def test_retry_after_is_bounded_without_private_header_logging(header, expected):
    from umi.competition_proof_rpc import _retry_after

    error = ValidatorChainError("proof_rpc_rate_limited")
    error.__cause__ = RuntimeError("private")
    error.__cause__.response = SimpleNamespace(headers={"Retry-After": header})
    assert _retry_after(error) == expected


async def test_close_waits_for_inflight_attempt_and_does_not_start_backup():
    started, release = asyncio.Event(), asyncio.Event()

    class Transport:
        bulk_storage_reads = False
        calls = 0
        closed = False

        async def request(self, *args):
            self.calls += 1
            started.set()
            await release.wait()
            return "done"

        async def aclose(self):
            self.closed = True

    transports = (Transport(), Transport(), Transport())
    router = FailoverProofRpc(transports, timeout_seconds=15)
    task = asyncio.create_task(router.request("chain_getHeader", ("fixed",)))
    await started.wait()
    closing = asyncio.create_task(router.aclose())
    await asyncio.sleep(0)
    assert not closing.done() and not any(t.closed for t in transports)
    release.set()
    assert await task == "done"
    await closing
    assert all(t.closed for t in transports)
    assert [t.calls for t in transports] == [1, 0, 0]


async def test_cancellation_drains_attempt_before_another_endpoint_can_run():
    started, cleanup, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class Transport:
        bulk_storage_reads = False

        def __init__(self):
            self.calls = 0

        async def request(self, *args):
            self.calls += 1
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleanup.set()
                await release.wait()

    first, second = Transport(), Transport()
    rpc = FailoverProofRpc((first, second, Transport()), timeout_seconds=15)
    task = asyncio.create_task(rpc.request("chain_getHeader", ("fixed-hash",)))
    await started.wait()
    task.cancel()
    await cleanup.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and second.calls == 0
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert second.calls == 0


async def test_timeout_drains_primary_then_uses_exact_same_request():
    completed = []

    class First:
        bulk_storage_reads = False

        async def request(self, *args):
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0)
                completed.append("drained")

    class Second:
        bulk_storage_reads = False

        async def request(self, *args):
            assert completed == ["drained"]
            return args

    rpc = FailoverProofRpc((First(), Second(), Second()), timeout_seconds=0.04)
    assert await rpc.request("chain_getHeader", ("exact",)) == ("chain_getHeader", ("exact",))


async def test_repeated_close_cancellation_waits_for_every_transport():
    started, release = asyncio.Event(), asyncio.Event()

    class Transport:
        bulk_storage_reads = False
        closed = False

        async def aclose(self):
            started.set()
            await release.wait()
            self.closed = True

    transports = (Transport(), Transport(), Transport())
    rpc = FailoverProofRpc(transports, timeout_seconds=15)
    task = asyncio.create_task(rpc.aclose())
    await started.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(t.closed for t in transports)
    await rpc.aclose()
    with pytest.raises(ValueError, match="closed"):
        await rpc.request("chain_getHeader", ())
