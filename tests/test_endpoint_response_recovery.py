"""Real miner HTTP, signatures and ledger; video/model and network are fixtures."""

import asyncio
import time
from dataclasses import replace

import bittensor as bt
import httpx
import pytest

from umi.endpoint_response_recovery import retrieve_endpoint_response
from umi.miner import RESPONSE_RECOVERY_PATH, TRANSLATE_PATH, create_app

from .factories import challenge_request, dev_wallet
from .test_miner_response_recovery import client, post, selected_runtime
from .test_miner_transport import CoordinatedTranslator, CountingFetcher, CountingTranslator


async def public_resolver(host, port):
    return ["8.8.8.8"]


async def recover(selected, request, transport, **kw):
    return await retrieve_endpoint_response(
        request,
        wallet=kw.pop("wallet", dev_wallet("//Alice")),
        validator_hotkey=dev_wallet("//Alice").hotkey.ss58_address,
        miner_hotkey=selected.hotkey_ss58,
        miner_url=kw.pop("miner_url", "https://miner.example"),
        limits=kw.pop("limits", selected.limits),
        timeout_seconds=kw.pop("timeout_seconds", 5),
        resolver=kw.pop("resolver", public_resolver),
        transport=transport,
        **kw,
    )


async def test_real_miner_expired_response_is_retrieved_with_new_route_auth(tmp_path, monkeypatch):
    calls = []
    selected = selected_runtime(tmp_path / "miner.sqlite", translator=CountingTranslator())
    request = challenge_request()
    async with client(selected) as http:
        original = await post(http, selected, request, TRANSLATE_PATH)
    assert original.status_code == 200
    selected.resource_ledger.prune_closed_windows(request.response_close_round)
    monkeypatch.setattr(bt.timelock, "current_round", lambda: request.reveal_round + 12000)
    asgi = httpx.ASGITransport(app=create_app(selected))

    class Capture(httpx.AsyncBaseTransport):
        async def handle_async_request(self, wire):
            calls.append(wire)
            return await asgi.handle_async_request(wire)

    before = time.time_ns()
    first = await recover(selected, request, Capture())
    second = await recover(selected, request, Capture())
    assert first.status == second.status == "recovered"
    assert bytes.fromhex(first.response.envelope_hex) == original.content
    assert first.response.signature == original.headers["x-umi-signature"]
    assert int(first.response.retrieved_at_unix_ns) >= before
    assert selected.translator.calls == 1
    for wire in calls:
        assert wire.url.path == RESPONSE_RECOVERY_PATH
        assert wire.url.host == "8.8.8.8"
        assert wire.headers["host"] == "miner.example"
        assert wire.extensions["sni_hostname"] == "miner.example"
    assert calls[0].headers["x-bittensor-nonce"] != calls[1].headers["x-bittensor-nonce"]
    selected.resource_ledger.close()


async def test_pending_remote_inference_does_not_invoke_again(tmp_path):
    model = CoordinatedTranslator(asyncio.Event(), asyncio.Event())
    selected = selected_runtime(tmp_path / "miner.sqlite", translator=model)
    request = challenge_request()
    async with client(selected) as http:
        running = asyncio.create_task(post(http, selected, request, TRANSLATE_PATH))
        await asyncio.wait_for(model.started.wait(), 3)
        try:
            result = await recover(selected, request, httpx.ASGITransport(app=create_app(selected)))
            assert result.status == "pending" and result.http_status == 202
            assert result.response is None and model.calls == 1
        finally:
            model.release.set()
        assert (await running).status_code == 200
    selected.resource_ledger.close()


@pytest.mark.parametrize("status", [202, 301, 307, 401, 404, 409, 429, 500, 503])
async def test_unavailable_archive_is_pending_and_never_follows_redirect(tmp_path, status):
    fetch, model, calls = CountingFetcher(), CountingTranslator(), []
    selected = selected_runtime(tmp_path / "miner.sqlite", translator=model, fetcher=fetch)

    def handler(wire):
        calls.append(wire.url.path)
        return httpx.Response(
            status, headers={"Location": "/v1/translate"}, content=b"private error"
        )

    result = await recover(selected, challenge_request(), httpx.MockTransport(handler))
    assert result.status == "pending" and result.response is None
    assert result.http_status == status
    assert calls == [RESPONSE_RECOVERY_PATH]
    assert model.calls == fetch.calls == 0
    assert "private error" not in repr(result)
    selected.resource_ledger.close()


@pytest.mark.parametrize(
    "damage", ["signature", "canonical", "binding", "missing", "encoding", "oversized"]
)
async def test_invalid_response_does_not_become_retained_success(tmp_path, damage):
    selected = selected_runtime(tmp_path / "miner.sqlite")
    request = challenge_request()
    async with client(selected) as http:
        original = await post(http, selected, request, TRANSLATE_PATH)
    raw, signature = original.content, original.headers["x-umi-signature"]
    headers = {"x-umi-signature": signature}
    if damage == "signature":
        headers["x-umi-signature"] = "0x" + "00" * 64
    elif damage == "canonical":
        raw += b"\n"
    elif damage == "binding":
        request = request.model_copy(update={"issued_block_hash": "0x" + "ff" * 32})
    elif damage == "missing":
        headers.clear()
    elif damage == "encoding":
        headers["content-encoding"] = "gzip"
    else:
        headers["content-length"] = str(selected.limits.maximum_response_body_bytes + 1)

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield raw

    result = await recover(
        selected,
        request,
        httpx.MockTransport(lambda wire: httpx.Response(200, headers=headers, stream=Body())),
    )
    assert result.status == "pending" and result.response is None
    selected.resource_ledger.close()


@pytest.mark.parametrize("failure", ["timeout", "network", "dns"])
async def test_network_failures_are_bounded_pending_attempts(tmp_path, failure):
    selected = selected_runtime(tmp_path / "miner.sqlite")
    called = []

    async def handler(wire):
        called.append(wire.url.path)
        if failure == "timeout":
            await asyncio.Event().wait()
        raise httpx.ReadError("do not retain capability URL")

    async def resolver(host, port):
        if failure == "dns":
            raise OSError("do not retain secret")
        return ["8.8.8.8"]

    result = await recover(
        selected,
        challenge_request(),
        httpx.MockTransport(handler),
        resolver=resolver,
        timeout_seconds=0.01,
    )
    assert result.status == "pending" and result.response is None
    assert "secret" not in repr(result) and "capability" not in repr(result)
    assert called == ([] if failure == "dns" else [RESPONSE_RECOVERY_PATH])
    selected.resource_ledger.close()


@pytest.mark.parametrize("answers", [["127.0.0.1"], ["8.8.8.8", "10.0.0.1"], []])
async def test_nonpublic_or_mixed_origin_never_receives_request(tmp_path, answers):
    selected = selected_runtime(tmp_path / "miner.sqlite")
    called = []

    async def resolver(host, port):
        return answers

    result = await recover(
        selected,
        challenge_request(),
        httpx.MockTransport(lambda wire: called.append(wire)),
        resolver=resolver,
    )
    assert result.status == "pending" and not called
    selected.resource_ledger.close()


@pytest.mark.parametrize("bad_timeout", [0, -1, float("nan"), float("inf"), True, 3601])
async def test_invalid_timeout_is_rejected_before_network(tmp_path, bad_timeout):
    selected = selected_runtime(tmp_path / "miner.sqlite")
    with pytest.raises(ValueError, match="timeout"):
        await recover(
            selected,
            challenge_request(),
            httpx.MockTransport(lambda _: None),
            timeout_seconds=bad_timeout,
        )
    selected.resource_ledger.close()


async def test_wrong_signer_and_excessive_bounds_fail_before_network(tmp_path):
    selected = selected_runtime(tmp_path / "miner.sqlite")
    transport = httpx.MockTransport(lambda _: pytest.fail("unexpected network"))
    with pytest.raises(ValueError, match="signer"):
        await recover(selected, challenge_request(), transport, wallet=dev_wallet("//Charlie"))
    with pytest.raises(ValueError, match="bounded"):
        await recover(
            selected,
            challenge_request(),
            transport,
            limits=replace(selected.limits, maximum_response_body_bytes=128 * 1024),
        )
    selected.resource_ledger.close()


async def test_cancellation_does_not_turn_into_success_or_new_work(tmp_path):
    selected = selected_runtime(tmp_path / "miner.sqlite")
    started = asyncio.Event()

    async def handler(wire):
        started.set()
        await asyncio.Event().wait()

    work = asyncio.create_task(recover(selected, challenge_request(), httpx.MockTransport(handler)))
    await asyncio.wait_for(started.wait(), 2)
    work.cancel()
    with pytest.raises(asyncio.CancelledError):
        await work
    selected.resource_ledger.close()
