"""Transport retry must precede sealing and retain the original resource budget."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import httpx
import pytest

from umi.auth import HotkeyAuth
from umi.config import Limits
from umi.miner import _translate, create_app
from umi.miner_resources import MinerAssignmentBinding
from umi.protocol import canonical_json_bytes
from umi.video import HttpVideoFetcher, VideoFetchError

from .factories import VIDEO_BYTES, challenge_request, dev_wallet
from .test_miner_transport import CountingTranslator, runtime
from .test_video import public_resolver


class ClipTransport(httpx.AsyncBaseTransport):
    def __init__(self, failures: list[str]) -> None:
        self.failures = list(failures)
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        mode = self.failures.pop(0) if self.failures else "ok"
        if mode == "timeout":
            raise httpx.ReadTimeout("read timed out", request=request)
        if mode == "internal":
            raise RuntimeError("backend bug")
        if mode == "reset":

            class BrokenBody(httpx.AsyncByteStream):
                async def __aiter__(self):
                    yield VIDEO_BYTES[:3]
                    raise httpx.RemoteProtocolError("peer closed before declared body")

            return httpx.Response(
                200,
                headers={"Content-Type": "video/mp4", "Content-Length": str(len(VIDEO_BYTES))},
                stream=BrokenBody(),
            )
        body = {
            "ok": VIDEO_BYTES,
            "short": VIDEO_BYTES[:3],
            "digest": b"x" * len(VIDEO_BYTES),
            "oversize": VIDEO_BYTES + b"x",
        }.get(mode, VIDEO_BYTES)
        headers = {"Content-Type": "video/mp4"}
        if mode == "short":
            headers["Content-Length"] = str(len(VIDEO_BYTES))
        if mode == "bad_length":
            headers["Content-Length"] = str(len(VIDEO_BYTES) + 1)
        return httpx.Response(200, headers=headers, content=body)


def setup(failures: list[str], *, limits: Limits | None = None, ledger_path=":memory:"):
    transport = ClipTransport(failures)
    fetcher = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=1024,
        timeout_seconds=1,
        transport=transport,
        resolver=public_resolver,
    )
    translator = CountingTranslator()
    selected = runtime(
        fetcher=fetcher, translator=translator, limits=limits, ledger_path=ledger_path
    )
    request = challenge_request()
    validator = dev_wallet("//Alice")
    binding = MinerAssignmentBinding.from_request(
        request, validator_hotkey=validator.hotkey.ss58_address
    )
    return selected, transport, translator, request, validator, binding


@pytest.mark.parametrize("failure", ["short", "reset", "timeout"])
async def test_transient_download_uses_remaining_fetch_before_success(failure):
    selected, transport, translator, request, validator, binding = setup([failure])
    result = await _translate(selected, request, validator.hotkey.ss58_address)
    snapshot = selected.resource_ledger.snapshot(binding)
    assert result.status == "ok"
    assert result.hypothesis == "hello world"
    assert transport.calls == snapshot.video_fetch_attempts == 2
    assert translator.calls == 1
    assert snapshot.request_transmissions == 1
    assert snapshot.response_bodies == 0
    assert snapshot.observed_wire_bytes > len(VIDEO_BYTES)
    assert snapshot.accounted_wire_bytes == snapshot.observed_wire_bytes


@pytest.mark.parametrize("failure", ["digest", "oversize", "bad_length", "internal"])
async def test_invalid_download_is_not_retried(failure):
    selected, transport, translator, request, validator, binding = setup([failure])
    result = await _translate(selected, request, validator.hotkey.ss58_address)
    assert result.status == "error"
    assert result.error_code == "video_fetch_failed"
    assert transport.calls == selected.resource_ledger.snapshot(binding).video_fetch_attempts == 1
    assert translator.calls == 0


@pytest.mark.parametrize("failure_count", [1, 2])
async def test_retransmission_reuses_sealed_outcome_after_bounded_fetches(failure_count):
    selected, transport, translator, request, validator, binding = setup(["reset"] * failure_count)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(selected)), base_url="http://miner.test"
    ) as client:
        replies = [
            await client.post(
                "/v1/translate",
                content=canonical_json_bytes(request),
                auth=HotkeyAuth(validator, selected.hotkey_ss58),
            )
            for _ in range(2)
        ]
    assert [reply.status_code for reply in replies] == [200, 200]
    assert replies[0].content == replies[1].content
    assert replies[0].headers["x-umi-signature"] == replies[1].headers["x-umi-signature"]
    snapshot = selected.resource_ledger.snapshot(binding)
    assert transport.calls == snapshot.video_fetch_attempts == 2
    assert snapshot.request_transmissions == snapshot.response_bodies == 2
    assert translator.calls == (1 if failure_count == 1 else 0)


async def test_retry_respects_single_attempt_policy():
    selected, transport, translator, request, validator, binding = setup(
        ["short"], limits=Limits(maximum_video_fetch_attempts_per_actor=1)
    )
    result = await _translate(selected, request, validator.hotkey.ss58_address)
    assert result.status == "error"
    assert transport.calls == selected.resource_ledger.snapshot(binding).video_fetch_attempts == 1
    assert translator.calls == 0


async def test_retry_reserves_wire_budget_before_network_io():
    limits = Limits(maximum_assignment_wire_bytes=2 * 16 * 1024 + len(VIDEO_BYTES))
    selected, transport, translator, request, validator, binding = setup(["reset"], limits=limits)
    result = await _translate(selected, request, validator.hotkey.ss58_address)
    assert result.status == "error"
    assert transport.calls == selected.resource_ledger.snapshot(binding).video_fetch_attempts == 1
    assert translator.calls == 0


async def test_cancelled_second_attempt_remains_accounted():
    selected, transport, translator, request, validator, binding = setup(["short"])
    second_started = asyncio.Event()

    async def slow_resolver(host, port):
        if transport.calls == 1:
            second_started.set()
            await asyncio.Event().wait()
        return await public_resolver(host, port)

    selected = replace(
        selected, video_fetcher=replace(selected.video_fetcher, resolver=slow_resolver)
    )
    task = asyncio.create_task(_translate(selected, request, validator.hotkey.ss58_address))
    await asyncio.wait_for(second_started.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    snapshot = selected.resource_ledger.snapshot(binding)
    assert snapshot.video_fetch_attempts == 2
    assert snapshot.accounted_wire_bytes > snapshot.observed_wire_bytes
    assert snapshot.cached_response_sha256 is None
    assert translator.calls == 0


async def test_restart_does_not_reopen_used_fetch_budget(tmp_path):
    ledger = tmp_path / "assignment.sqlite"
    first, transport, _, request, validator, binding = setup(["short", "reset"], ledger_path=ledger)
    result = await _translate(first, request, validator.hotkey.ss58_address)
    assert result.status == "error"
    first.resource_ledger.close()
    second, transport, translator, request, validator, binding = setup([], ledger_path=ledger)
    result = await _translate(second, request, validator.hotkey.ss58_address)
    assert result.status == "error"
    assert second.resource_ledger.snapshot(binding).video_fetch_attempts == 2
    assert transport.calls == translator.calls == 0
    second.resource_ledger.close()


def test_unspecified_fetch_error_is_permanent():
    assert VideoFetchError("custom fetcher failure").retryable is False
