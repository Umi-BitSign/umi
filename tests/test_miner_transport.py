from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx
import pytest

from umi.auth import HotkeyAuth, RequestAuthenticator
from umi.backends import Translator
from umi.config import Limits
from umi.miner import MinerRuntime, _identity, _translate, create_app
from umi.protocol import TranslationRequest, canonical_json_bytes
from umi.validator import query_miner
from umi.video import VideoFetcher, VideoFetchError

from .factories import VIDEO_BYTES, challenge_request, dev_wallet


@dataclass(frozen=True)
class StaticFetcher(VideoFetcher):
    video: bytes = VIDEO_BYTES
    failure: bool = False

    async def fetch(self, descriptor) -> bytes:
        if self.failure:
            raise VideoFetchError("fixture failure")
        return self.video


@dataclass(frozen=True)
class StaticTranslator(Translator):
    hypothesis: str = "hello world"
    failure: bool = False

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        assert video == VIDEO_BYTES
        if self.failure:
            raise RuntimeError("fixture model outage")
        return self.hypothesis


@dataclass(frozen=True)
class SlowTranslator(Translator):
    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        await asyncio.sleep(0.05)
        return "too late"


def runtime(*, translator=None, fetcher=None, allowed_wallet=None, limits=None) -> MinerRuntime:
    miner_wallet = dev_wallet("//Bob")
    validator_wallet = allowed_wallet or dev_wallet("//Alice")
    hotkey, scheme = _identity(miner_wallet)
    return MinerRuntime(
        wallet=miner_wallet,
        hotkey_ss58=hotkey,
        signature_scheme=scheme,
        translator=translator or StaticTranslator(),
        video_fetcher=fetcher or StaticFetcher(),
        allowed_validator_hotkeys=frozenset({validator_wallet.hotkey.ss58_address}),
        authenticator=RequestAuthenticator.in_memory(hotkey),
        limits=limits or Limits(),
    )


@pytest.mark.asyncio
async def test_signed_http_round_trip_returns_copy_proof_envelope() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    app = create_app(miner_runtime)
    request = challenge_request()

    outcome = await query_miner(
        request,
        wallet=validator_wallet,
        miner_url="http://miner.test",
        miner_hotkey=miner_runtime.hotkey_ss58,
        limits=Limits(),
        timeout_seconds=5,
        transport=httpx.ASGITransport(app=app),
    )

    assert outcome.failure_code is None
    assert outcome.envelope is not None
    assert outcome.sealed_response is not None
    assert outcome.envelope.validator_hotkey == validator_wallet.hotkey.ss58_address
    assert outcome.envelope.serving_hotkey == miner_runtime.hotkey_ss58
    assert outcome.envelope.response_reveal_round == request.reveal_round
    assert outcome.auth_headers["x-bittensor-hotkey"] == validator_wallet.hotkey.ss58_address
    assert b"hello world" not in (outcome.envelope_bytes or b"")


@pytest.mark.asyncio
async def test_authenticated_but_unlisted_validator_is_rejected() -> None:
    allowed = dev_wallet("//Alice")
    caller = dev_wallet("//Charlie")
    miner_runtime = runtime(allowed_wallet=allowed)
    request = challenge_request()
    body = canonical_json_bytes(request)

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        response = await client.post(
            "/v1/translate",
            content=body,
            auth=HotkeyAuth(caller, miner_runtime.hotkey_ss58),
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_noncanonical_signed_json_is_rejected() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    request = challenge_request()
    body = b"  " + canonical_json_bytes(request)

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        response = await client.post(
            "/v1/translate",
            content=body,
            auth=HotkeyAuth(validator_wallet, miner_runtime.hotkey_ss58),
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_request_body_ceiling_precedes_auth_and_json_parsing() -> None:
    miner_runtime = runtime()
    oversized = b"x" * (miner_runtime.limits.maximum_request_body_bytes + 1)
    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        response = await client.post("/v1/translate", content=oversized)
    assert response.status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("translator", "fetcher", "expected_code"),
    [
        (StaticTranslator(), StaticFetcher(failure=True), "video_fetch_failed"),
        (StaticTranslator(failure=True), StaticFetcher(), "inference_failed"),
        (
            StaticTranslator(hypothesis=" ".join("word" for _ in range(129))),
            StaticFetcher(),
            "hypothesis_invalid",
        ),
        (StaticTranslator(hypothesis="\ud800"), StaticFetcher(), "hypothesis_invalid"),
        (StaticTranslator(hypothesis="a" * 513), StaticFetcher(), "hypothesis_invalid"),
        (StaticTranslator(hypothesis="\0" * 11_000), StaticFetcher(), "hypothesis_invalid"),
    ],
)
async def test_failures_become_explicit_error_plaintexts(
    translator: StaticTranslator,
    fetcher: StaticFetcher,
    expected_code: str,
) -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(
        allowed_wallet=validator_wallet,
        translator=translator,
        fetcher=fetcher,
    )
    plaintext = await _translate(
        miner_runtime,
        challenge_request(),
        validator_wallet.hotkey.ss58_address,
    )
    assert plaintext.status == "error"
    assert plaintext.hypothesis is None
    assert plaintext.error_code == expected_code


@pytest.mark.asyncio
async def test_inference_timeout_becomes_an_explicit_zero_error() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(
        allowed_wallet=validator_wallet,
        translator=SlowTranslator(),
        limits=Limits(inference_timeout_seconds=0.001),
    )
    plaintext = await _translate(
        miner_runtime,
        challenge_request(),
        validator_wallet.hotkey.ss58_address,
    )
    assert plaintext.status == "error"
    assert plaintext.error_code == "inference_failed"


@pytest.mark.asyncio
async def test_health_never_claims_weight_activation_or_conformance() -> None:
    app = create_app(runtime())
    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=app),
    ) as client:
        response = await client.get("/healthz")
    assert response.json() == {
        "ok": True,
        "netuid": 78,
        "translation_weights_active": False,
        "protocol_conformance": False,
    }


@pytest.mark.asyncio
async def test_validator_timeout_caps_the_entire_slow_response() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)

    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10):
                await asyncio.sleep(0.01)
                yield b"x"

        async def aclose(self) -> None:
            return None

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"X-UMI-Signature": "0x" + "00" * 64},
            stream=SlowStream(),
        )

    outcome = await query_miner(
        challenge_request(),
        wallet=validator_wallet,
        miner_url="https://miner.test",
        miner_hotkey=miner_runtime.hotkey_ss58,
        limits=Limits(),
        timeout_seconds=0.02,
        transport=httpx.MockTransport(handler),
    )
    assert outcome.failure_code == "transport_timeout"
    assert outcome.envelope is None


@pytest.mark.asyncio
async def test_validator_counts_duplicate_response_header_lines() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    duplicate_headers = [(b"x-duplicate", b"a" * 100) for _ in range(200)]
    duplicate_headers.append((b"x-umi-signature", b"0x" + b"00" * 64))

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=duplicate_headers, content=b"{}")

    outcome = await query_miner(
        challenge_request(),
        wallet=validator_wallet,
        miner_url="https://miner.test",
        miner_hotkey=miner_runtime.hotkey_ss58,
        limits=Limits(),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
    )
    assert outcome.failure_code == "resource_limit"
    assert outcome.envelope is None


def test_runtime_fails_before_serving_when_hotkey_cannot_sign(monkeypatch) -> None:
    def fail_signing(*_args, **_kwargs):
        raise FileNotFoundError("missing hotkey")

    monkeypatch.setattr("umi.miner.sign_response_digest", fail_signing)
    with pytest.raises(RuntimeError, match="signing preflight failed"):
        runtime()
