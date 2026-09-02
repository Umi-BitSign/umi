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

MODEL_REVISION = "ab" * 32


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


class CountingFetcher(VideoFetcher):
    def __init__(self) -> None:
        self.calls = 0

    async def fetch(self, descriptor) -> bytes:
        self.calls += 1
        return VIDEO_BYTES


class LifecycleTranslator(Translator):
    model_revision = MODEL_REVISION

    def __init__(self, *, startup_delay: float = 0, shutdown_delay: float = 0) -> None:
        self.startup_delay = startup_delay
        self.shutdown_delay = shutdown_delay
        self.events: list[str] = []

    async def startup(self) -> None:
        self.events.append("startup")
        await asyncio.sleep(self.startup_delay)

    async def shutdown(self) -> None:
        self.events.append("shutdown")
        await asyncio.sleep(self.shutdown_delay)

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        return "hello world"


def runtime(
    *,
    translator=None,
    fetcher=None,
    allowed_wallet=None,
    limits=None,
    model_revision=None,
    inference_semaphore=None,
) -> MinerRuntime:
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
        model_revision=model_revision,
        inference_semaphore=inference_semaphore or asyncio.Semaphore(1),
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
async def test_saturated_admission_returns_zero_before_fetching_video() -> None:
    validator_wallet = dev_wallet("//Alice")
    slot = asyncio.Semaphore(1)
    await slot.acquire()
    fetcher = CountingFetcher()
    miner_runtime = runtime(
        allowed_wallet=validator_wallet,
        fetcher=fetcher,
        limits=Limits(inference_admission_timeout_seconds=0.001),
        inference_semaphore=slot,
    )
    try:
        plaintext = await _translate(
            miner_runtime,
            challenge_request(),
            validator_wallet.hotkey.ss58_address,
        )
    finally:
        slot.release()

    assert plaintext.status == "error"
    assert plaintext.error_code == "inference_failed"
    assert plaintext.received_video_sha256 is None
    assert fetcher.calls == 0


@pytest.mark.asyncio
async def test_saturated_admission_still_returns_a_signed_sealed_envelope() -> None:
    validator_wallet = dev_wallet("//Alice")
    slot = asyncio.Semaphore(1)
    await slot.acquire()
    fetcher = CountingFetcher()
    limits = Limits(inference_admission_timeout_seconds=0.001)
    miner_runtime = runtime(
        allowed_wallet=validator_wallet,
        fetcher=fetcher,
        limits=limits,
        inference_semaphore=slot,
    )
    try:
        outcome = await query_miner(
            challenge_request(),
            wallet=validator_wallet,
            miner_url="http://miner.test",
            miner_hotkey=miner_runtime.hotkey_ss58,
            limits=limits,
            timeout_seconds=5,
            transport=httpx.ASGITransport(app=create_app(miner_runtime)),
        )
    finally:
        slot.release()

    assert outcome.failure_code is None
    assert outcome.envelope is not None
    assert outcome.sealed_response is not None
    assert outcome.response_signature is not None
    assert b"inference_failed" not in (outcome.envelope_bytes or b"")
    assert fetcher.calls == 0


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
        "model_revision": None,
    }


@pytest.mark.asyncio
async def test_backend_lifecycle_and_verified_revision_are_exposed() -> None:
    translator = LifecycleTranslator()
    miner_runtime = runtime(translator=translator, model_revision=MODEL_REVISION)
    app = create_app(miner_runtime)

    async with app.router.lifespan_context(app):
        assert translator.events == ["startup"]
        async with httpx.AsyncClient(
            base_url="http://miner.test",
            transport=httpx.ASGITransport(app=app),
        ) as client:
            response = await client.get("/healthz")
        assert response.json()["model_revision"] == MODEL_REVISION

    assert translator.events == ["startup", "shutdown"]


@pytest.mark.asyncio
async def test_backend_startup_and_shutdown_hooks_are_time_bounded() -> None:
    slow_start = LifecycleTranslator(startup_delay=0.05)
    start_app = create_app(
        runtime(
            translator=slow_start,
            limits=Limits(backend_lifecycle_timeout_seconds=0.001),
        )
    )
    with pytest.raises(RuntimeError, match="startup hook timed out"):
        async with start_app.router.lifespan_context(start_app):
            pass
    assert slow_start.events == ["startup", "shutdown"]

    slow_shutdown = LifecycleTranslator(shutdown_delay=0.05)
    shutdown_app = create_app(
        runtime(
            translator=slow_shutdown,
            limits=Limits(backend_lifecycle_timeout_seconds=0.001),
        )
    )
    with pytest.raises(RuntimeError, match="shutdown hook timed out"):
        async with shutdown_app.router.lifespan_context(shutdown_app):
            pass
    assert slow_shutdown.events == ["startup", "shutdown"]


def test_configured_model_revision_must_match_loaded_backend_identity() -> None:
    translated = LifecycleTranslator()
    assert runtime(translator=translated).model_revision == MODEL_REVISION
    assert (
        runtime(translator=translated, model_revision=MODEL_REVISION).model_revision
        == MODEL_REVISION
    )

    with pytest.raises(ValueError, match="does not match"):
        runtime(translator=translated, model_revision="cd" * 32)
    with pytest.raises(ValueError, match="requires the translation backend"):
        runtime(translator=StaticTranslator(), model_revision=MODEL_REVISION)


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
