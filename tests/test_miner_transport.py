from __future__ import annotations

import asyncio
import gzip
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import bittensor as bt
import httpx
import pytest

from umi.auth import REQUEST_BODY_SHA256_HEADER, HotkeyAuth, RequestAuthenticator
from umi.backends import Translator
from umi.config import Limits
from umi.encoding import account_id32
from umi.miner import (
    IngressLimitExceeded,
    MinerRuntime,
    _authenticated_ingress_slot,
    _authenticated_request_task_limits,
    _effective_inference_concurrency,
    _identity,
    _load_policy,
    _translate,
    _uvicorn_limits,
    create_app,
)
from umi.miner_admission import (
    LocalComponentWindowAuthority,
    MinerAdmissionError,
    MinerWindowAdmission,
)
from umi.miner_resources import (
    MinerAssignmentBinding,
    MinerResourceError,
    SQLiteMinerResourceLedger,
)
from umi.protocol import TranslationRequest, canonical_json_bytes
from umi.resources import ResourceLedger
from umi.validator import prepare_request_attempt, query_miner, send_prepared_request
from umi.video import VideoFetcher, VideoFetchError

from .factories import VIDEO_BYTES, challenge_request, dev_wallet
from .test_policy import make_policy


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


@dataclass
class CountingFetcher(VideoFetcher):
    calls: int = 0

    async def fetch(self, descriptor) -> bytes:
        self.calls += 1
        return VIDEO_BYTES


@dataclass
class CountingTranslator(Translator):
    calls: int = 0

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        self.calls += 1
        return "hello world"


@dataclass
class LifecycleProbeTranslator(Translator):
    startup_entered: asyncio.Event
    shutdown_entered: asyncio.Event

    async def startup(self) -> None:
        self.startup_entered.set()

    async def shutdown(self) -> None:
        self.shutdown_entered.set()

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        return "hello world"


@dataclass
class BlockingLifecycleTranslator(Translator):
    shutdown_entered: asyncio.Event

    async def startup(self) -> None:
        await asyncio.Event().wait()

    async def shutdown(self) -> None:
        self.shutdown_entered.set()

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        return "hello world"


@dataclass
class CoordinatedFetcher(VideoFetcher):
    started: asyncio.Event
    release: asyncio.Event
    calls: int = 0

    async def fetch(self, descriptor) -> bytes:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return VIDEO_BYTES


@dataclass
class CoordinatedTranslator(Translator):
    started: asyncio.Event
    release: asyncio.Event
    calls: int = 0

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return "hello world"


@dataclass
class FairnessTranslator(Translator):
    first_started: asyncio.Event
    two_started: asyncio.Event
    release: asyncio.Event
    started: list[str]

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        self.started.append(request.challenge_id)
        if len(self.started) == 1:
            self.first_started.set()
        if len(self.started) == 2:
            self.two_started.set()
        await self.release.wait()
        return "hello world"


@dataclass
class FetchFairnessProbe(VideoFetcher):
    attacker_started: asyncio.Event
    honest_started: asyncio.Event
    release_attacker: asyncio.Event
    bodies: dict[str, bytes]
    active_attackers: int = 0
    maximum_active_attackers: int = 0

    async def fetch(self, descriptor) -> bytes:
        if "/attacker-" in str(descriptor.url):
            self.active_attackers += 1
            self.maximum_active_attackers = max(
                self.maximum_active_attackers,
                self.active_attackers,
            )
            self.attacker_started.set()
            try:
                await self.release_attacker.wait()
            finally:
                self.active_attackers -= 1
        else:
            self.honest_started.set()
        return self.bodies[descriptor.sha256]


@dataclass(frozen=True)
class NonTextTranslator(Translator):
    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        return 42  # type: ignore[return-value]


@dataclass
class RejectingWindowAuthority:
    retryable: bool = False
    calls: int = 0

    async def authorize(self, request: TranslationRequest) -> MinerWindowAdmission:
        self.calls += 1
        raise MinerAdmissionError("request_window_binding_mismatch", retryable=self.retryable)


def runtime(
    *,
    translator=None,
    fetcher=None,
    allowed_wallet=None,
    allowed_wallets=None,
    authenticator=None,
    limits=None,
    model_revision=None,
    ledger_path: str | Path = ":memory:",
    window_authority=None,
) -> MinerRuntime:
    miner_wallet = dev_wallet("//Bob")
    validators = tuple(allowed_wallets or ((allowed_wallet or dev_wallet("//Alice")),))
    hotkey, scheme = _identity(miner_wallet)
    selected_limits = limits or Limits(maximum_inference_concurrency=len(validators))
    policy_hash = "20" * 32
    return MinerRuntime(
        wallet=miner_wallet,
        hotkey_ss58=hotkey,
        signature_scheme=scheme,
        translator=translator or StaticTranslator(),
        video_fetcher=fetcher or StaticFetcher(),
        allowed_validator_hotkeys=frozenset(
            validator.hotkey.ss58_address for validator in validators
        ),
        authenticator=authenticator or RequestAuthenticator.in_memory(hotkey),
        limits=selected_limits,
        scoring_policy_sha256=policy_hash,
        response_deadline_blocks=10,
        resource_ledger=SQLiteMinerResourceLedger(
            ledger_path,
            miner_hotkey=hotkey,
            scoring_policy_sha256=policy_hash,
            limits=selected_limits,
        ),
        window_authority=window_authority or LocalComponentWindowAuthority(),
        model_revision=model_revision,
        inference_semaphore=asyncio.Semaphore(selected_limits.maximum_inference_concurrency),
        work_semaphore=asyncio.Semaphore(selected_limits.maximum_inference_concurrency),
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
async def test_app_lifespan_starts_and_stops_the_model_backend() -> None:
    startup_entered = asyncio.Event()
    shutdown_entered = asyncio.Event()
    app = create_app(
        runtime(
            translator=LifecycleProbeTranslator(startup_entered, shutdown_entered),
        )
    )

    async with app.router.lifespan_context(app):
        assert startup_entered.is_set()
        assert not shutdown_entered.is_set()

    assert shutdown_entered.is_set()


@pytest.mark.asyncio
async def test_model_startup_is_bounded_before_the_miner_serves() -> None:
    shutdown_entered = asyncio.Event()
    app = create_app(
        runtime(
            translator=BlockingLifecycleTranslator(shutdown_entered),
            limits=Limits(backend_lifecycle_timeout_seconds=0.01),
        )
    )

    with pytest.raises(asyncio.TimeoutError):
        async with app.router.lifespan_context(app):
            raise AssertionError("a miner with an unready model must not serve")
    assert shutdown_entered.is_set()


@pytest.mark.asyncio
async def test_inference_capacity_wait_is_bounded() -> None:
    selected_limits = Limits(
        maximum_inference_concurrency=1,
        inference_admission_timeout_seconds=0.01,
    )
    miner_runtime = runtime(limits=selected_limits)
    await miner_runtime.inference_semaphore.acquire()
    try:
        plaintext = await _translate(
            miner_runtime,
            challenge_request(),
            dev_wallet("//Alice").hotkey.ss58_address,
        )
    finally:
        miner_runtime.inference_semaphore.release()

    assert plaintext.status == "error"
    assert plaintext.error_code == "inference_failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(("retryable", "status"), ((False, 422), (True, 503)))
async def test_window_authority_rejects_before_resource_or_model_work(
    retryable: bool,
    status: int,
) -> None:
    validator_wallet = dev_wallet("//Alice")
    fetcher = CountingFetcher()
    translator = CountingTranslator()
    authority = RejectingWindowAuthority(retryable=retryable)
    miner_runtime = runtime(
        allowed_wallet=validator_wallet,
        fetcher=fetcher,
        translator=translator,
        window_authority=authority,
    )
    request = challenge_request()
    binding = MinerAssignmentBinding.from_request(
        request,
        validator_hotkey=validator_wallet.hotkey.ss58_address,
    )
    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        response = await client.post(
            "/v1/translate",
            content=canonical_json_bytes(request),
            auth=HotkeyAuth(validator_wallet, miner_runtime.hotkey_ss58),
        )

    assert response.status_code == status
    assert response.json()["detail"] == "request_window_binding_mismatch"
    assert authority.calls == 1
    assert fetcher.calls == translator.calls == 0
    with pytest.raises(MinerResourceError, match="assignment_not_recorded"):
        miner_runtime.resource_ledger.snapshot(binding)


@pytest.mark.asyncio
async def test_retry_reuses_one_encrypted_response_without_repeating_inference() -> None:
    validator_wallet = dev_wallet("//Alice")
    fetcher = CountingFetcher()
    translator = CountingTranslator()
    miner_runtime = runtime(
        allowed_wallet=validator_wallet,
        fetcher=fetcher,
        translator=translator,
    )
    request = challenge_request()
    body = canonical_json_bytes(request)
    binding = MinerAssignmentBinding.from_request(
        request,
        validator_hotkey=validator_wallet.hotkey.ss58_address,
    )

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        first = await client.post(
            "/v1/translate",
            content=body,
            auth=HotkeyAuth(validator_wallet, miner_runtime.hotkey_ss58),
        )
        second = await client.post(
            "/v1/translate",
            content=body,
            auth=HotkeyAuth(validator_wallet, miner_runtime.hotkey_ss58),
        )
        third = await client.post(
            "/v1/translate",
            content=body,
            auth=HotkeyAuth(validator_wallet, miner_runtime.hotkey_ss58),
        )

    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert first.headers["x-umi-signature"] == second.headers["x-umi-signature"]
    assert third.status_code == 429
    assert third.json()["detail"] == "request_transmission_limit"
    assert fetcher.calls == translator.calls == 1
    snapshot = miner_runtime.resource_ledger.snapshot(binding)
    assert snapshot.request_transmissions == 2
    assert snapshot.video_fetch_attempts == 1
    assert snapshot.response_bodies == 2


@pytest.mark.asyncio
async def test_overlapping_retry_waits_for_and_reuses_the_first_sealed_response() -> None:
    validator_wallet = dev_wallet("//Alice")
    fetcher = CountingFetcher()
    translator = CoordinatedTranslator(asyncio.Event(), asyncio.Event())
    miner_runtime = runtime(
        allowed_wallet=validator_wallet,
        fetcher=fetcher,
        translator=translator,
    )
    request = challenge_request()
    body = canonical_json_bytes(request)
    binding = MinerAssignmentBinding.from_request(
        request,
        validator_hotkey=validator_wallet.hotkey.ss58_address,
    )

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        first_task = asyncio.create_task(
            client.post(
                "/v1/translate",
                content=body,
                auth=HotkeyAuth(validator_wallet, miner_runtime.hotkey_ss58),
            )
        )
        await translator.started.wait()
        second_task = asyncio.create_task(
            client.post(
                "/v1/translate",
                content=body,
                auth=HotkeyAuth(validator_wallet, miner_runtime.hotkey_ss58),
            )
        )
        await asyncio.sleep(0.02)
        assert translator.calls == 1
        translator.release.set()
        first, second = await asyncio.gather(first_task, second_task)

    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert first.headers["x-umi-signature"] == second.headers["x-umi-signature"]
    assert fetcher.calls == translator.calls == 1
    snapshot = miner_runtime.resource_ledger.snapshot(binding)
    assert snapshot.request_transmissions == 2
    assert snapshot.response_bodies == 2


@pytest.mark.asyncio
async def test_one_validator_cannot_fill_the_global_inference_queue() -> None:
    first_validator = dev_wallet("//Alice")
    second_validator = dev_wallet("//Charlie")
    model = FairnessTranslator(asyncio.Event(), asyncio.Event(), asyncio.Event(), [])
    miner_runtime = runtime(
        translator=model,
        limits=Limits(maximum_inference_concurrency=2),
        allowed_wallets=(first_validator, second_validator),
    )
    first_request = challenge_request(1)
    queued_same_validator = challenge_request(2)
    other_validator_request = challenge_request(3)

    first = asyncio.create_task(
        _translate(miner_runtime, first_request, first_validator.hotkey.ss58_address)
    )
    await asyncio.wait_for(model.first_started.wait(), timeout=1)
    same_validator = asyncio.create_task(
        _translate(
            miner_runtime,
            queued_same_validator,
            first_validator.hotkey.ss58_address,
        )
    )
    other_validator = asyncio.create_task(
        _translate(
            miner_runtime,
            other_validator_request,
            second_validator.hotkey.ss58_address,
        )
    )
    await asyncio.wait_for(model.two_started.wait(), timeout=1)

    assert model.started == [first_request.challenge_id, other_validator_request.challenge_id]
    model.release.set()
    await asyncio.gather(first, same_validator, other_validator)
    assert model.started[-1] == queued_same_validator.challenge_id


@pytest.mark.parametrize(
    ("requested", "validators", "expected"),
    ((None, 4, 4), (8, 4, 8)),
)
def test_inference_concurrency_reserves_one_slot_per_validator(
    requested: int | None,
    validators: int,
    expected: int,
) -> None:
    assert _effective_inference_concurrency(requested, validator_count=validators) == expected


def test_inference_concurrency_rejects_a_value_below_validator_count() -> None:
    with pytest.raises(ValueError, match="one slot per policy validator"):
        _effective_inference_concurrency(3, validator_count=4)


def test_inference_concurrency_rejects_an_unequal_validator_partition() -> None:
    with pytest.raises(ValueError, match="multiple of the policy validator count"):
        _effective_inference_concurrency(7, validator_count=4)


@pytest.mark.asyncio
async def test_extra_inference_slots_are_partitioned_fairly_between_validators() -> None:
    first_validator = dev_wallet("//Alice")
    second_validator = dev_wallet("//Charlie")
    started = asyncio.Queue[str]()
    release = asyncio.Event()

    @dataclass
    class ProbeTranslator(Translator):
        async def translate(self, video: bytes, request: TranslationRequest) -> str:
            await started.put(request.challenge_id)
            await release.wait()
            return "hello world"

    miner_runtime = runtime(
        translator=ProbeTranslator(),
        limits=Limits(maximum_inference_concurrency=4),
        allowed_wallets=(first_validator, second_validator),
    )
    first_requests = [challenge_request(index) for index in range(1, 4)]
    second_requests = [challenge_request(index) for index in range(4, 6)]
    tasks = [
        asyncio.create_task(_translate(miner_runtime, request, first_validator.hotkey.ss58_address))
        for request in first_requests
    ]
    tasks.extend(
        asyncio.create_task(
            _translate(miner_runtime, request, second_validator.hotkey.ss58_address)
        )
        for request in second_requests
    )
    try:
        observed = {await asyncio.wait_for(started.get(), timeout=1) for _index in range(4)}
        assert observed == {
            first_requests[0].challenge_id,
            first_requests[1].challenge_id,
            second_requests[0].challenge_id,
            second_requests[1].challenge_id,
        }
    finally:
        release.set()
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_authenticated_ingress_accepts_the_full_launch_attempt_burst() -> None:
    validators = tuple(dev_wallet(seed) for seed in ("//Alice", "//Charlie", "//Dave", "//Eve"))
    miner_runtime = runtime(allowed_wallets=validators)
    accounts = tuple(account_id32(wallet.hotkey.ss58_address).hex() for wallet in validators)
    per_validator_limit, total_limit = _authenticated_request_task_limits(miner_runtime)
    assert (per_validator_limit, total_limit) == (56, 224)

    release = asyncio.Event()
    entered = asyncio.Queue[str]()

    async def occupy(account: str) -> None:
        async with _authenticated_ingress_slot(miner_runtime, account):
            await entered.put(account)
            await release.wait()

    tasks = [
        asyncio.create_task(occupy(account))
        for account in accounts
        for _index in range(per_validator_limit)
    ]
    try:
        observed = [
            await asyncio.wait_for(entered.get(), timeout=1) for _index in range(total_limit)
        ]
        assert {account: observed.count(account) for account in accounts} == {
            account: per_validator_limit for account in accounts
        }
        assert sum(miner_runtime.active_ingress_accounts.values()) == total_limit
        with pytest.raises(IngressLimitExceeded, match="validator_ingress_busy"):
            async with _authenticated_ingress_slot(miner_runtime, accounts[0]):
                pytest.fail("the per-validator ingress ceiling was not enforced")
    finally:
        release.set()
        await asyncio.gather(*tasks)
    assert miner_runtime.active_ingress_accounts == {}


@pytest.mark.asyncio
async def test_hung_validators_cannot_consume_the_last_validator_inference_slot() -> None:
    validators = tuple(dev_wallet(seed) for seed in ("//Alice", "//Charlie", "//Dave", "//Eve"))
    started = asyncio.Queue[str]()
    release = asyncio.Event()

    @dataclass
    class ProbeTranslator(Translator):
        async def translate(self, video: bytes, request: TranslationRequest) -> str:
            await started.put(request.challenge_id)
            await release.wait()
            return "hello world"

    miner_runtime = runtime(
        translator=ProbeTranslator(),
        allowed_wallets=validators,
    )
    tasks = [
        asyncio.create_task(
            _translate(
                miner_runtime,
                challenge_request(index),
                validator.hotkey.ss58_address,
            )
        )
        for index, validator in enumerate(validators, start=1)
    ]
    try:
        observed = {await asyncio.wait_for(started.get(), timeout=1) for _validator in validators}
        assert observed == {
            challenge_request(index).challenge_id for index in range(1, len(validators) + 1)
        }
    finally:
        release.set()
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_one_validator_cannot_fill_fetch_slots_or_delay_another_validator() -> None:
    first_validator = dev_wallet("//Alice")
    second_validator = dev_wallet("//Charlie")
    bodies: dict[str, bytes] = {}

    def unique_request(index: int, *, owner: str) -> TranslationRequest:
        video = f"video-{owner}-{index}".encode()
        digest = hashlib.sha256(video).hexdigest()
        bodies[digest] = video
        request = challenge_request(index)
        return request.model_copy(
            update={
                "video": request.video.model_copy(
                    update={
                        "url": f"https://videos.example/{owner}-{index}",
                        "sha256": digest,
                        "size_bytes": len(video),
                    }
                )
            }
        )

    fetcher = FetchFairnessProbe(
        attacker_started=asyncio.Event(),
        honest_started=asyncio.Event(),
        release_attacker=asyncio.Event(),
        bodies=bodies,
    )
    miner_runtime = runtime(
        fetcher=fetcher,
        translator=CountingTranslator(),
        allowed_wallets=(first_validator, second_validator),
    )
    attacker_requests = [unique_request(index, owner="attacker") for index in range(1, 29)]
    honest_request = unique_request(100, owner="honest")

    attacker_tasks = [
        asyncio.create_task(_translate(miner_runtime, request, first_validator.hotkey.ss58_address))
        for request in attacker_requests
    ]
    await asyncio.wait_for(fetcher.attacker_started.wait(), timeout=1)
    honest_task = asyncio.create_task(
        _translate(miner_runtime, honest_request, second_validator.hotkey.ss58_address)
    )
    await asyncio.wait_for(fetcher.honest_started.wait(), timeout=1)

    assert fetcher.maximum_active_attackers == 1
    assert (await honest_task).status == "ok"
    fetcher.release_attacker.set()
    results = await asyncio.gather(*attacker_tasks)
    assert all(result.status == "ok" for result in results)
    assert fetcher.maximum_active_attackers == 1


@pytest.mark.asyncio
async def test_restart_reuses_the_exact_signed_envelope_without_model_work(
    tmp_path: Path,
) -> None:
    validator_wallet = dev_wallet("//Alice")
    database = tmp_path / "assignments.sqlite3"
    first_fetcher = CountingFetcher()
    first_translator = CountingTranslator()
    first_runtime = runtime(
        allowed_wallet=validator_wallet,
        fetcher=first_fetcher,
        translator=first_translator,
        ledger_path=database,
    )
    request = challenge_request()
    body = canonical_json_bytes(request)
    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(first_runtime)),
    ) as client:
        first = await client.post(
            "/v1/translate",
            content=body,
            auth=HotkeyAuth(validator_wallet, first_runtime.hotkey_ss58),
        )
    first_runtime.resource_ledger.close()

    second_fetcher = CountingFetcher()
    second_translator = CountingTranslator()
    restarted = runtime(
        allowed_wallet=validator_wallet,
        fetcher=second_fetcher,
        translator=second_translator,
        ledger_path=database,
    )
    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(restarted)),
    ) as client:
        second = await client.post(
            "/v1/translate",
            content=body,
            auth=HotkeyAuth(validator_wallet, restarted.hotkey_ss58),
        )

    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert first.headers["x-umi-signature"] == second.headers["x-umi-signature"]
    assert first_fetcher.calls == first_translator.calls == 1
    assert second_fetcher.calls == second_translator.calls == 0


@pytest.mark.asyncio
async def test_overlapping_validators_do_not_share_unverified_fetch_state() -> None:
    first_validator = dev_wallet("//Alice")
    second_validator = dev_wallet("//Charlie")
    fetcher = CoordinatedFetcher(asyncio.Event(), asyncio.Event())
    translator = CountingTranslator()
    miner_runtime = runtime(
        fetcher=fetcher,
        translator=translator,
        allowed_wallets=(first_validator, second_validator),
    )
    request = challenge_request()

    first = asyncio.create_task(
        _translate(miner_runtime, request, first_validator.hotkey.ss58_address)
    )
    await fetcher.started.wait()
    second = asyncio.create_task(
        _translate(miner_runtime, request, second_validator.hotkey.ss58_address)
    )
    await asyncio.sleep(0.03)
    assert fetcher.calls == 2
    fetcher.release.set()

    first_plaintext, second_plaintext = await asyncio.gather(first, second)
    assert first_plaintext.status == second_plaintext.status == "ok"
    assert fetcher.calls == 2
    assert translator.calls == 2


@pytest.mark.asyncio
async def test_request_can_be_signed_and_self_verified_before_transmission() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    request = challenge_request()
    prepared = prepare_request_attempt(
        request,
        wallet=validator_wallet,
        miner_hotkey=miner_runtime.hotkey_ss58,
    )

    assert prepared.request_bytes == canonical_json_bytes(request)
    assert prepared.auth_evidence.request_bytes == prepared.request_bytes
    assert prepared.auth_evidence.auth_record.sender == validator_wallet.hotkey.ss58_address
    assert prepared.auth_evidence.auth_record.receiver == miner_runtime.hotkey_ss58

    ledger = ResourceLedger(
        maximum_assignment_wire_bytes=1_000_000,
        maximum_window_wire_bytes=1_000_000,
    )
    outcome = await send_prepared_request(
        prepared,
        miner_url="http://miner.test",
        limits=Limits(),
        timeout_seconds=5,
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
        resource_ledger=ledger,
        assignment_id="assignment-1",
    )
    assert outcome.failure_code is None
    snapshot = ledger.snapshot()
    assert snapshot.attempts == (
        ("request:assignment-1", 1),
        ("response:assignment-1", 1),
    )
    assert snapshot.assignment_wire_bytes[0][1] > len(prepared.request_bytes)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resolved_addresses",
    [
        (),
        ("127.0.0.1",),
        ("10.0.0.1",),
        ("1.1.1.1", "192.168.1.1"),
    ],
)
async def test_validator_rejects_empty_nonpublic_or_mixed_dns_answers(
    resolved_addresses: tuple[str, ...],
) -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    prepared = prepare_request_attempt(
        challenge_request(),
        wallet=validator_wallet,
        miner_hotkey=miner_runtime.hotkey_ss58,
    )
    handler_called = False

    async def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        return resolved_addresses

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal handler_called
        handler_called = True
        return httpx.Response(503)

    outcome = await send_prepared_request(
        prepared,
        miner_url="https://miner.example",
        limits=Limits(),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )

    assert outcome.failure_code == "transport_error"
    assert not handler_called


@pytest.mark.asyncio
async def test_validator_pins_one_public_ip_and_preserves_host_and_tls_name() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    prepared = prepare_request_attempt(
        challenge_request(),
        wallet=validator_wallet,
        miner_hotkey=miner_runtime.hotkey_ss58,
    )
    resolver_calls: list[tuple[str, int]] = []
    observed: dict[str, object] = {}

    async def resolver(hostname: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((hostname, port))
        return ("2606:4700:4700::1111", "8.8.8.8", "1.1.1.1")

    async def handler(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["host"] = request.headers["host"]
        observed["sni_hostname"] = request.extensions["sni_hostname"]
        return httpx.Response(503)

    outcome = await send_prepared_request(
        prepared,
        miner_url="https://Miner.Example:8443",
        limits=Limits(),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )

    assert outcome.failure_code == "http_error"
    assert resolver_calls == [("miner.example", 8443)]
    assert observed == {
        "url": "https://1.1.1.1:8443/v1/translate",
        "host": "miner.example:8443",
        "sni_hostname": "miner.example",
    }


@pytest.mark.asyncio
async def test_validator_rejects_plain_http_before_public_resolution_or_transport() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    prepared = prepare_request_attempt(
        challenge_request(),
        wallet=validator_wallet,
        miner_hotkey=miner_runtime.hotkey_ss58,
    )
    resolver_called = False
    handler_called = False

    async def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        nonlocal resolver_called
        resolver_called = True
        return ("1.1.1.1",)

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal handler_called
        handler_called = True
        return httpx.Response(503)

    outcome = await send_prepared_request(
        prepared,
        miner_url="http://miner.example",
        limits=Limits(),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )

    assert outcome.failure_code == "transport_error"
    assert not resolver_called
    assert not handler_called


@pytest.mark.asyncio
async def test_oversized_response_preserves_only_bounded_prefix_hash() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    prepared = prepare_request_attempt(
        challenge_request(),
        wallet=validator_wallet,
        miner_hotkey=miner_runtime.hotkey_ss58,
    )

    class OneChunkStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * 100

        async def aclose(self) -> None:
            return None

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200,
            headers={"X-UMI-Signature": "0x" + "00" * 64},
            stream=OneChunkStream(),
        )

    outcome = await send_prepared_request(
        prepared,
        miner_url="https://miner.test",
        limits=Limits(maximum_response_body_bytes=10),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
    )
    assert outcome.failure_code == "resource_limit"
    assert outcome.envelope_bytes is None
    assert outcome.received_bytes_sha256 == hashlib.sha256(b"x" * 10).hexdigest()
    assert outcome.received_body_prefix == b"x" * 10


@pytest.mark.asyncio
async def test_encoded_response_is_rejected_before_decompression_or_body_read() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    prepared = prepare_request_attempt(
        challenge_request(),
        wallet=validator_wallet,
        miner_hotkey=miner_runtime.hotkey_ss58,
    )
    encoded = gzip.compress(b"x" * (8 * 1024 * 1024))
    assert len(encoded) < Limits().maximum_response_body_bytes

    class EncodedStream(httpx.AsyncByteStream):
        iterated = False

        async def __aiter__(self):
            self.iterated = True
            yield encoded

        async def aclose(self) -> None:
            return None

    stream = EncodedStream()

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200,
            headers={
                "Content-Encoding": "gzip",
                "Content-Length": str(len(encoded)),
                "X-UMI-Signature": "0x" + "00" * 64,
            },
            stream=stream,
        )

    outcome = await send_prepared_request(
        prepared,
        miner_url="https://miner.test",
        limits=Limits(),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
    )

    assert outcome.failure_code == "outer_invalid"
    assert outcome.envelope_bytes is None
    assert outcome.received_bytes_sha256 == hashlib.sha256(b"").hexdigest()
    assert outcome.received_body_prefix == b""
    assert not stream.iterated


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
async def test_unlisted_claim_is_rejected_before_body_auth_and_nonce_mutation(tmp_path) -> None:
    allowed = dev_wallet("//Alice")
    caller = dev_wallet("//Charlie")
    miner_hotkey, _scheme = _identity(dev_wallet("//Bob"))
    authenticator = RequestAuthenticator.sqlite(
        miner_hotkey,
        tmp_path / "nonces.sqlite3",
        allowed_hotkeys=(allowed.hotkey.ss58_address,),
        maximum_nonces_per_hotkey=2,
        maximum_total_nonces=2,
        maximum_database_bytes=128 * 1024,
    )
    miner_runtime = runtime(
        allowed_wallet=allowed,
        authenticator=authenticator,
    )

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        response = await client.post(
            "/v1/translate",
            content=canonical_json_bytes(challenge_request()),
            auth=HotkeyAuth(caller, miner_runtime.hotkey_ss58),
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "claimed caller is not allowed"
    assert authenticator.nonce_store.row_count() == 0


@pytest.mark.asyncio
async def test_signed_malformed_requests_are_bounded_before_assignment_state(tmp_path) -> None:
    validator = dev_wallet("//Alice")
    miner_hotkey, _scheme = _identity(dev_wallet("//Bob"))
    authenticator = RequestAuthenticator.sqlite(
        miner_hotkey,
        tmp_path / "nonces.sqlite3",
        allowed_hotkeys=(validator.hotkey.ss58_address,),
        maximum_nonces_per_hotkey=2,
        maximum_total_nonces=2,
        maximum_database_bytes=128 * 1024,
    )
    miner_runtime = runtime(
        allowed_wallet=validator,
        authenticator=authenticator,
    )

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        responses = [
            await client.post(
                "/v1/translate",
                content=b"{}",
                auth=HotkeyAuth(validator, miner_runtime.hotkey_ss58),
            )
            for _index in range(3)
        ]

    assert [response.status_code for response in responses] == [422, 422, 429]
    assert responses[-1].json()["detail"] == "nonce_store_capacity"
    assert authenticator.nonce_store.row_count() == 2


@pytest.mark.asyncio
async def test_duplicate_sender_header_is_rejected_before_nonce_mutation(tmp_path) -> None:
    validator = dev_wallet("//Alice")
    miner_hotkey, _scheme = _identity(dev_wallet("//Bob"))
    authenticator = RequestAuthenticator.sqlite(
        miner_hotkey,
        tmp_path / "nonces.sqlite3",
        allowed_hotkeys=(validator.hotkey.ss58_address,),
        maximum_nonces_per_hotkey=2,
        maximum_total_nonces=2,
        maximum_database_bytes=128 * 1024,
    )
    miner_runtime = runtime(allowed_wallet=validator, authenticator=authenticator)
    body = canonical_json_bytes(challenge_request())
    headers = bt.http_auth.sign(
        validator,
        method="POST",
        path="/v1/translate",
        body=body,
        receiver_ss58=miner_runtime.hotkey_ss58,
    )
    duplicated = [
        *headers.items(),
        (bt.http_auth.HEADER_HOTKEY, validator.hotkey.ss58_address),
    ]

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        response = await client.post(
            "/v1/translate",
            content=body,
            headers=duplicated,
        )

    assert response.status_code == 401
    assert authenticator.nonce_store.row_count() == 0


@pytest.mark.asyncio
async def test_unsigned_slow_claims_cannot_reserve_authenticated_validator_slot() -> None:
    validator = dev_wallet("//Alice")
    attacker = dev_wallet("//Mallory")
    limits = Limits(request_body_timeout_seconds=0.2)
    miner_runtime = runtime(
        allowed_wallet=validator,
        limits=limits,
    )
    started_count = 0

    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal started_count
            started_count += 1
            await asyncio.Event().wait()
            yield b"unreachable"

        async def aclose(self) -> None:
            return None

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        forged_headers = bt.http_auth.sign(
            attacker,
            method="POST",
            path="/v1/translate",
            body=b"{}",
            receiver_ss58=miner_runtime.hotkey_ss58,
        )
        forged_headers[bt.http_auth.HEADER_HOTKEY] = validator.hotkey.ss58_address
        forged_headers[REQUEST_BODY_SHA256_HEADER] = hashlib.sha256(b"{}").hexdigest()
        slow_tasks = [
            asyncio.create_task(
                client.send(
                    client.build_request(
                        "POST",
                        "/v1/translate",
                        headers=forged_headers,
                        content=SlowBody(),
                    )
                )
            )
            for _index in range(4)
        ]
        await asyncio.sleep(0)

        legitimate = await asyncio.wait_for(
            client.post(
                "/v1/translate",
                content=canonical_json_bytes(challenge_request(2)),
                auth=HotkeyAuth(validator, miner_runtime.hotkey_ss58),
            ),
            timeout=1,
        )
        slow = await asyncio.wait_for(asyncio.gather(*slow_tasks), timeout=1)

    assert legitimate.status_code == 200
    assert [response.status_code for response in slow] == [401, 401, 401, 401]
    assert started_count == 0


@pytest.mark.asyncio
async def test_signed_route_burst_is_not_rejected_by_the_preauth_guard() -> None:
    first_validator = dev_wallet("//Alice")
    second_validator = dev_wallet("//Charlie")
    started = asyncio.Queue[str]()
    release = asyncio.Event()

    @dataclass
    class BlockingTranslator(Translator):
        calls: int = 0

        async def translate(self, video: bytes, request: TranslationRequest) -> str:
            self.calls += 1
            await started.put(request.challenge_id)
            await release.wait()
            return "hello world"

    translator = BlockingTranslator()
    miner_runtime = runtime(
        translator=translator,
        allowed_wallets=(first_validator, second_validator),
        limits=Limits(
            maximum_assignments_per_validator_window=4,
            maximum_total_assignments_per_window=8,
            maximum_inference_concurrency=2,
        ),
    )
    assert miner_runtime.maximum_preauth_concurrency == 4
    requests = (
        *((first_validator, challenge_request(index)) for index in range(1, 5)),
        *((second_validator, challenge_request(index)) for index in range(5, 9)),
    )

    async with httpx.AsyncClient(
        base_url="http://miner.test",
        transport=httpx.ASGITransport(app=create_app(miner_runtime)),
    ) as client:
        tasks = [
            asyncio.create_task(
                client.post(
                    "/v1/translate",
                    content=canonical_json_bytes(request),
                    auth=HotkeyAuth(validator, miner_runtime.hotkey_ss58),
                )
            )
            for validator, request in requests
        ]
        try:
            observed = {await asyncio.wait_for(started.get(), timeout=2) for _index in range(2)}
            assert observed == {requests[0][1].challenge_id, requests[4][1].challenge_id}
            assert not any(task.done() for task in tasks)
        finally:
            release.set()
        responses = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)

    assert [response.status_code for response in responses] == [200] * 8
    assert translator.calls == 8
    assert miner_runtime.active_preauth_tokens == set()
    assert miner_runtime.active_ingress_accounts == {}


def test_launch_connection_limit_covers_every_bounded_signed_attempt() -> None:
    validators = tuple(dev_wallet(seed) for seed in ("//Alice", "//Charlie", "//Dave", "//Eve"))
    miner_runtime = runtime(allowed_wallets=validators)
    assert _authenticated_request_task_limits(miner_runtime) == (56, 224)

    assert _uvicorn_limits(miner_runtime) == {
        "limit_concurrency": 236,
        "backlog": 472,
        "timeout_keep_alive": 5,
    }


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
async def test_request_for_a_different_policy_is_rejected_before_resource_state() -> None:
    validator_wallet = dev_wallet("//Alice")
    miner_runtime = runtime(allowed_wallet=validator_wallet)
    request = challenge_request().model_copy(update={"scoring_policy_hash": "99" * 32})
    body = canonical_json_bytes(request)

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
    assert response.json()["detail"] == "request scoring policy does not match"


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
async def test_model_revision_is_bound_only_to_successful_model_output() -> None:
    validator_wallet = dev_wallet("//Alice")
    revision = "ab" * 32
    miner_runtime = runtime(allowed_wallet=validator_wallet, model_revision=revision)
    plaintext = await _translate(
        miner_runtime,
        challenge_request(),
        validator_wallet.hotkey.ss58_address,
    )
    assert plaintext.status == "ok"
    assert plaintext.model_revision == revision

    failed = await _translate(
        runtime(
            allowed_wallet=validator_wallet,
            translator=StaticTranslator(failure=True),
            model_revision=revision,
        ),
        challenge_request(),
        validator_wallet.hotkey.ss58_address,
    )
    assert failed.status == "error"
    assert failed.model_revision is None


@pytest.mark.asyncio
async def test_non_text_model_result_becomes_an_explicit_zero_error() -> None:
    validator_wallet = dev_wallet("//Alice")
    plaintext = await _translate(
        runtime(allowed_wallet=validator_wallet, translator=NonTextTranslator()),
        challenge_request(),
        validator_wallet.hotkey.ss58_address,
    )
    assert plaintext.status == "error"
    assert plaintext.error_code == "inference_failed"


def test_runtime_rejects_an_unbound_model_revision() -> None:
    with pytest.raises(ValueError, match="model revision"):
        runtime(model_revision="not-a-digest")


def test_miner_loads_an_exact_canonical_policy_file(tmp_path: Path) -> None:
    policy = make_policy()
    path = tmp_path / "policy.json"
    path.write_bytes(canonical_json_bytes(policy))

    assert _load_policy(path) == policy


@pytest.mark.skipif(os.name != "posix", reason="POSIX path-safety assertion")
def test_miner_rejects_unsafe_policy_paths(tmp_path: Path) -> None:
    policy = make_policy()
    target = tmp_path / "policy.json"
    target.write_bytes(canonical_json_bytes(policy))

    symlink = tmp_path / "policy-link.json"
    symlink.symlink_to(target)
    with pytest.raises(RuntimeError, match="opened safely"):
        _load_policy(symlink)

    hardlink = tmp_path / "policy-hardlink.json"
    os.link(target, hardlink)
    with pytest.raises(RuntimeError, match="file is unsafe"):
        _load_policy(hardlink)
    hardlink.unlink()

    target.chmod(0o666)
    with pytest.raises(RuntimeError, match="file is unsafe"):
        _load_policy(target)
    target.chmod(0o600)

    public_parent = tmp_path / "public-config"
    public_parent.mkdir(mode=0o777)
    public_parent.chmod(0o777)
    public_policy = public_parent / "policy.json"
    public_policy.write_bytes(canonical_json_bytes(policy))
    with pytest.raises(RuntimeError, match="parent is unsafe"):
        _load_policy(public_policy)


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
        "runtime_mode": "inactive_shadow",
        "scoring_policy_sha256": "20" * 32,
        "model_revision": None,
        "window_authority": "LocalComponentWindowAuthority",
        "finality_service": "component_authority",
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
