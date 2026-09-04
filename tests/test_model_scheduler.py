from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

import umi.miner as miner_module
from umi.config import Limits
from umi.model_scheduler import WindowCoalescingTranslator
from umi.protocol import TranslationRequest, base64url_encode

from .factories import POLICY_HASH, TEST_REVEAL_ROUND, VIDEO_BYTES, challenge_request

MODEL_REVISION = "ab" * 32


def _request(
    video: bytes = VIDEO_BYTES,
    *,
    index: int = 1,
    issued_block: int = 100,
    video_url: str | None = None,
    response_close_round: int = TEST_REVEAL_ROUND - 2,
) -> TranslationRequest:
    value = challenge_request().model_dump(mode="json", by_alias=True)
    value.update(
        {
            "batch_id": base64url_encode(bytes([index + 32]) * 16),
            "challenge_id": base64url_encode(bytes([index]) * 16),
            "issued_block": issued_block,
            "issued_block_hash": "0x" + bytes([index + 64]).hex() * 32,
            "deadline_block": issued_block + 10,
            "response_close_round": response_close_round,
            "reveal_round": response_close_round + 2,
            "video": {
                "url": video_url or f"https://delivery-{index}.example/{index:032x}",
                "sha256": hashlib.sha256(video).hexdigest(),
                "size_bytes": len(video),
                "media_type": "video/mp4",
            },
        }
    )
    return TranslationRequest.model_validate(value)


@dataclass
class _BlockingBackend:
    release: asyncio.Event = field(default_factory=asyncio.Event)
    first_started: asyncio.Event = field(default_factory=asyncio.Event)
    worker_limit_reached: asyncio.Event = field(default_factory=asyncio.Event)
    expected_active_workers: int = 1
    calls: list[TranslationRequest] = field(default_factory=list)
    active: int = 0
    maximum_active: int = 0
    cancellations: int = 0
    startups: int = 0
    shutdowns: int = 0
    active_at_shutdown: list[int] = field(default_factory=list)

    async def startup(self) -> None:
        self.startups += 1

    async def shutdown(self) -> None:
        self.shutdowns += 1
        self.active_at_shutdown.append(self.active)

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        assert hashlib.sha256(video).hexdigest() == request.video.sha256
        self.calls.append(request)
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        self.first_started.set()
        if self.active >= self.expected_active_workers:
            self.worker_limit_reached.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancellations += 1
            raise
        finally:
            self.active -= 1
        return "shared hypothesis"


@dataclass
class _ImmediateBackend:
    calls: int = 0
    startups: int = 0
    shutdowns: int = 0

    async def startup(self) -> None:
        self.startups += 1

    async def shutdown(self) -> None:
        self.shutdowns += 1

    async def translate(self, _video: bytes, _request: TranslationRequest) -> str:
        self.calls += 1
        return "immediate hypothesis"


@dataclass
class _FailOnceBackend:
    calls: int = 0

    async def translate(self, _video: bytes, _request: TranslationRequest) -> str:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("fixture backend failure")
        return "recovered hypothesis"


@dataclass
class _NeverCompletesBackend:
    calls: int = 0
    cancellations: int = 0

    async def translate(self, _video: bytes, _request: TranslationRequest) -> str:
        self.calls += 1
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancellations += 1
            raise
        raise AssertionError("unreachable")


def _scheduler(
    backend: object,
    *,
    maximum_workers: int = 2,
    maximum_window_keys: int = 28,
    maximum_inference_seconds: float = 1.0,
) -> WindowCoalescingTranslator:
    return WindowCoalescingTranslator(
        backend,  # type: ignore[arg-type]
        model_revision=MODEL_REVISION,
        maximum_workers=maximum_workers,
        maximum_window_keys=maximum_window_keys,
        maximum_inference_seconds=maximum_inference_seconds,
    )


@pytest.mark.asyncio
async def test_semantic_projection_coalesces_delivery_and_issuance_differences() -> None:
    backend = _BlockingBackend()
    scheduler = _scheduler(backend)
    await scheduler.startup()
    first_request = _request(index=1, issued_block=100, video_url="https://first.example/a")
    second_request = _request(index=2, issued_block=105, video_url="https://second.example/b")

    try:
        first = asyncio.create_task(scheduler.translate(VIDEO_BYTES, first_request))
        await asyncio.wait_for(backend.first_started.wait(), timeout=1)
        second = asyncio.create_task(scheduler.translate(VIDEO_BYTES, second_request))
        await asyncio.sleep(0)

        snapshot = scheduler.capacity_snapshot()
        assert snapshot["translation_jobs_started"] == 1
        assert snapshot["coalesced_waiters"] == 1
        assert backend.calls == [first_request]

        backend.release.set()
        assert await asyncio.gather(first, second) == [
            "shared hypothesis",
            "shared hypothesis",
        ]
        assert scheduler.capacity_snapshot()["cached_successes"] == 1
    finally:
        await scheduler.shutdown()


@pytest.mark.asyncio
async def test_cancelled_waiter_leaves_shared_work_for_cached_retry() -> None:
    backend = _BlockingBackend()
    scheduler = _scheduler(backend)
    request = _request()
    await scheduler.startup()

    try:
        waiter = asyncio.create_task(scheduler.translate(VIDEO_BYTES, request))
        await asyncio.wait_for(backend.first_started.wait(), timeout=1)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert backend.cancellations == 0

        backend.release.set()
        for _ in range(100):
            if scheduler.capacity_snapshot()["translation_jobs_succeeded"] == 1:
                break
            await asyncio.sleep(0.001)
        else:  # pragma: no cover - protects the test from hanging
            pytest.fail("shared inference did not complete")

        assert await scheduler.translate(VIDEO_BYTES, request) == "shared hypothesis"
        snapshot = scheduler.capacity_snapshot()
        assert snapshot["translation_jobs_started"] == 1
        assert snapshot["cache_hits"] == 1
        assert len(backend.calls) == 1
    finally:
        await scheduler.shutdown()


@pytest.mark.asyncio
async def test_backend_failure_is_not_cached() -> None:
    backend = _FailOnceBackend()
    scheduler = _scheduler(backend)
    request = _request()
    await scheduler.startup()

    try:
        with pytest.raises(RuntimeError, match="fixture backend failure"):
            await scheduler.translate(VIDEO_BYTES, request)
        assert scheduler.capacity_snapshot()["cached_successes"] == 0

        assert await scheduler.translate(VIDEO_BYTES, request) == "recovered hypothesis"
        assert backend.calls == 2
        assert scheduler.capacity_snapshot()["translation_jobs_succeeded"] == 1
    finally:
        await scheduler.shutdown()


@pytest.mark.asyncio
async def test_backend_timeout_is_not_cached() -> None:
    backend = _NeverCompletesBackend()
    scheduler = _scheduler(backend, maximum_inference_seconds=0.01)
    request = _request()
    await scheduler.startup()

    try:
        for expected_calls in (1, 2):
            with pytest.raises(asyncio.TimeoutError):
                await scheduler.translate(VIDEO_BYTES, request)
            assert scheduler.capacity_snapshot()["cached_successes"] == 0
            assert backend.calls == expected_calls
        assert backend.cancellations == 2
    finally:
        await scheduler.shutdown()


@pytest.mark.asyncio
async def test_backend_worker_concurrency_is_bounded() -> None:
    backend = _BlockingBackend(expected_active_workers=2)
    scheduler = _scheduler(backend, maximum_workers=2, maximum_window_keys=5)
    inputs = [f"video-{index}".encode() for index in range(1, 6)]
    await scheduler.startup()

    try:
        tasks = [
            asyncio.create_task(scheduler.translate(video, _request(video, index=index)))
            for index, video in enumerate(inputs, start=1)
        ]
        await asyncio.wait_for(backend.worker_limit_reached.wait(), timeout=1)
        await asyncio.sleep(0.01)
        assert backend.active == 2
        assert backend.maximum_active == 2
        assert scheduler.capacity_snapshot()["maximum_active_workers"] == 2

        backend.release.set()
        assert await asyncio.gather(*tasks) == ["shared hypothesis"] * 5
        assert len(backend.calls) == 5
        assert scheduler.capacity_snapshot()["translation_jobs_succeeded"] == 5
    finally:
        await scheduler.shutdown()


@pytest.mark.asyncio
async def test_window_expiry_removes_cached_hypothesis(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _ImmediateBackend()
    scheduler = _scheduler(backend)
    monkeypatch.setattr(scheduler, "_seconds_until_round", lambda _round: 0.02)
    await scheduler.startup()

    try:
        assert await scheduler.translate(VIDEO_BYTES, _request()) == "immediate hypothesis"
        assert scheduler.capacity_snapshot()["cached_successes"] == 1
        for _ in range(100):
            if scheduler.capacity_snapshot()["active_window_id"] is None:
                break
            await asyncio.sleep(0.001)
        else:  # pragma: no cover - protects the test from hanging
            pytest.fail("window cache did not expire")
        snapshot = scheduler.capacity_snapshot()
        assert snapshot["cached_successes"] == 0
        assert snapshot["inflight_keys"] == 0
        with pytest.raises(RuntimeError, match="not newer than"):
            await scheduler.translate(VIDEO_BYTES, _request())

        newer_request = _request(index=2, response_close_round=TEST_REVEAL_ROUND - 1)
        assert await scheduler.translate(VIDEO_BYTES, newer_request) == "immediate hypothesis"
        assert backend.calls == 2
    finally:
        await scheduler.shutdown()


@pytest.mark.asyncio
async def test_shutdown_cancels_work_before_backend_shutdown() -> None:
    backend = _BlockingBackend()
    scheduler = _scheduler(backend)
    await scheduler.startup()
    translation = asyncio.create_task(scheduler.translate(VIDEO_BYTES, _request()))
    await asyncio.wait_for(backend.first_started.wait(), timeout=1)

    await scheduler.shutdown()

    with pytest.raises(asyncio.CancelledError):
        await translation
    assert backend.cancellations == 1
    assert backend.shutdowns == 1
    assert backend.active_at_shutdown == [0]
    snapshot = scheduler.capacity_snapshot()
    assert snapshot["active_window_id"] is None
    assert snapshot["cached_successes"] == 0
    assert snapshot["inflight_keys"] == 0
    with pytest.raises(RuntimeError, match="has not completed startup"):
        await scheduler.translate(VIDEO_BYTES, _request())


@pytest.mark.asyncio
async def test_shutdown_blocks_translation_paused_before_window_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _ImmediateBackend()
    scheduler = _scheduler(backend)
    activation_entered = asyncio.Event()
    allow_activation = asyncio.Event()
    original_activate_window = scheduler._activate_window

    async def delayed_activate_window(window: tuple[str, int]) -> None:
        activation_entered.set()
        await allow_activation.wait()
        await original_activate_window(window)

    monkeypatch.setattr(scheduler, "_activate_window", delayed_activate_window)
    await scheduler.startup()
    translation = asyncio.create_task(scheduler.translate(VIDEO_BYTES, _request()))
    await asyncio.wait_for(activation_entered.wait(), timeout=1)

    await scheduler.shutdown()
    allow_activation.set()
    try:
        with pytest.raises(RuntimeError, match="has not completed startup"):
            await translation
        assert backend.calls == 0
        assert scheduler.capacity_snapshot()["active_window_id"] is None
    finally:
        if scheduler.capacity_snapshot()["active_window_id"] is not None:
            await scheduler.shutdown()


@pytest.mark.asyncio
async def test_startup_resets_capacity_counters() -> None:
    backend = _ImmediateBackend()
    scheduler = _scheduler(backend)
    await scheduler.startup()
    assert await scheduler.translate(VIDEO_BYTES, _request()) == "immediate hypothesis"
    assert scheduler.capacity_snapshot()["translation_jobs_started"] == 1
    await scheduler.shutdown()

    await scheduler.startup()
    try:
        snapshot = scheduler.capacity_snapshot()
        assert snapshot["translation_jobs_started"] == 0
        assert snapshot["translation_jobs_succeeded"] == 0
        assert snapshot["cache_hits"] == 0
        assert snapshot["coalesced_waiters"] == 0
        assert snapshot["maximum_active_workers"] == 0
        assert snapshot["maximum_inflight_keys"] == 0
        assert backend.startups == 2
        assert await scheduler.translate(VIDEO_BYTES, _request()) == "immediate hypothesis"
        assert backend.calls == 2
    finally:
        await scheduler.shutdown()
    assert backend.shutdowns == 2


@pytest.mark.parametrize(
    ("overrides", "error", "message"),
    (
        ({"model_revision": 1}, TypeError, "must be text"),
        ({"model_revision": "AB" * 32}, ValueError, "lowercase SHA-256"),
        ({"model_revision": "ab"}, ValueError, "lowercase SHA-256"),
        ({"maximum_workers": True}, ValueError, "positive integer"),
        ({"maximum_workers": 0}, ValueError, "positive integer"),
        ({"maximum_window_keys": 0}, ValueError, "positive integer"),
        ({"maximum_inference_seconds": True}, ValueError, "positive"),
        ({"maximum_inference_seconds": 0}, ValueError, "positive"),
        ({"maximum_inference_seconds": float("nan")}, ValueError, "positive"),
        ({"maximum_inference_seconds": float("inf")}, ValueError, "positive"),
    ),
)
def test_scheduler_rejects_invalid_configuration(
    overrides: dict[str, object],
    error: type[Exception],
    message: str,
) -> None:
    values: dict[str, object] = {
        "model_revision": MODEL_REVISION,
        "maximum_workers": 1,
        "maximum_window_keys": 1,
        "maximum_inference_seconds": 1.0,
    }
    values.update(overrides)

    with pytest.raises(error, match=message):
        WindowCoalescingTranslator(_ImmediateBackend(), **values)  # type: ignore[arg-type]


def _translator_arguments(**overrides: object) -> SimpleNamespace:
    values = {
        "coalesce_window_video_inference": False,
        "max_backend_workers": None,
        "translator_unix_socket": None,
        "translator": "fixture:translator",
        "allow_unsafe_sync_translator": False,
        "model_revision": MODEL_REVISION,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_build_translator_wraps_only_explicit_in_process_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _ImmediateBackend()
    monkeypatch.setattr(miner_module, "load_translator", lambda *_args, **_kwargs: backend)
    limits = Limits(maximum_inference_concurrency=4, inference_timeout_seconds=3.0)

    plain = miner_module._build_translator(
        _translator_arguments(),
        limits=limits,
        scoring_policy_sha256=POLICY_HASH,
        validator_count=4,
    )
    shared = miner_module._build_translator(
        _translator_arguments(
            coalesce_window_video_inference=True,
            max_backend_workers=2,
        ),
        limits=limits,
        scoring_policy_sha256=POLICY_HASH,
        validator_count=4,
    )

    assert plain is backend
    assert isinstance(shared, WindowCoalescingTranslator)
    assert shared.backend is backend
    assert shared.maximum_workers == 2
    assert shared.maximum_window_keys == limits.maximum_unique_videos_per_validator_window
    assert shared.maximum_inference_seconds == limits.inference_timeout_seconds


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        ({"max_backend_workers": 1}, "requires --coalesce"),
        (
            {
                "coalesce_window_video_inference": True,
                "max_backend_workers": 1,
                "model_revision": None,
            },
            "requires a bound model revision",
        ),
        (
            {"coalesce_window_video_inference": True, "max_backend_workers": None},
            "requires --max-backend-workers",
        ),
        (
            {"coalesce_window_video_inference": True, "max_backend_workers": 5},
            "cannot exceed outer inference concurrency",
        ),
        (
            {
                "coalesce_window_video_inference": True,
                "max_backend_workers": 1,
                "translator_unix_socket": "/private/model.sock",
            },
            "limited to in-process translators",
        ),
    ),
)
def test_build_translator_rejects_unsafe_sharing_combinations(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    message: str,
) -> None:
    monkeypatch.setattr(
        miner_module,
        "load_translator",
        lambda *_args, **_kwargs: _ImmediateBackend(),
    )

    with pytest.raises(ValueError, match=message):
        miner_module._build_translator(
            _translator_arguments(**overrides),
            limits=Limits(maximum_inference_concurrency=4),
            scoring_policy_sha256=POLICY_HASH,
            validator_count=4,
        )
