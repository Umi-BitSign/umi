"""Optional bounded sharing for model backends with request-invariant output.

The protocol passes a complete request to a model backend. Most backends must
therefore execute each request independently. An operator may explicitly wrap a
backend whose output depends only on the verified video and the semantic fields in
``SharedInferenceKey``. This is useful when independent validators assign the same
batch and differ only in delivery or issuance metadata.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from .backends import Translator
from .protocol import TranslationRequest


@dataclass(frozen=True, slots=True)
class SharedInferenceKey:
    """Model-semantic request projection used by the explicit sharing profile."""

    window_id: str
    response_close_round: int
    video_sha256: str
    video_size_bytes: int
    video_media_type: str
    source_language: str
    target_language: str
    stratum: str
    scoring_policy_sha256: str
    model_revision: str

    @classmethod
    def from_request(
        cls,
        request: TranslationRequest,
        *,
        model_revision: str,
    ) -> SharedInferenceKey:
        return cls(
            window_id=request.window_id,
            response_close_round=request.response_close_round,
            video_sha256=request.video.sha256,
            video_size_bytes=request.video.size_bytes,
            video_media_type=request.video.media_type,
            source_language=request.task.source_language,
            target_language=request.task.target_language,
            stratum=request.task.stratum,
            scoring_policy_sha256=request.scoring_policy_hash,
            model_revision=model_revision,
        )


class WindowCoalescingTranslator:
    """Share successful same-window inference under an explicit backend contract."""

    def __init__(
        self,
        backend: Translator,
        *,
        model_revision: str,
        maximum_workers: int,
        maximum_window_keys: int,
        maximum_inference_seconds: float,
    ) -> None:
        if not isinstance(model_revision, str):
            raise TypeError("model_revision must be text")
        try:
            revision = bytes.fromhex(model_revision)
        except ValueError as error:
            raise ValueError("model_revision must be lowercase SHA-256") from error
        if len(revision) != 32 or revision.hex() != model_revision:
            raise ValueError("model_revision must be lowercase SHA-256")
        for value, label in (
            (maximum_workers, "maximum_workers"),
            (maximum_window_keys, "maximum_window_keys"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(maximum_inference_seconds, bool)
            or not isinstance(maximum_inference_seconds, (int, float))
            or not math.isfinite(maximum_inference_seconds)
            or maximum_inference_seconds <= 0
        ):
            raise ValueError("maximum_inference_seconds must be positive")
        self.backend = backend
        self.model_revision = model_revision
        self.maximum_workers = maximum_workers
        self.maximum_window_keys = maximum_window_keys
        self.maximum_inference_seconds = float(maximum_inference_seconds)
        self._lock = asyncio.Lock()
        self._worker_semaphore = asyncio.Semaphore(maximum_workers)
        self._inflight: dict[SharedInferenceKey, asyncio.Task[str]] = {}
        self._success_cache: OrderedDict[SharedInferenceKey, str] = OrderedDict()
        self._tasks: set[asyncio.Task[str]] = set()
        self._active_window: tuple[str, int] | None = None
        self._last_response_close_round: int | None = None
        self._expiry_task: asyncio.Task[None] | None = None
        self._started = False
        self._closing = False
        self._translation_jobs_started = 0
        self._translation_jobs_succeeded = 0
        self._cache_hits = 0
        self._coalesced_waiters = 0
        self._active_workers = 0
        self._maximum_active_workers = 0
        self._maximum_inflight_keys = 0

    async def startup(self) -> None:
        if self._started:
            return
        self._closing = False
        hook = getattr(self.backend, "startup", None)
        if hook is not None:
            await hook()
        self._worker_semaphore = asyncio.Semaphore(self.maximum_workers)
        self._translation_jobs_started = 0
        self._translation_jobs_succeeded = 0
        self._cache_hits = 0
        self._coalesced_waiters = 0
        self._active_workers = 0
        self._maximum_active_workers = 0
        self._maximum_inflight_keys = 0
        self._last_response_close_round = None
        self._started = True

    async def shutdown(self) -> None:
        self._closing = True
        async with self._lock:
            expiry = self._expiry_task
            self._expiry_task = None
            tasks = tuple(self._tasks)
            self._inflight.clear()
            self._success_cache.clear()
            self._active_window = None
        if expiry is not None:
            expiry.cancel()
        for task in tasks:
            task.cancel()
        await asyncio.gather(
            *((expiry,) if expiry is not None else ()),
            *tasks,
            return_exceptions=True,
        )
        self._tasks.clear()
        try:
            hook = getattr(self.backend, "shutdown", None)
            if hook is not None:
                await hook()
        finally:
            self._started = False

    def capacity_snapshot(self) -> dict[str, int | str | None]:
        """Return aggregate counters without video or hypothesis material."""

        return {
            "active_window_id": None if self._active_window is None else self._active_window[0],
            "active_window_response_close_round": (
                None if self._active_window is None else self._active_window[1]
            ),
            "maximum_workers": self.maximum_workers,
            "maximum_window_keys": self.maximum_window_keys,
            "translation_jobs_started": self._translation_jobs_started,
            "translation_jobs_succeeded": self._translation_jobs_succeeded,
            "cache_hits": self._cache_hits,
            "coalesced_waiters": self._coalesced_waiters,
            "cached_successes": len(self._success_cache),
            "inflight_keys": len(self._inflight),
            "maximum_inflight_keys": self._maximum_inflight_keys,
            "active_workers": self._active_workers,
            "maximum_active_workers": self._maximum_active_workers,
        }

    @staticmethod
    def _consume_task_result(task: asyncio.Task[Any]) -> None:
        if not task.cancelled():
            task.exception()

    async def _cancel_tasks(self, tasks: tuple[asyncio.Task[str], ...]) -> None:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _seconds_until_round(round_number: int) -> float:
        import bittensor as bt

        return bt.timelock.reveal_time(round_number).timestamp() - time.time()

    async def _expire_window(self, window: tuple[str, int]) -> None:
        try:
            await asyncio.sleep(max(0.0, self._seconds_until_round(window[1])))
            async with self._lock:
                if self._active_window != window:
                    return
                tasks = tuple(set(self._inflight.values()))
                self._inflight.clear()
                self._success_cache.clear()
                self._active_window = None
                self._expiry_task = None
            await self._cancel_tasks(tasks)
        except asyncio.CancelledError:
            raise

    async def _activate_window(self, window: tuple[str, int]) -> None:
        stale_tasks: tuple[asyncio.Task[str], ...] = ()
        stale_expiry: asyncio.Task[None] | None = None
        async with self._lock:
            if not self._started or self._closing:
                raise RuntimeError("model scheduler has not completed startup")
            current = self._active_window
            if current == window:
                return
            if (current is not None and window[1] <= current[1]) or (
                current is None
                and self._last_response_close_round is not None
                and window[1] <= self._last_response_close_round
            ):
                raise RuntimeError("model request window is not newer than the latest window")
            stale_tasks = tuple(set(self._inflight.values()))
            stale_expiry = self._expiry_task
            self._inflight.clear()
            self._success_cache.clear()
            self._active_window = window
            self._last_response_close_round = window[1]
            self._expiry_task = asyncio.create_task(self._expire_window(window))
            self._expiry_task.add_done_callback(self._consume_task_result)
        if stale_expiry is not None:
            stale_expiry.cancel()
        await asyncio.gather(
            *((stale_expiry,) if stale_expiry is not None else ()),
            return_exceptions=True,
        )
        await self._cancel_tasks(stale_tasks)

    async def _run_shared(
        self,
        key: SharedInferenceKey,
        video: bytes,
        request: TranslationRequest,
    ) -> str:
        result: str | None = None
        try:

            async def run_backend() -> str:
                async with self._worker_semaphore:
                    self._active_workers += 1
                    self._maximum_active_workers = max(
                        self._maximum_active_workers,
                        self._active_workers,
                    )
                    self._translation_jobs_started += 1
                    try:
                        result = await self.backend.translate(video, request)
                        if not isinstance(result, str):
                            raise TypeError("translation backend must return str")
                    finally:
                        self._active_workers -= 1
                    return result

            result = await asyncio.wait_for(
                run_backend(),
                timeout=self.maximum_inference_seconds,
            )
            self._translation_jobs_succeeded += 1
            return result
        finally:
            task = asyncio.current_task()
            async with self._lock:
                if task is not None and self._inflight.get(key) is task:
                    del self._inflight[key]
                    if result is not None and self._active_window == (
                        key.window_id,
                        key.response_close_round,
                    ):
                        self._success_cache[key] = result

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        if not self._started or self._closing:
            raise RuntimeError("model scheduler has not completed startup")
        key = SharedInferenceKey.from_request(request, model_revision=self.model_revision)
        window = (key.window_id, key.response_close_round)
        await self._activate_window(window)
        async with self._lock:
            if not self._started or self._closing:
                raise RuntimeError("model scheduler has not completed startup")
            if self._active_window != window:
                raise RuntimeError("model request window changed before inference")
            cached = self._success_cache.get(key)
            if cached is not None:
                self._success_cache.move_to_end(key)
                self._cache_hits += 1
                return cached
            task = self._inflight.get(key)
            if task is None:
                if len(self._inflight) + len(self._success_cache) >= self.maximum_window_keys:
                    raise RuntimeError("model shared-window key limit exceeded")
                task = asyncio.create_task(self._run_shared(key, video, request))
                self._inflight[key] = task
                self._tasks.add(task)
                self._maximum_inflight_keys = max(
                    self._maximum_inflight_keys,
                    len(self._inflight),
                )
                task.add_done_callback(self._tasks.discard)
                task.add_done_callback(self._consume_task_result)
            else:
                self._coalesced_waiters += 1
        return await asyncio.shield(task)


__all__ = ["SharedInferenceKey", "WindowCoalescingTranslator"]
