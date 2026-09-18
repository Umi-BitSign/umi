"""Bounded public cache for verified competition registration captures.

Public reads never initiate finality collection.  A background refresh and
deadline-sensitive admission requests share one in-flight provider call, so a
status poll cannot occupy or queue the proof collector ahead of an admission.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from .competition_chain import RegistrationCapture
from .open_competition import CompetitionPolicy, RegistrationSnapshot, digest
from .protocol import canonical_json_bytes

_LOGGER = logging.getLogger(__name__)

PROVENANCE_FIELDS = frozenset(
    {
        "schema",
        "evidence_class",
        "offline_finality_proof",
        "genesis_block_hash",
        "block",
        "block_hash",
        "state_root",
        "timestamp_ms",
        "snapshot_sha256",
        "evidence_sha256",
        "metadata_sha256",
        "finality_evidence_sha256",
        "finality_verifier_sha256",
        "storage_proof_verifier_sha256",
        "chain_submission_authorized",
    }
)


class VerifiedCaptureUnavailable(ValueError):
    """No sufficiently recent verified capture is available for public reads."""


@dataclass(frozen=True, slots=True)
class _CachedCapture:
    capture: RegistrationCapture
    verified_monotonic: float


class VerifiedRegistrationCache:
    """Coalesce fresh proof collection and expose only bounded-age captures.

    The provider remains the authority for head freshness and proof validity.
    ``maximum_cache_age_seconds`` bounds the additional time for which that
    successful verification may be reused by unauthenticated public reads.
    """

    def __init__(
        self,
        provider: Any,
        policy: CompetitionPolicy,
        *,
        maximum_cache_age_seconds: float,
        maximum_head_age_ms: int,
        maximum_future_skew_ms: int,
        public_wait_seconds: float,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    ) -> None:
        if (
            maximum_cache_age_seconds <= 0
            or maximum_head_age_ms <= 0
            or maximum_future_skew_ms < 0
            or public_wait_seconds <= 0
        ):
            raise ValueError("verified registration cache intervals must be positive")
        self._provider = provider
        self._policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self._maximum_age = float(maximum_cache_age_seconds)
        self._maximum_head_age_ms = maximum_head_age_ms
        self._maximum_future_skew_ms = maximum_future_skew_ms
        self._public_wait = float(public_wait_seconds)
        self._monotonic = monotonic
        self._wall_clock_ms = wall_clock_ms
        self._guard = asyncio.Lock()
        self._inflight: asyncio.Task | None = None
        self._cached: _CachedCapture | None = None
        self._runner: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._closed = False
        self._refresh_interval = max(0.05, min(30.0, self._maximum_age / 4))

    async def start(self) -> None:
        if self._closed or self._runner is not None:
            raise ValueError("verified registration cache cannot be started")
        self._runner = asyncio.create_task(self._run(), name="competition-finality-cache")
        # Let the runner publish an in-flight task before the application begins
        # serving. Public reads may await it, but never create it themselves.
        await asyncio.sleep(0)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        runner = self._runner
        if runner is not None:
            runner.cancel()
            await asyncio.gather(runner, return_exceptions=True)
        async with self._guard:
            inflight = self._inflight
        if inflight is not None and not inflight.done():
            inflight.cancel()
        if inflight is not None:
            await asyncio.gather(inflight, return_exceptions=True)
        self._cached = None

    async def collect_fresh(self) -> RegistrationCapture:
        """Return one newly collected capture, sharing an existing collection."""
        if self._closed:
            raise VerifiedCaptureUnavailable("verified registration cache is closed")
        async with self._guard:
            task = self._inflight
            if task is None:
                task = asyncio.create_task(
                    self._provider.collect(), name="competition-finality-collection"
                )
                self._inflight = task
                task.add_done_callback(self._collection_finished)
        raw = await asyncio.shield(task)
        capture = self._validate(raw)
        self._cached = _CachedCapture(capture, self._monotonic())
        return self._current()

    def _collection_finished(self, task: asyncio.Task) -> None:
        # The event loop invokes callbacks serially. Clear even when every
        # request awaiting the shielded provider call was cancelled.
        if self._inflight is task:
            self._inflight = None

    async def cached(self) -> RegistrationCapture:
        """Return a recent cached capture without initiating proof collection."""
        try:
            return self._current()
        except VerifiedCaptureUnavailable:
            pass
        async with self._guard:
            task = self._inflight
        if task is not None:
            try:
                raw = await asyncio.wait_for(asyncio.shield(task), timeout=self._public_wait)
            except Exception as error:
                # Never reveal provider, filesystem or RPC details publicly.
                raise VerifiedCaptureUnavailable(
                    "verified registration capture is unavailable"
                ) from error
            capture = self._validate(raw)
            self._cached = _CachedCapture(capture, self._monotonic())
        return self._current()

    def _current(self) -> RegistrationCapture:
        cached = self._cached
        if cached is None:
            raise VerifiedCaptureUnavailable("verified registration capture is unavailable")
        age = self._monotonic() - cached.verified_monotonic
        if not 0 <= age <= self._maximum_age:
            raise VerifiedCaptureUnavailable("verified registration capture is stale")
        timestamp_ms = cached.capture.provenance["timestamp_ms"]
        wall_age_ms = self._wall_clock_ms() - timestamp_ms
        if not -self._maximum_future_skew_ms <= wall_age_ms <= self._maximum_head_age_ms:
            raise VerifiedCaptureUnavailable("verified registration head is stale")
        return cached.capture

    def _validate(self, raw: Any) -> RegistrationCapture:
        if not isinstance(raw, RegistrationCapture):
            raise ValueError("registration provider returned another capture type")
        snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(raw.snapshot))
        if not self._policy.valid_from_block <= snapshot.block <= self._policy.valid_through_block:
            raise ValueError("intake policy is not current")
        provenance = {
            key: value for key, value in raw.provenance.items() if key in PROVENANCE_FIELDS
        }
        if (
            set(provenance) != PROVENANCE_FIELDS
            or provenance.get("schema") != "umi-competition-registration-provenance/1"
            or provenance.get("snapshot_sha256") != digest(snapshot)
            or provenance.get("block") != snapshot.block
            or provenance.get("block_hash") != snapshot.block_hash
            or provenance.get("evidence_class") != "verifier_attested_finality"
            or provenance.get("offline_finality_proof") is not False
            or provenance.get("chain_submission_authorized") is not False
            or type(provenance.get("timestamp_ms")) is not int
            or len(canonical_json_bytes(provenance)) > 16 * 1024
        ):
            raise ValueError("registration provenance mismatch")
        return RegistrationCapture(snapshot=snapshot, provenance=provenance)

    async def _run(self) -> None:
        last_error_type = None
        while not self._stop.is_set():
            try:
                await self.collect_fresh()
                if last_error_type is not None:
                    _LOGGER.info("registration_refresh_recovered")
                    last_error_type = None
            except asyncio.CancelledError:
                raise
            except Exception as error:
                # A prior verified value remains usable only until its bounded
                # age expires. Repeated failures therefore fail public state shut.
                # Log transitions privately, without RPC URLs, paths, or bodies.
                error_type = type(error).__name__
                if error_type != last_error_type:
                    _LOGGER.warning("registration_refresh_failed error_type=%s", error_type)
                    last_error_type = error_type
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self._refresh_interval)
