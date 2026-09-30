"""Bounded public cache for verified competition registration captures.

Public reads never initiate finality collection.  A background refresh and
deadline-sensitive admission requests share one in-flight provider call, so a
status poll cannot occupy or queue the proof collector ahead of an admission.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from .competition_chain import OwnedFinalityStale, RegistrationCacheFull, RegistrationCapture
from .competition_submission_checkpoint import SubmissionCheckpointError
from .concurrency import await_owned_task
from .open_competition import CompetitionPolicy, RegistrationSnapshot, digest
from .protocol import canonical_json_bytes
from .validator_chain import ValidatorChainError

_LOGGER = logging.getLogger(__name__)
_RATE_LIMIT_COOLDOWN_SECONDS = 30.0

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


_CHAIN_REFRESH_REASONS = frozenset(
    {
        "owned_finality_unavailable",
        "owned_finalized_snapshot_invalid",
        "finalized_snapshot_rpc_failed",
        "finalized_header_invalid",
        "finalized_header_number_invalid",
        "finalized_header_number_mismatch",
        "finalized_block_hash_invalid",
        "finalized_block_hash_mismatch",
        "finalized_parent_hash_invalid",
        "finalized_parent_hash_mismatch",
        "finalized_state_root_invalid",
        "finalized_state_root_mismatch",
        "proof_rpc_endpoint_unavailable",
        "proof_rpc_endpoint_invalid",
        "proof_rpc_failed",
        "proof_rpc_rate_limited",
        "proof_rpc_error",
        "proof_rpc_response_invalid",
        "proof_rpc_response_limit",
        "proof_rpc_request_invalid",
        "proof_rpc_request_limit",
        "proof_rpc_method_forbidden",
        "runtime_version_invalid",
        "runtime_version_pin_mismatch",
        "runtime_metadata_rpc_failed",
        "runtime_metadata_invalid",
        "runtime_metadata_limit",
        "runtime_metadata_pin_mismatch",
        "runtime_codec_initialization_failed",
        "storage_codec_initialization_failed",
        "storage_codec_metadata_pin_mismatch",
        "storage_value_decode_failed",
        "storage_value_invalid",
        "storage_value_limit",
        "storage_values_size_limit",
        "storage_proof_rpc_failed",
        "storage_proof_verification_failed",
        "storage_multi_proof_verifier_unavailable",
        "storage_proof_invalid",
        "storage_proof_block_mismatch",
        "storage_proof_node_invalid",
        "storage_proof_node_limit",
        "storage_proof_node_size_limit",
        "storage_proof_size_limit",
        "storage_proof_duplicate_node",
    }
)
_REFRESH_FAILURE_CLASSES = {
    OwnedFinalityStale: ("OwnedFinalityStale", "owned_finality_stale"),
    RegistrationCacheFull: ("RegistrationCacheFull", "registration_cache_capacity"),
    SubmissionCheckpointError: ("SubmissionCheckpointError", "submission_checkpoint_failure"),
    VerifiedCaptureUnavailable: ("VerifiedCaptureUnavailable", "verified_capture_unavailable"),
    OSError: ("OSError", "refresh_io_failure"),
    sqlite3.OperationalError: ("OperationalError", "refresh_storage_failure"),
    ValueError: ("ValueError", "refresh_validation_failed"),
    TypeError: ("TypeError", "refresh_type_invalid"),
    RuntimeError: ("RuntimeError", "refresh_runtime_failure"),
}


def _refresh_failure(error: Exception) -> tuple[str, str]:
    """Classify without formatting exceptions or following their cause chains."""
    # asyncio.TimeoutError is a distinct class on supported Python 3.10.
    if type(error) in (TimeoutError, asyncio.TimeoutError):
        return "TimeoutError", "refresh_timeout"
    if type(error) is ValidatorChainError:
        reason = getattr(error, "reason_code", None)
        if type(reason) is str and len(reason) <= 64 and reason in _CHAIN_REFRESH_REASONS:
            return "ValidatorChainError", reason
        return "ValidatorChainError", "validator_chain_unclassified"
    # Exact classes prevent untrusted subclasses from supplying a property or
    # dynamic class name as a purported diagnostic. All output is fixed text.
    return _REFRESH_FAILURE_CLASSES.get(type(error), ("Exception", "unclassified_refresh_failure"))


@dataclass(frozen=True, slots=True)
class _CachedCapture:
    capture: RegistrationCapture
    verified_monotonic: float


class VerifiedRegistrationCache:
    """Coalesce fresh proof collection and expose only bounded-age captures.

    The provider remains the authority for head freshness and proof validity.
    ``maximum_cache_age_seconds`` bounds the additional time for which that
    successful verification may be reused by unauthenticated public reads.
    An explicit RPC rate limit pauses new collections for 30 seconds across
    background refreshes and admissions. Admissions still require fresh proof;
    the cooldown never extends a cached capture's validity.
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
        self._closing: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._closed = False
        self._refresh_interval = max(0.05, min(30.0, self._maximum_age / 4))
        self._rate_limit_until: float | None = None

    async def start(self) -> None:
        if self._closed or self._runner is not None:
            raise ValueError("verified registration cache cannot be started")
        self._runner = asyncio.create_task(self._run(), name="competition-finality-cache")
        # Let the runner publish an in-flight task before the application begins
        # serving. Public reads may await it, but never create it themselves.
        await asyncio.sleep(0)

    async def aclose(self) -> None:
        """Drain one shared cleanup task before any close caller can finish."""
        if self._closing is None:
            self._closed = True
            self._closing = asyncio.create_task(
                self._close(), name="competition-finality-cache-close"
            )
        await await_owned_task(self._closing)

    async def _close(self) -> None:
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
        return self._remember(await self._collect_raw())

    async def collect_for_cohort_recovery(self) -> RegistrationCapture:
        """Collect owned fresh evidence outside the legacy policy interval.

        The caller must separately verify the admitted recovery authority,
        current cohort history and explicit miner consent. This method does not
        admit legacy submissions or relax head freshness and proof validation.
        """
        raw = await self._collect_raw()
        self._require_open()
        capture = self._validate(raw, require_current_policy=False)
        self._check_head_age(capture)
        return capture

    async def _collect_raw(self) -> RegistrationCapture:
        self._require_open()
        async with self._guard:
            self._require_open()
            task = self._inflight
            if task is None:
                if (
                    self._rate_limit_until is not None
                    and self._monotonic() < self._rate_limit_until
                ):
                    raise ValidatorChainError("proof_rpc_rate_limited")
                self._rate_limit_until = None
                task = asyncio.create_task(
                    self._provider.collect(), name="competition-finality-collection"
                )
                self._inflight = task
                task.add_done_callback(self._collection_finished)
        # The cache owns collection after a caller disconnects. wait() neither
        # cancels it nor logs its eventual exception; the completion callback
        # consumes that exception without exposing private provider details.
        await asyncio.wait((task,))
        return task.result()

    def _collection_finished(self, task: asyncio.Task) -> None:
        # The event loop invokes callbacks serially. Clear even when every
        # request awaiting the shielded provider call was cancelled.
        if self._inflight is task:
            self._inflight = None
        # Observe failures even when no waiter remains, without logging private
        # provider details. Active awaiters still receive the original exception.
        if not task.cancelled():
            failure = task.exception()
            if failure is not None and _refresh_failure(failure) == (
                "ValidatorChainError",
                "proof_rpc_rate_limited",
            ):
                # Store only a monotonic deadline, including when every waiter
                # canceled before the provider reported its rate limit.
                self._rate_limit_until = self._monotonic() + _RATE_LIMIT_COOLDOWN_SECONDS

    async def cached(self) -> RegistrationCapture:
        """Return a recent cached capture without initiating proof collection."""
        self._require_open()
        try:
            return self._current()
        except VerifiedCaptureUnavailable:
            pass
        async with self._guard:
            self._require_open()
            task = self._inflight
        if task is not None:
            try:
                done, _ = await asyncio.wait((task,), timeout=self._public_wait)
                if not done:
                    raise asyncio.TimeoutError
                raw = task.result()
            except Exception as error:
                # Never reveal provider, filesystem or RPC details publicly.
                raise VerifiedCaptureUnavailable(
                    "verified registration capture is unavailable"
                ) from error
            return self._remember(raw)
        return self._current()

    def _remember(self, raw: Any) -> RegistrationCapture:
        # A provider may finish while shutdown is draining it. Late waiters
        # must neither return that capture nor repopulate a closed cache.
        self._require_open()
        capture = self._validate(raw)
        self._cached = _CachedCapture(capture, self._monotonic())
        return self._current()

    def _require_open(self) -> None:
        if self._closed:
            raise VerifiedCaptureUnavailable("verified registration cache is closed")

    def _current(self) -> RegistrationCapture:
        self._require_open()
        cached = self._cached
        if cached is None:
            raise VerifiedCaptureUnavailable("verified registration capture is unavailable")
        age = self._monotonic() - cached.verified_monotonic
        if not 0 <= age <= self._maximum_age:
            raise VerifiedCaptureUnavailable("verified registration capture is stale")
        self._check_head_age(cached.capture)
        return cached.capture

    def _check_head_age(self, capture: RegistrationCapture) -> None:
        timestamp_ms = capture.provenance["timestamp_ms"]
        wall_age_ms = self._wall_clock_ms() - timestamp_ms
        if not -self._maximum_future_skew_ms <= wall_age_ms <= self._maximum_head_age_ms:
            raise VerifiedCaptureUnavailable("verified registration head is stale")

    def _validate(self, raw: Any, *, require_current_policy: bool = True) -> RegistrationCapture:
        if not isinstance(raw, RegistrationCapture):
            raise ValueError("registration provider returned another capture type")
        snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(raw.snapshot))
        if require_current_policy and not (
            self._policy.valid_from_block <= snapshot.block <= self._policy.valid_through_block
        ):
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
        last_failure = None
        while not self._stop.is_set():
            try:
                await self.collect_fresh()
                if last_failure is not None:
                    _LOGGER.info("registration_refresh_recovered")
                    last_failure = None
            except asyncio.CancelledError:
                raise
            except Exception as error:
                # A prior verified value remains usable only until its bounded
                # age expires. Repeated failures therefore fail public state shut.
                # Log transitions privately, without RPC URLs, paths, or bodies.
                failure = _refresh_failure(error)
                if failure != last_failure:
                    _LOGGER.warning(
                        "registration_refresh_failed error_type=%s reason_code=%s", *failure
                    )
                    last_failure = failure
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self._refresh_interval)
