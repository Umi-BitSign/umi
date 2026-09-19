from __future__ import annotations

import asyncio
import gc
import weakref
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from umi.competition_chain import OwnedFinalityStale, RegistrationCacheFull
from umi.competition_finality_cache import (
    VerifiedCaptureUnavailable,
    VerifiedRegistrationCache,
    _refresh_failure,
)
from umi.competition_submission_checkpoint import SubmissionCheckpointError
from umi.validator_chain import ValidatorChainError

from .test_open_competition import policy as policy

_PRIVATE_URL = "wss://private-provider.invalid/token/should-never-be-logged"


class ControlledProvider:
    def __init__(self, failure):
        self.failure = failure
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def collect(self):
        self.started.set()
        await self.release.wait()
        raise self.failure


def cache_for(provider, policy, **options):
    return VerifiedRegistrationCache(
        provider,
        policy,
        maximum_cache_age_seconds=60,
        maximum_head_age_ms=120_000,
        maximum_future_skew_ms=1_000,
        public_wait_seconds=1,
        **options,
    )


@contextmanager
def unhandled_errors():
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    errors = []

    def record_error(_loop, context):
        errors.append(context)
        loop.default_exception_handler(context)

    loop.set_exception_handler(record_error)
    try:
        yield errors
    finally:
        loop.set_exception_handler(previous)


async def drain_callbacks():
    # Let provider completion and its done callbacks run, then collect any
    # traceback cycles so an unobserved exception cannot escape the test.
    for _ in range(3):
        await asyncio.sleep(0)
    gc.collect()
    for _ in range(3):
        await asyncio.sleep(0)


class ClosingProvider:
    def __init__(self):
        self.started = asyncio.Event()
        self.cleaning = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = False

    async def collect(self):
        self.started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.cleaning.set()
            await self.release.wait()
            self.finished = True


async def finish_close_test(cache, provider, *tasks):
    provider.release.set()
    # Drain even a broken implementation, so a regression reports a failure
    # instead of leaving the test runner waiting for an abandoned collection.
    inflight = cache._inflight
    if inflight is not None and not inflight.done():
        inflight.cancel()
    await cache.aclose()
    await asyncio.gather(
        *(task for task in (*tasks, inflight) if task is not None), return_exceptions=True
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_again", [False, True])
async def test_close_cancellation_waits_for_shared_provider_cleanup(policy, cancel_again):
    provider = ClosingProvider()
    cache = cache_for(provider, policy)
    waiter = asyncio.create_task(cache.collect_fresh())
    closing = repeated = None
    try:
        await asyncio.wait_for(provider.started.wait(), 1)
        closing = asyncio.create_task(cache.aclose())
        await asyncio.wait_for(provider.cleaning.wait(), 1)
        closing.cancel()
        await asyncio.sleep(0.025)
        if cancel_again:
            closing.cancel()
            await asyncio.sleep(0.025)
        repeated = asyncio.create_task(cache.aclose())
        await asyncio.sleep(0.025)
        assert not closing.done(), "cancelled close released an active provider"
        assert not repeated.done(), "second close returned before provider cleanup"
        assert not provider.finished
        with pytest.raises(VerifiedCaptureUnavailable, match="closed"):
            await cache.collect_fresh()
        with pytest.raises(VerifiedCaptureUnavailable, match="closed"):
            await asyncio.wait_for(cache.cached(), 0.1)
        provider.release.set()
        with pytest.raises(asyncio.CancelledError):
            await closing
        await asyncio.wait_for(repeated, 1)
        assert provider.finished
        assert cache._inflight is None
        assert cache._cached is None
    finally:
        await finish_close_test(cache, provider, waiter, closing, repeated)


@pytest.mark.asyncio
async def test_collection_waiting_for_guard_cannot_start_after_close(policy):
    provider = ClosingProvider()
    cache = cache_for(provider, policy)
    waiter = closing = None
    await cache._guard.acquire()
    try:
        waiter = asyncio.create_task(cache.collect_fresh())
        await asyncio.sleep(0)
        closing = asyncio.create_task(cache.aclose())
        await asyncio.sleep(0)
        assert cache._closed
        cache._guard.release()
        with pytest.raises(VerifiedCaptureUnavailable, match="closed"):
            await asyncio.wait_for(waiter, 1)
        await asyncio.wait_for(closing, 1)
        assert not provider.started.is_set()
    finally:
        if cache._guard.locked():
            cache._guard.release()
        await finish_close_test(cache, provider, waiter, closing)


@pytest.mark.asyncio
async def test_closed_cache_does_not_serve_previously_verified_capture(policy):
    provider = CountingProvider()
    provider.failure = None
    cache = cache_for(provider, policy)
    try:
        first = await cache.collect_fresh()
        assert await cache.cached() == first
        closing = asyncio.create_task(cache.aclose())
        # The close call fences reads before its cleanup task drains.
        await asyncio.sleep(0)
        with pytest.raises(VerifiedCaptureUnavailable, match="closed"):
            await cache.cached()
        await closing
        assert cache._cached is None
    finally:
        await cache.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("public_read", [False, True])
async def test_late_provider_success_cannot_repopulate_closed_cache(policy, public_read):
    class FinishesOnCancel(CountingProvider):
        async def collect(self):
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return self.capture

    provider = FinishesOnCancel()
    cache = cache_for(provider, policy)
    waiter = asyncio.create_task(cache.collect_fresh())
    reader = None
    try:
        await asyncio.wait_for(provider.started.wait(), 1)
        if public_read:
            reader = asyncio.create_task(cache.cached())
            await asyncio.sleep(0)
        await cache.aclose()
        for task in (waiter, reader):
            if task is not None:
                with pytest.raises(VerifiedCaptureUnavailable, match="closed"):
                    await asyncio.wait_for(task, 1)
        assert cache._cached is None
        assert cache._inflight is None
    finally:
        await finish_close_test(cache, provider, waiter, reader)


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_cancelled", [False, True])
async def test_abandoned_collection_completion_has_no_unhandled_exception(
    policy, caplog, provider_cancelled
):
    failure = asyncio.CancelledError() if provider_cancelled else RuntimeError(_PRIVATE_URL)
    provider = ControlledProvider(failure)
    cache = cache_for(provider, policy)
    with unhandled_errors() as errors:
        waiter = asyncio.create_task(cache.collect_fresh())
        try:
            await asyncio.wait_for(provider.started.wait(), timeout=1)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            assert cache._inflight is not None and not cache._inflight.done()
            provider.release.set()
            await drain_callbacks()
            assert cache._inflight is None
            assert errors == []
            assert _PRIVATE_URL not in caplog.text
        finally:
            provider.release.set()
            await cache.aclose()
            await asyncio.gather(waiter, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_one", [False, True])
async def test_collection_error_still_reaches_active_waiters(policy, cancel_one):
    failure = RuntimeError(_PRIVATE_URL)
    provider = ControlledProvider(failure)
    cache = cache_for(provider, policy)
    with unhandled_errors() as errors:
        waiters = [asyncio.create_task(cache.collect_fresh()) for _ in range(3)]
        try:
            await asyncio.wait_for(provider.started.wait(), timeout=1)
            if cancel_one:
                waiters[0].cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiters[0]
            provider.release.set()
            active = waiters[1:] if cancel_one else waiters
            outcomes = await asyncio.gather(*active, return_exceptions=True)
            assert all(outcome is failure for outcome in outcomes)
            await drain_callbacks()
            assert cache._inflight is None
            assert errors == []
        finally:
            provider.release.set()
            await cache.aclose()
            await asyncio.gather(*waiters, return_exceptions=True)


@pytest.mark.asyncio
async def test_provider_cancellation_clears_collection_without_callback_failure(policy):
    provider = ControlledProvider(asyncio.CancelledError())
    cache = cache_for(provider, policy)
    with unhandled_errors() as errors:
        waiter = asyncio.create_task(cache.collect_fresh())
        try:
            await asyncio.wait_for(provider.started.wait(), timeout=1)
            provider.release.set()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            await drain_callbacks()
            assert cache._inflight is None
            assert errors == []

            # A cancelled attempt does not poison the next collection, and
            # observing completion must not swallow a later caller's failure.
            failure = RuntimeError("later provider failure")
            provider.failure = failure
            with pytest.raises(RuntimeError) as caught:
                await cache.collect_fresh()
            assert caught.value is failure
        finally:
            provider.release.set()
            await cache.aclose()
            await asyncio.gather(waiter, return_exceptions=True)


@pytest.mark.parametrize(
    "reason",
    [
        "owned_finality_unavailable",
        "proof_rpc_failed",
        "proof_rpc_rate_limited",
        "proof_rpc_error",
        "proof_rpc_response_invalid",
        "storage_proof_rpc_failed",
        "storage_proof_verification_failed",
        "storage_value_decode_failed",
        "runtime_metadata_rpc_failed",
    ],
)
def test_known_chain_failure_has_exact_redacted_diagnostic(reason):
    failure = ValidatorChainError(reason)
    failure.__cause__ = RuntimeError(_PRIVATE_URL)
    failure.__notes__ = [_PRIVATE_URL]
    assert _refresh_failure(failure) == ("ValidatorChainError", reason)


@pytest.mark.parametrize(
    "reason",
    [
        _PRIVATE_URL,
        "private_token_with_only_valid_identifier_characters",
        "proof_rpc_failed\n" + _PRIVATE_URL,
        _PRIVATE_URL * 1000,
        None,
        ["proof_rpc_failed"],
    ],
)
def test_unrecognized_chain_reason_is_not_forwarded(reason):
    failure = ValidatorChainError(reason)
    assert _refresh_failure(failure) == ("ValidatorChainError", "validator_chain_unclassified")


@pytest.mark.parametrize(
    ("failure_class", "expected"),
    [
        (OwnedFinalityStale, ("OwnedFinalityStale", "owned_finality_stale")),
        (RegistrationCacheFull, ("RegistrationCacheFull", "registration_cache_capacity")),
        (SubmissionCheckpointError, ("SubmissionCheckpointError", "submission_checkpoint_failure")),
        (TimeoutError, ("TimeoutError", "refresh_timeout")),
        (asyncio.TimeoutError, ("TimeoutError", "refresh_timeout")),
        (ValueError, ("ValueError", "refresh_validation_failed")),
    ],
)
def test_known_failure_class_does_not_forward_message_or_reason(failure_class, expected):
    failure = failure_class(_PRIVATE_URL)
    failure.reason_code = _PRIVATE_URL
    assert _refresh_failure(failure) == expected


def test_unknown_exception_does_not_expose_dynamic_type_or_inspect_attributes():
    class Untrusted(ValidatorChainError):
        def __init__(self):
            RuntimeError.__init__(self)

        @property
        def reason_code(self):
            raise AssertionError("must not inspect unknown diagnostic attributes")

        def __str__(self):
            raise AssertionError("must not format unknown exceptions")

    Untrusted.__name__ = _PRIVATE_URL
    assert _refresh_failure(Untrusted()) == ("Exception", "unclassified_refresh_failure")


@pytest.mark.asyncio
async def test_refresh_logs_reason_transitions_and_resets_after_recovery(
    policy, monkeypatch, caplog
):
    cache = cache_for(None, policy)
    failures = iter(
        [
            ValidatorChainError("owned_finality_unavailable"),
            ValidatorChainError("owned_finality_unavailable"),
            ValidatorChainError("storage_proof_rpc_failed"),
            ValidatorChainError("storage_proof_rpc_failed"),
            None,
            ValidatorChainError("storage_proof_rpc_failed"),
            ValidatorChainError("storage_value_decode_failed"),
            ValidatorChainError(_PRIVATE_URL),
            ValidatorChainError("another_private_token"),
            None,
        ]
    )
    remaining = 10

    async def collect():
        nonlocal remaining
        failure = next(failures)
        remaining -= 1
        if not remaining:
            cache._stop.set()
        if failure is not None:
            failure.__cause__ = RuntimeError(_PRIVATE_URL)
            failure.__notes__ = [_PRIVATE_URL]
            raise failure

    monkeypatch.setattr(cache, "collect_fresh", collect)
    cache._refresh_interval = 0.001
    with caplog.at_level("INFO", logger="umi.competition_finality_cache"):
        await cache._run()
    messages = [record.getMessage() for record in caplog.records]
    prefix = "registration_refresh_failed error_type=ValidatorChainError reason_code="
    assert messages == [
        prefix + "owned_finality_unavailable",
        prefix + "storage_proof_rpc_failed",
        "registration_refresh_recovered",
        prefix + "storage_proof_rpc_failed",
        prefix + "storage_value_decode_failed",
        prefix + "validator_chain_unclassified",
        "registration_refresh_recovered",
    ]
    assert all(record.exc_info is None and record.stack_info is None for record in caplog.records)
    assert _PRIVATE_URL not in caplog.text
    assert "another_private_token" not in caplog.text
    assert remaining == 0
    with pytest.raises(VerifiedCaptureUnavailable):
        await cache.cached()


@pytest.mark.asyncio
async def test_classified_provider_failure_still_reaches_the_caller(policy):
    failure = ValidatorChainError("proof_rpc_failed")
    failure.__cause__ = RuntimeError(_PRIVATE_URL)
    provider = ControlledProvider(failure)
    provider.release.set()
    cache = cache_for(provider, policy)
    try:
        with pytest.raises(ValidatorChainError) as caught:
            await cache.collect_fresh()
        assert caught.value is failure
        with pytest.raises(VerifiedCaptureUnavailable):
            await cache.cached()
    finally:
        await cache.aclose()


class CountingProvider(ControlledProvider):
    def __init__(self):
        from .test_competition_service import Provider

        super().__init__(ValidatorChainError("proof_rpc_rate_limited"))
        self.capture = Provider(None, None).capture
        self.calls = 0
        self.release.set()

    async def collect(self):
        self.calls += 1
        self.started.set()
        await self.release.wait()
        if self.failure is not None:
            raise self.failure
        return self.capture


def rate_limit_setup(policy):
    provider = CountingProvider()
    clock = SimpleNamespace(now=100.0)
    cache = cache_for(provider, policy, monotonic=lambda: clock.now)
    return provider, clock, cache


async def expect_rate_limit(cache):
    with pytest.raises(ValidatorChainError) as caught:
        await cache.collect_fresh()
    assert caught.value.reason_code == "proof_rpc_rate_limited"
    assert str(caught.value) == "proof_rpc_rate_limited"


@pytest.mark.asyncio
async def test_rate_limit_cooldown_bounds_sequential_attempts_without_extending(policy):
    provider, clock, cache = rate_limit_setup(policy)
    try:
        await expect_rate_limit(cache)
        assert provider.calls == 1
        for clock.now in (100.0, 115.0, 129.999):
            await expect_rate_limit(cache)
        assert provider.calls == 1
        with pytest.raises(VerifiedCaptureUnavailable):
            await cache.cached()
        clock.now = 130.0
        await expect_rate_limit(cache)
        assert provider.calls == 2
    finally:
        await cache.aclose()


@pytest.mark.asyncio
async def test_rate_limit_cooldown_expiry_starts_one_shared_probe(policy):
    provider, clock, cache = rate_limit_setup(policy)
    waiters = []
    try:
        for expected_calls in (1, 2):
            provider.started.clear()
            provider.release.clear()
            waiters = [asyncio.create_task(cache.collect_fresh()) for _ in range(4)]
            await asyncio.wait_for(provider.started.wait(), 1)
            assert provider.calls == expected_calls
            provider.release.set()
            outcomes = await asyncio.gather(*waiters, return_exceptions=True)
            assert all(outcome is provider.failure for outcome in outcomes)
            await expect_rate_limit(cache)
            assert provider.calls == expected_calls
            clock.now += 30.0
    finally:
        provider.release.set()
        await cache.aclose()
        await asyncio.gather(*waiters, return_exceptions=True)


@pytest.mark.asyncio
async def test_rate_limit_cooldown_survives_all_waiters_cancelling(policy, caplog):
    provider, clock, cache = rate_limit_setup(policy)
    provider.release.clear()
    provider.failure.__cause__ = RuntimeError(_PRIVATE_URL)
    with unhandled_errors() as errors:
        waiters = [asyncio.create_task(cache.collect_fresh()) for _ in range(3)]
        try:
            await asyncio.wait_for(provider.started.wait(), 1)
            for waiter in waiters:
                waiter.cancel()
            results = await asyncio.gather(*waiters, return_exceptions=True)
            assert all(isinstance(result, asyncio.CancelledError) for result in results)
            clock.now = 110.0
            provider.release.set()
            await drain_callbacks()
            assert cache._inflight is None
            clock.now = 139.999
            await expect_rate_limit(cache)
            assert provider.calls == 1
            assert errors == []
            assert _PRIVATE_URL not in caplog.text
            clock.now = 140.0
            await expect_rate_limit(cache)
            assert provider.calls == 2
        finally:
            provider.release.set()
            await cache.aclose()
            await asyncio.gather(*waiters, return_exceptions=True)


@pytest.mark.asyncio
async def test_rate_limit_cooldown_does_not_retain_original_exception(policy):
    class PrivateMarker:
        pass

    provider, _clock, cache = rate_limit_setup(policy)
    marker = PrivateMarker()
    reference = weakref.ref(marker)
    provider.failure.private_marker = marker
    del marker
    try:
        await expect_rate_limit(cache)
        provider.failure = None
        await drain_callbacks()
        assert reference() is None
        await expect_rate_limit(cache)
        assert provider.calls == 1
    finally:
        await cache.aclose()


@pytest.mark.asyncio
async def test_rate_limit_cooldown_recovers_without_reusing_stale_capture(policy):
    provider, clock, cache = rate_limit_setup(policy)
    try:
        provider.failure = None
        first = await cache.collect_fresh()
        assert first.snapshot == provider.capture.snapshot
        clock.now += 61.0
        provider.failure = ValidatorChainError("proof_rpc_rate_limited")
        await expect_rate_limit(cache)
        provider.failure = None
        with pytest.raises(VerifiedCaptureUnavailable):
            await cache.cached()
        await expect_rate_limit(cache)
        assert provider.calls == 2
        clock.now += 30.0
        assert await cache.collect_fresh() == first
        assert provider.calls == 3
        assert await cache.collect_fresh() == first
        assert provider.calls == 4
    finally:
        await cache.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_kind", ["other_code", "same_message", "subclass", "cancelled"])
async def test_rate_limit_cooldown_does_not_apply_to_other_failures(policy, failure_kind):
    class OtherChainError(ValidatorChainError):
        pass

    provider, _clock, cache = rate_limit_setup(policy)
    provider.failure = {
        "other_code": ValidatorChainError("proof_rpc_failed"),
        "same_message": RuntimeError("proof_rpc_rate_limited"),
        "subclass": OtherChainError("proof_rpc_rate_limited"),
        "cancelled": asyncio.CancelledError(),
    }[failure_kind]
    try:
        for expected_calls in (1, 2):
            with pytest.raises(type(provider.failure)):
                await cache.collect_fresh()
            assert provider.calls == expected_calls
    finally:
        await cache.aclose()


@pytest.mark.asyncio
async def test_rate_limit_cooldown_is_shared_with_background_refresh(policy, monkeypatch):
    provider, _clock, cache = rate_limit_setup(policy)
    logged = asyncio.Event()

    def warning(message, *args):
        assert message % args == (
            "registration_refresh_failed error_type=ValidatorChainError "
            "reason_code=proof_rpc_rate_limited"
        )
        logged.set()

    monkeypatch.setattr("umi.competition_finality_cache._LOGGER.warning", warning)
    try:
        await expect_rate_limit(cache)
        await cache.start()
        await asyncio.wait_for(logged.wait(), 1)
        assert provider.calls == 1
        await expect_rate_limit(cache)
        assert provider.calls == 1
    finally:
        await cache.aclose()
