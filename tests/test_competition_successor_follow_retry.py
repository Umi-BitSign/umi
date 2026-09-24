"""Service retry qualification using native publication journals and controlled RPC faults."""

import asyncio

import pytest

from umi.competition_chain import OwnedFinalityStale, RegistrationProviderTimeout
from umi.competition_successor_follow import poll_successor_rounds, wait_publisher_ready
from umi.validator_chain import ValidatorChainError

from .test_competition_successor_follow import automatic as automatic
from .test_competition_successor_follow import chain_config as chain_config
from .test_competition_successor_follow import completed
from .test_competition_successor_follow import feed_case as feed_case
from .test_competition_successor_follow import guarded as guarded
from .test_competition_successor_follow import package_case as package_case
from .test_competition_successor_follow import package_limits as package_limits
from .test_competition_successor_follow import policy as policy
from .test_competition_successor_follow import publication_case as publication_case
from .test_competition_successor_follow import release_identity as release_identity
from .test_competition_successor_follow import replay_limits as replay_limits
from .test_competition_successor_follow import successor_case as successor_case
from .test_competition_successor_follow import successor_chain as successor_chain
from .test_competition_successor_follow import successor_release as successor_release
from .test_competition_successor_follow import v3_predecessor as v3_predecessor
from .test_competition_successor_follow import worker_capacity as worker_capacity


class Finished(Exception):
    pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason",
    [
        "proof_rpc_failed",
        "proof_rpc_rate_limited",
        "proof_rpc_error",
        "timeout",
        "collection_timeout",
        "owned_finality_stale",
    ],
)
async def test_transient_capture_reuses_publisher_and_publishes(
    automatic, package_case, monkeypatch, reason
):
    c = automatic
    completed(c, package_case)
    collect = c.provider.collect
    calls = 0
    reports = []

    async def flaky():
        nonlocal calls
        calls += 1
        if calls == 1:
            if reason == "timeout":
                raise TimeoutError("private endpoint detail")
            if reason == "collection_timeout":
                raise RegistrationProviderTimeout("registration collection timed out")
            if reason == "owned_finality_stale":
                raise OwnedFinalityStale("owned finality is stale")
            raise ValidatorChainError(reason)
        return await collect()

    monkeypatch.setattr(c.provider, "collect", flaky)

    def report(result):
        reports.append(result)
        if result["status"] == "published":
            raise Finished

    with pytest.raises(Finished):
        await poll_successor_rounds(c.service, poll_seconds=0.001, report=report)
    assert reports[0]["status"] == "waiting_for_chain"
    assert reports[0]["reason_code"] == (
        "chain_collection_timeout" if reason in {"timeout", "collection_timeout"} else reason
    )
    assert "private" not in str(reports)
    assert len(c.feed.history()) == 1
    assert len(c.publisher.builder.journal.keys("authorization")) == 1


@pytest.mark.asyncio
async def test_retry_after_signed_publication_recovers_without_resigning(
    automatic, package_case, monkeypatch
):
    c = automatic
    completed(c, package_case)
    build = c.publisher.build
    calls = 0

    async def interrupted(*args, **kwargs):
        nonlocal calls
        calls += 1
        await build(*args, **kwargs)
        raise TimeoutError("lost result after signing")

    monkeypatch.setattr(c.publisher, "build", interrupted)
    reports = []

    def report(result):
        reports.append(result)
        if result["status"] == "recovered_signed_history":
            raise Finished

    with pytest.raises(Finished):
        await poll_successor_rounds(c.service, poll_seconds=0.001, report=report)
    assert calls == 1
    assert reports[0]["status"] == "waiting_for_chain"
    assert len(c.feed.history()) == 1
    assert len(c.publisher.builder.journal.keys("authorization")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason", ["proof_invalid", "proof_rpc_response_invalid", "proof_rpc_response_limit"]
)
async def test_invalid_chain_evidence_is_not_retried(automatic, monkeypatch, reason):
    async def invalid():
        raise ValidatorChainError(reason)

    monkeypatch.setattr(automatic.provider, "collect", invalid)
    reports = []
    with pytest.raises(ValidatorChainError, match=reason):
        await poll_successor_rounds(automatic.service, poll_seconds=0.001, report=reports.append)
    assert reports == []


@pytest.mark.asyncio
async def test_startup_wait_preserves_provider_then_recovers():
    class Provider:
        def __init__(self):
            self.calls = 0

        def ensure_observer_running(self):
            pass

        async def wait_ready(self):
            self.calls += 1
            if self.calls < 4:
                raise ValidatorChainError("proof_rpc_rate_limited")
            return "ready"

    p, reports = Provider(), []
    assert await wait_publisher_ready(p, retry_seconds=0.001, report=reports.append) == "ready"
    assert p.calls == 4 and len(reports) == 3


@pytest.mark.asyncio
async def test_startup_retry_cancels_without_another_attempt():
    entered = asyncio.Event()

    class Provider:
        calls = 0

        def ensure_observer_running(self):
            pass

        async def wait_ready(self):
            self.calls += 1
            raise ValidatorChainError("proof_rpc_failed")

    p = Provider()
    task = asyncio.create_task(
        wait_publisher_ready(p, retry_seconds=60, report=lambda _: entered.set())
    )
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert p.calls == 1


@pytest.mark.asyncio
async def test_startup_retry_does_not_hide_a_terminal_observer():
    class Provider:
        calls = 0

        def ensure_observer_running(self):
            raise RuntimeError("owned_finality_observer_stopped")

        async def wait_ready(self):
            self.calls += 1
            raise ValidatorChainError("proof_rpc_failed")

    p, reports = Provider(), []
    with pytest.raises(RuntimeError, match="owned_finality_observer_stopped"):
        await wait_publisher_ready(p, retry_seconds=0.001, report=reports.append)
    assert p.calls == 1 and reports == []


@pytest.mark.asyncio
async def test_generic_value_error_cannot_masquerade_as_transport_timeout(automatic, monkeypatch):
    async def invalid():
        raise ValueError("registration collection timed out")

    monkeypatch.setattr(automatic.provider, "collect", invalid)
    with pytest.raises(ValueError, match="registration collection timed out"):
        await poll_successor_rounds(automatic.service, poll_seconds=0.001)
