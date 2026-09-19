"""Provider shutdown owns queued collections, RPC cleanup and cache leases."""

import asyncio

import pytest

from umi.competition_chain_state import FinalizedCompetitionWeightProvider
from umi.competition_origin import FinalizedEndpointProvider

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_open_competition import policy as policy


def weight_provider(chain):
    return FinalizedCompetitionWeightProvider(
        chain.config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )


class ClosingRpc:
    def __init__(self, *, release=None, error=None):
        self.entered = asyncio.Event()
        self.release = release
        self.error = error
        self.calls = 0
        self.closed = False

    async def aclose(self):
        self.calls += 1
        self.entered.set()
        if self.release is not None:
            await self.release.wait()
        self.closed = True
        if self.error is not None:
            raise self.error


@pytest.mark.parametrize("cancellations", [0, 1, 2])
async def test_weight_close_owns_rpc_cleanup_and_namespace_lease(chain, cancellations):
    provider = weight_provider(chain)
    release_rpc = asyncio.Event()
    registration = provider._registration_rpc = ClosingRpc()
    weight = provider._weight_rpc = ClosingRpc(release=release_rpc)
    runtime = provider._runtime_rpc = ClosingRpc()
    await provider._lock.acquire()
    owns_lock = True
    closing = asyncio.create_task(provider.aclose())
    second_close = None
    try:
        await asyncio.sleep(0)
        assert provider._closed and provider._stop.is_set()
        assert not closing.done()
        assert registration.calls == weight.calls == runtime.calls == 0
        with pytest.raises(BlockingIOError):
            weight_provider(chain)

        # Finish the outstanding collection. Subclass RPC cleanup must remain
        # owned, even after base cleanup has finished and callers cancel close.
        provider._lock.release()
        owns_lock = False
        await asyncio.wait_for(weight.entered.wait(), timeout=2)
        assert registration.closed and not weight.closed and runtime.calls == 0
        assert provider._lock.locked()
        for _ in range(cancellations):
            closing.cancel()
            await asyncio.sleep(0)
            assert not closing.done()
        second_close = asyncio.create_task(provider.aclose())
        await asyncio.sleep(0)
        assert not second_close.done()
        with pytest.raises(BlockingIOError):
            weight_provider(chain)
    finally:
        if owns_lock:
            provider._lock.release()
        release_rpc.set()
        await asyncio.gather(closing, return_exceptions=True)
        if second_close is not None:
            await asyncio.gather(second_close, return_exceptions=True)
        await provider.aclose()

    assert closing.cancelled() is bool(cancellations)
    if not cancellations:
        closing.result()
    assert second_close.result() is None
    assert registration.closed and weight.closed and runtime.closed
    assert registration.calls == weight.calls == runtime.calls == 1
    assert provider._cache_lease is None
    assert not provider._lock.locked()
    reopened = weight_provider(chain)
    await reopened.aclose()


@pytest.mark.parametrize("kind", ["endpoint", "weight"])
async def test_queued_subclass_collection_checks_closed_after_lock(chain, monkeypatch, kind):
    if kind == "endpoint":
        provider = FinalizedEndpointProvider(
            chain.config,
            chain.policy,
            finality=chain.finality,
            proofs=chain.proofs,
            now_ms=lambda: chain.clock.now,
        )
        collect = provider._collect_origin_locked(None, None)
    else:
        provider = weight_provider(chain)
        collect = provider._collect_weights_locked(None, (), None)

    async def unexpected_read():
        pytest.fail("a queued collection read finality after shutdown began")

    monkeypatch.setattr(provider._proofs, "finalized_snapshot", unexpected_read)
    await provider._lock.acquire()
    collection = asyncio.create_task(collect)
    closing = None
    try:
        await asyncio.sleep(0)
        assert not collection.done()
        closing = asyncio.create_task(provider.aclose())
        await asyncio.sleep(0)
        assert provider._closed
    finally:
        provider._lock.release()
        await asyncio.gather(collection, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        await provider.aclose()
    with pytest.raises(ValueError, match=f"{kind} provider is closed"):
        collection.result()
    assert closing.result() is None


@pytest.mark.parametrize("failure", ["registration", "weight", "runtime"])
async def test_weight_close_failure_still_releases_every_resource_once(chain, failure):
    provider = weight_provider(chain)
    probes = {
        name: ClosingRpc(error=RuntimeError(name) if name == failure else None)
        for name in ("registration", "weight", "runtime")
    }
    provider._registration_rpc = probes["registration"]
    provider._weight_rpc = probes["weight"]
    provider._runtime_rpc = probes["runtime"]
    for _ in range(2):
        with pytest.raises(RuntimeError, match=f"^{failure}$"):
            await provider.aclose()
    assert all(probe.closed and probe.calls == 1 for probe in probes.values())
    assert provider._cache_lease is None
    assert not provider._lock.locked()
    reopened = weight_provider(chain)
    await reopened.aclose()
