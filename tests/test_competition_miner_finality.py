from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_chain import OwnedFinalityStale
from umi.competition_miner_finality import CompetitionMinerFinality
from umi.miner import build_runtime

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_finalized_ancestry import recovery as recovery
from .test_open_competition import policy as policy


class Provider:
    def __init__(self):
        self.started = asyncio.Event()
        self.closed = False
        self.failed = False
        self.requests = []
        self.config = SimpleNamespace(collection_timeout_seconds=1)

    async def start(self):
        self.started.set()

    def ensure_observer_running(self):
        if self.failed:
            raise RuntimeError("observer failed")

    async def aclose(self):
        self.closed = True

    async def verified_blocks(self, heights=()):
        self.requests.append(heights)
        if any(type(h) is not int or h <= 0 or h > 500 for h in heights):
            raise ValueError("invalid height")
        return SimpleNamespace(height=500), tuple(SimpleNamespace(height=h) for h in heights)


def service():
    # Exercise lifecycle/port behavior without pretending this test provider
    # verifies proofs. Production construction always owns DispatchFinalityProvider.
    value = object.__new__(CompetitionMinerFinality)
    value._provider = Provider()
    value._running = False
    value._closed = False
    return value


async def test_all_header_reads_use_verified_provider_and_close():
    value = service()
    with pytest.raises(RuntimeError, match="not running"):
        await value.finalized_head_height()
    stop = asyncio.Event()
    task = asyncio.create_task(value.run(stop))
    await value._provider.started.wait()
    assert await value.finalized_head_height() == 500
    assert (await value.verified_block_at(320)).height == 320
    assert value._provider.requests == [(), (320,)]
    stop.set()
    await task
    assert value._provider.closed
    with pytest.raises(RuntimeError, match="not running"):
        await value.verified_block_at(320)
    with pytest.raises(RuntimeError, match="cannot be reused"):
        await value.run(stop)


async def test_observer_failure_terminates_lifecycle_and_closes():
    value = service()
    value._provider.failed = True
    with pytest.raises(RuntimeError, match="observer failed"):
        await value.run(asyncio.Event())
    assert value._provider.closed and value._closed


async def test_cancellation_closes_provider():
    value = service()
    task = asyncio.create_task(value.run(asyncio.Event()))
    await value._provider.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert value._provider.closed


@pytest.mark.parametrize("height", [True, 0, -1, 501])
async def test_invalid_or_future_headers_fail_closed(height):
    value = service()
    stop = asyncio.Event()
    task = asyncio.create_task(value.run(stop))
    await value._provider.started.wait()
    try:
        with pytest.raises(ValueError, match="invalid height"):
            await value.verified_block_at(height)
    finally:
        stop.set()
        await task


async def test_proof_failure_is_not_replaced_with_rpc_data():
    value = service()

    async def failed(heights=()):
        raise ValueError("bad proof")

    value._provider.verified_blocks = failed
    stop = asyncio.Event()
    task = asyncio.create_task(value.run(stop))
    await value._provider.started.wait()
    try:
        with pytest.raises(ValueError, match="bad proof"):
            await value.verified_block_at(320)
    finally:
        stop.set()
        await task


@pytest.mark.parametrize("height", [None, 320])
async def test_stale_head_waits_for_owned_recovery_of_the_original_header_query(height):
    value = service()
    value._running = True
    original = value._provider.verified_blocks
    attempts = []

    async def recovering(heights=()):
        attempts.append(heights)
        if len(attempts) == 1:
            raise OwnedFinalityStale("owned finalized head is stale")
        return await original(heights)

    value._provider.verified_blocks = recovering
    result = (
        await value.finalized_head_height()
        if height is None
        else (await value.verified_block_at(height)).height
    )
    assert result == (500 if height is None else height)
    assert attempts == ([(), ()] if height is None else [(height,), (height,)])


async def test_stale_head_wait_is_bounded_by_existing_collection_timeout():
    value = service()
    value._running = True
    value._provider.config.collection_timeout_seconds = 0.02

    async def stale(heights=()):
        raise OwnedFinalityStale("owned finalized head is stale")

    value._provider.verified_blocks = stale
    with pytest.raises(asyncio.TimeoutError):
        await value.finalized_head_height()


async def test_stale_head_recovery_does_not_hide_terminal_observer_failure():
    value = service()
    value._running = True

    async def stopped(heights=()):
        value._provider.failed = True
        raise OwnedFinalityStale("owned finalized head is stale")

    value._provider.verified_blocks = stopped
    with pytest.raises(RuntimeError, match="observer failed"):
        await value.finalized_head_height()


async def test_cancelling_stale_head_wait_joins_its_collection_task():
    value = service()
    value._running = True
    entered = asyncio.Event()
    exited = asyncio.Event()

    async def blocked(heights=()):
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            exited.set()

    value._provider.verified_blocks = blocked
    task = asyncio.create_task(value.finalized_head_height())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert exited.is_set()


def test_partial_configuration_fails_before_wallet_access(monkeypatch):
    import bittensor as bt

    monkeypatch.setattr(bt, "Wallet", lambda **kwargs: pytest.fail("wallet accessed"))
    with pytest.raises(ValueError, match="requires a competition policy"):
        build_runtime(SimpleNamespace(competition_chain_config="config.json"))


async def test_missing_observer_header_uses_verified_ancestry_and_timestamp(recovery):
    from types import MethodType

    from umi.competition_dispatch import DispatchFinalityProvider

    value = service()
    value._provider = recovery.source
    value._running = True
    recovery.source.verified_blocks = MethodType(
        DispatchFinalityProvider.verified_blocks, recovery.source
    )
    height = recovery.first + 1
    assert await recovery.source._finality.verified_block_at(height) is None
    block = await value.verified_block_at(height)
    assert block.height == height
    assert block.block_hash == recovery.by_height[height]
    assert recovery.state.roots == [bytes.fromhex(block.state_root[2:])]
    recovery.state.bad_proof = True
    with pytest.raises((ValueError, RuntimeError)):
        await value.verified_block_at(height)
