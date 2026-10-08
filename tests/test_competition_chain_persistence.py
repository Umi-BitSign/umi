"""Blocking retention owns its thread without blocking intake or outliving its lock."""

import asyncio
import os
import sqlite3
import threading

import pytest

from umi.private_files import PrivateStateBusyError, lock_private_file

from .test_competition_chain import _HEIGHT
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_registration_retention import advance, retained_rows
from .test_open_competition import policy as policy


def blocked_retention(provider, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    threads = []

    def retained():
        threads.append(threading.get_ident())
        entered.set()
        if not release.wait(3):
            raise RuntimeError("test retention was not released")
        return frozenset()

    monkeypatch.setattr(provider, "_retained_capture_blocks", retained)
    return entered, release, threads


async def test_busy_retention_reuses_collected_proof_and_preserves_prior_capture(
    chain, monkeypatch, tmp_path
):
    provider = chain.provider
    await provider.collect()
    before = retained_rows(provider)
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)
    path = tmp_path / "retention.lock"
    path.write_bytes(b"")
    path.chmod(0o600)
    held = lock_private_file(path)
    busy = threading.Event()

    def retained():
        try:
            descriptor = lock_private_file(path)
        except PrivateStateBusyError:
            busy.set()
            raise
        os.close(descriptor)
        return frozenset({_HEIGHT})

    monkeypatch.setattr(provider, "_retained_capture_blocks", retained)
    task = asyncio.create_task(provider.collect())
    try:
        assert await asyncio.to_thread(busy.wait, 120)
        calls = tuple(chain.rpc.calls)
        # Collection completes while the real retention mutex remains held.
        assert (await task).snapshot.block == chain.finality.ref.block_number
    finally:
        os.close(held)
        await asyncio.gather(task, return_exceptions=True)
    assert task.result().snapshot.block == chain.finality.ref.block_number
    assert tuple(chain.rpc.calls) == calls
    assert retained_rows(provider)[0] == before[0]


async def test_cancelled_busy_retention_persistence_rolls_back(chain, monkeypatch):
    provider = chain.provider
    await provider.collect()
    before = retained_rows(provider)
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)
    busy, release = threading.Event(), threading.Event()

    def retained():
        busy.set()
        assert release.wait(120)
        raise PrivateStateBusyError("round_journal_lock", "ab" * 32, 11)

    monkeypatch.setattr(provider, "_retained_capture_blocks", retained)
    task = asyncio.create_task(provider._collect_locked())
    try:
        assert await asyncio.to_thread(busy.wait, 120)
        task.cancel()
        await asyncio.sleep(0)
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled() and not provider._lock.locked()
    assert retained_rows(provider) == before


async def test_busy_retention_does_not_bypass_working_cache_capacity(chain, monkeypatch):
    from umi.competition_chain import RegistrationCacheFull

    provider = chain.provider
    await provider.collect()
    before = retained_rows(provider)
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)
    provider.config = provider.config.model_copy(update={"maximum_cache_bytes": 1})

    def retained():
        raise PrivateStateBusyError("round_journal_lock", "ab" * 32, 11)

    monkeypatch.setattr(provider, "_retained_capture_blocks", retained)
    with pytest.raises(RegistrationCacheFull):
        await provider.collect()
    assert retained_rows(provider) == before


@pytest.mark.parametrize("untrusted_subclass", [False, True])
async def test_invalid_retention_still_holds_without_pruning(
    chain, monkeypatch, untrusted_subclass
):
    provider = chain.provider
    await provider.collect()
    before = retained_rows(provider)
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)

    class Untrusted(PrivateStateBusyError):
        pass

    def retained():
        if untrusted_subclass:
            raise Untrusted("round_journal_lock", "ab" * 32, 11)
        raise ValueError("invalid retention")

    monkeypatch.setattr(provider, "_retained_capture_blocks", retained)
    with pytest.raises(PrivateStateBusyError if untrusted_subclass else ValueError):
        await provider.collect()
    assert retained_rows(provider) == before


async def test_blocking_retention_does_not_block_intake_event_loop(chain, monkeypatch):
    provider = chain.provider
    entered, release, threads = blocked_retention(provider, monkeypatch)
    task = asyncio.create_task(provider.collect())
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        assert not task.done(), "intake could not run while the retention callback was blocked"
        assert len(threads) == 1
        assert threads[0] != threading.get_ident()
        assert provider._lock.locked()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert task.result().snapshot.block == _HEIGHT


@pytest.mark.parametrize("cancellation", ["once", "repeated", "timeout"])
async def test_cancelled_persistence_drains_before_unlock_and_rolls_back(
    chain, monkeypatch, cancellation
):
    provider = chain.provider
    await provider.collect()
    before = retained_rows(provider)
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)
    entered, release, _ = blocked_retention(provider, monkeypatch)
    if cancellation == "timeout":
        provider.config = provider.config.model_copy(update={"collection_timeout_seconds": 1})
        task = asyncio.create_task(provider.collect())
    else:
        # Target the owning task directly to exercise a second cancellation
        # during thread cleanup rather than wait_for's cancellation wrapper.
        task = asyncio.create_task(provider._collect_locked())
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        assert not task.done()
        if cancellation == "timeout":
            await asyncio.sleep(1.1)
        else:
            task.cancel()
            await asyncio.sleep(0.01)
            if cancellation == "repeated":
                task.cancel()
                await asyncio.sleep(0.01)
        assert not task.done(), "persistence ownership was released before its thread stopped"
        assert provider._lock.locked()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    if cancellation == "timeout":
        with pytest.raises(ValueError, match="registration collection timed out"):
            task.result()
    else:
        assert task.cancelled()
    assert not provider._lock.locked()
    assert retained_rows(provider) == before
    with sqlite3.connect(provider._path) as connection:
        assert connection.execute("SELECT block FROM observed_head").fetchone() == (_HEIGHT,)
    retry = await provider.collect()
    assert retry.snapshot.block == chain.finality.ref.block_number


@pytest.mark.parametrize("cancellations", [0, 1, 2])
async def test_close_drains_persistence_before_releasing_provider(
    chain, monkeypatch, cancellations
):
    provider = chain.provider
    entered, release, _ = blocked_retention(provider, monkeypatch)
    collection = asyncio.create_task(provider.collect())
    closing = None
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        closing = asyncio.create_task(provider.aclose())
        await asyncio.sleep(0.01)
        assert provider._closed
        assert not closing.done(), "provider closed while its persistence thread was still active"
        for _ in range(cancellations):
            closing.cancel()
            await asyncio.sleep(0.01)
            assert not closing.done()
        assert provider._lock.locked()
    finally:
        release.set()
        await asyncio.gather(collection, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
    assert provider._latest is None
    assert not provider._lock.locked()
    assert closing.cancelled() is bool(cancellations)
    if not cancellations:
        closing.result()
    await provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await provider.collect()


async def test_collection_queued_before_close_rechecks_closed_after_lock(chain):
    provider = chain.provider
    await provider._lock.acquire()
    collection = asyncio.create_task(provider.collect())
    closing = None
    try:
        await asyncio.sleep(0.01)
        assert not collection.done()
        closing = asyncio.create_task(provider.aclose())
        await asyncio.sleep(0.01)
        assert provider._closed
    finally:
        provider._lock.release()
        await asyncio.gather(collection, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
    with pytest.raises(ValueError, match="closed"):
        collection.result()
    closing.result()
    assert not retained_rows(provider)
