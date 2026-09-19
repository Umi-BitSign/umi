from __future__ import annotations

import asyncio
import threading

import pytest

from umi import competition_work_queue as queue_module
from umi.competition_work_signing import statement_slot
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .async_ownership import PausedCall as PausedCall
from .test_competition_work_queue import endorse_model
from .test_competition_work_queue_batch import batch as batch_fixture
from .test_competition_work_queue_batch import chain_config as chain_config
from .test_competition_work_queue_batch import entries, prepare
from .test_competition_work_queue_batch import policy as policy
from .test_competition_work_queue_batch import runtime as runtime
from .test_competition_work_queue_batch import setup as setup
from .test_competition_work_queue_batch import signing as signing
from .test_competition_work_queue_batch import work as work

batch = batch_fixture


@pytest.mark.asyncio
async def test_unsigned_retry_does_not_collect_a_head_per_retained_endpoint(batch):
    original = batch.queue.provider.collect
    observations = []

    async def collect():
        observations.append(1)
        return await original()

    batch.queue.provider.collect = collect
    await prepare(batch)
    initial_collections = len(observations)
    assert initial_collections > 0
    observations.clear()
    await prepare(batch)
    assert len(observations) <= initial_collections
    assert not tuple(batch.queue.publication_directory.iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["model", "authorization"])
async def test_finalized_expiry_during_certificate_retention_prevents_delivery(
    setup, monkeypatch, kind
):
    await prepare(setup)
    statement = getattr(setup, kind)
    votes = [
        await endorse_model(setup, signer) if kind == "model" else await signer.endorse(statement)
        for signer in setup.signers
    ]
    await setup.queue.accept(votes[0])
    slot = statement_slot(statement)
    assert setup.queue.journal.get("certificate", slot) is None
    assert not tuple(setup.queue.order_directory.iterdir())
    assert not tuple(setup.queue.publication_directory.iterdir())

    original = setup.queue._certificate
    paused = PausedCall(lambda result: result)
    retained = []

    def retain_then_pause(*args):
        result = original(*args)
        assert result is not None
        retained.append(result)
        return paused(result)

    monkeypatch.setattr(setup.queue, "_certificate", retain_then_pause)
    observed = []
    collect = setup.provider.collect

    async def record_head():
        capture = await collect()
        observed.append(setup.provider.block)
        return capture

    monkeypatch.setattr(setup.provider, "collect", record_head)

    def evidence():
        with setup.queue.journal.transaction() as db:
            return {
                (row[0], row[1]): bytes(row[2])
                for row in db.execute(
                    "SELECT kind,id,body FROM records WHERE kind IN ('vote','certificate')"
                )
            }

    task = asyncio.create_task(setup.queue.accept(votes[1]))
    try:
        await asyncio.wait_for(paused.entered.wait(), timeout=5)
        assert paused.thread_id != threading.get_ident()
        assert not task.done()
        saved = evidence()
        assert saved[("certificate", slot)] == canonical_json_bytes(retained[0])
        for vote in votes:
            key = slot + ":" + identity(vote.signature.hotkey)
            assert saved[("vote", key)] == canonical_json_bytes(vote)

        closed = statement.body.round.evaluation_close_block + 1
        assert observed and all(block < closed for block in observed)
        setup.provider.block = closed
        paused.release.set()
        assert await asyncio.wait_for(task, timeout=5) == digest(statement)
        assert observed[-1] == closed
        assert evidence() == saved
        assert not tuple(setup.queue.order_directory.iterdir())
        assert not tuple(setup.queue.publication_directory.iterdir())
    finally:
        paused.release.set()
        await asyncio.gather(task, return_exceptions=True)


async def pause_operation(batch, monkeypatch, operation):
    if operation == "pending":
        await prepare(batch)
        name = "_statement"
    else:
        name = "_retain_many"
    paused = PausedCall(getattr(batch.queue, name))
    monkeypatch.setattr(batch.queue, name, paused)

    async def run():
        if operation == "prepare":
            return await prepare(batch)
        return await batch.queue.pending(batch.work.signers[0].hotkey.ss58_address)

    return paused, run


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["prepare", "pending"])
async def test_queue_blocking_work_keeps_event_loop_responsive(batch, monkeypatch, operation):
    paused, run = await pause_operation(batch, monkeypatch, operation)
    task = asyncio.create_task(run())
    try:
        await asyncio.wait_for(paused.entered.wait(), timeout=5)
        assert paused.thread_id != threading.get_ident()
        assert not task.done() and not paused.finished.is_set()
        progress = asyncio.Event()
        asyncio.get_running_loop().call_soon(progress.set)
        await asyncio.wait_for(progress.wait(), timeout=1)
        assert not paused.release.is_set()
        paused.release.set()
        result = await asyncio.wait_for(task, timeout=5)
        assert paused.finished.is_set()
        if operation == "prepare":
            assert len(entries(batch)) == 2
        else:
            assert {digest(s) for s in result[1]} == {digest(s) for s in batch.statements}
    finally:
        paused.release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["prepare", "pending"])
async def test_queue_cancellation_drains_blocking_work_before_releasing_locks(
    batch, monkeypatch, operation
):
    competing = queue_module.WorkQueue(**batch.arguments)
    paused, run = await pause_operation(batch, monkeypatch, operation)
    task = asyncio.create_task(run())
    follower = None
    try:
        await asyncio.wait_for(paused.entered.wait(), timeout=5)
        assert paused.thread_id != threading.get_ident()
        assert batch.queue.serial.locked()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not paused.finished.is_set()

        follower = asyncio.create_task(
            batch.queue.pending(batch.work.signers[0].hotkey.ss58_address)
        )
        await asyncio.sleep(0)
        assert not follower.done()
        if operation == "prepare":
            with pytest.raises(BlockingIOError), competing.journal.locked():
                pytest.fail("cancelled preparation released its process lease before drainage")

        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and batch.queue.serial.locked()
        paused.release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        assert paused.finished.is_set()
        _, statements = await asyncio.wait_for(follower, timeout=5)
        assert {digest(s) for s in statements} == {digest(s) for s in batch.statements}
        assert not batch.queue.serial.locked()
        with competing.journal.locked():
            assert len(entries(batch)) == 2
        if operation == "prepare":
            # Cancellation may leave a complete immutable batch, never a partial
            # cohort or permission to choose a replacement issuance on retry.
            original = entries(batch)
            await prepare(batch)
            assert entries(batch) == original
            assert len(batch.queue.transport_provider.calls) == 2
    finally:
        paused.release.set()
        await asyncio.gather(
            *(t for t in (task, follower) if t is not None), return_exceptions=True
        )
