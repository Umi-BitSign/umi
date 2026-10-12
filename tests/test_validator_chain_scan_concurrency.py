"""Independent block reads overlap while shared provider ownership is retained."""

import asyncio

import pytest

from umi.concurrency import await_owned_task
from umi.validator_chain_scan import ValidatorChainScanError

from .test_validator_chain_scan import FakePort, add_block, identity, scanner


@pytest.mark.asyncio
async def test_body_and_event_reads_overlap_without_changing_decoded_block():
    port = FakePort()
    item = identity(40)
    add_block(port, item, [], [])
    expected = await scanner(port).decode_block_commitments(item)
    body_started, events_started = asyncio.Event(), asyncio.Event()
    body_read, events_read = port.block_body_at, port.event_storage_at

    async def body(ref):
        body_started.set()
        await asyncio.wait_for(events_started.wait(), timeout=30)
        return await body_read(ref)

    async def events(ref, key):
        events_started.set()
        await asyncio.wait_for(body_started.wait(), timeout=30)
        return await events_read(ref, key)

    port.block_body_at, port.event_storage_at = body, events
    assert await scanner(port).decode_block_commitments(item) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["body", "events", "cancel"])
async def test_read_failure_or_cancellation_drains_sibling_before_releasing_provider(failure):
    port = FakePort()
    item = identity(40)
    add_block(port, item, [], [])
    started = {name: asyncio.Event() for name in ("body", "events")}
    cleaning = asyncio.Event()
    release = asyncio.Event()
    finished = set()

    async def read(name):
        started[name].set()
        other = "events" if name == "body" else "body"
        try:
            await started[other].wait()
            if name == failure:
                raise OSError("transport unavailable")
            await asyncio.Event().wait()
        finally:
            if name != failure:
                cleaning.set()

                # Model owned thread/subprocess cleanup: cancelling its waiter
                # must not let the caller close the provider before it finishes.
                async def finish():
                    await release.wait()
                    finished.add(name)

                await await_owned_task(asyncio.create_task(finish()))

    async def body(ref):
        return await read("body")

    async def events(ref, key):
        return await read("events")

    port.block_body_at, port.event_storage_at = body, events
    operation = asyncio.create_task(scanner(port).decode_block_commitments(item))
    try:
        await asyncio.wait_for(started["body"].wait(), timeout=30)
        await asyncio.wait_for(started["events"].wait(), timeout=30)
        if failure == "cancel":
            operation.cancel()
        await asyncio.wait_for(cleaning.wait(), timeout=30)
        assert not operation.done()
        # A second caller cancellation must still leave cleanup owned.
        operation.cancel()
        await asyncio.sleep(0)
        assert not operation.done()
        release.set()
        expected = asyncio.CancelledError if failure == "cancel" else ValidatorChainScanError
        with pytest.raises(expected):
            await asyncio.wait_for(operation, timeout=30)
        assert finished == ({"body", "events"} - {failure})
    finally:
        release.set()
        if not operation.done():
            operation.cancel()
            await asyncio.gather(operation, return_exceptions=True)
