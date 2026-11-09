"""Bounded reads own their bytes and threads through gaps, errors and shutdown."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_parallel as parallel


def reader_for(load, *, budget=200, checkpoint=lambda height: None):
    reader = SimpleNamespace(
        checkpoints=SimpleNamespace(load=checkpoint),
        archive=None,
        verification_profile=SimpleNamespace(maximum_in_flight_bytes=budget),
        _source_tokens={},
        _prepared_encodings={},
        progress=SimpleNamespace(
            preparation_start=lambda *args: None,
            report=lambda *args: None,
        ),
    )

    def retained(height):
        value = load(height)
        if value is not None:
            reader._source_tokens[height] = [height]
            reader._prepared_encodings[height] = value
        return value

    reader._load = retained
    return reader


@pytest.mark.parametrize("size, expected_count", [(60, 2), (10, 4)])
async def test_in_flight_reservations_and_completed_frames_share_one_budget(
    monkeypatch, size, expected_count
):
    monkeypatch.setattr(parallel, "MAX_FRAME_BYTES", 100)
    barrier = threading.Barrier(2, timeout=3)
    lock = threading.Lock()
    active, resident, peak, requested = 0, 0, 0, []

    def load(height):
        nonlocal active, resident, peak
        with lock:
            active += 1
            peak = max(peak, active)
            requested.append(height)
            assert resident + active * 100 <= 200
        if height < 12:
            barrier.wait()
        with lock:
            active -= 1
            resident += size
        return {"proof": b"x" * size}

    reader = reader_for(load)
    loaded = []
    async with parallel._FrameInputs(reader, asyncio.Event(), 10, 13) as inputs:
        for height in range(10, 14):
            _, fields, _ = await inputs.take(height)
            if fields is None:
                break
            loaded.append(height)
    assert peak == 2
    assert loaded == list(range(10, 10 + expected_count))
    assert sorted(requested) == loaded


@pytest.mark.parametrize("boundary", ["gap", "checkpoint", "failure"])
async def test_boundary_drains_later_read_and_releases_unconsumed_encodings(monkeypatch, boundary):
    monkeypatch.setattr(parallel, "MAX_FRAME_BYTES", 100)
    loop = asyncio.get_running_loop()
    started, release = asyncio.Event(), threading.Event()
    requested = []

    def load(height):
        requested.append(height)
        if height == 10:
            if boundary == "failure":
                raise OSError("selected retained input failed")
            return None
        loop.call_soon_threadsafe(started.set)
        assert release.wait(3)
        return {"proof": b"later"}

    receipt = {"already_verified": 10}
    reader = reader_for(
        load,
        checkpoint=lambda height: receipt if height == 10 and boundary == "checkpoint" else None,
    )

    async def consume():
        async with parallel._FrameInputs(reader, asyncio.Event(), 10, 13) as inputs:
            return await inputs.take(10)

    task = asyncio.create_task(consume())
    try:
        await asyncio.wait_for(started.wait(), 3)
        assert not task.done()
    finally:
        release.set()
    if boundary == "failure":
        with pytest.raises(OSError, match="selected retained input failed"):
            await task
    else:
        result = await task
        assert result[0] == (receipt if boundary == "checkpoint" else None)
        assert result[1] is None
    assert sorted(requested) == ([11] if boundary == "checkpoint" else [10, 11])
    assert not reader._prepared_encodings and not reader._source_tokens


async def test_repeated_cancellation_before_first_result_drains_all_reads(monkeypatch):
    monkeypatch.setattr(parallel, "MAX_FRAME_BYTES", 100)
    loop = asyncio.get_running_loop()
    started = [asyncio.Event(), asyncio.Event()]
    release = threading.Event()
    finished = []

    def load(height):
        loop.call_soon_threadsafe(started[height - 10].set)
        assert release.wait(3)
        finished.append(height)
        return {"proof": b"unconsumed"}

    reader = reader_for(load)
    stop = asyncio.Event()

    async def consume():
        async with parallel._FrameInputs(reader, stop, 10, 13) as inputs:
            return await inputs.take(10)

    task = asyncio.create_task(consume())
    try:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started)), 3)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert stop.is_set() and not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert sorted(finished) == [10, 11]
    assert not reader._prepared_encodings and not reader._source_tokens


async def test_stop_before_admission_does_not_read_checkpoints_or_payloads(monkeypatch):
    monkeypatch.setattr(parallel, "MAX_FRAME_BYTES", 100)

    def forbidden(height):
        pytest.fail("shutdown admitted a new read")

    reader = reader_for(forbidden, checkpoint=forbidden)
    stop = asyncio.Event()
    stop.set()
    async with parallel._FrameInputs(reader, stop, 10, 13) as inputs:
        assert await inputs.take(10) == (None, None, False)


async def test_background_read_does_not_replace_owned_header_progress(monkeypatch):
    monkeypatch.setattr(parallel, "MAX_FRAME_BYTES", 100)
    loop = asyncio.get_running_loop()
    later, release = asyncio.Event(), threading.Event()
    reports = []

    def load(height):
        if height == 11:
            loop.call_soon_threadsafe(later.set)
            assert release.wait(3)
        return {"proof": b"frame"}

    reader = reader_for(load)
    reader.progress.preparation_start = lambda *args: reports.append(args)
    async with parallel._FrameInputs(reader, asyncio.Event(), 10, 11) as inputs:
        try:
            assert (await inputs.take(10))[1] is not None
            await asyncio.wait_for(later.wait(), 3)
            reader.progress.preparation_start("owned_history_header_resolution", 10, "ancestry")
        finally:
            release.set()
    assert [report[0] for report in reports] == [
        "retained_history_loading",
        "owned_history_header_resolution",
    ]
    assert set(reader._prepared_encodings) == {10}
    assert set(reader._source_tokens) == {10}
