"""Scheduling uses a real private cursor/lease; service and chain ports are fixtures."""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_cohort_service_worker import ServiceWorkWorker
from umi.competition_round_journal import RoundJournal
from umi.private_files import lock_private_file

HOTKEYS = (
    "5C5hoeGp5j8hm4RXDvV3mZUj8dnwjZKjF1gHt8eWguMmkAQF",
    "5C7X1gViYuRXY3sMXtHGNJQ8dKRiznmzQSicyYwaRuRcDoVw",
    "5CALdJkFkieqqAupURM9LAAft5GeCyPBx53kD4vSTdxYECir",
)


def scheduler(tmp_path, *, miners=(0, 1, 2), concurrency=2, batch_size=2):
    worker = object.__new__(ServiceWorkWorker)
    worker.journal = RoundJournal(
        tmp_path / "queue",
        {"fixture": "service-scheduler"},
        maximum_rounds=64,
        maximum_bytes=1024**2,
        maximum_record_bytes=4096,
    )
    with worker.journal.transaction() as db:
        db.execute(
            "CREATE TABLE service_worker_cursor "
            "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), ordinal INTEGER NOT NULL)"
        )
    rows = tuple(
        SimpleNamespace(
            ordinal=i + 1,
            work_sha256=f"{i + 1:064x}",
            claim=SimpleNamespace(claim=SimpleNamespace(hotkey=HOTKEYS[m])),
        )
        for i, m in enumerate(miners)
    )
    worker.queue = SimpleNamespace(
        entries=lambda *, after_ordinal=0, limit=16: [r for r in rows if r.ordinal > after_ordinal][
            :limit
        ]
    )
    worker.batch_size, worker.concurrency = batch_size, concurrency
    worker.capacity, worker.serial = asyncio.Semaphore(concurrency), asyncio.Lock()
    worker._operation_stages = {}
    worker._operation_lanes = {}
    worker._ready_stage = lambda _: "dispatch"
    worker.transport = SimpleNamespace(timeout=30)
    return worker, rows


async def test_ready_service_crosses_batch_boundary_while_first_miner_waits(tmp_path):
    worker, _rows = scheduler(tmp_path)
    entered, third, release, stop = (asyncio.Event() for _ in range(4))
    seen = []

    async def advance(row, **kwargs):
        seen.append(row.ordinal)
        if row.ordinal == 1:
            entered.set()
            await release.wait()
        if row.ordinal == 3:
            third.set()
        return "completed", "fixture_terminal"

    worker._advance = advance
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01))
    try:
        await asyncio.wait_for(entered.wait(), 15)
        await asyncio.wait_for(third.wait(), 15)
        assert not release.is_set() and {1, 2, 3} <= set(seen)
    finally:
        stop.set()
        release.set()
        await asyncio.wait_for(task, 15)


async def test_service_serializes_one_miner_without_blocking_other_miners(tmp_path):
    worker, _rows = scheduler(tmp_path, miners=(0, 0, 1, 2))
    entered, other, release, stop = (asyncio.Event() for _ in range(4))
    same_miner = 0
    maximum_same_miner = 0

    async def advance(row, **kwargs):
        nonlocal same_miner, maximum_same_miner
        if row.ordinal <= 2:
            same_miner += 1
            maximum_same_miner = max(maximum_same_miner, same_miner)
            try:
                entered.set()
                await release.wait()
            finally:
                same_miner -= 1
        else:
            other.set()
        return "completed", "fixture_terminal"

    worker._advance = advance
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01))
    try:
        await asyncio.wait_for(entered.wait(), 15)
        await asyncio.wait_for(other.wait(), 15)
        assert maximum_same_miner == 1 and not release.is_set()
    finally:
        stop.set()
        release.set()
        await asyncio.wait_for(task, 15)


async def test_service_cursor_keeps_unstarted_work_and_recovers_after_restart(tmp_path):
    worker, _rows = scheduler(tmp_path, batch_size=3, concurrency=1)
    entered, release = asyncio.Event(), asyncio.Event()

    async def waiting(row, **kwargs):
        entered.set()
        await release.wait()
        return "completed", "fixture_terminal"

    worker._advance = waiting
    active = {}
    await worker._rolling_poll(active)
    await asyncio.wait_for(entered.wait(), 15)
    with worker.journal.transaction() as db:
        assert db.execute("SELECT ordinal FROM service_worker_cursor").fetchone() == (3,)
    await worker._stop_tasks(task for _, task in active.values())
    # Capacity-blocked rows remain accepted; restart rotates through all original rows.
    restarted = object.__new__(ServiceWorkWorker)
    restarted.journal, restarted.queue = worker.journal, worker.queue
    restarted.batch_size = worker.batch_size
    assert [row.ordinal for row in restarted._batch()] == [1, 2, 3]


async def test_service_run_drains_repeated_cancellation_before_releasing_lease(tmp_path):
    import os

    worker, _rows = scheduler(tmp_path)
    entered, cleaning, release = (asyncio.Event() for _ in range(3))

    async def waiting(row, **kwargs):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()

    worker._advance = waiting
    task = asyncio.create_task(worker.run(asyncio.Event(), poll_seconds=0.01))
    await asyncio.wait_for(entered.wait(), 15)
    task.cancel()
    await asyncio.wait_for(cleaning.wait(), 15)
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(BlockingIOError):
        lock_private_file(worker.journal.root / "service-worker.lock")
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 15)
    lease = lock_private_file(worker.journal.root / "service-worker.lock")
    os.close(lease)


async def test_service_rolling_reports_retry_without_secret_exception_text(tmp_path):
    worker, _rows = scheduler(tmp_path)

    async def failing(row, **kwargs):
        raise OSError("https://private.example/?token=private-capability")

    worker._advance = failing
    active = {}
    await worker._rolling_poll(active)
    await asyncio.gather(*(task for _, task in active.values()))
    report = await worker._rolling_poll(active)
    try:
        assert report["work_pending"] == report["retry_count"] == 2
        assert report["work_complete"] == 0
        assert report["last_retry_details"][0]["reason_code"] == "os_error"
        assert "private" not in str(report)
        assert not report["request_closure_authorized"]
        assert not report["chain_submission_authorized"]
    finally:
        await worker._stop_tasks(task for _, task in active.values())
