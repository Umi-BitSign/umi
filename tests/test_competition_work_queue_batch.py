from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from umi import competition_work_queue as queue_module
from umi.competition_work_plans import endpoint_proposals
from umi.competition_work_signing import WorkStatement, statement_slot
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_work_plans import two_endpoint_work
from .test_competition_work_queue import chain_config as chain_config
from .test_competition_work_queue import policy as policy
from .test_competition_work_queue import runtime as runtime
from .test_competition_work_queue import setup as queue_fixture
from .test_competition_work_queue import signing as signing
from .test_competition_work_queue import work as work

setup = queue_fixture


@pytest.fixture
def batch(setup):
    """Two real signed endpoint submissions, using the existing cutoff fixture."""
    work = two_endpoint_work(setup.work)
    setup.statements = tuple(
        WorkStatement(schema="umi-work-statement/1", plan=work.plan, body=body)
        for body in endpoint_proposals(**work.options)
    )
    assert len(setup.statements) == 2
    return setup


async def prepare(batch):
    await batch.queue.prepare(batch.work.plan, videos=batch.work.options["videos"])


def entries(batch):
    with batch.queue.journal.transaction() as db:
        return db.execute("SELECT slot,statement FROM work_index ORDER BY sequence").fetchall()


@pytest.mark.asyncio
@pytest.mark.parametrize("capacity", ["records", "bytes"])
async def test_capacity_failure_exposes_no_partial_endpoint_batch(batch, capacity):
    if capacity == "records":
        batch.queue.journal.maximum_rounds = 1
    else:
        size = sum(len(canonical_json_bytes(s)) for s in batch.statements)
        batch.queue.journal.maximum_bytes = len(canonical_json_bytes(batch.work.plan)) + size - 1
    with pytest.raises(ValueError, match="capacity exhausted"):
        await prepare(batch)
    assert batch.queue.journal.keys("intent") == []
    assert entries(batch) == []
    assert not list(Path(batch.arguments["publication_directory"]).glob("*.json"))


@pytest.mark.asyncio
async def test_later_statement_validation_failure_exposes_no_partial_batch(batch, monkeypatch):
    original = queue_module._StatementValidator.validate
    calls = 0

    def validate(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("injected second statement failure")
        return original(*args)

    monkeypatch.setattr(queue_module._StatementValidator, "validate", validate)
    with pytest.raises(ValueError, match="second statement failure"):
        await prepare(batch)
    assert batch.queue.journal.keys("intent") == []
    assert entries(batch) == []


@pytest.mark.asyncio
async def test_index_error_rolls_back_every_new_intent(batch):
    with batch.queue.journal.transaction() as db:
        db.execute(
            "CREATE TRIGGER fail_second_index BEFORE INSERT ON work_index "
            "WHEN (SELECT COUNT(*) FROM work_index) = 1 "
            "BEGIN SELECT RAISE(ABORT,'injected index failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected index failure"):
        await prepare(batch)
    assert batch.queue.journal.keys("intent") == []
    assert entries(batch) == []


@pytest.mark.asyncio
async def test_partial_legacy_batch_is_preserved_without_new_issuance(batch):
    first = batch.statements[0]
    batch.queue.journal.put(
        "work-plan", batch.work.plan.cutoff.publication.round.suite_sha256, batch.work.plan
    )
    batch.queue._retain(first)
    before = entries(batch)
    with pytest.raises(ValueError, match="partial endpoint batch"):
        await prepare(batch)
    assert batch.queue.journal.keys("intent") == [statement_slot(first)]
    assert entries(batch) == before
    assert not batch.queue.transport_provider.calls


@pytest.mark.asyncio
async def test_full_retry_repairs_indexes_without_new_issuance_or_bytes(batch):
    await prepare(batch)
    retained = {key: batch.queue.journal.get("intent", key) for key, _ in entries(batch)}
    with batch.queue.journal.transaction() as db:
        db.execute("DELETE FROM work_index")
    batch.clock.now += 60 * 60 * 1000
    batch.queue = queue_module.WorkQueue(**batch.arguments)
    await prepare(batch)
    assert {key: batch.queue.journal.get("intent", key) for key, _ in entries(batch)} == retained
    assert len(batch.queue.transport_provider.calls) == 2


@pytest.mark.asyncio
async def test_other_queue_writer_cannot_choose_a_second_window(batch):
    competing = queue_module.WorkQueue(**batch.arguments)
    original = batch.queue.transport_provider.verified_blocks
    started, release = asyncio.Event(), asyncio.Event()

    async def paused(heights=()):
        started.set()
        await release.wait()
        return await original(heights)

    batch.queue.transport_provider.verified_blocks = paused
    first = asyncio.create_task(prepare(batch))
    try:
        await asyncio.wait_for(started.wait(), 2)
        with pytest.raises(BlockingIOError):
            await asyncio.wait_for(
                competing.prepare(batch.work.plan, videos=batch.work.options["videos"]), 0.2
            )
    finally:
        release.set()
        await first
    assert len(entries(batch)) == 2


@pytest.mark.asyncio
async def test_discovery_from_another_instance_sees_no_incomplete_batch(batch):
    reader = queue_module.WorkQueue(**batch.arguments)
    original = batch.queue.provider.collect
    observations = []

    async def observe():
        observations.append(entries(batch))
        return await original()

    batch.queue.provider.collect = observe
    await prepare(batch)
    assert all(len(rows) in (0, 2) for rows in observations)
    _, pending = await reader.pending(batch.work.signers[0].hotkey.ss58_address)
    assert {digest(s) for s in pending} == {digest(s) for s in batch.statements}


@pytest.mark.asyncio
async def test_window_expiring_while_entering_retention_rolls_back_batch(batch, monkeypatch):
    original = batch.queue.journal.put_many

    def elapsed(records, *, index=None):
        def serialize_then_expire():
            yield from records
            if index is not None:
                batch.clock.now = queue_module.issue_close_ms(
                    batch.statements[0], batch.work.item.legacy_policy
                )

        return original(serialize_then_expire(), index=index)

    monkeypatch.setattr(batch.queue.journal, "put_many", elapsed)
    with pytest.raises(ValueError, match="elapsed during batch retention"):
        await prepare(batch)
    assert batch.queue.journal.keys("intent") == []
    assert entries(batch) == []


@pytest.mark.asyncio
async def test_slow_atomic_batch_preserves_its_fresh_initial_issuance(batch, monkeypatch):
    original = queue_module.endpoint_proposals
    observations = []

    def slow_construction(**kwargs):
        observations.append(kwargs["now_ms"])
        result = original(**kwargs)
        if len(observations) == 1:
            batch.clock.now += 70_000
        return result

    monkeypatch.setattr(queue_module, "endpoint_proposals", slow_construction)
    await prepare(batch)
    assert len(entries(batch)) == 2
    assert observations[0] == observations[1]
    for statement in batch.statements:
        assert batch.queue.journal.get("intent", statement_slot(statement)) == (
            statement.model_dump(mode="json", by_alias=True)
        )


@pytest.mark.asyncio
async def test_issuance_stale_before_batch_construction_is_still_rejected(batch, monkeypatch):
    original = batch.queue.journal.put_many

    def delayed_start(records, *, index=None):
        if index is not None:
            batch.clock.now += 70_000
        return original(records, index=index)

    monkeypatch.setattr(batch.queue.journal, "put_many", delayed_start)
    with pytest.raises(ValueError, match="issuance is not fresh"):
        await prepare(batch)
    assert batch.queue.journal.keys("intent") == []
    assert entries(batch) == []


@pytest.mark.asyncio
async def test_cancellation_during_issuance_releases_writer_lock(batch):
    original = batch.queue.transport_provider.verified_blocks
    started, release = asyncio.Event(), asyncio.Event()

    async def paused(heights=()):
        started.set()
        await release.wait()
        return await original(heights)

    batch.queue.transport_provider.verified_blocks = paused
    task = asyncio.create_task(prepare(batch))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert batch.queue.journal.keys("intent") == []
    assert entries(batch) == []
    batch.queue.transport_provider.verified_blocks = original
    batch.queue = queue_module.WorkQueue(**batch.arguments)
    await prepare(batch)
    assert len(entries(batch)) == 2


@pytest.mark.asyncio
async def test_retention_exact_byte_budget_succeeds(batch):
    budget = len(canonical_json_bytes(batch.work.plan)) + sum(
        len(canonical_json_bytes(s)) for s in batch.statements
    )
    batch.queue.journal.maximum_bytes = budget
    await prepare(batch)
    assert len(entries(batch)) == 2
    with batch.queue.journal.transaction() as db:
        assert db.execute("SELECT SUM(LENGTH(body)) FROM records").fetchone()[0] == budget


@pytest.mark.asyncio
async def test_retained_index_corruption_rolls_back_other_index_repairs(batch):
    await prepare(batch)
    first, second = entries(batch)
    with batch.queue.journal.transaction() as db:
        db.execute("DELETE FROM work_index WHERE slot=?", (first[0],))
        db.execute("UPDATE work_index SET closes=closes+1 WHERE slot=?", (second[0],))
    before = entries(batch)
    with pytest.raises(ValueError, match="index differs"):
        await prepare(batch)
    assert entries(batch) == before
    assert len(batch.queue.journal.keys("intent")) == 2
