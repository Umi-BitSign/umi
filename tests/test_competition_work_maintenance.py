from __future__ import annotations

import pytest

from umi import competition_work_queue as queue_module
from umi.competition_work_signing import WorkEndorsement, statement_slot
from umi.open_competition import digest, sign_object

from .test_competition_work_queue_batch import batch as batch
from .test_competition_work_queue_batch import chain_config as chain_config
from .test_competition_work_queue_batch import entries
from .test_competition_work_queue_batch import policy as policy
from .test_competition_work_queue_batch import runtime as runtime
from .test_competition_work_queue_batch import setup as setup
from .test_competition_work_queue_batch import signing as signing
from .test_competition_work_queue_batch import work as work


async def maintain(batch):
    await batch.queue.maintain(batch.work.plan, videos=batch.work.options["videos"])


@pytest.mark.asyncio
async def test_recurring_maintenance_does_not_repeat_whole_batch_recovery(batch, monkeypatch):
    await maintain(batch)
    before = entries(batch)

    def no_full_recovery(*args, **kwargs):
        pytest.fail("periodic maintenance repeated full-batch recovery")

    monkeypatch.setattr(batch.queue, "_retained_endpoints", no_full_recovery)
    for _ in range(3):
        await maintain(batch)
    assert entries(batch) == before


@pytest.mark.asyncio
async def test_reopen_checks_the_complete_batch_and_preserves_issuance(batch, monkeypatch):
    await maintain(batch)
    before = entries(batch)
    batch.queue = queue_module.WorkQueue(**batch.arguments)
    calls = []
    original = batch.queue._retained_endpoints

    def recover(plan):
        calls.append(1)
        return original(plan)

    monkeypatch.setattr(batch.queue, "_retained_endpoints", recover)
    await maintain(batch)
    assert calls == [1]
    assert entries(batch) == before


@pytest.mark.asyncio
async def test_maintenance_repairs_indexes_without_reissuing(batch):
    await maintain(batch)
    before = {slot: body for slot, body in entries(batch)}
    with batch.queue.journal.transaction() as db:
        db.execute("DELETE FROM work_index")
    await maintain(batch)
    assert dict(entries(batch)) == before


@pytest.mark.asyncio
async def test_maintenance_recovers_retained_quorum_after_interrupted_delivery(batch):
    await maintain(batch)
    statement = batch.statements[0]
    for signer in batch.work.signers:
        vote = WorkEndorsement(
            statement_sha256=digest(statement), signature=sign_object(statement.body, signer)
        )
        value, checked, key = batch.queue._verified_vote(vote)
        batch.queue._retain_vote(value, checked, key, batch.provider.block)
    assert not tuple(batch.queue.publication_directory.iterdir())
    await maintain(batch)
    assert len(tuple(batch.queue.publication_directory.glob("*.json"))) == 1
    # The endpoint order now exists, but still needs its own quorum.
    assert len(entries(batch)) == 3
    assert not tuple(batch.queue.order_directory.iterdir())
    before = {p.name: p.read_bytes() for p in batch.queue.publication_directory.glob("*.json")}
    await maintain(batch)
    assert before == {
        p.name: p.read_bytes() for p in batch.queue.publication_directory.glob("*.json")
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing", "body", "index"])
async def test_maintenance_revalidates_retained_state(batch, damage):
    await maintain(batch)
    slot = statement_slot(batch.statements[0])
    with batch.queue.journal.transaction() as db:
        if damage == "missing":
            db.execute("DELETE FROM records WHERE kind='intent' AND id=?", (slot,))
        elif damage == "body":
            db.execute("UPDATE records SET body=? WHERE kind='intent' AND id=?", (b"{}", slot))
        else:
            db.execute("UPDATE work_index SET statement=? WHERE slot=?", ("ee" * 32, slot))
    with pytest.raises(ValueError):
        await maintain(batch)
    assert not tuple(batch.queue.publication_directory.iterdir())


@pytest.mark.asyncio
async def test_maintenance_respects_original_issue_deadline(batch):
    await maintain(batch)
    statement = batch.statements[0]
    for signer in batch.work.signers:
        vote = WorkEndorsement(
            statement_sha256=digest(statement), signature=sign_object(statement.body, signer)
        )
        value, checked, key = batch.queue._verified_vote(vote)
        batch.queue._retain_vote(value, checked, key, batch.provider.block)
    batch.clock.now = queue_module.issue_close_ms(statement, batch.work.item.legacy_policy)
    await maintain(batch)
    assert not tuple(batch.queue.publication_directory.iterdir())
