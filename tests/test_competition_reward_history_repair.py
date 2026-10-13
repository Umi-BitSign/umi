"""The production repair loop consumes native original history without reset."""

import asyncio

import pytest

from umi import competition_reward_history as history_module
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_history_repair import repair_history_scope
from umi.competition_reward_history_repair_journal import DONE, INTENT, RESULT, HistoryRepairRequest
from umi.private_files import PrivateStateBusyError

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


def raw_records(journal):
    with journal.read_transaction() as db:
        return db.execute(
            "SELECT kind,id,body FROM records WHERE kind IN "
            "('control_history_block','control_history_chunk','control_history_object') "
            "ORDER BY kind,id"
        ).fetchall()


@pytest.mark.parametrize("damage", ["missing", "malformed", "changed_source", "missing_index"])
async def test_operator_repair_loop_reuses_good_blocks_and_survives_retry_restart(
    history_case, monkeypatch, damage
):
    h = history_case
    expected = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    journal, affected = h.reader.journal, h.old.height + 1
    original, inode = raw_records(journal), journal.path.stat().st_ino
    with journal.transaction() as db:
        key = db.execute(
            "SELECT key FROM history_checkpoint_index WHERE height=?", (affected,)
        ).fetchone()[0]
        if damage == "missing":
            db.execute("DELETE FROM records WHERE kind='control_history_verified' AND id=?", (key,))
        elif damage == "malformed":
            db.execute(
                "UPDATE records SET body=? WHERE kind='control_history_verified' AND id=?",
                (b'{"damaged":true}', key),
            )
        elif damage == "missing_index":
            db.execute("DELETE FROM history_checkpoint_index WHERE height=?", (affected,))
        else:
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(affected),),
            )
    h.reader = await h.restart()
    native, calls = history_module.review_control_writes, []

    async def counted(*args, **kwargs):
        calls.append(1)
        return await native(*args, **kwargs)

    monkeypatch.setattr(history_module, "review_control_writes", counted)
    remember = h.reader.checkpoints.remember
    acknowledgements = []

    def lost_ack(value, **kwargs):
        remember(value, **kwargs)
        if value["snapshot"]["block_number"] == affected and not acknowledgements:
            acknowledgements.append(1)
            raise PrivateStateBusyError("private_file_lock", "aa" * 32, 11)

    monkeypatch.setattr(h.reader.checkpoints, "remember", lost_ack)
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        asyncio.Event(),
        through_block=h.end,
        reason="operator recovered original retained source",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    assert report["status"] == "history_repaired"
    assert report["percent"] == 100 and report["eta_seconds"] == 0
    assert calls == acknowledgements == [1]
    assert raw_records(journal) == original and journal.path.stat().st_ino == inode
    assert (await h.reader.verified_prefix(h.end)) == expected
    assert h.reader.checkpoints.load(affected)["repair"]["reason"] == (
        "operator recovered original retained source"
    )
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    repeated = await repair_history_scope(
        h.reader,
        h.item.provider,
        asyncio.Event(),
        through_block=h.end,
        reason="operator recovered original retained source",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    assert repeated["status"] == "history_repaired" and repeated["native_completed"] == 0
    assert repeated["restored_completed"] == h.end - h.old.height + 1


async def test_operator_repair_migrates_legacy_raw_journal_in_place(history_case, monkeypatch):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    journal = h.reader.journal
    original, inode = raw_records(journal), journal.path.stat().st_ino
    with journal.transaction() as db:
        for trigger in h.reader.checkpoints.triggers:
            db.execute("DROP TRIGGER " + trigger)
        for table in (
            "history_checkpoint_state",
            "history_checkpoint_index",
            "history_source_identity",
        ):
            db.execute("DROP TABLE " + table)
        db.execute(
            "DELETE FROM records WHERE kind IN "
            "('control_history_verified','control_history_checkpoint_owner',"
            "'control_history_checkpoint_repair','control_history_checkpoint_done')"
        )
    h.reader = await h.restart()
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        asyncio.Event(),
        through_block=h.end,
        reason="one native pass for original legacy retained history",
        maximum_blocks=2,
        poll_seconds=0.001,
    )
    assert report["status"] == "history_repaired"
    assert report["native_completed"] == h.end - h.old.height + 1
    assert raw_records(journal) == original and journal.path.stat().st_ino == inode
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history is not None


async def test_operator_repair_interrupts_between_batches_and_resumes_completed_facts(
    history_case, monkeypatch
):
    h, stop = history_case, asyncio.Event()
    native = h.reader.repair_checkpoints

    async def stop_after_batch(*args, **kwargs):
        result = await native(*args, **kwargs)
        stop.set()
        return result

    monkeypatch.setattr(h.reader, "repair_checkpoints", stop_after_batch)
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        stop,
        through_block=h.end,
        reason="operator resumed retained repair",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    assert report["status"] == "interrupted" and report["completed_blocks"] == 1
    saved = h.reader.checkpoints.load(h.old.height)
    h.reader = await h.restart()
    stop.clear()
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        stop,
        through_block=h.end,
        reason="operator resumed retained repair",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    assert report["status"] == "history_repaired" and report["restored_completed"] >= 1
    assert h.reader.checkpoints.load(h.old.height) == saved


async def test_durable_intent_survives_before_first_block_and_exact_repeat(
    history_case, monkeypatch
):
    h, stop = history_case, asyncio.Event()
    stop.set()
    inode = h.reader.journal.path.stat().st_ino
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        stop,
        through_block=h.end,
        reason="approved finite repair",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    key, journal = report["repair_request_sha256"], h.reader.journal
    assert report["status"] == "interrupted"
    intent = journal.get(INTENT, key)
    assert intent["through_block"] == h.end and intent["reason"] == "approved finite repair"
    assert intent["owner"] == h.reader.checkpoints.owner
    assert journal.get(RESULT, key) is None and not journal.keys("control_history_block")
    h.reader = await h.restart()
    stop.clear()
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        stop,
        through_block=h.end,
        reason="approved finite repair",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    assert report["repair_request_sha256"] == key and report["status"] == "history_repaired"
    result, done = journal.get(RESULT, key), journal.get(DONE, key)
    assert result["completed_blocks"] == h.end - h.old.height + 1
    assert result["request_sha256"] == key and result["tip"]["block_number"] == h.end
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    await repair_history_scope(
        h.reader,
        h.item.provider,
        stop,
        through_block=h.end,
        reason="approved finite repair",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    assert journal.keys(INTENT) == journal.keys(RESULT) == journal.keys(DONE) == [key]
    assert journal.get(INTENT, key) == intent and journal.get(RESULT, key) == result
    assert journal.get(DONE, key) == done and journal.path.stat().st_ino == inode


@pytest.mark.parametrize("kind", [INTENT, RESULT, DONE])
async def test_completed_repair_audit_loss_requires_original_metadata(history_case, kind):
    h = history_case
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        asyncio.Event(),
        through_block=h.end,
        reason="approved finite repair",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    key = report["repair_request_sha256"]
    with h.reader.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, key))
    with pytest.raises(HistoryCheckpointRepairRequired, match="metadata"):
        HistoryRepairRequest(h.reader, h.end, "approved finite repair")


async def test_lost_operation_acknowledgements_reuse_intent_and_native_results(
    history_case, monkeypatch
):
    h = history_case
    put = h.reader.journal.put

    def lost_intent_ack(kind, key, value):
        put(kind, key, value)
        if kind == INTENT:
            raise OSError("lost intent acknowledgement")

    monkeypatch.setattr(h.reader.journal, "put", lost_intent_ack)
    with pytest.raises(OSError, match="intent"):
        await repair_history_scope(
            h.reader,
            h.item.provider,
            asyncio.Event(),
            through_block=h.end,
            reason="approved finite repair",
            maximum_blocks=1,
            poll_seconds=0.001,
        )
    assert len(h.reader.journal.keys(INTENT)) == 1 and not h.reader.journal.keys(RESULT)
    h.reader = await h.restart()
    put_many = h.reader.journal.put_many

    def lost_result_ack(records, **kwargs):
        records = tuple(records)
        put_many(records, **kwargs)
        if any(kind == RESULT for kind, _, _ in records):
            raise OSError("lost result acknowledgement")

    monkeypatch.setattr(h.reader.journal, "put_many", lost_result_ack)
    with pytest.raises(OSError, match="result"):
        await repair_history_scope(
            h.reader,
            h.item.provider,
            asyncio.Event(),
            through_block=h.end,
            reason="approved finite repair",
            maximum_blocks=1,
            poll_seconds=0.001,
        )
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    report = await repair_history_scope(
        h.reader,
        h.item.provider,
        asyncio.Event(),
        through_block=h.end,
        reason="approved finite repair",
        maximum_blocks=1,
        poll_seconds=0.001,
    )
    assert report["status"] == "history_repaired" and report["native_completed"] == 0
