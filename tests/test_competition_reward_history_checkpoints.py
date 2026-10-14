"""Native success survives restart; broken completed work needs explicit repair."""

import asyncio
import logging
import sqlite3
import threading

import pytest

from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.private_files import PrivateStateBusyError

from .logging_helpers import progress_payloads
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_completed_benchmark_target_extends_after_restart_without_rechecking_prefix(
    history_case, monkeypatch
):
    h = history_case
    sample_end = h.old.height + 1
    completed = (await h.reader.advance(h.item.provider, through_block=sample_end)).history
    assert completed is not None
    owner, inode = h.reader.checkpoints.owner, h.reader.journal.path.stat().st_ino
    retained = {
        height: h.reader.checkpoints.load(height) for height in range(h.old.height, sample_end + 1)
    }
    h.offline_through = sample_end
    h.reader = await h.restart()
    load = h.reader._load

    def new_sources_only(height):
        if height <= sample_end:
            pytest.fail("completed benchmark payload was reread")
        return load(height)

    monkeypatch.setattr(h.reader, "_load", new_sources_only)
    h.body_requests.clear()
    result = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    assert result is not None and result.tip.block_number == h.end
    assert await h.reader.verified_prefix(sample_end) == completed
    assert h.reader.checkpoints.owner == owner
    assert h.reader.journal.path.stat().st_ino == inode
    assert all(h.reader.checkpoints.load(height) == saved for height, saved in retained.items())
    assert h.body_requests == list(range(sample_end + 1, h.end + 1))


@pytest.mark.usefixtures("http_log_redaction")
@pytest.mark.parametrize("damage", ["table", "counter", "trigger"])
async def test_capacity_repair_preserves_verified_history_and_repeat_reuses_metadata(
    history_case, monkeypatch, caplog, damage
):
    from umi.competition_reward_history import RewardControlHistoryReader
    from umi.competition_round_journal import RoundCapacityRepairRequired

    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    journal = h.reader.journal
    with journal.read_transaction() as db:
        records = db.execute("SELECT * FROM records ORDER BY kind,id").fetchall()
    inode = journal.path.stat().st_ino
    with sqlite3.connect(journal.path) as db:
        db.execute(
            {
                "table": "DROP TABLE round_record_capacity_kinds",
                "counter": "UPDATE round_record_capacity SET number=number+1",
                "trigger": "DROP TRIGGER round_record_capacity_insert",
            }[damage]
        )

    def reopen(*, repair=False):
        return RewardControlHistoryReader(
            journal.root,
            control_hotkey=h.reader.hotkey,
            chain_config_sha256=h.reader.config_sha256,
            first_block=h.reader.first_block,
            maximum_bytes=journal.maximum_bytes,
            repair_record_capacity=repair,
        )

    with pytest.raises(RoundCapacityRepairRequired):
        reopen()
    caplog.set_level(logging.INFO, logger="umi.competition_round_journal")
    h.reader = reopen(repair=True)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.native_completed == 0
    assert journal.path.stat().st_ino == inode
    with h.reader.journal.read_transaction() as db:
        assert db.execute("SELECT * FROM records ORDER BY kind,id").fetchall() == records
    assert any(
        event["state"] == "completed"
        for event in progress_payloads(
            caplog.records, logger="umi.competition_round_journal", event="round_journal_progress"
        )
    )
    caplog.clear()
    h.reader = reopen(repair=True)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert not progress_payloads(
        caplog.records, logger="umi.competition_round_journal", event="round_journal_progress"
    )


def prohibit_proof_replay(monkeypatch, reader):
    from umi import competition_reward_history as module

    def forbidden(*args, **kwargs):
        raise AssertionError("completed history proof was replayed")

    monkeypatch.setattr(reader, "_load", forbidden)
    monkeypatch.setattr(module, "review_control_writes", forbidden)
    monkeypatch.setattr(module, "capture_control_writes", forbidden)


async def test_larger_capacity_restart_preserves_native_results_without_proof_reads(
    history_case, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    journal, owner = h.reader.journal, h.reader.checkpoints.owner
    inode = journal.path.stat().st_ino
    with journal.read_transaction() as db:
        binding = db.execute("SELECT body FROM binding").fetchall()
        records = db.execute("SELECT kind,id,body FROM records ORDER BY kind,id").fetchall()
    h.offline_through = h.end
    for _ in range(2):
        h.reader = h.new_reader(maximum_bytes=64 * 1024**3)
        prohibit_proof_replay(monkeypatch, h.reader)
        assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
        assert h.reader.progress.native_completed == 0
        assert h.reader.checkpoints.owner == owner
        assert h.reader.journal.path.stat().st_ino == inode
        assert h.reader.journal.maximum_bytes == 64 * 1024**3
        with h.reader.journal.read_transaction() as db:
            assert db.execute("SELECT body FROM binding").fetchall() == binding
            assert (
                db.execute("SELECT kind,id,body FROM records ORDER BY kind,id").fetchall()
                == records
            )


async def test_completed_restart_uses_only_compact_results_and_current_finality(
    history_case, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    prefix = await h.reader.verified_prefix(h.old.height + 1)
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    resolve = h.item.provider._resolve_control_header
    tips = []

    async def counted(ref, encoded):
        tips.append(ref.block_number)
        return await resolve(ref, encoded)

    monkeypatch.setattr(h.item.provider, "_resolve_control_header", counted)
    h.rpc_calls.clear()
    actual = await h.reader.advance(h.item.provider, through_block=h.end)
    assert actual == expected
    assert await h.reader.verified_prefix(h.old.height + 1) == prefix
    assert h.reader.progress.native_completed == 0
    assert h.reader.progress.restored_completed == h.end - h.old.height + 1
    assert h.reader.progress.latest["percent"] == 100
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}
    assert tips == [h.end]


@pytest.mark.parametrize("damage", ["missing", "malformed", "changed_source", "missing_index"])
async def test_damaged_completed_result_requires_scoped_repair(history_case, monkeypatch, damage):
    from umi import competition_reward_history as module

    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    affected = h.old.height + 1
    journal = h.reader.journal
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
            # Even unchanged-length updates acquire a new mutation identity.
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(affected),),
            )
    h.reader = await h.restart()
    with pytest.raises(HistoryCheckpointRepairRequired):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader.progress.latest["state"] == "repair_required"
    assert h.reader.progress.latest["eta_seconds"] is None
    native = module.review_control_writes
    calls = []

    async def counted(provider, **kwargs):
        calls.append(1)
        return await native(provider, **kwargs)

    monkeypatch.setattr(module, "review_control_writes", counted)
    result = await h.reader.repair_checkpoints(
        h.item.provider, through_block=h.end, reason="test scoped retained repair"
    )
    assert result == expected
    assert len(calls) == 1
    assert h.reader.checkpoints.load(affected)["repair"]["reason"] == "test scoped retained repair"
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected


async def test_legacy_raw_first_pass_is_checkpointed_without_rewriting_evidence(
    history_case, monkeypatch
):
    from umi import competition_reward_history as module

    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    journal = h.reader.journal
    with journal.transaction() as db:
        original = db.execute(
            "SELECT kind,id,body FROM records WHERE kind IN "
            "('control_history_block','control_history_chunk','control_history_object') ORDER "
            "BY kind,id"
        ).fetchall()
        for name in h.reader.checkpoints.triggers:
            db.execute("DROP TRIGGER " + name)
        for name in (
            "history_checkpoint_state",
            "history_checkpoint_index",
            "history_source_identity",
        ):
            db.execute("DROP TABLE " + name)
        db.execute(
            "DELETE FROM records WHERE kind IN "
            "('control_history_verified','control_history_checkpoint_owner',"
            "'control_history_checkpoint_repair','control_history_checkpoint_done')"
        )
    inode = journal.path.stat().st_ino
    h.reader = await h.restart()
    native = module.review_control_writes
    calls = []

    async def counted(*args, **kwargs):
        calls.append(1)
        return await native(*args, **kwargs)

    monkeypatch.setattr(module, "review_control_writes", counted)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert len(calls) == h.end - h.old.height + 1
    with journal.read_transaction() as db:
        assert (
            db.execute(
                "SELECT kind,id,body FROM records WHERE kind IN "
                "('control_history_block','control_history_chunk','control_history_object') "
                "ORDER BY kind,id"
            ).fetchall()
            == original
        )
    assert journal.path.stat().st_ino == inode
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected


@pytest.mark.usefixtures("http_log_redaction")
async def test_missing_metadata_is_not_a_new_legacy_journal(history_case, caplog):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    with h.reader.journal.transaction() as db:
        for name in h.reader.checkpoints.triggers:
            db.execute("DROP TRIGGER " + name)
        for name in (
            "history_checkpoint_state",
            "history_checkpoint_index",
            "history_source_identity",
        ):
            db.execute("DROP TABLE " + name)
    with (
        caplog.at_level("INFO"),
        pytest.raises(HistoryCheckpointRepairRequired, match="metadata lost"),
    ):
        await h.restart()
    events = progress_payloads(
        caplog.records,
        logger="umi.competition_reward_history_checkpoint",
        event="reward_history_progress",
    )
    assert events
    event = events[-1]
    assert event["state"] == "repair_required"
    assert event["eta_seconds"] is None and event["percent"] is None


async def test_export_failure_does_not_repeat_successful_native_verification(
    history_case, monkeypatch, tmp_path
):
    from umi import competition_reward_history as module

    h = history_case
    export = RewardProofArchive(tmp_path / "export")
    h.reader.export_archive = export

    def fail(*args):
        raise OSError("export offline")

    monkeypatch.setattr(h.reader, "_export", fail)
    with pytest.raises(OSError, match="export offline"):
        await h.reader.advance(h.item.provider, through_block=h.old.height)
    assert h.reader.checkpoints.load(h.old.height) is not None
    h.reader = await h.restart()
    h.reader.export_archive = export

    def forbidden(*args, **kwargs):
        raise AssertionError("native proof repeated after downstream export error")

    monkeypatch.setattr(module, "review_control_writes", forbidden)
    monkeypatch.setattr(module, "capture_control_writes", forbidden)
    assert (await h.reader.advance(h.item.provider, through_block=h.old.height)).history is not None
    assert h.reader.checkpoints.load(h.old.height)["exports"]


async def test_lost_checkpoint_acknowledgement_restores_without_native_replay(
    history_case, monkeypatch
):
    h = history_case
    remember = h.reader.checkpoints.remember

    def lost_ack(*args, **kwargs):
        remember(*args, **kwargs)
        raise OSError("lost checkpoint acknowledgement")

    monkeypatch.setattr(h.reader.checkpoints, "remember", lost_ack)
    with pytest.raises(OSError, match="lost checkpoint acknowledgement"):
        await h.reader.advance(h.item.provider, through_block=h.old.height)
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (await h.reader.advance(h.item.provider, through_block=h.old.height)).history is not None


async def test_archive_lock_contention_preserves_successful_prefetched_block(
    history_case, monkeypatch, tmp_path
):
    from umi import competition_reward_history as module

    h = history_case
    first = h.old.height
    export = RewardProofArchive(tmp_path / "contended-export")
    h.reader.export_archive = export

    def busy(*args):
        raise PrivateStateBusyError("archive object publication", "ab" * 32, 11)

    monkeypatch.setattr(h.reader, "_export", busy)
    with pytest.raises(PrivateStateBusyError):
        await h.reader.advance(h.item.provider, through_block=first + 1)
    assert h.reader._next == first
    for height in (first, first + 1):
        assert h.reader.checkpoints.load(height) is not None
    h.reader = await h.restart()
    h.reader.export_archive = export

    def forbidden(*args, **kwargs):
        raise AssertionError("completed prefetched proof was replayed")

    monkeypatch.setattr(module, "capture_control_writes", forbidden)
    monkeypatch.setattr(module, "review_control_writes", forbidden)
    result = await h.reader.advance(h.item.provider, through_block=first + 1)
    assert result.history is not None
    assert h.reader.progress.restored_completed == 2


async def test_cancellation_during_save_finishes_native_checkpoint_before_releasing_owner(
    history_case, monkeypatch
):
    h = history_case
    entered = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    save = h.reader._save

    def blocked(observation):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(10)
        save(observation)

    monkeypatch.setattr(h.reader, "_save", blocked)
    task = asyncio.create_task(h.reader.advance(h.item.provider, through_block=h.old.height))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert h.reader._next == h.old.height
    assert h.reader.checkpoints.load(h.old.height) is not None
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (await h.reader.advance(h.item.provider, through_block=h.old.height)).history is not None


async def test_lost_save_acknowledgement_keeps_native_result(history_case, monkeypatch):
    h = history_case
    save = h.reader._save

    def lost_ack(observation):
        save(observation)
        raise OSError("lost save acknowledgement")

    monkeypatch.setattr(h.reader, "_save", lost_ack)
    with pytest.raises(OSError, match="lost save acknowledgement"):
        await h.reader.advance(h.item.provider, through_block=h.old.height)
    assert h.reader.checkpoints.load(h.old.height) is not None
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (await h.reader.advance(h.item.provider, through_block=h.old.height)).history is not None


async def test_out_of_order_success_does_not_claim_missing_predecessor_completed(
    history_case, monkeypatch
):
    h = history_case
    first = h.old.height
    save = h.reader._save

    def fail_predecessor(observation):
        if observation.slot.snapshot.block_number == first:
            raise OSError("predecessor storage unavailable")
        save(observation)

    monkeypatch.setattr(h.reader, "_save", fail_predecessor)
    with pytest.raises(OSError, match="predecessor storage unavailable"):
        await h.reader.advance(h.item.provider, through_block=first + 1)
    assert h.reader.checkpoints.load(first) is None
    assert h.reader.checkpoints.load(first + 1) is not None
    h.reader = await h.restart()
    assert (await h.reader.advance(h.item.provider, through_block=first + 1)).history is not None
    assert h.reader.progress.native_completed == 1
    assert h.reader.progress.restored_completed == 1
