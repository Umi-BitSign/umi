"""Native successful facts transfer; raw archives alone never authorize reuse."""

import hashlib
import threading
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_transfer as module
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
from umi.protocol import canonical_json_bytes

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay
from .test_competition_reward_history_origin_migration import original as original
from .test_competition_reward_history_origin_migration import selected as selected

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


@pytest.fixture
async def transfer_case(history_case, tmp_path, monkeypatch):
    h = history_case
    h.expected = await h.reader.advance(h.item.provider, through_block=h.end)
    h.source = h.reader
    h.source_inode = h.source.journal.path.stat().st_ino
    h.target_root = tmp_path / "target-history"

    def target():
        return RewardControlHistoryReader(
            h.target_root,
            control_hotkey=h.source.hotkey,
            chain_config_sha256=h.source.config_sha256,
            first_block=h.source.first_block,
        )

    h.target = target()
    h.reopen_target = target
    h.owner = SimpleNamespace(context_sha256="a" * 64, active=True)

    # Real lease construction/systemd refusal is qualified by the guarded owner
    # tests. This fixture replaces only that external authority, never native
    # proof verification, checkpoint loads, source identities or journal locks.
    def checked(owner, source, destination):
        if owner is not h.owner or not owner.active:
            raise ValueError("test owner is closed")
        if source is not h.source or destination.journal.root != h.target_root:
            raise ValueError("test owner selected other readers")
        if (source.hotkey, source.config_sha256, source.first_block) != (
            destination.hotkey,
            destination.config_sha256,
            destination.first_block,
        ) or source.checkpoints.semantics != destination.checkpoints.semantics:
            raise ValueError("history transfer reader context or verifier semantics differs")

    monkeypatch.setattr(module, "_check_owner", checked)
    h.options = {"first_block": h.source.first_block, "through_block": h.end}

    def transfer(**kwargs):
        return module.transfer_history_checkpoints(
            h.source, h.target, owner=h.owner, **(h.options | kwargs)
        )

    h.transfer = transfer
    return h


def records(journal):
    with journal.read_transaction() as db:
        return db.execute("SELECT kind,id,body FROM records ORDER BY kind,id").fetchall()


async def test_native_transfer_preserves_source_target_binding_restore_exports_and_restart(
    transfer_case, tmp_path, monkeypatch
):
    h = transfer_case
    original = records(h.source.journal)
    target_inode = h.target.journal.path.stat().st_ino
    samples = []
    result = h.transfer(progress=samples.append)
    assert result["status"] == "completed"
    assert result["transferred_blocks"] == h.end - h.source.first_block + 1
    assert result["copied_source_bytes"] > 0
    assert result["reused_source_records"] > 0
    assert result["chain_submission_authorized"] is False
    assert samples[-1]["status"] == "completed"
    assert samples[-1]["eta_seconds"] == 0
    assert samples[0]["planning_eta_seconds"]
    assert h.target.journal.path.stat().st_ino == target_inode
    assert h.source.journal.path.stat().st_ino == h.source_inode
    assert records(h.source.journal) == original
    assert h.target._next == h.source.first_block
    with pytest.raises(ValueError, match="not been natively verified"):
        await h.target.verified_prefix(h.end)
    archive = RewardProofArchive(tmp_path / "new-export")
    h.target.export_archive = archive
    prohibit_proof_replay(monkeypatch, h.target)
    assert await h.target.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.target.progress.native_completed == 0
    for height in range(h.source.first_block, h.end + 1):
        checkpoint = h.target.checkpoints.load(height)
        assert checkpoint["owner"] != h.source.checkpoints.owner
        assert checkpoint["exports"]
        _, fields = archive.read(
            "history",
            history_archive_key(h.target.config_sha256, h.target.hotkey, height),
            bounds={
                "slot_evidence": 64 * 1024**2,
                "slot_metadata": 16 * 1024**2,
                "evidence": 128 * 1024**2,
            },
        )
        assert hashlib.sha256(fields["evidence"]).hexdigest() == checkpoint["write_evidence_sha256"]
    h.target = h.reopen_target()
    h.target.export_archive = archive
    prohibit_proof_replay(monkeypatch, h.target)
    assert await h.target.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.transfer()["transferred_blocks"] == 0


async def test_source_mappings_reuse_shared_bytes_across_blocks_and_process_reopen(
    transfer_case, monkeypatch
):
    h = transfer_case
    calls = []
    read = h.source.journal.get_raw

    def counted(kind, key, **kwargs):
        if kind in module._PRIVATE_FIELDS:  # facts are metadata, not payloads
            pytest.fail("unexpected source kind")
        if kind in {"control_history_block", "control_history_chunk", "control_history_object"}:
            calls.append((kind, key))
        return read(kind, key, **kwargs)

    monkeypatch.setattr(h.source.journal, "get_raw", counted)
    result = h.transfer(maximum_blocks=1)
    assert result["transferred_blocks"] == 1
    first_calls = set(calls)
    h.target = h.reopen_target()
    while result["status"] != "completed":
        result = h.transfer(maximum_blocks=1)
        # The final bounded call can finish the full selected interval.
        if result["next_block"] == h.end + 1:
            break
    assert len(calls) == len(set(calls))
    assert first_calls < set(calls)
    calls.clear()
    assert h.transfer()["existing_blocks"] == h.end - h.source.first_block + 1
    assert calls == []


@pytest.mark.parametrize("when", ["after_sources", "after_intent", "after_checkpoint"])
async def test_interrupted_and_lost_acknowledgement_resume_without_payload_repeat(
    transfer_case, monkeypatch, when
):
    h = transfer_case
    options = {"through_block": h.source.first_block}
    with monkeypatch.context() as patch:
        if when == "after_sources":
            real = module._copy_sources

            def fail(*args):
                real(*args)
                raise OSError("lost acknowledgement")

            patch.setattr(module, "_copy_sources", fail)
        else:
            real = h.target.checkpoints.remember

            def fail(value):
                if when == "after_checkpoint":
                    real(value)
                raise OSError("lost acknowledgement")

            patch.setattr(h.target.checkpoints, "remember", fail)
        with pytest.raises(OSError, match="lost acknowledgement"):
            h.transfer(**options)
    h.target = h.reopen_target()
    real_read = h.source.journal.get_raw

    def no_sources(kind, key, **kwargs):
        if kind in {"control_history_block", "control_history_chunk", "control_history_object"}:
            pytest.fail("completed source copied again")
        return real_read(kind, key, **kwargs)

    monkeypatch.setattr(h.source.journal, "get_raw", no_sources)
    assert h.transfer(**options)["status"] == "completed"
    assert h.target.checkpoints.load(h.source.first_block)


async def test_stop_checkpoint_and_repeat_finish_original_work(transfer_case):
    h = transfer_case
    stop = threading.Event()
    events = []

    def observed(value):
        events.append(value)
        if value["completed_units"] == 1:
            stop.set()

    result = h.transfer(progress=observed, stop_requested=stop)
    assert result["transferred_blocks"] == 1
    assert result["status"] == "checkpointed"
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["status"] == "retrying"
    h.target = h.reopen_target()
    assert h.transfer()["status"] == "completed"


@pytest.mark.parametrize(
    "damage",
    ["source_token", "source_checkpoint", "source_gap", "closed_owner", "semantics", "alias"],
)
async def test_unsupported_or_damaged_source_refuses_without_target_changes(transfer_case, damage):
    h = transfer_case
    first = h.source.first_block
    before = records(h.target.journal)
    if damage == "closed_owner":
        h.owner.active = False
    elif damage == "semantics":
        h.target.checkpoints.semantics = "b" * 64
    elif damage == "alias":
        h.source.journal.put("control_history_remote_source", "irrelevant", {})
    else:
        with h.source.journal.transaction() as db:
            if damage == "source_token":
                db.execute(
                    "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                    (str(first),),
                )
            elif damage == "source_checkpoint":
                db.execute("DELETE FROM records WHERE kind='control_history_verified'")
            else:
                db.execute("DELETE FROM history_checkpoint_index WHERE height=?", (h.end,))
    with pytest.raises((ValueError, HistoryCheckpointRepairRequired)):
        h.transfer()
    assert records(h.target.journal) == before


@pytest.mark.parametrize(
    "damage", ["mapping", "done", "target_token", "source_token", "block", "missing_block"]
)
async def test_missing_or_changed_transfer_records_require_repair_without_payload_reads(
    transfer_case, monkeypatch, damage
):
    h = transfer_case
    first = h.source.first_block
    h.transfer(through_block=first)
    with h.target.journal.transaction() as db:
        if damage == "mapping":
            db.execute("DELETE FROM records WHERE kind=?", (module._MAP,))
        elif damage == "done":
            db.execute("DELETE FROM records WHERE kind=?", (module._MAP_DONE,))
        elif damage == "missing_block":
            db.execute("DELETE FROM records WHERE kind=?", (module._BLOCK,))
        elif damage == "target_token":
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(first),),
            )
        elif damage == "block":
            key, raw = db.execute(
                "SELECT id,body FROM records WHERE kind=? LIMIT 1", (module._BLOCK,)
            ).fetchone()
            import json

            value = json.loads(raw)
            value["target_success"] = "e" * 64
            db.execute(
                "UPDATE records SET body=? WHERE kind=? AND id=?",
                (canonical_json_bytes(value), module._BLOCK, key),
            )
    if damage == "source_token":
        with h.source.journal.transaction() as db:
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(first),),
            )
    real_read = h.source.journal.get_raw

    def no_sources(kind, key, **kwargs):
        if kind in {"control_history_block", "control_history_chunk", "control_history_object"}:
            pytest.fail("damaged transfer silently recopied payload")
        return real_read(kind, key, **kwargs)

    monkeypatch.setattr(h.source.journal, "get_raw", no_sources)
    with pytest.raises(HistoryCheckpointRepairRequired):
        h.transfer(through_block=first)


async def test_existing_native_overlap_preserved_and_disagreement_refused(transfer_case):
    h = transfer_case
    first = h.source.first_block
    await h.target.advance(h.item.provider, through_block=first)
    before = h.target.checkpoints.load(first)
    assert h.transfer()["existing_blocks"] == 1
    assert h.target.checkpoints.load(first) == before
    altered = {**before, "writes": [[0, "e" * 64]]}
    h.target.checkpoints.remember(altered, repair_reason="test deliberate differing facts")
    target_records = records(h.target.journal)
    with pytest.raises(HistoryCheckpointRepairRequired, match="different native facts"):
        h.transfer()
    assert records(h.target.journal) == target_records


async def test_existing_raw_conflict_is_not_overwritten_or_conflict_held(transfer_case):
    h = transfer_case
    token = h.source.checkpoints.load(h.source.first_block)["sources"][0]
    h.target.journal.put(token[0], token[1], {"conflict": True})
    before = records(h.target.journal)
    with pytest.raises(HistoryCheckpointRepairRequired, match="target source conflicts"):
        h.transfer()
    assert records(h.target.journal) == before
    with h.target.journal.read_transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM holds").fetchone() == (0,)


async def test_compound_lock_contention_refuses_without_changes(transfer_case):
    h = transfer_case
    before = records(h.target.journal)
    with h.source.journal.locked(), pytest.raises((BlockingIOError, ValueError)):
        h.transfer()
    assert records(h.target.journal) == before


async def test_aggregate_admission_interval_refused_before_mutation(transfer_case, monkeypatch):
    h = transfer_case
    before = records(h.target.journal)
    monkeypatch.setattr(
        h.source.completed_admission, "load", lambda: {"snapshot": {"block_number": h.end}}
    )
    with pytest.raises(ValueError, match="completed admission"):
        h.transfer()
    assert records(h.target.journal) == before


async def test_original_export_migration_provenance_survives_transfer_and_remains_required(
    selected, tmp_path, monkeypatch
):
    from umi import competition_reward_history_origin_migration as migration

    c, h = selected, selected.h
    c.running[0] = False
    migration.migrate_original_export_history(c.path, maximum_history_bytes=8 * 1024**2)
    source = h.new_reader()
    destination = tmp_path / "migrated-target"

    def target_reader():
        return RewardControlHistoryReader(
            destination,
            control_hotkey=source.hotkey,
            chain_config_sha256=source.config_sha256,
            first_block=source.first_block,
        )

    target = target_reader()
    owner = SimpleNamespace(context_sha256="c" * 64)

    def check(selected, a, b):
        assert selected is owner and a is source and b.journal.root == destination

    monkeypatch.setattr(module, "_check_owner", check)
    module.transfer_history_checkpoints(
        source,
        target,
        owner=owner,
        first_block=source.first_block,
        through_block=h.end,
    )
    for height in range(source.first_block, h.end + 1):
        assert (
            target.checkpoints.load(height)["repair"] == source.checkpoints.load(height)["repair"]
        )
    target = target_reader()
    prohibit_proof_replay(monkeypatch, target)
    assert (await target.advance(h.item.provider, through_block=h.end)).history == h.expected
    with target.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=?", (module._ORIGIN,))
    target = target_reader()
    with pytest.raises(HistoryCheckpointRepairRequired, match="damaged"):
        target.checkpoints.load(source.first_block)


async def test_source_mutation_during_record_commit_rolls_back_target_batch(
    transfer_case, monkeypatch
):
    h = transfer_case
    before = records(h.target.journal)
    put = h.target.journal.put_many

    def mutate(*args, **kwargs):
        with h.source.journal.transaction() as db:
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(h.source.first_block),),
            )
        return put(*args, **kwargs)

    monkeypatch.setattr(h.target.journal, "put_many", mutate)
    with pytest.raises(HistoryCheckpointRepairRequired, match="source changed"):
        h.transfer()
    assert records(h.target.journal) == before


async def materialized_case(h, tmp_path):
    h.transfer()
    h.target.export_archive = RewardProofArchive(tmp_path / "materialized-export")
    h.target.export_archive._ensure_root()
    for height in range(h.source.first_block, h.end + 1):
        await h.target._ensure_checkpoint_export(h.target.checkpoints.load(height))


async def test_materialization_terminal_binds_contiguous_source_target_exports_without_applying(
    transfer_case, tmp_path, monkeypatch
):
    h = transfer_case
    await materialized_case(h, tmp_path)
    source_bytes = h.source.journal.get_raw
    target_bytes = h.target.journal.get_raw

    def guarded(read):
        def run(kind, key, **kwargs):
            if kind in {"control_history_block", "control_history_chunk", "control_history_object"}:
                pytest.fail("materialization reread native proof bytes")
            return read(kind, key, **kwargs)

        return run

    monkeypatch.setattr(h.source.journal, "get_raw", guarded(source_bytes))
    monkeypatch.setattr(h.target.journal, "get_raw", guarded(target_bytes))
    events = []
    result = module.review_history_materialization(
        h.source,
        h.target,
        owner=h.owner,
        progress=events.append,
        **h.options,
    )
    total = h.end - h.source.first_block + 1
    assert result["schema"] == "umi-local-history-materialization/1"
    assert (
        result["checkpoint_blocks"]
        == result["source_complete_blocks"]
        == result["export_complete_blocks"]
        == total
    )
    assert result["newly_applied_blocks"] == 0
    assert result["applied_progress"] is None
    assert h.target._next == h.target.first_block
    assert result["source_owner"] == h.source.checkpoints.owner
    assert result["target_owner"] == h.target.checkpoints.owner
    assert result["journal_database"]["identity"]["ino"] == h.target.journal.path.stat().st_ino
    assert (
        result["source_journal_database"]["identity"]["ino"] == h.source.journal.path.stat().st_ino
    )
    assert result["target_export_identity"] == h.target._export_identity()
    assert result["ordered_restore_and_fresh_finality_required"]
    assert not result["chain_submission_authorized"]
    assert events[-1]["status"] == "completed"
    assert events[-1]["eta_seconds"] == 0
    assert (
        module.review_history_materialization(h.source, h.target, owner=h.owner, **h.options)
        == result
    )


@pytest.mark.parametrize(
    "damage", ["missing_checkpoint", "missing_export", "changed_source", "other_export"]
)
async def test_materialization_refuses_incomplete_or_changed_inventory(
    transfer_case, tmp_path, damage
):
    h = transfer_case
    await materialized_case(h, tmp_path)
    if damage == "missing_checkpoint":
        with h.target.journal.transaction() as db:
            db.execute("DELETE FROM history_checkpoint_index WHERE height=?", (h.end,))
    elif damage == "missing_export":
        value = h.target.checkpoints.load(h.end)
        h.target.checkpoints.remember(
            {**value, "exports": []}, repair_reason="fixture omitted export"
        )
    elif damage == "changed_source":
        with h.source.journal.transaction() as db:
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(h.end),),
            )
    else:
        h.target.export_archive = RewardProofArchive(tmp_path / "different-export")
        h.target.export_archive._ensure_root()
    with pytest.raises(HistoryCheckpointRepairRequired):
        module.review_history_materialization(h.source, h.target, owner=h.owner, **h.options)


@pytest.mark.parametrize("stop_at", ["first", "last"])
async def test_materialization_stop_emits_no_completed_terminal(transfer_case, tmp_path, stop_at):
    h = transfer_case
    await materialized_case(h, tmp_path)
    stop = threading.Event()
    events = []

    def progress(event):
        events.append(event)
        count = 1 if stop_at == "first" else h.end - h.source.first_block + 1
        if event["completed_units"] == count:
            stop.set()

    with pytest.raises(InterruptedError):
        module.review_history_materialization(
            h.source,
            h.target,
            owner=h.owner,
            stop_requested=stop,
            progress=progress,
            **h.options,
        )
    assert events[-1]["status"] == "retrying"
    assert not any(event["status"] == "completed" for event in events)
    assert h.target._next == h.target.first_block
