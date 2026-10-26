"""Original native verdicts survive remote payload eviction, restart and repair."""

import asyncio
import json
import sqlite3
from contextlib import contextmanager
from threading import Barrier, Lock

import pytest

from umi.competition_history_source_externalization import (
    ALIAS_KIND,
    CAPTURE_SCHEMA,
    HEX_OBJECT_ENCODING,
    MARKER_TABLE,
)
from umi.competition_remote_proof_store import ProofArchiveR2Config, RemoteProofStore
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import SOURCE_KINDS, HistoryCheckpointRepairRequired
from umi.competition_reward_history_workers import HistoryVerificationProfile
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest

from .test_competition_remote_proof_store import EvidenceServer, config, store
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay
from .test_competition_reward_history_parallel import retained_parallel_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


def reopen(reader, remote, *, parallel=False, export_archive=None):
    return RewardControlHistoryReader(
        reader.journal.root,
        control_hotkey=reader.hotkey,
        chain_config_sha256=reader.config_sha256,
        first_block=reader.first_block,
        maximum_bytes=reader.journal.maximum_bytes,
        remote_store=remote,
        export_archive=export_archive,
        verification_profile=HistoryVerificationProfile(schema="umi-history-verification-profile/1")
        if parallel
        else None,
    )


def retained(journal):
    with journal.read_transaction() as db:
        return db.execute(
            "SELECT kind,id,body FROM records WHERE kind IN "
            "('control_history_verified','control_history_checkpoint_done') ORDER BY kind,id"
        ).fetchall()


def originals(journal):
    with journal.read_transaction() as db:
        return db.execute(
            "SELECT kind,id,body FROM records WHERE kind IN (?,?,?) ORDER BY kind,id", SOURCE_KINDS
        ).fetchall()


def fresh_remote(reader, remote, root):
    return RewardControlHistoryReader(
        root,
        control_hotkey=reader.hotkey,
        chain_config_sha256=reader.config_sha256,
        first_block=reader.first_block,
        maximum_bytes=reader.journal.maximum_bytes,
        remote_store=remote,
    )


async def test_shutdown_does_not_admit_another_source_replication_batch(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    stop = asyncio.Event()
    remote = store(tmp_path / "shutdown-remote", EvidenceServer())
    h.reader = reopen(h.reader, remote)
    h.reader.shutdown_event = stop
    externalize = h.reader._externalize_sources
    batches = []

    def finish_owned_batch(maximum_records):
        result = externalize(maximum_records)
        batches.append(result)
        # A stop during the first owned replication must not start capture or
        # another replication batch, even though the caller wasn't cancelled.
        stop.set()
        return result

    monkeypatch.setattr(h.reader, "_externalize_sources", finish_owned_batch)
    result = await h.reader.advance(h.item.provider, through_block=h.end)
    assert result.history is None and result.next_block == h.reader.first_block
    assert len(batches) == 1 and not h.body_requests
    assert h.reader.progress.latest["shutdown_state"] == "drained"


async def test_read_through_keeps_original_local_delivery_without_claiming_r2_replication(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    archive = tmp_path / "original-export"
    h.reader.export_archive = RewardProofArchive(archive)
    await h.reader.advance(h.item.provider, through_block=h.end)
    height = h.reader.first_block
    original = h.reader.checkpoints.load(height)
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    selected = RewardProofArchive(archive, remote=remote, legacy_read_through=True)
    h.reader = reopen(h.reader, remote, export_archive=selected)
    h.reader.progress.start(h.end, height)
    h.reader.progress.remote_export_selected = True
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader._ensure_checkpoint_export(original) == original
    assert h.reader.checkpoints.load(height) == original
    assert h.reader.progress.retained_local_export_count == 1
    assert h.reader.progress.counts["exported"] == 0
    assert server.calls == []


async def test_read_through_new_tail_exports_to_r2_without_backfilling_original_archive(
    history_case, tmp_path
):
    h = history_case
    archive = tmp_path / "original-export"
    h.reader.export_archive = RewardProofArchive(archive)
    await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=1)
    height = h.reader.first_block
    original_sources = originals(h.reader.journal)
    remote = store(tmp_path / "remote", EvidenceServer())
    selected = RewardProofArchive(archive, remote=remote, legacy_read_through=True)
    h.reader = reopen(h.reader, remote, export_archive=selected)
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history is not None
    remaining_sources = originals(h.reader.journal)
    assert all(row in remaining_sources for row in original_sources)
    assert (
        remote.reference_for_path(
            "frames/history/" + history_archive_key(h.reader.config_sha256, h.reader.hotkey, height)
        )
        is None
    )
    assert h.reader.progress.latest["retained_local_export_blocks"] == 1
    assert h.reader.progress.latest["replicated_blocks"] == h.end - height
    assert (
        remote.reference_for_path(
            "frames/history/" + history_archive_key(h.reader.config_sha256, h.reader.hotkey, h.end)
        )
        is not None
    )


@pytest.mark.parametrize("read_through_selection", ["source", "export", "both"])
@pytest.mark.parametrize("partial_explicit_migration", [False, True])
async def test_read_through_full_advance_reuses_original_checkpoint_without_implicit_migration(
    history_case, tmp_path, monkeypatch, read_through_selection, partial_explicit_migration
):
    h = history_case
    archive = tmp_path / "original-export"
    h.reader.export_archive = RewardProofArchive(archive)
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    saved_sources = originals(h.reader.journal)
    saved_successes = retained(h.reader.journal)
    server = EvidenceServer()
    selected_config = config(tmp_path)
    if read_through_selection in ("source", "both"):
        selected_config = selected_config.model_copy(
            update={"schema_": "umi-r2-proof-archive/2", "legacy_read_through": True}
        )
    remote = RemoteProofStore(tmp_path / "remote", selected_config, client=server.client())
    # Both selections preserve existing local export delivery. The source-only
    # case has no export owner and must still avoid implicit source migration.
    selected_archive = (
        RewardProofArchive(archive, remote=remote, legacy_read_through=True)
        if read_through_selection in ("export", "both")
        else None
    )
    h.reader = reopen(h.reader, remote, export_archive=selected_archive)
    if partial_explicit_migration:
        # Supported explicit migration remains available, and an interrupted
        # migration must not silently resume ahead of completed history replay.
        result = await h.reader.externalize_history_sources(maximum_records=1)
        assert result["replicated_records"] == 1
        saved_sources = originals(h.reader.journal)
        assert retained(h.reader.journal) == saved_successes
        h.reader = reopen(h.reader, remote, export_archive=selected_archive)
        server.calls.clear()

    def reject_implicit_migration(*_args, **_kwargs):
        raise AssertionError("read-through must not migrate retained SQL sources during advance")

    monkeypatch.setattr(h.reader, "_externalize_sources", reject_implicit_migration)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert originals(h.reader.journal) == saved_sources
    assert retained(h.reader.journal) == saved_successes
    assert h.reader.progress.native_completed == 0 and not server.calls


async def test_retained_local_delivery_never_hides_damaged_completed_remote_receipt(
    history_case, tmp_path
):
    h = history_case
    archive = tmp_path / "original-export"
    h.reader.export_archive = RewardProofArchive(archive)
    await h.reader.advance(h.item.provider, through_block=h.end)
    original = h.reader.checkpoints.load(h.reader.first_block)
    remote = store(tmp_path / "remote", EvidenceServer())
    key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, h.reader.first_block)
    frame = (archive / "history" / (key + ".json")).read_bytes()
    remote.put_bytes(frame, path="frames/history/" + key)
    with remote.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='remote_proof_object'")
    selected = RewardProofArchive(archive, remote=remote, legacy_read_through=True)
    h.reader = reopen(h.reader, remote, export_archive=selected)
    with pytest.raises(ValueError, match="missing or damaged"):
        await h.reader._ensure_checkpoint_export(original)
    assert h.reader.progress.retained_local_export_count == 0


async def test_new_history_is_captured_remotely_before_native_verification_and_reuses_success(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    server = EvidenceServer()
    direct = fresh_remote(h.reader, store(tmp_path / "direct-index", server), tmp_path / "direct")
    transaction = direct.journal.transaction

    @contextmanager
    def no_local_payloads(**kwargs):
        with transaction(**kwargs) as db:
            yield db
            assert not db.execute(
                "SELECT 1 FROM records WHERE kind IN (?,?,?) LIMIT 1", SOURCE_KINDS
            ).fetchone()

    monkeypatch.setattr(direct.journal, "transaction", no_local_payloads)
    assert await direct.advance(h.item.provider, through_block=h.end) == expected
    assert direct.progress.native_completed == h.end - direct.first_block + 1
    assert not originals(direct.journal)
    successes = retained(direct.journal)
    server.calls.clear()
    direct = reopen(direct, store(tmp_path / "direct-index", server))
    prohibit_proof_replay(monkeypatch, direct)
    assert await direct.advance(h.item.provider, through_block=h.end) == expected
    assert direct.progress.native_completed == 0 and server.calls == []
    assert retained(direct.journal) == successes


async def test_readonly_receipt_consumer_reuses_capture_success_without_proofs_or_payloads(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    server = EvidenceServer()
    producer = store(tmp_path / "producer-index", server)
    direct = fresh_remote(h.reader, producer, tmp_path / "direct")
    assert await direct.advance(h.item.provider, through_block=h.end) == expected
    successes = retained(direct.journal)
    original = direct.journal.path.read_bytes()
    source_original = producer.journal.path.read_bytes()
    server.calls.clear()
    remote = RemoteProofStore(
        tmp_path / "consumer-index",
        config(tmp_path, read_only=True),
        client=server.client(),
        receipt_source_directory=producer.journal.root,
    )
    readonly = RewardControlHistoryReader(
        direct.journal.root,
        control_hotkey=direct.hotkey,
        chain_config_sha256=direct.config_sha256,
        first_block=direct.first_block,
        maximum_bytes=direct.journal.maximum_bytes,
        remote_store=remote,
        existing_only=True,
        read_only=True,
    )
    prohibit_proof_replay(monkeypatch, readonly)
    assert await readonly.advance(h.item.provider, through_block=h.end) == expected
    assert readonly.progress.native_completed == 0 and server.calls == []
    assert retained(readonly.journal) == successes
    assert direct.journal.path.read_bytes() == original
    assert producer.journal.path.read_bytes() == source_original


async def test_direct_capture_and_proof_export_share_exact_acknowledged_node_objects(
    history_case, tmp_path
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    height = h.reader.first_block
    fields = h.reader._load(height)
    server = EvidenceServer()
    remote = store(tmp_path / "direct-index", server)
    direct = fresh_remote(h.reader, remote, tmp_path / "direct")
    direct.export_archive = RewardProofArchive(tmp_path / "export", remote=remote)
    direct._save_fields(height, fields)
    with direct.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (5,)
        aliases = [
            json.loads(row[0])
            for row in db.execute("SELECT body FROM records WHERE kind=?", (ALIAS_KIND,))
        ]
    nodes = [a for a in aliases if a["schema"] == CAPTURE_SCHEMA]
    assert nodes and all(a["encoding"] == HEX_OBJECT_ENCODING for a in nodes)
    assert all(a["remote"]["content_sha256"] == a["key"] for a in nodes)
    keys = {a["remote"]["key"] for a in nodes}
    server.calls.clear()
    direct._export_fields(height, fields, direct.export_archive)
    assert not any(
        method == "PUT" and path.removeprefix("/umi-proof-artifacts/") in keys
        for method, path in server.calls
    )
    assert direct._load(height) == fields


async def test_capture_upgrade_preserves_original_v3_aliases_tokens_successes_and_inode(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    fields = h.reader._load(h.reader.first_block)
    server = EvidenceServer()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    await h.reader.externalize_history_sources(maximum_records=4096)
    with h.reader.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (3,)
        aliases = db.execute(
            "SELECT id,body FROM records WHERE kind=? ORDER BY id", (ALIAS_KIND,)
        ).fetchall()
    inode, successes = h.reader.journal.path.stat().st_ino, retained(h.reader.journal)
    saved = h.reader.checkpoints.load(h.reader.first_block)
    server.calls.clear()
    h.reader._save_fields(h.reader.first_block, fields)
    with h.reader.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (5,)
        assert (
            db.execute(
                "SELECT id,body FROM records WHERE kind=? ORDER BY id", (ALIAS_KIND,)
            ).fetchall()
            == aliases
        )
    assert h.reader.journal.path.stat().st_ino == inode
    assert retained(h.reader.journal) == successes
    assert h.reader.checkpoints.load(h.reader.first_block) == saved
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert server.calls == []


async def test_unsupported_reader_and_downgraded_capture_capability_refuse_before_replay(
    history_case, tmp_path
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    remote = store(tmp_path / "direct-index", EvidenceServer())
    direct = fresh_remote(h.reader, remote, tmp_path / "direct")
    direct._save_fields(h.reader.first_block, h.reader._load(h.reader.first_block))
    with (
        direct.journal.read_transaction() as db,
        pytest.raises(ValueError, match="unsupported round journal capability"),
    ):
        RoundJournal._version(db)
    with direct.journal.transaction() as db:
        db.execute("PRAGMA user_version=3")
    with pytest.raises(ValueError, match="original selected R2 namespace"):
        reopen(direct, store(tmp_path / "direct-index", EvidenceServer()))


@pytest.mark.parametrize("interruption", ["put_ack", "before_commit", "after_commit"])
async def test_interrupted_direct_capture_retains_remote_progress_without_local_payloads(
    history_case, tmp_path, monkeypatch, interruption
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    height = h.reader.first_block
    fields = h.reader._load(height)
    server = EvidenceServer()
    direct = fresh_remote(h.reader, store(tmp_path / "direct-index", server), tmp_path / "direct")
    with monkeypatch.context() as patch:
        if interruption == "put_ack":
            server.lose_put_ack = True
        elif interruption == "before_commit":
            transaction = direct.journal.transaction

            @contextmanager
            def interrupted(**kwargs):
                with transaction(**kwargs) as db:
                    yield db
                    if db.execute("SELECT 1 FROM records WHERE kind=?", (ALIAS_KIND,)).fetchone():
                        raise OSError("interrupted direct capture commit")

            patch.setattr(direct.journal, "transaction", interrupted)
        else:
            capture = direct.remote_sources.capture

            def interrupted(*args, **kwargs):
                capture(*args, **kwargs)
                raise OSError("lost direct capture commit acknowledgement")

            patch.setattr(direct.remote_sources, "capture", interrupted)
        with pytest.raises(OSError):
            direct._save_fields(height, fields)
    assert not originals(direct.journal)
    assert direct.checkpoints.load(height) is None
    direct = reopen(direct, store(tmp_path / "direct-index", server))
    calls = len(server.calls)
    direct._save_fields(height, fields)
    assert direct._load(height) == fields
    assert not originals(direct.journal)
    if interruption != "put_ack":
        assert not any(method == "PUT" for method, _ in server.calls[calls:])


async def test_direct_capture_refuses_missing_original_alias_identity(history_case, tmp_path):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    height = h.reader.first_block
    fields = h.reader._load(height)
    direct = fresh_remote(
        h.reader, store(tmp_path / "direct-index", EvidenceServer()), tmp_path / "direct"
    )
    direct._save_fields(height, fields)
    with direct.journal.transaction() as db:
        db.execute(
            "DELETE FROM history_source_identity WHERE kind=? AND id=?",
            ("control_history_block", str(height)),
        )
    with pytest.raises(HistoryCheckpointRepairRequired, match="identity missing"):
        direct._save_fields(height, fields)


async def test_direct_capture_preserves_a_source_that_appears_during_publication(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    height = h.reader.first_block
    fields = h.reader._load(height)
    direct = fresh_remote(
        h.reader, store(tmp_path / "direct-index", EvidenceServer()), tmp_path / "direct"
    )
    publish = direct.remote_store.put_many

    def raced(objects):
        publish(objects)
        direct.journal.put("control_history_block", str(height), {"competing": True})

    monkeypatch.setattr(direct.remote_store, "put_many", raced)
    with pytest.raises(HistoryCheckpointRepairRequired, match="changed during publication"):
        direct._save_fields(height, fields)
    assert direct.journal.get("control_history_block", str(height)) == {"competing": True}
    assert direct.journal.get(ALIAS_KIND, digest(["control_history_block", str(height)])) is None


@pytest.mark.parametrize("parallel", [False, True])
async def test_original_success_replays_without_payload_io_after_eviction_and_restart(
    history_case, tmp_path, monkeypatch, parallel
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    successes = retained(h.reader.journal)
    inode = h.reader.journal.path.stat().st_ino
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    h.reader = reopen(h.reader, remote)
    result = await h.reader.externalize_history_sources(maximum_records=4096)
    assert result["replicated_records"] > 0 and result["remaining_local_records"] == 0
    assert not originals(h.reader.journal)
    assert retained(h.reader.journal) == successes
    assert h.reader.journal.path.stat().st_ino == inode
    server.calls.clear()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server), parallel=parallel)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.native_completed == 0
    assert h.reader.progress.latest["captured_blocks"] == h.end - h.reader.first_block + 1
    assert server.calls == []
    assert retained(h.reader.journal) == successes


async def test_restore_and_duplicate_save_preserve_exact_fields_and_original_tokens(
    history_case, tmp_path
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    height = h.reader.first_block
    fields = h.reader._load(height)
    checkpoint = h.reader.checkpoints.load(height)
    server = EvidenceServer()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    await h.reader.externalize_history_sources(maximum_records=4096)
    h.reader.remote_store.evict_cache()
    assert h.reader._load(height) == fields
    assert any(method == "GET" for method, _ in server.calls)
    h.reader._save_fields(height, fields)
    assert not originals(h.reader.journal)
    assert h.reader.checkpoints.load(height) == checkpoint
    assert h.reader._source_tokens[height] == checkpoint["sources"]


async def test_cold_remote_legacy_frames_reach_spawned_native_verification_once(
    history_case, tmp_path, monkeypatch
):
    h = await retained_parallel_case(history_case, tmp_path, monkeypatch)
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    h.reader = reopen(h.reader, remote, parallel=True)
    await h.reader.externalize_history_sources(maximum_records=4096)
    remote.evict_cache()
    assert not originals(h.reader.journal)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.native_completed == len(h.frames)
    assert len(h.pools) == 2
    server.calls.clear()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server), parallel=True)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert server.calls == []
    assert len(h.pools) == 2


@pytest.mark.parametrize("interruption", ["put_ack", "before_alias_commit", "after_alias_commit"])
async def test_interrupted_externalization_keeps_success_and_exact_retry(
    history_case, tmp_path, monkeypatch, interruption
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    successes = retained(h.reader.journal)
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    h.reader = reopen(h.reader, remote)
    kind, key, raw = originals(h.reader.journal)[0]
    if interruption == "put_ack":
        server.lose_put_ack = True
    elif interruption == "before_alias_commit":
        transaction = h.reader.journal.transaction

        @contextmanager
        def interrupted():
            with transaction() as db:
                yield db
                if db.execute("SELECT 1 FROM records WHERE kind=?", (ALIAS_KIND,)).fetchone():
                    raise OSError("interrupted alias transaction")

        monkeypatch.setattr(h.reader.journal, "transaction", interrupted)
    else:
        commit = h.reader.remote_sources._commit_alias

        def interrupted(*args):
            commit(*args)
            raise OSError("lost alias acknowledgement")

        monkeypatch.setattr(h.reader.remote_sources, "_commit_alias", interrupted)
    with pytest.raises(OSError):
        h.reader.remote_sources.externalize(kind, key)
    assert retained(h.reader.journal) == successes
    if interruption != "after_alias_commit":
        assert h.reader.journal.get_raw(kind, key) == raw
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    h.reader.remote_sources.externalize(kind, key)
    assert h.reader.journal.get(kind, key) is None
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert retained(h.reader.journal) == successes


async def test_source_mutation_during_upload_refuses_eviction_without_writer_io(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    remote = store(tmp_path / "remote", EvidenceServer())
    h.reader = reopen(h.reader, remote)
    kind, key, raw = originals(h.reader.journal)[0]
    original_put = remote.put_bytes

    def mutate(raw):
        # This independent writer would block/fail if network publication were
        # being performed inside the history writer transaction.
        with h.reader.journal.transaction() as db:
            db.execute("UPDATE records SET body=body WHERE kind=? AND id=?", (kind, key))
        return original_put(raw)

    monkeypatch.setattr(remote, "put_bytes", mutate)
    with pytest.raises(HistoryCheckpointRepairRequired, match="changed during upload"):
        h.reader.remote_sources.externalize(kind, key)
    assert h.reader.journal.get_raw(kind, key) == raw
    assert h.reader.journal.get(ALIAS_KIND, digest([kind, key])) is None


async def test_later_source_reinsertion_never_resurrects_original_verdict(history_case, tmp_path):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    kind, key, raw = originals(h.reader.journal)[0]
    h.reader.remote_sources.externalize(kind, key)
    h.reader.journal.put(kind, key, json.loads(raw))
    with pytest.raises(HistoryCheckpointRepairRequired, match="mutated"):
        h.reader.checkpoints.load(int(key))


@pytest.mark.parametrize("large", [True, False])
async def test_full_journal_charges_net_replacement_and_rolls_back_if_it_cannot_fit(
    history_case, tmp_path, large
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    key = "d" * 64
    kind = "control_history_object"
    h.reader.journal.put(kind, key, {"hex": "ff" * (10000 if large else 1)})
    original = h.reader.journal.get_raw(kind, key)
    with h.reader.journal.read_transaction() as db:
        _, used, _ = h.reader.journal._record_capacity(db)
    h.reader.journal.maximum_bytes = used
    if large:
        result = h.reader.remote_sources.externalize(kind, key)
        assert result["released_logical_bytes"] > 0
        assert h.reader.journal.get_raw(kind, key) is None
    else:
        with pytest.raises(ValueError, match="exceeds journal capacity"):
            h.reader.remote_sources.externalize(kind, key)
        assert h.reader.journal.get_raw(kind, key) == original
        assert h.reader.journal.get(ALIAS_KIND, digest([kind, key])) is None


async def test_full_owner_bounded_replication_reclaims_payload_before_small_frames(
    history_case, tmp_path
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    with h.reader.journal.read_transaction() as db:
        _, used, _ = h.reader.journal._record_capacity(db)
    h.reader.journal.maximum_bytes = used
    result = await h.reader.externalize_history_sources(maximum_records=4096)
    assert result["remaining_local_records"] == 0
    assert result["released_logical_bytes"] > 0


async def test_source_publication_overlaps_four_transfers_and_restart_reuses_each_alias(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    successes = retained(h.reader.journal)
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    h.reader = reopen(h.reader, remote)
    keys = [("control_history_object", digest(["bounded-source", i])) for i in range(9)]
    for i, (kind, key) in enumerate(keys):
        h.reader.journal.put(kind, key, {"hex": f"{i:02x}" * (9000 if i == 0 else 8000)})
    with h.reader.journal.read_transaction() as db:
        tokens = {key: h.reader.remote_sources.source_token(*key, db) for key in keys}

    barrier, lock = Barrier(4, timeout=10), Lock()
    active = peak = 0
    publish = remote.put_bytes

    def concurrent(raw):
        nonlocal active, peak
        # The largest record is deliberately committed before concurrent work.
        if b'"00' in raw:
            assert active == 0
            return publish(raw)
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            barrier.wait()
            return publish(raw)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(remote, "put_bytes", concurrent)
    result = h.reader.remote_sources.externalize_many(keys)
    assert peak == 4 and active == 0
    assert result["replicated_records"] == 9 and result["released_logical_bytes"] > 0
    assert retained(h.reader.journal) == successes
    with h.reader.journal.read_transaction() as db:
        assert {key: h.reader.remote_sources.source_token(*key, db) for key in keys} == tokens

    remote.evict_cache()
    server.calls.clear()
    selected = remote.config.model_copy(
        update={"schema_": "umi-r2-proof-archive/2", "legacy_read_through": True}
    )
    h.reader = reopen(
        h.reader, RemoteProofStore(tmp_path / "remote", selected, client=server.client())
    )
    read = h.reader.journal.get_raw

    def no_repeated_payload(kind, key, **kwargs):
        assert (kind, key) not in keys, "completed source payload was read again"
        return read(kind, key, **kwargs)

    monkeypatch.setattr(h.reader.journal, "get_raw", no_repeated_payload)
    assert h.reader.remote_sources.externalize_many(keys)["restored_records"] == 9
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert not server.calls


async def test_parallel_source_failure_drains_workers_and_reuses_completed_publication(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    successes = retained(h.reader.journal)
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    h.reader = reopen(h.reader, remote)
    keys = [("control_history_object", digest(["interrupted-source", i])) for i in range(9)]
    for i, (kind, key) in enumerate(keys):
        h.reader.journal.put(kind, key, {"hex": f"{i:02x}" * (9000 if i == 0 else 8000)})
    barrier = Barrier(4, timeout=10)
    publish = remote.put_bytes

    def interrupted(raw):
        if b'"00' not in raw:
            barrier.wait()
        result = publish(raw)
        if b'"01' in raw:
            raise OSError("lost one parallel source acknowledgement")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(remote, "put_bytes", interrupted)
        with pytest.raises(OSError, match="parallel source acknowledgement"):
            h.reader.remote_sources.externalize_many(keys[:5])
    published = set(server.objects)
    with h.reader.journal.read_transaction() as db:
        remaining = [key for key in keys[:5] if h.reader.journal.get_raw(*key, db=db)]
    assert 1 <= len(remaining) < 5
    assert retained(h.reader.journal) == successes
    server.calls.clear()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    result = h.reader.remote_sources.externalize_many(keys[:5])
    assert result["replicated_records"] == 5
    assert all(
        path.removeprefix("/umi-proof-artifacts/") not in published
        for method, path in server.calls
        if method == "PUT"
    )
    assert retained(h.reader.journal) == successes


@pytest.mark.parametrize("retained_local", [False, True])
async def test_advance_reclaims_full_owner_before_capturing_next_native_block(
    history_case, tmp_path, monkeypatch, retained_local
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=1)
    original = h.reader.checkpoints.load(h.reader.first_block)
    # A retained historical object makes the selected envelope sufficient for
    # the next frame, but has consumed every logical byte before replication.
    h.reader.journal.put("control_history_object", "e" * 64, {"hex": "ff" * 100000})
    with h.reader.journal.read_transaction() as db:
        _, used, _ = h.reader.journal._record_capacity(db)
    h.reader.journal.maximum_bytes = used
    server = EvidenceServer()
    selected_config = config(tmp_path)
    if retained_local:
        selected_config = ProofArchiveR2Config.model_validate(
            selected_config.model_dump(mode="json", by_alias=True)
            | {
                "schema": "umi-r2-proof-archive/2",
                "legacy_read_through": True,
                "source_release_batch_records": 256,
            }
        )
    h.reader = reopen(
        h.reader, RemoteProofStore(tmp_path / "remote", selected_config, client=server.client())
    )
    save = h.reader._save_fields
    captures = []

    def assert_reclaimed(height, fields):
        with h.reader.journal.read_transaction() as db:
            assert db.execute("SELECT 1 FROM records WHERE kind=?", (ALIAS_KIND,)).fetchone()
        captures.append(height)
        return save(height, fields)

    monkeypatch.setattr(h.reader, "_save_fields", assert_reclaimed)
    result = await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=2)
    # Restoring the constant-sized ordered fold consumes no new-block budget.
    assert result.next_block == h.reader.first_block + 3
    assert captures == [h.reader.first_block + 1, h.reader.first_block + 2]
    assert h.reader.checkpoints.load(h.reader.first_block) == original
    assert h.reader.checkpoints.load(h.reader.first_block + 1) is not None


async def test_existing_reservation_generation_is_refused_without_remote_publication(
    history_case, tmp_path
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    server = EvidenceServer()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    kind, key, raw = originals(h.reader.journal)[0]
    with h.reader.journal.transaction() as db:
        h.reader.journal._enable_reservations(db)
    with pytest.raises(ValueError, match="refuses reservation-generation"):
        h.reader.remote_sources.externalize(kind, key)
    assert server.calls == []
    assert h.reader.journal.get_raw(kind, key) == raw


@pytest.mark.parametrize("damage", ["changed_remote", "corrupt_get", "deleted_remote"])
async def test_observed_remote_damage_blocks_reuse_until_original_generation_repaired(
    history_case, tmp_path, damage
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    server = EvidenceServer()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    height = h.reader.first_block
    checkpoint = h.reader.checkpoints.load(height)
    await h.reader.externalize_history_sources(maximum_records=4096)
    # Observe remote damage after releasing trusted local bytes.
    h.reader.remote_store.evict_cache()
    alias = h.reader.journal.get(ALIAS_KIND, digest(["control_history_block", str(height)]))
    ref = alias["remote"]
    original = server.objects[ref["key"]]
    if damage == "deleted_remote":
        del server.objects[ref["key"]]
    elif damage == "changed_remote":
        server.objects[ref["key"]] = b"changed"
    else:
        server.corrupt_get = True
    with pytest.raises(HistoryCheckpointRepairRequired, match="restoration"):
        h.reader._load(height)
    server.objects[ref["key"]] = original
    server.corrupt_get = False
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    with pytest.raises(HistoryCheckpointRepairRequired, match="receipt damaged"):
        h.reader.checkpoints.load(height)
    h.reader.remote_store.repair_reference(ref)
    assert h.reader.checkpoints.load(height) == checkpoint


async def test_rollback_and_changed_namespace_refuse_before_owner_mutation(history_case, tmp_path):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    await h.reader.externalize_history_sources(maximum_records=1)
    successes = retained(h.reader.journal)
    with (
        h.reader.journal.read_transaction() as db,
        pytest.raises(ValueError, match="unsupported round"),
    ):
        RoundJournal._version(db)
    with pytest.raises(ValueError, match="original selected R2 namespace"):
        reopen(h.reader, None)
    with pytest.raises(ValueError, match="original selected R2 namespace"):
        reopen(h.reader, store(tmp_path / "different", EvidenceServer(), prefix="different"))
    assert retained(h.reader.journal) == successes
    with sqlite3.connect(h.reader.journal.path) as db:
        db.execute("PRAGMA user_version=0")
        with pytest.raises(ValueError, match="downgraded"):
            RoundJournal._version(db)
    with pytest.raises(ValueError, match="downgraded"):
        reopen(h.reader, h.reader.remote_store)


async def test_alias_mutation_is_fenced_and_missing_fence_requires_explicit_repair(
    history_case, tmp_path
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    await h.reader.externalize_history_sources(maximum_records=1)
    with (
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
        h.reader.journal.transaction() as db,
    ):
        db.execute("DELETE FROM records WHERE kind=?", (ALIAS_KIND,))
    with sqlite3.connect(h.reader.journal.path) as db:
        db.execute(f"DROP TRIGGER {MARKER_TABLE}_delete")
    with pytest.raises(ValueError, match="alias fences changed"):
        reopen(h.reader, h.reader.remote_store)


async def test_remote_archive_selection_automatically_externalizes_and_reports_replication(
    history_case, tmp_path
):
    h = history_case
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=remote)
    h.reader = reopen(h.reader, remote, export_archive=archive)
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history is not None
    assert not originals(h.reader.journal)
    assert h.reader.progress.latest["replicated_blocks"] == h.end - h.reader.first_block + 1
    identity = h.reader._export_identity()
    assert identity in h.reader.checkpoints.load(h.reader.first_block)["exports"]
    remote.namespace_sha256 = "f" * 64
    assert h.reader._export_identity() != identity
