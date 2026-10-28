"""An admitted original prefix survives exact remote source release, never mutation."""

from contextlib import contextmanager

import pytest

from umi.competition_history_source_externalization import ALIAS_KIND
from umi.competition_remote_proof_store import ProofArchiveR2Config, RemoteProofStore
from umi.competition_reward_decision_review import review_reward_decision
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_signing import RewardDecisionSigner

from .test_competition_history_source_externalization import originals, reopen
from .test_competition_remote_proof_store import EvidenceServer, store
from .test_competition_remote_proof_store import config as proof_config
from .test_competition_reward_admission_migration import admission_case as admission_case
from .test_competition_reward_admission_migration import chain as chain
from .test_competition_reward_admission_migration import chain_config as chain_config
from .test_competition_reward_admission_migration import control as control
from .test_competition_reward_admission_migration import historical as historical
from .test_competition_reward_admission_migration import original_chain as original_chain
from .test_competition_reward_admission_migration import (
    original_chain_config as original_chain_config,
)
from .test_competition_reward_admission_migration import policy as policy
from .test_competition_reward_admission_migration import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_selected_read_through_release_runs_once_after_restoration_and_resumes_without_replay(
    admission_case, tmp_path, monkeypatch
):
    c, h = admission_case, admission_case.h
    admitted = await c.migrate()
    server = EvidenceServer()
    configured = ProofArchiveR2Config.model_validate(
        proof_config(tmp_path).model_dump(mode="json", by_alias=True)
        | {
            "schema": "umi-r2-proof-archive/2",
            "legacy_read_through": True,
            "source_release_batch_records": 1,
        }
    )

    def selected():
        return RemoteProofStore(tmp_path / "remote", configured, client=server.client())

    before = len(originals(h.reader.journal))
    h.reader = reopen(h.reader, selected())
    original_inode = h.reader.journal.path.stat().st_ino
    native = h.reader._externalize_sources_locked
    calls = []

    def release(maximum):
        assert h.reader._next > c.boundary, "release started before native admission restoration"
        calls.append(maximum)
        return native(maximum)

    monkeypatch.setattr(h.reader, "_externalize_sources_locked", release)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (await h.reader.advance(h.item.provider, through_block=c.boundary)).history == c.expected
    assert calls == [1]
    assert len(originals(h.reader.journal)) == before - 1
    assert h.reader.completed_admission.load() == admitted
    progress = h.reader.progress.latest["local_release"]
    assert progress["remaining_local_records"] == before - 1
    assert progress["total_records"] == before
    assert progress["completed_records"] == 1
    assert progress["eta_seconds"] > 0 and progress["elapsed_seconds"] > 0
    assert "excludes_advancement" in progress["eta_basis"]
    h.reader.remote_store.evict_cache()
    h.reader = reopen(h.reader, selected())
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (await h.reader.advance(h.item.provider, through_block=c.boundary)).history == c.expected
    assert len(originals(h.reader.journal)) == before - 2
    assert h.reader.completed_admission.load() == admitted
    assert h.reader.journal.path.stat().st_ino == original_inode
    while originals(h.reader.journal):
        await h.reader.advance(h.item.provider, through_block=c.boundary)
    server.calls.clear()
    h.reader = reopen(h.reader, selected())
    prohibit_proof_replay(monkeypatch, h.reader)
    await h.reader.advance(h.item.provider, through_block=c.boundary)
    progress = h.reader.progress.latest["local_release"]
    assert progress["remaining_local_records"] == 0 and progress["percent"] == 100
    assert progress["state"] == "completed" and progress["eta_seconds"] == 0
    assert not server.calls, "completed migration reread or republished retained payloads"


async def test_selected_read_through_release_drains_without_admitting_a_new_batch(
    admission_case, tmp_path, monkeypatch
):
    import asyncio

    c, h = admission_case, admission_case.h
    await c.migrate()
    server = EvidenceServer()
    configured = ProofArchiveR2Config.model_validate(
        proof_config(tmp_path).model_dump(mode="json", by_alias=True)
        | {
            "schema": "umi-r2-proof-archive/2",
            "legacy_read_through": True,
            "source_release_batch_records": 1,
        }
    )
    h.reader = reopen(
        h.reader, RemoteProofStore(tmp_path / "remote", configured, client=server.client())
    )
    stop = asyncio.Event()
    h.reader.shutdown_event = stop
    restore = h.reader._restore_completed_admission

    async def finish(*args, **kwargs):
        result = await restore(*args, **kwargs)
        stop.set()
        return result

    def forbidden(_):
        raise AssertionError("stop admitted another source migration batch")

    monkeypatch.setattr(h.reader, "_restore_completed_admission", finish)
    monkeypatch.setattr(h.reader, "_externalize_sources_locked", forbidden)
    await h.reader.advance(h.item.provider, through_block=c.boundary)
    assert h.reader.progress.local_release is None


async def test_selected_release_retry_keeps_completed_item_and_resumes_the_remaining_owner(
    admission_case, tmp_path, monkeypatch
):
    c, h = admission_case, admission_case.h
    admitted = await c.migrate()
    server = EvidenceServer()
    configured = ProofArchiveR2Config.model_validate(
        proof_config(tmp_path).model_dump(mode="json", by_alias=True)
        | {
            "schema": "umi-r2-proof-archive/2",
            "legacy_read_through": True,
            "source_release_batch_records": 2,
        }
    )

    def selected():
        return RemoteProofStore(tmp_path / "remote", configured, client=server.client())

    before = len(originals(h.reader.journal))
    h.reader = reopen(h.reader, selected())
    externalize = h.reader.remote_sources.externalize
    completed = []

    def interrupted(kind, key):
        if completed:
            raise OSError("interrupted after a completed exact alias")
        result = externalize(kind, key)
        completed.append((kind, key))
        return result

    monkeypatch.setattr(h.reader.remote_sources, "externalize", interrupted)
    prohibit_proof_replay(monkeypatch, h.reader)
    with pytest.raises(OSError, match="completed exact alias"):
        await h.reader.advance(h.item.provider, through_block=c.boundary)
    assert len(originals(h.reader.journal)) == before - 1
    assert h.reader.completed_admission.load() == admitted
    assert h.reader.progress.latest["state"] == "retrying"
    first_objects = set(server.objects)
    server.calls.clear()
    h.reader = reopen(h.reader, selected())
    prohibit_proof_replay(monkeypatch, h.reader)
    assert (await h.reader.advance(h.item.provider, through_block=c.boundary)).history == c.expected
    assert len(originals(h.reader.journal)) == before - 3
    assert h.reader.completed_admission.load() == admitted
    assert all(
        path.removeprefix("/umi-proof-artifacts/") not in first_objects
        for method, path in server.calls
        if method == "PUT"
    )


async def test_admitted_source_release_is_bounded_and_restart_never_replays_native_work(
    admission_case, tmp_path, monkeypatch
):
    c, h = admission_case, admission_case.h
    admitted = await c.migrate()
    identity = h.reader.journal.path.stat().st_ino
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    h.reader = reopen(h.reader, remote)
    original_count = len(originals(h.reader.journal))
    with h.reader.journal.read_transaction() as db:
        _, before_bytes, _ = h.reader.journal._record_capacity(db)
    first = await h.reader.externalize_history_sources(maximum_records=1)
    assert first["replicated_records"] == 1
    assert len(originals(h.reader.journal)) == original_count - 1
    with h.reader.journal.read_transaction() as db:
        _, after_bytes, _ = h.reader.journal._record_capacity(db)
    assert first["released_logical_bytes"] == before_bytes - after_bytes
    assert h.reader.completed_admission.load() == admitted
    # Resume the actual partially migrated journal, preserving its original
    # inode, admitted interval, remote generation and remaining exact sources.
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    second = await h.reader.externalize_history_sources(maximum_records=4096)
    assert second["remaining_local_records"] == 0
    assert not originals(h.reader.journal)
    assert h.reader.completed_admission.load() == admitted
    assert h.reader.journal.path.stat().st_ino == identity
    with h.reader.journal.read_transaction() as db:
        assert db.execute("SELECT revision FROM history_completed_admission").fetchall() == [(0,)]
    h.reader.remote_store.evict_cache()
    server.calls.clear()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    prohibit_proof_replay(monkeypatch, h.reader)
    restored = (await h.reader.advance(h.item.provider, through_block=c.boundary)).history
    assert restored == c.expected
    assert h.reader.progress.native_completed == 0
    assert not server.calls, "unchanged admitted proof payload was read again"
    assert (await h.reader.externalize_history_sources())["replicated_records"] == 0
    assert not server.calls
    reviewed = review_reward_decision(
        c.decision_reader,
        c.manifest,
        (),
        c.body,
        control=c.original_control,
        history=restored,
        maximum_promotion_bytes=1024**2,
    )
    assert reviewed.intent == c.original_review.intent

    async def no_new_signature(_):
        raise AssertionError("unchanged admitted reward decision was signed again")

    await RewardDecisionSigner(c.source, no_new_signature).attest(reviewed)


@pytest.mark.parametrize("interruption", ["put_ack", "before_alias_commit", "after_alias_commit"])
async def test_admitted_source_release_resumes_each_atomic_failure_boundary(
    admission_case, tmp_path, monkeypatch, interruption
):
    c, h = admission_case, admission_case.h
    admitted = await c.migrate()
    server = EvidenceServer()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    kind, key, raw = originals(h.reader.journal)[0]
    with monkeypatch.context() as patch:
        if interruption == "put_ack":
            server.lose_put_ack = True
        elif interruption == "before_alias_commit":
            transaction = h.reader.journal.transaction

            @contextmanager
            def interrupted():
                with transaction() as db:
                    yield db
                    if db.execute("SELECT 1 FROM records WHERE kind=?", (ALIAS_KIND,)).fetchone():
                        raise OSError("interrupted alias commit")

            patch.setattr(h.reader.journal, "transaction", interrupted)
        else:
            commit = h.reader.remote_sources._commit_alias

            def interrupted(*args):
                commit(*args)
                raise OSError("lost alias acknowledgement")

            patch.setattr(h.reader.remote_sources, "_commit_alias", interrupted)
        with pytest.raises(OSError):
            h.reader.remote_sources.externalize(kind, key)
    assert h.reader.completed_admission.load() == admitted
    with h.reader.journal.read_transaction() as db:
        if interruption != "after_alias_commit":
            assert h.reader.journal.get_raw(kind, key, db=db) == raw
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    result = h.reader.remote_sources.externalize(kind, key)
    assert result["restored"] == (interruption == "after_alias_commit")
    assert h.reader.completed_admission.load() == admitted


@pytest.mark.parametrize("when", ["before_upload", "during_upload", "inside_alias_transaction"])
async def test_admitted_source_release_never_erases_an_unrelated_source_mutation(
    admission_case, tmp_path, monkeypatch, when
):
    c, h = admission_case, admission_case.h
    await c.migrate()
    server = EvidenceServer()
    h.reader = reopen(h.reader, store(tmp_path / "remote", server))
    sources = originals(h.reader.journal)
    kind, key, raw = sources[0]
    other_kind, other_key, _ = sources[1]

    def mutate(db):
        db.execute("UPDATE records SET body=body WHERE kind=? AND id=?", (other_kind, other_key))

    if when == "before_upload":
        with h.reader.journal.transaction() as db:
            mutate(db)
    elif when == "during_upload":
        put = h.reader.remote_store.put_bytes

        def changed(*args, **kwargs):
            value = put(*args, **kwargs)
            with h.reader.journal.transaction() as db:
                mutate(db)
            return value

        monkeypatch.setattr(h.reader.remote_store, "put_bytes", changed)
    else:
        token = h.reader.remote_sources.source_token

        def changed(kind, key, db):
            value = token(kind, key, db)
            if db.execute("PRAGMA query_only").fetchone() == (0,):
                mutate(db)
            return value

        monkeypatch.setattr(h.reader.remote_sources, "source_token", changed)
    with pytest.raises(HistoryCheckpointRepairRequired, match=r"admission.*(changed|release)"):
        h.reader.remote_sources.externalize(kind, key)
    with h.reader.journal.read_transaction() as db:
        assert h.reader.journal.get_raw(kind, key, db=db) == raw
        assert not db.execute("SELECT 1 FROM records WHERE kind=?", (ALIAS_KIND,)).fetchone()
    if when == "inside_alias_transaction":
        # The additional mutation and release roll back together.
        assert h.reader.completed_admission.load() is not None
    else:
        with pytest.raises(HistoryCheckpointRepairRequired, match="source or marker changed"):
            h.reader.completed_admission.load()


async def test_admitted_remote_sources_restore_original_bytes_and_keep_missing_receipts_explicit(
    admission_case, tmp_path
):
    c, h = admission_case, admission_case.h
    admitted = await c.migrate()
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    h.reader = reopen(h.reader, remote)
    sources = originals(h.reader.journal)
    await h.reader.externalize_history_sources(maximum_records=4096)
    remote.evict_cache()
    for kind, key, raw in sources:
        with h.reader.journal.read_transaction() as db:
            assert h.reader.remote_sources.get_raw(kind, key, db=db) == raw
    assert h.reader.completed_admission.load() == admitted
    # Existing remote repair semantics must survive admission preservation.
    with remote.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='remote_proof_object'")
    with pytest.raises(HistoryCheckpointRepairRequired):
        h.reader.completed_admission.load()


async def test_reinsertion_of_a_non_boundary_original_invalidates_the_whole_admitted_prefix(
    admission_case, tmp_path
):
    c, h = admission_case, admission_case.h
    admitted = await c.migrate()
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    boundary = {(kind, key) for kind, key, _ in admitted["boundary_sources"]}
    source = next(value for value in originals(h.reader.journal) if value[:2] not in boundary)
    await h.reader.externalize_history_sources(maximum_records=4096)
    with h.reader.journal.transaction() as db:
        db.execute("INSERT INTO records VALUES (?,?,?)", source)
    with pytest.raises(HistoryCheckpointRepairRequired, match="source or marker changed"):
        h.reader.completed_admission.load()


@pytest.mark.parametrize("damage", ["marker", "trigger"])
async def test_missing_release_fence_is_repair_not_a_legacy_admission(
    admission_case, tmp_path, damage
):
    c, h = admission_case, admission_case.h
    await c.migrate()
    h.reader = reopen(h.reader, store(tmp_path / "remote", EvidenceServer()))
    await h.reader.externalize_history_sources(maximum_records=1)
    with h.reader.journal.transaction() as db:
        if damage == "marker":
            db.execute(
                "DELETE FROM records WHERE kind='control_history_completed_admission_release'"
            )
        else:
            db.execute("DROP TRIGGER history_completed_admission_reinsert")
    with pytest.raises(HistoryCheckpointRepairRequired, match=r"release (marker|fence)"):
        h.reader.completed_admission.load()
