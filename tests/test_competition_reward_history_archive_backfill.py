"""Owner-driven bounded legacy transport; proof work and local release stay separate."""

import pytest

from umi.competition_remote_proof_store import ProofArchiveR2Config, RemoteProofStore
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key

from .test_competition_history_source_externalization import reopen
from .test_competition_remote_proof_store import EvidenceServer, config
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


def selected(root, server, *, release=False):
    raw = config(root).model_dump(mode="json", by_alias=True)
    raw.update(
        schema="umi-r2-proof-archive/2", legacy_read_through=True, archive_backfill_batch_frames=1
    )
    if release:
        raw.update(
            archive_release_batch_files=4096,
            archive_release_consumer_abi="umi-proof-read-release-lease/1",
        )
    return RemoteProofStore(
        root / "index", ProofArchiveR2Config.model_validate(raw), client=server.client()
    )


async def prepare(h, tmp_path, *, release=False):
    root = tmp_path / "original"
    h.reader.export_archive = RewardProofArchive(root)
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    server = EvidenceServer()
    remote = selected(tmp_path / "remote", server, release=release)
    h.reader = reopen(
        h.reader,
        remote,
        export_archive=RewardProofArchive(root, remote=remote, legacy_read_through=True),
    )
    return expected, root, server, remote


async def test_background_cursor_is_bounded_and_never_replays_native_payload(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected, root, server, remote = await prepare(h, tmp_path)
    prohibit_proof_replay(monkeypatch, h.reader)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    status = h.reader.progress.archive_delivery
    assert status["completed_blocks"] == 1 and status["total_blocks"] == 5
    key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, h.reader.first_block)
    assert remote.reference_for_path("frames/history/" + key) is not None
    assert (root / "history" / (key + ".json")).exists()
    assert status["removed_files"] == 0
    assert status["local_release_state"] == "not_selected"
    for _ in range(4):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader.progress.archive_delivery["state"] == "completed"
    server.calls.clear()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert server.calls == []


async def test_release_waits_for_active_reader_then_reclaims_and_restarts(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected, root, server, remote = await prepare(h, tmp_path, release=True)
    prohibit_proof_replay(monkeypatch, h.reader)
    with h.reader.export_archive.read_release_lease():
        assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
        status = h.reader.progress.archive_delivery
        assert status["local_release_state"] == "waiting_for_active_archive_reader"
        assert status["removed_files"] == 0
    for _ in range(5):
        await h.reader.advance(h.item.provider, through_block=h.end)
    status = h.reader.progress.archive_delivery
    assert status["removed_files"] > 0 and status["reclaimed_allocated_bytes"] > 0
    assert status["removed_files"] == status["queued_files"]
    old_counts = (status["removed_files"], status["reclaimed_allocated_bytes"])
    await h.reader.advance(h.item.provider, through_block=h.end)
    status = h.reader.progress.archive_delivery
    assert (status["removed_files"], status["reclaimed_allocated_bytes"]) == old_counts
    # Ordinary selected readers restore proof bytes through retained R2 receipts.
    key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, h.reader.first_block)
    context, fields = h.reader.export_archive.read("history", key, bounds=h.reader._field_bounds)
    assert context == h.reader._archive_context(h.reader.first_block)
    assert set(fields) == set(h.reader._field_bounds)
    # A fresh native owner resumes the durable cursor and release counters.
    h.reader = reopen(
        h.reader,
        remote,
        export_archive=RewardProofArchive(root, remote=remote, legacy_read_through=True),
    )
    prohibit_proof_replay(monkeypatch, h.reader)
    server.calls.clear()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert server.calls == []
    restarted = h.reader.progress.archive_delivery
    assert (restarted["removed_files"], restarted["reclaimed_allocated_bytes"]) == old_counts


async def test_frame_failure_keeps_native_history_and_retries_only_missing_delivery(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected, _root, server, _remote = await prepare(h, tmp_path)
    prohibit_proof_replay(monkeypatch, h.reader)
    key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, h.reader.first_block)
    server.fail_put_suffix = "frames/history/" + key
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.archive_delivery["state"] == "retrying"
    assert h.reader._next == h.end + 1
    sent = [path for method, path in server.calls if method == "PUT" and "/objects/" in path]
    assert sent
    server.fail_put_suffix = None
    server.calls.clear()
    await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader.progress.archive_delivery["completed_blocks"] == 1
    assert not any(method == "PUT" and path in sent for method, path in server.calls)


async def test_unlink_fsync_interruption_resumes_exact_intent_once(
    history_case, tmp_path, monkeypatch
):
    import os

    from umi import competition_reward_history_archive_backfill as module

    h = history_case
    expected, _root, _server, _remote = await prepare(h, tmp_path, release=True)
    original = os.fsync
    failures = []

    def interrupted(fd):
        if not failures:
            failures.append(1)
            raise OSError("simulated directory fsync interruption")
        return original(fd)

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "fsync", interrupted)
        assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert failures
    assert h.reader.progress.archive_delivery["state"] == "retrying"
    assert h.reader.progress.archive_delivery["removed_files"] == 0
    for _ in range(5):
        await h.reader.advance(h.item.provider, through_block=h.end)
    status = h.reader.progress.archive_delivery
    assert status["removed_files"] == status["queued_files"]
    before = (status["removed_files"], status["reclaimed_allocated_bytes"])
    await h.reader.advance(h.item.provider, through_block=h.end)
    after = h.reader.progress.archive_delivery
    assert (after["removed_files"], after["reclaimed_allocated_bytes"]) == before


async def test_legacy_nonstandard_chunk_boundaries_copy_without_expansion(
    history_case, tmp_path, monkeypatch
):
    import hashlib

    from umi import competition_reward_proof_archive as module
    from umi.competition_evidence_codec import encode_evidence
    from umi.protocol import canonical_json_bytes

    h = history_case
    expected, root, _server, remote = await prepare(h, tmp_path)
    original = RewardProofArchive(root)
    height = h.reader.first_block
    key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, height)
    context, fields = original.read("history", key, bounds=h.reader._field_bounds)
    frame = original._frame("history", key)
    raw = fields["evidence"]
    pieces = (raw[: len(raw) // 2], raw[len(raw) // 2 :])
    parts = []
    for piece in pieces:
        encoded = encode_evidence(piece, kind="proof")
        for body in encoded.objects.values():
            original._retain_bytes(body)
        original._retain_bytes(encoded.recipe)
        parts.append(
            module._Part(
                sha256=encoded.sha256,
                expanded_bytes=len(piece),
                recipe_sha256=hashlib.sha256(encoded.recipe).hexdigest(),
            )
        )
    changed = frame.model_copy(update={"fields": dict(frame.fields, evidence=tuple(parts))})
    original._path("history", key).write_bytes(canonical_json_bytes(changed))

    def forbidden(*args, **kwargs):
        pytest.fail("archive backfill expanded already verified proof bytes")

    with monkeypatch.context() as patch:
        patch.setattr(module, "decode_evidence", forbidden)
        assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.archive_delivery["completed_blocks"] == 1
    assert remote.reference_for_path("frames/history/" + key)
    assert h.reader.export_archive.read("history", key, bounds=h.reader._field_bounds) == (
        context,
        fields,
    )
