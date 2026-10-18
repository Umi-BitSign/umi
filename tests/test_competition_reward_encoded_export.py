"""Compact export preserves bytes and never substitutes for native success."""

import hashlib
import sqlite3

import pytest

from umi.competition_evidence_codec import MAX_EVIDENCE_BYTES, encode_evidence
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


def encoded(raw, *, legacy=False):
    item = encode_evidence(raw, kind="proof")
    if legacy:
        recipe = canonical_json_bytes(
            {
                "schema": "umi-weight-evidence-recipe/1",
                "length": len(raw),
                "segments": [["b", item.sha256, len(raw)]],
            }
        )
        return (item.sha256, len(raw), recipe), {item.sha256: raw}
    return (item.sha256, len(raw), item.recipe), item.objects


@pytest.mark.parametrize("legacy", [False, True])
def test_compact_transport_round_trip_and_repeat_preserve_exact_recipes(tmp_path, legacy):
    raw = b'{"proof":"' + b"ab" * 4096 + b'"}'
    part, objects = encoded(raw, legacy=legacy)
    archive = RewardProofArchive(tmp_path / "archive")
    for _ in range(2):
        assert archive.copy_encoded_transport(
            "history",
            "a" * 64,
            context={"block": 3},
            fields={"evidence": (part,)},
            resolve=lambda sha, size: objects[sha],
        )
        assert archive.read("history", "a" * 64, bounds={"evidence": len(raw)}) == (
            {"block": 3},
            {"evidence": raw},
        )
    frame = archive._frame("history", "a" * 64)
    assert frame.fields["evidence"][0].recipe_sha256 == hashlib.sha256(part[2]).hexdigest()


def test_existing_other_representation_requests_original_fallback_without_writing(tmp_path):
    raw = b'{"proof":"' + b"ab" * 4096 + b'"}'
    part, _ = encoded(raw, legacy=True)
    archive = RewardProofArchive(tmp_path / "archive")
    archive.write("history", "a" * 64, context={}, fields={"evidence": raw})
    before = {p.relative_to(archive.root): p.read_bytes() for p in archive.root.rglob("*.json")}

    def forbidden(*args):
        pytest.fail("different retained destination must use its original fallback")

    assert not archive.copy_encoded_transport(
        "history", "a" * 64, context={}, fields={"evidence": (part,)}, resolve=forbidden
    )
    assert before == {
        p.relative_to(archive.root): p.read_bytes() for p in archive.root.rglob("*.json")
    }


@pytest.mark.parametrize("failure", ["bytes", "length", "interrupted"])
def test_bad_or_interrupted_objects_publish_no_frame_and_can_resume(tmp_path, failure):
    raw = b'{"proof":"' + b"ab" * 4096 + b'"}'
    part, objects = encoded(raw)
    archive = RewardProofArchive(tmp_path / "archive")

    def broken(sha, size):
        if failure == "interrupted":
            raise OSError("delivery interrupted")
        return b"?" * (size if failure == "bytes" else size + 1)

    with pytest.raises((ValueError, OSError)):
        archive.copy_encoded_transport(
            "history", "a" * 64, context={}, fields={"evidence": (part,)}, resolve=broken
        )
    assert not archive._path("history", "a" * 64).exists()
    assert archive.copy_encoded_transport(
        "history",
        "a" * 64,
        context={},
        fields={"evidence": (part,)},
        resolve=lambda sha, size: objects[sha],
    )
    assert archive.read("history", "a" * 64, bounds={"evidence": len(raw)})[1]["evidence"] == raw


def test_transport_metadata_cannot_substitute_for_expanded_hash_verification(tmp_path):
    part, objects = encoded(b"original")
    forged = ("e" * 64, part[1], part[2])
    archive = RewardProofArchive(tmp_path / "archive")
    assert archive.copy_encoded_transport(
        "history",
        "a" * 64,
        context={},
        fields={"evidence": (forged,)},
        resolve=lambda sha, size: objects[sha],
    )
    with pytest.raises(ValueError):
        archive.read("history", "a" * 64, bounds={"evidence": 1024})


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_completed_new_export_never_expands_proofs_and_restart_reuses_receipt(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    archive = RewardProofArchive(tmp_path / "new-export")
    h.reader.export_archive = archive

    def forbidden(*args, **kwargs):
        pytest.fail("completed export expanded or reverified original proof bytes")

    monkeypatch.setattr(h.reader, "_load", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.native_completed == 0
    retained = [h.reader.checkpoints.load(n) for n in range(h.old.height, h.end + 1)]
    assert all(value["exports"] for value in retained)
    for value in retained:
        height = value["snapshot"]["block_number"]
        _, fields = archive.read(
            "history",
            history_archive_key(h.reader.config_sha256, h.reader.hotkey, height),
            bounds={
                "slot_evidence": 64 * 1024**2,
                "slot_metadata": 16 * 1024**2,
                "evidence": 128 * 1024**2,
            },
        )
        assert hashlib.sha256(fields["slot_evidence"]).hexdigest() == value["slot_evidence_sha256"]
        assert hashlib.sha256(fields["slot_metadata"]).hexdigest() == value["slot_metadata_sha256"]
        assert hashlib.sha256(fields["evidence"]).hexdigest() == value["write_evidence_sha256"]
    h.reader = await h.restart()
    h.reader.export_archive = archive
    monkeypatch.setattr(h.reader, "_load", forbidden)
    monkeypatch.setattr(archive, "copy_encoded_transport", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("when", ["before", "during"])
async def test_changed_source_never_gets_export_receipt(history_case, tmp_path, monkeypatch, when):
    from umi.competition_reward_history import _FIELDS
    from umi.competition_reward_history_export import export_completed_checkpoint

    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.old.height)
    value = h.reader.checkpoints.load(h.old.height)
    archive = RewardProofArchive(tmp_path / "new-export")
    h.reader.export_archive = archive

    def change():
        with sqlite3.connect(h.reader.journal.path) as db:
            db.execute(
                "UPDATE records SET body=body WHERE kind=? AND id=?",
                ("control_history_block", str(h.old.height)),
            )

    if when == "before":
        change()
    else:
        load = h.reader.checkpoints.load
        calls = 0

        def changed(height):
            nonlocal calls
            calls += 1
            if calls == 2:
                # The source read transaction protects the copy. A later
                # mutation must still fail before completion is remembered.
                change()
            return load(height)

        monkeypatch.setattr(h.reader.checkpoints, "load", changed)
    with pytest.raises(HistoryCheckpointRepairRequired):
        export_completed_checkpoint(h.reader, value, field_limits=_FIELDS)
    assert value["exports"] == []


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_lost_compact_export_acknowledgement_reuses_durable_completion(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.old.height)
    h.reader = await h.restart()
    archive = RewardProofArchive(tmp_path / "new-export")
    h.reader.export_archive = archive
    remember = h.reader.checkpoints.remember

    def lost_ack(*args, **kwargs):
        remember(*args, **kwargs)
        raise OSError("completion acknowledgement lost")

    monkeypatch.setattr(h.reader.checkpoints, "remember", lost_ack)
    with pytest.raises(OSError, match="acknowledgement"):
        await h.reader.advance(h.item.provider, through_block=h.old.height)
    assert h.reader.checkpoints.load(h.old.height)["exports"]
    h.reader = await h.restart()
    h.reader.export_archive = archive

    def forbidden(*args, **kwargs):
        pytest.fail("durable export was repeated after lost acknowledgement")

    monkeypatch.setattr(h.reader, "_load", forbidden)
    monkeypatch.setattr(archive, "copy_encoded_transport", forbidden)
    assert (await h.reader.advance(h.item.provider, through_block=h.old.height)).history is not None


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("existing_destination", [False, True])
async def test_completed_legacy_boundaries_rechunk_only_affected_field_and_restart(
    history_case, tmp_path, monkeypatch, existing_destination
):
    from umi import competition_reward_history as module

    h = history_case
    height = h.old.height
    expected = await h.reader.advance(h.item.provider, through_block=height)
    fields = h.reader._load(height)
    journal = h.reader.journal
    with journal.read_transaction() as db:
        frame = journal.get("control_history_block", str(height), db=db)
    raw = fields["evidence"]
    midpoint = len(raw) // 2
    assert 0 < midpoint < len(raw) < MAX_EVIDENCE_BYTES
    chunks = [encode_evidence(part, kind="proof") for part in (raw[:midpoint], raw[midpoint:])]
    records = []
    for chunk in chunks:
        records.append(
            (
                "control_history_chunk",
                chunk.sha256,
                {"length": chunk.expanded_bytes, "recipe_hex": chunk.recipe.hex()},
            )
        )
        records.extend(
            ("control_history_object", sha, {"hex": value.hex()})
            for sha, value in chunk.objects.items()
        )
    journal.put_many(records)
    frame["evidence"] = [chunk.sha256 for chunk in chunks]
    with journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind='control_history_block' AND id=?",
            (canonical_json_bytes(frame), str(height)),
        )
    # Obtain a genuine native checkpoint for this supported historical layout.
    # Its source identities must name the changed frame and both original parts.
    h.reader = await h.restart()
    assert (
        await h.reader.repair_checkpoints(
            h.item.provider, through_block=height, reason="qualify retained legacy chunk layout"
        )
        == expected
    )
    checkpoint = h.reader.checkpoints.load(height)
    assert all(
        ["control_history_chunk", chunk.sha256] in [source[:2] for source in checkpoint["sources"]]
        for chunk in chunks
    )
    h.reader = await h.restart()
    archive = RewardProofArchive(tmp_path / "legacy-export")
    h.reader.export_archive = archive
    key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, height)
    if existing_destination:
        archive.write("history", key, context=h.reader._archive_context(height), fields=fields)
    write, prepared_fields = archive.write, []

    def observed_write(*args, **kwargs):
        prepared_fields.append(set(kwargs["prepared_encodings"]))
        return write(*args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("completed legacy checkpoint repeated native verification")

    monkeypatch.setattr(archive, "write", observed_write)
    monkeypatch.setattr(module, "review_control_writes", forbidden)
    monkeypatch.setattr(module, "capture_control_writes", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=height) == expected
    assert prepared_fields == [{"slot_evidence", "slot_metadata"}]
    assert archive.read("history", key, bounds=module._FIELDS)[1] == fields
    assert len(archive._frame("history", key).fields["evidence"]) == 1
    assert h.reader.checkpoints.load(height)["sources"] == checkpoint["sources"]
    with journal.read_transaction() as db:
        assert journal.get("control_history_block", str(height), db=db) == frame
    h.reader = await h.restart()
    h.reader.export_archive = archive
    monkeypatch.setattr(h.reader, "_load", forbidden)
    monkeypatch.setattr(archive, "copy_encoded_transport", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=height) == expected


def test_remote_compact_transport_multiple_parts(tmp_path):
    class Store:
        def __init__(self):
            self.data = {}

        def put_bytes(self, raw, *, path=None):
            sha = hashlib.sha256(raw).hexdigest()
            self.data[path or "objects/" + sha] = raw
            return {"content_sha256": sha}

        def read_path(self, path, *, maximum):
            if path not in self.data:
                raise FileNotFoundError(path)
            raw = self.data[path]
            assert len(raw) <= maximum
            return raw

        def read_object(self, sha, *, maximum):
            return self.read_path("objects/" + sha, maximum=maximum)

    values = [b"a" * MAX_EVIDENCE_BYTES, b"second part"]
    parts, objects = [], {}
    for raw in values:
        part, found = encoded(raw)
        parts.append(part)
        objects.update(found)
    archive = RewardProofArchive(tmp_path / "archive", remote=Store())
    assert archive.copy_encoded_transport(
        "history",
        "a" * 64,
        context={},
        fields={"evidence": tuple(parts)},
        resolve=lambda sha, size: objects[sha],
    )
    assert archive.read("history", "a" * 64, bounds={"evidence": MAX_EVIDENCE_BYTES + 1024})[1][
        "evidence"
    ] == b"".join(values)


def test_completed_compact_copy_does_not_resolve_unchanged_published_objects(tmp_path, monkeypatch):
    from umi import competition_reward_proof_archive as module

    monkeypatch.setattr(module, "_publication_clock_ns", lambda: 2**63 - 1)
    raw = b'{"proof":"' + b"ab" * 4096 + b'"}'
    part, objects = encoded(raw)
    archive = RewardProofArchive(tmp_path / "archive")
    kwargs = dict(context={}, fields={"evidence": (part,)})
    assert archive.copy_encoded_transport(
        "history", "a" * 64, resolve=lambda sha, size: objects[sha], **kwargs
    )
    before = {p.relative_to(archive.root): p.read_bytes() for p in archive.root.rglob("*.json")}

    def forbidden(*args):
        pytest.fail("unchanged completed publication needs no source payload read")

    assert archive.copy_encoded_transport("history", "a" * 64, resolve=forbidden, **kwargs)
    assert before == {
        p.relative_to(archive.root): p.read_bytes() for p in archive.root.rglob("*.json")
    }


@pytest.mark.parametrize(
    "change", ["corrupt", "replace", "delete", "fresh_owner", "fork", "unqualified_tick"]
)
def test_compact_copy_cannot_reuse_changed_or_unqualified_transport_presence(
    tmp_path, monkeypatch, change
):
    from umi import competition_reward_proof_archive as module

    monkeypatch.setattr(
        module, "_publication_clock_ns", lambda: 0 if change == "unqualified_tick" else 2**63 - 1
    )
    raw = b"original-object"
    part, objects = encoded(raw)
    archive = RewardProofArchive(tmp_path / "archive")
    kwargs = dict(context={}, fields={"evidence": (part,)})
    assert archive.copy_encoded_transport(
        "history", "a" * 64, resolve=lambda sha, size: objects[sha], **kwargs
    )
    sha = next(iter(objects))
    path = archive.root / "objects" / (sha + ".json")
    if change == "corrupt":
        path.write_bytes(canonical_json_bytes({"hex": b"modified-object".hex()}))
    elif change == "replace":
        original = path.read_bytes()
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o600)
    elif change == "delete":
        path.unlink()
    elif change == "fresh_owner":
        archive = RewardProofArchive(archive.root)
    elif change == "fork":
        monkeypatch.setattr(module.os, "getpid", lambda: archive._pid + 1)
    resolved = []

    def resolve(sha, size):
        resolved.append(sha)
        return objects[sha]

    if change == "corrupt":
        with pytest.raises(ValueError, match="different bytes"):
            archive.copy_encoded_transport("history", "a" * 64, resolve=resolve, **kwargs)
    else:
        assert archive.copy_encoded_transport("history", "a" * 64, resolve=resolve, **kwargs)
    assert sha in resolved


def test_transport_presence_cannot_alias_another_object_length(tmp_path, monkeypatch):
    from umi import competition_reward_proof_archive as module

    monkeypatch.setattr(module, "_publication_clock_ns", lambda: 2**63 - 1)
    archive = RewardProofArchive(tmp_path / "archive")
    raw = b"original-object"
    sha = archive._retain_bytes(raw)
    assert not archive._published_object_present(sha, len(raw) + 1)
