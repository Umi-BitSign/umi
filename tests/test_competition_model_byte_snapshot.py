"""Portable selected facts survive filesystem replacement, never changing trust."""

import asyncio
import json
import os
import shutil
from pathlib import Path

import pytest

from umi import competition_model_byte_snapshot as portable
from umi.competition_transport_verification import ByteCheckpoints
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_chunked_model_backup import backup as backup
from .test_competition_chunked_model_backup import other_cohort, retained_files
from .test_competition_model_byte_store import exported, imported
from .test_open_competition import policy as policy


async def captured(case, tmp_path):
    source, pin = await exported(case, tmp_path)
    before = retained_files(source.root)
    saved = portable.capture_portable_snapshot(pin, tmp_path / "portable")
    assert portable.capture_portable_snapshot(pin, tmp_path / "portable") == saved
    assert retained_files(source.root) == before
    assert not case.remote.reads
    return source, saved


async def test_native_reader_reuses_after_old_root_and_backup_are_removed(backup, tmp_path):
    source, pin = await captured(backup, tmp_path)
    shutil.rmtree(source.root)
    destination = tmp_path / "replacement"
    events = []
    first = portable.restore_portable_snapshot(pin, destination, report=events.append)
    assert first["restored_files"] == 7 and first["reused_files"] == 0
    second = portable.restore_portable_snapshot(pin, destination)
    assert second["restored_files"] == 0 and second["reused_files"] == 7
    shutil.rmtree(Path(pin.directory))
    for _ in range(2):
        target = imported(other_cohort(backup), destination, ())
        result = await target.verify(document_paths=("license.txt",))
        target.require_verified(result)
        assert result.documents["license.txt"] == backup.contents["license.txt"].hex()
    assert not backup.remote.reads
    reports = [v for v in events if v["stage"] == "model_byte_portable_restore"]
    assert reports and reports[-1]["completed_units"] == reports[-1]["total_units"]
    assert all("elapsed_seconds" in v and "eta_basis" in v for v in reports)


async def test_interrupted_restore_reuses_each_committed_file(backup, tmp_path, monkeypatch):
    source, pin = await captured(backup, tmp_path)
    shutil.rmtree(source.root)
    destination = tmp_path / "replacement"
    original = ByteCheckpoints.remember
    completed = []

    def interrupt(self, slot, identity, result):
        original(self, slot, identity, result)
        if self.root.is_relative_to(destination):
            completed.append(slot)
            if len(completed) == 5:
                raise asyncio.CancelledError()

    with monkeypatch.context() as patch:
        patch.setattr(ByteCheckpoints, "remember", interrupt)
        with pytest.raises(asyncio.CancelledError):
            portable.restore_portable_snapshot(pin, destination)
    # The already completed license no longer depends on its backup document.
    license_sha = sha256_hex(backup.contents["license.txt"])
    portable.portable_member_path(Path(pin.directory), "documents", license_sha).unlink()
    result = portable.restore_portable_snapshot(pin, destination)
    assert result["reused_files"] == 5 and result["restored_files"] == 2
    target = imported(backup, destination, ())
    await target.verify(document_paths=("license.txt",))
    assert not backup.remote.reads


@pytest.mark.parametrize("fault", ["receipt", "marker", "document"])
async def test_scoped_target_damage_restores_from_portable_metadata(backup, tmp_path, fault):
    source, pin = await captured(backup, tmp_path)
    shutil.rmtree(source.root)
    destination = tmp_path / "replacement"
    portable.restore_portable_snapshot(pin, destination)
    target = imported(backup, destination, ())
    receipt = target._store(None).path("license.txt")
    if fault == "receipt":
        receipt.write_bytes(b"corrupt")
    elif fault == "marker":
        receipt.with_suffix(".complete").unlink()
    else:
        (receipt.parent / (sha256_hex(b"license.txt") + ".document")).write_bytes(b"bad")
    events = []
    portable.restore_portable_snapshot(pin, destination, report=events.append)
    await target.verify(document_paths=("license.txt",))
    assert not backup.remote.reads
    assert any(v["status"] == "repair_required" for v in events)


@pytest.mark.parametrize("fault", ["snapshot", "export", "coverage", "context", "model"])
async def test_changed_selection_refuses_before_creating_destination(backup, tmp_path, fault):
    _, pin = await captured(backup, tmp_path)
    root = Path(pin.directory)
    path = portable.portable_member_path(root, "snapshots", pin.snapshot_sha256)
    if fault == "snapshot":
        path.write_bytes(b"{}")
    elif fault == "export":
        portable.portable_member_path(root, "exports", pin.export_sha256).write_bytes(b"{}")
    elif fault == "coverage":
        value = json.loads(path.read_bytes())
        value["documents"] = []
        raw = canonical_json_bytes(value)
        pin = pin.model_copy(update={"snapshot_sha256": sha256_hex(raw)})
        path = portable.portable_member_path(root, "snapshots", pin.snapshot_sha256)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)
    else:
        field = "context_sha256" if fault == "context" else "model_sha256"
        pin = pin.model_copy(update={field: "00" * 32})
    destination = tmp_path / "refused"
    with pytest.raises((OSError, ValueError)):
        portable.restore_portable_snapshot(pin, destination)
    assert not destination.exists() and not backup.remote.reads


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public"])
async def test_unsafe_portable_metadata_refuses(backup, tmp_path, kind):
    _, pin = await captured(backup, tmp_path)
    path = portable.portable_member_path(Path(pin.directory), "exports", pin.export_sha256)
    if kind == "symlink":
        old = path.with_suffix(".saved")
        path.rename(old)
        path.symlink_to(old)
    elif kind == "hardlink":
        os.link(path, path.with_suffix(".hardlink"))
    else:
        path.chmod(0o644)
    with pytest.raises((OSError, ValueError)):
        portable.restore_portable_snapshot(pin, tmp_path / "refused")
    assert not backup.remote.reads


async def test_generation_change_still_requires_only_affected_native_payload(backup, tmp_path):
    source, pin = await captured(backup, tmp_path)
    shutil.rmtree(source.root)
    destination = tmp_path / "replacement"
    portable.restore_portable_snapshot(pin, destination)
    changed = "chunks/sha256/" + sha256_hex(b"weights")
    backup.remote.etags[changed] = "new-generation"
    target = imported(backup, destination, ())
    await target.verify()
    assert backup.remote.reads == [changed]
    before = retained_files(destination)
    with pytest.raises(ValueError, match="conflicts"):
        portable.restore_portable_snapshot(pin, destination)
    assert retained_files(destination) == before


async def test_missing_backup_document_is_visible_repair_not_payload_fallback(backup, tmp_path):
    _, pin = await captured(backup, tmp_path)
    documents = Path(pin.directory) / "documents"
    for path in documents.rglob("*.document"):
        path.unlink()
    events = []
    with pytest.raises(FileNotFoundError):
        portable.restore_portable_snapshot(pin, tmp_path / "replacement", report=events.append)
    assert not backup.remote.reads
    assert any(v["status"] == "repair_required" for v in events)


async def test_incompatible_verifier_semantics_refuse_before_target_creation(backup, tmp_path):
    source, old = await exported(backup, tmp_path)
    path = source.root / "exports" / (old.export_sha256 + ".json")
    value = json.loads(path.read_bytes())
    value["context"]["semantics"][1][0] = "unknown-verifier/99"
    data = canonical_json_bytes(value)
    changed = old.model_copy(update={"export_sha256": sha256_hex(data)})
    path.with_name(changed.export_sha256 + ".json").write_bytes(data)
    path.with_name(changed.export_sha256 + ".json").chmod(0o600)
    with pytest.raises(ValueError, match="compatible verifier semantics"):
        portable.capture_portable_snapshot(changed, tmp_path / "refused")
    assert not (tmp_path / "refused").exists() and not backup.remote.reads


async def test_portable_restore_cannot_borrow_another_service_UID(backup, tmp_path):
    _, pin = await captured(backup, tmp_path)
    root = Path(pin.directory)
    export = json.loads(
        portable.portable_member_path(root, "exports", pin.export_sha256).read_bytes()
    )
    export["source_identity"][2] = str(os.getuid() + 1)
    data = canonical_json_bytes(export)
    export_sha = sha256_hex(data)
    path = portable.portable_member_path(root, "exports", export_sha)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)
    snapshot = json.loads(
        (portable.portable_member_path(root, "snapshots", pin.snapshot_sha256)).read_bytes()
    )
    snapshot["export_sha256"] = export_sha
    data = canonical_json_bytes(snapshot)
    snapshot_sha = sha256_hex(data)
    path = portable.portable_member_path(root, "snapshots", snapshot_sha)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)
    changed = pin.model_copy(update={"export_sha256": export_sha, "snapshot_sha256": snapshot_sha})
    with pytest.raises(ValueError, match="original service UID"):
        portable.restore_portable_snapshot(changed, tmp_path / "refused")
    assert not (tmp_path / "refused").exists() and not backup.remote.reads
