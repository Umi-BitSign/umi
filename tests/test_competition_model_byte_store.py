"""Account-private cross-root continuity never borrows cohort signing authority."""

import asyncio
import json
import os
from pathlib import Path

import pytest

from umi import competition_model_byte_store as stores
from umi.competition_chunked_model_backup import ChunkedModelBackupReader
from umi.competition_transport_verification import ByteCheckpoints
from umi.private_files import PrivateStateBusyError
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_chunked_model_backup import (
    backup as backup,
)
from .test_competition_chunked_model_backup import (
    legacy_receipts,
    other_cohort,
    reader,
    retained_files,
    selection,
)
from .test_open_competition import policy as policy


def imported(case, root, exports):
    return ChunkedModelBackupReader(
        selection(case),
        policy=case.policy,
        multipart=case.remote,
        verification_root=root,
        byte_store_imports=exports,
    )


async def exported(case, tmp_path):
    source = reader(case, tmp_path / "old")
    await source.verify(document_paths=("license.txt",))
    pin = await source.export_completed()
    case.remote.reads.clear()
    return source, pin


async def test_import_restart_retains_source_and_documents_without_gets(backup, tmp_path):
    source, pin = await exported(backup, tmp_path)
    before = retained_files(source._store(None).root)
    target = imported(other_cohort(backup), tmp_path / "new", (pin,))
    events = []
    for _ in range(2):
        result = await target.verify(document_paths=("license.txt",), report=events.append)
        target.require_verified(result)
    assert not backup.remote.reads
    assert retained_files(source._store(None).root) == before
    assert result.documents["license.txt"] == backup.contents["license.txt"].hex()
    progress = [e for e in events if e["stage"] == "model_byte_store_import"]
    assert progress and all("elapsed_seconds" in e and "eta_basis" in e for e in progress)
    # A complete target remains usable even when the legacy export is no longer mounted.
    (source.root / "exports" / (pin.export_sha256 + ".json")).unlink()
    await target.verify(document_paths=("license.txt",))
    assert not backup.remote.reads


async def test_interrupted_import_resumes_each_committed_item(backup, tmp_path, monkeypatch):
    source, pin = await exported(backup, tmp_path)
    target = imported(backup, tmp_path / "new", (pin,))
    remember = ByteCheckpoints.remember
    completed = []

    def interrupted(self, slot, identity, result):
        remember(self, slot, identity, result)
        if self.root.is_relative_to(target.root):
            completed.append(slot)
            if len(completed) == 3:
                raise asyncio.CancelledError()

    with monkeypatch.context() as patch:
        patch.setattr(ByteCheckpoints, "remember", interrupted)
        with pytest.raises(asyncio.CancelledError):
            await target.verify()
    # Already imported target results do not require their source receipt again.
    for name in completed:
        source._store(None).path(name).unlink()
    restart = imported(backup, target.root, (pin,))
    snapshot = await restart.verify()
    restart.require_verified(snapshot)
    assert len(completed) == 3 and not backup.remote.reads


@pytest.mark.parametrize("fault", ["receipt", "marker", "document", "checksum_forgery"])
async def test_changed_pinned_source_is_repair_gate(backup, tmp_path, fault):
    source, pin = await exported(backup, tmp_path)
    receipt = source._store(None).path("license.txt")
    if fault == "receipt":
        receipt.unlink()
    elif fault == "marker":
        receipt.with_suffix(".complete").unlink()
    elif fault == "document":
        (receipt.parent / (sha256_hex(b"license.txt") + ".document")).write_bytes(b"bad")
    else:
        value = json.loads(receipt.read_bytes())
        value["result"] = "00" * 32
        value.pop("checksum")
        value["checksum"] = sha256_hex(canonical_json_bytes(value))
        receipt.write_bytes(canonical_json_bytes(value))
    target = imported(backup, tmp_path / "new", (pin,))
    events = []
    with pytest.raises((OSError, ValueError)):
        await target.verify(document_paths=("license.txt",), report=events.append)
    assert not backup.remote.reads
    assert any(
        e.get("reason_code") == "byte_store_import_source_missing_or_damaged" for e in events
    )


@pytest.mark.parametrize("fault", ["receipt", "marker", "document", "empty_document"])
async def test_missing_or_corrupt_target_is_restored_without_gets(backup, tmp_path, fault):
    _, pin = await exported(backup, tmp_path)
    target = imported(backup, tmp_path / "new", (pin,))
    await target.verify(document_paths=("license.txt",))
    receipt = target._store(None).path("license.txt")
    if fault == "receipt":
        receipt.write_bytes(b"broken")
    elif fault == "marker":
        receipt.with_suffix(".complete").unlink()
    else:
        (receipt.parent / (sha256_hex(b"license.txt") + ".document")).write_bytes(
            b"" if fault == "empty_document" else b"bad"
        )
    events = []
    result = await target.verify(document_paths=("license.txt",), report=events.append)
    target.require_verified(result)
    assert not backup.remote.reads
    assert any(e["status"] == "repair_required" for e in events)


async def test_changed_generation_checks_only_affected_file(backup, tmp_path):
    _, pin = await exported(backup, tmp_path)
    changed = "chunks/sha256/" + sha256_hex(b"weights")
    backup.remote.etags[changed] = "new-generation"
    target = imported(backup, tmp_path / "new", (pin,))
    events = []
    await target.verify(report=events.append)
    assert backup.remote.reads == [changed]
    assert any(e.get("reason_code") == "byte_store_generation_changed" for e in events)


async def test_generation_changes_during_import_refuse(backup, tmp_path, monkeypatch):
    _, pin = await exported(backup, tmp_path)
    target = imported(backup, tmp_path / "new", (pin,))
    original = ByteCheckpoints.remember

    def remember(self, *args):
        original(self, *args)
        if self.root.is_relative_to(target.root):
            key = next(iter(backup.remote.etags))
            backup.remote.etags[key] = "replaced-during-import"

    monkeypatch.setattr(ByteCheckpoints, "remember", remember)
    with pytest.raises(ValueError, match="generation changed"):
        await target.verify()
    assert not backup.remote.reads


@pytest.mark.parametrize(
    "fault", ["missing", "hash", "file_shape", "coverage", "root", "symlink", "hardlink"]
)
async def test_import_envelope_and_paths_refuse(backup, tmp_path, fault):
    source, pin = await exported(backup, tmp_path)
    path = source.root / "exports" / (pin.export_sha256 + ".json")
    if fault == "missing":
        path.unlink()
    elif fault == "hash":
        path.write_bytes(b"{}")
    elif fault in {"file_shape", "coverage", "root"}:
        value = json.loads(path.read_bytes())
        if fault == "file_shape":
            value["files"][0]["receipt"] = {}
        elif fault == "coverage":
            value["files"][0]["path"] = "another.txt"
        else:
            value["source_identity"][1] = "0"
        raw = canonical_json_bytes(value)
        pin = pin.model_copy(update={"export_sha256": sha256_hex(raw)})
        path = path.with_name(pin.export_sha256 + ".json")
        path.write_bytes(raw)
        path.chmod(0o600)
    elif fault == "symlink":
        old = path.with_suffix(".retained")
        path.rename(old)
        path.symlink_to(old)
    else:
        os.link(path, path.with_suffix(".hardlink"))
    target = imported(backup, tmp_path / "new", (pin,))
    events = []
    with pytest.raises((OSError, ValueError)):
        await target.verify(report=events.append)
    assert not backup.remote.reads
    assert any(e["status"] == "repair_required" for e in events)


async def test_foreign_package_context_does_not_import(backup, tmp_path):
    source, pin = await exported(backup, tmp_path)
    path = source.root / "exports" / (pin.export_sha256 + ".json")
    value = json.loads(path.read_bytes())
    value["context"]["policy"] = "aa" * 32
    raw = canonical_json_bytes(value)
    pin = pin.model_copy(update={"export_sha256": sha256_hex(raw)})
    path = path.with_name(pin.export_sha256 + ".json")
    path.write_bytes(raw)
    path.chmod(0o600)
    await imported(backup, tmp_path / "new", (pin,)).verify()
    assert len(backup.remote.reads) == len(backup.bundle.files)


async def test_export_incomplete_marker_refuses(backup, tmp_path):
    source, _ = await exported(backup, tmp_path)
    source._store(None).path("weights.txt").with_suffix(".complete").unlink()
    events = []
    with pytest.raises(FileNotFoundError):
        await source.export_completed(report=events.append)
    assert any(e.get("reason_code") == "byte_store_export_incomplete" for e in events)
    assert not backup.remote.reads


async def test_shared_store_lock_contention_is_bounded_then_reuses(backup, tmp_path):
    first = reader(backup, tmp_path)
    second = reader(other_cohort(backup), tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    original = backup.remote.read_range

    async def block(*args, **kwargs):
        entered.set()
        await release.wait()
        return await original(*args, **kwargs)

    backup.remote.read_range = block
    task = asyncio.create_task(first.verify())
    await entered.wait()
    try:
        with pytest.raises(PrivateStateBusyError):
            await second.verify()
    finally:
        release.set()
        await task
    count = len(backup.remote.reads)
    await second.verify()
    assert len(backup.remote.reads) == count


def test_shared_config_preserves_exact_paths_and_refuses_aliases(tmp_path):
    from umi.competition_cohort_legacy_model_selection import LegacyModelStorageSourceConfig

    root = str(tmp_path / "shared")
    source = LegacyModelStorageSourceConfig(
        schema="umi-legacy-model-storage-source/1",
        cohort_sha256="01" * 32,
        directory=str(tmp_path / "originals"),
        baseline_model_sha256="02" * 32,
    )
    raw = canonical_json_bytes(source)
    assert b"shared_byte_store" not in raw
    assert canonical_json_bytes(type(source).model_validate_json(raw)) == raw
    config = stores.ModelByteStoreConfig(
        schema="umi-model-byte-verification-store/1", directory=root
    )
    a = source.model_copy(update={"shared_byte_store": config})
    b = source.model_copy(update={"cohort_sha256": "03" * 32, "shared_byte_store": config})
    assert stores.shared_byte_store_paths((a, b)) == (Path(root),)
    for path in (root, root + "/child", str(tmp_path)):
        with pytest.raises(ValueError, match="overlaps"):
            stores.validate_shared_byte_stores((a, b), (path,))
    changed = config.model_copy(
        update={
            "imports": (
                stores.ModelByteStoreImport(
                    directory=str(tmp_path / "old"),
                    export_sha256="04" * 32,
                ),
            )
        }
    )
    with pytest.raises(ValueError, match="conflict"):
        stores.validate_shared_byte_stores((a, b.model_copy(update={"shared_byte_store": changed})))


async def test_old_selection_receipts_export_without_payload_recheck(backup, tmp_path):
    old = tmp_path / "old"
    legacy = await legacy_receipts(backup, old)
    before = retained_files(legacy)
    source = reader(backup, old)
    # Installation provisioning seals old intermediate roots made under umask002.
    source.root.chmod(0o700)
    backup.remote.reads.clear()
    pin = await source.export_completed()
    target = imported(other_cohort(backup), tmp_path / "new", (pin,))
    await target.verify(document_paths=("license.txt",))
    assert not backup.remote.reads
    assert retained_files(legacy) == before


async def test_export_account_mismatch_refuses(backup, tmp_path, monkeypatch):
    source, _ = await exported(backup, tmp_path)
    actual = os.getuid()
    monkeypatch.setattr(stores.os, "getuid", lambda: actual + 1)
    with pytest.raises(ValueError, match="owned"):
        stores._directory_identity(source.root)


async def test_cross_root_receipts_survive_cold_interpreter(backup, tmp_path):
    import subprocess
    import sys

    _, pin = await exported(backup, tmp_path)
    target = tmp_path / "cold-target"
    script = """
import asyncio, json, sys
from pathlib import Path
from umi.competition_chunked_model_backup import ChunkedModelBackupReader
from umi.competition_model_byte_store import ModelByteStoreImport
from umi.open_competition import CompetitionPolicy
from tests.test_competition_chunked_model_backup import selected, selection
async def main():
    case = selected(CompetitionPolicy.model_validate_json(sys.argv[1]))
    target = ChunkedModelBackupReader(selection(case), policy=case.policy,
        multipart=case.remote, verification_root=Path(sys.argv[2]),
        byte_store_imports=(ModelByteStoreImport.model_validate_json(sys.argv[3]),))
    snapshot = await target.verify(document_paths=('license.txt',))
    target.require_verified(snapshot)
    print(json.dumps({'reads':len(case.remote.reads)}))
asyncio.run(main())
"""
    repo = Path(__file__).resolve().parents[1]
    for _ in range(2):
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                script,
                canonical_json_bytes(backup.policy).decode(),
                str(target),
                canonical_json_bytes(pin).decode(),
            ],
            cwd=repo,
            env={**os.environ, "PYTHONPATH": str(repo / "src")},
            capture_output=True,
            text=True,
            check=False,
        )
        assert process.returncode == 0, process.stderr
        assert json.loads(process.stdout) == {"reads": 0}


def test_namespace_preflight_refuses_read_only_target_before_use(tmp_path, monkeypatch):
    from types import SimpleNamespace

    root = tmp_path / "shared"
    selected = stores.ModelByteStoreConfig(
        schema="umi-model-byte-verification-store/1", directory=str(root)
    )
    events = []

    def readonly(_):
        raise PermissionError("namespace is read only")

    monkeypatch.setattr(stores, "lock_private_file", readonly)
    with pytest.raises(PermissionError):
        stores.qualify_shared_byte_stores(
            (SimpleNamespace(shared_byte_store=selected),), report=events.append
        )
    assert any(e.get("reason_code") == "model_byte_store_namespace_unavailable" for e in events)
