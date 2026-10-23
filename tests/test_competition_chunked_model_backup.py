"""Legacy signed manifests remain unchanged through chunked R2 restoration."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_chunked_model_backup as chunked
from umi.competition_artifacts import verify_preserved_bundle
from umi.competition_chunked_model_backup import (
    CHUNK_BYTES,
    ChunkedBackupBinding,
    ChunkedModelBackupReader,
    validate_chunked_backup,
)
from umi.competition_transport_verification import ByteCheckpoints
from umi.open_competition import BundleFile, ModelBundle, digest
from umi.protocol import canonical_json_bytes, sha256_hex
from umi.r2_multipart import R2ObjectHead

from .test_open_competition import policy as policy


class Remote:
    def __init__(self, objects):
        self.objects = objects
        self.signer = SimpleNamespace(
            endpoint="https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
            bucket="umi-model-artifacts",
        )
        self.etags = dict.fromkeys(objects, "original-generation")
        self.reads = []
        self.heads = []
        self.fail = None
        self.change = None

    async def head(self, key):
        self.heads.append(key)
        raw = self.objects.get(key)
        return None if raw is None else R2ObjectHead(size_bytes=len(raw), etag=self.etags[key])

    async def read_range(self, key, *, offset, size_bytes):
        assert offset == 0 and 0 < size_bytes <= CHUNK_BYTES
        if self.fail == key:
            raise OSError("interrupted fixture download")
        self.reads.append(key)
        if self.change == key:
            self.etags[key] = "changed-generation"
        return self.objects[key][offset : offset + size_bytes]


def selected(policy, *, weights=b"weights", mutation=None, object_key_prefix=""):
    contents = {
        role + ".txt": weights if role == "weights" else role.encode()
        for role in (
            "config",
            "environment",
            "inference",
            "license",
            "processor",
            "provenance",
            "weights",
        )
    }
    bundle = ModelBundle(
        schema="umi-model-bundle/1",
        profile="offline_bundle/1",
        parent_baseline_sha256=None,
        license_id="CC-BY-SA-4.0",
        files=tuple(
            BundleFile(
                path=name, role=name.split(".")[0], sha256=sha256_hex(raw), size_bytes=len(raw)
            )
            for name, raw in sorted(contents.items())
        ),
    )
    objects = {}
    files = []
    for record in bundle.files:
        chunks = []
        raw = contents[record.path]
        for offset in range(0, len(raw), CHUNK_BYTES):
            part = raw[offset : offset + CHUNK_BYTES]
            key = sha256_hex(part)
            objects[object_key_prefix + "chunks/sha256/" + key] = part
            chunks.append({"sha256": key, "size_bytes": len(part)})
        files.append({"path": record.path, "chunks": chunks})
    package = {
        "schema": "umi-cohort-model-preserved-package/1",
        "model_sha256": digest(bundle),
        "native_bundle": bundle.model_dump(mode="json", by_alias=True),
        "files": files,
        "chunk_bytes": CHUNK_BYTES,
        "policy_sha256": digest(policy),
        "source": "verified_native_c5_artifact_archive",
        "rights_approved": False,
        "benchmark_certified": False,
        "rewards_authorized": False,
    }
    if mutation is not None:
        mutation(package)
    raw_package = canonical_json_bytes(package)
    package_sha = sha256_hex(raw_package)
    association = {
        "schema": "umi-cohort-model-backup-association/1",
        "model_sha256": digest(bundle),
        "package_key": f"packages/{digest(bundle)}/{package_sha}.json",
        "package_sha256": package_sha,
        "verification": "all_declared_bytes_uploaded_and_read_back",
        "artifact_acceptance_certified": False,
    }
    raw_association = canonical_json_bytes(association)
    remote = Remote(objects)
    binding = ChunkedBackupBinding(
        schema="umi-chunked-model-backup-binding/1",
        association_sha256=sha256_hex(raw_association),
        model_sha256=digest(bundle),
        policy_sha256=digest(policy),
        provenance_sha256="12" * 32,
        endpoint=remote.signer.endpoint,
        bucket=remote.signer.bucket,
        object_key_prefix=object_key_prefix,
    )
    return SimpleNamespace(
        bundle=bundle,
        contents=contents,
        remote=remote,
        raw_association=raw_association,
        raw_package=raw_package,
        raw_manifest=canonical_json_bytes(bundle),
        binding=binding,
        policy=policy,
    )


def selection(case, **changes):
    return validate_chunked_backup(
        changes.get("raw_association", case.raw_association),
        changes.get("raw_package", case.raw_package),
        changes.get("raw_manifest", case.raw_manifest),
        policy=changes.get("policy", case.policy),
        binding=changes.get("binding", case.binding),
    )


def reader(case, tmp_path, **changes):
    return ChunkedModelBackupReader(
        selection(case),
        policy=case.policy,
        multipart=changes.get("multipart", case.remote),
        verification_root=tmp_path / "verification",
    )


def remote_receipt_root(case, tmp_path):
    return reader(case, tmp_path)._store(None).root


@pytest.fixture
def backup(policy):
    return selected(policy)


def test_exact_legacy_metadata_retains_original_manifest_and_non_authority(backup):
    actual = selection(backup)
    assert canonical_json_bytes(actual.bundle) == backup.raw_manifest
    assert actual.association.artifact_acceptance_certified is False
    assert actual.package.rewards_authorized is False


@pytest.mark.parametrize("field", ["raw_association", "raw_package", "raw_manifest"])
def test_noncanonical_metadata_refuses(backup, field):
    with pytest.raises(ValueError, match="not canonical"):
        selection(backup, **{field: getattr(backup, field) + b"\n"})


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(rewards_authorized=True),
        lambda p: p.update(chunk_bytes=4 * 1024**2),
        lambda p: p.update(source="unverified_source"),
        lambda p: p["files"].reverse(),
        lambda p: p["files"].pop(),
        lambda p: p["files"][0].update(path="../escape"),
        lambda p: p["files"][0]["chunks"].clear(),
        lambda p: p["files"][0]["chunks"][0].update(size_bytes=1),
        lambda p: p["files"][0]["chunks"].append(copy.deepcopy(p["files"][0]["chunks"][0])),
        lambda p: p["native_bundle"]["files"][0].update(path="../escape"),
        lambda p: p.update(policy_sha256="34" * 32),
    ],
)
def test_wrong_package_shape_or_coverage_refuses(policy, mutation):
    case = selected(policy, mutation=mutation)
    with pytest.raises(ValueError):
        selection(case)


@pytest.mark.parametrize("field", ["association_sha256", "model_sha256", "policy_sha256"])
def test_changed_authenticated_pin_refuses(backup, field):
    with pytest.raises(ValueError):
        selection(backup, binding=backup.binding.model_copy(update={field: "34" * 32}))


def test_association_key_and_unknown_fields_refuse(backup):
    raw = json.loads(backup.raw_association)
    raw["package_key"] = "packages/other.json"
    with pytest.raises(ValueError, match="key differs"):
        selection(backup, raw_association=canonical_json_bytes(raw))
    raw = json.loads(backup.raw_association)
    raw["extra"] = True
    with pytest.raises(ValueError):
        selection(backup, raw_association=canonical_json_bytes(raw))


def test_reader_refuses_wrong_provider_namespace_before_remote_work(backup, tmp_path):
    backup.remote.signer.bucket = "other-model-artifacts"
    with pytest.raises(ValueError, match="namespace differs"):
        reader(backup, tmp_path)
    assert not backup.remote.reads and not backup.remote.heads


@pytest.mark.asyncio
async def test_restart_reuses_completed_remote_files_and_documents_without_gets(backup, tmp_path):
    first = await reader(backup, tmp_path).verify(document_paths=("license.txt", "provenance.txt"))
    reads = tuple(backup.remote.reads)
    second = await reader(backup, tmp_path).verify(document_paths=("license.txt", "provenance.txt"))
    assert first == second
    assert bytes.fromhex(first.documents["license.txt"]) == b"license"
    assert tuple(backup.remote.reads) == reads
    assert len(first.objects) == 7


def other_cohort(case):
    other = copy.copy(case)
    other.binding = case.binding.model_copy(update={"provenance_sha256": "34" * 32})
    return other


async def legacy_receipts(case, tmp_path):
    """Exercise the exact previous receipt context/layout using native byte checks."""
    actual = reader(case, tmp_path)
    actual._store = lambda progress: ByteCheckpoints(
        actual.root / digest(case.bundle) / "remote", actual._context(), progress
    )
    actual._migrate_remote_receipts = lambda *args, **kwargs: None
    await actual.verify(document_paths=("license.txt",))
    # A real pre-file-sharing release could not have produced these facts.
    for name in ("shared-file-bytes-v1", "shared-file-index-v1"):
        shutil.rmtree(actual.root / name, ignore_errors=True)
    return actual.root / digest(case.bundle) / "remote"


def retained_files(root):
    return {
        p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
        for p in root.iterdir()
        if p.suffix in {".json", ".complete", ".document"}
    }


@pytest.mark.asyncio
async def test_two_cohort_selections_share_byte_facts_without_sharing_authority(backup, tmp_path):
    other = other_cohort(backup)
    first = await reader(backup, tmp_path).verify(document_paths=("license.txt",))
    original_reads = tuple(backup.remote.reads)
    second = await reader(other, tmp_path).verify(document_paths=("license.txt",))
    assert first.selection_sha256 != second.selection_sha256
    assert first.documents == second.documents
    for case, snapshot in ((backup, first), (other, second), (backup, first)):
        restarted = reader(case, tmp_path)
        assert await restarted.verify(document_paths=("license.txt",)) == snapshot
        restarted.require_verified(snapshot)
    assert tuple(backup.remote.reads) == original_reads
    with pytest.raises(ValueError, match="selected source"):
        reader(other, tmp_path).require_verified(first)
    with pytest.raises(ValueError, match="selected source"):
        reader(backup, tmp_path).require_verified(second)

    # A real new interpreter reopens both selections and completed receipts.
    script = """
import asyncio, json, sys
from pathlib import Path
from umi.open_competition import CompetitionPolicy
from tests.test_competition_chunked_model_backup import selected, other_cohort, reader
async def main():
    case = selected(CompetitionPolicy.model_validate_json(sys.argv[2]))
    for current in (other_cohort(case), case, other_cohort(case)):
        actual = reader(current, Path(sys.argv[1]))
        result = await actual.verify(document_paths=('license.txt',))
        actual.require_verified(result)
    print(json.dumps({'reads': len(case.remote.reads)}))
asyncio.run(main())
"""
    process = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            script,
            str(tmp_path),
            canonical_json_bytes(backup.policy).decode(),
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout) == {"reads": 0}


@pytest.mark.asyncio
async def test_legacy_migration_preserves_originals_documents_and_completed_bytes(backup, tmp_path):
    legacy = await legacy_receipts(backup, tmp_path)
    originals = retained_files(legacy)
    backup.remote.reads.clear()
    events = []
    migrated = await reader(backup, tmp_path).verify(
        document_paths=("license.txt",), report=events.append
    )
    shared = await reader(other_cohort(backup), tmp_path).verify(document_paths=("license.txt",))
    assert migrated.documents == shared.documents == {"license.txt": b"license".hex()}
    assert backup.remote.reads == []
    assert retained_files(legacy) == originals
    migration = [e for e in events if e["stage"] == "chunked_model_receipt_migration"]
    assert migration[0]["planning_eta_seconds"] is not None
    assert migration[-1]["completed_units"] == migration[-1]["total_units"] == 7
    assert migration[-1]["status"] == "completed"
    assert migration[-1]["eta_seconds"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("marker_state", ["missing", "damaged"])
async def test_legacy_migration_preserves_incomplete_original_markers(
    backup, tmp_path, marker_state
):
    legacy = await legacy_receipts(backup, tmp_path)
    name = sha256_hex(canonical_json_bytes("weights.txt"))
    marker = legacy / (name + ".complete")
    if marker_state == "missing":
        marker.unlink()
    else:
        marker.write_bytes(b"damaged original marker")
    originals = retained_files(legacy)
    backup.remote.reads.clear()
    snapshot = await reader(backup, tmp_path).verify()
    assert retained_files(legacy) == originals
    assert backup.remote.reads == []
    new_marker = remote_receipt_root(backup, tmp_path) / marker.name
    assert new_marker.read_bytes() == name.encode()
    reader(backup, tmp_path).require_verified(snapshot)
    assert await reader(other_cohort(backup), tmp_path).verify()
    assert retained_files(legacy) == originals
    assert backup.remote.reads == []


@pytest.mark.asyncio
async def test_interrupted_legacy_migration_reuses_each_committed_file(
    backup, tmp_path, monkeypatch
):
    legacy = await legacy_receipts(backup, tmp_path)
    originals = retained_files(legacy)
    backup.remote.reads.clear()
    remember = ByteCheckpoints.remember
    migrated = []

    def interrupted(saved, slot, identity, result):
        remember(saved, slot, identity, result)
        if saved.root.parent.name == "remote-bytes-v2":
            migrated.append(slot)
            if len(migrated) == 3:
                raise OSError("interrupted receipt migration")

    with monkeypatch.context() as patch:
        patch.setattr(ByteCheckpoints, "remember", interrupted)
        with pytest.raises(OSError, match="interrupted receipt"):
            await reader(backup, tmp_path).verify(document_paths=("license.txt",))
    shared_root = remote_receipt_root(backup, tmp_path)
    completed = retained_files(shared_root)
    await reader(backup, tmp_path).verify(document_paths=("license.txt",))
    current = retained_files(shared_root)
    assert all(current[key] == value for key, value in completed.items())
    assert retained_files(legacy) == originals
    assert backup.remote.reads == []


@pytest.mark.asyncio
async def test_foreign_legacy_selection_requires_preserving_migration_not_reverification(
    backup, tmp_path
):
    legacy = await legacy_receipts(backup, tmp_path)
    originals = retained_files(legacy)
    backup.remote.reads.clear()
    events = []
    with pytest.raises(OSError, match="original authenticated selection"):
        await reader(other_cohort(backup), tmp_path).verify(report=events.append)
    assert backup.remote.reads == []
    assert retained_files(legacy) == originals
    assert any(e["reason_code"] == "chunked_model_legacy_selection_required" for e in events)
    await reader(backup, tmp_path).verify()
    await reader(other_cohort(backup), tmp_path).verify()
    assert backup.remote.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("corrupt", [False, True])
async def test_cross_cohort_changed_generation_invalidates_only_affected_byte_fact(
    backup, tmp_path, corrupt
):
    first = await reader(backup, tmp_path).verify()
    key = "chunks/sha256/" + sha256_hex(b"weights")
    backup.remote.etags[key] = "replacement-generation"
    backup.remote.reads.clear()
    if corrupt:
        backup.remote.objects[key] = b"WEIGHTS"
        with pytest.raises(ValueError, match="chunk bytes differ"):
            await reader(other_cohort(backup), tmp_path).verify()
    else:
        await reader(other_cohort(backup), tmp_path).verify()
        await reader(backup, tmp_path).verify()
        with pytest.raises(OSError, match="requires repair"):
            reader(backup, tmp_path).require_verified(first)
    assert backup.remote.reads == [key]


@pytest.mark.asyncio
async def test_distinct_byte_contexts_do_not_replace_each_others_completed_receipts(
    backup, tmp_path
):
    changed_policy = backup.policy.model_copy(update={"maximum_bundle_bytes": 20000})
    other = selected(changed_policy)
    assert digest(other.bundle) == digest(backup.bundle)
    assert remote_receipt_root(other, tmp_path) != remote_receipt_root(backup, tmp_path)
    for case in (backup, other):
        await reader(case, tmp_path).verify()
    original = retained_files(remote_receipt_root(backup, tmp_path))
    separate = retained_files(remote_receipt_root(other, tmp_path))
    backup.remote.reads.clear()
    other.remote.reads.clear()
    for case in (backup, other, backup):
        await reader(case, tmp_path).verify()
    assert backup.remote.reads == other.remote.reads == []
    assert retained_files(remote_receipt_root(backup, tmp_path)) == original
    assert retained_files(remote_receipt_root(other, tmp_path)) == separate


@pytest.mark.asyncio
async def test_commit_cannot_restore_old_generations_from_legacy_receipts(backup, tmp_path):
    await legacy_receipts(backup, tmp_path)
    old = await reader(backup, tmp_path).verify()
    key = "chunks/sha256/" + sha256_hex(b"weights")
    backup.remote.etags[key] = "replacement-generation"
    current = await reader(backup, tmp_path).verify()
    before = retained_files(remote_receipt_root(backup, tmp_path))
    backup.remote.reads.clear()
    with pytest.raises(OSError, match="requires repair"):
        reader(backup, tmp_path).require_verified(old)
    assert retained_files(remote_receipt_root(backup, tmp_path)) == before
    reader(backup, tmp_path).require_verified(current)
    assert backup.remote.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["empty", "context", "missing"])
async def test_damaged_legacy_receipt_repairs_only_affected_file(backup, tmp_path, damage):
    legacy = await legacy_receipts(backup, tmp_path)
    receipt = legacy / (sha256_hex(canonical_json_bytes("weights.txt")) + ".json")
    if damage == "missing":
        receipt.unlink()
    elif damage == "empty":
        receipt.write_text("{}")
    else:
        damaged = json.loads(receipt.read_bytes())
        damaged["context"] = "45" * 32  # Checksum deliberately remains stale.
        receipt.write_text(json.dumps(damaged))
    originals = retained_files(legacy)
    backup.remote.reads.clear()
    events = []
    await reader(backup, tmp_path).verify(report=events.append)
    assert backup.remote.reads == ["chunks/sha256/" + sha256_hex(b"weights")]
    assert retained_files(legacy) == originals
    assert any(e["status"] == "repair_required" for e in events)
    assert not any(e["reason_code"] == "chunked_model_legacy_selection_required" for e in events)


@pytest.mark.asyncio
async def test_document_requested_after_receipt_migration_uses_retained_original(backup, tmp_path):
    legacy = await legacy_receipts(backup, tmp_path)
    originals = retained_files(legacy)
    await reader(backup, tmp_path).verify()
    backup.remote.reads.clear()
    result = await reader(other_cohort(backup), tmp_path).verify(document_paths=("license.txt",))
    assert result.documents == {"license.txt": b"license".hex()}
    assert backup.remote.reads == []
    assert retained_files(legacy) == originals


@pytest.mark.asyncio
async def test_mixed_legacy_store_migrates_each_matching_original_without_payload_reads(
    backup, tmp_path
):
    other = other_cohort(backup)
    legacy = await legacy_receipts(backup, tmp_path)
    alternate = await legacy_receipts(other, tmp_path / "other-original")
    name = sha256_hex(canonical_json_bytes("weights.txt"))
    for suffix in (".json", ".complete"):
        (legacy / (name + suffix)).write_bytes((alternate / (name + suffix)).read_bytes())
    originals = retained_files(legacy)
    backup.remote.reads.clear()
    with pytest.raises(OSError, match="original authenticated selection"):
        await reader(backup, tmp_path).verify()
    # The six matching facts completed before the foreign seventh was refused.
    assert len(list(remote_receipt_root(backup, tmp_path).glob("*.json"))) == 6
    await reader(other, tmp_path).verify()
    await reader(backup, tmp_path).verify()
    assert retained_files(legacy) == originals
    assert backup.remote.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe", ["symlink", "hardlink"])
async def test_legacy_receipt_migration_refuses_unsafe_files(backup, tmp_path, unsafe):
    legacy = await legacy_receipts(backup, tmp_path)
    receipt = legacy / (sha256_hex(canonical_json_bytes("weights.txt")) + ".json")
    other = tmp_path / "unrelated"
    if unsafe == "symlink":
        other.write_bytes(receipt.read_bytes())
        receipt.unlink()
        receipt.symlink_to(other)
    else:
        os.link(receipt, other)
    backup.remote.reads.clear()
    with pytest.raises(ValueError, match=r"symlink|private regular"):
        await reader(backup, tmp_path).verify()
    assert backup.remote.reads == []


@pytest.mark.asyncio
async def test_interrupted_first_verification_reuses_completed_files(backup, tmp_path):
    failed_key = "chunks/sha256/" + sha256_hex(b"processor")
    backup.remote.fail = failed_key
    with pytest.raises(OSError, match="interrupted"):
        await reader(backup, tmp_path).verify()
    completed = tuple(backup.remote.reads)
    backup.remote.fail = None
    await reader(backup, tmp_path).verify()
    assert all(backup.remote.reads.count(key) == 1 for key in completed)
    assert len(backup.remote.reads) == 7


@pytest.mark.asyncio
async def test_changed_generation_reverifies_only_affected_file(backup, tmp_path):
    await reader(backup, tmp_path).verify()
    backup.remote.reads.clear()
    changed = "chunks/sha256/" + sha256_hex(b"weights")
    backup.remote.etags[changed] = "new-generation"
    events = []
    await reader(backup, tmp_path).verify(report=events.append)
    assert backup.remote.reads == [changed]
    assert any(e.get("status") == "repair_required" for e in events)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["corrupt", "generation", "namespace"])
async def test_remote_replacement_or_wrong_bytes_refuses(backup, tmp_path, change):
    actual = reader(backup, tmp_path)
    key = "chunks/sha256/" + sha256_hex(b"weights")
    if change == "corrupt":
        backup.remote.objects[key] = b"WEIGHTS"
    elif change == "generation":
        backup.remote.change = key
    else:
        backup.remote.signer.bucket = "other-model-artifacts"
    with pytest.raises(ValueError):
        await actual.verify()


@pytest.mark.asyncio
async def test_missing_completed_receipt_repairs_from_exact_shared_file_fact(backup, tmp_path):
    actual = reader(backup, tmp_path)
    await actual.verify()
    root = remote_receipt_root(backup, tmp_path)
    # ByteCheckpoints uses SHA256 of canonical JSON slot names.
    (root / (sha256_hex(canonical_json_bytes("weights.txt")) + ".json")).unlink()
    backup.remote.reads.clear()
    events = []
    await reader(backup, tmp_path).verify(report=events.append)
    assert backup.remote.reads == []
    assert any(e.get("status") == "repair_required" for e in events)


@pytest.mark.asyncio
async def test_document_repair_is_bounded_and_unsafe_metadata_is_refused(backup, tmp_path):
    await reader(backup, tmp_path).verify(document_paths=("license.txt",))
    root = remote_receipt_root(backup, tmp_path)
    document = root / (sha256_hex(b"license.txt") + ".document")
    document.unlink()
    backup.remote.reads.clear()
    events = []
    await reader(backup, tmp_path).verify(document_paths=("license.txt",), report=events.append)
    assert backup.remote.reads == []
    assert any(e.get("status") == "repair_required" for e in events)
    document.unlink()
    document.symlink_to(tmp_path / "unrelated")
    backup.remote.reads.clear()
    with pytest.raises(ValueError, match="symlink"):
        await reader(backup, tmp_path).verify(document_paths=("license.txt",))
    assert not backup.remote.reads


async def restore(actual, archive, **changes):
    return await actual.materialize(
        archive,
        maximum_materialized_bytes=changes.get("limit", 1024**3),
        available_bytes=changes.get("available", lambda: 1024**3),
        reserve_bytes=1024,
        check_write=changes.get("check", lambda _: None),
        report=changes.get("report"),
    )


@pytest.mark.asyncio
async def test_native_restore_restart_eviction_and_verification_reuse(backup, tmp_path):
    archive = tmp_path / "cache"
    target = await restore(reader(backup, tmp_path), archive)
    assert verify_preserved_bundle(backup.bundle, archive, backup.policy) == digest(backup.bundle)
    assert (target / "manifest.json").read_bytes() == backup.raw_manifest
    first_reads = tuple(backup.remote.reads)
    first_heads = tuple(backup.remote.heads)
    await restore(reader(backup, tmp_path), archive)
    assert tuple(backup.remote.reads) == first_reads
    assert tuple(backup.remote.heads) == first_heads
    shutil.rmtree(archive)  # Fixture consumer released its disposable cache.
    await reader(backup, tmp_path).verify()
    assert tuple(backup.remote.reads) == first_reads
    await restore(reader(backup, tmp_path), archive)
    assert len(backup.remote.reads) == 2 * len(first_reads)
    assert verify_preserved_bundle(backup.bundle, archive, backup.policy) == digest(backup.bundle)


@pytest.mark.asyncio
async def test_interrupted_materialization_preserves_completed_files(backup, tmp_path):
    archive = tmp_path / "cache"
    backup.remote.fail = "chunks/sha256/" + sha256_hex(b"processor")
    with pytest.raises(OSError):
        await restore(reader(backup, tmp_path), archive)
    completed_reads = [
        "chunks/sha256/" + sha256_hex(raw)
        for name, raw in backup.contents.items()
        if (archive / digest(backup.bundle) / "model" / name).is_file()
        and (archive / digest(backup.bundle) / "model" / name).stat().st_mode & 0o200 == 0
    ]
    backup.remote.fail = None
    await restore(reader(backup, tmp_path), archive)
    assert all(backup.remote.reads.count(key) == 1 for key in completed_reads)
    assert verify_preserved_bundle(backup.bundle, archive, backup.policy) == digest(backup.bundle)


async def test_materialization_overlaps_bounded_reads_and_writes_in_manifest_order(
    backup, tmp_path, monkeypatch
):
    original = backup.remote.read_range
    active = peak = 0
    finished = []
    keys = list(backup.remote.objects)

    async def unordered(key, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.002 * (len(keys) - keys.index(key)))
            raw = await original(key, **kwargs)
            finished.append(key)
            return raw
        finally:
            active -= 1

    monkeypatch.setattr(backup.remote, "read_range", unordered)
    target = await restore(reader(backup, tmp_path), tmp_path / "cache")
    assert peak == chunked.MATERIALIZATION_PREFETCH_CHUNKS and active == 0
    assert finished != keys
    assert all(
        (target / "model" / name).read_bytes() == raw for name, raw in backup.contents.items()
    )
    assert verify_preserved_bundle(backup.bundle, target.parent, backup.policy) == digest(
        backup.bundle
    )


@pytest.mark.parametrize("failure", ["cancel", "read_error", "changed_generation"])
async def test_materialization_drains_prefetch_on_failure(backup, tmp_path, monkeypatch, failure):
    original = backup.remote.read_range
    active = set()
    started = asyncio.Event()
    release = asyncio.Event()
    first = next(iter(backup.remote.objects))

    async def blocked(key, **kwargs):
        active.add(key)
        try:
            if len(active) == chunked.MATERIALIZATION_PREFETCH_CHUNKS:
                started.set()
            await release.wait()
            if key == first and failure == "read_error":
                raise OSError("prefetch read unavailable")
            if key == first and failure == "changed_generation":
                backup.remote.etags[key] = "changed-generation"
            return await original(key, **kwargs)
        finally:
            active.remove(key)

    monkeypatch.setattr(backup.remote, "read_range", blocked)
    archive = tmp_path / "cache"
    task = asyncio.create_task(restore(reader(backup, tmp_path), archive))
    await asyncio.wait_for(started.wait(), 5)
    if failure == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        release.set()
        with pytest.raises((OSError, ValueError), match=r"unavailable|changed during transfer"):
            await task
    assert not active
    assert not (archive / digest(backup.bundle) / "manifest.json").exists()


@pytest.mark.asyncio
async def test_materialization_does_not_finish_at_last_payload_byte(backup, tmp_path, monkeypatch):
    events = []
    original = chunked._remember_preserved_verification
    observed = []

    def complete_receipt(*args):
        latest = next(e for e in reversed(events) if e["stage"] == "chunked_model_materialization")
        # Native manifest/receipt publication remains after the last tiny file.
        assert latest["completed_bytes"] == latest["total_bytes"]
        assert latest["completed_operations"] < latest["total_operations"]
        assert latest["status"] != "completed" and latest["percent"] < 100
        assert latest["eta_seconds"] != 0
        observed.append(True)
        return original(*args)

    monkeypatch.setattr(chunked, "_remember_preserved_verification", complete_receipt)
    archive = tmp_path / "cache"
    await restore(reader(backup, tmp_path), archive, report=events.append)
    terminal = next(e for e in reversed(events) if e["stage"] == "chunked_model_materialization")
    assert observed and terminal["status"] == "completed"
    assert terminal["completed_operations"] == terminal["total_operations"]
    previous_reads = list(backup.remote.reads)
    events.clear()
    await restore(reader(backup, tmp_path), archive, report=events.append)
    terminal = next(e for e in reversed(events) if e["stage"] == "chunked_model_materialization")
    assert backup.remote.reads == previous_reads
    assert terminal["restored_operations"] == terminal["total_operations"] - 1
    assert terminal["native_operations"] == 1


@pytest.mark.asyncio
async def test_restore_refuses_cache_state_overlap_capacity_and_links(backup, tmp_path):
    actual = reader(backup, tmp_path)
    with pytest.raises(ValueError, match="overlaps"):
        await restore(actual, tmp_path / "verification")
    with pytest.raises(ValueError, match="capacity budget"):
        await restore(actual, tmp_path / "cache", limit=1)
    with pytest.raises(OSError, match="capacity"):
        await restore(actual, tmp_path / "cache", available=lambda: 0)
    root = tmp_path / "cache" / digest(backup.bundle) / "model"
    (root / "config.txt").symlink_to(tmp_path / "unrelated")
    with pytest.raises(ValueError, match="symlink"):
        await restore(actual, tmp_path / "cache")


@pytest.mark.asyncio
async def test_real_chunk_bound_and_exact_two_chunk_restoration(policy, tmp_path):
    policy = policy.model_copy(update={"maximum_bundle_bytes": 2 * CHUNK_BYTES})
    case = selected(policy, weights=b"w" * CHUNK_BYTES + b"tail")
    writes = []
    target = await restore(reader(case, tmp_path), tmp_path / "cache", check=writes.append)
    assert max(writes) == CHUNK_BYTES
    assert (target / "model" / "weights.txt").read_bytes() == b"w" * CHUNK_BYTES + b"tail"
    assert verify_preserved_bundle(case.bundle, tmp_path / "cache", policy) == digest(case.bundle)


@pytest.mark.asyncio
async def test_zero_length_file_has_exact_empty_coverage(policy, tmp_path):
    case = selected(policy, weights=b"")
    await reader(case, tmp_path).verify()
    target = await restore(reader(case, tmp_path), tmp_path / "cache")
    assert (target / "model" / "weights.txt").read_bytes() == b""


@pytest.mark.asyncio
async def test_original_file_hash_remains_required_even_with_valid_chunks(backup, tmp_path):
    package = json.loads(backup.raw_package)
    package["native_bundle"]["files"][0]["sha256"] = "11" * 32
    new_bundle = ModelBundle.model_validate_json(canonical_json_bytes(package["native_bundle"]))
    package["model_sha256"] = digest(new_bundle)
    backup.raw_manifest = canonical_json_bytes(new_bundle)
    backup.raw_package = canonical_json_bytes(package)
    association = json.loads(backup.raw_association)
    association.update(
        model_sha256=digest(new_bundle), package_sha256=sha256_hex(backup.raw_package)
    )
    association["package_key"] = (
        f"packages/{digest(new_bundle)}/{association['package_sha256']}.json"
    )
    backup.raw_association = canonical_json_bytes(association)
    backup.binding = backup.binding.model_copy(
        update={
            "model_sha256": digest(new_bundle),
            "association_sha256": sha256_hex(backup.raw_association),
        }
    )
    with pytest.raises(ValueError, match="signed manifest"):
        await reader(backup, tmp_path).verify()


@pytest.mark.asyncio
async def test_interruption_before_sealing_repairs_complete_file_without_redownload(
    backup, tmp_path, monkeypatch
):
    archive = tmp_path / "cache"
    target = archive / digest(backup.bundle) / "model" / "config.txt"
    original = os.fchmod

    def interrupt(descriptor, mode):
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(target) and mode == 0o400:
            raise OSError("interrupted before sealing complete file")
        return original(descriptor, mode)

    with monkeypatch.context() as patch:
        patch.setattr(chunked.os, "fchmod", interrupt)
        with pytest.raises(OSError, match="before sealing"):
            await restore(reader(backup, tmp_path), archive)
    assert target.read_bytes() == b"config"
    assert target.stat().st_mode & 0o777 == 0o600
    completed_reads = ("chunks/sha256/" + sha256_hex(b"config"),)
    events = []
    await restore(reader(backup, tmp_path), archive, report=events.append)
    assert all(backup.remote.reads.count(key) == 1 for key in completed_reads)
    assert target.stat().st_mode & 0o777 == 0o400
    assert any(e["reason_code"] == "chunked_model_local_verification_required" for e in events)
    assert verify_preserved_bundle(backup.bundle, archive, backup.policy) == digest(backup.bundle)


@pytest.mark.asyncio
async def test_missing_local_completed_receipt_repairs_only_local_bytes(backup, tmp_path):
    archive = tmp_path / "cache"
    await restore(reader(backup, tmp_path), archive)
    state = (
        tmp_path
        / "verification"
        / digest(backup.bundle)
        / "materializations"
        / sha256_hex(os.fsencode(archive))
    )
    (state / (sha256_hex(canonical_json_bytes("weights.txt")) + ".json")).unlink()
    backup.remote.reads.clear()
    backup.remote.heads.clear()
    events = []
    await restore(reader(backup, tmp_path), archive, report=events.append)
    assert not backup.remote.reads and not backup.remote.heads
    assert any(e["reason_code"] == "completed_byte_receipt_missing" for e in events)
    assert any(e["reason_code"] == "byte_receipt_native_repair_persisted" for e in events)
    assert verify_preserved_bundle(backup.bundle, archive, backup.policy) == digest(backup.bundle)


@pytest.mark.asyncio
async def test_partial_large_file_retries_only_unfinished_file(policy, tmp_path):
    policy = policy.model_copy(update={"maximum_bundle_bytes": 2 * CHUNK_BYTES})
    case = selected(policy, weights=b"w" * CHUNK_BYTES + b"tail")
    case.remote.fail = "chunks/sha256/" + sha256_hex(b"tail")
    archive = tmp_path / "cache"
    with pytest.raises(OSError, match="interrupted"):
        await restore(reader(case, tmp_path), archive)
    target = archive / digest(case.bundle) / "model" / "weights.txt"
    assert target.stat().st_size == CHUNK_BYTES
    completed = tuple(case.remote.reads[:-1])
    case.remote.fail = None
    case.remote.heads.clear()
    await restore(reader(case, tmp_path), archive)
    assert all(case.remote.reads.count(key) == 1 for key in completed)
    assert case.remote.reads.count("chunks/sha256/" + sha256_hex(b"w" * CHUNK_BYTES)) == 2
    assert set(case.remote.heads) == {
        "chunks/sha256/" + sha256_hex(b"w" * CHUNK_BYTES),
        "chunks/sha256/" + sha256_hex(b"tail"),
    }
    assert verify_preserved_bundle(case.bundle, archive, case.policy) == digest(case.bundle)


@pytest.mark.asyncio
async def test_transfer_progress_reports_counts_eta_basis_and_restart_reuse(backup, tmp_path):
    events = []
    await reader(backup, tmp_path).verify(report=events.append)
    for stage in (
        "chunked_model_remote_metadata",
        "chunked_model_verification",
        "chunked_model_generation_confirmation",
    ):
        stage_events = [e for e in events if e["stage"] == stage]
        assert stage_events[0]["planning_eta_seconds"] is not None
        assert stage_events[-1]["status"] == "completed"
        assert stage_events[-1]["percent"] == 100.0
        assert stage_events[-1]["eta_seconds"] == 0
        assert stage_events[-1]["elapsed_seconds"] >= 0
        assert stage_events[-1]["completed_units"] == stage_events[-1]["total_units"]
    events.clear()
    await reader(backup, tmp_path).verify(report=events.append)
    completed = [e for e in events if e["stage"] == "chunked_model_verification"][-1]
    assert completed["native_bytes"] == 0
    assert completed["restored_bytes"] == sum(r.size_bytes for r in backup.bundle.files)


@pytest.mark.parametrize(
    "field",
    [
        "association_sha256",
        "model_sha256",
        "policy_sha256",
        "provenance_sha256",
    ],
)
def test_zero_pin_is_not_authenticated_provenance(backup, field):
    with pytest.raises(ValueError, match="explicit retained provenance"):
        selection(backup, binding=backup.binding.model_copy(update={field: "0" * 64}))


def test_reader_refuses_changed_policy_before_remote_work(backup, tmp_path):
    with pytest.raises(ValueError, match="policy differs"):
        ChunkedModelBackupReader(
            selection(backup),
            policy=backup.policy.model_copy(update={"maximum_bundle_bytes": 9999}),
            multipart=backup.remote,
            verification_root=tmp_path / "verification",
        )
    assert not backup.remote.heads and not backup.remote.reads


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_remote_metadata_is_bounded_parallel_and_drains_workers(
    backup, tmp_path, monkeypatch, fail
):
    actual = ChunkedModelBackupReader(
        selection(backup),
        policy=backup.policy,
        multipart=backup.remote,
        verification_root=tmp_path / "verification",
        metadata_workers=3,
    )
    active = maximum = 0
    original = backup.remote.head

    async def delayed(key):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        try:
            await asyncio.sleep(0.001)
            if fail:
                raise OSError("interrupted metadata scan")
            return await original(key)
        finally:
            active -= 1

    monkeypatch.setattr(backup.remote, "head", delayed)
    if fail:
        with pytest.raises(OSError, match="metadata scan"):
            await actual.verify()
    else:
        await actual.verify()
    assert maximum == 3
    assert active == 0


@pytest.mark.asyncio
async def test_original_local_completion_is_available_during_remote_outage(backup, tmp_path):
    archive = tmp_path / "cache"
    await restore(reader(backup, tmp_path), archive)
    backup.remote.objects.clear()
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    await restore(reader(backup, tmp_path), archive)
    assert not backup.remote.heads and not backup.remote.reads
    assert verify_preserved_bundle(backup.bundle, archive, backup.policy) == digest(backup.bundle)


@pytest.mark.asyncio
async def test_verified_retry_reads_only_two_cross_boundary_chunks(policy, tmp_path):
    policy = policy.model_copy(update={"maximum_bundle_bytes": 3 * CHUNK_BYTES})
    weights = b"a" * CHUNK_BYTES + b"b" * CHUNK_BYTES + b"c"
    case = selected(policy, weights=weights)
    actual = reader(case, tmp_path)
    snapshot = await actual.verify()
    case.remote.reads.clear()
    case.remote.heads.clear()
    reports = []
    index = next(i for i, file in enumerate(case.bundle.files) if file.role == "weights")
    # A new reader consumes durable verification; no model tree is materialized.
    value = await reader(case, tmp_path).read_verified_range(
        snapshot, file_index=index, offset=CHUNK_BYTES - 3, size_bytes=8, report=reports.append
    )
    assert value == b"aaa" + b"bbbbb"
    expected = [
        "chunks/sha256/" + sha256_hex(raw) for raw in (b"a" * CHUNK_BYTES, b"b" * CHUNK_BYTES)
    ]
    assert case.remote.reads == expected
    assert set(case.remote.heads) == set(expected)
    assert len(case.remote.heads) == 4  # Generation checks before and after each GET.
    assert reports[-1]["status"] == "completed"
    assert reports[-1]["eta_seconds"] == 0
    assert not (tmp_path / "archive").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["corrupt", "generation", "during_transfer", "receipt"])
async def test_verified_retry_refuses_changed_source_without_whole_model_restore(
    backup, tmp_path, change
):
    actual = reader(backup, tmp_path)
    snapshot = await actual.verify()
    key = "chunks/sha256/" + sha256_hex(b"weights")
    index = next(i for i, file in enumerate(backup.bundle.files) if file.role == "weights")
    if change == "corrupt":
        backup.remote.objects[key] = b"WEIGHTS"
    elif change == "generation":
        backup.remote.etags[key] = "replacement-generation"
    elif change == "during_transfer":
        backup.remote.change = key
    else:
        root = remote_receipt_root(backup, tmp_path)
        (root / (sha256_hex(canonical_json_bytes("weights.txt")) + ".json")).unlink()
    backup.remote.reads.clear()
    with pytest.raises((OSError, ValueError)):
        await actual.read_verified_range(snapshot, file_index=index, offset=1, size_bytes=3)
    assert backup.remote.reads == ([] if change in {"generation", "receipt"} else [key])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bounds",
    [
        {"file_index": -1},
        {"file_index": True},
        {"offset": -1},
        {"offset": True},
        {"size_bytes": 0},
        {"size_bytes": CHUNK_BYTES + 1},
        {"size_bytes": True},
        {"offset": 7, "size_bytes": 1},
    ],
)
async def test_verified_retry_rejects_invalid_range_before_remote_work(backup, tmp_path, bounds):
    actual = reader(backup, tmp_path)
    snapshot = await actual.verify()
    selected_range = {
        "file_index": next(
            i for i, file in enumerate(backup.bundle.files) if file.role == "weights"
        ),
        "offset": 0,
        "size_bytes": 1,
    }
    selected_range.update(bounds)
    backup.remote.reads.clear()
    backup.remote.heads.clear()
    with pytest.raises(ValueError):
        await actual.read_verified_range(snapshot, **selected_range)
    assert not backup.remote.reads and not backup.remote.heads


@pytest.mark.asyncio
async def test_empty_verified_retry_needs_no_remote_object(policy, tmp_path):
    case = selected(policy, weights=b"")
    actual = reader(case, tmp_path)
    snapshot = await actual.verify()
    index = next(i for i, file in enumerate(case.bundle.files) if file.role == "weights")
    case.remote.reads.clear()
    case.remote.heads.clear()
    assert (
        await actual.read_verified_range(snapshot, file_index=index, offset=0, size_bytes=0) == b""
    )
    assert not case.remote.reads and not case.remote.heads
