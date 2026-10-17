"""Native file facts survive different packages without granting model authority."""

import asyncio
import shutil
import subprocess
import sys

import pytest

from umi.competition_shared_file_bytes import SharedRemoteFileBytes
from umi.competition_transport_verification import TransferProgress
from umi.private_files import PrivateStateBusyError
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_chunked_model_backup import (
    backup as backup,
)
from .test_competition_chunked_model_backup import (
    reader,
    remote_receipt_root,
    retained_files,
    selected,
)
from .test_open_competition import policy as policy


@pytest.mark.asyncio
async def test_changed_weights_reuse_common_files_across_packages_and_cold_restart(
    backup, tmp_path
):
    first = await reader(backup, tmp_path).verify(document_paths=("license.txt",))
    old = retained_files(remote_receipt_root(backup, tmp_path))
    other = selected(backup.policy, weights=b"improved weights")
    actual = reader(other, tmp_path)
    second = await actual.verify(document_paths=("license.txt",))
    assert other.remote.reads == ["chunks/sha256/" + sha256_hex(b"improved weights")]
    assert first.selection_sha256 != second.selection_sha256
    assert second.documents == first.documents
    actual.require_verified(second)
    with pytest.raises(ValueError, match="selected source"):
        actual.require_verified(first)
    assert retained_files(remote_receipt_root(backup, tmp_path)) == old
    script = """
import asyncio,json,sys
from pathlib import Path
from umi.open_competition import CompetitionPolicy
from tests.test_competition_chunked_model_backup import reader,selected
async def main():
    policy=CompetitionPolicy.model_validate_json(sys.argv[2])
    for weights in (b'weights',b'improved weights'):
        c=selected(policy,weights=weights)
        r=reader(c,Path(sys.argv[1])); v=await r.verify(document_paths=('license.txt',))
        r.require_verified(v)
        assert c.remote.reads == []
    print('zero GETs')
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
        capture_output=True,
        text=True,
    )
    assert process.returncode == 0, process.stderr
    assert process.stdout.strip() == "zero GETs"


@pytest.mark.asyncio
async def test_completed_old_package_migrates_without_rewriting_exported_facts(backup, tmp_path):
    await reader(backup, tmp_path).verify(document_paths=("license.txt",))
    root = tmp_path / "verification"
    for name in ("shared-file-bytes-v1", "shared-file-index-v1"):
        shutil.rmtree(root / name)
    before = retained_files(remote_receipt_root(backup, tmp_path))
    backup.remote.reads.clear()
    await reader(backup, tmp_path).verify(document_paths=("license.txt",), completed_only=True)
    assert backup.remote.reads == []
    assert retained_files(remote_receipt_root(backup, tmp_path)) == before
    other = selected(backup.policy, weights=b"new weights")
    await reader(other, tmp_path).verify(document_paths=("license.txt",))
    assert other.remote.reads == ["chunks/sha256/" + sha256_hex(b"new weights")]


@pytest.mark.asyncio
async def test_metadata_only_migration_refuses_incomplete_original_without_get(backup, tmp_path):
    events = []
    with pytest.raises(OSError, match="completed native bytes"):
        await reader(backup, tmp_path).verify(completed_only=True, report=events.append)
    assert backup.remote.reads == []
    assert any(
        e.get("reason_code") == "shared_file_seed_requires_completed_native_bytes" for e in events
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "receipt",
        "store",
        "index",
        "index_empty",
        "index_oversize",
        "document",
        "document_empty",
        "document_oversize",
    ],
)
async def test_missing_or_damaged_shared_state_repairs_visibly_from_package(
    backup, tmp_path, fault
):
    actual = reader(backup, tmp_path)
    await actual.verify(document_paths=("license.txt",))
    heads = await actual._heads(None)
    record, item = next(
        (r, i)
        for r, i in zip(actual.selection.bundle.files, actual.selection.package.files, strict=True)
        if r.path == "license.txt"
    )
    events = []
    with TransferProgress("test", 1, events.append) as progress:
        shared = SharedRemoteFileBytes(actual, record, item, heads, progress)
        if fault == "receipt":
            shared.checks.path("contents").unlink()
        elif fault == "store":
            shutil.rmtree(shared.root)
        elif fault.startswith("index"):
            shared.index.write_bytes(
                b""
                if fault == "index_empty"
                else b"x" * (64 * 1024 + 1)
                if fault == "index_oversize"
                else b"{}"
            )
        else:
            (shared.root / "contents.document").write_bytes(
                b""
                if fault == "document_empty"
                else b"x" * (16 * 1024**2 + 1)
                if fault == "document_oversize"
                else b"damaged"
            )
    backup.remote.reads.clear()
    await reader(backup, tmp_path).verify(document_paths=("license.txt",), report=events.append)
    assert backup.remote.reads == []
    assert any(e.get("status") == "repair_required" for e in events)
    other = selected(backup.policy, weights=b"other")
    await reader(other, tmp_path).verify(document_paths=("license.txt",))
    assert len(other.remote.reads) == 1


@pytest.mark.asyncio
async def test_shared_damage_and_missing_package_requires_only_affected_file(backup, tmp_path):
    actual = reader(backup, tmp_path)
    await actual.verify()
    heads = await actual._heads(None)
    record, item = list(
        zip(actual.selection.bundle.files, actual.selection.package.files, strict=True)
    )[-1]
    with TransferProgress("test", 1) as progress:
        shared = SharedRemoteFileBytes(actual, record, item, heads, progress)
        shared.checks.path("contents").write_bytes(b"{}")
    (
        remote_receipt_root(backup, tmp_path)
        / (sha256_hex(canonical_json_bytes(record.path)) + ".json")
    ).unlink()
    backup.remote.reads.clear()
    events = []
    await reader(backup, tmp_path).verify(report=events.append)
    assert backup.remote.reads == ["chunks/sha256/" + sha256_hex(b"weights")]
    assert any(e.get("status") == "repair_required" for e in events)


@pytest.mark.asyncio
async def test_namespace_and_policy_do_not_borrow_shared_facts(backup, tmp_path):
    await reader(backup, tmp_path).verify()
    prefixed = selected(backup.policy, weights=b"new", object_key_prefix="another/")
    await reader(prefixed, tmp_path).verify()
    assert len(prefixed.remote.reads) == 7
    changed_policy = backup.policy.model_copy(update={"maximum_bundle_bytes": 20000})
    other = selected(changed_policy, weights=b"new")
    await reader(other, tmp_path).verify()
    assert len(other.remote.reads) == 7


@pytest.mark.asyncio
async def test_ordered_chunk_geometry_is_part_of_shared_identity(backup, tmp_path):
    await reader(backup, tmp_path).verify()

    def split(package):
        item = package["files"][-1]
        item["chunks"] = [
            {"sha256": sha256_hex(raw), "size_bytes": len(raw)} for raw in (b"wei", b"ghts")
        ]

    other = selected(backup.policy, mutation=split)
    for raw in (b"wei", b"ghts"):
        key = "chunks/sha256/" + sha256_hex(raw)
        other.remote.objects[key] = raw
        other.remote.etags[key] = "original-generation"
    with pytest.raises(ValueError, match="chunk geometry differs"):
        await reader(other, tmp_path).verify()
    assert not other.remote.reads


@pytest.mark.asyncio
async def test_cancellation_preserves_only_completed_files(backup, tmp_path):
    original = backup.remote.read_range
    blocked = asyncio.Event()

    async def pause(key, **kwargs):
        if key.endswith(sha256_hex(b"weights")):
            blocked.set()
            await asyncio.Future()
        return await original(key, **kwargs)

    backup.remote.read_range = pause
    task = asyncio.create_task(reader(backup, tmp_path).verify())
    await blocked.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    backup.remote.read_range = original
    backup.remote.reads.clear()
    await reader(backup, tmp_path).verify()
    assert backup.remote.reads == ["chunks/sha256/" + sha256_hex(b"weights")]


@pytest.mark.asyncio
async def test_per_file_lock_refuses_overlap_and_releases_on_cancel(backup, tmp_path):
    actual = reader(backup, tmp_path)
    heads = await actual._heads(None)
    record, item = next(
        zip(actual.selection.bundle.files, actual.selection.package.files, strict=True)
    )
    with TransferProgress("test", 1) as progress:
        with (
            SharedRemoteFileBytes(actual, record, item, heads, progress),
            pytest.raises(PrivateStateBusyError),
            SharedRemoteFileBytes(actual, record, item, heads, progress),
        ):
            pass
        with SharedRemoteFileBytes(actual, record, item, heads, progress):
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["symlink", "hardlink"])
async def test_unsafe_shared_receipt_refuses_without_gets(backup, tmp_path, fault):
    actual = reader(backup, tmp_path)
    await actual.verify()
    heads = await actual._heads(None)
    record, item = next(
        zip(actual.selection.bundle.files, actual.selection.package.files, strict=True)
    )
    with TransferProgress("test", 1) as progress:
        shared = SharedRemoteFileBytes(actual, record, item, heads, progress)
        path = shared.checks.path("contents")
        other = tmp_path / "unrelated"
        if fault == "symlink":
            other.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(other)
        else:
            import os

            os.link(path, other)
    backup.remote.reads.clear()
    with pytest.raises(ValueError, match=r"symlink|private regular"):
        await reader(backup, tmp_path).verify()
    assert backup.remote.reads == []
