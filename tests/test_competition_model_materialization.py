"""Interrupted bounded R2 caches retain authenticated work without trusting a new source."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from types import SimpleNamespace

import pytest

from umi import competition_model_materialization as materialization
from umi.competition_cohort_direct_model_upload import DirectModelPayload
from umi.competition_model_cache_space import BootDiskModelCache, BootDiskModelCacheConfig
from umi.competition_transport_verification import TransferProgress
from umi.open_competition import BundleFile, ModelBundle, digest


@pytest.fixture
def transfer(tmp_path, monkeypatch):
    roles = ("weights", "config", "processor", "inference", "environment", "license", "provenance")
    contents = {f"{index}-{role}.bin": bytes([65 + index]) * 64 for index, role in enumerate(roles)}
    bundle = ModelBundle(
        schema="umi-model-bundle/1",
        profile="offline_bundle/1",
        parent_baseline_sha256=None,
        license_id="MIT",
        files=tuple(
            BundleFile(
                path=name,
                role=role,
                sha256=hashlib.sha256(contents[name]).hexdigest(),
                size_bytes=len(contents[name]),
            )
            for role, name in zip(roles, contents, strict=True)
        ),
    )
    body = b"".join(contents.values())
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256="a" * 64,
        model_sha256=digest(bundle),
        payload_sha256=hashlib.sha256(body).hexdigest(),
        total_bytes=len(body),
        file_count=len(bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    key = "preserved/test-model"

    class Ranges:
        fail_at_offset = None

        def __init__(self):
            self.reads = []

        async def read_range(self, selected_key, *, offset, size_bytes):
            assert selected_key == key
            if self.fail_at_offset is not None and offset >= self.fail_at_offset:
                raise OSError("injected transfer interruption")
            self.reads.append((offset, size_bytes))
            return body[offset : offset + size_bytes]

    source = {
        "endpoint": "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
        "bucket": "model-artifacts",
        "key_sha256": hashlib.sha256(key.encode()).hexdigest(),
        "etag": "first-generation",
        "size_bytes": len(body),
    }
    archive, verification = tmp_path / "cache-root" / "cache", tmp_path / "durable-verification"
    multipart = Ranges()
    events = []
    reserve = 64
    monkeypatch.setattr(materialization, "MAXIMUM_RANGE_BYTES", 16)

    async def run(*, available=None, selected_source=None, check_write=None):
        with TransferProgress("model_materialization", len(body), events.append) as progress:
            return await materialization.materialize_model_files(
                archive=archive,
                bundle=bundle,
                payload=payload,
                multipart=multipart,
                key=key,
                selection="b" * 64,
                source=source if selected_source is None else selected_source,
                verification_root=verification,
                document_paths=tuple(
                    record.path
                    for record in bundle.files
                    if record.role in {"license", "provenance"}
                ),
                progress=progress,
                available_bytes=(lambda: 1024**3) if available is None else available,
                reserve_bytes=reserve,
                check_write=check_write,
            )

    model = archive / digest(bundle) / "model"

    def bounded_free():
        retained = sum(
            (model / record.path).stat().st_size
            for record in bundle.files
            if (model / record.path).exists()
        )
        return len(body) + reserve - retained

    return SimpleNamespace(
        run=run,
        multipart=multipart,
        source=source,
        bundle=bundle,
        payload=payload,
        model=model,
        archive=archive,
        verification=verification,
        events=events,
        contents=contents,
        bounded_free=bounded_free,
        reserve=reserve,
    )


async def test_partial_file_is_private_before_interruption_under_ordinary_umask(transfer):
    transfer.multipart.fail_at_offset = 16
    previous = os.umask(0o022)
    try:
        with pytest.raises(OSError, match="injected transfer interruption"):
            await transfer.run()
    finally:
        os.umask(previous)
    partial = transfer.model / transfer.bundle.files[0].path
    assert partial.read_bytes() == transfer.contents[partial.name][:16]
    assert partial.stat().st_mode & 0o077 == 0
    transfer.multipart.fail_at_offset = None
    await transfer.run()
    assert all(
        (transfer.model / name).read_bytes() == expected
        for name, expected in transfer.contents.items()
    )


async def test_completed_payload_survives_failed_manifest_publication_without_weight_reads(
    transfer, monkeypatch
):
    original_publish = materialization.publish_private_model

    def fail_manifest(path, value, **kwargs):
        if path.name == "manifest.json":
            raise OSError("injected final manifest failure")
        return original_publish(path, value, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(materialization, "publish_private_model", fail_manifest)
        with pytest.raises(OSError, match="injected final manifest failure"):
            await transfer.run()
    reads = list(transfer.multipart.reads)
    original_artifact = materialization._artifact

    def no_weight_reread(root_fd, record):
        assert record.role != "weights", "completed payload verification reread weights"
        return original_artifact(root_fd, record)

    with monkeypatch.context() as patch:
        patch.setattr(materialization, "_artifact", no_weight_reread)
        target, documents, written = await transfer.run(available=transfer.bounded_free)
    assert transfer.multipart.reads == reads
    assert (target / "manifest.json").is_file()
    assert documents == {
        record.path: transfer.contents[record.path]
        for record in transfer.bundle.files
        if record.role in {"license", "provenance"}
    }
    assert [record[0] for record in written] == [record.path for record in transfer.bundle.files]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("etag", "replacement-generation"),
        ("bucket", "other-model-artifacts"),
        ("endpoint", "https://other-provider.example.com"),
    ],
)
async def test_pending_generation_cannot_bless_old_local_ranges_as_new_r2_bytes(
    transfer, field, replacement
):
    transfer.multipart.fail_at_offset = transfer.bundle.files[0].size_bytes
    with pytest.raises(OSError, match="injected transfer interruption"):
        await transfer.run()
    reads = list(transfer.multipart.reads)
    transfer.multipart.fail_at_offset = None
    with pytest.raises(ValueError):
        await transfer.run(selected_source={**transfer.source, field: replacement})
    assert transfer.multipart.reads == reads


async def test_partial_space_is_reclaimed_before_resumed_capacity_check(transfer):
    transfer.multipart.fail_at_offset = 32
    with pytest.raises(OSError, match="injected transfer interruption"):
        await transfer.run(available=transfer.bounded_free)
    assert transfer.bounded_free() < transfer.payload.total_bytes + transfer.reserve
    transfer.multipart.fail_at_offset = None
    await transfer.run(available=transfer.bounded_free)
    assert transfer.bounded_free() == transfer.reserve


async def test_complete_file_without_receipt_repairs_locally_with_only_remaining_space(transfer):
    first = transfer.bundle.files[0]
    transfer.multipart.fail_at_offset = first.size_bytes
    with pytest.raises(OSError, match="injected transfer interruption"):
        await transfer.run(available=transfer.bounded_free)
    matches = [
        path
        for path in transfer.verification.rglob("*.json")
        if json.loads(path.read_bytes()).get("result") == first.sha256
    ]
    assert len(matches) == 1
    matches[0].unlink()
    transfer.multipart.reads.clear()
    transfer.multipart.fail_at_offset = None
    await transfer.run(available=transfer.bounded_free)
    assert all(offset >= first.size_bytes for offset, _ in transfer.multipart.reads)
    assert transfer.bounded_free() == transfer.reserve
    assert any(event["status"] == "repair_required" for event in transfer.events)


async def test_boot_cache_restarts_partial_transfer_evicts_and_restores_without_losing_receipts(
    transfer,
):
    config = BootDiskModelCacheConfig(
        schema="umi-boot-disk-model-cache/1",
        directory=str(transfer.archive.parent),
        maximum_allocated_bytes=2 * 1024**2,
    )

    async def restore():
        # New allocator instances model a process restart; only filesystem
        # identities and durable per-file receipts survive between executions.
        budget = BootDiskModelCache(config, reserve_bytes=transfer.reserve)
        with budget.allocation_lease():
            budget.prepare(transfer.bundle)
            return await transfer.run(
                available=budget.available_bytes, check_write=budget.check_write
            )

    first = transfer.bundle.files[0]
    transfer.multipart.fail_at_offset = first.size_bytes + 16
    with pytest.raises(OSError, match="injected transfer interruption"):
        await restore()
    assert (transfer.model / first.path).read_bytes() == transfer.contents[first.path]
    transfer.multipart.reads.clear()
    transfer.multipart.fail_at_offset = None
    await restore()
    assert all(offset >= first.size_bytes for offset, _ in transfer.multipart.reads)
    receipts = {
        p.relative_to(transfer.verification): p.read_bytes()
        for p in transfer.verification.rglob("*.json")
    }
    # The consumer releases only its cache after all invocation leases return.
    # Durable verification/checkpoint state remains outside that disposable tree.
    shutil.rmtree(transfer.archive)
    assert all((transfer.verification / p).read_bytes() == raw for p, raw in receipts.items())
    transfer.multipart.reads.clear()
    await restore()
    assert sum(size for _, size in transfer.multipart.reads) == transfer.payload.total_bytes
    assert all(
        (transfer.model / name).read_bytes() == expected
        for name, expected in transfer.contents.items()
    )


async def test_boot_reserve_exhaustion_retains_checkpoint_and_resumes_only_affected_file(transfer):
    first = transfer.bundle.files[0]
    interrupted = False

    def guard(size):
        nonlocal interrupted
        if (transfer.model / first.path).stat().st_size == first.size_bytes:
            interrupted = True
            raise OSError("boot filesystem reserve consumed by another service")

    with pytest.raises(OSError, match="reserve consumed"):
        await transfer.run(check_write=guard)
    assert interrupted
    transfer.multipart.reads.clear()
    await transfer.run()
    assert all(offset >= first.size_bytes for offset, _ in transfer.multipart.reads)
