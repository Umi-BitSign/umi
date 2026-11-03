"""Frozen-reference lifetime around native preserved bytes and R2 transfer boundary."""

import asyncio
import os
import threading
from types import SimpleNamespace

import pytest
from pydantic import RootModel

from umi import competition_artifacts as native
from umi import competition_cohort_reference_preparation as references
from umi.competition_model_cache_space import BootDiskModelCacheConfig
from umi.open_competition import digest
from umi.private_files import publish_private_model

from .test_open_competition import bundle_at
from .test_open_competition import policy as policy


@pytest.fixture
def case(tmp_path, policy, monkeypatch):
    bundle = bundle_at(tmp_path / "source")
    archive = tmp_path / "archive"
    archive.mkdir(mode=0o700)
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    boot = BootDiskModelCacheConfig(
        schema="umi-boot-disk-model-cache/1",
        directory=str(cache),
        maximum_allocated_bytes=1024**2,
    )
    config = SimpleNamespace(
        materialization_boot_disk_cache=boot,
        materialization_free_space_reserve_bytes=1024**2,
        reference_working_set_reclamation=True,
        reference_preservation_directory=str(archive),
    )
    config.model_copy = lambda **_: config
    artifacts = SimpleNamespace(
        config=config, policy=policy, multipart=None, verification_root=None
    )
    source = references._Source(bundle, selection={"original": "authenticated source"})
    calls = []

    async def materialize(selection, slot):
        assert selection == source.selection
        calls.append(slot)
        return native.preserve_bundle(bundle, tmp_path / "source", slot, policy)

    monkeypatch.setattr(
        references,
        "DirectModelArtifactReviewer",
        lambda *a, **k: SimpleNamespace(materialize=materialize),
    )

    def create():
        worker = references.SettlementReferencePreparation(
            artifacts, archive, SimpleNamespace(directory=tmp_path), maximum_bytes=1024**2
        )
        worker._source = lambda _: source
        return worker

    return SimpleNamespace(
        bundle=bundle,
        archive=archive,
        cache=cache,
        source=source,
        artifacts=artifacts,
        create=create,
        calls=calls,
        root=tmp_path,
    )


async def test_missing_frozen_reference_restores_once_and_last_consumer_reclaims(case, monkeypatch):
    first, second = case.create(), case.create()
    await first.ensure(None)
    assert len(case.calls) == 1
    assert not case.calls[0].exists()
    assert native.verify_preserved_bundle(
        case.bundle, case.archive, case.artifacts.policy
    ) == digest(case.bundle)

    def no_payload_read(*a, **k):
        raise AssertionError("unchanged local receipt reread model payload")

    monkeypatch.setattr(native, "_copy_verified", no_payload_read)
    await first.ensure(None)
    await second.ensure(None)
    first.close()
    assert (case.archive / digest(case.bundle)).exists()
    second.close()
    assert not (case.archive / digest(case.bundle)).exists()
    assert len(case.calls) == 1


async def test_restart_keeps_verified_reference_and_recovers_orphan_transfer_slot(
    case, monkeypatch
):
    first = case.create()
    await first.ensure(None)
    slot = first._slot(case.source)
    slot.mkdir(mode=0o700)
    (slot / "owned-transfer-scratch").write_bytes(b"unfinished cleanup")
    # Simulate a process exit after durable preservation but before scratch cleanup.
    os.close(first.active[1])
    first.active = None

    def no_payload_read(*a, **k):
        raise AssertionError("restart reread already preserved bytes")

    monkeypatch.setattr(native, "_copy_verified", no_payload_read)
    restarted = case.create()
    await restarted.ensure(None)
    assert len(case.calls) == 1 and not slot.exists()
    restarted.close()


async def test_preexisting_archive_is_reused_and_never_owned_or_deleted(case):
    native.preserve_bundle(case.bundle, case.root / "source", case.archive, case.artifacts.policy)
    worker = case.create()
    await worker.ensure(None)
    worker.close()
    assert not case.calls
    assert (case.archive / digest(case.bundle)).exists()


async def test_rollout_default_retains_created_model_until_archive_readers_are_upgraded(case):
    case.artifacts.config.reference_working_set_reclamation = False
    worker = case.create()
    await worker.ensure(None)
    worker.close()
    assert (case.archive / digest(case.bundle)).exists()
    case.artifacts.config.reference_working_set_reclamation = True
    upgraded = case.create()
    await upgraded.ensure(None)
    upgraded.close()
    assert not (case.archive / digest(case.bundle)).exists()
    assert len(case.calls) == 1


async def test_pending_marker_never_authorizes_removing_unproven_archive(case):
    worker = case.create()
    publish_private_model(
        worker._marker(digest(case.bundle)), RootModel(worker._expected(case.source))
    )
    native.preserve_bundle(case.bundle, case.root / "source", case.archive, case.artifacts.policy)
    await worker.ensure(None)
    worker.close()
    assert (case.archive / digest(case.bundle)).exists()


async def test_replaced_generation_is_not_deleted(case):
    worker = case.create()
    await worker.ensure(None)
    original = case.archive / digest(case.bundle)
    retained = case.archive / "external-old-generation"
    original.rename(retained)
    native.preserve_bundle(case.bundle, case.root / "source", case.archive, case.artifacts.policy)
    with pytest.raises(ValueError, match="ownership changed"):
        worker.close()
    assert original.exists() and retained.exists()


async def test_reserve_failure_happens_before_transfer_or_ownership_marker(case, monkeypatch):
    monkeypatch.setattr(references.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    worker = case.create()
    with pytest.raises(OSError, match="operating reserve"):
        await worker.ensure(None)
    assert not case.calls
    assert not worker._marker(digest(case.bundle)).exists()


async def test_native_preservation_failure_keeps_exact_transfer_for_retry(case, monkeypatch):
    worker = case.create()
    original = references.preserve_bundle

    def fail(*a, **k):
        raise OSError("transient publication capacity loss")

    monkeypatch.setattr(references, "preserve_bundle", fail)
    with pytest.raises(OSError, match="capacity loss"):
        await worker.ensure(None)
    assert worker._slot(case.source).exists()
    monkeypatch.setattr(references, "preserve_bundle", original)
    await worker.ensure(None)
    assert not worker._slot(case.source).exists()
    worker.close()


async def test_historical_readonly_archive_needs_no_new_directory_or_source_metadata(
    case, monkeypatch
):
    native.preserve_bundle(case.bundle, case.root / "source", case.archive, case.artifacts.policy)
    case.artifacts.config.reference_preservation_directory = None
    case.artifacts.config.reference_working_set_reclamation = False
    prepared = SimpleNamespace(
        policy_sha256=digest(case.artifacts.policy),
        incumbent_model_sha256=digest(case.bundle),
        cohort_sha256="12" * 32,
        sequence=7,
    )
    review = SimpleNamespace(
        target_cohort_sha256=prepared.cohort_sha256,
        target_sequence=prepared.sequence,
        policy_sha256=prepared.policy_sha256,
        model=case.bundle,
    )
    promotion = SimpleNamespace(
        directory=case.root, certified_cohort_baseline_reference=lambda *a, **k: review
    )

    def no_writes(*a, **k):
        raise AssertionError("historical read-only archive requires no new metadata writes")

    monkeypatch.setattr(references, "ensure_private_directory", no_writes)
    monkeypatch.setattr(references, "_original_source", no_writes)
    worker = references.SettlementReferencePreparation(
        case.artifacts, case.archive, promotion, maximum_bytes=1024**2
    )
    await worker.ensure(prepared)
    worker.close()
    assert not (case.archive / ".reference-working-set").exists()


def test_writable_alias_must_name_exact_same_physical_archive(case):
    wrong = case.root / "different-archive"
    wrong.mkdir(mode=0o700)
    case.artifacts.config.reference_preservation_directory = str(wrong)
    with pytest.raises(ValueError, match="selected archive"):
        case.create()


async def test_writable_owner_reaps_after_last_readonly_consumer_releases(case):
    owner = case.create()
    await owner.ensure(None)
    config = SimpleNamespace(**vars(case.artifacts.config))
    config.reference_preservation_directory = None
    reader_artifacts = SimpleNamespace(**{**vars(case.artifacts), "config": config})
    reader = references.SettlementReferencePreparation(
        reader_artifacts, case.archive, SimpleNamespace(directory=case.root), maximum_bytes=1024**2
    )
    reader._source = lambda _: case.source
    await reader.ensure(None)
    owner.close()
    await owner.reclaim_released()
    assert (case.archive / digest(case.bundle)).exists()
    reader.close()
    await owner.reclaim_released()
    assert not (case.archive / digest(case.bundle)).exists()


async def test_retry_counts_completed_transfer_bytes_only_once(case, monkeypatch):
    worker = case.create()
    slot = worker._slot(case.source)
    native.preserve_bundle(case.bundle, case.root / "source", slot, case.artifacts.policy)
    cache = references.BootDiskModelCache(
        case.artifacts.config.materialization_boot_disk_cache,
        reserve_bytes=case.artifacts.config.materialization_free_space_reserve_bytes,
    )
    rounded = cache.model_bytes(case.bundle)
    _, _, resident = cache._measure(selected=slot)
    # Enough for remaining transfer growth and canonical output, but below the
    # old reserve+2*rounded admission which double-counted the retained slot.
    free = cache.reserve_bytes + rounded + max(0, rounded - resident)
    assert free < cache.reserve_bytes + 2 * rounded
    monkeypatch.setattr(references.shutil, "disk_usage", lambda _: SimpleNamespace(free=free))
    await worker.ensure(None)
    assert not slot.exists()
    worker.close()


async def test_same_digest_local_candidate_reader_prevents_reference_reclamation(case, monkeypatch):
    worker = case.create()
    await worker.ensure(None)
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    original = native._verify_preserved_reader

    def candidate_read(*args):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(30)
        return original(*args)

    monkeypatch.setattr(native, "_verify_preserved_reader", candidate_read)
    read = asyncio.create_task(
        asyncio.to_thread(
            native.verify_preserved_bundle, case.bundle, case.archive, case.artifacts.policy
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), 30)
        worker.close()
        await worker.reclaim_released()
        assert (case.archive / digest(case.bundle)).exists()
    finally:
        release.set()
        await read
    await worker.reclaim_released()
    assert not (case.archive / digest(case.bundle)).exists()


async def test_retry_reclaims_only_native_locked_partial_preservation_before_admission(
    case, monkeypatch
):
    worker = case.create()
    pending = case.archive / (".pending-" + digest(case.bundle))
    pending.mkdir(mode=0o700)
    (pending / "partial-native-copy").write_bytes(b"unfinished")
    unrelated = case.archive / (".pending-" + "ff" * 32)
    unrelated.mkdir(mode=0o700)
    reserve = case.artifacts.config.materialization_free_space_reserve_bytes
    monkeypatch.setattr(
        references.shutil,
        "disk_usage",
        lambda _: SimpleNamespace(
            free=reserve if (pending / "partial-native-copy").exists() else reserve + 4 * 1024**2
        ),
    )
    await worker.ensure(None)
    assert not pending.exists() and unrelated.is_dir()
    assert (case.archive / digest(case.bundle)).exists()
    worker.close()
