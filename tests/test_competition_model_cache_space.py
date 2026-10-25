"""Boot-disk allocation boundaries use real cache files, never a larger FS quota."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_model_cache_space as space
from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
)
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_model_cache_space import BootDiskModelCache, BootDiskModelCacheConfig
from umi.private_files import ensure_private_directory
from umi.protocol import canonical_json_bytes


def test_resident_capacity_counts_existing_bytes_and_preserves_physical_reserve(
    managed, monkeypatch
):
    cache = managed.cache
    entries = {}
    allocated, _, _ = cache._measure(entries=entries)
    resident = sum(
        size
        for path, size in entries.items()
        if managed.archive in path.parents
        or path == managed.archive
        or managed.peer in path.parents
        or path == managed.peer
    )
    unrelated = allocated - resident
    monkeypatch.setattr(
        space.shutil, "disk_usage", lambda _: SimpleNamespace(free=cache.reserve_bytes + 4096)
    )
    with pytest.raises(ValueError, match="allocation lease"):
        cache.resident_capacity()
    with cache.allocation_lease():
        assert cache.resident_capacity() == resident + 4096
        monkeypatch.setattr(
            space.shutil, "disk_usage", lambda _: SimpleNamespace(free=cache.reserve_bytes - 8192)
        )
        assert cache.resident_capacity() == resident - 8192
        monkeypatch.setattr(space.shutil, "disk_usage", lambda _: SimpleNamespace(free=1024**4))
        assert cache.resident_capacity() == cache.maximum_bytes - unrelated
        other = cache.root / "unrelated.bin"
        with other.open("wb") as stream:
            stream.truncate(1024**2)
        other.chmod(0o600)
        assert cache.resident_capacity() == cache.maximum_bytes - unrelated - 1024**2
        assert other.exists()


@pytest.fixture
def managed(tmp_path):
    from umi.open_competition import BundleFile, digest

    from .test_open_competition import bundle_at

    bundle = bundle_at(tmp_path / "original", "leased")
    bundle = bundle.model_copy(
        update={
            "files": (
                *bundle.files,
                BundleFile(
                    path="z-append.bin",
                    role="weights",
                    sha256="ab" * 32,
                    size_bytes=512 * 1024,
                ),
            )
        }
    )
    config = BootDiskModelCacheConfig(
        schema="umi-boot-disk-model-cache/1",
        directory=str(tmp_path / "managed"),
        maximum_allocated_bytes=8 * 1024**2,
    )
    cache = BootDiskModelCache(config, reserve_bytes=1024**2)
    archive = cache.root / "direct-model-cache" / "archive"
    target = archive / digest(bundle) / "model" / "z-append.bin"
    for path in (cache.root, archive.parent, archive, target.parent.parent, target.parent):
        ensure_private_directory(path)
    target.touch(mode=0o600)
    peer = cache.root / "direct-model-cache" / "standby"
    ensure_private_directory(peer)
    for index in range(512):
        p = peer / str(index)
        p.write_bytes(b"retained")
        p.chmod(0o400)
    return SimpleNamespace(cache=cache, bundle=bundle, archive=archive, target=target, peer=peer)


def test_exclusive_path_accounting_walks_peer_once_and_checks_free_space_each_write(
    managed, monkeypatch, caplog
):
    caplog.set_level("INFO", logger="umi.competition.progress")
    m = managed
    walks = free_checks = 0
    measure, usage = m.cache._measure, space.shutil.disk_usage

    def counted(*args, **kwargs):
        nonlocal walks
        walks += 1
        return measure(*args, **kwargs)

    def disk(path):
        nonlocal free_checks
        free_checks += 1
        return usage(path)

    monkeypatch.setattr(m.cache, "_measure", counted)
    monkeypatch.setattr(space.shutil, "disk_usage", disk)
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        assert walks == 0
        with m.target.open("ab", buffering=0) as output:
            for _ in range(64):
                m.cache.check_file_write(m.target, 4096)
                output.write(b"x" * 4096)
        assert m.cache.incremental and walks == 1 and free_checks == 64
        observed = m.cache.allocated
        assert observed <= m.cache.maximum_bytes
    # A new transfer takes a fresh metadata snapshot; process memory is never
    # a durable capacity certificate. The original private peers are preserved.
    assert not m.cache.leased and m.cache.allocations is None
    actual, _ = m.cache._allocation()
    assert walks == 2 and actual <= m.cache.maximum_bytes
    assert m.target.stat().st_size == 64 * 4096 and len(tuple(m.peer.iterdir())) == 512
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert events[0]["allocation_basis"] == "exclusive_transfer_path_accounting"


def test_exclusive_path_accounting_refuses_consumed_physical_reserve(managed, monkeypatch):
    m = managed
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        m.cache.check_file_write(m.target, 4096)
        m.target.write_bytes(b"x" * 4096)
        monkeypatch.setattr(
            space.shutil,
            "disk_usage",
            lambda p: SimpleNamespace(
                free=m.cache.reserve_bytes + m.cache.metadata_bytes + 4095,
            ),
        )
        with pytest.raises(OSError, match="reserve is unavailable"):
            m.cache.check_file_write(m.target, 4096)
    assert m.target.stat().st_size == 4096


def test_exclusive_path_accounting_still_enforces_shared_logical_bound(managed):
    m = managed
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        m.cache.available_bytes()
        m.cache.maximum_bytes = m.cache.allocated + m.cache.metadata_bytes + 4095
        with pytest.raises(OSError, match="capacity"):
            m.cache.check_file_write(m.target, 4096)
    assert m.target.stat().st_size == 0


def test_unknown_consumer_appearing_during_transfer_restores_complete_accounting(managed):
    m = managed
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        m.cache.check_file_write(m.target, 4096)
        outsider = m.cache.root / "unrelated-consumer"
        outsider.touch(mode=0o600)
        with outsider.open("wb") as stream:
            stream.truncate(m.cache.maximum_bytes)
        with pytest.raises(OSError, match="exceeds its configured bound"):
            m.cache.check_file_write(m.target, 4096)
        assert not m.cache.incremental
    assert outsider.stat().st_size == m.cache.maximum_bytes


@pytest.mark.parametrize("unsafe", ("outside", "length", "symlink", "hardlink", "public"))
def test_path_accounting_requires_private_signed_files_and_lengths(managed, unsafe):
    m = managed
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        if unsafe == "outside":
            target, size = m.peer / "0", 1
        else:
            target, size = m.target, 1
        if unsafe == "length":
            size = 512 * 1024 + 1
        elif unsafe == "symlink":
            target.unlink()
            target.symlink_to(m.peer / "0")
        elif unsafe == "hardlink":
            (m.archive / "another-link").hardlink_to(target)
        elif unsafe == "public":
            target.chmod(0o644)
        with pytest.raises(ValueError, match=r"allocation|exclusive"):
            m.cache.check_file_write(target, size)


def test_restarted_accounting_counts_partial_cleanup_before_first_capacity_read(managed):
    m = managed
    m.target.write_bytes(b"x" * (128 * 1024))
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        # Native restoration removes an incomplete file before space accounting.
        m.target.unlink()
        m.target.touch(mode=0o600)
        m.cache.check_file_write(m.target, 4096)
        m.target.write_bytes(b"x" * 4096)
    restarted = BootDiskModelCache(
        SimpleNamespace(directory=str(m.cache.root), maximum_allocated_bytes=m.cache.maximum_bytes),
        reserve_bytes=m.cache.reserve_bytes,
    )
    with restarted.allocation_lease():
        restarted.prepare(m.bundle, archive=m.archive)
        restarted.check_file_write(m.target, 4096)
        assert restarted.incremental


def test_legacy_pathless_writer_and_nested_workspace_keep_complete_scans(managed, monkeypatch):
    m = managed
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        m.cache.check_write(4096)
        assert not m.cache.incremental
    workspace = m.cache.root / "live-invocations"
    ensure_private_directory(workspace)
    with m.cache.allocation_lease():
        m.cache.prepare(m.bundle, archive=m.archive)
        assert not m.cache.incremental
        m.cache.check_file_write(m.target, 4096)


@pytest.fixture
def config(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    return DirectModelReviewSourceConfig(
        schema="umi-direct-model-review-source/2",
        r2_credentials_file=str(tmp_path / "unused-credentials"),
        r2_bucket="model-artifacts",
        materialization_protected_roots=(str(protected),),
        maximum_materialized_bytes=1024**2,
        standing_review_policy=StandingModelReviewPolicy(
            schema="umi-standing-model-artifact-review-policy/1",
            competition_policy_sha256="ab" * 32,
            contribution_terms_sha256="cd" * 32,
            standing_approval_record_sha256="ef" * 32,
            approved_by="operator@example.test",
            approved_at_utc="2026-10-02T12:00:00Z",
            complete_declared_bundle_rights_approved=True,
            licenses_and_notices_reviewed=True,
            public_redistribution_and_evaluation_approved=True,
        ),
    )


def boot(config, tmp_path):
    return DirectModelReviewSourceConfig.model_validate_json(
        canonical_json_bytes(
            config.model_copy(
                update={
                    "materialization_boot_disk_cache": BootDiskModelCacheConfig(
                        schema="umi-boot-disk-model-cache/1",
                        directory=str(tmp_path / "cache"),
                        maximum_allocated_bytes=2 * 1024**2,
                    )
                }
            )
        )
    )


def reviewer(config):
    # This boundary is independent of wallets, policy review and providers.
    result = object.__new__(DirectModelArtifactReviewer)
    result.config = config
    return result


def test_legacy_canonical_bytes_and_explicit_boot_mode(config, tmp_path):
    raw = canonical_json_bytes(config)
    assert "materialization_boot_disk_cache" not in json.loads(raw)
    assert canonical_json_bytes(DirectModelReviewSourceConfig.model_validate_json(raw)) == raw
    assert (
        canonical_json_bytes(config.model_copy(update={"materialization_boot_disk_cache": None}))
        == raw
    )
    selected = boot(config, tmp_path)
    restored = DirectModelReviewSourceConfig.model_validate_json(canonical_json_bytes(selected))
    assert restored == selected
    assert restored.materialization_protected_roots == config.materialization_protected_roots
    assert restored.materialization_filesystem_maximum_bytes == 96 * 1024**3


def test_boot_mode_uses_real_shared_filesystem_without_dropping_protected_roots(config, tmp_path):
    selected = boot(config, tmp_path)
    cache_root = Path(selected.materialization_boot_disk_cache.directory)
    ensure_private_directory(cache_root)
    assert cache_root.stat().st_dev == Path(config.materialization_protected_roots[0]).stat().st_dev
    with pytest.raises(OSError, match="shares a protected filesystem"):
        reviewer(config).verify_materialization_filesystem(cache_root)
    usage = reviewer(selected).verify_materialization_filesystem(cache_root)
    assert usage.free > selected.materialization_free_space_reserve_bytes
    with pytest.raises(ValueError, match="outside its shared cache root"):
        reviewer(selected).verify_materialization_filesystem(tmp_path / "elsewhere")
    Path(config.materialization_protected_roots[0]).rmdir()
    with pytest.raises(OSError, match="protected filesystem is unavailable"):
        reviewer(selected).verify_materialization_filesystem(cache_root)


@pytest.mark.parametrize("overlap", ["same", "parent", "child"])
def test_boot_mode_refuses_protected_ancestry_before_writing(config, tmp_path, overlap):
    selected = boot(config, tmp_path)
    root = Path(selected.materialization_boot_disk_cache.directory)
    protected = {"same": root, "parent": root.parent, "child": root / "state"}[overlap]
    value = selected.model_copy(update={"materialization_protected_roots": (str(protected),)})
    with pytest.raises(ValueError, match="overlaps a protected root"):
        DirectModelReviewSourceConfig.model_validate_json(canonical_json_bytes(value))
    assert not root.exists()


def test_aggregate_cache_bound_counts_other_candidates_and_sparse_allocations(config, tmp_path):
    selected = boot(config, tmp_path)
    budget = BootDiskModelCache(
        selected.materialization_boot_disk_cache, reserve_bytes=64 * 1024**2
    )
    budget.validate_root(budget.root)
    retained = budget.root / "other-candidate"
    retained.mkdir(mode=0o700)
    path = retained / "weights"
    with path.open("wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.truncate(budget.maximum_bytes)
    with pytest.raises(OSError, match="exceeds its configured bound"):
        budget.check_write(1)
    # Allocation accounting never evicts someone else's cache to fit a transfer.
    assert path.exists() and path.stat().st_size == budget.maximum_bytes


def test_complete_slot_projection_counts_partial_bytes_once_and_keeps_other_allocations(
    config, tmp_path, monkeypatch
):
    from .test_open_competition import bundle_at

    selected = boot(config, tmp_path)
    budget = BootDiskModelCache(selected.materialization_boot_disk_cache, reserve_bytes=1024**2)
    budget.validate_root(budget.root)
    bundle = bundle_at(tmp_path / "original", "projection")
    archive = budget.root / "archive"
    archive.mkdir(mode=0o700)
    partial = archive / "partial"
    partial.write_bytes(b"retained")
    partial.chmod(0o600)
    assert budget.fits_materialization(bundle, archive)
    before = partial.stat()
    monkeypatch.setattr(
        space.shutil, "disk_usage", lambda path: SimpleNamespace(free=budget.reserve_bytes)
    )
    assert not budget.fits_materialization(bundle, archive)
    assert partial.stat() == before
    with pytest.raises(ValueError, match="outside"):
        budget.fits_materialization(bundle, budget.root.parent / "outside")


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "public", "mount"])
def test_cache_accounting_refuses_unsafe_entries(config, tmp_path, monkeypatch, unsafe):
    selected = boot(config, tmp_path)
    budget = BootDiskModelCache(
        selected.materialization_boot_disk_cache, reserve_bytes=64 * 1024**2
    )
    budget.validate_root(budget.root)
    path = budget.root / "entry"
    if unsafe == "symlink":
        path.symlink_to(tmp_path / "protected", target_is_directory=True)
    else:
        path.write_bytes(b"retained")
        path.chmod(0o600)
        if unsafe == "hardlink":
            (tmp_path / "another-name").hardlink_to(path)
        elif unsafe == "public":
            path.chmod(0o644)
        else:
            original = Path.lstat

            def changed_device(selected, *args, **kwargs):
                info = original(selected, *args, **kwargs)
                if selected == path:
                    return SimpleNamespace(st_dev=info.st_dev + 1)
                return info

            monkeypatch.setattr(Path, "lstat", changed_device)
    with pytest.raises(ValueError, match="unsafe allocation"):
        budget.available_bytes()


def test_shared_transfer_lock_releases_after_interruption_and_preserves_retained_bytes(
    config, tmp_path
):
    selected = boot(config, tmp_path)
    first = BootDiskModelCache(selected.materialization_boot_disk_cache, reserve_bytes=1024**2)
    restarted = BootDiskModelCache(selected.materialization_boot_disk_cache, reserve_bytes=1024**2)
    with pytest.raises(OSError, match="interruption"), first.allocation_lease():
        with pytest.raises(BlockingIOError), restarted.allocation_lease():
            pytest.fail("two allocators entered the shared cache")
        raise OSError("interruption")
    with restarted.allocation_lease():
        restarted.check_write(64)


def test_disk_reserve_is_rechecked_after_external_consumption(
    config, tmp_path, monkeypatch, caplog
):
    caplog.set_level("INFO", logger="umi.competition.progress")
    selected = boot(config, tmp_path)
    budget = BootDiskModelCache(selected.materialization_boot_disk_cache, reserve_bytes=1024**2)
    budget.validate_root(budget.root)
    budget.check_write(64)
    event = json.loads(caplog.records[-1].message)
    assert event["stage"] == "model_cache_local_space"
    assert event["allocated_bytes"] > 0
    assert event["maximum_allocated_bytes"] == budget.maximum_bytes
    assert event["eta_seconds"] == 0
    assert event["eta_scope"] == "space_check_only_not_materialization"
    assert event["elapsed_seconds"] >= 0
    monkeypatch.setattr(
        space.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=1024**4, free=budget.reserve_bytes + 4095),
    )
    with pytest.raises(OSError, match="reserve is unavailable"):
        budget.check_write(1)
    event = json.loads(caplog.records[-1].message)
    assert event["status"] == "retrying"
    assert event["eta_seconds"] is None
    assert event["eta_basis"] == "withdrawn_capacity_unavailable"


def test_process_death_releases_allocation_lease_without_deleting_partial_cache(config, tmp_path):
    selected = boot(config, tmp_path)
    cache_config = selected.materialization_boot_disk_cache
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from umi.competition_model_cache_space import BootDiskModelCache, BootDiskModelCacheConfig
config = BootDiskModelCacheConfig.model_validate_json(sys.argv[2])
cache = BootDiskModelCache(config, reserve_bytes=1024**2)
with cache.allocation_lease():
    descriptor = os.open(cache.root / 'partial', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(descriptor, b'partial transfer')
    os.fsync(descriptor)
    os._exit(23)
""",
            str(Path(space.__file__).parents[1]),
            canonical_json_bytes(cache_config).decode(),
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert child.returncode == 23, child.stderr.decode()
    restarted = BootDiskModelCache(cache_config, reserve_bytes=1024**2)
    with restarted.allocation_lease():
        restarted.check_write(64)
        assert (restarted.root / "partial").read_bytes() == b"partial transfer"
