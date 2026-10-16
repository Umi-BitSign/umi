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
