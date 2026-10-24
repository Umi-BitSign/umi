"""Bounded private metadata; immutable facts and explicit native receipt ABI."""

from types import SimpleNamespace

import pytest

from umi import competition_cohort_export_checkpoint as module
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


def checkpoint():
    job = "22" * 32
    return module.PartialExportCheckpoint(
        schema="umi-private-model-partial-export/1",
        context_sha256="11" * 32,
        owner_path="/tmp/native-owner/rounds.sqlite3",
        owner_device="1",
        owner_inode="2",
        slot="33" * 32,
        cohort_sha256="44" * 32,
        assignment_sha256="55" * 32,
        job_sha256=job,
        step_keys=tuple(
            digest(dict(schema="umi-cohort-execution-step/1", job=job, index=i)) for i in range(6)
        ),
        step_sha256s=("66" * 32, None, None, None, None, None),
        manifest_sha256="77" * 32,
        maximum_bytes=65536,
        completed_by_block=100,
    ).sealed()


def test_checkpoint_is_immutable_and_checksum_detects_changed_facts():
    value = checkpoint()
    assert value.checked() == value
    with pytest.raises(ValueError):
        value.job_sha256 = "00" * 32
    with pytest.raises(ValueError, match="checksum changed"):
        value.model_copy(update={"owner_inode": "3"}).checked()


def test_native_receipt_abi_is_distinct_from_chain_runtime(monkeypatch):
    monkeypatch.setattr(module, "runtime_identity", lambda: "ff" * 32)
    assert not module.legacy_publication_compatible()


def test_memory_cache_obeys_total_byte_budget(tmp_path, monkeypatch):
    value = checkpoint()
    size = len(canonical_json_bytes(value))
    monkeypatch.setattr(module, "MAX_CHECKPOINT_TOTAL_BYTES", size * 2 + 1)
    cache = module.ModelPartialExportCheckpoints(tmp_path)
    for key in ("a", "b", "c"):
        cache._remember(key, value)
    assert tuple(cache.entries) == ("b", "c")
    assert cache.retained_bytes == size * 2
    cache._remember("c", value)
    assert cache.retained_bytes == size * 2


def test_abandoned_atomic_bytes_count_toward_capacity(tmp_path, monkeypatch, caplog):
    cache = module.ModelPartialExportCheckpoints(tmp_path)
    cache.root.mkdir(mode=0o700)
    value = checkpoint()
    size = len(canonical_json_bytes(value))
    monkeypatch.setattr(module, "MAX_CHECKPOINT_TOTAL_BYTES", size * 2)
    pending = cache.root / ".publish-interrupted"
    pending.write_bytes(b"x" * (size * 2))
    owner = SimpleNamespace(journal=SimpleNamespace(path=value.owner_path))
    cache.remember(owner, value)
    assert "capacity_required" in caplog.text
    assert pending.read_bytes() == b"x" * (size * 2)
    assert not list(cache.root.glob("*.json"))
    assert cache.load(owner, value.slot) == value
