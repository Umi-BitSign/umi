"""Retirement reuses real restored bytes and refuses damaged completion state."""

import asyncio
import shutil
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_chunked_model_retirement as retirement
from umi.competition_artifacts import _file_identity
from umi.competition_cohort_legacy_model_cache import LegacyCohortModelCache
from umi.competition_model_generation_store import _paths
from umi.competition_transport_verification import ByteCheckpoints
from umi.open_competition import digest

from .test_competition_chunked_model_backup import backup as backup
from .test_competition_chunked_model_backup import reader
from .test_competition_cohort_cache_retirement import cache as cache
from .test_competition_model_generation_store import owned
from .test_open_competition import policy as policy


async def materialized(case, root, generation_owner=False):
    instance = owned(case, root) if generation_owner else reader(case, root)
    await instance.verify()
    archive = root / "cache"
    await instance.materialize(
        archive,
        maximum_materialized_bytes=1024**2,
        available_bytes=lambda: 8 * 1024**2,
        reserve_bytes=0,
        check_write=lambda size: None,
    )
    case.remote.reads.clear()
    case.remote.heads.clear()
    return instance, archive


@pytest.mark.parametrize("generation_owner", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
async def test_original_and_current_layouts_reuse_without_remote_or_payload_work(
    backup, tmp_path, monkeypatch, generation_owner, legacy
):
    instance, archive = await materialized(backup, tmp_path, generation_owner)
    if legacy:
        current = instance._store(None)
        old = ByteCheckpoints(
            instance.root / instance.selection.binding.model_sha256 / "remote",
            instance._context(),
            None,
        )
        with old:
            for record in backup.bundle.files:
                value = current._validated_record(current._read(current.path(record.path)))
                old.remember(record.path, value["identity"], value["result"])
        shutil.rmtree(current.root)
    before = {
        str(p): (p.read_bytes(), _file_identity(p.stat()))
        for p in instance.root.rglob("*")
        if p.is_file()
    }
    original_open = Path.open

    def metadata_only(path, *args, **kwargs):
        if path.is_relative_to(archive) and path.parent.name == "model":
            raise AssertionError("cleanup reread model payload")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", metadata_only)
    facts = retirement.completed_cache_retirement(instance, archive)
    assert facts == retirement.completed_cache_retirement(instance, archive)
    assert facts["model_sha256"] == digest(backup.bundle)
    assert facts["payload_bytes"] == sum(r.size_bytes for r in backup.bundle.files)
    assert backup.remote.reads == backup.remote.heads == []
    assert before == {
        str(p): (p.read_bytes(), _file_identity(p.stat()))
        for p in instance.root.rglob("*")
        if p.is_file()
    }
    # The existing legacy materializer exposes the same facts to the execution
    # owner; this method itself neither evicts nor supplies terminal authority.
    cache = LegacyCohortModelCache(
        SimpleNamespace(policy=backup.policy),
        SimpleNamespace(policy=backup.policy, reader=lambda source, **kwargs: instance),
    )
    assert cache.completed_cache_retirement(object(), archive) == facts
    assert archive.exists()


@pytest.mark.parametrize("damaged", ["marker", "receipt", "local", "pending", "payload"])
async def test_missing_or_changed_completion_never_repairs_itself(backup, tmp_path, damaged):
    instance, archive = await materialized(backup, tmp_path)
    receipt = instance._store(None).path(backup.bundle.files[0].path)
    if damaged == "marker":
        target = receipt.with_suffix(".complete")
        target.unlink()
    elif damaged == "receipt":
        target = receipt
        target.write_bytes(b"{}")
    elif damaged == "local":
        target = archive / (".verified-" + digest(backup.bundle) + ".json")
        target.unlink()
    elif damaged == "pending":
        target = archive / "materialization-pending.json"
        target.write_text("{}")
    else:
        target = archive / digest(backup.bundle) / "model" / backup.bundle.files[0].path
        target.touch()
    before = target.read_bytes() if target.exists() else None
    with pytest.raises((ValueError, OSError)):
        retirement.completed_cache_retirement(instance, archive)
    assert (target.read_bytes() if target.exists() else None) == before
    assert backup.remote.reads == backup.remote.heads == []


async def test_metadata_replacement_during_read_refuses(backup, tmp_path, monkeypatch):
    instance, archive = await materialized(backup, tmp_path)
    target = instance._store(None).path(backup.bundle.files[0].path)
    read = retirement._read_bounded_private_bytes

    def changed(path, **kwargs):
        raw = read(path, **kwargs)
        if path == target:
            path.write_bytes(raw)
        return raw

    monkeypatch.setattr(retirement, "_read_bounded_private_bytes", changed)
    with pytest.raises(ValueError, match="durable byte facts changed"):
        retirement.completed_cache_retirement(instance, archive)


@pytest.mark.parametrize("change", ["damage", "owner_missing", "journal"])
async def test_selected_generation_damage_and_recovery_are_not_cleanup(backup, tmp_path, change):
    instance, archive = await materialized(backup, tmp_path, True)
    _, directory, marker = _paths(instance.root, instance.generation_owner)
    database = directory / "rounds.sqlite3"
    if change == "damage":
        value = next(iter(instance._retained_generations().values()))
        instance._generations().hold(value.model_dump(mode="json"), reason="fixture_damage")
    elif change == "owner_missing":
        marker.unlink()
    else:
        Path(str(database) + "-journal").write_bytes(b"must not recover during cleanup")
    with pytest.raises((ValueError, OSError)):
        retirement.completed_cache_retirement(instance, archive)
    if change == "journal":
        assert Path(str(database) + "-journal").read_bytes() == b"must not recover during cleanup"
    assert backup.remote.reads == backup.remote.heads == []


@pytest.mark.parametrize("field", ["key", "sha256", "size_bytes"])
async def test_valid_receipt_checksum_cannot_substitute_another_object(backup, tmp_path, field):
    instance, archive = await materialized(backup, tmp_path)
    record = backup.bundle.files[0]
    saved = instance._store(None)
    value = saved._validated_record(saved._read(saved.path(record.path)))
    identity = value["identity"]
    identity[0][field] = {
        "key": "other/chunk",
        "sha256": "ff" * 32,
        "size_bytes": identity[0]["size_bytes"] + 1,
    }[field]
    with saved:
        saved.remember(record.path, identity, record.sha256)
    with pytest.raises(ValueError, match="remote object coverage changed"):
        retirement.completed_cache_retirement(instance, archive)
    assert backup.remote.reads == backup.remote.heads == []


async def test_unrelated_generation_progress_keeps_retirement_eligible(backup, tmp_path):
    instance, archive = await materialized(backup, tmp_path, True)
    facts = retirement.completed_cache_retirement(instance, archive)
    instance._generations().journal.put("unrelated-completion", "ab" * 32, {"complete": True})
    async with retirement.retirement_generation_lease(facts):
        assert archive.exists()
    assert backup.remote.reads == backup.remote.heads == []


async def test_generation_lease_serializes_damage_and_drains_on_cancellation(backup, tmp_path):
    instance, archive = await materialized(backup, tmp_path, True)
    facts = retirement.completed_cache_retirement(instance, archive)
    started, inside = threading.Event(), asyncio.Event()
    released = asyncio.Event()
    owner = instance._generations()
    value = next(iter(instance._retained_generations().values())).model_dump(mode="json")

    async def retire():
        async with retirement.retirement_generation_lease(facts):
            inside.set()
            await released.wait()

    def damage():
        started.set()
        owner.hold(value, reason="concurrent_damage")

    task = asyncio.create_task(retire())
    await asyncio.wait_for(inside.wait(), 5)
    writer = asyncio.create_task(asyncio.to_thread(damage))
    try:
        assert await asyncio.to_thread(started.wait, 5)
        await asyncio.sleep(0.05)
        assert not writer.done(), "damage commit passed the held retirement snapshot"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        await asyncio.wait_for(writer, 5)
        with pytest.raises(ValueError, match="held"):
            async with retirement.retirement_generation_lease(facts):
                raise AssertionError("damaged source reached eviction")
    finally:
        released.set()
        await asyncio.gather(task, writer, return_exceptions=True)


async def test_lease_failure_before_readiness_is_observed(backup, tmp_path):
    instance, archive = await materialized(backup, tmp_path, True)
    facts = retirement.completed_cache_retirement(instance, archive)
    _, _, marker = _paths(instance.root, instance.generation_owner)
    marker.unlink()
    with pytest.raises(ValueError, match="owner unavailable"):
        async with retirement.retirement_generation_lease(facts):
            raise AssertionError("missing owner reached eviction")


@pytest.mark.parametrize("interruption", ["after_unlink", "damage_before_unlink"])
async def test_execution_owner_retires_legacy_cache_and_resumes_original_intent(
    backup, tmp_path, cache, monkeypatch, interruption
):
    s = cache
    instance = owned(backup, tmp_path)
    await instance.verify()
    shutil.rmtree(s.archive)  # Replace only the fixture's inert candidate.
    await instance.materialize(
        s.archive,
        maximum_materialized_bytes=1024**2,
        available_bytes=lambda: 8 * 1024**2,
        reserve_bytes=0,
        check_write=lambda size: None,
    )
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    legacy = LegacyCohortModelCache(
        SimpleNamespace(policy=backup.policy),
        SimpleNamespace(policy=backup.policy, reader=lambda source, **kwargs: instance),
    )

    async def source(job, role):
        return SimpleNamespace(request=instance.selection, materializer=legacy)

    s.port._source_plan = source
    original_put = s.journal.put
    owner = instance._generations()
    value = next(iter(instance._retained_generations().values())).model_dump(mode="json")

    def interrupted(kind, key, value_):
        if kind == "model_cache_retired" and interruption == "after_unlink":
            raise OSError("fixture completion interruption")
        result = original_put(kind, key, value_)
        if kind == "model_cache_retirement" and interruption == "damage_before_unlink":
            owner.hold(value, reason="damage_before_eviction")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(s.journal, "put", interrupted)
        with pytest.raises((OSError, ValueError)):
            await s.create()()
    assert len(s.journal.keys("model_cache_retirement")) == 1
    if interruption == "after_unlink":
        assert not s.archive.exists()
        assert (await s.create()())["retired_models"] == 1
        assert len(s.journal.keys("model_cache_retired")) == 1
    else:
        assert s.archive.exists()
        assert not s.journal.keys("model_cache_retired")
    assert backup.remote.reads == backup.remote.heads == []
