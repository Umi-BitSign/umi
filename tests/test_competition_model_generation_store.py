"""Original byte generations survive restart without disguising remote damage."""

import select
import shutil
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from umi.competition_chunked_model_backup import BYTE_ABI, ChunkedModelBackupReader
from umi.competition_model_byte_store import ModelByteStoreConfig, qualify_shared_byte_stores
from umi.competition_model_generation_store import (
    ModelGenerationOwnerBusy,
    ModelGenerationRepairRequired,
    ModelGenerationStoreConfig,
    grow_generation_owner,
    initialize_generation_owner,
)
from umi.competition_transport_verification import (
    ByteCheckpoints,
    TransferProgress,
    verifier_semantics,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.r2_multipart import _R2HTTPFailure

from .test_competition_chunked_model_backup import backup as backup
from .test_competition_chunked_model_backup import reader, selected, selection
from .test_open_competition import policy as policy


def owned(case, tmp_path, *, initialize=True, owner=None, source=None):
    plain = reader(case, tmp_path)
    config = owner or ModelGenerationStoreConfig(
        schema="umi-model-generation-owner/1",
        owner_sha256="ab" * 32,
        namespace_sha256=digest(plain._namespace()),
        retention="retain_original_generations_until_authenticated_release",
    )
    if initialize:
        initialize_generation_owner(plain.root, config, semantics=[BYTE_ABI, verifier_semantics()])
    return ChunkedModelBackupReader(
        selection(case) if source is None else source,
        policy=case.policy,
        multipart=case.remote,
        verification_root=plain.root,
        generation_owner=config,
    )


async def test_restart_reuses_generations_without_head_or_download(backup, tmp_path):
    first = await owned(backup, tmp_path).verify()
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    instance = owned(backup, tmp_path)
    assert await instance.verify(completed_only=True) == first
    instance.require_verified(first)
    await instance.export_completed()
    assert backup.remote.heads == backup.remote.reads == []


@pytest.mark.parametrize("legacy_layout", [False, True])
async def test_native_legacy_metadata_migration_preserves_bytes_and_never_heads(
    backup, tmp_path, legacy_layout
):
    original = reader(backup, tmp_path)
    snapshot = await original.verify()
    root = original._store(None).root
    if legacy_layout:
        legacy = original.root / backup.binding.model_sha256 / "remote"
        heads = {value.sha256: value for value in snapshot.objects}
        with (
            TransferProgress("fixture_original_layout", 1) as progress,
            ByteCheckpoints(legacy, original._context(), progress) as saved,
        ):
            for record, item in zip(
                backup.bundle.files, original.selection.package.files, strict=True
            ):
                saved.remember(record.path, original._source(item, heads), record.sha256)
            progress.advance(1)
        shutil.rmtree(root)
        root = legacy
    before = {p.name: (p.read_bytes(), p.stat().st_ino) for p in root.iterdir() if p.is_file()}
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    assert await owned(backup, tmp_path).verify(completed_only=True) == snapshot
    after = {p.name: (p.read_bytes(), p.stat().st_ino) for p in root.iterdir() if p.is_file()}
    assert before == after
    assert backup.remote.heads == backup.remote.reads == []


async def test_authenticated_completion_snapshot_migration_is_metadata_only(backup, tmp_path):
    original = reader(backup, tmp_path)
    snapshot = await original.verify()
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    instance = owned(backup, tmp_path)
    assert instance.migrate_completed_generations(snapshot)
    assert instance.migrate_completed_generations(snapshot)
    assert instance._retained_generations() == {v.sha256: v for v in snapshot.objects}
    assert backup.remote.heads == backup.remote.reads == []


async def test_changed_generation_on_actual_read_holds_every_reader_until_original_repair(
    backup, tmp_path
):
    snapshot = await owned(backup, tmp_path).verify()
    instance = owned(backup, tmp_path)
    key = snapshot.objects[0].key
    backup.remote.etags[key] = "replacement"
    # Historical byte completion is not a current availability probe.
    assert await instance.verify(completed_only=True) == snapshot
    with pytest.raises(ValueError, match="generation changed"):
        await instance.available()
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        await owned(backup, tmp_path).verify(completed_only=True)
    assert backup.remote.heads == backup.remote.reads == []
    with pytest.raises(ValueError, match="generation changed"):
        await instance.repair_generations()
    backup.remote.etags[key] = "original-generation"
    backup.remote.reads.clear()
    await instance.repair_generations()
    assert backup.remote.reads == [key]
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    assert await owned(backup, tmp_path).verify(completed_only=True) == snapshot
    assert backup.remote.heads == backup.remote.reads == []
    # A second damage event must not inherit the first event's repair.
    backup.remote.etags[key] = "replacement-again"
    with pytest.raises(ValueError):
        await instance.available()
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        await owned(backup, tmp_path).verify(completed_only=True)


@pytest.mark.parametrize("fault", ["missing", "corrupt", "get404", "quota", "network"])
async def test_actual_transfer_damage_is_distinct_from_retry(backup, tmp_path, monkeypatch, fault):
    instance = owned(backup, tmp_path)
    snapshot = await instance.verify()
    record = backup.bundle.files[0]
    chunk = instance.selection.package.files[0].chunks[0]
    key = instance._key(chunk)
    if fault == "missing":
        del backup.remote.objects[key]
    elif fault == "corrupt":
        backup.remote.objects[key] = b"x" * record.size_bytes
    else:

        async def failed(*args, **kwargs):
            if fault == "network":
                raise OSError("transport unavailable")
            raise _R2HTTPFailure(404 if fault == "get404" else 429, None)

        monkeypatch.setattr(backup.remote, "read_range", failed)
    with pytest.raises((OSError, ValueError)):
        await instance.read_verified_range(
            snapshot, file_index=0, offset=0, size_bytes=record.size_bytes
        )
    if fault in {"quota", "network"}:
        assert await owned(backup, tmp_path).verify(completed_only=True) == snapshot
    else:
        with pytest.raises(ModelGenerationRepairRequired, match="held"):
            await owned(backup, tmp_path).verify(completed_only=True)


@pytest.mark.parametrize("fault", ["database", "enrollment", "schema", "completion"])
async def test_lost_or_damaged_ledger_never_becomes_first_pass(backup, tmp_path, fault):
    instance = owned(backup, tmp_path)
    await instance.verify()
    path = instance._generations().journal.path
    if fault == "database":
        path.unlink()
    elif fault == "enrollment":
        (path.parent.parent / (instance.generation_owner.owner_sha256 + ".json")).unlink()
    else:
        with sqlite3.connect(path) as db:
            db.execute("DROP TRIGGER round_generation_model_owner_delete")
            if fault == "completion":
                db.execute("DELETE FROM records WHERE kind='scope'")
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    with pytest.raises(ModelGenerationRepairRequired):
        await owned(backup, tmp_path, initialize=False).verify()
    assert backup.remote.heads == backup.remote.reads == []


async def test_same_chunks_share_generation_facts_without_model_authority(backup, tmp_path):
    one = owned(backup, tmp_path)
    original = await one.verify()
    different = selected(backup.policy, weights=b"new independent model weights")
    different.remote.objects.update(backup.remote.objects)
    different.remote.etags.update(backup.remote.etags)
    two = owned(different, tmp_path)
    second = await two.verify()
    new_keys = set(different.remote.objects) - set(backup.remote.objects)
    assert set(different.remote.heads) == new_keys
    assert set(different.remote.reads) == new_keys
    with pytest.raises(ValueError, match="selected source"):
        two.require_verified(original)
    assert second.selection_sha256 != original.selection_sha256


async def test_independent_root_does_not_inherit_another_owner_state(backup, tmp_path):
    await owned(backup, tmp_path / "one").verify()
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    with pytest.raises(ModelGenerationRepairRequired):
        await owned(backup, tmp_path / "two", initialize=False).verify()
    assert backup.remote.heads == backup.remote.reads == []


async def test_namespace_and_semantics_are_owned_not_rebound(backup, tmp_path):
    instance = owned(backup, tmp_path)
    await instance.verify()
    other = instance.generation_owner.model_copy(update={"namespace_sha256": "cc" * 32})
    with pytest.raises(ValueError, match="namespace"):
        owned(backup, tmp_path, initialize=False, owner=other)
    with pytest.raises(ModelGenerationRepairRequired):
        from umi.competition_model_generation_store import ModelGenerationStore

        ModelGenerationStore(instance.root, instance.generation_owner, semantics=["different"])


async def test_ordinary_restore_checks_original_generation_and_publishes_damage(backup, tmp_path):
    instance = owned(backup, tmp_path)
    snapshot = await instance.verify()
    backup.remote.etags[snapshot.objects[0].key] = "changed"
    with pytest.raises(ValueError, match="generation changed"):
        await instance.materialize(
            tmp_path / "cache",
            maximum_materialized_bytes=1024**2,
            available_bytes=lambda: 1024**3,
            reserve_bytes=1024,
            check_write=lambda size: None,
        )
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        instance.require_verified(snapshot)


async def test_repair_cannot_clear_damage_observed_during_its_transfer(
    backup, tmp_path, monkeypatch
):
    instance = owned(backup, tmp_path)
    snapshot = await instance.verify()
    value = snapshot.objects[0]
    instance._hold_generation(value, "initial-observation")
    original = backup.remote.read_range

    async def concurrent(key, **kwargs):
        raw = await original(key, **kwargs)
        instance._hold_generation(value, "concurrent-observation")
        return raw

    monkeypatch.setattr(backup.remote, "read_range", concurrent)
    with pytest.raises(ModelGenerationRepairRequired, match="changed during repair"):
        await instance.repair_generations()
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        instance.require_verified(snapshot)


def test_old_store_configuration_bytes_remain_unchanged(tmp_path):
    value = {
        "schema": "umi-model-byte-verification-store/1",
        "directory": str(tmp_path),
        "imports": [],
    }
    assert canonical_json_bytes(
        ModelByteStoreConfig.model_validate_json(canonical_json_bytes(value))
    ) == canonical_json_bytes(value)


async def test_interrupted_migration_retains_completed_objects_and_never_reads_remote(
    backup, tmp_path, monkeypatch
):
    from umi.competition_model_generation_store import _GenerationIndex

    snapshot = await reader(backup, tmp_path).verify()
    instance = owned(backup, tmp_path)
    original = _GenerationIndex.put
    completed = []

    def interrupted(journal, kind, key, value):
        if kind == "object":
            if completed:
                raise OSError("fixture migration interruption")
            completed.append(key)
        return original(journal, kind, key, value)

    monkeypatch.setattr(_GenerationIndex, "put", interrupted)
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    with pytest.raises(OSError, match="interruption"):
        instance.migrate_completed_generations(snapshot)
    assert len(instance._generations().known(instance._declarations())) == 1
    monkeypatch.setattr(_GenerationIndex, "put", original)
    assert instance.migrate_completed_generations(snapshot)
    assert await owned(backup, tmp_path).verify(completed_only=True) == snapshot
    assert backup.remote.heads == backup.remote.reads == []


async def test_live_writer_does_not_make_a_committed_owner_look_damaged(backup, tmp_path):
    instance = owned(backup, tmp_path)
    snapshot = await instance.verify()
    owner = instance._generations()
    entered, release = threading.Event(), threading.Event()
    errors = []

    def writing():
        try:
            with owner.journal.transaction() as db:
                db.execute("INSERT INTO records VALUES ('fixture','writer',?)", (b"{}",))
                entered.set()
                assert release.wait(10)
        except BaseException as error:
            errors.append(error)
            entered.set()

    thread = threading.Thread(target=writing)
    thread.start()
    try:
        assert entered.wait(5)
        reopened = owned(backup, tmp_path, initialize=False)
        assert reopened._retained_generations() == {v.sha256: v for v in snapshot.objects}
    finally:
        release.set()
        thread.join(10)
    assert not errors and not thread.is_alive()


@pytest.mark.parametrize("fault", ["locked", "schema"])
async def test_native_owner_recovery_distinguishes_contention_from_damage(backup, tmp_path, fault):
    instance = owned(backup, tmp_path)
    snapshot = await instance.verify()
    path = instance._generations().journal.path
    script = """
import sqlite3,sys
db=sqlite3.connect(sys.argv[1],isolation_level=None)
if sys.argv[2] == "schema":
    db.execute("ALTER TABLE binding RENAME COLUMN body TO private_body")
db.execute("BEGIN EXCLUSIVE" if sys.argv[2] == "locked" else "BEGIN IMMEDIATE")
db.execute("INSERT INTO records VALUES ('fixture','pending',?)", (b'{}',))
print("ready", flush=True)
sys.stdin.readline()
db.rollback()
db.close()
"""
    writer = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", script, str(path), fault],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([writer.stdout], [], [], 10)[0]
        assert writer.stdout.readline().strip() == "ready"
        backup.remote.heads.clear()
        backup.remote.reads.clear()
        expected = ModelGenerationOwnerBusy if fault == "locked" else ModelGenerationRepairRequired
        with pytest.raises(expected) as failure:
            owned(backup, tmp_path, initialize=False)._generations()
        assert isinstance(failure.value.__cause__, sqlite3.OperationalError)
        assert str(path) not in str(failure.value)
        assert "private_body" not in str(failure.value)
        assert backup.remote.heads == backup.remote.reads == []
    finally:
        try:
            writer.communicate("release\n", timeout=10)
        except subprocess.TimeoutExpired:
            writer.kill()
            writer.communicate(timeout=5)
    assert writer.returncode == 0
    if fault == "locked":
        recovered = owned(backup, tmp_path, initialize=False)
        assert await recovered.verify(completed_only=True) == snapshot
        assert backup.remote.heads == backup.remote.reads == []


def fill_owner(owner):
    with owner.journal.read_transaction() as db:
        _, used, _ = owner.journal._record_capacity(db)
    owner.journal.put(
        "fixture", "capacity-fill", {"payload": "x" * (owner.journal.maximum_bytes - used - 64)}
    )


async def test_full_owner_grows_without_forgetting_damage_or_rechecking_unaffected_objects(
    backup, tmp_path
):
    config = owned(backup, tmp_path, initialize=False).generation_owner.model_copy(
        update={"maximum_bytes": 1024**2}
    )
    instance = owned(backup, tmp_path, owner=config)
    snapshot = await instance.verify()
    owner = instance._generations()
    originals = {
        v.sha256: owner.journal.get("object", owner.object_id(v.model_dump(mode="json")))
        for v in snapshot.objects
    }
    fill_owner(owner)
    with pytest.raises(ModelGenerationRepairRequired, match="pending capacity event retained"):
        owner.hold(snapshot.objects[0].model_dump(mode="json"), reason="actual_damage")
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    with pytest.raises(ModelGenerationRepairRequired, match="held for capacity growth"):
        await owned(backup, tmp_path, owner=config, initialize=False).verify(completed_only=True)
    enlarged = config.model_copy(update={"maximum_bytes": 2 * 1024**2})
    with pytest.raises(ModelGenerationRepairRequired, match="requires native grow-generations"):
        owned(backup, tmp_path, owner=enlarged, initialize=False)._generations()
    observations = []

    def concurrent_observation(event):
        if event.get("completed_units") == 1 and not observations:
            observations.append(event)
            with pytest.raises(
                ModelGenerationRepairRequired, match="pending capacity event retained"
            ):
                owner.hold(snapshot.objects[0].model_dump(mode="json"), reason="concurrent_damage")

    for _ in range(2):
        grow_generation_owner(
            instance.root,
            enlarged,
            semantics=[BYTE_ABI, verifier_semantics()],
            report=concurrent_observation,
        )
    assert observations
    assert backup.remote.heads == backup.remote.reads == []
    restarted = owned(backup, tmp_path, owner=enlarged, initialize=False)
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        await restarted.verify(completed_only=True)
    await restarted.repair_generations()
    assert backup.remote.reads == [snapshot.objects[0].key]
    backup.remote.reads.clear()
    backup.remote.heads.clear()
    for capacity_selection in (config, enlarged):
        reader = owned(backup, tmp_path, owner=capacity_selection, initialize=False)
        assert await reader.verify(completed_only=True) == snapshot
        assert reader._generations().journal.maximum_bytes == enlarged.maximum_bytes
    assert backup.remote.heads == backup.remote.reads == []
    after = restarted._generations()
    assert originals == {
        v.sha256: after.journal.get("object", after.object_id(v.model_dump(mode="json")))
        for v in snapshot.objects
    }


async def test_capacity_recovery_reuses_already_finished_original_repair(backup, tmp_path):
    config = owned(backup, tmp_path, initialize=False).generation_owner.model_copy(
        update={"maximum_bytes": 1024**2}
    )
    instance = owned(backup, tmp_path, owner=config)
    snapshot = await instance.verify()
    owner = instance._generations()
    owner.hold(snapshot.objects[0].model_dump(mode="json"), reason="actual_damage")
    fill_owner(owner)
    backup.remote.reads.clear()
    with pytest.raises(ModelGenerationRepairRequired, match="pending capacity event retained"):
        await instance.repair_generations()
    assert backup.remote.reads == [snapshot.objects[0].key]
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    grow_generation_owner(
        instance.root,
        config.model_copy(update={"maximum_bytes": 2 * 1024**2}),
        semantics=[BYTE_ABI, verifier_semantics()],
    )
    assert await instance.verify(completed_only=True) == snapshot
    assert backup.remote.heads == backup.remote.reads == []


def test_interrupted_empty_enrollment_resumes_exact_renamed_journal(backup, tmp_path, monkeypatch):
    from umi import competition_model_generation_store as generation

    instance = owned(backup, tmp_path, initialize=False)
    publish = generation.publish_private_model

    def interrupted(*args, **kwargs):
        raise OSError("fixture interrupted after rename")

    monkeypatch.setattr(generation, "publish_private_model", interrupted)
    with pytest.raises(OSError, match="after rename"):
        initialize_generation_owner(
            instance.root, instance.generation_owner, semantics=[BYTE_ABI, verifier_semantics()]
        )
    target = instance.root / "generation-owners-v1" / instance.generation_owner.owner_sha256
    before = (target / "rounds.sqlite3").read_bytes()
    inode = (target / "rounds.sqlite3").stat().st_ino
    monkeypatch.setattr(generation, "publish_private_model", publish)
    initialize_generation_owner(
        instance.root, instance.generation_owner, semantics=[BYTE_ABI, verifier_semantics()]
    )
    assert (target / "rounds.sqlite3").read_bytes() == before
    assert (target / "rounds.sqlite3").stat().st_ino == inode
    assert instance._generations().known(instance._declarations()) == {}
    assert backup.remote.heads == backup.remote.reads == []


async def test_missing_established_enrollment_cannot_be_reinitialized(backup, tmp_path):
    instance = owned(backup, tmp_path)
    await instance.verify()
    marker = (
        instance.root / "generation-owners-v1" / (instance.generation_owner.owner_sha256 + ".json")
    )
    marker.unlink()
    with pytest.raises(ModelGenerationRepairRequired, match="established generation enrollment"):
        initialize_generation_owner(
            instance.root, instance.generation_owner, semantics=[BYTE_ABI, verifier_semantics()]
        )
    assert not marker.exists()


async def test_native_hot_rollback_recovery_keeps_committed_damage_and_completion(backup, tmp_path):
    instance = owned(backup, tmp_path)
    snapshot = await instance.verify()
    owner = instance._generations()
    owner.hold(snapshot.objects[0].model_dump(mode="json"), reason="committed_before_crash")
    path = owner.journal.path
    script = """
import os,sqlite3,sys
db=sqlite3.connect(sys.argv[1],isolation_level=None)
db.execute("PRAGMA synchronous=FULL")
db.execute("PRAGMA cache_size=8")
db.execute("PRAGMA cache_spill=ON")
db.execute("BEGIN IMMEDIATE")
body=b'{"payload":"'+b'x'*4096+b'"}'
for index in range(1024):
    db.execute("INSERT INTO records VALUES ('crashed-fixture',?,?)",(str(index),body))
os._exit(0)
"""
    subprocess.run([sys.executable, "-I", "-B", "-c", script, str(path)], check=True, timeout=20)
    rollback = path.with_name(path.name + "-journal")
    with rollback.open("rb") as stream:
        assert stream.read(8) != b"\0" * 8
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    recovered = owned(backup, tmp_path, initialize=False)
    current = recovered._generations()
    assert current.journal.keys("crashed-fixture") == []
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        await recovered.verify(completed_only=True)
    assert backup.remote.heads == backup.remote.reads == []
    await recovered.repair_generations()
    assert backup.remote.reads == [snapshot.objects[0].key]


def test_native_growth_cli_uses_root_controlled_request_and_retained_capacity(
    backup, tmp_path, monkeypatch, capsys
):
    from umi import competition_model_byte_store_cli as cli

    instance = owned(backup, tmp_path)
    enlarged = instance.generation_owner.model_copy(update={"maximum_bytes": 512 * 1024**2})
    request = cli.ModelGenerationCapacityRequest(
        schema="umi-model-generation-owner-grow/1",
        store=ModelByteStoreConfig(
            schema="umi-model-byte-verification-store/1",
            directory=str(instance.root),
            generation_owner=enlarged,
        ),
    )
    observed = []

    def selected_request(path, maximum, *, modes):
        observed.append((path.name, maximum, modes))
        return canonical_json_bytes(request)

    monkeypatch.setattr(cli, "_read_root_control_path", selected_request)
    assert cli.main(["grow-generations", "--request", str(tmp_path / "grow.json")]) == 0
    assert observed == [("grow.json", 64 * 1024**2, {0o444})]
    assert '"generation_owner_capacity_updated":true' in capsys.readouterr().out
    assert instance._generations().journal.maximum_bytes == enlarged.maximum_bytes
    assert backup.remote.heads == backup.remote.reads == []


def test_startup_qualifies_selected_owner_without_network_or_completion_work(backup, tmp_path):
    instance = owned(backup, tmp_path, initialize=False)
    selection = ModelByteStoreConfig(
        schema="umi-model-byte-verification-store/1",
        directory=str(instance.root),
        generation_owner=instance.generation_owner,
    )
    sources = (SimpleNamespace(shared_byte_store=selection),)
    with pytest.raises(ModelGenerationRepairRequired):
        qualify_shared_byte_stores(sources)
    initialize_generation_owner(
        instance.root, instance.generation_owner, semantics=[BYTE_ABI, verifier_semantics()]
    )
    qualify_shared_byte_stores(sources)
    assert instance._generations().known(instance._declarations()) == {}
    assert backup.remote.heads == backup.remote.reads == []


async def test_restored_owner_keeps_damage_history_and_original_repair_path(backup, tmp_path):
    source = owned(backup, tmp_path / "source")
    snapshot = await source.verify()
    source._hold_generation(snapshot.objects[0], "verified_object_damage")
    target = tmp_path / "restored"
    shutil.copytree(source.root, target / "verification")
    backup.remote.heads.clear()
    backup.remote.reads.clear()
    restored = owned(backup, target, initialize=False)
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        await restored.verify(completed_only=True)
    assert backup.remote.heads == backup.remote.reads == []
    await restored.repair_generations()
    assert backup.remote.reads == [snapshot.objects[0].key]
    # Restoration explicitly creates a separate root; it cannot clear the
    # original owner's independent damage history.
    with pytest.raises(ModelGenerationRepairRequired, match="held"):
        await source.verify(completed_only=True)
