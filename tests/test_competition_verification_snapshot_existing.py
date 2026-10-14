"""Periodic consumers must never turn unavailable reuse into a payload import."""

import os

import pytest

from umi import competition_verification_snapshot as module
from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.competition_cohort_reward_package import RewardPackageObject
from umi.competition_verification_snapshot import (
    VerificationPackageStore,
    VerificationSnapshotRepairRequired,
    VerificationSnapshotUnavailable,
)
from umi.open_competition import digest

from .test_competition_verification_snapshot import Package
from .test_host_memory_verified_shape import selected_bounds as selected_bounds


def fixture(tmp_path, *, imported=True):
    value = {"payload": "original"}
    package = Package(
        name="source", objects=(RewardPackageObject(sha256=digest(value), value=value),)
    )
    path = tmp_path / "package.json"
    publish_aggregate_model(path, package, maximum_bytes=1024**2)
    store = VerificationPackageStore(tmp_path / "snapshot")
    if imported:
        store.load(path, Package, maximum_bytes=1024**2)
    return store, path, package


def forbid_payload_import(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("existing snapshot lookup attempted payload import")

    monkeypatch.setattr(module, "read_aggregate_model", refused)
    monkeypatch.setattr(module, "endpoint_object_bytes", refused)
    monkeypatch.setattr(module, "read_endpoint_object", refused)
    original = module._read_bounded_private_bytes

    def metadata_only(path, **kwargs):
        assert path.suffix != ".bin"
        return original(path, **kwargs)

    monkeypatch.setattr(module, "_read_bounded_private_bytes", metadata_only)


def test_existing_snapshot_reopens_without_original_or_object_payload_io(tmp_path, monkeypatch):
    store, path, package = fixture(tmp_path)
    forbid_payload_import(monkeypatch)
    snapshot = VerificationPackageStore(store.directory).load_existing(
        path, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
    )
    assert snapshot.sha256 == digest(package)
    assert snapshot.name == package.name
    assert len(snapshot.records) == 1


def test_missing_initial_snapshot_never_imports_implicitly(tmp_path, monkeypatch):
    store, path, _ = fixture(tmp_path, imported=False)
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotUnavailable):
        store.load_existing(path, Package, maximum_bytes=1024**2)


@pytest.mark.parametrize(
    "damage", ["missing_metadata", "corrupt_metadata", "missing_object", "changed_object"]
)
def test_damaged_snapshot_requires_explicit_repair(tmp_path, monkeypatch, damage):
    store, path, package = fixture(tmp_path)
    metadata = next(store.directory.glob("*.json"))
    item = store.object_path(package.objects[0].sha256)
    if damage == "missing_metadata":
        metadata.unlink()
    elif damage == "corrupt_metadata":
        metadata.write_text("{}")
    elif damage == "missing_object":
        item.unlink()
    else:
        item.chmod(0o600)
        item.write_bytes(b"changed")
        item.chmod(0o400)
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load_existing(path, Package, maximum_bytes=1024**2)


def test_changed_original_identity_does_not_trigger_full_read(tmp_path, monkeypatch):
    store, path, _ = fixture(tmp_path)
    before = path.stat()
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load_existing(path, Package, maximum_bytes=1024**2)


def test_expected_digest_mismatch_refuses_without_reimport(tmp_path, monkeypatch):
    store, path, _ = fixture(tmp_path)
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load_existing(path, Package, maximum_bytes=1024**2, expected_sha256="ff" * 32)


@pytest.mark.parametrize("damage", ["metadata", "selection", "preparation", "object_record"])
def test_automatic_load_refuses_lost_completed_state(tmp_path, monkeypatch, damage):
    store, path, package = fixture(tmp_path)
    if damage == "metadata":
        next(store.directory.glob("*.json")).unlink()
    elif damage == "selection":
        store.selection_path(path).unlink()
    elif damage == "preparation":
        # Preparation is not needed by a healthy completed snapshot. A repair
        # must be explicit once both its snapshot and preparation are lost.
        next(store.directory.glob("*.json")).unlink()
        next(store.preparations.glob("*.json")).unlink()
    else:
        next(store.directory.glob("*.json")).unlink()
        (store.objects / (package.objects[0].sha256 + ".json")).unlink()
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load(path, Package, maximum_bytes=1024**2)


def test_legacy_snapshot_migrates_binding_without_payload_io(tmp_path, monkeypatch):
    store, path, package = fixture(tmp_path)
    for directory in (store.selections, store.identities, store.preparations):
        for item in directory.iterdir():
            item.unlink()
    forbid_payload_import(monkeypatch)
    fresh = VerificationPackageStore(store.directory)
    assert fresh.load(path, Package, maximum_bytes=1024**2).sha256 == digest(package)
    assert fresh.selection_path(path).exists()
    before = path.stat()
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
    with pytest.raises(VerificationSnapshotRepairRequired):
        fresh.load(path, Package, maximum_bytes=1024**2)


def test_repair_lost_object_uses_only_its_original_slice(tmp_path, monkeypatch):
    store, path, package = fixture(tmp_path)
    key = package.objects[0].sha256
    store.object_path(key).unlink()

    def refuse_aggregate(*args, **kwargs):
        pytest.fail("repair reread an already prepared entire package")

    monkeypatch.setattr(module, "read_aggregate_model", refuse_aggregate)
    restored = store.repair(path, Package, maximum_bytes=1024**2, reason="restore missing object")
    assert restored.read(key) == module.endpoint_object_bytes(package.objects[0].value, key)
    selected = module.SnapshotSelection.model_validate_json(store.selection_path(path).read_bytes())
    assert selected.state == "complete"
    assert selected.repair_reason == "restore missing object"
    forbid_payload_import(monkeypatch)
    assert store.load(path, Package, maximum_bytes=1024**2).sha256 == digest(package)


def test_interrupted_explicit_repair_resumes_without_aggregate_reread(tmp_path, monkeypatch):
    store, path, package = fixture(tmp_path)
    key = package.objects[0].sha256
    store.object_path(key).unlink()
    native = module.read_endpoint_object

    def interrupted(*args, **kwargs):
        raise InterruptedError("repair interruption")

    monkeypatch.setattr(module, "read_endpoint_object", interrupted)
    with pytest.raises(InterruptedError):
        store.repair(path, Package, maximum_bytes=1024**2, reason="restore missing object")
    monkeypatch.setattr(module, "read_endpoint_object", native)
    monkeypatch.setattr(
        module, "read_aggregate_model", lambda *a, **k: pytest.fail("repeat decode")
    )
    assert VerificationPackageStore(store.directory).load(
        path, Package, maximum_bytes=1024**2
    ).sha256 == digest(package)


def test_repair_changed_source_preserves_previously_selected_digest(tmp_path):
    store, path, _ = fixture(tmp_path)
    changed = Package(name="different", objects=())
    path.write_bytes(module.canonical_json_bytes(changed))
    with pytest.raises(ValueError, match="independently selected identity"):
        store.repair(path, Package, maximum_bytes=1024**2, reason="restore source")


def test_missing_preparation_requires_explicit_repair_after_interruption(tmp_path, monkeypatch):
    store, path, package = fixture(tmp_path, imported=False)
    native = module.read_endpoint_object
    monkeypatch.setattr(
        module, "read_endpoint_object", lambda *a: (_ for _ in ()).throw(InterruptedError())
    )
    with pytest.raises(InterruptedError):
        store.load(path, Package, maximum_bytes=1024**2)
    next(store.preparations.glob("*.json")).unlink()
    monkeypatch.setattr(module, "read_endpoint_object", native)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load(path, Package, maximum_bytes=1024**2)
    assert store.repair(
        path, Package, maximum_bytes=1024**2, reason="lost prepared slices"
    ).sha256 == digest(package)


def test_missing_initial_source_stays_unavailable_to_offer_discovery(tmp_path):
    store = VerificationPackageStore(tmp_path / "snapshot")
    with pytest.raises(FileNotFoundError):
        store.load(tmp_path / "absent.json", Package, maximum_bytes=1024**2)


@pytest.mark.parametrize("same_store", [False, True])
def test_verified_replica_binds_without_payload_import(tmp_path, monkeypatch, same_store):
    from umi.competition_aggregate_replica_binding import _issue_verified_replica
    from umi.file_identity import file_fingerprint

    store, path, package = fixture(tmp_path)
    snapshot = store.load_existing(path, Package, maximum_bytes=1024**2)
    target = tmp_path / "replica.json"
    target.write_bytes(path.read_bytes())
    target.chmod(0o600)
    # The transport's actual issued capability is tested in aggregate_replica;
    # here exercise the bounded consumer that must not decode or hash again.
    binding = _issue_verified_replica(
        target, digest(package), tuple(str(v) for v in file_fingerprint(target.stat()))
    )
    consumer = store if same_store else VerificationPackageStore(tmp_path / "consumer")
    monkeypatch.setattr(
        module, "read_aggregate_model", lambda *a, **k: pytest.fail("repeat decode")
    )
    monkeypatch.setattr(
        module, "endpoint_object_bytes", lambda *a, **k: pytest.fail("repeat encoding")
    )
    monkeypatch.setattr(
        module, "read_endpoint_object", lambda *a, **k: pytest.fail("repeat verification")
    )
    result = consumer.bind_replica(snapshot, binding, maximum_bytes=1024**2)
    assert result.sha256 == digest(package)
    assert result.original_identity()[0] == target
    forbid_payload_import(monkeypatch)
    assert consumer.load_existing(target, Package, maximum_bytes=1024**2).sha256 == digest(package)
    assert consumer.bind_replica(snapshot, binding, maximum_bytes=1024**2).sha256 == digest(package)


def test_replica_binding_rejects_wrong_digest_and_changed_target(tmp_path):
    from umi.competition_aggregate_replica_binding import _issue_verified_replica
    from umi.file_identity import file_fingerprint

    store, path, package = fixture(tmp_path)
    snapshot = store.load_existing(path, Package, maximum_bytes=1024**2)
    target = tmp_path / "replica.json"
    target.write_bytes(path.read_bytes())
    target.chmod(0o600)
    stamp = tuple(str(v) for v in file_fingerprint(target.stat()))
    with pytest.raises(TypeError):
        store.bind_replica(snapshot, object(), maximum_bytes=1024**2)
    with pytest.raises(ValueError):
        store.bind_replica(
            snapshot, _issue_verified_replica(target, "ff" * 32, stamp), maximum_bytes=1024**2
        )
    binding = _issue_verified_replica(target, digest(package), stamp)
    target.write_bytes(b"changed")
    with pytest.raises(ValueError):
        store.bind_replica(snapshot, binding, maximum_bytes=1024**2)


def test_preparation_digest_and_offsets_preserve_escaped_values(tmp_path, monkeypatch):
    from umi.protocol import canonical_json_bytes

    values = (
        {"payload": 'string with objects and escaped " quotes [x] \n'},
        {"payload": {"x": [None, "😀", "é", 1.2e-8]}},
    )
    package = Package(
        name="😀 canonical envelope",
        objects=tuple(RewardPackageObject(sha256=digest(value), value=value) for value in values),
    )
    path = tmp_path / "original.json"
    publish_aggregate_model(path, package, maximum_bytes=1024**2)
    store = VerificationPackageStore(tmp_path / "snapshots")
    native = module.read_endpoint_object
    monkeypatch.setattr(
        module, "read_endpoint_object", lambda *a: (_ for _ in ()).throw(InterruptedError())
    )
    with pytest.raises(InterruptedError):
        store.load(path, Package, maximum_bytes=1024**2, expected_sha256=digest(package))
    prepared = module.SnapshotPreparation.model_validate_json(
        next(store.preparations.glob("*.json")).read_bytes()
    )
    assert prepared.package_sha256 == digest(package)
    raw = path.read_bytes()
    assert [raw[item.offset : item.offset + item.size] for item in prepared.inputs] == [
        canonical_json_bytes(item) for item in package.objects
    ]
    monkeypatch.setattr(module, "read_endpoint_object", native)
    monkeypatch.setattr(
        module, "read_aggregate_model", lambda *a, **k: pytest.fail("repeat decode")
    )
    restored = store.load(path, Package, maximum_bytes=1024**2)
    assert len(restored.records) == 2


def test_snapshot_progress_reports_preparation_resume_repair_and_counts(
    tmp_path, monkeypatch, caplog
):
    import json
    import logging

    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    store, path, _ = fixture(tmp_path)
    next(store.directory.glob("*.json")).unlink()
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load(path, Package, maximum_bytes=1024**2)
    store.repair(path, Package, maximum_bytes=1024**2, reason="telemetry qualification")
    events = [
        json.loads(record.message) for record in caplog.records if record.message.startswith("{")
    ]
    assert any(event["state"] == "repair_required" for event in events)
    assert any(
        event["stage"] == "verification_snapshot_prepare" and event["state"] == "hit"
        for event in events
    )
    assert any(
        event.get("planning_eta_basis") == "package_bytes_at_1_to_10_mib_per_second"
        for event in events
    )
    progress = [event for event in events if event["schema"] == "umi-competition-work-progress/1"]
    assert progress and all(
        "elapsed_seconds" in event and "eta_basis" in event for event in progress
    )
    assert any(
        event["state"] == "completed" and event["completed"] == event["total"] for event in progress
    )


def test_remaining_slice_rejects_swapped_open_file_descriptor(tmp_path, monkeypatch):
    store, path, _ = fixture(tmp_path, imported=False)
    native_validate = module.read_endpoint_object
    monkeypatch.setattr(
        module, "read_endpoint_object", lambda *a: (_ for _ in ()).throw(InterruptedError())
    )
    with pytest.raises(InterruptedError):
        store.load(path, Package, maximum_bytes=1024**2)
    monkeypatch.setattr(module, "read_endpoint_object", native_validate)
    alternative = tmp_path / "different-inode.json"
    alternative.write_bytes(path.read_bytes())
    alternative.chmod(0o600)
    native_open = module.os.open

    def replaced_descriptor(selected, flags, *args, **kwargs):
        return native_open(
            alternative if str(selected) == str(path) else selected, flags, *args, **kwargs
        )

    monkeypatch.setattr(module.os, "open", replaced_descriptor)
    with pytest.raises(VerificationSnapshotRepairRequired, match="explicit repair") as error:
        store.load(path, Package, maximum_bytes=1024**2)
    assert "restoration opened a changed source" in str(error.value.__cause__)


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_completed_shape_loss_requires_explicit_scoped_repair(
    tmp_path, monkeypatch, selected_bounds, damage
):
    from umi import host_memory_request_bounds as bounds

    store, path, package = fixture(tmp_path)
    key = package.objects[0].sha256
    changed = selected_bounds.model_copy(
        update={"maximum_json_values": selected_bounds.maximum_json_values + 1}
    )
    monkeypatch.setattr(bounds, "stage_bounds", lambda: changed)
    snapshot = store.load(path, Package, maximum_bytes=1024**2)
    with bounds.stage_evidence_budget():
        snapshot.collector(1024**2).verification_replay(key)
    shape = next(store.objects.glob("*-shape-*.json"))
    if damage == "missing":
        shape.unlink()
    else:
        shape.write_bytes(b"{}")
    with bounds.stage_evidence_budget(), pytest.raises(VerificationSnapshotRepairRequired):
        snapshot.collector(1024**2).verification_replay(key)
    monkeypatch.setattr(
        module, "read_aggregate_model", lambda *a, **k: pytest.fail("repeat full decode")
    )
    restored = store.repair(path, Package, maximum_bytes=1024**2, reason="restore shape receipt")
    monkeypatch.setattr(
        module.VerifiedPackageSnapshot, "read", lambda *a: pytest.fail("repeat shape payload")
    )
    with bounds.stage_evidence_budget():
        restored.collector(1024**2).verification_replay(key)


def test_concurrent_distinct_imports_keep_shared_verified_object_identity(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    value = {"payload": "shared original"}
    key = digest(value)
    sources = []
    for name in ("first", "second"):
        package = Package(name=name, objects=(RewardPackageObject(sha256=key, value=value),))
        path = tmp_path / (name + ".json")
        publish_aggregate_model(path, package, maximum_bytes=1024**2)
        sources.append(path)
    barrier = Barrier(2)
    native_decode, native_validate = module.read_aggregate_model, module.read_endpoint_object
    calls = []

    def decoded(*args, **kwargs):
        value = native_decode(*args, **kwargs)
        barrier.wait(timeout=5)
        return value

    def validated(*args, **kwargs):
        calls.append(1)
        return native_validate(*args, **kwargs)

    monkeypatch.setattr(module, "read_aggregate_model", decoded)
    monkeypatch.setattr(module, "read_endpoint_object", validated)
    directory = tmp_path / "snapshots"
    store = VerificationPackageStore(directory)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                VerificationPackageStore(directory).load, source, Package, maximum_bytes=1024**2
            )
            for source in sources
        ]
    snapshots = []
    monkeypatch.setattr(
        module, "read_aggregate_model", lambda *a, **k: pytest.fail("repeat decode")
    )
    for source, future in zip(sources, futures, strict=True):
        try:
            snapshots.append(future.result())
        except module.PrivateStateBusyError:
            snapshots.append(store.load(source, Package, maximum_bytes=1024**2))
    assert calls == [1]
    assert snapshots[0].identity(key) == snapshots[1].identity(key)
    assert snapshots[0].records[key].stamp == module._stamp(store.object_path(key), readonly=True)


def test_metadata_repair_reuses_completed_new_shape_without_payload_io(
    tmp_path, monkeypatch, selected_bounds
):
    from umi import host_memory_request_bounds as bounds

    store, path, package = fixture(tmp_path)
    key = package.objects[0].sha256
    changed = selected_bounds.model_copy(
        update={"maximum_json_values": selected_bounds.maximum_json_values + 1}
    )
    monkeypatch.setattr(bounds, "stage_bounds", lambda: changed)
    snapshot = store.load(path, Package, maximum_bytes=1024**2)
    with bounds.stage_evidence_budget():
        snapshot.collector(1024**2).verification_replay(key)
    next(store.directory.glob("*.json")).unlink()
    forbid_payload_import(monkeypatch)
    restored = store.repair(path, Package, maximum_bytes=1024**2, reason="restore package envelope")
    with bounds.stage_evidence_budget():
        restored.collector(1024**2).verification_replay(key)


def test_completed_package_identity_is_scoped_to_its_source_path(tmp_path):
    store, path, package = fixture(tmp_path)
    copied = tmp_path / "copy.json"
    copied.write_bytes(path.read_bytes())
    copied.chmod(0o600)
    restored = store.load(copied, Package, maximum_bytes=1024**2, expected_sha256=digest(package))
    assert restored.sha256 == digest(package)
    assert store.package_identity_path(path, restored.sha256) != store.package_identity_path(
        copied, restored.sha256
    )


def test_source_package_identity_detects_lost_selection_and_metadata(tmp_path, monkeypatch):
    store, path, package = fixture(tmp_path)
    selection = store.selection_path(path)
    selection.unlink()
    module.metadata_completion(selection).unlink()
    for metadata in store.directory.glob("*.json"):
        metadata.unlink()
        module.metadata_completion(metadata).unlink(missing_ok=True)
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load(path, Package, maximum_bytes=1024**2, expected_sha256=digest(package))


@pytest.mark.parametrize("legacy", [False, True])
def test_missing_completed_source_is_repair_not_first_delivery(tmp_path, monkeypatch, legacy):
    store, path, package = fixture(tmp_path)
    if legacy:
        for directory in (store.selections, store.identities, store.preparations):
            for item in directory.iterdir():
                item.unlink()
    path.unlink()
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired, match="restoration"):
        store.load(path, Package, maximum_bytes=1024**2, expected_sha256=digest(package))


def test_unrelated_completed_metadata_damage_does_not_block_new_source(tmp_path, monkeypatch):
    store, path, _ = fixture(tmp_path)
    next(store.directory.glob("*.json")).write_text("{}")
    payload = {"payload": "new cohort"}
    package = Package(
        name="another cohort", objects=(RewardPackageObject(sha256=digest(payload), value=payload),)
    )
    fresh = tmp_path / "new-cohort.json"
    publish_aggregate_model(fresh, package, maximum_bytes=1024**2)
    assert store.load(fresh, Package, maximum_bytes=1024**2).sha256 == digest(package)
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load(path, Package, maximum_bytes=1024**2)


def test_ambiguous_damaged_legacy_metadata_still_requires_repair(tmp_path):
    store, _path, package = fixture(tmp_path)
    for child in store.selections.iterdir():
        child.unlink()
    next(store.directory.glob("*.json")).write_text("{}")
    fresh = tmp_path / "new-cohort.json"
    publish_aggregate_model(fresh, package, maximum_bytes=1024**2)
    with pytest.raises(VerificationSnapshotRepairRequired):
        store.load(fresh, Package, maximum_bytes=1024**2)


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_shape_repair_restores_already_issued_and_shared_snapshots(
    tmp_path, monkeypatch, selected_bounds, damage
):
    from umi import host_memory_request_bounds as bounds

    store, path, package = fixture(tmp_path)
    first = store.load(path, Package, maximum_bytes=1024**2)
    other_source = tmp_path / "same-objects.json"
    other_package = package.model_copy(update={"name": "shared object consumer"})
    publish_aggregate_model(other_source, other_package, maximum_bytes=1024**2)
    other = store.load(other_source, Package, maximum_bytes=1024**2)
    key = package.objects[0].sha256
    changed = selected_bounds.model_copy(
        update={"maximum_json_values": selected_bounds.maximum_json_values + 1}
    )
    monkeypatch.setattr(bounds, "stage_bounds", lambda: changed)
    with bounds.stage_evidence_budget():
        first.collector(1024**2).verification_replay(key)
    shape = next(store.objects.glob("*-shape-*.json"))
    if damage == "missing":
        shape.unlink()
    else:
        shape.write_bytes(b"{}")
    store.repair(path, Package, maximum_bytes=1024**2, reason="repair shared shape")
    forbid_payload_import(monkeypatch)
    for snapshot in (first, other, store.load(other_source, Package, maximum_bytes=1024**2)):
        with bounds.stage_evidence_budget():
            snapshot.collector(1024**2).verification_replay(key)
    # Repeated repair also restores a secondary receipt when the primary
    # descriptor now already carries this selected shape.
    shape.unlink()
    store.repair(path, Package, maximum_bytes=1024**2, reason="repeat shared shape repair")
    with bounds.stage_evidence_budget():
        first.collector(1024**2).verification_replay(key)


@pytest.mark.parametrize("damage", ["invalid_json", "missing_during_scan"])
def test_missing_original_legacy_metadata_damage_is_repair_required(tmp_path, monkeypatch, damage):
    store, path, _ = fixture(tmp_path)
    for directory in (store.selections, store.identities, store.preparations):
        for item in directory.iterdir():
            item.unlink()
    metadata = next(store.directory.glob("*.json"))
    path.unlink()
    if damage == "invalid_json":
        metadata.write_bytes(b"{}")
    else:
        native = module.read_verification_metadata

        def disappeared(selected):
            if selected == metadata:
                raise FileNotFoundError("lost after legacy scan")
            return native(selected)

        monkeypatch.setattr(module, "read_verification_metadata", disappeared)
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired, match="legacy original selection"):
        store.load(path, Package, maximum_bytes=1024**2)


@pytest.mark.parametrize("surviving", ["snapshot", "preparation"])
def test_repair_recovers_missing_selection_identity_from_healthy_native_record(tmp_path, surviving):
    store, path, package = fixture(tmp_path)
    store.selection_path(path).write_bytes(b"{}")
    if surviving == "snapshot":
        next(store.preparations.glob("*.json")).write_bytes(b"{}")
    else:
        next(store.directory.glob("*.json")).write_bytes(b"{}")
    repaired = store.repair(path, Package, maximum_bytes=1024**2, reason="restore selected digest")
    assert repaired.sha256 == digest(package)


@pytest.mark.parametrize("selection_damage", ["missing", "corrupt"])
def test_repair_without_expected_digest_refuses_replacement_before_mutation(
    tmp_path, monkeypatch, selection_damage
):
    store, path, _ = fixture(tmp_path)
    selected = store.selection_path(path)
    if selection_damage == "missing":
        selected.unlink()
    else:
        selected.write_bytes(b"{}")
    for directory in (store.directory, store.preparations):
        for metadata in directory.glob("*.json"):
            metadata.write_bytes(b"{}")
    replacement = Package(name="replacement", objects=())
    path.write_bytes(module.canonical_json_bytes(replacement))
    before = {
        item: item.read_bytes()
        for directory in (store.directory, store.preparations, store.selections)
        for item in directory.glob("*.json")
    }
    forbid_payload_import(monkeypatch)
    with pytest.raises(VerificationSnapshotRepairRequired, match="independently selected digest"):
        store.repair(path, Package, maximum_bytes=1024**2, reason="restore missing identity")
    after = {
        item: item.read_bytes()
        for directory in (store.directory, store.preparations, store.selections)
        for item in directory.glob("*.json")
    }
    assert after == before


def test_repair_with_lost_selection_still_rejects_replacement_using_healthy_preparation(tmp_path):
    store, path, _ = fixture(tmp_path)
    store.selection_path(path).unlink()
    next(store.directory.glob("*.json")).write_bytes(b"{}")
    replacement = Package(name="replacement", objects=())
    path.write_bytes(module.canonical_json_bytes(replacement))
    with pytest.raises(ValueError, match="independently selected identity"):
        store.repair(path, Package, maximum_bytes=1024**2, reason="restore source")
