"""Trusted local identity replay never reads unchanged original payload files."""

import json

import pytest

from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.competition_cohort_aggregate_model import AggregateProtocolModel
from umi.competition_cohort_reward_package import RewardPackageObject
from umi.competition_verification_reuse import VerificationReuse, verified_replay
from umi.competition_verification_snapshot import VerificationPackageStore
from umi.open_competition import digest
from umi.protocol import StrictProtocolModel

from .test_host_memory_verified_shape import selected_bounds as selected_bounds
from .test_open_competition import policy as policy


class Package(AggregateProtocolModel):
    name: str
    objects: tuple[RewardPackageObject, ...]


class Result(StrictProtocolModel):
    value: str


def test_warm_snapshot_and_verdict_do_not_open_payloads(tmp_path, monkeypatch, policy):
    from umi import competition_verification_reuse as reuse_module
    from umi import competition_verification_snapshot as module
    from umi.competition_cohort_endpoint_archive import read_endpoint_object

    value = {"payload": "retained"}
    key = digest(value)
    package = Package(name="source", objects=(RewardPackageObject(sha256=key, value=value),))
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    store = VerificationPackageStore(tmp_path / "verified")
    snapshot = store.load(source, Package, maximum_bytes=1024**2, expected_sha256=digest(package))
    counts = []

    @verified_replay("snapshot_test", Result)
    def verify(objects, policy):
        counts.append(1)
        return Result(value=json.loads(read_endpoint_object(objects, key))["payload"])

    with VerificationReuse(tmp_path / "verdicts", owner="one").selected():
        assert verify(snapshot.collector(1024**2), policy).value == "retained"
    calls = []
    native_read = module._read_bounded_private_bytes

    def metadata_only(path, **kwargs):
        calls.append(path)
        assert path != source
        assert path.suffix != ".bin"
        return native_read(path, **kwargs)

    monkeypatch.setattr(module, "_read_bounded_private_bytes", metadata_only)
    monkeypatch.setattr(reuse_module, "_read_bounded_private_bytes", metadata_only)
    # A fresh object store and verdict owner simulate independent restart.
    snapshot = VerificationPackageStore(tmp_path / "verified").load(
        source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
    )
    collector = snapshot.collector(1024**2)
    with VerificationReuse(tmp_path / "verdicts", owner="one").selected():
        assert verify(collector, policy).value == "retained"
    assert set(collector.values) == {key}
    assert collector.used > 0
    assert len(counts) == 1
    assert calls


def test_interrupted_import_preserves_existing_verified_objects(tmp_path, monkeypatch):
    from umi import competition_verification_snapshot as module

    values = ({"payload": "one"}, {"payload": "two"})
    package = Package(
        name="source", objects=tuple(RewardPackageObject(sha256=digest(v), value=v) for v in values)
    )
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    store = VerificationPackageStore(tmp_path / "verified")
    native = module.read_endpoint_object
    calls = []

    def interrupted(*args):
        calls.append(1)
        if len(calls) == 2:
            raise InterruptedError("import interrupted")
        return native(*args)

    monkeypatch.setattr(module, "read_endpoint_object", interrupted)
    with pytest.raises(InterruptedError):
        store.load(source, Package, maximum_bytes=1024**2)
    first = store.object_path(digest(values[0])).stat()
    monkeypatch.setattr(module, "read_endpoint_object", native)
    store.load(source, Package, maximum_bytes=1024**2)
    after = store.object_path(digest(values[0])).stat()
    assert (first.st_ino, first.st_ctime_ns) == (after.st_ino, after.st_ctime_ns)


def test_nested_warm_verdict_retains_dependencies_without_reading_payloads(
    tmp_path, monkeypatch, policy
):
    from umi import competition_verification_snapshot as module
    from umi.competition_cohort_endpoint_archive import read_endpoint_object

    value = {"payload": "nested retained"}
    key = digest(value)
    package = Package(name="nested", objects=(RewardPackageObject(sha256=key, value=value),))
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    snapshot = VerificationPackageStore(tmp_path / "snapshots").load(
        source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
    )
    calls = []

    @verified_replay("snapshot_nested_inner", Result)
    def inner(objects, policy):
        calls.append("inner")
        return Result(value=json.loads(read_endpoint_object(objects, key))["payload"])

    @verified_replay("snapshot_nested_outer", Result)
    def outer(objects, policy):
        calls.append("outer")
        return inner(objects, policy)

    receipts = tmp_path / "receipts"
    with VerificationReuse(receipts, owner="nested").selected():
        assert inner(snapshot.collector(1024**2), policy).value == value["payload"]
    native_read = module._read_bounded_private_bytes

    def no_payload_reads(path, **kwargs):
        assert path != source and path.suffix != ".bin"
        return native_read(path, **kwargs)

    monkeypatch.setattr(module, "_read_bounded_private_bytes", no_payload_reads)
    for _ in range(2):
        snapshot = VerificationPackageStore(tmp_path / "snapshots").load(
            source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
        )
        collector = snapshot.collector(1024**2)
        with VerificationReuse(receipts, owner="nested").selected():
            assert outer(collector, policy).value == value["payload"]
        assert set(collector.values) == {key}
        assert collector.used == snapshot.records[key].size
    assert calls == ["inner", "outer"]
    retained = [json.loads(path.read_bytes()) for path in receipts.glob("*.json")]
    assert len(retained) == 2
    assert all([item["key"] for item in record["dependencies"]] == [key] for record in retained)


@pytest.mark.parametrize("damage", ["invalid_json", "envelope", "object_size"])
def test_corrupt_snapshot_metadata_repairs_from_original_without_replacing_objects(
    tmp_path, monkeypatch, damage
):
    from umi import competition_verification_snapshot as module

    value = {"payload": "original"}
    key = digest(value)
    package = Package(name="original", objects=(RewardPackageObject(sha256=key, value=value),))
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    original_bytes = source.read_bytes()
    store = VerificationPackageStore(tmp_path / "snapshots")
    store.load(source, Package, maximum_bytes=1024**2, expected_sha256=digest(package))
    object_before = store.object_path(key).stat()
    metadata = next(store.directory.glob("*.json"))
    if damage == "invalid_json":
        metadata.write_bytes(b"interrupted metadata write")
    else:
        record = json.loads(metadata.read_bytes())
        if damage == "envelope":
            envelope = json.loads(record["envelope_json"])
            envelope["name"] = "corrupt"
            record["envelope_json"] = json.dumps(envelope)
        else:
            record["objects"][0]["size"] += 1
        metadata.write_text(json.dumps(record))
    reads = []
    native_read = module.read_aggregate_model

    def read_original(*args, **kwargs):
        reads.append(args[0])
        return native_read(*args, **kwargs)

    monkeypatch.setattr(module, "read_aggregate_model", read_original)
    restored = VerificationPackageStore(store.directory).load(
        source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
    )
    assert reads == [source]
    assert restored.name == "original"
    assert restored.records[key].size == object_before.st_size
    assert source.read_bytes() == original_bytes
    object_after = store.object_path(key).stat()
    assert (object_after.st_ino, object_after.st_ctime_ns) == (
        object_before.st_ino,
        object_before.st_ctime_ns,
    )
    VerificationPackageStore(store.directory).load(
        source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
    )
    assert reads == [source]


def test_warm_snapshot_and_receipt_metadata_do_not_consume_declaration_budget(tmp_path, policy):
    from umi import host_memory_request_bounds as bounds
    from umi.competition_cohort_endpoint_archive import read_endpoint_object

    value = {"payload": "budget"}
    key = digest(value)
    package = Package(name="budget", objects=(RewardPackageObject(sha256=key, value=value),))
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    snapshot = VerificationPackageStore(tmp_path / "snapshots").load(
        source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
    )
    calls = []

    @verified_replay("snapshot_declaration_budget", Result)
    def verify(objects, policy):
        calls.append(1)
        return Result(value=json.loads(read_endpoint_object(objects, key))["payload"])

    with VerificationReuse(tmp_path / "receipts", owner="budget").selected():
        assert verify(snapshot.collector(1024**2), policy).value == "budget"
    token = bounds._declarations.set([1])
    try:
        snapshot = VerificationPackageStore(tmp_path / "snapshots").load(
            source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
        )
        with VerificationReuse(tmp_path / "receipts", owner="budget").selected():
            assert verify(snapshot.collector(1024**2), policy).value == "budget"
        assert bounds._declarations.get() == [1]
    finally:
        bounds._declarations.reset(token)
    assert calls == [1]


def test_changed_shape_context_is_retained_across_restart(tmp_path, monkeypatch, selected_bounds):
    from umi import competition_verification_snapshot as module
    from umi import host_memory_request_bounds as bounds

    value = {"payload": "shape context"}
    key = digest(value)
    package = Package(name="shape", objects=(RewardPackageObject(sha256=key, value=value),))
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)

    def reopen():
        return VerificationPackageStore(tmp_path / "snapshots").load(
            source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
        )

    snapshot = reopen()
    changed = selected_bounds.model_copy(
        update={"maximum_json_values": selected_bounds.maximum_json_values + 1}
    )
    monkeypatch.setattr(bounds, "stage_bounds", lambda: changed)
    calls = []
    native = module.check_stage_json

    def count_shape(*args, **kwargs):
        calls.append(1)
        return native(*args, **kwargs)

    monkeypatch.setattr(module, "check_stage_json", count_shape)
    with bounds.stage_evidence_budget():
        snapshot.collector(1024**2).verification_replay(key)
    assert calls == [1]

    def no_payload_reads(*args):
        pytest.fail("a successfully retained new shape context reread its payload")

    monkeypatch.setattr(module.VerifiedPackageSnapshot, "read", no_payload_reads)
    for _ in range(2):
        with bounds.stage_evidence_budget():
            collector = reopen().collector(1024**2)
            collector.verification_replay(key)
            assert set(collector.values) == {key}
    assert calls == [1]


@pytest.mark.parametrize("wrapper", [False, True])
def test_reused_collector_charges_each_operation_and_current_object_budget(
    tmp_path, selected_bounds, wrapper
):
    from umi import host_memory_request_bounds as bounds
    from umi.competition_cohort_reward_package import ReplayObjectCollector

    value = {"payload": list(range(80))}
    key = digest(value)
    package = Package(name="accounting", objects=(RewardPackageObject(sha256=key, value=value),))
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    snapshot = VerificationPackageStore(tmp_path / "snapshots").load(
        source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
    )
    collector = snapshot.collector(1024**2)
    if wrapper:
        collector = ReplayObjectCollector(collector, 1024**2)
    descriptor = snapshot.records[key]
    for _ in range(2):
        with bounds.stage_evidence_budget():
            for _ in range(2):
                collector.verification_replay(key)
                assert bounds._evidence_values.get()["remaining"] == (
                    selected_bounds.maximum_json_values - descriptor.shape_values
                )
    with (
        bounds.stage_evidence_budget(),
        bounds.stage_object_budget(descriptor.size - 1),
        pytest.raises(ValueError, match="qualified byte bound"),
    ):
        collector.verification_replay(key)


def test_same_verified_bytes_reuse_across_snapshot_roots_without_payload_io(
    tmp_path, monkeypatch, policy
):
    from umi import competition_verification_reuse as reuse_module
    from umi.competition_cohort_endpoint_archive import read_endpoint_object
    from umi.competition_cohort_reward_package import ReplayObjectCollector
    from umi.competition_verification_snapshot import VerifiedPackageSnapshot
    from umi.protocol import canonical_json_bytes

    value = {"payload": "shared immutable input"}
    key, raw = digest(value), canonical_json_bytes(value)
    snapshots = []
    for name in ("a", "b"):
        package = Package(name=name, objects=(RewardPackageObject(sha256=key, value=value),))
        source = tmp_path / name / "original.json"
        publish_aggregate_model(source, package, maximum_bytes=1024**2)
        snapshots.append(
            VerificationPackageStore(tmp_path / name / "snapshot").load(
                source, Package, maximum_bytes=1024**2, expected_sha256=digest(package)
            )
        )
    assert snapshots[0].identity(key) != snapshots[1].identity(key)
    calls = []

    @verified_replay("snapshot_same_bytes_bridge", Result)
    def verify(objects, policy):
        calls.append(1)
        return Result(value=json.loads(read_endpoint_object(objects, key))["payload"])

    with VerificationReuse(tmp_path / "receipts", owner="same-owner").selected():
        assert verify(snapshots[0].collector(1024**2), policy).value == value["payload"]

    def no_payload_reads(*args):
        pytest.fail("unchanged authenticated bytes were reopened in another snapshot")

    native_sha = reuse_module.hashlib.sha256

    def no_payload_hash(data=b"", *args, **kwargs):
        assert data != raw, "unchanged authenticated bytes were hashed again"
        return native_sha(data, *args, **kwargs)

    monkeypatch.setattr(VerifiedPackageSnapshot, "read", no_payload_reads)
    monkeypatch.setattr(reuse_module.hashlib, "sha256", no_payload_hash)
    collector = ReplayObjectCollector(snapshots[1].collector(1024**2), 1024**2)
    with VerificationReuse(tmp_path / "receipts", owner="same-owner").selected():
        assert verify(collector, policy).value == value["payload"]
    assert set(collector.values) == {key}
    assert collector.used == len(raw)
    assert calls == [1]


def test_warm_snapshot_rechecks_selected_aggregate_capacity_without_payload_read(
    tmp_path, monkeypatch
):
    from umi import competition_verification_snapshot as module

    value = {"payload": "a" * 2048}
    package = Package(
        name="aggregate bound", objects=(RewardPackageObject(sha256=digest(value), value=value),)
    )
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=4096)
    original_bytes = source.read_bytes()
    store = VerificationPackageStore(tmp_path / "snapshots")
    store.load(source, Package, maximum_bytes=4096, expected_sha256=digest(package))
    with pytest.raises(ValueError):
        VerificationPackageStore(tmp_path / "cold").load(
            source, Package, maximum_bytes=1024, expected_sha256=digest(package)
        )

    def no_aggregate_read(*args, **kwargs):
        pytest.fail("selected capacity rejection must use original size metadata")

    monkeypatch.setattr(module, "read_aggregate_model", no_aggregate_read)
    with pytest.raises(ValueError):
        VerificationPackageStore(store.directory).load(
            source, Package, maximum_bytes=1024, expected_sha256=digest(package)
        )
    assert source.read_bytes() == original_bytes
