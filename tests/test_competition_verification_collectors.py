"""Owner and package wrappers preserve immutable coverage without payload replay."""

import json

import pytest

from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects, read_endpoint_object
from umi.competition_cohort_reward_package import ReplayObjectCollector, RewardPackageObject
from umi.competition_cohort_settlement import CohortSettlement
from umi.competition_round_journal import RoundJournal
from umi.competition_verification_reuse import VerificationReuse, verified_replay
from umi.competition_verification_snapshot import VerificationPackageStore, VerifiedPackageSnapshot
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_service_grants import review_service_closed
from .test_competition_verification_reuse import base_policy as base_policy
from .test_competition_verification_reuse import chain as chain
from .test_competition_verification_reuse import chain_config as chain_config
from .test_competition_verification_reuse import endpoint as endpoint
from .test_competition_verification_reuse import execution as execution
from .test_competition_verification_reuse import granted as granted
from .test_competition_verification_reuse import harness as harness
from .test_competition_verification_reuse import known_video_bytes as known_video_bytes
from .test_competition_verification_reuse import legacy_scenario as legacy_scenario
from .test_competition_verification_reuse import miner_policy as miner_policy
from .test_competition_verification_reuse import original_harness as original_harness
from .test_competition_verification_reuse import policy as policy
from .test_competition_verification_reuse import receipt_scenario as receipt_scenario
from .test_competition_verification_reuse import recovery as recovery
from .test_competition_verification_reuse import recovery_case as recovery_case
from .test_competition_verification_reuse import relay as relay
from .test_competition_verification_reuse import runtime as runtime
from .test_competition_verification_reuse import scenario as scenario
from .test_competition_verification_reuse import service as service
from .test_competition_verification_reuse import service_catalog_inputs as service_catalog_inputs
from .test_competition_verification_reuse import service_closed as service_closed
from .test_competition_verification_reuse import service_owner as service_owner
from .test_competition_verification_reuse import shared_control_group as shared_control_group
from .test_competition_verification_snapshot import Package, Result


def snapshot_at(root, objects):
    package = Package(
        name="native",
        objects=tuple(
            RewardPackageObject(sha256=key, value=json.loads(raw))
            for key, raw in sorted(objects.items())
        ),
    )
    path = root / "original.json"
    publish_aggregate_model(path, package, maximum_bytes=8 * 1024**2)

    def reopen():
        return VerificationPackageStore(root / "snapshots").load(
            path, Package, maximum_bytes=8 * 1024**2, expected_sha256=digest(package)
        )

    return reopen


def settlement_source(root, snapshot):
    owner = object.__new__(CohortSettlement)
    owner.journal = RoundJournal(root / "journal", {"scope": "verification-adapter"})
    owner.archive = JournalEndpointObjects(owner.journal)
    owner.external = snapshot.collector(8 * 1024**2)
    return owner


@pytest.mark.parametrize("wrapper", [False, True])
def test_native_closure_owner_source_restarts_without_payload_reads(
    service_closed, tmp_path, monkeypatch, wrapper
):
    b = service_closed
    reopen = snapshot_at(tmp_path, b["objects"])

    def selected(snapshot):
        owner = settlement_source(tmp_path, snapshot)
        objects = owner._object
        return owner, ReplayObjectCollector(objects, 8 * 1024**2) if wrapper else objects

    owner, objects = selected(reopen())
    with VerificationReuse(tmp_path / "receipts", owner="native").selected():
        assert review_service_closed(b, objects=objects) == b["closure"]
    original_coverage = set(owner.external.values)
    assert len(original_coverage) > 1

    def no_payload_reads(*args):
        pytest.fail("unchanged native closure reopened an immutable payload")

    monkeypatch.setattr(VerifiedPackageSnapshot, "read", no_payload_reads)
    owner, objects = selected(reopen())
    with VerificationReuse(tmp_path / "receipts", owner="native").selected():
        assert review_service_closed(b, objects=objects) == b["closure"]
    assert set(owner.external.values) == original_coverage
    if wrapper:
        assert set(objects.values) == original_coverage
        assert objects.used == owner.external.used


def test_archive_shadow_cannot_borrow_external_identity_or_bypass_conflict(
    tmp_path, monkeypatch, policy
):
    result = Result(value="retained")
    key = digest(result)
    owner = settlement_source(
        tmp_path, snapshot_at(tmp_path, {key: canonical_json_bytes(result)})()
    )

    @verified_replay("archive_selection", Result)
    def verify(objects, policy):
        return Result.model_validate_json(read_endpoint_object(objects, key))

    with VerificationReuse(tmp_path / "receipts", owner="archive").selected():
        assert verify(owner._object, policy) == result
    assert owner._object.verification_identity(key) is not None
    owner.archive.put(result)
    assert owner._object.verification_identity(key) is None

    def no_external_reads(*args):
        pytest.fail("journal-shadowed object was read from its external source")

    monkeypatch.setattr(VerifiedPackageSnapshot, "read", no_external_reads)
    with VerificationReuse(tmp_path / "receipts", owner="archive").selected():
        assert verify(owner._object, policy) == result
    with owner.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (key,))
    with (
        VerificationReuse(tmp_path / "receipts", owner="archive").selected(),
        pytest.raises(ValueError, match="conflict held"),
    ):
        verify(owner._object, policy)


def test_lazy_collector_preserves_bounds_coverage_and_export_bytes(tmp_path, monkeypatch):
    objects = {
        digest(value): canonical_json_bytes(value)
        for value in ({"payload": "a" * 600}, {"payload": "b" * 600})
    }
    snapshot = snapshot_at(tmp_path, objects)()
    collector = ReplayObjectCollector(snapshot.collector(8 * 1024**2), 1024)
    first, second = sorted(objects)
    native = VerifiedPackageSnapshot.read

    def no_payload_reads(*args):
        pytest.fail("coverage or lazy replay opened a payload")

    monkeypatch.setattr(VerifiedPackageSnapshot, "read", no_payload_reads)
    collector.verification_replay(first)
    collector.verification_replay(first)
    assert set(collector.values) == {first}
    assert first in collector.values and second not in collector.values
    assert collector.used == len(objects[first])
    assert not collector._values
    with pytest.raises(ValueError, match="evidence exceeds its bound"):
        collector.verification_replay(second)
    assert set(collector.values) == {first}
    assert set(collector.source.values) == {first}
    monkeypatch.setattr(VerifiedPackageSnapshot, "read", native)
    assert dict(collector.values) == {first: objects[first]}
    assert collector.used == len(objects[first])


def test_lazy_collector_refuses_changed_source_before_materializing(tmp_path):
    result = Result(value="retained")
    key = digest(result)
    snapshot = snapshot_at(tmp_path, {key: canonical_json_bytes(result)})()
    collector = ReplayObjectCollector(snapshot.collector(8 * 1024**2), 1024)
    collector.verification_replay(key)
    original = snapshot.store.object_path(key)
    original.chmod(0o600)
    original.write_bytes(b'{"value":"changed"}')
    original.chmod(0o400)
    with pytest.raises(ValueError, match="immutable identity"):
        dict(collector.values)
