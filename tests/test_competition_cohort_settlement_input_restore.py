"""Restored original inputs resume from native identities without manual repair."""

import json
import logging
from types import SimpleNamespace

import pytest

from umi import competition_cohort_settlement_service as service
from umi import competition_verification_snapshot as snapshots
from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.competition_cohort_reward_package import RewardPackageObject
from umi.competition_verification_snapshot import (
    VerificationPackageStore,
    VerificationSnapshotRepairRequired,
)
from umi.open_competition import digest

from .test_competition_verification_snapshot import Package


@pytest.fixture
def retained(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "SettlementInputPackage", Package)
    item = {"payload": "original"}
    package = Package(
        name="reviewed", objects=(RewardPackageObject(sha256=digest(item), value=item),)
    )
    source = tmp_path / "original.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    node = object.__new__(service.CohortSettlementService)
    node.config = SimpleNamespace(maximum_package_bytes=1024**2)
    node.cohort = "11" * 32
    node.verified_packages = VerificationPackageStore(tmp_path / "snapshots")
    previous = node.verified_packages.load(source, Package, maximum_bytes=1024**2)
    return SimpleNamespace(
        node=node,
        source=source,
        raw=source.read_bytes(),
        prior={"sha256": previous.sha256},
        package=package,
    )


async def test_missing_reviewed_original_holds_then_resumes_exact_restored_bytes(retained, caplog):
    h = retained
    h.source.unlink()
    with pytest.raises(VerificationSnapshotRepairRequired, match="must be restored"):
        await h.node._input_snapshot(h.source, h.prior)
    h.source.write_bytes(h.raw)
    h.source.chmod(0o600)
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    restored = await h.node._input_snapshot(h.source, h.prior)
    assert restored.sha256 == h.prior["sha256"] and h.source.read_bytes() == h.raw
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    repair = [r for r in events if r.get("stage") == "settlement_original_input_repair"]
    assert repair[0]["state"] == "started" and repair[-1]["state"] == "completed"
    assert repair[-1]["completed"] == repair[-1]["total"] == 1
    assert repair[-1]["eta_seconds"] == 0


async def test_unchanged_input_and_derived_metadata_repair_do_not_reread_package(
    retained, monkeypatch
):
    h = retained

    def forbidden(*args, **kwargs):
        raise AssertionError("unchanged original must reuse retained native preparation")

    monkeypatch.setattr(snapshots, "read_aggregate_model", forbidden)
    current = await h.node._input_snapshot(h.source, h.prior)
    metadata, _ = h.node.verified_packages._paths(h.source, current.record.original_stamp)
    metadata.write_bytes(b"damaged derived metadata")
    restored = await h.node._input_snapshot(h.source, h.prior)
    assert restored.sha256 == h.prior["sha256"] and h.source.read_bytes() == h.raw


async def test_conflicting_replacement_cannot_change_retained_identity_and_correct_restore_recovers(
    retained,
):
    h = retained
    h.source.unlink()
    conflict = h.package.model_copy(update={"name": "unreviewed replacement"})
    publish_aggregate_model(h.source, conflict, maximum_bytes=1024**2)
    replacement = h.source.read_bytes()
    with pytest.raises(ValueError):
        await h.node._input_snapshot(h.source, h.prior)
    assert h.source.read_bytes() == replacement
    h.source.write_bytes(h.raw)
    restored = await h.node._input_snapshot(h.source, h.prior)
    assert restored.sha256 == h.prior["sha256"]


async def test_first_missing_input_does_not_invent_prior_authority(retained):
    h = retained
    missing = h.source.with_name("not-yet-delivered.json")
    with pytest.raises(FileNotFoundError):
        await h.node._input_snapshot(missing, None)


def test_fixture_transport_preserves_receiver_local_verification_receipts(tmp_path):
    from .cohort_native_settlement_fixture import copy_originals

    source, target = tmp_path / "source", tmp_path / "target"
    for root, local in ((source, b"producer inode"), (target, b"receiver inode")):
        (root / "inputs").mkdir(mode=0o700, parents=True)
        receipt = root / "inputs/.aggregate-verification/model/receipt.json"
        receipt.parent.mkdir(mode=0o700, parents=True)
        receipt.write_bytes(local)
    package = source / "inputs/published.json"
    package.write_bytes(b"original protocol bytes")
    copy_originals(source, target)
    assert (target / "inputs/published.json").read_bytes() == package.read_bytes()
    assert (target / "inputs/.aggregate-verification/model/receipt.json").read_bytes() == (
        b"receiver inode"
    )
