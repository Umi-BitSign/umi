"""Retained reward-file consumers preserve snapshots on supported clocks."""

import pytest

from umi import competition_reward_files as files_module
from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.competition_cohort_reward_package import RewardPackageObject
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_verification_snapshot import VerificationPackageStore
from umi.open_competition import digest

from .test_competition_verification_snapshot import Package


@pytest.mark.parametrize("qualified_clock", [False, True])
def test_retained_snapshot_supports_first_replica_and_warm_consumption(
    tmp_path, monkeypatch, qualified_clock
):
    from umi import competition_cohort_aggregate_replica as replica_module
    from umi import competition_verification_snapshot as snapshot_module

    # Substitute only the small aggregate schema. Store capabilities, original
    # file handling, copy/byte verification and receiving consumer are native.
    monkeypatch.setattr(files_module, "CohortRewardPackage", Package)
    if not qualified_clock:
        monkeypatch.setattr(replica_module, "verification_tick", lambda *_: False)
    value = {"payload": "retained"}
    package = Package(
        name="reward-input", objects=(RewardPackageObject(sha256=digest(value), value=value),)
    )
    source = tmp_path / "settlement.json"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    files = StandingRewardFiles(
        tmp_path / "reward-files", maximum_package_bytes=1024**2, maximum_witness_bytes=1024**2
    )
    snapshot = files.package_store.load(source, Package, maximum_bytes=1024**2)
    calls = []
    original = snapshot_module.read_aggregate_model

    def counted(path, *args, **kwargs):
        calls.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(snapshot_module, "read_aggregate_model", counted)
    files.retain_package(snapshot)
    target = files.root / "packages" / (digest(package) + ".json")
    assert calls == ([] if qualified_clock else [target])
    assert target.read_bytes() == source.read_bytes()

    def no_payload(*args, **kwargs):
        pytest.fail("completed replica was parsed or copied again")

    monkeypatch.setattr(snapshot_module, "read_aggregate_model", no_payload)
    native_read = snapshot_module._read_bounded_private_bytes

    def metadata_only(path, **kwargs):
        assert path not in (source, target) and path.suffix != ".bin"
        return native_read(path, **kwargs)

    monkeypatch.setattr(snapshot_module, "_read_bounded_private_bytes", metadata_only)
    reopened = StandingRewardFiles(
        files.root, maximum_package_bytes=1024**2, maximum_witness_bytes=1024**2
    )
    assert reopened.verified_package(digest(package)).sha256 == digest(package)
    if qualified_clock:
        monkeypatch.setattr(replica_module, "_transfer", no_payload)
        source_snapshot = VerificationPackageStore(files.package_store.directory).load_existing(
            source, Package, maximum_bytes=1024**2
        )
        reopened.retain_package(source_snapshot)
