"""A native source capability skips source hashing, never destination checks."""

from pathlib import Path

import pytest

from umi import competition_cohort_aggregate_replica as replica
from umi.competition_aggregate_replica_binding import VerifiedAggregateReplica
from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.competition_cohort_reward_package import RewardPackageObject
from umi.competition_verification_snapshot import VerificationPackageStore
from umi.open_competition import digest

from .test_competition_verification_snapshot import Package

LIMIT = 1024**2


def source_fixture(tmp_path):
    value = {"payload": "native source"}
    package = Package(
        name="source", objects=(RewardPackageObject(sha256=digest(value), value=value),)
    )
    path = tmp_path / "source.json"
    publish_aggregate_model(path, package, maximum_bytes=LIMIT)
    snapshot = VerificationPackageStore(tmp_path / "snapshot").load(
        path, Package, maximum_bytes=LIMIT
    )
    return path, tmp_path / "replica" / "source.json", snapshot


def copy(source, target, snapshot):
    return replica.replicate_verified_aggregate(
        source,
        target,
        expected_digest=snapshot.sha256,
        maximum_bytes=LIMIT,
        verified_source=snapshot,
    )


def test_first_replica_reuses_source_and_checks_new_destination_once(tmp_path, monkeypatch):
    source, target, snapshot = source_fixture(tmp_path)
    native = replica._transfer
    calls = []

    def observed(path, output, *args, **kwargs):
        calls.append((path, output is not None, kwargs.get("verified_identity") is not None))
        return native(path, output, *args, **kwargs)

    monkeypatch.setattr(replica, "_transfer", observed)
    binding = copy(source, target, snapshot)
    assert type(binding) is VerifiedAggregateReplica
    assert calls == [(source, True, True), (target, False, False)]
    assert binding.check(snapshot.sha256, LIMIT)[0] == target
    assert target.read_bytes() == source.read_bytes()
    calls.clear()
    repeated = copy(source, target, snapshot)
    assert repeated.check(snapshot.sha256, LIMIT) == binding.check(snapshot.sha256, LIMIT)
    assert calls == []


def test_digest_only_does_not_acquire_source_capability(tmp_path, monkeypatch):
    source, target, snapshot = source_fixture(tmp_path)
    native = replica._transfer
    observed = []

    def checked(path, output, *args, **kwargs):
        observed.append(kwargs.get("verified_identity"))
        return native(path, output, *args, **kwargs)

    monkeypatch.setattr(replica, "_transfer", checked)
    assert (
        replica.replicate_verified_aggregate(
            source, target, expected_digest=snapshot.sha256, maximum_bytes=LIMIT
        )
        is None
    )
    assert observed == [None]


@pytest.mark.parametrize("changed", ["source", "digest", "capability", "path"])
def test_wrong_or_changed_native_source_refuses_before_copy(tmp_path, monkeypatch, changed):
    source, target, snapshot = source_fixture(tmp_path)
    sha = snapshot.sha256
    selected = snapshot
    if changed == "source":
        source.write_bytes(b"corrupt")
    elif changed == "digest":
        sha = "ff" * 32
    elif changed == "capability":
        selected = {"sha256": sha}
    else:
        other = tmp_path / "different.json"
        other.write_bytes(source.read_bytes())
        other.chmod(0o600)
        source = other

    def refused(*args, **kwargs):
        pytest.fail("invalid capability attempted a payload copy")

    monkeypatch.setattr(replica, "_transfer", refused)
    with pytest.raises((ValueError, TypeError)):
        replica.replicate_verified_aggregate(
            source, target, expected_digest=sha, maximum_bytes=LIMIT, verified_source=selected
        )
    assert not target.exists()


def test_changed_destination_invalidates_native_replica_binding(tmp_path):
    source, target, snapshot = source_fixture(tmp_path)
    binding = copy(source, target, snapshot)
    target.write_bytes(b"mutated destination")
    with pytest.raises(ValueError, match="replica changed"):
        binding.check(snapshot.sha256, LIMIT)


def test_replica_binding_cannot_be_constructed_by_digest(tmp_path):
    with pytest.raises(TypeError, match="native byte verification"):
        VerifiedAggregateReplica(Path(tmp_path / "unverified"), "ff" * 32, (), issuer=object())


def test_same_native_original_needs_no_second_byte_check(tmp_path, monkeypatch):
    source, _target, snapshot = source_fixture(tmp_path)

    def refused(*args, **kwargs):
        pytest.fail("native original was unnecessarily reread")

    monkeypatch.setattr(replica, "_transfer", refused)
    binding = copy(source, source, snapshot)
    assert binding.check(snapshot.sha256, LIMIT)[0] == source


def test_unqualified_clock_keeps_copy_without_issuing_stamp_reuse(tmp_path, monkeypatch):
    source, target, snapshot = source_fixture(tmp_path)
    monkeypatch.setattr(replica, "verification_tick", lambda *_: False)
    assert copy(source, target, snapshot) is None
    assert target.read_bytes() == source.read_bytes()


def test_destination_corruption_between_copy_and_check_is_rejected(tmp_path, monkeypatch):
    source, target, snapshot = source_fixture(tmp_path)
    native = replica.verification_tick

    def corrupt(*args):
        if target.exists():
            target.write_bytes(b"corrupt")
        return native(*args)

    monkeypatch.setattr(replica, "verification_tick", corrupt)
    with pytest.raises(ValueError):
        copy(source, target, snapshot)
