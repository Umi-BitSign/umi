from __future__ import annotations

import hashlib
import json
import os
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_package
from umi.competition_package import (
    CompetitionPackageLimits,
    CompetitionPackageManifest,
    CompetitionReleaseIdentity,
    competition_package_digest,
    load_competition_package,
    prepare_competition_package,
)
from umi.competition_policy_lineage import (
    clear_lineage_registry,
    register_lineage,
    registered_lineage,
)
from umi.protocol import canonical_json_bytes

from .test_competition_publication import _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_open_competition import digest
from .test_open_competition import policy as policy


@pytest.fixture
def package_limits() -> CompetitionPackageLimits:
    return CompetitionPackageLimits(
        maximum_manifest_bytes=64 * 1024,
        maximum_policy_bytes=1_000_000,
        maximum_cutoff_certificate_bytes=10_000_000,
        maximum_settlement_certificate_bytes=10_000_000,
        maximum_settlement_bytes=10_000_000,
        maximum_roster_bytes=1_000_000,
        maximum_evidence_bytes=5_000_000,
        maximum_replay_limits_bytes=4096,
        maximum_release_identity_bytes=4096,
        maximum_aggregate_bytes=40_000_000,
    )


@pytest.fixture
def release_identity() -> CompetitionReleaseIdentity:
    return CompetitionReleaseIdentity(
        schema="umi-competition-replay-release-identity/1",
        umi_revision="ab" * 20,
        release_manifest_sha256="cd" * 32,
        release_bundle_sha256="ef" * 32,
        target_triple="x86_64-unknown-linux-gnu",
    )


@pytest.fixture
def package_case(tmp_path, policy, replay_limits, package_limits, release_identity):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    prepared = prepare_competition_package(
        policy=policy,
        cutoff_certificate=scenario.cutoff_certificate,
        settlement_certificate=scenario.settlement_certificate,
        retained_settlement=scenario.settlement,
        roster=tuple(reversed(scenario.submissions)),
        evidence=tuple(reversed(scenario.evidence)),
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=tmp_path / "packages",
        limits=package_limits,
    )
    case = SimpleNamespace(
        scenario=scenario,
        prepared=prepared,
        path=Path(prepared.package_path),
    )
    try:
        yield case
    finally:
        # Package directories are deliberately sealed mode 0500. Restore only
        # this fixture-owned directory so pytest can unlink its contents.
        with suppress(FileNotFoundError):
            case.path.chmod(0o700)


def _load(case, policy, package_limits, release_identity, **changes):
    arguments = {
        "expected_package_sha256": case.prepared.package_sha256,
        "expected_policy_sha256": digest(policy),
        "observed_release": release_identity,
        "limits": package_limits,
    }
    arguments.update(changes)
    return load_competition_package(case.path, **arguments)


def _replace_payload(case, name: str, body: bytes) -> str:
    manifest_path = case.path / "manifest.json"
    manifest = CompetitionPackageManifest.model_validate_json(
        manifest_path.read_bytes(), strict=True
    )
    case.path.chmod(0o700)
    try:
        path = case.path / name
        path.chmod(0o600)
        path.write_bytes(body)
        path.chmod(0o400)
        files = tuple(
            item.model_copy(
                update={
                    "size_bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            )
            if item.name == name
            else item
            for item in manifest.files
        )
        manifest = manifest.model_copy(update={"files": files})
        manifest_path.chmod(0o600)
        manifest_path.write_bytes(canonical_json_bytes(manifest))
        manifest_path.chmod(0o400)
    finally:
        case.path.chmod(0o500)
    return competition_package_digest(manifest)


@pytest.fixture(params=(1, 2))
def carried_package(tmp_path, policy, replay_limits, package_limits, release_identity, request):
    successor = policy.model_copy(
        update={
            "sequence": policy.sequence + 1,
            "predecessor_sha256": digest(policy),
            "maximum_inference_ms": policy.maximum_inference_ms * 2,
        }
    )
    predecessors = (policy,)
    if request.param == 2:
        predecessors = (successor, policy)
        successor = successor.model_copy(
            update={
                "sequence": successor.sequence + 1,
                "predecessor_sha256": digest(successor),
            }
        )
    scenario = _scenario(
        policy,
        tmp_path / "scenario",
        replay_limits,
        successor_policy=successor,
        predecessor_policies=predecessors,
    )
    prepared = prepare_competition_package(
        policy=successor,
        cutoff_certificate=scenario.cutoff_certificate,
        settlement_certificate=scenario.settlement_certificate,
        retained_settlement=scenario.settlement,
        roster=scenario.submissions,
        evidence=scenario.evidence,
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=tmp_path / "packages",
        limits=package_limits,
    )
    case = SimpleNamespace(
        prepared=prepared,
        path=Path(prepared.package_path),
        policy=successor,
        predecessors=predecessors,
    )
    try:
        yield case
    finally:
        case.path.chmod(0o700)


def test_carried_package_replays_without_process_registry(
    carried_package, policy, package_limits, release_identity
):
    case = carried_package
    roster = json.loads((case.path / "roster.json").read_bytes())
    assert roster["schema"] == "umi-competition-replay-roster/2"
    assert roster["predecessor_policies"] == [
        p.model_dump(mode="json", by_alias=True) for p in case.predecessors
    ]
    clear_lineage_registry()
    loaded = _load(case, case.policy, package_limits, release_identity)
    assert loaded.roster.predecessor_policies == case.predecessors
    assert registered_lineage(case.policy).admitted_policy_sha256s == (digest(case.policy),)


@pytest.mark.parametrize("mutation", ["omitted", "different", "reversed_version"])
def test_package_cannot_borrow_undeclared_lineage(
    carried_package, policy, package_limits, release_identity, mutation
):
    case = carried_package
    # A warm service process must not make an incomplete package appear valid.
    register_lineage(case.policy, case.predecessors)
    before = registered_lineage(case.policy).admitted_policy_sha256s
    roster = json.loads((case.path / "roster.json").read_bytes())
    if mutation == "omitted":
        roster["schema"] = "umi-competition-replay-roster/1"
        roster.pop("predecessor_policies")
    elif mutation == "different":
        roster["predecessor_policies"][0]["maximum_inference_ms"] += 1
    else:
        roster["schema"] = "umi-competition-replay-roster/1"
    package_id = _replace_payload(case, "roster.json", canonical_json_bytes(roster))
    with pytest.raises(ValueError):
        _load(
            case, case.policy, package_limits, release_identity, expected_package_sha256=package_id
        )
    assert registered_lineage(case.policy).admitted_policy_sha256s == before


def test_prepare_load_and_exact_retry(
    package_case, policy, replay_limits, package_limits, release_identity
):
    case = package_case
    loaded = _load(case, policy, package_limits, release_identity)
    retried = prepare_competition_package(
        policy=policy,
        cutoff_certificate=case.scenario.cutoff_certificate,
        settlement_certificate=case.scenario.settlement_certificate,
        retained_settlement=case.scenario.settlement,
        roster=case.scenario.submissions,
        evidence=case.scenario.evidence,
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=case.path.parent,
        limits=package_limits,
    )

    assert retried == case.prepared
    assert loaded.package_sha256 == case.prepared.package_sha256
    assert loaded.manifest.policy_sha256 == digest(policy)
    assert loaded.retained_settlement == case.scenario.settlement
    assert set(json.loads((case.path / "roster.json").read_bytes())) == {"schema", "submissions"}
    assert {entry.name for entry in case.path.iterdir()} == {
        "manifest.json",
        "cutoff-certificate.json",
        "evidence.json",
        "policy.json",
        "release-identity.json",
        "replay-limits.json",
        "roster.json",
        "settlement-certificate.json",
        "settlement.json",
    }
    assert case.path.stat().st_mode & 0o777 == 0o500
    assert all(entry.stat().st_mode & 0o777 == 0o400 for entry in case.path.iterdir())
    assert not list(case.path.parent.glob(".pending-*"))


@pytest.mark.parametrize("mismatch", ["package", "policy", "release"])
def test_load_rejects_expected_binding_mismatch(
    package_case, policy, package_limits, release_identity, mismatch
):
    changes = {}
    if mismatch == "package":
        changes["expected_package_sha256"] = "00" * 32
    elif mismatch == "policy":
        changes["expected_policy_sha256"] = "11" * 32
    else:
        changes["observed_release"] = release_identity.model_copy(
            update={"release_bundle_sha256": "12" * 32}
        )
    with pytest.raises(ValueError):
        _load(package_case, policy, package_limits, release_identity, **changes)


@pytest.mark.parametrize(
    "tamper",
    [
        "noncanonical",
        "extra",
        "missing",
        "mode",
        "symlink",
        "hardlink",
        "fifo",
        "bound",
        "aggregate-bound",
    ],
)
def test_load_rejects_canonical_tree_mode_link_and_bound_tamper(
    package_case, policy, package_limits, release_identity, tmp_path, tamper
):
    case = package_case
    expected = case.prepared.package_sha256
    limits = package_limits

    if tamper == "noncanonical":
        body = (case.path / "release-identity.json").read_bytes()
        expected = _replace_payload(case, "release-identity.json", b" " + body)
    elif tamper == "bound":
        size = (case.path / "evidence.json").stat().st_size
        limits = package_limits.model_copy(update={"maximum_evidence_bytes": size - 1})
    elif tamper == "aggregate-bound":
        size = sum(entry.stat().st_size for entry in case.path.iterdir())
        limits = package_limits.model_copy(update={"maximum_aggregate_bytes": size - 1})
    else:
        case.path.chmod(0o700)
        try:
            target = case.path / "evidence.json"
            if tamper == "extra":
                extra = case.path / "extra.json"
                extra.write_bytes(b"{}")
                extra.chmod(0o400)
            elif tamper == "missing":
                target.unlink()
            elif tamper == "mode":
                target.chmod(0o600)
            else:
                body = target.read_bytes()
                target.unlink()
                outside = tmp_path / f"outside-{tamper}"
                if tamper == "symlink":
                    outside.write_bytes(body)
                    target.symlink_to(outside)
                elif tamper == "hardlink":
                    outside.write_bytes(body)
                    outside.chmod(0o400)
                    os.link(outside, target)
                else:
                    os.mkfifo(target, 0o400)
        finally:
            case.path.chmod(0o500)

    try:
        with pytest.raises((OSError, ValueError)):
            _load(
                case,
                policy,
                limits,
                release_identity,
                expected_package_sha256=expected,
            )
    finally:
        case.path.chmod(0o700)


def test_retained_settlement_must_equal_signed_publication(
    package_case, policy, package_limits, release_identity
):
    case = package_case
    changed = case.scenario.settlement.model_copy(
        update={"observed_block": case.scenario.settlement.observed_block + 1}
    )
    expected = _replace_payload(case, "settlement.json", canonical_json_bytes(changed))

    with pytest.raises(ValueError, match="differs from the retained settlement"):
        _load(
            case,
            policy,
            package_limits,
            release_identity,
            expected_package_sha256=expected,
        )


def test_load_never_follows_an_intermediate_directory_symlink(
    package_case, policy, package_limits, release_identity, tmp_path
):
    alias = tmp_path / "aliased-packages"
    alias.symlink_to(package_case.path.parent, target_is_directory=True)

    with pytest.raises(OSError):
        load_competition_package(
            alias / package_case.path.name,
            expected_package_sha256=package_case.prepared.package_sha256,
            expected_policy_sha256=digest(policy),
            observed_release=release_identity,
            limits=package_limits,
        )


def test_failed_write_leaves_only_an_inert_partial_package(
    tmp_path, policy, replay_limits, package_limits, release_identity, monkeypatch
):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    destination = tmp_path / "packages"
    original = competition_package._write_sealed_file
    calls = 0

    def fail_after_two(directory, name, body):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("injected package write failure")
        return original(directory, name, body)

    monkeypatch.setattr(competition_package, "_write_sealed_file", fail_after_two)
    with pytest.raises(RuntimeError, match="injected package write failure"):
        prepare_competition_package(
            policy=policy,
            cutoff_certificate=scenario.cutoff_certificate,
            settlement_certificate=scenario.settlement_certificate,
            retained_settlement=scenario.settlement,
            roster=scenario.submissions,
            evidence=scenario.evidence,
            replay_limits=replay_limits,
            release_identity=release_identity,
            destination_root=destination,
            limits=package_limits,
        )

    children = list(destination.iterdir())
    assert len(children) == 1
    partial = children[0]
    assert partial.is_dir()
    assert partial.stat().st_mode & 0o777 == 0o700
    assert not list(destination.glob(".pending-*"))
    with pytest.raises((OSError, ValueError)):
        load_competition_package(
            partial,
            expected_package_sha256=partial.name,
            expected_policy_sha256=digest(policy),
            observed_release=release_identity,
            limits=package_limits,
        )
