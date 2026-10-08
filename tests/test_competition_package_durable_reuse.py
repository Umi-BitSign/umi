from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from umi import competition_package as package
from umi.competition_package_reuse import package_verification_session

from .test_competition_package import _load
from .test_competition_package import (
    package_case as package_case,
)
from .test_competition_package import (
    package_limits as package_limits,
)
from .test_competition_package import (
    policy as policy,
)
from .test_competition_package import (
    release_identity as release_identity,
)
from .test_competition_package import (
    replay_limits as replay_limits,
)


def test_fresh_process_reconstructs_verified_package_without_replaying(
    package_case, policy, package_limits, release_identity, tmp_path
):
    directory = tmp_path / "verification"
    with package_verification_session(directory=directory):
        expected = _load(package_case, policy, package_limits, release_identity)
    # Persist only a small verdict, never another copy of the package evidence.
    receipts = list(directory.glob("*.json"))
    assert len(receipts) == 1 and receipts[0].stat().st_size < 1024
    script = """
import json,sys
from pathlib import Path
from umi import competition_package as p
from umi.competition_package_reuse import package_verification_session
args=json.loads(sys.argv[1])
def no_replay(*a,**k):
    raise AssertionError("restart must not repeat publication verification")
p._verify_publications=no_replay
read=p._read_sealed_file
def no_payload_hash(*a,**k):
    assert k.get("expected_sha256") is None
    return read(*a,**k)
p._read_sealed_file=no_payload_hash
with package_verification_session(directory=Path(args.pop("directory"))):
    path=Path(args.pop("path"))
    args["observed_release"]=p.CompetitionReleaseIdentity.model_validate(args["observed_release"])
    args["limits"]=p.CompetitionPackageLimits.model_validate(args["limits"])
    value=p.load_competition_package(path,**args)
    assert not value.chain_submission_authorized
    print(value.manifest_sha256)
"""
    args = dict(
        directory=str(directory),
        path=str(package_case.path),
        expected_package_sha256=expected.package_sha256,
        expected_policy_sha256=expected.manifest.policy_sha256,
        observed_release=release_identity.model_dump(mode="json", by_alias=True),
        limits=package_limits.model_dump(mode="json", by_alias=True),
    )
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(args)],
        env={**os.environ, "PYTHONPATH": str(Path(package.__file__).resolve().parents[1])},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected.manifest_sha256


def test_receipt_cannot_verify_a_different_stored_copy(
    package_case, policy, package_limits, release_identity, tmp_path, monkeypatch
):
    directory = tmp_path / "verification"
    with package_verification_session(directory=directory):
        _load(package_case, policy, package_limits, release_identity)
    copied = tmp_path / "copied"
    shutil.copytree(package_case.path, copied)
    package_case.path = copied

    def fail(*args, **kwargs):
        raise ValueError("new stored copy requires verification")

    monkeypatch.setattr(package, "_verify_publications", fail)
    with (
        pytest.raises(ValueError, match="new stored copy"),
        package_verification_session(directory=directory),
    ):
        _load(package_case, policy, package_limits, release_identity)


@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "public", "oversize", "invalid"])
def test_unsafe_receipt_is_never_trusted(
    mutation, package_case, policy, package_limits, release_identity, tmp_path
):
    directory = tmp_path / "verification"
    with package_verification_session(directory=directory):
        _load(package_case, policy, package_limits, release_identity)
    receipt = next(directory.glob("*.json"))
    if mutation == "symlink":
        target = tmp_path / "moved"
        receipt.rename(target)
        receipt.symlink_to(target)
    elif mutation == "hardlink":
        (tmp_path / "linked").hardlink_to(receipt)
    elif mutation == "public":
        receipt.chmod(0o644)
    elif mutation == "oversize":
        receipt.write_bytes(b" " * 1025)
    else:
        receipt.write_bytes(b"{}")
    with pytest.raises((OSError, ValueError)), package_verification_session(directory=directory):
        _load(package_case, policy, package_limits, release_identity)


def test_changed_content_is_not_verified_by_prior_receipt(
    package_case, policy, package_limits, release_identity, tmp_path
):
    directory = tmp_path / "verification"
    with package_verification_session(directory=directory):
        _load(package_case, policy, package_limits, release_identity)
    path = package_case.path / "evidence.json"
    path.chmod(0o600)
    path.write_bytes(b" " + path.read_bytes()[1:])
    path.chmod(0o400)
    with pytest.raises(ValueError), package_verification_session(directory=directory):
        _load(package_case, policy, package_limits, release_identity)


def test_small_memory_budget_still_retains_durable_verification(
    package_case, policy, package_limits, release_identity, tmp_path, monkeypatch
):
    directory = tmp_path / "verification"
    with package_verification_session(directory=directory, maximum_input_bytes=1):
        first = _load(package_case, policy, package_limits, release_identity)

    def no_replay(*args, **kwargs):
        raise AssertionError("parsed-object memory budget must not discard durable verification")

    monkeypatch.setattr(package, "_verify_publications", no_replay)
    with package_verification_session(directory=directory, maximum_input_bytes=1):
        assert _load(package_case, policy, package_limits, release_identity) == first
        assert _load(package_case, policy, package_limits, release_identity) == first
