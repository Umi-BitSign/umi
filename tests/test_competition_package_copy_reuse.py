from __future__ import annotations

import shutil

import pytest

from umi import competition_package as package
from umi import competition_package_reuse as reuse_module
from umi.competition_package_reuse import package_verification_session

from .test_competition_package import _load
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import policy as policy
from .test_competition_package import release_identity as release_identity
from .test_competition_package import replay_limits as replay_limits


def _copies(case, tmp_path):
    original = case.path
    copied = tmp_path / "retained-copy"
    shutil.copytree(original, copied)
    return original, copied


def _qualify(case, copies, policy, limits, release, directory):
    with package_verification_session(directory=directory):
        for path in copies:
            case.path = path
            expected = _load(case, policy, limits, release)
    return expected


def test_retained_copies_reconstruct_once_after_restart_and_remain_isolated(
    monkeypatch, package_case, policy, package_limits, release_identity, tmp_path
):
    copies = _copies(package_case, tmp_path)
    directory = tmp_path / "verification"
    expected = _qualify(package_case, copies, policy, package_limits, release_identity, directory)
    calls = []
    load = package._load_competition_package

    def counted(*args, **kwargs):
        calls.append(args[0])
        return load(*args, **kwargs)

    monkeypatch.setattr(package, "_load_competition_package", counted)
    with package_verification_session(directory=directory):
        package_case.path = copies[0]
        first = _load(package_case, policy, package_limits, release_identity)
        # Both stored copies were independently verified before this process.
        # A second reconstruction would reread/parse the large unchanged payload.
        monkeypatch.setattr(
            package, "_read_sealed_file", lambda *a, **k: pytest.fail("payload reread")
        )
        for path in [copies[1], copies[0], copies[1]]:
            package_case.path = path
            current = _load(package_case, policy, package_limits, release_identity)
            assert current == expected and current is not first
            assert current.evidence is not first.evidence
            object.__setattr__(current, "package_sha256", "f" * 64)
    assert calls == [copies[0]]


def test_unverified_copy_cannot_borrow_parsed_content(
    monkeypatch, package_case, policy, package_limits, release_identity, tmp_path
):
    copies = _copies(package_case, tmp_path)
    with package_verification_session(directory=tmp_path / "verification"):
        package_case.path = copies[0]
        _load(package_case, policy, package_limits, release_identity)
        package_case.path = copies[1]
        monkeypatch.setattr(
            package,
            "_verify_publications",
            lambda *a, **k: pytest.fail("new copy verification reached"),
        )
        with pytest.raises(pytest.fail.Exception, match="new copy verification reached"):
            _load(package_case, policy, package_limits, release_identity)


@pytest.mark.parametrize("change", ["bytes", "mode", "replacement", "receipt"])
def test_changed_copy_or_receipt_never_reuses_other_copy(
    change, monkeypatch, package_case, policy, package_limits, release_identity, tmp_path
):
    copies = _copies(package_case, tmp_path)
    directory = tmp_path / "verification"
    _qualify(package_case, copies, policy, package_limits, release_identity, directory)
    with package_verification_session(directory=directory):
        package_case.path = copies[0]
        _load(package_case, policy, package_limits, release_identity)
        package_case.path = copies[1]
        item = copies[1] / "evidence.json"
        if change == "receipt":
            key, _ = package._package_reuse_key(
                copies[1],
                expected_package_sha256=package_case.prepared.package_sha256,
                expected_policy_sha256=package.digest(policy),
                observed_release=release_identity,
                limits=package_limits,
            )
            receipt = directory / (reuse_module._metadata_digest(key) + ".json")
            receipt.write_bytes(b"{}")
        elif change == "mode":
            item.chmod(0o600)
        elif change == "replacement":
            copies[1].chmod(0o700)
            data = item.read_bytes()
            item.unlink()
            item.write_bytes(data)
            item.chmod(0o400)
            copies[1].chmod(0o500)
        else:
            item.chmod(0o600)
            item.write_bytes(b" " + item.read_bytes()[1:])
            item.chmod(0o400)
        monkeypatch.setattr(
            package,
            "_load_competition_package",
            lambda *a, **k: (_ for _ in ()).throw(ValueError("fresh verification required")),
        )
        with pytest.raises((OSError, ValueError)):
            _load(package_case, policy, package_limits, release_identity)


@pytest.mark.parametrize("change", ["policy", "release", "limits"])
def test_other_copy_reuse_keeps_exact_policy_release_and_limits(
    change, monkeypatch, package_case, policy, package_limits, release_identity, tmp_path
):
    copies = _copies(package_case, tmp_path)
    directory = tmp_path / "verification"
    _qualify(package_case, copies, policy, package_limits, release_identity, directory)
    with package_verification_session(directory=directory):
        package_case.path = copies[0]
        _load(package_case, policy, package_limits, release_identity)
        package_case.path = copies[1]
        args = {}
        if change == "policy":
            args["expected_policy_sha256"] = "f" * 64
        elif change == "release":
            release_identity = release_identity.model_copy(update={"umi_revision": "1" * 40})
        else:
            package_limits = package_limits.model_copy(update={"maximum_evidence_bytes": 1})
        with pytest.raises(ValueError):
            _load(package_case, policy, package_limits, release_identity, **args)


@pytest.mark.parametrize("other_copy", [False, True])
def test_change_during_cached_projection_is_rejected(
    other_copy, monkeypatch, package_case, policy, package_limits, release_identity, tmp_path
):
    copies = _copies(package_case, tmp_path)
    directory = tmp_path / "verification"
    _qualify(package_case, copies, policy, package_limits, release_identity, directory)
    with package_verification_session(directory=directory):
        package_case.path = copies[0]
        _load(package_case, policy, package_limits, release_identity)
        package_case.path = copies[int(other_copy)]
        original = reuse_module.deepcopy

        def changed(value):
            result = original(value)
            item = package_case.path / "evidence.json"
            item.chmod(0o600)
            item.chmod(0o400)
            return result

        monkeypatch.setattr(reuse_module, "deepcopy", changed)
        with pytest.raises(ValueError, match="changed during verified copy reuse"):
            _load(package_case, policy, package_limits, release_identity)
