from __future__ import annotations

import shutil

import pytest

from umi import competition_package as package
from umi.competition_package_reuse import current_package_reuse, package_verification_session

from .test_competition_package import (
    _load,
)
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


def _count_verification(monkeypatch):
    calls = []
    original = package._load_competition_package

    def counted(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(package, "_load_competition_package", counted)
    return calls


def test_identical_copies_reuse_verification_but_never_return_shared_models(
    monkeypatch, package_case, policy, package_limits, release_identity, tmp_path
):
    calls = _count_verification(monkeypatch)
    with package_verification_session():
        first = _load(package_case, policy, package_limits, release_identity)
        copied = tmp_path / "copied-package"
        shutil.copytree(package_case.path, copied)
        try:
            original_path, package_case.path = package_case.path, copied
            second = _load(package_case, policy, package_limits, release_identity)
            assert first == second and first is not second
            assert first.evidence is not second.evidence
            assert len(calls) == 1
            # Even deliberate mutation of a returned model cannot poison the
            # cache's private copy or the next caller's verified projection.
            object.__setattr__(first, "package_sha256", "f" * 64)
            assert _load(package_case, policy, package_limits, release_identity) == second
        finally:
            package_case.path = original_path
            copied.chmod(0o700)
    assert current_package_reuse() is None
    _load(package_case, policy, package_limits, release_identity)
    assert len(calls) == 2


@pytest.mark.parametrize("mutation", ["bytes", "mode", "extra", "hardlink", "symlink"])
def test_reuse_rechecks_sealed_files(
    mutation, package_case, policy, package_limits, release_identity
):
    with package_verification_session():
        _load(package_case, policy, package_limits, release_identity)
        root = package_case.path
        item = root / "evidence.json"
        root.chmod(0o700)
        if mutation == "bytes":
            raw = item.read_bytes()
            item.chmod(0o600)
            item.write_bytes(b" " + raw[1:])
            item.chmod(0o400)
        elif mutation == "mode":
            item.chmod(0o600)
        elif mutation == "extra":
            (root / "extra").write_text("unexpected")
        elif mutation == "hardlink":
            (root.parent / "extra-link").hardlink_to(item)
        else:
            moved = root.parent / "moved-evidence"
            item.rename(moved)
            item.symlink_to(moved)
        root.chmod(0o500)
        with pytest.raises((OSError, ValueError)):
            _load(package_case, policy, package_limits, release_identity)


def test_reuse_preserves_release_policy_and_capacity_checks(
    package_case, policy, package_limits, release_identity
):
    with package_verification_session():
        _load(package_case, policy, package_limits, release_identity)
        with pytest.raises(ValueError):
            _load(package_case, policy, package_limits, release_identity,
                  expected_policy_sha256="f" * 64)
        with pytest.raises(ValueError):
            _load(package_case, policy, package_limits,
                  release_identity.model_copy(update={"umi_revision": "1" * 40}))
        with pytest.raises(ValueError):
            _load(package_case, policy,
                  package_limits.model_copy(update={"maximum_evidence_bytes": 1}),
                  release_identity)


def test_small_cache_falls_back_without_rejecting_valid_work(
    monkeypatch, package_case, policy, package_limits, release_identity
):
    calls = _count_verification(monkeypatch)
    with package_verification_session(maximum_input_bytes=1):
        assert _load(package_case, policy, package_limits, release_identity) == _load(
            package_case, policy, package_limits, release_identity
        )
    assert len(calls) == 2


def test_failed_verification_is_not_remembered(
    monkeypatch, package_case, policy, package_limits, release_identity
):
    original = package._load_competition_package
    with package_verification_session():
        def fail(*args, **kwargs):
            raise ValueError("injected failure")
        monkeypatch.setattr(package, "_load_competition_package", fail)
        with pytest.raises(ValueError, match="injected"):
            _load(package_case, policy, package_limits, release_identity)
        monkeypatch.setattr(package, "_load_competition_package", original)
        assert _load(package_case, policy, package_limits, release_identity).package_sha256 == (
            package_case.prepared.package_sha256
        )


def test_context_exit_clears_even_after_failure():
    with pytest.raises(RuntimeError), package_verification_session() as reuse:
        raise RuntimeError("shutdown")
    assert current_package_reuse() is None
    assert reuse.lookup(("anything",)) is None
