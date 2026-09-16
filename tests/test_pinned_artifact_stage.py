import hashlib
import stat

import pytest

from umi.pinned_artifact import PinnedArtifact, PinnedArtifactError, staged_pinned_artifacts


def specification(tmp_path):
    source = tmp_path.resolve() / "source"
    source.write_bytes(b"checked executable")
    source.chmod(0o500)
    return PinnedArtifact(
        "binary", source, hashlib.sha256(source.read_bytes()).hexdigest(), 1024, True
    )


def test_explicit_private_staging_parent_preserves_verified_copy_and_cleanup(tmp_path):
    item = specification(tmp_path)
    parent = tmp_path.resolve() / "exec-stage"
    parent.mkdir(mode=0o700)
    with staged_pinned_artifacts((item,), staging_directory=parent) as staged:
        copy = staged["binary"]
        assert copy.parent.parent == parent
        assert copy.read_bytes() == item.source.read_bytes()
        assert stat.S_IMODE(copy.stat().st_mode) == 0o500
    assert not list(parent.iterdir())


@pytest.mark.parametrize("mode", [0o755, 0o777, 0o750])
def test_staging_parent_must_be_private(tmp_path, mode):
    item = specification(tmp_path)
    parent = tmp_path.resolve() / "exec-stage"
    parent.mkdir()
    parent.chmod(mode)
    with (
        pytest.raises(PinnedArtifactError, match="unsafe_stage_parent"),
        staged_pinned_artifacts((item,), staging_directory=parent),
    ):
        pytest.fail("unsafe staging parent accepted")


def test_staging_parent_symlink_is_rejected(tmp_path):
    item = specification(tmp_path)
    parent = tmp_path.resolve() / "exec-stage"
    parent.mkdir(mode=0o700)
    link = tmp_path.resolve() / "link"
    link.symlink_to(parent, target_is_directory=True)
    with (
        pytest.raises(PinnedArtifactError, match="unsafe_stage_parent"),
        staged_pinned_artifacts((item,), staging_directory=link),
    ):
        pytest.fail("staging symlink accepted")


def test_environment_stage_uses_same_private_parent_checks(tmp_path, monkeypatch):
    item = specification(tmp_path)
    parent = tmp_path.resolve() / "private-stage"
    monkeypatch.setenv("UMI_PINNED_ARTIFACT_STAGE", str(parent))
    with staged_pinned_artifacts((item,)) as staged:
        assert staged["binary"].parent.parent == parent
    assert not list(parent.iterdir())
    parent.chmod(0o755)
    with (
        pytest.raises(PinnedArtifactError, match="unsafe_stage_parent"),
        staged_pinned_artifacts((item,)),
    ):
        pytest.fail("unsafe environment stage accepted")


def test_explicit_stage_takes_precedence_over_environment(tmp_path, monkeypatch):
    item = specification(tmp_path)
    parent = tmp_path.resolve() / "private-stage"
    parent.mkdir(mode=0o700)
    monkeypatch.setenv("UMI_PINNED_ARTIFACT_STAGE", "/missing-environment-stage")
    with staged_pinned_artifacts((item,), staging_directory=parent) as staged:
        assert staged["binary"].parent.parent == parent


@pytest.mark.parametrize("value", ["", ".", "relative-stage"])
def test_relative_environment_stage_is_rejected(tmp_path, monkeypatch, value):
    item = specification(tmp_path)
    monkeypatch.setenv("UMI_PINNED_ARTIFACT_STAGE", value)
    with (
        pytest.raises((PinnedArtifactError, FileNotFoundError)),
        staged_pinned_artifacts((item,)),
    ):
        pytest.fail("relative environment stage accepted")
