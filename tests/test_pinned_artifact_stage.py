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
