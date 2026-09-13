from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from umi import competition_initial_upgrade as upgrade

from .test_validator_supervisor import _config


@pytest.fixture
def case(tmp_path, monkeypatch):
    source = tmp_path / "state" / "successor-v4" / "activation-source"
    source.mkdir(parents=True, mode=0o700)
    source.parent.chmod(0o700)
    retained = source.parent / "retained-anchors"
    config = _config(state_root=str(source.parents[1]))
    user = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
    monkeypatch.setattr(upgrade.anchors, "_root_owner_uid", os.geteuid)
    monkeypatch.setattr(upgrade, "_require_root_linux", lambda: None)
    directory = upgrade._directory

    def portable_directory(path, **kwargs):
        # Root's group 0 is unavailable in the unprivileged macOS suite. All
        # other metadata checks run unchanged; the opt-in Linux test uses root.
        kwargs["group"] = os.getegid()
        return directory(path, **kwargs)

    def portable_rename(parent, name, destination, *, destination_parent):
        os.fchmod(parent, 0o755)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        mode = os.fstat(child).st_mode & 0o777
        os.fchmod(child, 0o755)
        try:
            try:
                os.stat(destination, dir_fd=destination_parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(destination)
            os.rename(name, destination, src_dir_fd=parent, dst_dir_fd=destination_parent)
        finally:
            os.fchmod(child, mode)
            os.close(child)
            os.fchmod(parent, 0o555)

    monkeypatch.setattr(upgrade, "_directory", portable_directory)
    monkeypatch.setattr(upgrade.anchors, "_rename_noreplace", portable_rename)

    def partial(index, mode=0o700, parent=source):
        name = upgrade.anchors.ANCHOR_STAGING_PREFIX + f"{index:032x}"
        path = parent / name
        path.mkdir(mode=0o700)
        (path / "evidence").write_bytes(b"retained proof bytes")
        path.chmod(mode)
        return path

    result = SimpleNamespace(
        source=source,
        retained=retained,
        config=config,
        user=user,
        partial=partial,
        rename=portable_rename,
    )
    yield result
    source.chmod(0o700)
    for path in tmp_path.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o700)


@pytest.mark.parametrize("mode", [0o700, 0o555])
def test_interrupted_anchor_is_moved_intact_and_retry_is_idempotent(case, mode):
    original = case.partial(1, mode)
    inode = original.stat().st_ino
    case.source.chmod(0o555)
    upgrade._retain_interrupted_anchors(case.config, case.user)
    kept = case.retained / original.name
    assert not original.exists()
    assert kept.stat().st_ino == inode and kept.stat().st_mode & 0o777 == mode
    assert (kept / "evidence").read_bytes() == b"retained proof bytes"
    assert not list(case.source.iterdir())
    upgrade._retain_interrupted_anchors(case.config, case.user)
    assert kept.stat().st_ino == inode


def test_interruption_between_moves_resumes_without_overwrite(case, monkeypatch):
    first, second = case.partial(1), case.partial(2)
    case.source.chmod(0o555)
    calls = []

    def interrupted(*args, **kwargs):
        calls.append(args[1])
        if len(calls) == 2:
            raise OSError("simulated process interruption")
        case.rename(*args, **kwargs)

    monkeypatch.setattr(upgrade.anchors, "_rename_noreplace", interrupted)
    with pytest.raises(OSError, match="simulated"):
        upgrade._retain_interrupted_anchors(case.config, case.user)
    assert not first.exists() and second.exists()
    assert (case.retained / first.name / "evidence").read_bytes() == b"retained proof bytes"
    monkeypatch.setattr(upgrade.anchors, "_rename_noreplace", case.rename)
    upgrade._retain_interrupted_anchors(case.config, case.user)
    assert {p.name for p in case.retained.iterdir()} == {first.name, second.name}


@pytest.mark.parametrize("invalid", ["name", "mode", "symlink", "collision", "bound"])
def test_unexpected_sources_and_full_retention_hold_without_removing_anything(case, invalid):
    original = case.partial(1)
    if invalid == "name":
        (case.source / "unrecognized").mkdir()
    elif invalid == "mode":
        original.chmod(0o755)
    elif invalid == "symlink":
        (case.source / (upgrade.anchors.ANCHOR_STAGING_PREFIX + "f" * 32)).symlink_to(original)
    else:
        case.retained.mkdir(mode=0o700)
        for index in [1] if invalid == "collision" else range(2, 10):
            case.partial(index, parent=case.retained)
    case.source.chmod(0o555)
    with pytest.raises((OSError, ValueError)):
        upgrade._retain_interrupted_anchors(case.config, case.user)
    assert (original / "evidence").read_bytes() == b"retained proof bytes"


def test_published_anchor_is_not_moved_or_treated_as_a_partial(case):
    anchor = case.source / upgrade.activation.ANCHOR_DIRECTORY_NAME
    anchor.mkdir()
    (anchor / "marker").write_bytes(b"already published")
    case.source.chmod(0o555)
    upgrade._retain_interrupted_anchors(case.config, case.user)
    assert (anchor / "marker").read_bytes() == b"already published"
    assert not case.retained.exists()
