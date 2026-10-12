"""Bounded exact replication after native review, including interrupted retries."""

import os
import stat

import pytest

from umi import competition_cohort_aggregate_replica as replica
from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError, lock_private_file
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Document(StrictProtocolModel):
    body: str


@pytest.fixture
def files(tmp_path):
    value = Document(body="a\u2603" * 300000)
    source, destination = tmp_path / "original" / "package.json", tmp_path / "out" / "package.json"
    publish_aggregate_model(source, value, maximum_bytes=2 * 1024**2)
    return source, destination, digest(value), canonical_json_bytes(value)


def copy(files, **changes):
    source, destination, expected, raw = files
    replica.replicate_verified_aggregate(
        source, destination, expected_digest=expected, maximum_bytes=changes.get("limit", len(raw))
    )


def test_exact_bytes_inode_and_private_mode_survive_retry(files):
    source, destination, _, raw = files
    copy(files)
    inode = destination.stat().st_ino
    assert destination.read_bytes() == source.read_bytes() == raw
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    copy(files)
    assert destination.stat().st_ino == inode


@pytest.mark.parametrize("side", ["source", "destination"])
@pytest.mark.parametrize("fault", ["changed", "symlink", "hardlink", "public", "fifo"])
def test_rejects_invalid_files_without_replacing_originals(files, side, fault):
    source, destination, _, raw = files
    copy(files)
    path = source if side == "source" else destination
    if fault == "changed":
        path.write_bytes(raw[:-1] + b" ")
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(source if side == "destination" else destination)
    elif fault == "hardlink":
        os.link(path, path.with_suffix(".linked"))
    elif fault == "public":
        path.chmod(0o644)
    else:
        path.unlink()
        os.mkfifo(path, 0o600)
    with pytest.raises((ValueError, OSError)):
        copy(files)
    assert not list(destination.parent.glob(".pending-*"))
    if side == "source":
        assert destination.read_bytes() == raw


def test_missing_source_remains_required_even_after_publication(files):
    source, destination, _, raw = files
    copy(files)
    source.unlink()
    with pytest.raises(FileNotFoundError):
        copy(files)
    assert destination.read_bytes() == raw


def test_limit_refusal_does_not_publish(files):
    source, destination, _, raw = files
    with pytest.raises(ValueError, match="byte bound"):
        copy(files, limit=len(raw) - 1)
    assert not destination.exists()
    assert source.read_bytes() == raw
    assert not list(destination.parent.glob(".pending-*"))


def test_changed_source_does_not_publish(files):
    source, destination, _, raw = files
    source.write_bytes(raw[:-1] + b" ")
    with pytest.raises(ValueError, match="verified original"):
        copy(files)
    assert not destination.exists()
    assert not list(destination.parent.glob(".pending-*"))


def test_publish_lock_stays_nonblocking(files):
    _, destination, _, _ = files
    destination.parent.mkdir(mode=0o700)
    descriptor = lock_private_file(destination.parent / ".publish.lock")
    try:
        with pytest.raises(PrivateStateBusyError):
            copy(files)
    finally:
        os.close(descriptor)
    copy(files)


@pytest.mark.parametrize("failure", ["file_fsync", "rename", "directory_fsync"])
def test_publication_failure_and_exact_retry_keep_verified_bytes(files, monkeypatch, failure):
    _, destination, _, raw = files
    original_fsync, original_rename = replica.os.fsync, replica.os.rename

    def fsync(descriptor):
        directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
        if (directory and failure == "directory_fsync") or (
            not directory and failure == "file_fsync"
        ):
            raise OSError("injected durability refusal")
        return original_fsync(descriptor)

    def rename(*args):
        if failure == "rename":
            raise OSError("injected rename refusal")
        return original_rename(*args)

    with monkeypatch.context() as patch:
        patch.setattr(replica.os, "fsync", fsync)
        patch.setattr(replica.os, "rename", rename)
        with pytest.raises(OSError, match="injected"):
            copy(files)
    assert destination.exists() == (failure == "directory_fsync")
    inode = destination.stat().st_ino if destination.exists() else None
    assert not list(destination.parent.glob(".pending-*"))
    copy(files)
    assert destination.read_bytes() == raw
    if inode is not None:
        assert destination.stat().st_ino == inode
