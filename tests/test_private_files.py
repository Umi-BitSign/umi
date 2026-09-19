import errno
import os
import stat

import pytest

import umi.private_files as files
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class StoredRecord(StrictProtocolModel):
    value: str


def test_publication_exact_retry_preserves_inode_and_conflict_preserves_bytes(tmp_path):
    path = tmp_path / "outbox" / "record.json"
    value = StoredRecord(value="first")
    files.publish_private_model(path, value)
    inode = path.stat().st_ino
    assert path.read_bytes() == canonical_json_bytes(value)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert files.read_private_model(path, StoredRecord) == value

    files.publish_private_model(path, value)
    assert path.stat().st_ino == inode
    with pytest.raises(ValueError, match="already contains different bytes"):
        files.publish_private_model(path, StoredRecord(value="different"))
    assert path.stat().st_ino == inode
    assert path.read_bytes() == canonical_json_bytes(value)
    assert not list(path.parent.glob(".pending-*"))


def _unsafe_destination(path, kind):
    path.write_bytes(canonical_json_bytes(StoredRecord(value="original")))
    path.chmod(0o600)
    if kind == "symlink":
        original = path.with_name("original.json")
        path.rename(original)
        path.symlink_to(original)
    elif kind == "hardlink":
        os.link(path, path.with_name("second-link"))
    elif kind == "public":
        path.chmod(0o644)
    else:
        path.unlink()
        os.mkfifo(path, 0o600)


# Historical evaluator tests cover these cases at the inbox reader. Exercise
# the shared lock and existing-output boundaries here without duplicating them.
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "fifo"])
@pytest.mark.parametrize("operation", ["lock", "publish"])
def test_unsafe_lock_or_existing_output_is_rejected(tmp_path, kind, operation, monkeypatch):
    root = tmp_path / "private"
    files.ensure_private_directory(root)
    path = root / "record.json"
    _unsafe_destination(path, kind)
    before = path.lstat()
    opened = []
    real_open = os.open

    def tracked_open(candidate, *args, **kwargs):
        descriptor = real_open(candidate, *args, **kwargs)
        if candidate == path:
            opened.append(descriptor)
        return descriptor

    with monkeypatch.context() as patch:
        patch.setattr(files.os, "open", tracked_open)
        with pytest.raises((OSError, ValueError)):
            if operation == "lock":
                files.lock_private_file(path)
            else:
                files.publish_private_model(path, StoredRecord(value="replacement"))
    assert path.lstat().st_ino == before.st_ino
    assert stat.S_IFMT(path.lstat().st_mode) == stat.S_IFMT(before.st_mode)
    assert not list(root.glob(".pending-*"))
    for descriptor in opened:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF


def test_lock_contention_prevents_publication_and_release_allows_retry(tmp_path):
    root = tmp_path / "private"
    files.ensure_private_directory(root)
    lock_path = root / ".publish.lock"
    lock = files.lock_private_file(lock_path)
    path = root / "record.json"
    value = StoredRecord(value="bounded")
    try:
        with pytest.raises(BlockingIOError):
            files.lock_private_file(lock_path)
        with pytest.raises(BlockingIOError):
            files.publish_private_model(path, value)
        assert not path.exists()
        assert not list(root.glob(".pending-*"))
    finally:
        os.close(lock)
    files.publish_private_model(path, value)
    assert files.read_private_model(path, StoredRecord) == value


def test_output_bound_is_inclusive_and_rejection_precedes_directory_creation(tmp_path, monkeypatch):
    value = StoredRecord(value="bounded")
    raw = canonical_json_bytes(value)
    path = tmp_path / "allowed" / "record.json"
    monkeypatch.setattr(files, "MAX_PRIVATE_BYTES", len(raw))
    files.publish_private_model(path, value)
    assert files.read_private_model(path, StoredRecord) == value

    monkeypatch.setattr(files, "MAX_PRIVATE_BYTES", len(raw) - 1)
    rejected = tmp_path / "rejected" / "record.json"
    with pytest.raises(ValueError, match="output exceeds its byte bound"):
        files.publish_private_model(rejected, value)
    assert not rejected.parent.exists()


@pytest.mark.parametrize("stage", ["file_sync", "rename", "directory_sync"])
def test_failed_publication_removes_pending_file_and_releases_lock(tmp_path, monkeypatch, stage):
    path = tmp_path / "outbox" / "record.json"
    value = StoredRecord(value="retained")
    original_fsync = os.fsync

    def fail_sync(descriptor):
        is_directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
        if (stage == "file_sync" and not is_directory) or (
            stage == "directory_sync" and is_directory
        ):
            raise OSError("injected publication failure")
        return original_fsync(descriptor)

    def fail_rename(*args):
        raise OSError("injected publication failure")

    with monkeypatch.context() as patch:
        if stage == "rename":
            patch.setattr(files.os, "rename", fail_rename)
        else:
            patch.setattr(files.os, "fsync", fail_sync)
        with pytest.raises(OSError, match="injected publication failure"):
            files.publish_private_model(path, value)

    assert not list(path.parent.glob(".pending-*"))
    assert path.exists() == (stage == "directory_sync")
    lock = files.lock_private_file(path.parent / ".publish.lock")
    os.close(lock)
    # A directory-sync error happens after rename. Keep the canonical output and
    # let the retry verify it, without deleting a possibly published artifact.
    inode = path.stat().st_ino if path.exists() else None
    files.publish_private_model(path, value)
    assert files.read_private_model(path, StoredRecord) == value
    if inode is not None:
        assert path.stat().st_ino == inode


def test_exact_retry_resyncs_directory_after_uncertain_publication(tmp_path, monkeypatch):
    path = tmp_path / "outbox" / "record.json"
    value = StoredRecord(value="retained")
    real_fsync = os.fsync
    directory_syncs = []

    def sync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs.append(os.fstat(descriptor).st_ino)
            if len(directory_syncs) <= 2:
                raise OSError("directory sync unavailable")
        return real_fsync(descriptor)

    monkeypatch.setattr(files.os, "fsync", sync)
    # Rename succeeded, but neither attempt may report durable publication
    # while the containing directory still cannot be synced.
    for _ in range(2):
        with pytest.raises(OSError, match="directory sync unavailable"):
            files.publish_private_model(path, value)
        assert path.read_bytes() == canonical_json_bytes(value)
        assert not list(path.parent.glob(".pending-*"))
    inode = path.stat().st_ino
    files.publish_private_model(path, value)
    assert directory_syncs == [path.parent.stat().st_ino] * 3
    assert path.stat().st_ino == inode
