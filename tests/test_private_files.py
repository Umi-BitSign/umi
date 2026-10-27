import errno
import fcntl
import os
import select
import stat
from contextlib import ExitStack, contextmanager

import pytest
from pydantic import field_validator

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


def test_exact_retry_compares_current_bytes_with_only_one_buffered_encoding(tmp_path, monkeypatch):
    path = tmp_path / "outbox" / "record.json"
    value = StoredRecord(value="retained")
    files.publish_private_model(path, value)

    encode, calls = files.canonical_json_bytes, []

    def counted(value):
        calls.append(type(value))
        return encode(value)

    monkeypatch.setattr(files, "canonical_json_bytes", counted)
    files.publish_private_model(path, value)
    assert calls == [StoredRecord]
    path.write_bytes(canonical_json_bytes(StoredRecord(value="different")))
    with pytest.raises(ValueError, match="different bytes"):
        files.publish_private_model(path, value)


def test_exact_retry_still_validates_a_constructed_model(tmp_path):
    path = tmp_path / "outbox" / "record.json"
    # Initial publication historically allows a BaseModel constructed without
    # validation. Exact equality must not bypass the retry's schema validation.
    value = StoredRecord.model_construct(value=123)
    with pytest.warns(UserWarning):
        files.publish_private_model(path, value)
    with pytest.warns(UserWarning), pytest.raises(ValueError):
        files.publish_private_model(path, value)


def test_exact_retry_rejects_bytes_changed_by_schema_normalization(tmp_path):
    class NormalizedRecord(StoredRecord):
        @field_validator("value")
        @classmethod
        def normalized(cls, value):
            return value.strip()

    path = tmp_path / "outbox" / "record.json"
    value = NormalizedRecord.model_construct(value=" padded ")
    files.publish_private_model(path, value)
    with pytest.raises(ValueError, match="stable canonical bytes"):
        files.publish_private_model(path, value)


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
@pytest.mark.parametrize("operation", ["lock", "shared_lock", "publish"])
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
            if operation in {"lock", "shared_lock"}:
                files.lock_private_file(path, shared=operation == "shared_lock")
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


def test_read_only_shared_archive_lease_blocks_exclusive_release(tmp_path, monkeypatch):
    lock_path = tmp_path / ".proof-read-release.lock"
    owner = files.lock_private_file(lock_path)
    os.close(owner)
    inode = lock_path.stat().st_ino
    open_file = os.open

    def read_only_mount(path, flags, *args, **kwargs):
        if path == lock_path and flags & (os.O_CREAT | os.O_RDWR | os.O_WRONLY):
            raise OSError(errno.EROFS, "read-only archive mount")
        return open_file(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(files.os, "open", read_only_mount)
        first = files.lock_private_file(lock_path, shared=True)
        second = files.lock_private_file(lock_path, shared=True)
    try:
        assert fcntl.fcntl(first, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        assert os.fstat(first).st_ino == os.fstat(second).st_ino == inode
        with pytest.raises(files.PrivateStateBusyError):
            files.lock_private_file(lock_path)
        os.close(first)
        first = None
        with pytest.raises(files.PrivateStateBusyError):
            files.lock_private_file(lock_path)
    finally:
        if first is not None:
            os.close(first)
        os.close(second)
    owner = files.lock_private_file(lock_path)
    os.close(owner)
    assert lock_path.stat().st_ino == inode


def test_read_only_archive_missing_lease_requires_owner_provisioning(tmp_path, monkeypatch):
    path = tmp_path / ".proof-read-release.lock"
    open_file = os.open

    def read_only_mount(candidate, flags, *args, **kwargs):
        if candidate == path and flags & (os.O_CREAT | os.O_RDWR | os.O_WRONLY):
            raise OSError(errno.EROFS, "owner must provision the archive lease")
        return open_file(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(files.os, "open", read_only_mount)
    with pytest.raises(OSError) as caught:
        files.lock_private_file(path, shared=True)
    assert caught.value.errno == errno.EROFS
    assert list(tmp_path.iterdir()) == []


@contextmanager
def _child_holding_inherited_descriptors():
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    child = os.fork()
    if child == 0:
        # Model the pre-exec interval of a concurrent proof-helper fork. Never
        # use inherited Python locks or run pytest cleanup inside this child.
        os.close(ready_read)
        os.close(release_write)
        os.write(ready_write, b"1")
        ready, _, _ = select.select([release_read], [], [], 10)
        if ready:
            os.read(release_read, 1)
        os._exit(0 if ready else 124)
    os.close(ready_write)
    os.close(release_read)
    try:
        assert select.select([ready_read], [], [], 5)[0]
        assert os.read(ready_read, 1) == b"1"
        yield child
    finally:
        os.close(release_write)  # EOF also releases the child after a failed assertion.
        os.close(ready_read)
        assert os.waitpid(child, 0) == (child, 0)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX inherited flock description")
@pytest.mark.parametrize("stage", ["new", "retry", "conflict", "directory_sync_failure"])
def test_publication_releases_lock_while_fork_child_still_has_descriptor(
    tmp_path, monkeypatch, stage
):
    path = tmp_path / "outbox" / "first.json"
    value = StoredRecord(value="original")
    if stage in ("retry", "conflict"):
        files.publish_private_model(path, value)
    inode = path.stat().st_ino if path.exists() else None
    lock, sync = files.lock_private_file, os.fsync
    children, directory_syncs = [], []
    with ExitStack() as cleanup:

        def inherited(candidate):
            descriptor = lock(candidate)
            children.append(cleanup.enter_context(_child_holding_inherited_descriptors()))
            return descriptor

        def sync_while_locked(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                # Durability must finish before explicit unlock, including
                # exact retries. The new owner must still be excluded here.
                with pytest.raises(files.PrivateStateBusyError):
                    lock(path.parent / ".publish.lock")
                directory_syncs.append(descriptor)
                if stage == "directory_sync_failure":
                    raise OSError("injected directory sync failure")
            sync(descriptor)

        with monkeypatch.context() as patch:
            patch.setattr(files, "lock_private_file", inherited)
            patch.setattr(files.os, "fsync", sync_while_locked)
            if stage == "conflict":
                with pytest.raises(ValueError, match="different bytes"):
                    files.publish_private_model(path, StoredRecord(value="conflict"))
            elif stage == "directory_sync_failure":
                with pytest.raises(OSError, match="injected directory sync failure"):
                    files.publish_private_model(path, value)
            else:
                files.publish_private_model(path, value)
        assert len(children) == 1 and os.waitpid(children[0], os.WNOHANG) == (0, 0)
        # The child deliberately still owns its inherited descriptor. Closing
        # only the parent's fd leaves the lock held and makes this call fail.
        second = path.with_name("second.json")
        files.publish_private_model(second, StoredRecord(value="next"))
        assert files.read_private_model(path, StoredRecord) == value
        assert files.read_private_model(second, StoredRecord).value == "next"
        assert bool(directory_syncs) == (stage != "conflict")
        if inode is not None:
            assert path.stat().st_ino == inode


@pytest.mark.parametrize("failure", ["busy", "unsafe"])
def test_failed_lock_acquisition_never_runs_publication_unlock(tmp_path, monkeypatch, failure):
    root = tmp_path / "private"
    files.ensure_private_directory(root)
    lock_path = root / ".publish.lock"
    owner = files.lock_private_file(lock_path)
    flock, unlocks = fcntl.flock, []

    def tracked(descriptor, operation):
        if operation == fcntl.LOCK_UN:
            unlocks.append(descriptor)
        return flock(descriptor, operation)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(files.fcntl, "flock", tracked)
            if failure == "unsafe":
                lock_path.chmod(0o644)
            with pytest.raises(files.PrivateStateBusyError if failure == "busy" else ValueError):
                files.publish_private_model(root / "record.json", StoredRecord(value="busy"))
            assert unlocks == []
            lock_path.chmod(0o600)
            with pytest.raises(files.PrivateStateBusyError):
                files.lock_private_file(lock_path)
    finally:
        os.close(owner)


def test_publication_unlock_failure_still_closes_owned_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "outbox" / "record.json"
    flock, descriptors = fcntl.flock, []

    def fail_unlock(descriptor, operation):
        if operation == fcntl.LOCK_UN:
            descriptors.append(descriptor)
            raise OSError("injected unlock failure")
        return flock(descriptor, operation)

    with monkeypatch.context() as patch:
        patch.setattr(files.fcntl, "flock", fail_unlock)
        with pytest.raises(OSError, match="injected unlock failure"):
            files.publish_private_model(path, StoredRecord(value="retained"))
    assert len(descriptors) == 1
    with pytest.raises(OSError) as caught:
        os.fstat(descriptors[0])
    assert caught.value.errno == errno.EBADF
    files.publish_private_model(path, StoredRecord(value="retained"))


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
