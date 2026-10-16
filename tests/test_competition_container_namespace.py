"""Actual Linux flock ownership, without a Podman store or production state."""

import fcntl
import os
import sys

import pytest

from umi.competition_container_namespace import require_supervisor_process_owner

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux fdinfo ownership")


def test_namespace_owner_never_acquires_a_missing_lease(tmp_path):
    path = tmp_path / "supervisor-process.lock"
    path.write_bytes(b"original lease metadata")
    path.chmod(0o600)
    before = path.stat()
    with pytest.raises(ValueError, match="original lock"):
        require_supervisor_process_owner(tmp_path)
    with path.open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require_supervisor_process_owner(tmp_path)
    after = path.stat()
    assert (before.st_ino, before.st_ctime_ns) == (after.st_ino, after.st_ctime_ns)
    assert path.read_bytes() == b"original lease metadata"


def test_namespace_owner_rejects_replaced_lock_inode(tmp_path):
    path = tmp_path / "supervisor-process.lock"
    path.write_bytes(b"original")
    path.chmod(0o600)
    with path.open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path.rename(tmp_path / "retained-original")
        path.write_bytes(b"replacement")
        path.chmod(0o600)
        with pytest.raises(ValueError, match="original lock"):
            require_supervisor_process_owner(tmp_path)


def test_another_process_lock_does_not_authorize_namespace_migration(tmp_path):
    path = tmp_path / "supervisor-process.lock"
    path.write_bytes(b"original")
    path.chmod(0o600)
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(ready_r)
            os.close(release_w)
            with path.open("rb") as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(ready_w, b"1")
                os.read(release_r, 1)
        finally:
            os._exit(0)
    os.close(ready_w)
    os.close(release_r)
    try:
        assert os.read(ready_r, 1) == b"1"
        with pytest.raises(ValueError, match="original lock"):
            require_supervisor_process_owner(tmp_path)
    finally:
        os.close(release_w)
        os.close(ready_r)
        _, status = os.waitpid(child, 0)
        assert status == 0
