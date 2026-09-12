"""Kernel lock/descriptor checks using a synthetic child process, no wallet."""

from __future__ import annotations

import os
import selectors
import subprocess
import sys
from contextlib import suppress
from types import SimpleNamespace

import pytest

from umi import competition_host_start as start
from umi.competition_upgrade import _fingerprint

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="requires Linux procfs")


# Keep the child independent of application imports. Its lifetime follows the
# parent pipe: EOF also releases the lock if the test runner exits unexpectedly.
_HOLDER = """
import fcntl, os, sys
descriptor = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(1, b'ready\\n')
    sys.stdin.buffer.read(1)
finally:
    os.close(descriptor)
"""


@pytest.fixture
def held(tmp_path):
    path = tmp_path / "synthetic-supervisor-process.lock"
    path.write_bytes(b"")
    path.chmod(0o600)
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", _HOLDER, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(10), "synthetic lock-holder failed to start"
            assert os.read(process.stdout.fileno(), 6) == b"ready\n"
        fixture = SimpleNamespace(
            plan=SimpleNamespace(service_uid=os.geteuid()),
            _stopped=SimpleNamespace(
                _lease=SimpleNamespace(
                    config_path=tmp_path / "synthetic-config.json",
                    lock_path=path,
                    lock_identity=_fingerprint(path.stat()),
                )
            ),
        )
        yield process, fixture
    finally:
        with suppress(BrokenPipeError):
            process.stdin.close()
        process.stdin = None
        try:
            output, error = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
            raise
        assert process.returncode == 0 and output == error == b""


def test_kernel_holder_is_the_expected_main_process(held):
    process, fixture = held
    start._process_owns_lock(process.pid, fixture)


def test_some_other_holder_cannot_stand_in_for_main_process(held):
    _, fixture = held
    with pytest.raises(start._StartupPending, match="does not retain"):
        start._process_owns_lock(os.getpid(), fixture)


def test_replaced_kernel_lock_inode_is_rejected(held):
    process, fixture = held
    path = fixture._stopped._lease.lock_path
    path.rename(path.with_suffix(".retained"))
    path.write_bytes(b"")
    path.chmod(0o600)
    with pytest.raises(start.HostUpgradeError, match="changed identity"):
        start._process_owns_lock(process.pid, fixture)
