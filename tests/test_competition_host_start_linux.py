"""Kernel lock/descriptor checks using a synthetic child process, no wallet."""

from __future__ import annotations

import fcntl
import multiprocessing
import os
import sys
from types import SimpleNamespace

import pytest

from umi import competition_host_start as start
from umi.competition_upgrade import _fingerprint

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="requires Linux procfs")


def _holder(path, ready, finish):
    descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ready.set()
        finish.wait(15)
    finally:
        os.close(descriptor)


@pytest.fixture
def held(tmp_path):
    path = tmp_path / "synthetic-supervisor-process.lock"
    path.write_bytes(b"")
    path.chmod(0o600)
    process_context = multiprocessing.get_context("spawn")
    ready, finish = process_context.Event(), process_context.Event()
    process = process_context.Process(target=_holder, args=(path, ready, finish))
    process.start()
    try:
        assert ready.wait(10), "synthetic lock-holder failed to start"
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
        finish.set()
        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0


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
