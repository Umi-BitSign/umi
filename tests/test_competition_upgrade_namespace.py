from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_upgrade_namespace as namespace
from umi.competition_host_upgrade import HostUpgradeError


def test_mount_syscall_uses_fixed_bytes_without_shell(monkeypatch):
    calls = []

    def mount(*arguments):
        calls.append(arguments)
        return 0

    monkeypatch.setattr(namespace.ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(mount=mount))
    namespace._mount(None, "/", None, namespace._MS_PRIVATE | namespace._MS_REC)
    assert calls == [(None, b"/", None, namespace._MS_PRIVATE | namespace._MS_REC, None)]
    assert mount.restype is namespace.ctypes.c_int


def test_syscall_failure_has_no_source_or_secret_output(monkeypatch):
    def mount(*_):
        return -1

    monkeypatch.setattr(namespace.ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(mount=mount))
    with pytest.raises(HostUpgradeError, match=r"^could not establish the private observer mount$"):
        namespace._mount("sensitive-test-path", "/", None, namespace._MS_PRIVATE)


@pytest.fixture
def unsharing(monkeypatch):
    calls = []
    identities = iter([(1, 2), (1, 3), (1, 1)])

    def unshare(flags):
        calls.append(("unshare", flags))
        return 0

    monkeypatch.setattr(namespace, "_require_root_linux", lambda: None)
    monkeypatch.setattr(namespace, "_single_thread", lambda: None)
    monkeypatch.setattr(namespace, "_ENTERED_PID", None)
    monkeypatch.setattr(namespace, "_namespace_id", lambda *a: next(identities))
    monkeypatch.setattr(namespace.ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(unshare=unshare))
    monkeypatch.setattr(namespace, "_mount", lambda *a: calls.append(("mount", *a)))
    return calls


def test_unshare_precedes_disabling_propagation_and_can_only_run_once(unsharing):
    namespace._unshare_mounts()
    assert unsharing == [
        ("unshare", namespace._CLONE_NEWNS),
        ("mount", None, "/", None, namespace._MS_PRIVATE | namespace._MS_REC),
    ]
    assert os.getpid() == namespace._ENTERED_PID
    with pytest.raises(HostUpgradeError, match="repeated or inherited"):
        namespace._unshare_mounts()


def test_failure_after_unshare_cannot_retry(unsharing, monkeypatch):
    def failed(*_):
        raise HostUpgradeError("injected propagation failure")

    monkeypatch.setattr(namespace, "_mount", failed)
    with pytest.raises(HostUpgradeError, match="propagation failure"):
        namespace._unshare_mounts()
    with pytest.raises(HostUpgradeError, match="repeated or inherited"):
        namespace._unshare_mounts()


@pytest.mark.parametrize("ids", [[(1, 2), (1, 2), (1, 1)], [(1, 2), (1, 1), (1, 1)]])
def test_rejects_unchanged_or_init_namespace_without_mounting(unsharing, monkeypatch, ids):
    identities = iter(ids)
    monkeypatch.setattr(namespace, "_namespace_id", lambda *a: next(identities))
    with pytest.raises(HostUpgradeError, match="did not become private"):
        namespace._unshare_mounts()
    assert unsharing == [("unshare", namespace._CLONE_NEWNS)]


def test_namespace_rejects_unverified_tree_before_side_effects(monkeypatch):
    monkeypatch.setattr(namespace, "_require_root_linux", lambda: None)
    monkeypatch.setattr(namespace, "_unshare_mounts", lambda: pytest.fail("unshared early"))
    with pytest.raises(HostUpgradeError, match="verified signed host tree"):
        namespace.prepare_upgrade_observer_namespace(
            host_tree=object(), config=object(), control_directory=Path("/test")
        )
