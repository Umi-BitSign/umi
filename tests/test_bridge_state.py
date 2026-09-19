"""Durable state ownership is independent of bridge CLI/network orchestration."""

import ast
import os
from pathlib import Path

import pytest

import umi.registration_bridge as bridge
from umi.bridge import state as persistence


def test_state_and_file_helpers_keep_the_existing_import_paths():
    assert bridge.RegistrationBridgeState is persistence.RegistrationBridgeState
    assert bridge._read_bytes is persistence._read_bytes
    assert bridge._write_new is persistence._write_new
    assert bridge._fsync is persistence._fsync
    assert bridge.MAX_HISTORY_BYTES == persistence.MAX_HISTORY_BYTES
    assert bridge.MAX_HISTORY_FILES == persistence.MAX_HISTORY_FILES
    assert bridge.SimpleBootstrapJournal is persistence.SimpleBootstrapJournal
    assert bridge.SIMPLE_BOOTSTRAP_MANIFEST_SHA256 == persistence.SIMPLE_BOOTSTRAP_MANIFEST_SHA256


def test_state_does_not_import_the_cli_or_native_chain_orchestration():
    tree = ast.parse(Path(persistence.__file__).read_text())
    imports = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not any(
        n.module in {"registration_bridge", "native", "submission", "signing", "receipts"}
        for n in imports
    )
    for function in ast.walk(tree):
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(function))


@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt])
def test_failed_initial_snapshot_closes_the_descriptor_and_releases_lock(
    tmp_path, monkeypatch, error
):
    root = tmp_path.resolve() / "state"
    state = persistence.RegistrationBridgeState(root)
    held = []

    def fail():
        state.require_locked()
        held.append(state.descriptor)
        raise error("initial snapshot failed")

    monkeypatch.setattr(state, "_snapshot", fail)
    with pytest.raises(error, match="initial snapshot failed"):
        state.__enter__()
    assert state.descriptor == -1
    with pytest.raises(OSError):
        os.fstat(held[0])
    with persistence.RegistrationBridgeState(root) as reopened:
        reopened.require_locked()


def test_capacity_rejection_does_not_leak_the_service_lock(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "state"
    root.mkdir(mode=0o700)
    history = root / "registration-bridge-history"
    history.mkdir(mode=0o700)
    path = history / "retained.json"
    path.write_bytes(b"retained evidence")
    path.chmod(0o600)
    state = persistence.RegistrationBridgeState(root)
    with monkeypatch.context() as patch:
        patch.setattr(persistence, "MAX_HISTORY_FILES", 0)
        with pytest.raises(RuntimeError, match="history_capacity_reached"):
            state.__enter__()
    assert state.descriptor == -1
    assert path.read_bytes() == b"retained evidence"
    with persistence.RegistrationBridgeState(root) as reopened:
        reopened.require_locked()
