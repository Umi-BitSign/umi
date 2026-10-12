"""Native startup checks on the updater's account and configuration path contract."""

from __future__ import annotations

import json
import os
import pwd
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.miner import _read_startup_file

from .test_miner_upgrade import ROOT, _manifest, upgrade, wallet


@pytest.mark.parametrize("owner", ["account", "root", "unrelated"])
@pytest.mark.parametrize("mode", [0o700, 0o755, 0o775])
def test_native_startup_parent_trust_keeps_account_owned_files(tmp_path, monkeypatch, owner, mode):
    path = tmp_path / "config.json"
    path.write_bytes(b'{"safe":true}')
    path.chmod(0o600)
    account_uid = os.geteuid()
    parent_uid = {"account": account_uid, "root": 0, "unrelated": account_uid + 10000}[owner]
    original = Path.lstat

    def observed_parent(candidate):
        metadata = original(candidate)
        if candidate == tmp_path:
            return SimpleNamespace(st_mode=0o040000 | mode, st_uid=parent_uid)
        return metadata

    monkeypatch.setattr(Path, "lstat", observed_parent)
    if owner == "unrelated" or mode & 0o022:
        with pytest.raises(RuntimeError, match="parent is unsafe"):
            _read_startup_file(path)
    else:
        assert _read_startup_file(path) == path.read_bytes()


def test_trusted_parent_does_not_allow_a_different_file_owner(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_bytes(b'{"safe":true}')
    path.chmod(0o600)
    native_stat = os.fstat

    def wrong_file_owner(fd):
        metadata = native_stat(fd)
        values = list(metadata)
        values[4] = os.geteuid() + 10000
        return os.stat_result(values)

    monkeypatch.setattr(os, "fstat", wrong_file_owner)
    with pytest.raises(RuntimeError, match="file is unsafe"):
        _read_startup_file(path)


@pytest.mark.parametrize("fault", [None, "policy_hash", "account_file", "state_overlap"])
def test_pre_cutover_check_uses_native_reader_and_preserved_service_cwd(
    tmp_path, monkeypatch, fault
):
    manifest = _manifest()
    config = tmp_path / "configuration"
    config.mkdir(mode=0o700)
    for name, source in (
        ("competition.json", "C5_POLICY.json"),
        ("transport.json", "C5_TRANSPORT_POLICY.json"),
    ):
        path = config / name
        path.write_bytes((ROOT / "docs/competition" / source).read_bytes())
        path.chmod(0o600)
    hotkey = wallet("//Bob").hotkey.ss58_address
    startup = config / "startup.json"
    startup.write_bytes(
        upgrade.startup(manifest, tmp_path / "state", hotkey, "10" * 32, "https://miner")
    )
    startup.chmod(0o600)
    if fault == "policy_hash":
        manifest["policy"]["sha256"] = "ff" * 32
    if fault == "account_file":
        startup.chmod(0o666)
    account = pwd.getpwuid(os.geteuid())
    arguments = [
        sys.executable,
        "-I",
        "-B",
        "-m",
        "umi.miner",
        "--policy",
        "configuration/transport.json",
        "--competition-policy",
        "configuration/competition.json",
        "--competition-cohort-config",
        "configuration/startup.json",
        "--nonce-db",
        "state/grants/nonce.db" if fault == "state_overlap" else "state/nonce.db",
        "--assignment-db",
        "state/assignment.db",
        "--finality-state",
        "state/finality.db",
        "--model-revision",
        "10" * 32,
        "--serving-origin",
        "https://miner",
    ]
    calls = []
    native_run = upgrade.run

    def selected_run(*command, **kwargs):
        assert command[:4] == ("runuser", "--user", account.pw_name, "--")
        assert command[4:8] == (sys.executable, "-I", "-B", "-c")
        selected = list(command[4:])
        # The subprocess executes real selected-runtime validation without requiring
        # privileged runuser in an ordinary test run. Actual UID is this fixture's
        # retained service UID; the source insertion represents installed source.
        selected[4] = "import sys;sys.path.insert(0," + repr(str(ROOT / "src")) + ");" + selected[4]
        calls.append(json.loads(selected[5]))
        return native_run(*selected, **kwargs)

    monkeypatch.setattr(upgrade, "run", selected_run)
    if fault is None:
        upgrade.validate_startup(arguments, account, tmp_path, hotkey, manifest)
    else:
        expected = {
            "policy_hash": "competition policy differs",
            "account_file": "file is unsafe",
            "state_overlap": "separate durable directory",
        }[fault]
        with pytest.raises(RuntimeError, match=expected):
            upgrade.validate_startup(arguments, account, tmp_path, hotkey, manifest)
    assert len(calls) == 1
    assert calls[0]["cwd"] == str(tmp_path)
    assert not (tmp_path / "state").exists()
