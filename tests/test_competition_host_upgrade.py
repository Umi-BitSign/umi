from __future__ import annotations

import fcntl
import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_competition_upgrade import installation, write
from tests.test_validator_supervisor_adapters import _bootstrap_bundle
from umi import competition_host_upgrade as host
from umi.protocol import canonical_json_bytes


@pytest.fixture(scope="module")
def inputs():
    return _bootstrap_bundle()


@pytest.fixture
def installed(tmp_path, inputs, monkeypatch):
    value = installation(tmp_path / "installed", inputs, "linux/amd64")
    write(value.root / "state" / "supervisor-process.lock", b'{"old":"identity"}', 0o600)
    # These are OS test ports, not production configuration or authority inputs.
    monkeypatch.setattr(host, "_require_root_linux", lambda: None)
    monkeypatch.setattr(host, "_root_file", lambda path: None)
    monkeypatch.setattr(host, "_check_unit", lambda *args: {"FragmentPath": str(value.config_path)})
    return value


def hold(value, **changes):
    options = dict(
        config_path=value.config_path,
        accepted_directive_bytes=canonical_json_bytes(value.signed),
        expected_hotkey=value.config.validator_hotkey,
        service_uid=os.geteuid(),
    )
    options.update(changes)
    return host.hold_stopped_supervisor(**options)


def test_live_stopped_lease_preserves_bytes_and_expires(installed):
    lock = installed.root / "state" / "supervisor-process.lock"
    previous = lock.read_bytes()
    with hold(installed) as stopped:
        assert stopped.state_root == installed.root / "state"
        assert stopped.worker_state_root == installed.root / "worker"
        assert stopped.accepted_directive_sha256 == installed.signed.directive_sha256
        assert (
            stopped.accepted_signed_directive_sha256
            == hashlib.sha256(canonical_json_bytes(installed.signed)).hexdigest()
        )
        assert stopped.expected_manifest_sha256
        assert stopped.config_sha256
        assert stopped.installation_sha256
        stopped.recheck_stopped()
        other = os.open(lock, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)
    assert lock.read_bytes() == previous
    assert not Path(installed.config.wallet.path).exists()
    with pytest.raises(host.HostUpgradeError, match="closed"):
        stopped.recheck_stopped()


def test_capability_cannot_be_rebound_to_another_installation(installed):
    with hold(installed) as stopped:
        forged = replace(stopped, config_sha256="a" * 64)
        with pytest.raises(host.HostUpgradeError, match="altered"):
            forged.recheck_stopped()
        forged = replace(stopped, _issuer=None)
        with pytest.raises(host.HostUpgradeError, match="absent"):
            forged.recheck_stopped()


def test_supervisor_lock_held_blocks_checkpoint(installed):
    descriptor = os.open(installed.root / "state" / "supervisor-process.lock", os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(host.HostUpgradeError, match="still holds"), hold(installed):
            pytest.fail("a running supervisor cannot grant a stopped lease")
    finally:
        os.close(descriptor)


def test_hotkey_mismatch_rejected(installed):
    from tests.factories import dev_wallet

    with (
        pytest.raises(host.HostUpgradeError, match="another validator"),
        hold(installed, expected_hotkey=dev_wallet("//Bob").hotkey.ss58_address),
    ):
        pytest.fail("cross-validator recovery")


def test_changed_highwater_invalidates_lease(installed):
    with pytest.raises(ValueError, match="changed"), hold(installed) as stopped:
        write(installed.state_path, b'{"altered":true}', 0o600)
        stopped.recheck_stopped()


def test_replaced_lock_invalidates_lease(installed):
    with (
        pytest.raises(host.HostUpgradeError, match=r"changed|replaced"),
        hold(installed) as stopped,
    ):
        path = installed.root / "state" / "supervisor-process.lock"
        path.rename(path.with_suffix(".retained"))
        write(path, b'{"different":"identity"}', 0o600)
        stopped.recheck_stopped()


def test_service_restart_invalidates_lease(installed, monkeypatch):
    with pytest.raises(host.HostUpgradeError, match="not stopped"), hold(installed) as stopped:

        def running(*args):
            raise host.HostUpgradeError("exact supervisor unit is not stopped")

        monkeypatch.setattr(host, "_check_unit", running)
        stopped.recheck_stopped()


def test_exception_releases_lease_without_lifecycle_calls(installed):
    with pytest.raises(RuntimeError), hold(installed) as stopped:
        raise RuntimeError("reconciliation failed")
    assert not stopped._lease.active
    with hold(installed) as retry:
        retry.recheck_stopped()


@pytest.mark.parametrize(
    "field,value",
    [
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("MainPID", "42"),
        ("ControlPID", "42"),
        ("Id", "other.service"),
        ("LoadState", "not-found"),
        ("ExecStart", "--config /etc/umi/another.json ;"),
        ("FragmentPath", "/tmp/forged.service"),
        ("DropInPaths", "/tmp/override.conf"),
    ],
)
def test_exact_unit_binding_rejects_unsafe_state(monkeypatch, field, value):
    values = {
        "Id": "umi-validator-supervisor.service",
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ControlPID": "0",
        "User": "umi-validator",
        "ControlGroup": "",
        "DropInPaths": "",
        "FragmentPath": "/etc/systemd/system/umi-validator-supervisor.service",
        "ExecStart": "{ path=/usr/bin/env ; argv[]=x --config /etc/umi/config.json ; }",
    }
    values[field] = value
    monkeypatch.setattr(host, "_unit_snapshot", lambda unit: values)
    monkeypatch.setattr(host.pwd, "getpwnam", lambda user: SimpleNamespace(pw_uid=1001))
    monkeypatch.setattr(host, "_root_file", lambda path: None)
    monkeypatch.setattr(host, "_require_empty_cgroup", lambda *args: None)
    with pytest.raises(host.HostUpgradeError):
        host._check_unit("umi-validator-supervisor.service", Path("/etc/umi/config.json"), 1001)


def test_unit_reader_uses_only_readonly_show(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0, stdout=b"".join((key + "=\n").encode() for key in host._PROPERTIES)
        )

    monkeypatch.setattr(host.subprocess, "run", run)
    host._unit_snapshot("umi-validator-supervisor.service")
    assert calls[0][0][0:2] == ["/usr/bin/systemctl", "show"]
    assert calls[0][0][-2:] == ["--", "umi-validator-supervisor.service"]
    assert calls[0][1]["stdin"] == host.subprocess.DEVNULL
    with pytest.raises(host.HostUpgradeError):
        host._unit_snapshot("--all")
    assert len(calls) == 1


def test_descendant_cgroup_process_is_not_ignored(tmp_path, monkeypatch):
    root = tmp_path / "group"
    root.mkdir()
    (root / "cgroup.procs").write_bytes(b"")
    child = root / "child"
    child.mkdir()
    (child / "cgroup.procs").write_bytes(b"1234\n")
    original = host._open_without_links
    monkeypatch.setattr(host, "_open_without_links", lambda path: original(root))
    with pytest.raises(host.HostUpgradeError, match="still contains"):
        host._require_empty_cgroup("umi-validator-supervisor.service", "")
    (child / "cgroup.procs").write_bytes(b"")
    host._require_empty_cgroup("umi-validator-supervisor.service", "")
    with pytest.raises(host.HostUpgradeError, match="outside"):
        host._require_empty_cgroup("umi-validator-supervisor.service", "/")


def test_missing_cgroup_not_accepted_if_systemd_still_reports_it(monkeypatch):
    def missing(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(host, "_open_without_links", missing)
    host._require_empty_cgroup("umi-validator-supervisor.service", "")
    with pytest.raises(host.HostUpgradeError, match="unavailable"):
        host._require_empty_cgroup(
            "umi-validator-supervisor.service",
            "/system.slice/umi-validator-supervisor.service",
        )
