"""Opt-in root filesystem crash tests in the wallet-free rehearsal VM.

These publish only beneath the dedicated /var/lib fixture directory. They do
not install units under /etc, use wallets or call systemd lifecycle commands.
"""

from __future__ import annotations

import os
import sys

import pytest

from tests.test_competition_host_service import case as case
from tests.test_competition_host_switch_linux import files as files
from umi import competition_host_switch as switch
from umi import competition_switch_recovery as recovery
from umi.protocol import canonical_json_bytes

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_SERVICE_REHEARSAL") != "1",
    reason="requires root opt-in in the wallet-free rehearsal VM",
)


def intent(plan):
    return canonical_json_bytes(
        recovery.SuccessorSwitchIntent(
            schema="umi-successor-service-switch-intent/1",
            unit_name=plan.unit_name,
            config_path="/etc/umi/validator-supervisor.json",
            service_uid=1001,
            config_sha256="11" * 32,
            installation_sha256="22" * 32,
            anchor_receipt_sha256="33" * 32,
            host_manifest_sha256=plan.host_manifest_sha256,
            plan_sha256=recovery._plan_sha256(plan),
            fragment_sha256="44" * 32,
            original_unit={},
            lock_device="1",
            lock_inode="2",
        )
    )


@pytest.mark.parametrize("boundary", ["before_rename", "after_rename", "after_return"])
def test_process_death_never_exposes_a_marker_without_complete_intent(files, boundary):
    payload = intent(files)
    pid = os.fork()
    if pid == 0:
        original = recovery._rename_noreplace

        def crash(parent, source, destination, **kwargs):
            if boundary == "before_rename":
                os._exit(77)
            original(parent, source, destination, **kwargs)
            if boundary == "after_rename":
                os._exit(77)

        recovery._rename_noreplace = crash
        recovery.publish_switch_intent(files, payload)
        os._exit(77)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    if boundary == "before_rename":
        assert not files.drop_in_path.parent.exists()
        marker = recovery.publish_switch_intent(files, payload)
        os.close(marker)
    assert recovery.read_switch_intent(files) == payload
    assert not files.cleanup_unit_path.exists() and not files.drop_in_path.exists()
    with pytest.raises(ValueError, match="already exists"):
        recovery.publish_switch_intent(files, payload)
    assert recovery.read_switch_intent(files) == payload


def test_real_root_partial_preservation_and_idempotent_reads(files):
    payload = intent(files)
    marker = recovery.publish_switch_intent(files, payload)
    try:
        partial = files.drop_in_path.parent / (".umi-successor-" + "aa" * 16)
        partial.write_bytes(b"unfinished bytes")
        partial.chmod(0o600)
        inode = partial.stat().st_ino
        recovery._retain_partial_files(files, marker)
        retained = partial.parent / recovery.RETAINED_DIRECTORY / partial.name
        assert retained.stat().st_ino == inode and retained.read_bytes() == b"unfinished bytes"
        switch._write_cleanup_once(files)
        switch._write_drop_in_once(files, marker)
        switch._read_drop_in(files)
        recovery._retain_partial_files(files, marker)
        assert recovery.read_switch_intent(files) == payload
        assert not partial.exists()
    finally:
        os.close(marker)


@pytest.mark.parametrize("change", ["writable", "hardlink", "symlink"])
def test_actual_root_intent_permissions_and_link_checks(files, change):
    marker = recovery.publish_switch_intent(files, intent(files))
    os.close(marker)
    path = files.drop_in_path.parent / recovery.INTENT_FILENAME
    if change == "writable":
        path.chmod(0o644)
    elif change == "hardlink":
        os.link(path, path.with_name("retained-hardlink"))
    else:
        saved = path.with_name("retained-original")
        path.rename(saved)
        path.symlink_to(saved)
    with pytest.raises((ValueError, OSError)):
        recovery.read_switch_intent(files)


def test_upgrade_mutex_excludes_other_process_and_survives_crashed_owner(files, monkeypatch):
    mutex_root = files.cleanup_unit_path.parent / "operator-locks"
    monkeypatch.setattr(recovery, "_UPGRADE_LOCK_ROOT", mutex_root)
    unit = files.unit_name
    with recovery.exclusive_upgrade_operation(unit):
        pid = os.fork()
        if pid == 0:
            try:
                with recovery.exclusive_upgrade_operation(unit):
                    os._exit(1)
            except ValueError as error:
                os._exit(0 if "another upgrade operation" in str(error) else 2)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
    inode = (mutex_root / (unit + ".lock")).stat().st_ino
    pid = os.fork()
    if pid == 0:
        with recovery.exclusive_upgrade_operation(unit):
            os._exit(77)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    with recovery.exclusive_upgrade_operation(unit):
        assert (mutex_root / (unit + ".lock")).stat().st_ino == inode
