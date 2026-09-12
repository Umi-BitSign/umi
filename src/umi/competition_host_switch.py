"""Publish one verified systemd successor switch while retaining the old lock.

This module never stops a running legacy service or starts a validator. The
caller must already hold a stopped-host lease and have sealed the recovery
anchor. Publication consumes that lease's legacy recovery authority. A failed
switch retains its files for explicit recovery; it never restores the old unit.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .competition_host_anchor import MaterializedSuccessorAnchor, _rename_noreplace
from .competition_host_artifacts import SignedSuccessorHostArtifact, VerifiedHostTree
from .competition_host_service import SuccessorServiceSwitchPlan, plan_successor_service_switch
from .competition_host_upgrade import (
    HostUpgradeError,
    StoppedSupervisor,
    _bind_successor_handoff,
    _consume_stopped_lease_for_successor,
    _require_empty_cgroup,
    _require_root_linux,
    _root_file,
    _stopped_binding,
    _successor_handoff_matches,
    _unit_snapshot,
)
from .competition_upgrade import _fingerprint, _open_without_links

_ISSUER = object()


def _root_owner_uid() -> int:
    return 0


@dataclass(frozen=True, slots=True)
class CommittedSuccessorServiceSwitch:
    plan: SuccessorServiceSwitchPlan
    _stopped: StoppedSupervisor = field(repr=False, compare=False)
    _anchor: MaterializedSuccessorAnchor = field(repr=False, compare=False)
    _tree: VerifiedHostTree = field(repr=False, compare=False)
    _unit: tuple[tuple[str, str], ...] = field(repr=False, compare=False)
    _cleanup_unit: tuple[tuple[str, str], ...] = field(repr=False, compare=False)
    _intent: bytes = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _read_drop_in(plan: SuccessorServiceSwitchPlan) -> None:
    from .competition_switch_recovery import (
        INTENT_FILENAME,
        RETAINED_DIRECTORY,
        read_switch_intent,
    )

    parent = _root_directory(plan.drop_in_path.parent)
    try:
        names = set(os.listdir(parent))
        if (
            plan.drop_in_path.name not in names
            or not names <= {plan.drop_in_path.name, INTENT_FILENAME, RETAINED_DIRECTORY}
            or (RETAINED_DIRECTORY in names and INTENT_FILENAME not in names)
        ):
            raise HostUpgradeError("successor unit has unexpected drop-in files")
        if INTENT_FILENAME in names:
            read_switch_intent(plan)
        if RETAINED_DIRECTORY in names:
            retained = _root_directory(plan.drop_in_path.parent / RETAINED_DIRECTORY)
            os.close(retained)
    finally:
        os.close(parent)
    _read_control(plan.drop_in_path, plan.drop_in_bytes, plan.drop_in_sha256)
    _read_control(plan.cleanup_unit_path, plan.cleanup_unit_bytes, plan.cleanup_unit_sha256)


def _read_control(path: Path, payload: bytes, expected_sha256: str) -> None:
    parent = _root_directory(path.parent)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != _root_owner_uid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_size != len(payload)
            or len(payload) > 128 * 1024
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise HostUpgradeError("successor drop-in is not the exact sealed control file")
        data = bytearray()
        while len(data) <= before.st_size:
            part = os.read(descriptor, before.st_size + 1 - len(data))
            if not part:
                break
            data.extend(part)
        if bytes(data) != payload or _fingerprint(before) != _fingerprint(os.fstat(descriptor)):
            raise HostUpgradeError("successor drop-in changed during verification")
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if _fingerprint(named) != _fingerprint(before):
            raise HostUpgradeError("successor drop-in was replaced")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _root_directory(path: Path) -> int:
    # Check each ancestor; O_NOFOLLOW on the final path alone is insufficient.
    for item in (*reversed(path.parents), path):
        descriptor = (
            os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            if item == Path("/")
            else _open_without_links(item)
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _root_owner_uid()
            or info.st_mode & 0o022
        ):
            os.close(descriptor)
            raise HostUpgradeError("successor systemd parent is not root-controlled")
        if item == path:
            return descriptor
        os.close(descriptor)
    raise HostUpgradeError("successor systemd parent is unavailable")


def _create_switch_marker(plan: SuccessorServiceSwitchPlan) -> int:
    """Persist the legacy-recovery fence before writing any successor bytes."""
    root = _root_directory(plan.drop_in_path.parent.parent)
    try:
        os.mkdir(plan.drop_in_path.parent.name, 0o755, dir_fd=root)
        os.fsync(root)
        parent = _root_directory(plan.drop_in_path.parent)
        try:
            os.fchmod(parent, 0o755)
            os.fsync(parent)
            if os.listdir(parent):
                raise HostUpgradeError("successor switch marker is not empty")
        except BaseException:
            os.close(parent)
            raise
        return parent
    finally:
        os.close(root)


def _check_switch_marker(plan: SuccessorServiceSwitchPlan, marker: int) -> None:
    current = _root_directory(plan.drop_in_path.parent)
    try:
        expected, actual = os.fstat(marker), os.fstat(current)
        if (
            (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino)
            or not stat.S_ISDIR(expected.st_mode)
            or expected.st_uid != _root_owner_uid()
            or stat.S_IMODE(expected.st_mode) != 0o755
        ):
            raise HostUpgradeError("successor switch marker was replaced or changed")
    finally:
        os.close(current)


def _write_drop_in_once(plan: SuccessorServiceSwitchPlan, marker: int) -> None:
    from .competition_switch_recovery import INTENT_FILENAME, RETAINED_DIRECTORY

    _check_switch_marker(plan, marker)
    parent, descriptor = marker, -1
    try:
        original_names = set(os.listdir(parent))
        if not original_names <= {INTENT_FILENAME, RETAINED_DIRECTORY}:
            raise HostUpgradeError("successor switch marker already contains retained files")
        stage = ".umi-successor-" + secrets.token_hex(16)
        descriptor = os.open(
            stage,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        remaining = memoryview(plan.drop_in_bytes)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise HostUpgradeError("successor drop-in write made no progress")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        if set(os.listdir(parent)) != original_names | {stage}:
            raise HostUpgradeError("successor drop-in parent changed during publication")
        _rename_noreplace(parent, stage, plan.drop_in_path.name)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _check_switch_marker(plan, marker)
    _read_drop_in(plan)


def _write_cleanup_once(plan: SuccessorServiceSwitchPlan) -> None:
    parent = _root_directory(plan.cleanup_unit_path.parent)
    descriptor = -1
    try:
        stage = ".umi-cleanup-" + secrets.token_hex(16)
        descriptor = os.open(
            stage,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        remaining = memoryview(plan.cleanup_unit_bytes)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise HostUpgradeError("successor cleanup-unit write made no progress")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        _rename_noreplace(parent, stage, plan.cleanup_unit_path.name)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
    _read_control(plan.cleanup_unit_path, plan.cleanup_unit_bytes, plan.cleanup_unit_sha256)


def _reload_systemd() -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", "daemon-reload"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode != 0:
        raise HostUpgradeError("systemd successor reload failed; retain stopped installation")


def _lock_and_originals(stopped: StoppedSupervisor, *, require_held: bool) -> None:
    if type(stopped) is not StoppedSupervisor or stopped._binding != _stopped_binding(stopped):
        raise HostUpgradeError("successor switch has an altered stopped installation")
    lease = stopped._lease
    if require_held:
        if not lease.active or _fingerprint(os.fstat(lease.lock_fd)) != lease.lock_identity:
            raise HostUpgradeError("successor switch lost its original process lock")
    elif lease.active:
        raise HostUpgradeError("successor source switch still holds the original lock")
    descriptor = _open_without_links(lease.lock_path)
    try:
        if _fingerprint(os.fstat(descriptor)) != lease.lock_identity:
            raise HostUpgradeError("successor source switch process lock was replaced")
    finally:
        os.close(descriptor)
    lease.reader.unchanged()


def _switched_unit(stopped: StoppedSupervisor, plan: SuccessorServiceSwitchPlan):
    values = _unit_snapshot(plan.unit_name)
    original = stopped._lease.unit_snapshot
    if (
        values["Id"] != plan.unit_name
        or values["LoadState"] != "loaded"
        or values["ActiveState"] not in {"inactive", "failed"}
        or values["SubState"] not in {"dead", "failed"}
        or values["MainPID"] != "0"
        or values["ControlPID"] != "0"
        or values["User"] != original["User"]
        or values["FragmentPath"] != original["FragmentPath"]
        or values["DropInPaths"] != str(plan.drop_in_path)
        or values.get("OnFailure") != plan.cleanup_unit_name
        or (
            str(plan.host_root)
            + "/.venv/bin/umi-competition-supervisor --config "
            + str(stopped._lease.config_path)
            + " ;"
        )
        not in values["ExecStart"]
    ):
        raise HostUpgradeError("reloaded successor unit does not match the exact stopped switch")
    _root_file(Path(values["FragmentPath"]))
    _require_empty_cgroup(plan.unit_name, values["ControlGroup"])
    return values


def _cleanup_unit(plan: SuccessorServiceSwitchPlan, config_path: Path):
    values = _unit_snapshot(plan.cleanup_unit_name, successor_cleanup=True)
    if (
        values["Id"] != plan.cleanup_unit_name
        or values["LoadState"] != "loaded"
        or values["ActiveState"] not in {"inactive", "failed"}
        or values["SubState"] not in {"dead", "failed"}
        or values["MainPID"] != "0"
        or values["ControlPID"] != "0"
        or values["User"] != plan.service_user
        or values["FragmentPath"] != str(plan.cleanup_unit_path)
        or values["DropInPaths"] != ""
        or values.get("OnFailure") != ""
        or (
            str(plan.host_root)
            + "/.venv/bin/umi-competition-supervisor-cleanup --config "
            + str(config_path)
            + " ;"
        )
        not in values["ExecStart"]
    ):
        raise HostUpgradeError("reloaded successor cleanup unit differs from the exact plan")
    _require_empty_cgroup(plan.cleanup_unit_name, values["ControlGroup"])
    return values


def _binding(result: CommittedSuccessorServiceSwitch) -> str:
    from .protocol import canonical_json_bytes

    values = {name: str(getattr(result.plan, name)) for name in result.plan.__dataclass_fields__}
    values["unit"] = str(result._unit)
    values["cleanup_unit"] = str(result._cleanup_unit)
    values["installation"] = result._stopped.installation_sha256
    values["anchor"] = result._anchor.receipt.checkpoint_sha256
    values["host"] = result._tree.manifest_sha256
    values["intent"] = hashlib.sha256(result._intent).hexdigest()
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def commit_successor_service_switch(
    *,
    stopped: StoppedSupervisor,
    anchor: MaterializedSuccessorAnchor,
    host_tree: VerifiedHostTree,
    signed_host: SignedSuccessorHostArtifact,
) -> CommittedSuccessorServiceSwitch:
    """Install/reload the exact override; leave the service stopped and lock held.

    No generic unit, command, user, path or mutable plan can be supplied. This
    must run only after the new host and service sandbox have passed rehearsal.
    Source publication alone does not establish launch or chain-write readiness.
    """
    _require_root_linux()
    plan = plan_successor_service_switch(
        stopped=stopped, anchor=anchor, host_tree=host_tree, signed_host=signed_host
    )
    from .competition_switch_recovery import _intent_bytes, publish_switch_intent

    intent = _intent_bytes(stopped, anchor, plan)
    # Consume legacy recovery authority before the first mutation. An interrupted
    # publication must not be reused to mint another legacy checkpoint.
    _consume_stopped_lease_for_successor(stopped)
    # _check_unit rejects this exact directory even before systemd has loaded
    # any files. Its durable presence survives loss of the process registry.
    marker = publish_switch_intent(plan, intent)
    try:
        _write_cleanup_once(plan)
        _write_drop_in_once(plan, marker)
    finally:
        os.close(marker)
    _lock_and_originals(stopped, require_held=True)
    if _unit_snapshot(plan.unit_name) != stopped._lease.unit_snapshot:
        raise HostUpgradeError("stopped unit changed before successor reload")
    _require_empty_cgroup(plan.unit_name, stopped._lease.unit_snapshot["ControlGroup"])
    anchor.recheck()
    host_tree.recheck()
    _reload_systemd()
    _lock_and_originals(stopped, require_held=True)
    _read_drop_in(plan)
    snapshot = _switched_unit(stopped, plan)
    cleanup_snapshot = _cleanup_unit(plan, stopped._lease.config_path)
    anchor.recheck()
    host_tree.recheck()
    result = CommittedSuccessorServiceSwitch(
        plan,
        stopped,
        anchor,
        host_tree,
        tuple(sorted(snapshot.items())),
        tuple(sorted(cleanup_snapshot.items())),
        intent,
        _ISSUER,
    )
    object.__setattr__(result, "_binding", _binding(result))
    _bind_successor_handoff(stopped, result)
    recheck_committed_successor_switch(result, require_held=True)
    return result


def recheck_committed_successor_switch(
    result: CommittedSuccessorServiceSwitch, *, require_held: bool
) -> None:
    _require_root_linux()
    if (
        type(result) is not CommittedSuccessorServiceSwitch
        or result._issuer is not _ISSUER
        or result._stopped._lease.successor_handoff is not result
        or not _successor_handoff_matches(result._stopped, result)
        or result._binding != _binding(result)
    ):
        raise HostUpgradeError("successor switch was not committed by this process")
    _lock_and_originals(result._stopped, require_held=require_held)
    _read_drop_in(result.plan)
    from .competition_switch_recovery import read_switch_intent

    if read_switch_intent(result.plan) != result._intent:
        raise HostUpgradeError("committed successor switch intent changed")
    if tuple(sorted(_switched_unit(result._stopped, result.plan).items())) != result._unit:
        raise HostUpgradeError("stopped successor unit changed after source switch")
    if (
        tuple(sorted(_cleanup_unit(result.plan, result._stopped._lease.config_path).items()))
        != result._cleanup_unit
    ):
        raise HostUpgradeError("successor cleanup unit changed after source switch")
    result._anchor.recheck()
    result._tree.recheck()
