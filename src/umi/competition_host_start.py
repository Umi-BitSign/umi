"""Start one committed successor switch after the old process lock is released.

This operation reports service health only. Signed successor inputs and the
worker's own chain checks remain responsible for authorizing any weight write.
An unsuccessful start never restores the legacy executable or discards state.
"""

from __future__ import annotations

import fcntl
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass

from .competition_host_switch import (
    CommittedSuccessorServiceSwitch,
    _read_drop_in,
    recheck_committed_successor_switch,
)
from .competition_host_upgrade import (
    HostUpgradeError,
    _expected_cgroup,
    _require_empty_cgroup,
    _unit_snapshot,
)
from .competition_switch_recovery import (
    RecoveredSuccessorServiceSwitch,
    recheck_recovered_successor_switch,
)
from .competition_upgrade import _open_without_links

StartableSwitch = CommittedSuccessorServiceSwitch | RecoveredSuccessorServiceSwitch
_STARTED: dict[int, StartableSwitch] = {}


def _recheck_startable(switch: StartableSwitch) -> None:
    if type(switch) is RecoveredSuccessorServiceSwitch:
        recheck_recovered_successor_switch(switch)
    else:
        recheck_committed_successor_switch(switch, require_held=False)


def _installation(switch: StartableSwitch):
    if type(switch) is RecoveredSuccessorServiceSwitch:
        return switch.config_path, switch.lock_path, switch.lock_identity
    lease = switch._stopped._lease
    return lease.config_path, lease.lock_path, lease.lock_identity


class _StartupPending(HostUpgradeError):
    pass


def _exec_start_command(value: str) -> str:
    # systemctl's ExecStart report includes changing execution metadata after
    # the configured path, argv and ignore-errors flag. Permit only that known
    # suffix to change. Extra commands, fields or malformed reports must fail.
    match = re.fullmatch(
        r"(?P<command>\{ path=[^;\n{}]+ ; argv\[\]=[^;\n{}]+ ; ignore_errors=(?:yes|no))"
        r" ; start_time=\[[^\[\]\n]*\] ; stop_time=\[[^\[\]\n]*\]"
        r" ; pid=[0-9]+ ; code=(?:\(null\)|[A-Za-z0-9_-]+) ; status=[0-9]+/[A-Za-z0-9_+-]+ \}",
        value,
    )
    if match is None:
        raise HostUpgradeError("unexpected successor ExecStart observation")
    return match["command"]


@dataclass(frozen=True)
class SuccessorServiceStart:
    unit_name: str
    main_pid: int
    host_manifest_sha256: str
    checkpoint_sha256: str
    chain_submission_authorized: bool = False


def _systemctl(verb: str, unit: str) -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", verb, "--", unit],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=45,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode:
        raise HostUpgradeError(f"successor service {verb} failed")


def _process_owns_lock(pid: int, switch: StartableSwitch) -> None:
    _, lock_path, lock_identity = _installation(switch)
    _process_owns_exact_lock(
        pid, lock_path=lock_path, lock_identity=lock_identity, service_uid=switch.plan.service_uid
    )


def _process_owns_exact_lock(pid, *, lock_path, lock_identity, service_uid) -> None:
    """Verify kernel lock ownership without granting installation authority."""
    descriptor = _open_without_links(lock_path)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != service_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != lock_identity[:2]
        ):
            raise HostUpgradeError("successor startup process lock changed identity")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise _StartupPending("successor process has not acquired the original lock")
        # procfs descriptor links intentionally refer to the running process's
        # open files. Only stat their targets; never read wallet/file contents.
        with os.scandir(f"/proc/{pid}/fd") as entries:
            for count, entry in enumerate(entries, 1):
                if count > 4096:
                    raise HostUpgradeError("successor descriptor count exceeds its bound")
                try:
                    target = entry.stat(follow_symlinks=True)
                except FileNotFoundError:
                    continue
                if (target.st_dev, target.st_ino) == (info.st_dev, info.st_ino):
                    # An open descriptor is insufficient: even our probe has
                    # one. fdinfo must name the exclusive flock on this open
                    # file description, attributed to the main process.
                    fdinfo = os.open(
                        f"/proc/{pid}/fdinfo/{entry.name}",
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    )
                    try:
                        metadata = os.read(fdinfo, 4097)
                        if len(metadata) > 4096:
                            raise HostUpgradeError("successor lock metadata exceeds its bound")
                    finally:
                        os.close(fdinfo)
                    if _kernel_flock_matches(metadata, pid=pid, info=info):
                        return
        raise _StartupPending("successor main process does not retain the original lock")
    finally:
        os.close(descriptor)


def _kernel_flock_matches(metadata: bytes, *, pid: int, info: os.stat_result) -> bool:
    # Linux fs/locks.c: __show_fd_locks + lock_get_status. Inspect only the
    # kernel metadata for the matching inode; never read the opened file.
    # https://github.com/torvalds/linux/blob/v6.8/fs/locks.c
    for line in metadata.decode("ascii", errors="strict").splitlines():
        fields = line.split()
        if (
            len(fields) != 9
            or fields[0] != "lock:"
            or fields[2:6] != ["FLOCK", "ADVISORY", "WRITE", str(pid)]
            or fields[7:] != ["0", "EOF"]
        ):
            continue
        device = fields[6].split(":")
        if len(device) != 3:
            continue
        try:
            identity = (int(device[0], 16), int(device[1], 16), int(device[2]))
        except ValueError:
            continue
        if identity == (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino):
            return True
    return False


def _running(switch: StartableSwitch) -> int:
    unit = _unit_snapshot(switch.plan.unit_name)
    original = dict(switch._unit)
    for key in (
        "Id",
        "LoadState",
        "User",
        "FragmentPath",
        "DropInPaths",
        "ExecStart",
        "OnFailure",
        "RootDirectory",
        "RootImage",
        "Slice",
    ):
        if unit.get(key) != original.get(key):
            if key == "ExecStart" and _exec_start_command(unit[key]) == _exec_start_command(
                original[key]
            ):
                continue
            raise HostUpgradeError("started successor unit execution identity changed: " + key)
    if unit["ActiveState"] == "activating":
        raise _StartupPending("successor service is still activating")
    if (
        unit["ActiveState"] != "active"
        or unit["SubState"] != "running"
        or not unit["MainPID"].isascii()
        or not unit["MainPID"].isdigit()
        or int(unit["MainPID"]) <= 1
        or unit["ControlPID"] != "0"
        or unit["ControlGroup"] != _expected_cgroup(switch.plan.unit_name)
    ):
        raise HostUpgradeError("successor service is not running in its exact cgroup")
    pid = int(unit["MainPID"])
    _process_owns_lock(pid, switch)
    _read_drop_in(switch.plan)
    switch._tree.recheck()
    switch._anchor.recheck()
    if _unit_snapshot(switch.plan.unit_name) != unit:
        raise _StartupPending("successor main process changed during startup verification")
    return pid


def _contain_failed_start(switch: StartableSwitch) -> None:
    # The separately sealed cleanup unit can run even when activation bind
    # mounts prevent ExecStopPost from entering the main service namespace.
    _systemctl("stop", switch.plan.unit_name)
    _read_drop_in(switch.plan)
    from .competition_host_switch import _cleanup_unit

    _cleanup_unit(switch.plan, _installation(switch)[0])
    _systemctl("start", switch.plan.cleanup_unit_name)
    for name, cleanup in ((switch.plan.unit_name, False), (switch.plan.cleanup_unit_name, True)):
        unit = _unit_snapshot(name, successor_cleanup=cleanup)
        if (
            unit["ActiveState"] not in {"inactive", "failed"}
            or unit["MainPID"] != "0"
            or unit["ControlPID"] != "0"
        ):
            raise HostUpgradeError("successor failed-start cleanup did not stop all processes")
        _require_empty_cgroup(name, unit["ControlGroup"])


def start_committed_successor_service(
    switch: StartableSwitch,
) -> SuccessorServiceStart:
    """Consume this process's switch once and verify its exact running process.

    Call only after leaving hold_stopped_supervisor. A process restart requires
    durable switch recovery, which issues a separate start-only handle without
    reconstructing the legacy lease or granting checkpoint authority.
    A failed attempt remains consumed and preserves all installation evidence.
    """
    _recheck_startable(switch)
    if id(switch) in _STARTED:
        raise HostUpgradeError("successor switch already has a start attempt")
    _STARTED[id(switch)] = switch
    try:
        _systemctl("start", switch.plan.required_user_manager)
        # Recheck after the manager may have taken time to start. The writer
        # remains stopped and the closed legacy lease cannot authorize work.
        _recheck_startable(switch)
        _systemctl("start", switch.plan.unit_name)
        deadline = time.monotonic() + 30
        while True:
            try:
                pid = _running(switch)
                break
            except (_StartupPending, FileNotFoundError):
                if time.monotonic() >= deadline:
                    raise HostUpgradeError("successor startup verification timed out") from None
                time.sleep(0.25)
    except BaseException:
        try:
            _contain_failed_start(switch)
        except BaseException as cleanup_error:
            raise HostUpgradeError(
                "successor startup failed and cleanup is unconfirmed; inspect the exact unit"
            ) from cleanup_error
        raise
    return SuccessorServiceStart(
        switch.plan.unit_name, pid, switch.plan.host_manifest_sha256, switch.plan.checkpoint_sha256
    )
