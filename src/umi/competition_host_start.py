"""Start one committed successor switch after the old process lock is released.

This operation reports service health only. Signed successor inputs and the
worker's own chain checks remain responsible for authorizing any weight write.
An unsuccessful start never restores the legacy executable or discards state.
"""

from __future__ import annotations

import fcntl
import os
import stat
import subprocess
import time
from dataclasses import dataclass

from .competition_host_switch import (
    CommittedSuccessorServiceSwitch,
    _read_drop_in,
    recheck_committed_successor_switch,
)
from .competition_host_upgrade import HostUpgradeError, _require_empty_cgroup, _unit_snapshot
from .competition_upgrade import _open_without_links

_STARTED: dict[int, CommittedSuccessorServiceSwitch] = {}


class _StartupPending(HostUpgradeError):
    pass


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


def _process_owns_lock(pid: int, switch: CommittedSuccessorServiceSwitch) -> None:
    lease = switch._stopped._lease
    descriptor = _open_without_links(lease.lock_path)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != switch.plan.service_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != lease.lock_identity[:2]
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
                    return
        raise _StartupPending("successor main process does not retain the original lock")
    finally:
        os.close(descriptor)


def _running(switch: CommittedSuccessorServiceSwitch) -> int:
    unit = _unit_snapshot(switch.plan.unit_name)
    original = dict(switch._unit)
    for key in ("Id", "LoadState", "User", "FragmentPath", "DropInPaths", "ExecStart", "OnFailure"):
        if unit[key] != original[key]:
            raise HostUpgradeError("started successor unit execution identity changed")
    if unit["ActiveState"] == "activating":
        raise _StartupPending("successor service is still activating")
    if (
        unit["ActiveState"] != "active"
        or unit["SubState"] != "running"
        or not unit["MainPID"].isascii()
        or not unit["MainPID"].isdigit()
        or int(unit["MainPID"]) <= 1
        or unit["ControlPID"] != "0"
        or unit["ControlGroup"] != "/system.slice/" + switch.plan.unit_name
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


def _contain_failed_start(switch: CommittedSuccessorServiceSwitch) -> None:
    # The separately sealed cleanup unit can run even when activation bind
    # mounts prevent ExecStopPost from entering the main service namespace.
    _systemctl("stop", switch.plan.unit_name)
    _read_drop_in(switch.plan)
    from .competition_host_switch import _cleanup_unit

    _cleanup_unit(switch.plan, switch._stopped._lease.config_path)
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
    switch: CommittedSuccessorServiceSwitch,
) -> SuccessorServiceStart:
    """Consume this process's switch once and verify its exact running process.

    Call only after leaving hold_stopped_supervisor. A process restart requires
    durable switch recovery, not reconstruction of this in-memory capability.
    A failed attempt remains consumed and preserves all installation evidence.
    """
    recheck_committed_successor_switch(switch, require_held=False)
    if id(switch) in _STARTED:
        raise HostUpgradeError("successor switch already has a start attempt")
    _STARTED[id(switch)] = switch
    try:
        _systemctl("start", switch.plan.required_user_manager)
        # Recheck after the manager may have taken time to start. The writer
        # remains stopped and the closed legacy lease cannot authorize work.
        recheck_committed_successor_switch(switch, require_held=False)
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
