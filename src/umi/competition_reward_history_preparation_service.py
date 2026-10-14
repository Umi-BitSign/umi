"""Read-only stopped-state check for an isolated root preparation service."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

from .competition_host_start import _exec_start_command
from .competition_host_upgrade import _require_empty_cgroup_path
from .competition_reward_writer_service import _control, _needs_daemon_reload

_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "User",
    "FragmentPath",
    "ExecStart",
    "DropInPaths",
    "RootDirectory",
    "RootImage",
    "Slice",
)


def _snapshot(unit):
    if not re.fullmatch(r"umi-[a-z0-9][a-z0-9-]{1,120}\.service", unit):
        raise ValueError("capacity migration requires an exact preparation unit")
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=" + ",".join(_PROPERTIES),
            "--",
            unit,
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if len(result.stdout) > 128 * 1024:
        raise ValueError("preparation service observation exceeds its bound")
    values = {}
    for line in result.stdout.decode("utf-8", errors="strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in _PROPERTIES or key in values:
            raise ValueError("preparation service observation differs")
        values[key] = value
    if set(values) != set(_PROPERTIES):
        raise ValueError("preparation service observation is incomplete")
    return values


def stopped_preparation_service(unit, *, installed_unit, config_path, python_path, choices):
    """Require this actual native preparation command to have no surviving process."""
    values = _snapshot(unit)
    if (
        values["Id"] != unit
        or values["LoadState"] != "loaded"
        or values["ActiveState"] not in {"inactive", "failed"}
        or values["SubState"] not in {"dead", "failed"}
        or values["MainPID"] != "0"
        or values["ControlPID"] != "0"
        or values["User"] not in {"root", "0"}
        or values["RootDirectory"]
        or values["RootImage"]
        or values["Slice"] != "system.slice"
        or _needs_daemon_reload(unit)
    ):
        raise ValueError("capacity migration requires its stopped root preparation service")
    command = _exec_start_command(values["ExecStart"])
    argv = shlex.split(command.split(" ; argv[]=", 1)[1].rsplit(" ; ignore_errors=", 1)[0])
    if (
        not argv
        or not os.path.isabs(argv[0])
        or argv[0] != str(python_path)
        or command.split(" ; argv[]=", 1)[0] != "{ path=" + str(python_path)
    ):
        raise ValueError("preparation command interpreter differs")
    expected = [
        [
            argv[0],
            "-B",
            "-m",
            "umi.competition_reward_history_preparation_cli",
            "replay",
            "--unit",
            installed_unit,
            "--config",
            str(config_path),
            "--standing-boot",
            str(boot),
            "--approval",
            str(approval),
            "--launch",
            str(launch),
        ]
        for boot, approval, launch in choices
    ]
    if argv not in expected:
        raise ValueError("stopped service does not select this preparation scope")
    fragment = Path(values["FragmentPath"])
    if fragment != Path("/etc/systemd/system") / unit:
        raise ValueError("preparation fragment is outside its exact installed unit")
    paths = tuple(Path(value) for value in values["DropInPaths"].split())
    if len(paths) > 64 or len(set(paths)) != len(paths):
        raise ValueError("preparation service overrides are ambiguous")
    controls = [_control(fragment, 65536)[1]]
    for path in paths:
        if path.suffix != ".conf" or not any(
            path.is_relative_to(root)
            for root in (Path("/etc/systemd/system"), Path("/run/systemd/system"))
        ):
            raise ValueError("preparation override is outside system controls")
        controls.append(_control(path, 65536)[1])
    _require_empty_cgroup_path("/system.slice/" + unit, values["ControlGroup"])
    if _needs_daemon_reload(unit):
        raise ValueError("preparation loaded controls changed")
    return command, tuple(controls)
