"""Authenticate the loaded stopped writer's original root service controls."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from .competition_host_activation import _read_root_control_path
from .competition_host_upgrade import _check_service_namespace
from .competition_upgrade import _fingerprint
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    parse_canonical_validator_supervisor_config,
)

SYSTEMD_ROOTS = (Path("/etc/systemd/system"), Path("/run/systemd/system"))
_MODES = {0o400, 0o440, 0o444, 0o600, 0o640, 0o644}


def _needs_daemon_reload(unit):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", "--property=NeedDaemonReload", "--value", unit],
        check=True,
        capture_output=True,
        timeout=20,
    )
    if result.stdout.strip() not in {b"yes", b"no"}:
        raise ValueError("writer loaded service state is unavailable")
    return result.stdout.strip() == b"yes"


def _control(path, maximum):
    before = path.lstat()
    raw = _read_root_control_path(path, maximum, modes=_MODES)
    after = path.lstat()
    if _fingerprint(before) != _fingerprint(after):
        raise ValueError("writer root service control changed during inspection")
    return raw, (
        str(path),
        tuple(str(value) for value in _fingerprint(after)),
        hashlib.sha256(raw).hexdigest(),
    )


def authenticate_writer_service(anchor, unit, config_path, values):
    """Pin complete root control bytes, config identity and loaded overrides.

    This authenticates a stopped installed selection. It does not approve a new
    command, clear an approval hold, or grant directory selection authority.
    """
    config_path = Path(config_path)
    if _needs_daemon_reload(unit):
        raise ValueError("writer service has pending same-path control changes")
    layout = _check_service_namespace(unit, values)
    if any(character.isspace() for character in str(config_path)):
        raise ValueError("writer service config path is ambiguous")
    configured = re.findall(r"(?:^|\s)--config\s+(\S+)", values["ExecStart"])
    if configured != [str(config_path)]:
        raise ValueError("writer service does not select the exact installed config")
    raw, config_control = _control(config_path, MAX_SUPERVISOR_DOCUMENT_BYTES)
    if parse_canonical_validator_supervisor_config(raw) != anchor.config:
        raise ValueError("writer service config differs from native startup ownership")
    expected = layout.fragment if layout else SYSTEMD_ROOTS[0] / unit
    fragment = Path(values["FragmentPath"])
    if fragment != expected:
        raise ValueError("writer service fragment differs from its installed unit")
    controls = [config_control, _control(fragment, 65536)[1]]
    paths = tuple(Path(value) for value in values["DropInPaths"].split())
    if len(paths) > 64 or len(set(paths)) != len(paths):
        raise ValueError("writer service overrides are ambiguous")
    for path in paths:
        if path.suffix != ".conf" or not any(path.is_relative_to(root) for root in SYSTEMD_ROOTS):
            raise ValueError("writer service override is outside supported root controls")
        controls.append(_control(path, 65536)[1])
    names = {unit, "service"}
    if layout:
        names.add(layout.fragment.name)
    # Include template and shared dashed-name drop-ins supported by systemd.
    for name in tuple(names):
        if "@" in name:
            names.add(name.split("@", 1)[0] + "@.service")
        stem = name.removesuffix(".service")
        for index, character in enumerate(stem):
            if character == "-":
                names.add(stem[: index + 1] + ".service")
    loaded = set(paths)
    for root in SYSTEMD_ROOTS:
        for name in names:
            directory = root / (name + ".d")
            if not directory.exists():
                if directory.is_symlink():
                    raise ValueError("writer service override directory is dangling")
                continue
            entries = tuple(directory.iterdir())
            if len(entries) > 128 or any(
                path.suffix == ".conf" and path not in loaded for path in entries
            ):
                raise ValueError("writer service has an unloaded or unexamined override")
    if _needs_daemon_reload(unit):
        raise ValueError("writer service controls changed after the loaded selection")
    return tuple(controls)
