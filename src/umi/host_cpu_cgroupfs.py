"""Explicit cgroupfs layout for prospectively selected CPU measurements.

The caller has already authenticated C8 CPU timing and owns the existing native
slot lease. C7 keeps its original command and systemd path reader unchanged.
"""

import json
import re
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")
CID = re.compile(r"[0-9a-f]{64}\Z")


def _absolute(value):
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("invalid CPU cgroup path")
    path = Path(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ValueError("CPU cgroup path must be exact and absolute")
    return path


def podman_parent_argument(owned_parent, *, cgroup_root=CGROUP_ROOT):
    path = _absolute(owned_parent)
    relative = path.relative_to(cgroup_root)
    if len(relative.parts) < 2:
        raise ValueError("CPU parent must be a scoped delegated descendant")
    # OCI cgroupfs paths are absolute within the cgroup mount, not host paths
    # prefixed by /sys/fs/cgroup a second time.
    return "/" + str(relative)


def timed_podman_prefix():
    return ("/usr/bin/podman", "--cgroup-manager=cgroupfs")


def cgroupfs_payload_directory(raw, *, container_id, name, owned_parent):
    """Exact inspect-to-kernel binding for Podman4.9.3/crun1.14.1 cgroupfs."""
    if CID.fullmatch(container_id) is None or len(raw) > 65536:
        raise ValueError("invalid bounded CPU container identity")
    records = json.loads(raw)
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise ValueError("inspection must identify exactly one CPU invocation")
    record = records[0]
    if record.get("Id") != container_id or record.get("Name") not in {name, "/" + name}:
        raise ValueError("inspection differs from retained CPU invocation")
    state = record.get("State", {})
    if not isinstance(state, dict):
        raise ValueError("inspection has an invalid container state")
    if state.get("Running") is not True or not state.get("CgroupPath"):
        return None
    observed = _absolute(state["CgroupPath"])
    if not observed.is_relative_to(CGROUP_ROOT):
        observed = CGROUP_ROOT / str(observed).lstrip("/")
    expected = _absolute(owned_parent) / ("libpod-" + container_id)
    if observed != expected:
        raise ValueError("CPU payload is outside its exact delegated slot")
    # cgroupfs does NOT use libpod-ID.scope/container. Native fd/type/resource
    # readback and existing shared lease ownership follow this path resolution.
    return observed
