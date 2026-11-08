"""Kernel witnesses for graph grants sharing one enforced service ceiling.

Each slot uses a distinct existing cgroup control-file inode. Model witnesses
use directory inodes, so older /2 readers keep their full conservative charge
without mistaking these for model containers or duplicate bindings. No cgroup
files are created or changed. The witness and held file descriptor die with the
native lease. Only bounded native graph grants publish this witness.
"""

import os
import stat
from pathlib import Path

from . import host_memory_peer

# Stable prefixes permit additive policy slots. Unsupported/missing files keep
# the historical full reservation. These are witnesses, not memory samples.
_FILES = (
    "memory.current",
    "memory.max",
    "memory.events",
    "memory.stat",
    "memory.low",
    "memory.high",
    "memory.min",
    "memory.swap.max",
    "memory.swap.current",
    "memory.pressure",
    "memory.peak",
    "memory.swap.events",
)


def _marker(policy, slot):
    index = next(i for i, item in enumerate(policy.slots) if item.name == slot.name)
    return _FILES[index] if index < len(_FILES) else None


def _membership(pid):
    with Path(f"/proc/{pid}/cgroup").open("rb") as stream:
        raw = stream.read(4097).decode("ascii").strip()
    if len(raw) > 4096 or not raw.startswith("0::/") or "\n" in raw:
        raise ValueError("graph witness requires unified cgroup membership")
    relative = Path(raw[4:])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("graph witness has invalid cgroup membership")
    return Path("/sys/fs/cgroup") / relative


def _operator_controlled(root, name):
    info = os.stat(name, dir_fd=root, follow_symlinks=False)
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022


def _open_group(pid, marker, maximum):
    from .host_memory_admission import (
        _FILE_FLAGS,
        _cgroup_value,
        _open_cgroup_directory,
        _require_cgroup2,
    )

    root = file = None
    try:
        path = _membership(pid)
        root = _open_cgroup_directory(path)
        _require_cgroup2(root)
        # Limits must be operator-owned. A delegated sandbox cannot enlarge
        # the ceiling on which an independent reader bases its shared charge.
        for name in ("memory.max", "memory.swap.max"):
            if not _operator_controlled(root, name):
                raise ValueError("graph service ceiling is not operator controlled")
        cap = _cgroup_value(root, "memory.max")
        if not cap.isdecimal() or not 0 < int(cap) <= maximum:
            raise ValueError("graph service ceiling exceeds its selected budget")
        if _cgroup_value(root, "memory.swap.max") != "0":
            raise ValueError("graph service swap is not bounded to zero")
        file = os.open(marker, _FILE_FLAGS, dir_fd=root)
        info, group = os.fstat(file), os.fstat(root)
        if not stat.S_ISREG(info.st_mode) or info.st_dev != group.st_dev:
            raise ValueError("graph marker is outside its kernel cgroup")
        if _membership(pid) != path:
            raise ValueError("graph lease owner changed cgroup")
        result = ((group.st_dev, group.st_ino), int(cap), info.st_ino, root, file)
        root = file = None
        return result
    finally:
        for descriptor in (file, root):
            if descriptor is not None:
                os.close(descriptor)


def close(binding):
    if binding is not None:
        os.close(binding[4])
        os.close(binding[3])


def own_binding(controller, slot):
    marker = _marker(controller.policy, slot)
    budget = controller.startup_reservation_bytes
    if not controller.peer_execution_stage or budget is None or marker is None:
        return None
    try:
        return _open_group(os.getpid(), marker, budget)
    except (OSError, ValueError):
        return None


def share_retained(controller, parent):
    """Keep an already admitted settlement ceiling alive for local graph work.

    Each operation owns duplicated descriptors, including the cohort marker
    and settlement gate. The kernel releases capacity only after the final
    owner drains. Models and exports always acquire their separate slots.
    """
    from .host_memory_admission import HostMemoryLease

    if not controller.peer_execution_stage:
        return None
    for owner in tuple(controller._model_leases):
        if (
            owner.closed
            or owner._creator_pid != os.getpid()
            or owner.slot.lane != "settlement_retained"
            or not owner.service_bounded
            or owner._graph_binding is None
        ):
            continue
        binding = own_binding(controller, owner.slot)
        descriptor = probe = None
        group = []
        try:
            probe = controller._open_slot(parent, owner.slot)
            if (
                binding is None
                or binding[1] > owner.slot.reservation_bytes
                or binding[:3] != owner._graph_binding[:3]
                or host_memory_peer.observed_inode(probe) != binding[2]
            ):
                continue
            # dup retains the same flock and OFD witness, rather than opening a
            # new reservation. Graph close must leave that witness to the final
            # descriptor's kernel lifetime, including forked/borrowed owners.
            descriptor = os.dup(owner._descriptor)
            for held in owner._group:
                group.append(os.dup(held))
            lease = HostMemoryLease(descriptor, owner.slot, group=group)
            descriptor, group = None, []
            lease._graph_binding, binding = binding, None
            lease._peer_witness = True
            lease.service_bounded = True
            controller._model_leases.add(lease)
            controller.last_model_admission = dict(
                shared_retained_graph_slot=owner.slot.name,
                shared_service_ceiling_bytes=lease._graph_binding[1],
                additional_reservation_bytes=0,
            )
            return lease
        finally:
            close(binding)
            for held in [probe, descriptor, *group]:
                if held is not None:
                    os.close(held)
    return None


def _lock_owners():
    # /proc/locks supplies the native flock owner. PIDs alone never establish
    # graph ownership: callers also match the exact live OFD inode witness.
    with Path("/proc/locks").open("rb") as stream:
        raw = stream.read(1024**2 + 1)
    if len(raw) > 1024**2:
        raise ValueError("graph lease inventory exceeds its bound")
    result, ambiguous = {}, set()
    for line in raw.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) != 8 or fields[1:4] != ["FLOCK", "ADVISORY", "WRITE"]:
            continue
        pid = int(fields[4])
        if pid <= 0 or fields[6:] != ["0", "EOF"]:
            continue
        major, minor, inode = fields[5].split(":")
        key = (os.makedev(int(major, 16), int(minor, 16)), int(inode))
        if key in ambiguous:
            continue
        if key in result:
            # /proc/locks is sampled while unrelated locks change. An
            # ambiguous inode cannot establish ownership, but must not erase
            # independent witnessed reservations elsewhere on the host.
            result.pop(key)
            ambiguous.add(key)
            continue
        result[key] = pid
    return result


def discount(controller, parent, busy, *, selected=None, selected_bytes=0):
    """Return only duplicate graph charges proven under one kernel hard cap.

    No resident pages are credited. Missing/incompatible markers and old hosts
    retain full slot charges. Model/container grants remain separate. The native
    transaction prevents another acquisition from replacing a sampled lease.
    """
    if not controller.peer_execution_stage or not busy:
        return 0
    try:
        owners = _lock_owners()
    except (OSError, ValueError):
        return 0
    groups = {}
    if selected is not None:
        groups[selected[0]] = [selected[1], selected_bytes]
    maximum = max(s.reservation_bytes for s in controller.policy.slots if s.lane == "transient")
    for slot in controller.policy.slots:
        key = (slot.device, slot.inode)
        marker = _marker(controller.policy, slot)
        if key not in busy or key not in owners or marker is None:
            continue
        descriptor = binding = None
        try:
            descriptor = controller._open_slot(parent, slot)
            witness = host_memory_peer.observed_inode(descriptor)
            if witness is None:
                continue
            binding = _open_group(owners[key], marker, maximum)
            if binding[2] != witness or host_memory_peer.observed_inode(descriptor) != witness:
                continue
            group = groups.setdefault(binding[0], [binding[1], 0])
            # A cap change during a supported handoff cannot reduce the charge
            # below either observed ceiling. Enlargements beyond the slot
            # budget were already rejected by _open_group.
            group[0] = max(group[0], binding[1])
            group[1] += slot.reservation_bytes
        except (OSError, ValueError):
            continue
        finally:
            close(binding)
            if descriptor is not None:
                os.close(descriptor)
    return sum(max(0, charge - cap) for cap, charge in groups.values())
