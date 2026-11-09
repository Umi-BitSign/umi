"""Credit stable anonymous pages already included in a witnessed hard ceiling.

The host availability sample is bracketed by cgroup observations. Anonymous
bytes and fault counters must remain identical, with zero swap and the same
live witness and cap. Cache and kernel memory receive no credit. Missing,
changing or overlapping observations keep the full reservation.
"""

import os
from contextlib import suppress
from pathlib import Path

from . import host_memory_peer


def observation_slack(anonymous_bytes):
    # Linux batches memcg statistics in 64-page units per CPU. Keep four
    # batches per configured CPU, plus at least 1/16 of observed anonymous
    # usage, charged for sampling/allocator variation. The host floor remains
    # separate. This slack is never a reduction of an enforced memory limit.
    return max(anonymous_bytes // 16, 256 * os.sysconf("SC_PAGE_SIZE") * (os.cpu_count() or 1))


def _sample(descriptor, ceiling):
    from .host_memory_admission import _cgroup_value

    if _cgroup_value(descriptor, "memory.max") != str(ceiling):
        raise ValueError("resident ceiling changed")
    if any(
        _cgroup_value(descriptor, name) != "0"
        for name in ("memory.swap.max", "memory.swap.current")
    ):
        raise ValueError("resident credit requires no swap")
    events = dict(line.split() for line in _cgroup_value(descriptor, "cgroup.events").splitlines())
    if events.get("populated") != "1":
        raise ValueError("resident owner is no longer populated")
    values = dict(line.split() for line in _cgroup_value(descriptor, "memory.stat").splitlines())
    keys = ("anon", "pgfault", "pgmajfault", "thp_fault_alloc", "pglazyfree")
    result = tuple(int(values[key]) for key in keys)
    current = int(_cgroup_value(descriptor, "memory.current"))
    if min(result) < 0 or not 0 <= result[0] <= current <= ceiling:
        raise ValueError("resident accounting is outside its enforced ceiling")
    return result


class ResidentBudget:
    def __init__(self, enabled):
        self.enabled = enabled
        self.entries = {}
        self.rejected = 0
        self.observation = {}

    def offer(self, descriptor, ceiling, slot_descriptor, witness):
        """Only callers proving this whole cap was charged may offer a group."""
        if not self.enabled:
            return
        held = slot = None
        try:
            info = os.fstat(descriptor)
            identity = (info.st_dev, info.st_ino)
            if identity in self.entries:
                return
            path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
            if not path.is_absolute() or ".." in path.parts or "(deleted)" in str(path):
                raise ValueError("resident group path is unavailable")
            if any(
                path == old[0] or path in old[0].parents or old[0] in path.parents
                for old in self.entries.values()
            ):
                raise ValueError("resident cgroups overlap")
            if host_memory_peer.observed_inode(slot_descriptor) != witness:
                raise ValueError("resident slot witness changed")
            before = _sample(descriptor, ceiling)
            held, slot = os.dup(descriptor), os.dup(slot_descriptor)
            self.entries[identity] = (path, held, ceiling, slot, witness, before)
            held = slot = None
        except (OSError, ValueError, KeyError):
            self.rejected += 1
        finally:
            for fd in (held, slot):
                if fd is not None:
                    os.close(fd)

    def measure(self, available_memory):
        available = available_memory()
        credit = accepted = observed = slack = 0
        for _, descriptor, ceiling, slot, witness, before in self.entries.values():
            try:
                after = _sample(descriptor, ceiling)
                if after != before or host_memory_peer.observed_inode(slot) != witness:
                    raise ValueError("resident allocation changed around host sample")
                # MADV_FREE pages may still be counted as anon while already
                # reclaimable in MemAvailable. Exclude every lifetime lazyfree
                # page conservatively, including ones since freed or reused.
                anonymous = max(0, before[0] - before[4] * os.sysconf("SC_PAGE_SIZE"))
                margin = min(anonymous, observation_slack(anonymous))
                observed += anonymous
                slack += margin
                credit += anonymous - margin
                accepted += int(anonymous > margin)
            except (OSError, ValueError, KeyError):
                self.rejected += 1
        self.observation = dict(
            resident_anonymous_credit_bytes=credit,
            resident_groups_credited=accepted,
            resident_groups_rejected=self.rejected,
            resident_cache_credit_bytes=0,
            resident_anonymous_observed_bytes=observed,
            resident_observation_slack_bytes=slack,
        )
        return available, credit

    def close(self):
        entries, self.entries = self.entries, {}
        for _, descriptor, _, slot, _, _ in entries.values():
            for fd in (descriptor, slot):
                with suppress(OSError):
                    os.close(fd)
