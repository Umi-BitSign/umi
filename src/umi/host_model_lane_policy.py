"""CPU-derived model lane ceilings over the existing shared memory admission.

These ceilings select how much work may compete for admission. They neither
grant memory nor change the signed per-invocation CPU/memory profile.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path, PurePosixPath

from .host_model_execution import ModelExecutionMemoryPolicy
from .open_competition import digest
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class CpuCapacity:
    affinity: tuple[int, ...]
    quota: Fraction | None

    @property
    def effective(self) -> Fraction:
        if not self.affinity or len(set(self.affinity)) != len(self.affinity):
            raise ValueError("model lane planning requires a nonempty distinct CPU affinity")
        if self.quota is not None and self.quota <= 0:
            raise ValueError("model lane planning requires a positive CPU quota")
        return min(Fraction(len(self.affinity)), self.quota or len(self.affinity))


def _small_text(path: Path) -> str:
    with path.open("r", encoding="ascii") as stream:
        value = stream.read(4097)
    if len(value) > 4096:
        raise ValueError("CPU capacity metadata exceeds its bound")
    return value


def _cpu_set(value: str) -> set[int]:
    result = set()
    for part in value.strip().split(","):
        fields = part.split("-")
        if not 1 <= len(fields) <= 2 or any(not item.isdecimal() for item in fields):
            raise ValueError("invalid effective CPU set")
        first, last = int(fields[0]), int(fields[-1])
        if first > last or last - first >= 8192 or len(result) + last - first + 1 > 8192:
            raise ValueError("effective CPU set exceeds its bound")
        result.update(range(first, last + 1))
    return result


def _hierarchy_capacity(current, root, affinity):
    quotas = []
    for _ in range(65):
        try:
            quota, period = _small_text(current / "cpu.max").split()
        except FileNotFoundError:
            pass  # An absent controller adds no local quota; visit its parent.
        else:
            if not period.isdecimal() or int(period) <= 0:
                raise ValueError("invalid worker CPU quota period")
            if quota != "max":
                if not quota.isdecimal() or int(quota) <= 0:
                    raise ValueError("invalid worker CPU quota")
                quotas.append(Fraction(int(quota), int(period)))
        try:
            effective = _small_text(current / "cpuset.cpus.effective").strip()
        except FileNotFoundError:
            effective = ""
        if effective:
            count = len(set(affinity) & _cpu_set(effective))
            if not count:
                raise ValueError("worker affinity and execution CPU set do not overlap")
            quotas.append(Fraction(count))
        if current == root:
            return quotas
        current = current.parent
    raise ValueError("worker CPU hierarchy exceeds its bound")


def observe_cpu_capacity(
    pid: int,
    *,
    proc_root=Path("/proc"),
    cgroup_root=Path("/sys/fs/cgroup"),
    execution_cgroup_roots=(),
):
    """Use the selected worker's affinity and every enclosing cgroup-v2 quota.

    Passing the target PID matters: a privileged provisioning process can have
    a broader affinity or quota than the evaluator it is preparing.
    """
    if type(pid) is not int or pid < 1:
        raise ValueError("a selected worker PID is required")
    process = proc_root / str(pid)
    stat_before = _small_text(process / "stat").rsplit(")", 1)[1].split()[19]
    affinity = tuple(sorted(os.sched_getaffinity(pid)))
    raw = _small_text(process / "cgroup")
    rows = [row[3:] for row in raw.splitlines() if row.startswith("0::")]
    if len(rows) != 1:
        raise ValueError("model lane planning requires one cgroup-v2 membership")
    relative = PurePosixPath(rows[0])
    if not relative.is_absolute() or ".." in relative.parts:
        raise ValueError("invalid worker cgroup membership")
    root = cgroup_root.resolve(strict=True)
    current = root.joinpath(*relative.parts[1:])
    if current.resolve(strict=True) != current:
        raise ValueError("worker cgroup path must not contain symlinks")
    quotas = _hierarchy_capacity(current, root, affinity)
    # Rootless containers can be placed outside the reviewer's systemd cgroup.
    # Bound the shared pool by those selected parents too, not only the Python
    # worker's less restrictive quota. Do not inspect per-container 6-CPU caps.
    if len(execution_cgroup_roots) > 64:
        raise ValueError("execution CPU roots exceed their bound")
    for path in execution_cgroup_roots:
        path = Path(path)
        if not path.is_relative_to(root) or path.resolve(strict=True) != path:
            raise ValueError("execution CPU root differs from the selected cgroup hierarchy")
        quotas.extend(_hierarchy_capacity(path, root, affinity))
    if (
        _small_text(process / "stat").rsplit(")", 1)[1].split()[19] != stat_before
        or _small_text(process / "cgroup") != raw
        or tuple(sorted(os.sched_getaffinity(pid))) != affinity
    ):
        raise ValueError("selected worker changed during CPU capacity observation")
    result = CpuCapacity(affinity, min(quotas) if quotas else None)
    _ = result.effective
    return result


def model_lane_count(capacity: CpuCapacity, runtime, *, maximum_lanes: int | None = None) -> int:
    if type(runtime.cpus) is not int or runtime.cpus < 1:
        raise ValueError("signed model runtime requires a positive CPU count")
    if maximum_lanes is not None and (
        type(maximum_lanes) is not int or not 1 <= maximum_lanes <= 32
    ):
        raise ValueError("operator model lane cap must be between one and 32")
    # A host smaller than one signed CPU quota still runs one invocation under
    # its enclosing quota. Never turn a slow supported host into zero workers.
    count = max(1, min(32, capacity.effective // runtime.cpus))
    return min(count, maximum_lanes) if maximum_lanes is not None else count


def validate_lane_runtime(previous: ModelExecutionMemoryPolicy, runtime) -> None:
    # Use the original signed profile bound by the immutable admission policy.
    # A prospective PID-only amendment preserves these CPU/memory limits.
    if digest(runtime) != previous.evaluation_runtime_sha256:
        raise ValueError("lane runtime differs from the selected signed profile")
    if any(
        slot.reservation_bytes != runtime.memory_bytes
        for slot in previous.slots
        if slot.lane == "transient"
    ):
        raise ValueError("model lane reservation differs from the signed memory budget")


def expanded_lane_policy(previous, runtime, added_slots, *, qualification_sha256):
    """Preserve every prior file identity and reserve the complete new envelope."""
    validate_lane_runtime(previous, runtime)
    slots = (*previous.slots, *added_slots)
    if any(
        slot.lane != "transient" or slot.reservation_bytes != runtime.memory_bytes
        for slot in added_slots
    ):
        raise ValueError("new lanes must retain the signed per-model memory budget")
    body = previous.model_dump(mode="json", by_alias=True)
    body.update(
        slots=[slot.model_dump(mode="json") for slot in slots],
        incremental_budget_bytes=max(
            previous.incremental_budget_bytes, sum(slot.reservation_bytes for slot in slots)
        ),
        qualification_sha256=qualification_sha256,
    )
    return ModelExecutionMemoryPolicy.model_validate_json(canonical_json_bytes(body))
