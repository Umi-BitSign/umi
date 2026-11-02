"""Qualified shared graph/model capacity with independent export and settlement.

This prospective policy does not change either legacy admission schema. Its
qualification must cover the selected workload and controller/cgroup limits;
closing a logical lease never claims that Python returned resident pages.
"""

from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .host_cpu_timing import CpuTimingHostSelection
from .host_memory_admission import HostMemoryAdmissionPolicy, HostMemorySlot, _absolute
from .host_memory_workload_profile import WorkloadProfileSelection
from .protocol import Hex32


class ExecutionMemoryPolicy(HostMemoryAdmissionPolicy):
    schema_: Literal["umi-host-execution-memory-admission/1"] = Field(alias="schema")
    minimum_available_bytes: Annotated[int, Field(ge=4 * 1024**3, strict=True)]
    slots: Annotated[tuple[HostMemorySlot, ...], Field(min_length=4, max_length=4)]
    protocol_policy_sha256: Hex32
    evaluation_runtime_sha256: Hex32
    workload_profile: WorkloadProfileSelection
    container_cgroup_roots: Annotated[tuple[str, ...], Field(min_length=1, max_length=64)]
    container_cgroupfs_roots: Annotated[tuple[str, ...], Field(max_length=64)] = ()
    cpu_timing_profile: CpuTimingHostSelection | None = None

    @model_serializer(mode="wrap")
    def optional_model_selection(self, handler):
        value = handler(self)
        if not self.container_cgroupfs_roots:
            value.pop("container_cgroupfs_roots", None)
        if self.cpu_timing_profile is None:
            value.pop("cpu_timing_profile", None)
        return value

    @model_validator(mode="after")
    def shared_execution_bindings(self):
        # The inherited contract checks distinct immutable files, both replica
        # roles, equal per-lane reservations and the complete incremental budget.
        if (
            sum(s.lane == "owner_export" for s in self.slots) != 1
            or sum(s.lane == "transient" for s in self.slots) != 1
        ):
            raise ValueError("joint execution requires one export and one shared transient slot")
        roots = (*self.container_cgroup_roots, *self.container_cgroupfs_roots)
        if len(set(roots)) != len(roots) or any(
            not str(_absolute(path)).startswith("/sys/fs/cgroup/") for path in roots
        ):
            raise ValueError("joint execution requires its selected kernel container roots")
        return self
