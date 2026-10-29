"""Shared CPU model capacity backed by existing root-bound memory leases."""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager, suppress
from contextvars import ContextVar
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_transport_verification import TransferProgress
from .host_memory_admission import (
    AdmissionBindingError,
    HostMemoryAdmission,
    HostMemoryFile,
    HostMemorySlot,
    _absolute,
)
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel

_ACTIVE = ContextVar("host_model_execution_lease", default=None)
_LOGGER = logging.getLogger("umi.competition.progress")


def _report_admission(controller, *, lane, count, started, state):
    observation = controller.last_model_admission
    if observation is None:
        return
    # Reuse the actual grant/wait decision. Diagnostics perform no fresh
    # inventory and cannot change admission or imply an inference finish time.
    with suppress(Exception):
        _LOGGER.info(
            "%s",
            json.dumps(
                dict(
                    schema="umi-model-admission-observation/1",
                    status=state,
                    state=state,
                    pid=os.getpid(),
                    lane=lane,
                    requested_slots=count,
                    observed_unix_ms=int(time.time() * 1000),
                    elapsed_seconds=round(time.monotonic() - started, 3),
                    eta_seconds=0 if state == "admitted" else None,
                    eta_basis=(
                        "capacity_granted"
                        if state == "admitted"
                        else "awaiting_external_capacity_change"
                    ),
                    eta_scope="model_capacity_admission_only",
                    **observation,
                ),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


class ModelInvocationCapacity:
    """A runner may bind a container only during this explicit invocation."""

    def __init__(self, controller, lease):
        self._controller, self._lease = controller, lease
        self._generation, self._pid = lease._generation, os.getpid()
        self._active, self._binding = True, None

    def bind_container(self, container_id, cgroup_path):
        if (
            not self._active
            or self._pid != os.getpid()
            or self._lease.closed
            or self._generation is not self._lease._generation
        ):
            raise AdmissionBindingError("model invocation capacity is no longer owned")
        bound = self._controller.bind_model_container(self._lease, container_id, cgroup_path)
        if bound:
            self._binding = self._lease._model_container
        return bound

    def clear_container(self):
        if self._binding is not None and self._lease._model_container is self._binding:
            self._lease.clear_model_container()
        self._binding = None

    def close(self):
        self.clear_container()
        self._active = False


class ModelExecutionMemoryPolicy(StrictProtocolModel):
    schema_: Literal["umi-host-model-execution-admission/1"] = Field(alias="schema")
    host_identity_sha256: Hex32
    directory: str
    directory_device: Annotated[int, Field(ge=0, strict=True)]
    directory_inode: Annotated[int, Field(gt=0, strict=True)]
    group_id: Annotated[int, Field(gt=0, strict=True)]
    minimum_available_bytes: Annotated[int, Field(ge=4 * 1024**3, strict=True)]
    incremental_budget_bytes: Annotated[int, Field(gt=0, strict=True)]
    background_reservation_bytes: Annotated[int, Field(ge=0, strict=True)]
    qualification_sha256: Hex32
    protocol_policy_sha256: Hex32
    evaluation_runtime_sha256: Hex32
    container_cgroup_roots: Annotated[tuple[str, ...], Field(min_length=1, max_length=64)]
    slots: Annotated[tuple[HostMemorySlot, ...], Field(min_length=2, max_length=33)]
    transaction_lock: HostMemoryFile

    @model_validator(mode="after")
    def bindings(self):
        _absolute(self.directory)
        if len(set(self.container_cgroup_roots)) != len(self.container_cgroup_roots) or any(
            not str(_absolute(path)).startswith("/sys/fs/cgroup/")
            for path in self.container_cgroup_roots
        ):
            raise ValueError("model execution requires its selected kernel container roots")
        if {s.lane for s in self.slots} != {"owner_export", "transient"} or sum(
            s.lane == "owner_export" for s in self.slots
        ) != 1:
            raise ValueError("model execution requires one separate preparation lane")
        files = (*self.slots, self.transaction_lock)
        if len({s.name for s in files}) != len(files) or len(
            {(s.device, s.inode) for s in files}
        ) != len(files):
            raise ValueError("model execution slots must have distinct names and inodes")
        if (
            any(s.settlement_role is not None for s in self.slots)
            or len({s.reservation_bytes for s in self.slots if s.lane == "transient"}) != 1
        ):
            raise ValueError("model execution slots require one signed invocation budget")
        if self.reserved_bytes > self.incremental_budget_bytes:
            raise ValueError("model execution exceeds its qualified host reservation")
        return self

    @property
    def reserved_bytes(self):
        return sum(s.reservation_bytes for s in self.slots)


class ModelExecutionAdmission:
    def __init__(self, selection, policy):
        self.controller = HostMemoryAdmission(
            policy_path=_absolute(selection.policy_path),
            expected_sha256=selection.policy_sha256,
            host_identity_path=_absolute(selection.host_identity_path),
        )
        selected = self.controller.policy
        if not self.controller.model_execution_stage or (
            selected.protocol_policy_sha256 != digest(policy)
            or selected.evaluation_runtime_sha256 != policy.evaluation_runtime_sha256
        ):
            raise AdmissionBindingError("model execution capacity differs from signed policy")
        self.protocol_policy = policy.model_copy(deep=True)
        self.slots = tuple(s for s in selected.slots if s.lane == "transient")

    def check_runtime(self, runtime, *, runtime_authorization=None):
        from .competition_evaluation_runtime import validate_evaluation_runtime_authorization

        try:
            validate_evaluation_runtime_authorization(
                runtime_authorization,
                policy=self.protocol_policy,
                runtime_sha256=digest(runtime),
            )
        except ValueError as error:
            raise AdmissionBindingError(
                "model execution reservation is below its signed runtime"
            ) from error
        if any(slot.reservation_bytes < runtime.memory_bytes for slot in self.slots):
            raise AdmissionBindingError("model execution reservation is below its signed runtime")

    @asynccontextmanager
    async def invocation(self, runtime, *, runtime_authorization=None):
        active = _ACTIVE.get()
        if (
            active is not None
            and active[0].policy_sha256 == self.controller.policy_sha256
            and active[2] is asyncio.current_task()
            and not active[1].closed
            and active[1]._creator_pid == os.getpid()
        ):
            self.check_runtime(runtime, runtime_authorization=runtime_authorization)
            token = ModelInvocationCapacity(active[0], active[1])
            try:
                yield token
            finally:
                token.close()
        else:
            async with self.hold(runtime, runtime_authorization=runtime_authorization) as lease:
                token = ModelInvocationCapacity(self.controller, lease)
                try:
                    yield token
                finally:
                    token.close()

    @asynccontextmanager
    async def hold(
        self, runtime, *, exclusive=False, preparation=False, runtime_authorization=None
    ):
        self.check_runtime(runtime, runtime_authorization=runtime_authorization)
        lane = "owner_export" if preparation else "transient"
        count = len(self.slots) if exclusive and not preparation else 1
        started = time.monotonic()
        with TransferProgress("model_execution_capacity", count, unit="slots") as progress:
            last_wait = None
            while True:
                lease = self.controller.try_acquire_group(lane, count)
                if lease is not None:
                    _report_admission(
                        self.controller, lane=lane, count=count, started=started, state="admitted"
                    )
                    break
                now = time.monotonic()
                if last_wait is None or now - last_wait >= 10:
                    progress.emit(
                        "waiting",
                        reason=(
                            "host_model_preparation_capacity"
                            if preparation
                            else "host_model_invocation_capacity"
                        ),
                    )
                    _report_admission(
                        self.controller, lane=lane, count=count, started=started, state="waiting"
                    )
                    last_wait = now
                await asyncio.sleep(0.5)
            progress.advance(count)
        try:
            token = (
                None
                if preparation
                else _ACTIVE.set((self.controller, lease, asyncio.current_task()))
            )
            yield lease
        finally:
            if token is not None:
                _ACTIVE.reset(token)
            lease.close()
