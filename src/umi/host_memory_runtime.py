"""Installed host admission selection and complete compact-result operations.

Only bootstrap selects a controller. Child tasks inherit that immutable
selection, never an active lease. Each operation acquires its own lease; there
is no implicit reentrancy or sharing between concurrent children.
"""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
from contextlib import asynccontextmanager, contextmanager, suppress
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Annotated

from pydantic import Field, ValidationError, model_validator

from .competition_cohort_public_progress import is_cached_cohort_progress_request
from .competition_progress import _failure_details
from .concurrency import run_owned_thread
from .host_memory_admission import HostMemoryAdmission, HostMemoryLease, _absolute
from .host_memory_request_bounds import stage_evidence_budget
from .host_memory_workload_profile import (
    WorkloadQualificationPending,
    load_workload_profile,
    workload_input_budget,
    workload_runtime,
)
from .protocol import StrictProtocolModel


class HostMemoryAdmissionSelection(StrictProtocolModel):
    policy_path: str
    host_identity_path: str = "/etc/machine-id"
    policy_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def binding(self):
        _absolute(self.policy_path)
        _absolute(self.host_identity_path)
        return self


_selected: ContextVar[HostMemoryAdmission | None] = ContextVar(
    "host_memory_admission", default=None
)


_active: ContextVar[HostMemoryLease | None] = ContextVar("host_memory_operation", default=None)
_active_task: ContextVar[asyncio.Task | None] = ContextVar(
    "host_memory_operation_task", default=None
)


def current_task_graph_lease():
    """Only the task that acquired a graph lease owns its cross-kind lifetime."""
    lease = _active.get()
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return None
    return lease if lease is not None and not lease.closed and task is _active_task.get() else None


def inherited_graph_lease():
    """A descendant cannot wait for capacity its awaiting parent still owns."""
    lease = _active.get()
    return lease if lease is not None and not lease.closed else None


def _check_model_nesting(controller):
    if getattr(controller, "joint_execution_stage", False):
        from .host_model_execution import inherited_model_lease

        if inherited_model_lease() is not None:
            raise RuntimeError("graph operation cannot acquire its own active model capacity")


def selected_memory() -> HostMemoryAdmission | None:
    return _selected.get()


@contextmanager
def memory_runtime(
    selection: HostMemoryAdmissionSelection | None,
    *,
    maximum_aggregate_bytes: int,
    role=None,
    protocol_policy_sha256=None,
    evaluation_runtime_sha256=None,
    series_sha256=None,
    authority_sha256=None,
):
    previous = selected_memory()
    if selection is None:
        if previous is not None:
            raise ValueError("nested host runtime cannot omit its selected memory policy")
        yield None
        return
    controller = HostMemoryAdmission(
        Path(selection.policy_path),
        expected_sha256=selection.policy_sha256,
        host_identity_path=Path(selection.host_identity_path),
    )
    controller.bind_runtime(role, protocol_policy_sha256, series_sha256, authority_sha256)
    if (
        getattr(controller, "joint_execution_stage", False)
        and evaluation_runtime_sha256 != controller.policy.evaluation_runtime_sha256
    ):
        raise ValueError("host workload differs from the actual evaluation runtime")
    controller.workload_profile = (
        load_workload_profile(
            controller.policy.workload_profile,
            dict(
                role=role,
                protocol_policy_sha256=protocol_policy_sha256,
                evaluation_runtime_sha256=evaluation_runtime_sha256,
                series_sha256=series_sha256,
                authority_sha256=authority_sha256,
            ),
        )
        if getattr(controller, "joint_execution_stage", False)
        else None
    )
    if maximum_aggregate_bytes > controller.policy.maximum_aggregate_bytes:
        raise ValueError("host aggregate limit exceeds its qualified admission policy")
    if previous is not None and previous.policy_sha256 != controller.policy_sha256:
        raise ValueError("nested host runtime changes its selected memory policy")
    token = _selected.set(controller)
    try:
        with workload_runtime(controller.workload_profile):
            yield controller
    finally:
        _selected.reset(token)


def discard_error_frames(error: BaseException) -> None:
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend(e for e in (current.__cause__, current.__context__) if e is not None)
        traceback.clear_frames(current.__traceback__)
        current.__traceback__ = current.__cause__ = current.__context__ = None


def _bounded_error_value(value, budget, depth=0):
    """Copy diagnostic scalars/containers, never retain rejected native objects."""
    if budget[0] <= 0 or depth > 4:
        return None
    budget[0] -= 1
    if value is None or type(value) is bool:
        return value
    if type(value) is int and value.bit_length() <= 256:
        return value
    if type(value) is str:
        result = value[: min(1024, budget[0])]
        budget[0] -= len(result)
        return result
    if type(value) in (tuple, list):
        copied = [_bounded_error_value(item, budget, depth + 1) for item in value[:32]]
        return tuple(copied) if type(value) is tuple else copied
    if type(value) is dict:
        copied = {}
        for name, item in value.items():
            if len(copied) >= 32 or budget[0] <= 0:
                break
            if type(name) is str and len(name) <= 128:
                budget[0] -= len(name)
                copied[name] = _bounded_error_value(item, budget, depth + 1)
        return copied
    return None


def compact_memory_error(error: BaseException) -> BaseException:
    # Record bounded source locations before dropping the rejected graph. A
    # later transport log can otherwise show only this wrapper's re-raise.
    # Diagnostic failure must never prevent native graph release.
    with suppress(Exception):
        logging.getLogger(__name__).warning(
            "native_aggregate_failed details=%s",
            json.dumps(_failure_details(error), separators=(",", ":")),
        )
    discard_error_frames(error)
    # Pydantic owns rejected inputs independently of its completed frames.
    if isinstance(error, ValidationError):
        return ValueError("native aggregate input validation failed")
    # Native exceptions can likewise own graphs in args or custom attributes.
    # Allocate a fresh exception without rerunning custom constructors, preserve
    # its catchable class and bounded diagnostic fields, and discard all graphs.
    # The original must die at the caller's except boundary before lease close.
    try:
        allocator = OSError.__new__ if isinstance(error, OSError) else BaseException.__new__
        result = allocator(type(error))
    except TypeError:
        return RuntimeError("native aggregate operation failed")
    budget = [8192]
    result.args = _bounded_error_value(error.args, budget)
    for name, value in (_bounded_error_value(error.__dict__, budget) or {}).items():
        setattr(result, name, value)
    if isinstance(error, OSError):
        for name in ("errno", "strerror", "filename", "filename2"):
            value = getattr(error, name)
            # Setting an absent filename changes OSError's formatting flags;
            # a plain-message failure would lose its original useful reason.
            if value is not None:
                setattr(result, name, _bounded_error_value(value, budget))
    return result


def memory_operation(function=None, *, operation=None, scope=None, requests_stage_only=False):
    """Guard a complete async operation whose successful result is compact.

    Callers must use owned work helpers and must not await peer operations
    needing this lane. Nested native package work belongs inside this scope,
    whereas preceding/following opportunity or peer-vote work stays outside.
    """

    if function is None:
        return lambda selected: memory_operation(
            selected, operation=operation, scope=scope, requests_stage_only=requests_stage_only
        )

    @wraps(function)
    async def admitted(*args, **kwargs):
        controller = selected_memory()
        if controller is None or (
            requests_stage_only and not getattr(controller, "requests_stage", False)
        ):
            return await function(*args, **kwargs)
        selected_scope = (
            {}
            if scope is None or not getattr(controller, "requests_stage", False)
            else dict(zip(("cohort", "phase"), scope(*args, **kwargs), strict=True))
        )
        if getattr(controller, "requests_stage", False):
            controller.authorize(operation, **selected_scope, lane="transient")
        _check_model_nesting(controller)
        inherited = _active.get()
        if inherited is not None and not inherited.closed:
            raise RuntimeError("nested host memory operation would wait on its own capacity")
        lease = await (
            controller.acquire("transient", operation=operation, **selected_scope)
            if getattr(controller, "requests_stage", False)
            else controller.acquire("transient")
        )
        token = _active.set(lease)
        task_token = _active_task.set(asyncio.current_task())
        failure = None
        try:
            with stage_evidence_budget(), workload_input_budget():
                return await function(*args, **kwargs)
        except BaseException as error:
            failure = compact_memory_error(error)
        finally:
            lease.close()
            _active_task.reset(task_token)
            _active.reset(token)
        raise failure from None

    return admitted


@asynccontextmanager
async def memory_operation_context(*, operation, cohort=None, phase=None):
    """Keep a transient grant through preparation, owned work and native cleanup.

    The yielded context is not a transferable lease. Its owned worker must
    compact native failures before handing them across the async context
    boundary; __aexit__ otherwise retains the original rejected input graph.
    Drain work and discard its results before leaving this scope.
    """
    controller = selected_memory()
    if controller is None:
        yield
        return
    selected_scope = {"cohort": cohort, "phase": phase}
    if getattr(controller, "requests_stage", False):
        controller.authorize(operation, **selected_scope, lane="transient")
    _check_model_nesting(controller)
    inherited = _active.get()
    if inherited is not None and not inherited.closed:
        raise RuntimeError("nested host memory operation would wait on its own capacity")
    lease = await (
        controller.acquire("transient", operation=operation, **selected_scope)
        if getattr(controller, "requests_stage", False)
        else controller.acquire("transient")
    )
    token = _active.set(lease)
    task_token = _active_task.set(asyncio.current_task())
    try:
        with stage_evidence_budget(), workload_input_budget():
            yield
    finally:
        lease.close()
        _active_task.reset(task_token)
        _active.reset(token)


@asynccontextmanager
async def history_memory_window(required_bytes):
    """Use the parent's full reservation; never acquire a nested worker lease."""
    controller = selected_memory()
    if controller is None:
        yield
        return
    inherited = _active.get()
    if inherited is not None and not inherited.closed:
        if inherited.slot.reservation_bytes < required_bytes:
            raise ValueError("parallel history exceeds the selected host memory reservation")
        yield
        return
    async with memory_operation_context(operation=None):
        if _active.get().slot.reservation_bytes < required_bytes:
            raise ValueError("parallel history exceeds the selected host memory reservation")
        yield


async def run_memory_thread(function, *args, operation=None, cohort=None, phase=None):
    """A complete local package operation returning only compact state."""
    admitted = memory_operation(operation=operation, scope=lambda *_: (cohort, phase))(
        run_owned_thread
    )
    return await admitted(function, *args)


def authorize_memory(operation, cohort, phase, *, lane=None):
    controller = selected_memory()
    if controller is not None and getattr(controller, "requests_stage", False):
        controller.authorize(operation, cohort, phase, lane=lane)


def requests_stage_policy():
    controller = selected_memory()
    return (
        controller.policy
        if controller is not None and getattr(controller, "requests_stage", False)
        else None
    )


@contextmanager
def bind_memory_controller(controller):
    """Bind an already validated immutable controller across an explicit entry."""
    previous = selected_memory()
    if previous is not None and previous.policy_sha256 != controller.policy_sha256:
        raise ValueError("entry point changes its selected memory policy")
    token = _selected.set(controller)
    try:
        with workload_runtime(getattr(controller, "workload_profile", None)):
            yield
    finally:
        _selected.reset(token)


class RequestsStageASGIBinding:
    """Cover lifespan children and independent HTTP tasks with the same policy.

    Cache-only public progress stays visible during requests closure. Other public
    routes refuse before reading bodies or native state. Private routes have fixed scopes.
    """

    def __init__(self, app, *, controller, private_role=None):
        self.app, self.controller, self.private_role = app, controller, private_role

    def _permitted(self, scope):
        if self.private_role is None:
            return is_cached_cohort_progress_request(scope.get("method"), scope.get("path"))
        # These authenticated endpoints copy cached process/stage diagnostics.
        # They read no native state and occupy no signing/admission lane.
        if (
            self.private_role == "phase_reviewer"
            and scope.get("method") == "GET"
            and scope.get("path") == "/internal/cohorts/execution-producer"
        ):
            return True
        if self.private_role == "phase_reviewer" and scope.get("method") == "GET":
            path = scope.get("path", "")
            for prefix in (
                "/internal/cohorts/execution-producer/work/",
                "/internal/cohorts/execution-producer/settlement/",
            ):
                if path.startswith(prefix):
                    cohort = path[len(prefix) :]
                    if len(cohort) == 64 and all(c in "0123456789abcdef" for c in cohort):
                        return True
        paths = {
            "intake": {"/internal/cohorts/request-review": "requests_export"},
            "phase_reviewer": {
                "/internal/cohorts/requests/votes/progress": "requests_review",
                "/internal/cohorts/requests/votes/decision": "requests_decision",
            },
        }
        operation = paths.get(self.private_role, {}).get(scope.get("path"))
        return scope.get("method") == "POST" and operation in self.controller.policy.operations

    async def __call__(self, scope, receive, send):
        with bind_memory_controller(self.controller):
            if scope["type"] == "http" and not self._permitted(scope):
                body = b'{"detail":"C5 request certification stage holds new admission work"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 503,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
            await self.app(scope, receive, send)


class WorkloadASGIBinding:
    """Propagate the selected profile and bound whole request graph lifetimes.

    Admission happens before the first body read. One service-wide counter covers
    every route, including parsed requests awaiting the shared native graph slot.
    A response keeps its reservation until the downstream app has released its
    local graph. No request body is copied or decoded by this middleware.
    """

    def __init__(self, app, *, controller):
        self.app, self.controller = app, controller
        self.workload = getattr(controller, "workload_profile", None)
        if self.workload is None:
            raise ValueError("bounded ASGI entry requires its selected workload profile")
        self.inflight = self.reserved = 0

    @staticmethod
    async def _pending(send):
        body = b'{"detail":"workload_qualification_pending","retry_unchanged":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", b"1"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def _reservation(self, scope):
        lengths = [
            value for name, value in scope.get("headers", ()) if name.lower() == b"content-length"
        ]
        if not lengths:
            return self.workload.bounds.maximum_input_bytes
        if len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0]) > 20:
            raise WorkloadQualificationPending("request_length_invalid")
        value = int(lengths[0])
        if value > self.workload.bounds.maximum_input_bytes:
            raise WorkloadQualificationPending("request_byte_bound")
        return value

    async def __call__(self, scope, receive, send):
        with bind_memory_controller(self.controller):
            if scope["type"] != "http" or is_cached_cohort_progress_request(
                scope.get("method"), scope.get("path")
            ):
                await self.app(scope, receive, send)
                return
            try:
                reservation = self._reservation(scope)
            except WorkloadQualificationPending:
                await self._pending(send)
                return
            profile = self.workload.profile
            # ASGI runs these counters on its owning loop; no await separates
            # the capacity check from acquisition or release.
            if (
                self.inflight >= profile.maximum_http_inflight
                or self.reserved + reservation > profile.maximum_queued_input_bytes
            ):
                await self._pending(send)
                return
            self.inflight += 1
            self.reserved += reservation
            received = 0
            response_started = False

            async def bounded_receive():
                nonlocal received
                message = await receive()
                if message["type"] == "http.request":
                    received += len(message.get("body", b""))
                    if received > reservation:
                        raise WorkloadQualificationPending("request_byte_bound")
                return message

            async def tracked_send(message):
                nonlocal response_started
                if message["type"] == "http.response.start":
                    response_started = True
                await send(message)

            try:
                with workload_input_budget():
                    await self.app(scope, bounded_receive, tracked_send)
            except WorkloadQualificationPending:
                if response_started:
                    raise
                await self._pending(send)
            finally:
                self.reserved -= reservation
                self.inflight -= 1
