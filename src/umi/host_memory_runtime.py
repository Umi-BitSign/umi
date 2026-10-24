"""Installed host admission selection and complete compact-result operations.

Only bootstrap selects a controller. Child tasks inherit that immutable
selection, never an active lease. Each operation acquires its own lease; there
is no implicit reentrancy or sharing between concurrent children.
"""

from __future__ import annotations

import traceback
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Annotated

from pydantic import Field, ValidationError, model_validator

from .concurrency import run_owned_thread
from .host_memory_admission import HostMemoryAdmission, HostMemoryLease, _absolute
from .host_memory_request_bounds import stage_evidence_budget
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


def selected_memory() -> HostMemoryAdmission | None:
    return _selected.get()


@contextmanager
def memory_runtime(
    selection: HostMemoryAdmissionSelection | None,
    *,
    maximum_aggregate_bytes: int,
    role=None,
    protocol_policy_sha256=None,
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
    if maximum_aggregate_bytes > controller.policy.maximum_aggregate_bytes:
        raise ValueError("host aggregate limit exceeds its qualified admission policy")
    if previous is not None and previous.policy_sha256 != controller.policy_sha256:
        raise ValueError("nested host runtime changes its selected memory policy")
    token = _selected.set(controller)
    try:
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
        inherited = _active.get()
        if inherited is not None and not inherited.closed:
            raise RuntimeError("nested host memory operation would wait on its own capacity")
        lease = await (
            controller.acquire("transient", operation=operation, **selected_scope)
            if getattr(controller, "requests_stage", False)
            else controller.acquire("transient")
        )
        token = _active.set(lease)
        failure = None
        try:
            with stage_evidence_budget():
                return await function(*args, **kwargs)
        except BaseException as error:
            failure = compact_memory_error(error)
        finally:
            lease.close()
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
    inherited = _active.get()
    if inherited is not None and not inherited.closed:
        raise RuntimeError("nested host memory operation would wait on its own capacity")
    lease = await (
        controller.acquire("transient", operation=operation, **selected_scope)
        if getattr(controller, "requests_stage", False)
        else controller.acquire("transient")
    )
    token = _active.set(lease)
    try:
        with stage_evidence_budget():
            yield
    finally:
        lease.close()
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
        yield
    finally:
        _selected.reset(token)


class RequestsStageASGIBinding:
    """Cover lifespan children and independent HTTP tasks with the same policy.

    Public routes are not qualified during requests closure and refuse before
    reading bodies or native state. Private owner/reviewer routes have fixed scopes.
    """

    def __init__(self, app, *, controller, private_role=None):
        self.app, self.controller, self.private_role = app, controller, private_role

    def _permitted(self, scope):
        if self.private_role is None:
            return False
        # This authenticated endpoint returns one cached process identity only.
        # It reads no native state and occupies no signing/admission lane.
        if (self.private_role == "phase_reviewer" and scope.get("method") == "GET"
                and scope.get("path") == "/internal/cohorts/execution-producer"):
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
