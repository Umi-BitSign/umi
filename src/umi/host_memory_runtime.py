"""Installed host admission selection and complete compact-result operations.

Only bootstrap selects a controller. Child tasks inherit that immutable
selection, never an active lease. Each operation acquires its own lease; there
is no implicit reentrancy or sharing between concurrent children.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import traceback
from collections import deque
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
            selected,
            operation=operation,
            scope=scope,
            requests_stage_only=requests_stage_only,
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

    _SHARE_HEADERS = frozenset(
        {
            b"host",
            b"accept",
            b"accept-encoding",
            b"accept-language",
            b"origin",
            b"range",
            b"if-none-match",
            b"if-modified-since",
            b"if-match",
            b"if-unmodified-since",
            b"if-range",
            b"cache-control",
            b"pragma",
        }
    )

    def __init__(
        self,
        app,
        *,
        controller,
        maximum_waiting=0,
        wait_seconds=0,
        maximum_control_waiting=None,
        shutdown_callbacks=None,
    ):
        self.app, self.controller = app, controller
        self.workload = getattr(controller, "workload_profile", None)
        if self.workload is None:
            raise ValueError("bounded ASGI entry requires its selected workload profile")
        self.inflight = self.reserved = 0
        if type(maximum_waiting) is not int or maximum_waiting < 0 or wait_seconds < 0:
            raise ValueError("invalid HTTP waiting bounds")
        if maximum_control_waiting is None:
            maximum_control_waiting = maximum_waiting
        if type(maximum_control_waiting) is not int or maximum_control_waiting < 0:
            raise ValueError("invalid HTTP control waiting bound")
        if (maximum_waiting or maximum_control_waiting) and not 0 < wait_seconds <= 120:
            raise ValueError("HTTP waiting requires its selected public timeout")
        self.waiting_limits = {
            "read": maximum_waiting,
            "write": maximum_control_waiting,
        }
        self.maximum_waiting = sum(self.waiting_limits.values())
        self.wait_seconds = wait_seconds
        self.waiting = 0
        self.waiting_groups = {"read": 0, "write": 0}
        self.queues = {"read": deque(), "write": deque()}
        self.control_burst = max(1, maximum_control_waiting)
        self.controls_since_read = 0
        self.closing = False
        self.shared = {}
        self.shared_bytes = 0
        self.capture_limit = min(
            getattr(self.workload.bounds, "maximum_object_bytes", 0),
            self.workload.profile.maximum_queued_input_bytes // 2,
        )
        self.active = {}
        self.rejections = {}
        self.last_report = float("-inf")
        self.completed_seconds = deque(maxlen=8)
        if shutdown_callbacks is not None:
            shutdown_callbacks.append(self.close)

    def close(self):
        """Cancel only queued pre-body requests; owned native work still drains."""
        self.closing = True
        for queue in self.queues.values():
            for ticket in queue:
                if not ticket["future"].done():
                    ticket["future"].set_exception(WorkloadQualificationPending("http_shutdown"))
        for shared in self.shared.values():
            if not shared["future"].done():
                shared["future"].set_result(None)

    @staticmethod
    def _group(scope):
        # Read-only status polling must not consume the mutation waiters.
        return "read" if scope.get("method") in ("GET", "HEAD") else "write"

    def _enter_wait(self, group):
        if self.closing:
            raise WorkloadQualificationPending("http_shutdown")
        if self.waiting_groups[group] >= self.waiting_limits[group]:
            raise WorkloadQualificationPending("http_request_capacity")
        self.waiting_groups[group] += 1
        self.waiting += 1

    def _leave_wait(self, group):
        self.waiting_groups[group] -= 1
        self.waiting -= 1

    def _report(self, reason):
        self.rejections[reason] = self.rejections.get(reason, 0) + 1
        now = time.monotonic()
        if now - self.last_report < 5:
            return
        self.last_report = now
        durations = tuple(self.completed_seconds)
        logging.getLogger(__name__).warning(
            "workload_http_admission %s",
            json.dumps(
                dict(
                    schema="umi-workload-http-admission/1",
                    reason_code=reason,
                    inflight=self.inflight,
                    reserved_input_bytes=self.reserved,
                    retained_shared_response_bytes=self.shared_bytes,
                    waiting=self.waiting,
                    maximum_waiting=self.maximum_waiting,
                    rejection_counts=self.rejections,
                    active=[
                        dict(
                            route=row["route"],
                            elapsed_seconds=round(now - row["started"], 3),
                        )
                        for row in self.active.values()
                    ],
                    eta_seconds=(sum(durations) / len(durations) * (self.waiting + 1))
                    if durations
                    else None,
                    eta_basis="recent_completed_request_seconds"
                    if durations
                    else "no_completed_request_samples",
                    planning_eta_seconds=None if durations else [0, self.wait_seconds],
                    eta_scope="HTTP_queue_only_excludes_model_certification",
                    stalled_or_retrying=True,
                ),
                separators=(",", ":"),
            ),
        )

    @staticmethod
    def _route(scope):
        # Never emit query strings, hotkeys, signatures or arbitrary path segments.
        names = {
            "v1",
            "competition",
            "cohorts",
            "status",
            "history",
            "readiness",
            "admissions",
            "participation",
            "participation-status",
            "service-work",
            "direct-model-uploads",
            "model-uploads",
            "parts",
            "complete",
            "restart",
            "by-upload",
            "files",
            "rounds",
            "index",
            "submissions",
            "progress",
        }
        path = "/".join(
            part if part in names else "{id}" for part in scope.get("path", "").split("/") if part
        )
        return scope.get("method", "") + " /" + path[:256]

    def _fits(self, reservation):
        profile = self.workload.profile
        return (
            self.inflight < profile.maximum_http_inflight
            and self.reserved + self.shared_bytes + reservation
            <= profile.maximum_queued_input_bytes
        )

    def _grant(self, ticket):
        ticket["active"] = True
        ticket["started"] = time.monotonic()
        self.inflight += 1
        self.reserved += ticket["reservation"]
        self.active[id(ticket)] = ticket
        self.controls_since_read = self.controls_since_read + 1 if ticket["group"] == "write" else 0

    def _wake(self):
        if self.closing:
            return
        while True:
            groups = (
                ("write", "read")
                if self.controls_since_read < self.control_burst
                else ("read", "write")
            )
            ticket = None
            for group in groups:
                queue = self.queues[group]
                while queue and queue[0]["future"].done():
                    queue.popleft()
                if queue and self._fits(queue[0]["reservation"]):
                    ticket = queue.popleft()
                    break
            if ticket is None:
                return
            self._grant(ticket)
            ticket["future"].set_result(None)

    def _release(self, ticket):
        if ticket["active"]:
            ticket["active"] = False
            self.inflight -= 1
            self.reserved -= ticket["reservation"]
            self.active.pop(id(ticket))
            self.completed_seconds.append(time.monotonic() - ticket["started"])
            self._wake()

    async def _acquire(self, scope, reservation):
        if self.closing:
            raise WorkloadQualificationPending("http_shutdown")
        ticket = dict(
            reservation=reservation,
            active=False,
            route=self._route(scope),
            group=self._group(scope),
        )
        if not any(self.queues.values()) and self._fits(reservation):
            self._grant(ticket)
            return ticket
        if reservation > self.workload.profile.maximum_queued_input_bytes:
            raise WorkloadQualificationPending("http_input_reservation")
        self._enter_wait(ticket["group"])
        ticket["future"] = asyncio.get_running_loop().create_future()
        self.queues[ticket["group"]].append(ticket)
        try:
            await asyncio.wait_for(asyncio.shield(ticket["future"]), self.wait_seconds)
            return ticket
        except BaseException as error:
            if ticket["active"]:
                self._release(ticket)
            else:
                if ticket in self.queues[ticket["group"]]:
                    self.queues[ticket["group"]].remove(ticket)
                if ticket["future"].done() and not ticket["future"].cancelled():
                    ticket["future"].exception()
                ticket["future"].cancel()
                self._wake()
            if isinstance(error, asyncio.TimeoutError):
                raise WorkloadQualificationPending("http_queue_timeout") from None
            raise
        finally:
            self._leave_wait(ticket["group"])

    @staticmethod
    def _public_share_path(path):
        if path in {
            "/v1/competition/status",
            "/v1/competition/cohorts",
            "/v1/competition/service-work",
        }:
            return True
        parts = path.split("/")
        if (
            len(parts) not in (7, 8)
            or parts[:4] != ["", "v1", "competition", "cohorts"]
            or parts[5] != "direct-model-uploads"
        ):
            return False
        if len(parts) == 8 and parts[6] != "by-upload":
            return False
        return all(
            len(value) == 64 and all(c in "0123456789abcdef" for c in value)
            for value in (parts[4], parts[-1])
        )

    def _share_key(self, scope):
        # These routes depend only on public state. Nonce/authorization routes
        # are deliberately absent. Share only the currently running response.
        if (
            not self.maximum_waiting
            or not self.capture_limit
            or scope.get("method") != "GET"
            or not self._public_share_path(scope.get("path", ""))
        ):
            return None
        headers = tuple((name.lower(), value) for name, value in scope.get("headers", ()))
        if any(
            name in {b"authorization", b"proxy-authorization", b"cookie"} for name, _ in headers
        ):
            return None
        if scope.get("user") is not None or scope.get("auth") is not None:
            return None
        if any(
            (name == b"content-length" and value != b"0") or name == b"transfer-encoding"
            for name, value in headers
        ):
            return None
        return (
            scope["path"],
            scope.get("query_string", b""),
            tuple((name, value) for name, value in headers if name in self._SHARE_HEADERS),
            scope.get("scheme"),
            scope.get("root_path", ""),
        )

    async def _shared_response(self, shared, send):
        self._enter_wait("read")
        shared["followers"] += 1
        response_started = False
        failure = None

        async def respond():
            nonlocal response_started
            messages = await asyncio.shield(shared["future"])
            if messages is None:
                reason = "http_shutdown" if self.closing else "http_shared_response_unavailable"
                raise WorkloadQualificationPending(reason)
            for message in messages:
                if message["type"] == "http.response.start":
                    response_started = True
                await send(dict(message))

        try:
            await asyncio.wait_for(respond(), self.wait_seconds)
        except BaseException as error:
            # A failed transport can retain response bytes in traceback frames.
            # Drop those references before releasing the follower's byte charge.
            failure = compact_memory_error(error)
            if isinstance(failure, asyncio.TimeoutError) and not response_started:
                failure = WorkloadQualificationPending("http_queue_timeout")
        finally:
            shared["followers"] -= 1
            if not shared["followers"] and shared["bytes"]:
                self.shared_bytes -= shared["bytes"]
                shared["bytes"] = 0
                # Release the retained response before admitting another graph.
                shared["future"] = None
                self._wake()
            self._leave_wait("read")
        if failure is not None:
            raise failure from None

    @staticmethod
    async def _pending(send, reason="workload_qualification_pending"):
        body = b'{"detail":"workload_qualification_pending","retry_unchanged":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", b"1"),
                    (b"x-umi-reason-code", reason.encode("ascii")),
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
            except WorkloadQualificationPending as error:
                self._report(error.qualification_reason)
                await self._pending(send, error.qualification_reason)
                return
            key = self._share_key(scope)
            shared = self.shared.get(key) if key is not None else None
            if shared is not None:
                try:
                    await self._shared_response(shared, send)
                except WorkloadQualificationPending as error:
                    self._report(error.qualification_reason)
                    await self._pending(send, error.qualification_reason)
                return
            shared = (
                dict(
                    future=asyncio.get_running_loop().create_future(),
                    followers=0,
                    bytes=0,
                )
                if key is not None
                else None
            )
            if shared is not None:
                self.shared[key] = shared
            ticket = None
            received = 0
            failure = None
            response_started = False
            response_complete = False
            captured_start, captured_body, captured_bytes = None, bytearray(), 0
            capture_limit = self.capture_limit
            input_reservation = reservation
            if shared is not None:
                # The active request owns capture/conversion memory. Transfer
                # only the final bytes to followers when its input charge ends.
                reservation = max(reservation, 2 * capture_limit)

            async def bounded_receive():
                nonlocal received
                message = await receive()
                if message["type"] == "http.request":
                    received += len(message.get("body", b""))
                    if received > input_reservation:
                        raise WorkloadQualificationPending("request_byte_bound")
                return message

            async def tracked_send(message):
                nonlocal \
                    response_started, \
                    response_complete, \
                    captured_start, \
                    captured_body, \
                    captured_bytes
                if message["type"] == "http.response.start":
                    response_started = True
                    if message.get("trailers", False):
                        captured_body = None
                    for name, value in message.get("headers", ()):
                        if name.lower() == b"set-cookie" or (
                            name.lower() == b"vary"
                            and any(
                                item.strip().lower() not in self._SHARE_HEADERS
                                for item in value.split(b",")
                            )
                        ):
                            captured_body = None
                if shared is not None and captured_body is not None:
                    body = message.get("body", b"")
                    captured_bytes += len(body) + sum(
                        len(k) + len(v) for k, v in message.get("headers", ())
                    )
                    if captured_bytes > capture_limit or message["type"] not in {
                        "http.response.start",
                        "http.response.body",
                    }:
                        captured_body = None
                    elif message["type"] == "http.response.start":
                        captured_start = {
                            **message,
                            "headers": list(message.get("headers", ())),
                        }
                    elif message["type"] == "http.response.body":
                        captured_body.extend(body)
                if message["type"] == "http.response.body" and not message.get("more_body", False):
                    # A completed computation can serve remaining clients even
                    # if this client's send fails. No partial body is shared.
                    response_complete = True
                await send(message)

            try:
                ticket = await self._acquire(scope, reservation)
                with workload_input_budget():
                    await self.app(scope, bounded_receive, tracked_send)
            except BaseException as error:
                failure = compact_memory_error(error)
            finally:
                if shared is not None:
                    self.shared.pop(key)
                    if not shared["future"].done():
                        if (
                            shared["followers"]
                            and response_complete
                            and captured_body is not None
                            and captured_start is not None
                        ):
                            messages = (
                                captured_start,
                                dict(type="http.response.body", body=bytes(captured_body)),
                            )
                            shared["bytes"] = captured_bytes
                            self.shared_bytes += captured_bytes
                            shared["future"].set_result(messages)
                            messages = None
                        else:
                            shared["future"].set_result(None)
                    captured_body = None
                    captured_start = None
                if ticket is not None:
                    self._release(ticket)
            if failure is not None:
                if isinstance(failure, WorkloadQualificationPending) and not response_started:
                    self._report(failure.qualification_reason)
                    await self._pending(send, failure.qualification_reason)
                else:
                    raise failure from None
