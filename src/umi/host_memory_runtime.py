"""Installed host admission selection and complete compact-result operations.

Only bootstrap selects a controller. Child tasks inherit that immutable
selection, never an active lease. Each operation acquires its own lease; there
is no implicit reentrancy or sharing between concurrent children.
"""

from __future__ import annotations

import traceback
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Annotated

from pydantic import Field, ValidationError, model_validator

from .concurrency import run_owned_thread
from .host_memory_admission import HostMemoryAdmission, HostMemoryLease, _absolute
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
def memory_runtime(selection: HostMemoryAdmissionSelection | None, *, maximum_aggregate_bytes: int):
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
            setattr(result, name, _bounded_error_value(getattr(error, name), budget))
    return result


def memory_operation(function):
    """Guard a complete async operation whose successful result is compact.

    Callers must use owned work helpers and must not await peer operations
    needing this lane. Nested native package work belongs inside this scope,
    whereas preceding/following opportunity or peer-vote work stays outside.
    """

    @wraps(function)
    async def admitted(*args, **kwargs):
        controller = selected_memory()
        if controller is None:
            return await function(*args, **kwargs)
        inherited = _active.get()
        if inherited is not None and not inherited.closed:
            raise RuntimeError("nested host memory operation would wait on its own capacity")
        lease = await controller.acquire("transient")
        token = _active.set(lease)
        failure = None
        try:
            return await function(*args, **kwargs)
        except BaseException as error:
            failure = compact_memory_error(error)
        finally:
            lease.close()
            _active.reset(token)
        raise failure from None

    return admitted


@memory_operation
async def run_memory_thread(function, *args):
    """A complete local package operation returning only compact state."""
    return await run_owned_thread(function, *args)
