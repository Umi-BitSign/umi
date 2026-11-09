"""Kernel-lived work demand for bounded transfer and graph scheduling courtesy.

The read OFD marker is on the existing transaction file, separate from its flock
and every slot/container witness. It reserves no capacity. Old readers ignore
it; every actual grant still uses the unchanged native memory admission path.
Export demand uses byte zero and ready model demand uses byte one.
"""

import asyncio
import fcntl
import os
import time
from contextlib import contextmanager

from .competition_transport_verification import TransferProgress
from .host_memory_peer import _command

MAX_EXPORT_TURN_SECONDS = 1.0
MAX_MODEL_TURN_SECONDS = 1.0


def _open(controller):
    parent = controller._open_root()
    try:
        return controller._open_slot(parent, controller.policy.transaction_lock)
    finally:
        os.close(parent)


@contextmanager
def _waiter(controller, enabled, offset):
    descriptor = None
    try:
        if controller.peer_execution_stage and enabled:
            descriptor = _open(controller)
            _command(descriptor, "F_OFD_SETLK", fcntl.F_RDLCK, offset, 1)
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)


def export_waiter(controller, lane):
    return _waiter(controller, lane == "owner_export", 0)


def model_waiter(controller, lane):
    return _waiter(controller, lane == "transient", 1)


def _waiting(controller, offset):
    if not controller.peer_execution_stage:
        return False
    descriptor = _open(controller)
    try:
        row = _command(descriptor, "F_OFD_GETLK", fcntl.F_WRLCK, offset, 1)
        if row.type == fcntl.F_UNLCK:
            return False
        if (row.type, row.whence, row.start, row.length, row.pid) != (
            fcntl.F_RDLCK,
            os.SEEK_SET,
            offset,
            1,
            -1,
        ):
            raise ValueError("work demand has unsupported kernel lock geometry")
        return True
    finally:
        os.close(descriptor)


def export_waiting(controller):
    return _waiting(controller, 0)


def model_waiting(controller):
    return _waiting(controller, 1)


async def yield_to_models(controller, lane, retry_seconds):
    """Let a ready invocation compete before a new transient graph allocation.

    Each courtesy ends after one second even if the model cannot fit. Existing
    graphs drain normally; neither retained capacity nor export work yields.
    No inference, buffer or graph is allocated by this scheduling marker.
    """
    if lane != "transient" or not controller.peer_execution_stage:
        return
    if any(
        not lease.closed
        and lease._creator_pid == os.getpid()
        and lease.slot.lane == "settlement_retained"
        and lease._graph_binding is not None
        for lease in tuple(controller._model_leases)
    ):
        return
    if not model_waiting(controller):
        return
    until = time.monotonic() + MAX_MODEL_TURN_SECONDS
    with TransferProgress(
        "graph_model_turn", 1, unit="turns", planning_unit_seconds=(0, MAX_MODEL_TURN_SECONDS)
    ) as progress:
        progress.emit("waiting", reason="model_invocation_waiting")
        while model_waiting(controller):
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(retry_seconds, remaining))
        progress.advance(1)


async def yield_to_export(controller, retry_seconds):
    """Give waiting exports a turn after a drained range, without indefinite delay.

    A slow or capacity-blocked exporter cannot hold a model transfer forever.
    The transfer reacquires its ordinary grant after this bounded courtesy; no
    inference lease is released and no request or signed budget is shortened.
    """
    if not export_waiting(controller):
        return
    until = time.monotonic() + MAX_EXPORT_TURN_SECONDS
    with TransferProgress(
        "model_preparation_export_turn",
        1,
        unit="turns",
        planning_unit_seconds=(0, MAX_EXPORT_TURN_SECONDS),
    ) as progress:
        progress.emit("waiting", reason="owner_export_waiting")
        while export_waiting(controller):
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(retry_seconds, remaining))
        progress.advance(1)
