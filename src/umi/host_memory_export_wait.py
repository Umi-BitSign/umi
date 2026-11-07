"""Kernel-lived export demand for bounded model-transfer scheduling courtesy.

The read OFD marker is on the existing transaction file, separate from its flock
and every slot/container witness. It reserves no capacity. Old readers ignore
it; every actual grant still uses the unchanged native memory admission path.
"""

import asyncio
import fcntl
import os
import time
from contextlib import contextmanager

from .competition_transport_verification import TransferProgress
from .host_memory_peer import _command

MAX_EXPORT_TURN_SECONDS = 1.0


def _open(controller):
    parent = controller._open_root()
    try:
        return controller._open_slot(parent, controller.policy.transaction_lock)
    finally:
        os.close(parent)


@contextmanager
def export_waiter(controller, lane):
    descriptor = None
    try:
        if controller.peer_execution_stage and lane == "owner_export":
            descriptor = _open(controller)
            _command(descriptor, "F_OFD_SETLK", fcntl.F_RDLCK, 0, 1)
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)


def export_waiting(controller):
    if not controller.peer_execution_stage:
        return False
    descriptor = _open(controller)
    try:
        row = _command(descriptor, "F_OFD_GETLK", fcntl.F_WRLCK, 0, 1)
        if row.type == fcntl.F_UNLCK:
            return False
        if (row.type, row.whence, row.start, row.length, row.pid) != (
            fcntl.F_RDLCK,
            os.SEEK_SET,
            0,
            1,
            -1,
        ):
            raise ValueError("export demand has unsupported kernel lock geometry")
        return True
    finally:
        os.close(descriptor)


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
