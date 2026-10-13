"""Explicit process-group ownership for native tools inside spawned workers.

Ordinary tools own a separate session. A spawned history process owns a whole
session on behalf of its parent; its pinned Rust tools do not spawn children,
so individual tool deadlines kill/reap that tool while preserving peer work.
The parent kills the worker's complete group on abnormal exit before reaping
its child and releasing the PID, closing the subprocess-orphan failure window.
"""

import os
import signal
from contextlib import contextmanager
from contextvars import ContextVar

_group: ContextVar[int | None] = ContextVar("owned_native_process_group", default=None)


@contextmanager
def owned_native_process_group():
    if os.getpid() != os.getpgrp() or os.getsid(0) != os.getpid():
        raise RuntimeError("native worker must own its process session")
    token = _group.set(os.getpid())
    try:
        yield
    finally:
        _group.reset(token)


def native_start_new_session():
    group = _group.get()
    if group is not None and os.getpgrp() != group:
        raise RuntimeError("native worker process-group ownership changed")
    return group is None


def kill_native_process(process):
    if not native_start_new_session():
        # These pinned Rust tools execute in process and cannot create children.
        # Killing the group here would kill the worker and its independent proof.
        process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, OSError):
        process.kill()
