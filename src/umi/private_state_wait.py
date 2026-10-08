"""Bounded waits for validated local mutex contention, with owned thread cleanup."""

import asyncio

from .concurrency import run_owned_thread
from .private_files import PrivateStateBusyError


async def run_private_state_operation(function, *args, timeout: float):
    """Retry only acquisition contention; callers must recollect mutable authority.

    Each attempt drains before another starts. Validation, permissions, I/O and
    corrupt-state failures propagate unchanged. Cancellation cannot abandon a
    thread holding a journal lock. This helper is for static reads and native
    idempotent writes, not for extending a previously collected chain head.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    delay = 0.05
    while True:
        try:
            return await run_owned_thread(function, *args)
        except PrivateStateBusyError:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise
            await asyncio.sleep(min(delay, remaining))
            delay = min(1.0, delay * 2)
