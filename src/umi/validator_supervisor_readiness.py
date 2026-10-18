"""Wait for a foreground worker's bounded, identity-checked startup."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from typing import Literal

WorkerReadiness = Literal["starting", "healthy", "unhealthy"]


def emit_startup_progress(value: dict[str, object]) -> None:
    print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)


async def wait_for_worker_readiness(
    *,
    probe: Callable[[], Awaitable[WorkerReadiness]],
    process_exited: Callable[[], bool],
    budget_seconds: float,
    progress: Callable[[dict[str, object]], None] = emit_startup_progress,
) -> bool:
    """Retry creation/startup only; a dead process or wrong identity refuses.

    The caller owns cleanup, transactions and signed block clocks. The local
    startup allowance never authorizes the worker to outlive those clocks.
    """
    loop = asyncio.get_running_loop()
    started = loop.time()
    attempts = 0

    def report(status: str, completed: int) -> None:
        progress(
            {
                "stage": "supervisor_worker_startup",
                "completed": completed,
                "total": 1,
                "percent": completed * 100,
                "elapsed_seconds": loop.time() - started,
                "eta_seconds": 0 if completed else None,
                "planning_seconds": None if completed else [0, budget_seconds],
                "eta_basis": (
                    "local startup allowance; container creation and exact identity probe; "
                    "not cohort or fleet ETA"
                ),
                "status": status,
                "retrying": attempts > 1 and not completed,
                "stalled": status == "refused",
            }
        )

    report("starting", 0)
    while True:
        remaining = budget_seconds - (loop.time() - started)
        if process_exited() or remaining <= 0:
            report("refused", 0)
            return False
        attempts += 1
        try:
            state = await asyncio.wait_for(probe(), timeout=remaining)
        except asyncio.TimeoutError:
            report("refused", 0)
            return False
        if process_exited() or state == "unhealthy":
            report("refused", 0)
            return False
        if state == "healthy":
            report("ready", 1)
            return True
        remaining = budget_seconds - (loop.time() - started)
        if remaining <= 0:
            report("refused", 0)
            return False
        report("starting", 0)
        await asyncio.sleep(min(0.25, remaining))
