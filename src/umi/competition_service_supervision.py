"""Exit idle HTTP services when an owned finality task terminates."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from .concurrency import await_owned_task


async def drain_server_requests(server):
    """Retain ownership until cancelled HTTP requests finish durable cleanup.

    Uvicorn cancels overdue requests but can return before their cancellation
    handlers finish. Call this after serving stops, before releasing host locks.
    """

    async def drain():
        tasks = tuple(server.server_state.tasks)
        for task in tasks:
            if not task.done() and not task.cancelling():
                task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError, Exception):
                await await_owned_task(task)

    await await_owned_task(asyncio.create_task(drain()))


async def run_supervised_server(server, providers, *, liveness_tasks=lambda: (), poll_seconds=1.0):
    serving = asyncio.create_task(server.serve())
    try:
        while not serving.done():
            if server.started and not server.should_exit:
                for provider in providers:
                    provider.ensure_observer_running()
                for task in liveness_tasks():
                    if task.done():
                        if task.cancelled():
                            raise RuntimeError("owned_service_task_stopped")
                        task.result()
                        raise RuntimeError("owned_service_task_stopped")
            await asyncio.wait((serving,), timeout=poll_seconds)
        await serving
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(asyncio.shield(serving), timeout=35)
        finally:
            if not serving.done():
                serving.cancel()
            try:
                await asyncio.gather(serving, return_exceptions=True)
            finally:
                await drain_server_requests(server)


def serve_with_finality_supervision(app, *, liveness_tasks=lambda: (), **options):
    import uvicorn

    # Request draining is bounded; lifespan shutdown still closes the providers
    # and retains their journals. The external service manager owns restart.
    config = uvicorn.Config(app, timeout_graceful_shutdown=15, **options)
    asyncio.run(
        run_supervised_server(
            uvicorn.Server(config),
            app.state.finality_providers,
            liveness_tasks=liveness_tasks,
        )
    )
