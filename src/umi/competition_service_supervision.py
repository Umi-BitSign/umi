"""Exit idle HTTP services when an owned finality task terminates."""

from __future__ import annotations

import asyncio


async def run_supervised_server(server, providers, *, poll_seconds=1.0):
    serving = asyncio.create_task(server.serve())
    try:
        while not serving.done():
            if server.started and not server.should_exit:
                for provider in providers:
                    provider.ensure_observer_running()
            await asyncio.wait((serving,), timeout=poll_seconds)
        await serving
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(asyncio.shield(serving), timeout=35)
        finally:
            if not serving.done():
                serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)


def serve_with_finality_supervision(app, **options):
    import uvicorn

    # Request draining is bounded; lifespan shutdown still closes the providers
    # and retains their journals. The external service manager owns restart.
    config = uvicorn.Config(app, timeout_graceful_shutdown=15, **options)
    asyncio.run(run_supervised_server(uvicorn.Server(config), app.state.finality_providers))
