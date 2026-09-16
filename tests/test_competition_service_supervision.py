import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from umi.competition_chain import FinalizedRegistrationProvider
from umi.competition_service_supervision import run_supervised_server


class Server:
    def __init__(self):
        self.started = self.should_exit = self.closed = False

    async def serve(self):
        self.started = True
        try:
            while not self.should_exit:
                await asyncio.sleep(0.001)
        finally:
            self.closed = True


def provider(task, *, owned=True, closed=False):
    value = SimpleNamespace(_owned=owned, _closed=closed, _task=task)
    value.ensure_observer_running = lambda: FinalizedRegistrationProvider.ensure_observer_running(
        value
    )
    return value


@pytest.mark.parametrize("termination", ["exception", "return", "cancel"])
async def test_terminal_observer_exits_idle_http_service(termination):
    async def observer():
        if termination == "exception":
            raise ValueError("private diagnostic must not appear")
        if termination == "cancel":
            await asyncio.Event().wait()

    task = asyncio.create_task(observer())
    if termination == "cancel":
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    server = Server()
    with pytest.raises(RuntimeError, match=r"^owned_finality_observer_stopped$"):
        await run_supervised_server(server, (provider(task),), poll_seconds=0.001)
    assert server.closed and server.should_exit


async def test_live_observer_wait_is_not_mistaken_for_failure():
    task = asyncio.create_task(asyncio.Event().wait())
    server = Server()
    running = asyncio.create_task(
        run_supervised_server(server, (provider(task),), poll_seconds=0.001)
    )
    try:
        await asyncio.sleep(0.02)
        assert not running.done() and not server.should_exit
        server.should_exit = True
        await running
        assert server.closed and not task.done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_failure_of_second_observer_stops_service():
    live = asyncio.create_task(asyncio.Event().wait())
    dead = asyncio.create_task(asyncio.sleep(0))
    await dead
    try:
        with pytest.raises(RuntimeError, match="owned_finality_observer_stopped"):
            await run_supervised_server(
                Server(), (provider(live), provider(dead)), poll_seconds=0.001
            )
    finally:
        live.cancel()
        await asyncio.gather(live, return_exceptions=True)


def test_observer_must_have_started_and_not_be_closed():
    with pytest.raises(RuntimeError, match="observer_stopped"):
        provider(None).ensure_observer_running()
    with pytest.raises(RuntimeError, match="provider_closed"):
        provider(None, closed=True).ensure_observer_running()
    provider(None, owned=False).ensure_observer_running()


async def test_real_uvicorn_closes_lifespan_after_observer_failure():
    import uvicorn
    from fastapi import FastAPI

    entered, stopped, fail = asyncio.Event(), asyncio.Event(), asyncio.Event()
    source = provider(None)

    async def observer():
        await fail.wait()
        raise RuntimeError("private observer failure")

    @asynccontextmanager
    async def lifespan(_):
        source._task = asyncio.create_task(observer())
        entered.set()
        try:
            yield
        finally:
            await asyncio.gather(source._task, return_exceptions=True)
            source._closed = True
            stopped.set()

    app = FastAPI(lifespan=lifespan)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=0, access_log=False, log_level="critical")
    )
    running = asyncio.create_task(run_supervised_server(server, (source,), poll_seconds=0.001))
    await asyncio.wait_for(entered.wait(), timeout=3)
    fail.set()
    with pytest.raises(RuntimeError, match="owned_finality_observer_stopped"):
        await asyncio.wait_for(running, timeout=3)
    assert stopped.is_set() and source._closed
