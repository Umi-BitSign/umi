import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from umi.competition_chain import FinalizedRegistrationProvider
from umi.competition_service_supervision import run_supervised_server

from .test_competition_progress import progress_events as progress_events


class Server:
    def __init__(self):
        self.started = self.should_exit = self.closed = False
        self.server_state = SimpleNamespace(tasks=set())

    async def serve(self):
        self.started = True
        try:
            while not self.should_exit:
                await asyncio.sleep(0.001)
        finally:
            # Match Uvicorn: cancel overdue requests without waiting for their
            # cancellation handlers. The supervisor must then retain ownership.
            for task in self.server_state.tasks:
                task.cancel()
            self.closed = True


async def test_shutdown_grace_does_not_replace_original_owned_failure(monkeypatch):
    from umi import competition_service_supervision as supervision

    class SlowServer(Server):
        async def serve(self):
            self.started = True
            try:
                await asyncio.Event().wait()
            finally:
                self.closed = True

    stopped = asyncio.create_task(asyncio.sleep(0))
    await stopped
    server = SlowServer()
    monkeypatch.setattr(supervision, "_SERVER_SHUTDOWN_SECONDS", 0.01)
    with pytest.raises(RuntimeError, match="owned_finality_observer_stopped"):
        await run_supervised_server(server, (provider(stopped),), poll_seconds=0.001)
    assert server.closed and server.should_exit


@pytest.mark.parametrize("failure_source", ["provider", "owned_task"])
async def test_original_failure_is_reported_before_owned_request_cleanup(
    failure_source, progress_events
):
    server = Server()
    entered, cancelling, release = (asyncio.Event() for _ in range(3))

    async def request():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelling.set()
            await release.wait()

    async def failed():
        raise ValueError("private diagnostic and https://secret.invalid/bearer")

    request_task = asyncio.create_task(request())
    dead = asyncio.create_task(failed())
    await entered.wait()
    await asyncio.gather(dead, return_exceptions=True)
    server.server_state.tasks.add(request_task)
    running = asyncio.create_task(
        run_supervised_server(
            server,
            (provider(dead),) if failure_source == "provider" else (),
            liveness_tasks=lambda: (dead,) if failure_source == "owned_task" else (),
            poll_seconds=0.001,
        )
    )
    try:
        await asyncio.wait_for(cancelling.wait(), timeout=3)
        assert not running.done()
        failures = [e for e in progress_events if e["event"] == "failed"]
        assert len(failures) == 1 and failures[0]["phase"] == "host_service"
        if failure_source == "provider":
            assert failures[0]["reason_code"] == "owned_finality_observer_stopped"
        else:
            assert failures[0]["reason_code"] == "validation_failed"
        import json

        assert "secret.invalid" not in json.dumps(progress_events)
        assert "private diagnostic" not in json.dumps(progress_events)
        release.set()
        with pytest.raises((ValueError, RuntimeError)):
            await asyncio.wait_for(running, timeout=3)
        assert request_task.done()
    finally:
        release.set()
        await asyncio.gather(running, request_task, return_exceptions=True)


async def test_supervisor_retains_cancelled_request_cleanup_on_repeated_cancellation():
    server = Server()
    entered, cancelling, release, finished = (asyncio.Event() for _ in range(4))

    async def request():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelling.set()
            await release.wait()
            finished.set()

    request_task = asyncio.create_task(request())
    server.server_state.tasks.add(request_task)
    await entered.wait()
    running = asyncio.create_task(run_supervised_server(server, (), poll_seconds=0.001))
    try:
        await asyncio.sleep(0.01)
        server.should_exit = True
        await asyncio.wait_for(cancelling.wait(), timeout=3)
        running.cancel()
        await asyncio.sleep(0.01)
        running.cancel()
        await asyncio.sleep(0.01)
        assert not running.done() and not finished.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(running, timeout=3)
        assert finished.is_set() and request_task.done()
    finally:
        release.set()
        await asyncio.gather(running, request_task, return_exceptions=True)


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


@pytest.mark.parametrize("termination", ["exception", "return", "cancel"])
async def test_terminal_owned_service_task_stops_http_service(termination):
    async def worker():
        if termination == "exception":
            raise ValueError("owned service failed")
        if termination == "cancel":
            await asyncio.Event().wait()

    task = asyncio.create_task(worker())
    if termination == "cancel":
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    server = Server()
    expected = (
        "owned service failed" if termination == "exception" else "owned_service_task_stopped"
    )
    with pytest.raises((ValueError, RuntimeError), match=expected):
        await run_supervised_server(
            server,
            (),
            liveness_tasks=lambda: (task,),
            poll_seconds=0.001,
        )
    assert server.closed and server.should_exit


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
