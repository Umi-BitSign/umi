from __future__ import annotations

import asyncio
from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
import uvicorn

from umi import miner as miner_module
from umi.grandpa_finality_supervisor import DurableGrandpaFinalityPort
from umi.miner import TRANSLATE_PATH, create_app

from .test_miner_transport import LifecycleProbeTranslator, runtime


class ControlledFinality(DurableGrandpaFinalityPort):
    """Exercise lifecycle supervision without spawning a real observer."""

    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        self.release = asyncio.Event()
        self.finished = asyncio.Event()

    async def run(self, stop_event: asyncio.Event) -> None:
        try:
            if self.outcome == "normal_stop":
                await stop_event.wait()
                return
            await self.release.wait()
            if self.outcome == "error":
                raise RuntimeError("private observer diagnostic")
            if self.outcome == "cancelled":
                raise asyncio.CancelledError
        finally:
            self.finished.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["error", "returned", "cancelled"])
async def test_terminal_finality_fails_health_and_work_and_always_cleans_up(outcome):
    finality = ControlledFinality(outcome)
    translator = LifecycleProbeTranslator(asyncio.Event(), asyncio.Event())
    miner = replace(runtime(translator=translator), finality_service=finality)
    notified = asyncio.Event()
    failures = []

    def failed(name):
        failures.append(name)
        notified.set()

    app = create_app(miner, on_background_failure=failed)
    expected = (
        pytest.raises(RuntimeError, match="private observer diagnostic")
        if outcome == "error"
        else nullcontext()
    )
    try:
        with expected:
            async with app.router.lifespan_context(app):
                assert translator.startup_entered.is_set()
                finality.release.set()
                await asyncio.wait_for(notified.wait(), 1)
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://miner.test"
                ) as client:
                    for _ in range(2):
                        health = await client.get("/healthz")
                        assert health.status_code == 503
                        assert health.json()["ok"] is False
                        assert health.json()["background_failure"] == "finality"
                        assert "private observer diagnostic" not in health.text
                    work = await client.post(TRANSLATE_PATH, content=b"untrusted")
                    assert work.status_code == 503
                    assert work.json()["detail"] == "miner_background_service_failed"
        assert failures == ["finality"]
        assert translator.shutdown_entered.is_set()
    finally:
        miner.resource_ledger.close()


@pytest.mark.asyncio
async def test_immediate_finality_startup_failure_still_closes_translator():
    finality = ControlledFinality("error")
    finality.release.set()
    translator = LifecycleProbeTranslator(asyncio.Event(), asyncio.Event())
    miner = replace(runtime(translator=translator), finality_service=finality)
    app = create_app(miner)
    try:
        with pytest.raises(RuntimeError, match="private observer diagnostic"):
            async with app.router.lifespan_context(app):
                pytest.fail("a failed finality startup must not serve")
        assert translator.shutdown_entered.is_set()
    finally:
        miner.resource_ledger.close()


@pytest.mark.asyncio
async def test_normal_finality_shutdown_does_not_signal_failure():
    finality = ControlledFinality("normal_stop")
    miner = replace(runtime(), finality_service=finality)
    failures = []
    app = create_app(miner, on_background_failure=failures.append)
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://miner.test"
            ) as client,
        ):
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["finality_service"] == "running"
        assert finality.finished.is_set()
        assert app.state.background_failure is None
        assert not failures
    finally:
        miner.resource_ledger.close()


@pytest.mark.parametrize("outcome", ["error", "returned", "cancelled", "normal_stop"])
def test_main_exits_unsuccessfully_after_terminal_background_task(monkeypatch, outcome):
    finality = ControlledFinality(outcome)
    translator = LifecycleProbeTranslator(asyncio.Event(), asyncio.Event())
    miner = replace(runtime(translator=translator), finality_service=finality)
    closed = []
    original_close = miner.resource_ledger.close

    def close():
        closed.append(True)
        original_close()

    monkeypatch.setattr(miner.resource_ledger, "close", close)
    monkeypatch.setattr(miner_module, "build_runtime", lambda _args: miner)
    monkeypatch.setattr(
        miner_module,
        "_parser",
        lambda: SimpleNamespace(
            parse_args=lambda: SimpleNamespace(log_level="WARNING", listen_host="127.0.0.1", port=0)
        ),
    )

    def run(server):
        async def lifecycle():
            app = server.config.app
            expected = (
                pytest.raises(RuntimeError, match="private observer diagnostic")
                if outcome == "error"
                else nullcontext()
            )
            with expected:
                async with app.router.lifespan_context(app):
                    server.started = True
                    if outcome != "normal_stop":
                        finality.release.set()
                        await asyncio.wait_for(finality.finished.wait(), 1)
                        # The task's done callback runs on the next loop turn.
                        await asyncio.sleep(0)
                        assert server.should_exit
                    else:
                        assert not server.should_exit

        asyncio.run(lifecycle())

    monkeypatch.setattr(uvicorn.Server, "run", run)
    expected = (
        nullcontext()
        if outcome == "normal_stop"
        else pytest.raises(RuntimeError, match="miner background service stopped: finality")
    )
    with expected:
        miner_module.main()
    assert closed == [True]
    assert translator.shutdown_entered.is_set()


def test_main_reports_failed_http_startup_and_closes_ledger(monkeypatch):
    miner = runtime()
    closed = []
    original_close = miner.resource_ledger.close

    def close():
        closed.append(True)
        original_close()

    monkeypatch.setattr(miner.resource_ledger, "close", close)
    monkeypatch.setattr(miner_module, "build_runtime", lambda _args: miner)
    monkeypatch.setattr(
        miner_module,
        "_parser",
        lambda: SimpleNamespace(
            parse_args=lambda: SimpleNamespace(log_level="WARNING", listen_host="127.0.0.1", port=0)
        ),
    )
    monkeypatch.setattr(uvicorn.Server, "run", lambda _server: None)
    with pytest.raises(RuntimeError, match="miner HTTP startup failed"):
        miner_module.main()
    assert closed == [True]


def test_real_http_server_stops_after_finality_failure(monkeypatch):
    finality = ControlledFinality("error")
    translator = LifecycleProbeTranslator(asyncio.Event(), asyncio.Event())
    miner = replace(runtime(translator=translator), finality_service=finality)
    original_startup = uvicorn.Server.startup
    servers = []

    async def startup(server, sockets=None):
        await original_startup(server, sockets=sockets)
        assert server.started
        servers.append(server)
        finality.release.set()

    monkeypatch.setattr(uvicorn.Server, "startup", startup)
    monkeypatch.setattr(miner_module, "build_runtime", lambda _args: miner)
    monkeypatch.setattr(
        miner_module,
        "_parser",
        lambda: SimpleNamespace(
            parse_args=lambda: SimpleNamespace(log_level="WARNING", listen_host="127.0.0.1", port=0)
        ),
    )
    with pytest.raises(RuntimeError, match="miner background service stopped: finality"):
        miner_module.main()
    assert len(servers) == 1
    assert servers[0].should_exit
    assert all(not listener.is_serving() for listener in servers[0].servers)
    assert translator.shutdown_entered.is_set()
