from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_dispatch as module
from umi.open_competition import identity
from umi.private_files import lock_private_file

from .test_competition_dispatch import authorization as authorization
from .test_competition_dispatch import dispatch as dispatch
from .test_competition_dispatch import feed as feed
from .test_open_competition import policy as policy


@pytest.fixture
def service(dispatch, monkeypatch):
    """Production opener with no network, subprocess or HTTP test workload."""
    state = SimpleNamespace(
        failure=None,
        calls=[],
        hold=None,
        entered={
            name: asyncio.Event()
            for name in ("start", "poll", "drain", "dispatch_close", "provider_close")
        },
        release={
            name: asyncio.Event()
            for name in ("start", "poll", "drain", "dispatch_close", "provider_close")
        },
    )

    def step(name):
        state.calls.append(name)
        if state.failure == name:
            raise RuntimeError(name)

    async def async_step(name):
        step(name)
        state.entered[name].set()
        if name in (state.hold or ()):
            await state.release[name].wait()

    class Provider:
        def __init__(self, *args):
            step("provider_constructor")

        async def start(self):
            await async_step("start")

        def ensure_observer_running(self):
            step("ensure")

        async def aclose(self):
            await async_step("provider_close")

    class Dispatcher:
        def __init__(self, *args):
            step("dispatch_constructor")
            self._tasks = {}
            self._counts = {"completed": 0, "held": 0, "uncertain": 0}

        async def poll_once(self):
            await async_step("poll")
            return {"in_flight": 0, "no_weight": True}

        async def drain(self):
            await async_step("drain")

        async def aclose(self):
            await async_step("dispatch_close")

    monkeypatch.setattr("bittensor.Wallet", lambda **_kw: dispatch.feed.item.validator_wallet)
    monkeypatch.setattr(module, "DispatchFinalityProvider", Provider)
    monkeypatch.setattr(module, "EndpointDispatcher", Dispatcher)
    state.lock = Path(dispatch.config.journal_directory) / (
        f".dispatch-{identity(dispatch.config.evaluator_hotkey)}.lock"
    )

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "add_signal_handler", lambda *args: None)
        monkeypatch.setattr(loop, "remove_signal_handler", lambda *args: True)
        return await module.run_dispatch(
            dispatch.config,
            dispatch.feed.item.policy,
            dispatch.feed.item.legacy_policy,
            once=True,
            report=lambda _status: step("report"),
        )

    state.run = run
    return state


def assert_locked(path):
    try:
        fd = lock_private_file(path)
    except BlockingIOError:
        return
    os.close(fd)
    pytest.fail("dispatcher service lease released before cleanup completed")


def assert_released(path):
    os.close(lock_private_file(path))


async def test_second_service_fails_before_constructing_or_starting_provider(service):
    service.hold = {"poll"}
    owner = asyncio.create_task(service.run())
    try:
        await service.entered["poll"].wait()
        assert_locked(service.lock)
        with pytest.raises(BlockingIOError):
            await service.run()
        assert service.calls.count("provider_constructor") == 1
        assert service.calls.count("start") == 1
        service.release["poll"].set()
        await owner
        assert_released(service.lock)
        await service.run()
        assert service.calls.count("provider_constructor") == 2
        assert service.calls.count("provider_close") == 2
    finally:
        service.release["poll"].set()
        owner.cancel()
        await asyncio.gather(owner, return_exceptions=True)


@pytest.mark.parametrize("cancellation_stage", ["start", "poll", "drain"])
@pytest.mark.parametrize("repeated_cancels", [0, 3])
async def test_cancelled_service_owns_lease_through_both_cleanup_stages(
    service,
    cancellation_stage,
    repeated_cancels,
):
    service.hold = {cancellation_stage, "dispatch_close", "provider_close"}
    owner = asyncio.create_task(service.run())
    try:
        await service.entered[cancellation_stage].wait()
        owner.cancel()
        await service.entered["dispatch_close"].wait()
        for _ in range(repeated_cancels):
            owner.cancel()
            await asyncio.sleep(0)
            assert_locked(service.lock)
            assert not owner.done()
        assert not service.entered["provider_close"].is_set()
        service.release["dispatch_close"].set()
        await service.entered["provider_close"].wait()
        for _ in range(repeated_cancels):
            owner.cancel()
            await asyncio.sleep(0)
            assert_locked(service.lock)
            assert not owner.done()
        assert_locked(service.lock)
        service.release["provider_close"].set()
        with pytest.raises(asyncio.CancelledError):
            await owner
        assert service.calls.count("dispatch_close") == 1
        assert service.calls.count("provider_close") == 1
        assert_released(service.lock)
    finally:
        for event in service.release.values():
            event.set()
        owner.cancel()
        await asyncio.gather(owner, return_exceptions=True)


@pytest.mark.parametrize(
    "failure",
    [
        "provider_constructor",
        "dispatch_constructor",
        "start",
        "ensure",
        "poll",
        "drain",
        "report",
        "dispatch_close",
        "provider_close",
    ],
)
async def test_service_releases_lease_after_initialization_runtime_or_cleanup_error(
    service, failure
):
    service.failure = failure
    with pytest.raises(RuntimeError, match=failure):
        await service.run()
    assert_released(service.lock)
    if failure != "provider_constructor":
        assert service.calls.count("provider_close") == 1
    if failure not in {"provider_constructor", "dispatch_constructor"}:
        assert service.calls.count("dispatch_close") == 1
