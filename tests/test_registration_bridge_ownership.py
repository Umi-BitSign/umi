"""A cancelled bridge iteration must drain history writes before unlock."""

import asyncio
import threading

import pytest

import umi.registration_bridge as bridge
from tests.test_registration_bridge_runtime import (
    REVISION,
    Chain,
    healthy,
    writer_observation,
)
from tests.test_registration_bridge_runtime import signed_policy as signed_policy
from tests.test_registration_bridge_runtime import wallet as wallet


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_cancelled_history_write_keeps_service_lock_until_drained(
    tmp_path, signed_policy, wallet, monkeypatch, failure
):
    root = tmp_path.resolve() / "state"
    state = bridge.RegistrationBridgeState(root)
    before = writer_observation(wallet)
    chain = Chain(state, [before])
    started = asyncio.Event()
    release, finished = threading.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    write = bridge._write_new
    initialize = state.initialize

    def paused_write(path, payload):
        if path.name.startswith(".registration-bridge-"):
            loop.call_soon_threadsafe(started.set)
            if not release.wait(5):
                raise TimeoutError("test did not release the owned write")
        write(path, payload)

    def owned_initialize(*args, **kwargs):
        try:
            result = initialize(*args, **kwargs)
            if failure:
                raise RuntimeError("injected history initialization failure")
            return result
        finally:
            finished.set()

    monkeypatch.setattr(bridge, "_write_new", paused_write)
    monkeypatch.setattr(state, "initialize", owned_initialize)

    async def service():
        with state:
            return await bridge.run_registration_bridge_iteration(
                signed_policy,
                wallet=wallet,
                chain=chain,
                state=state,
                expected_revision=REVISION,
                directive_valid_from=signed_policy.body.valid_from_block,
                directive_valid_through=signed_policy.body.hard_sunset_block - 1,
                request=healthy,
            )

    task = asyncio.create_task(service())
    try:
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        await asyncio.sleep(0.025)
        task.cancel()
        await asyncio.sleep(0.025)
        assert not task.done(), "service released ownership while history was still writing"
        with pytest.raises(BlockingIOError), bridge.RegistrationBridgeState(root):
            pass
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not chain.client.calls
    with bridge.RegistrationBridgeState(root) as reopened:
        assert reopened.load().phase == "idle"
