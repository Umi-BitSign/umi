"""The two legacy callers share recovery without importing each other's CLI."""

import ast
import asyncio
import threading
from pathlib import Path

import pytest

from tests.test_registration_bridge import NOW
from tests.test_registration_bridge_recover import recovery_case
from tests.test_registration_bridge_recover import signed_policy as signed_policy
from umi import registration_bridge as bridge
from umi import registration_bridge_recover as command
from umi.bridge import legacy_recovery
from umi.bridge.state import RegistrationBridgeState


def test_shared_recovery_keeps_existing_imports_without_a_runtime_cycle():
    for name in (
        "_event_matches",
        "_call_params",
        "prove_applied_attempt",
        "persist_recovered_attempt",
        "recover_with_client",
    ):
        assert getattr(command, name) is getattr(legacy_recovery, name)
    assert bridge.recover_with_client is legacy_recovery.recover_with_client
    tree = ast.parse(Path(legacy_recovery.__file__).read_text())
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module in {"registration_bridge", "registration_bridge_recover"}
        for node in ast.walk(tree)
    )
    for module in (legacy_recovery, bridge, command):
        tree = ast.parse(Path(module.__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert not any(
                    isinstance(child, ast.ImportFrom)
                    and child.module in {"registration_bridge", "registration_bridge_recover"}
                    for child in ast.walk(node)
                )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_cancelled_legacy_recovery_drains_publication_before_unlock(
    tmp_path, signed_policy, monkeypatch, failure
):
    journal, observation, block, events = recovery_case(signed_policy)
    root = tmp_path.resolve() / "state"
    with RegistrationBridgeState(root) as initial:
        initial.store(journal, archive=True)
    state = RegistrationBridgeState(root)
    loop = asyncio.get_running_loop()
    owner_thread = threading.get_ident()
    started = asyncio.Event()
    release, finished = threading.Event(), threading.Event()
    original = legacy_recovery.persist_recovered_attempt
    calls = []

    class Client:
        async def block_info(self, **kwargs):
            assert kwargs == {"block": block.number}
            return block

        async def query(self, item, **kwargs):
            assert item == ("System", "Events") and kwargs == {"block": block.number}
            return events

    class Chain:
        def clock(self):
            return NOW

        async def verify_finalized_receipt_with_client(self, client, receipt, **kwargs):
            assert kwargs == {"observation": observation}
            calls.append(receipt)

    def paused_publication(*args, **kwargs):
        # Fail promptly on the old event-loop implementation rather than
        # blocking the same loop that needs to release this test's write.
        assert threading.get_ident() != owner_thread, "disk publication blocks the event loop"
        try:
            loop.call_soon_threadsafe(started.set)
            if not release.wait(5):
                raise TimeoutError("test did not release legacy recovery")
            result = original(*args, **kwargs)
            if failure:
                raise OSError("injected completion failure")
            return result
        finally:
            finished.set()

    monkeypatch.setattr(legacy_recovery, "persist_recovered_attempt", paused_publication)

    async def service():
        with state:
            return await legacy_recovery.recover_with_client(
                state, journal, observation, Client(), Chain()
            )

    task = asyncio.create_task(service())
    try:
        await asyncio.wait_for(started.wait(), 2)
        assert len(calls) == 1
        for _ in range(2):
            task.cancel()
            await asyncio.sleep(0.025)
        assert not task.done()
        with pytest.raises(BlockingIOError), RegistrationBridgeState(root):
            pass
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled()
    assert finished.is_set()
    with RegistrationBridgeState(root) as reopened:
        assert reopened.load().phase == "applied"
