"""Check virtual-process transport isolation without native pipeline fixtures."""

import asyncio
import threading
from contextvars import ContextVar

import httpx
import pytest

from umi import host_memory_runtime as memory
from umi.concurrency import run_owned_thread

from .cohort_native_memory_fixture import isolated_asgi_transport
from .test_host_memory_admission import provisioned as provisioned


@pytest.mark.parametrize("fail", [False, True])
async def test_http_role_starts_in_clean_selected_context_and_returns_errors(provisioned, fail):
    selection = memory.HostMemoryAdmissionSelection(
        policy_path=str(provisioned[1]), policy_sha256=provisioned[4]
    )
    caller = ContextVar("native_transport_caller", default="new-process")
    caller.set("reviewer")
    calls = []

    async def app(scope, receive, send):
        assert caller.get() == "new-process"
        assert memory._active.get() is None
        controller = memory.selected_memory()
        assert controller.policy_sha256 == selection.policy_sha256
        assert controller.try_acquire("transient") is None
        async with controller.hold("owner_export"):
            calls.append("owner-export")
            if fail:
                raise ValueError("original HTTP failure")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"native-response"})

    transport = isolated_asgi_transport(httpx.ASGITransport, selection, 1024)(app=app)
    with memory.memory_runtime(selection, maximum_aggregate_bytes=1024) as controller:
        async with httpx.AsyncClient(transport=transport) as client:

            @memory.memory_operation
            async def review():
                return await client.get("https://owner.example/native")

            if fail:
                with pytest.raises(ValueError, match="original HTTP failure"):
                    await review()
            else:
                assert (await review()).content == b"native-response"
        assert caller.get() == "reviewer"
        for lane in ("transient", "owner_export"):
            lease = controller.try_acquire(lane)
            assert lease is not None
            lease.close()
    assert calls == ["owner-export"]


async def test_isolated_http_task_drains_owned_work_on_repeated_cancellation(provisioned):
    selection = memory.HostMemoryAdmissionSelection(
        policy_path=str(provisioned[1]), policy_sha256=provisioned[4]
    )
    entered, release = threading.Event(), threading.Event()

    def work():
        entered.set()
        assert release.wait(10)

    async def app(scope, receive, send):
        assert memory._active.get() is None
        async with memory.selected_memory().hold("owner_export"):
            await run_owned_thread(work)

    transport = isolated_asgi_transport(httpx.ASGITransport, selection, 1024)(app=app)
    with memory.memory_runtime(selection, maximum_aggregate_bytes=1024) as controller:
        async with httpx.AsyncClient(transport=transport) as client:

            @memory.memory_operation
            async def review():
                return await client.get("https://owner.example/native")

            task = asyncio.create_task(review())
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
                assert controller.try_acquire("transient") is None
                assert controller.try_acquire("owner_export") is None
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await task
                for lane in ("transient", "owner_export"):
                    lease = controller.try_acquire(lane)
                    assert lease is not None
                    lease.close()
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
