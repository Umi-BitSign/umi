"""Ownership across native preparation and the coordinator's later capture."""

import asyncio
import sqlite3
import threading
from contextlib import contextmanager

import pytest

from umi.competition_cohort_request_preparation import prepared_request_thread


@pytest.mark.parametrize("stage", ["enter", "capture", "sample", "exit"])
async def test_cancelled_preparation_drains_same_thread_and_releases_context(stage):
    loop = asyncio.get_running_loop()
    blocked, cleanup = asyncio.Event(), asyncio.Event()
    release = threading.Event()
    done = threading.Event()
    threads, exits = [], []

    def wait(which):
        threads.append(threading.get_ident())
        if stage == which:
            loop.call_soon_threadsafe(blocked.set)
            assert release.wait(30), "test must release native operation"

    @contextmanager
    def native():
        db = sqlite3.connect(":memory:")
        try:
            wait("enter")

            def sample(value):
                wait("sample")
                return db.execute("SELECT ?", (value,)).fetchone()[0]

            try:
                yield sample
            except BaseException as error:
                exits.append(type(error))
                raise
        finally:
            loop.call_soon_threadsafe(cleanup.set)
            wait("exit")
            db.close()
            done.set()

    async def work():
        async with prepared_request_thread(native()) as sample:
            if stage == "capture":
                blocked.set()
                await asyncio.Event().wait()
            assert await sample(42) == 42

    task = asyncio.create_task(work())
    try:
        await asyncio.wait_for(blocked.wait(), 30)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        if stage != "capture":
            assert not task.done() and not done.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 30)
        assert done.is_set() and cleanup.is_set()
        assert len(set(threads)) == 1 and threads[0] != threading.get_ident()
        if stage != "exit":
            assert exits == [asyncio.CancelledError]
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("stage", ["enter", "capture", "sample", "exit"])
async def test_native_preparation_keeps_original_errors_and_closes_resources(stage):
    from umi.host_memory_runtime import memory_operation_context, memory_runtime

    error = OSError("native preparation failure")
    closed = []

    @contextmanager
    def native():
        try:
            if stage == "enter":
                raise error

            def sample(value):
                if stage == "sample":
                    raise error
                return value

            yield sample
            if stage == "exit":
                raise error
        finally:
            closed.append(True)

    with (
        memory_runtime(None, maximum_aggregate_bytes=4 * 1024**3),
        pytest.raises(OSError) as caught,
    ):
        async with (
            memory_operation_context(
                operation="requests_observe", cohort="6" * 64, phase="requests"
            ),
            prepared_request_thread(native()) as sample,
        ):
            if stage == "capture":
                raise error
            assert await sample(42) == 42
    assert caught.value is error and closed == [True]


async def test_prepared_sampler_is_single_use_and_cannot_outlive_its_context():
    calls = []

    @contextmanager
    def native():
        yield lambda capture: calls.append(capture) or 42

    capture = object()
    async with prepared_request_thread(native()) as sample:
        assert await sample(capture) == 42
        with pytest.raises(RuntimeError, match="no longer available"):
            await sample(object())
    with pytest.raises(RuntimeError, match="no longer available"):
        await sample(object())
    assert calls == [capture]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "nonce",
        "policy",
        "cohort",
        "tip",
        "catalog",
        "gap",
        "hash",
        "root",
        "unready",
        "http",
        "reused",
    ],
)
async def test_prepared_readiness_validates_the_eventual_capture_and_attempt_nonce(fault):
    from types import SimpleNamespace

    import httpx

    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver, RequestReadiness
    from umi.competition_execution import execution_boundary
    from umi.open_competition import digest

    from .test_competition_cohort_service_queue import capture

    state = SimpleNamespace(cohort_sha256="01" * 32, tip_sha256="02" * 32, phase="requests")
    policy, catalog = {"policy": 1}, {"catalog": 1}
    observed = capture(400)
    opening = object()
    seen, nonces, cached = [], [], []

    @contextmanager
    def native(supplied):
        assert supplied is state and seen[-1] == "opening"
        seen.append("native_prepare")
        try:

            def sample(value, *, serving, opened):
                assert value is observed and opened is opening
                seen.append(serving)
                return serving

            yield sample
        finally:
            seen.append("release")

    source = SimpleNamespace(
        intake=SimpleNamespace(policy=policy),
        catalogs=(SimpleNamespace(catalog=catalog),),
        gap=10,
        prepare=native,
        has_fence_hint=lambda supplied: False,
    )

    async def response(request):
        seen.append("readiness")
        nonces.append(request.url.params["nonce"])
        if fault == "http":
            return httpx.Response(503)
        if fault == "reused" and cached:
            return httpx.Response(200, json=cached[0])
        body = RequestReadiness(
            schema="umi-cohort-request-readiness/1",
            nonce=nonces[-1],
            policy_sha256=digest(policy),
            cohort_sha256=state.cohort_sha256,
            recovery_tip_sha256=state.tip_sha256,
            catalog_sha256s=(digest(catalog),),
            observation=execution_boundary(observed),
            ready=fault != "unready",
        ).model_dump(mode="json", by_alias=True)
        fields = {
            "nonce": "nonce",
            "policy": "policy_sha256",
            "cohort": "cohort_sha256",
            "tip": "recovery_tip_sha256",
        }
        if fault in fields:
            body[fields[fault]] = "f" * (32 if fault == "nonce" else 64)
        if fault == "catalog":
            body["catalog_sha256s"] = ["f" * 64]
        if fault in {"hash", "root"}:
            body["observation"]["block_hash" if fault == "hash" else "state_root"] = "0x" + "f" * 64
        cached.append(body)
        return httpx.Response(200, json=body)

    async def clock(supplied):
        assert supplied is state
        seen.append("opening")
        return opening

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        live = LiveRequestPhaseObserver(
            source, "https://owner.example", client=client, opening_clock=clock
        )
        for attempt in range(2 if fault == "reused" else 1):
            async with live.prepare(state) as sample:
                assert seen[-3:] == ["readiness", "opening", "native_prepare"]
                if fault == "gap":
                    # Readiness was valid at fetch; only the later capture is
                    # authoritative for the existing maximum-gap check.
                    observed = capture(observed.snapshot.block + source.gap + 1)
                expected = fault is None or (fault == "reused" and attempt == 0)
                assert await sample(observed) is expected
            assert seen[-1] == "release"
    assert len(set(nonces)) == len(nonces)
