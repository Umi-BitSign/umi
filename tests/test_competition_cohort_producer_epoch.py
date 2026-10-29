"""Live application epochs, bounded transport and older-peer compatibility."""

import asyncio
from types import SimpleNamespace as NS

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_producer_epoch as module
from umi.competition_cohort_producer_epoch import ExecutionProducerEpochs, producer_epoch_routes
from umi.host_memory_runtime import RequestsStageASGIBinding
from umi.open_competition import identity

from .test_open_competition import wallet

EVALUATOR = wallet("Charlie").hotkey.ss58_address
EVALUATOR_ID = identity(EVALUATOR)
TOKEN = "private-reviewer-token" * 3


async def test_application_epoch_is_cached_authenticated_and_changes_on_restart():
    previous = None
    for _ in range(2):
        app = FastAPI()
        app.include_router(producer_epoch_routes(EVALUATOR, token=TOKEN, enabled=True))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://review.example"
        ) as client:
            path = module.PRODUCER_EPOCH_PATH
            assert (await client.get(path)).status_code == 401
            headers = {"authorization": "Bearer " + TOKEN}
            first = await client.get(path, headers=headers)
            assert (await client.get(path, headers=headers)).content == first.content
            body = first.json()
            assert body["evaluator"] == EVALUATOR_ID and body["execution_enabled"]
            assert len(body["epoch_sha256"]) == 64 and body["epoch_sha256"] != previous
            previous = body["epoch_sha256"]
            # Requests-stage binding also permits the cached authenticated GET.
            wrapper = RequestsStageASGIBinding(
                app, controller=NS(policy=NS(operations=())), private_role="phase_reviewer"
            )
            assert wrapper._permitted({"path": path, "method": "GET"})
            assert not wrapper._permitted({"path": "/other", "method": "GET"})


async def test_peer_epoch_cache_refresh_and_failed_refresh_withdraw_previous_epoch(monkeypatch):
    clock, calls, state = [0], [], ["11" * 32]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])

    def respond(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer " + TOKEN
        if state[0] is None:
            return httpx.Response(503)
        return httpx.Response(
            200,
            json=dict(
                schema="umi-execution-producer-epoch/1",
                evaluator=EVALUATOR_ID,
                epoch_sha256=state[0],
                execution_enabled=True,
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = ExecutionProducerEpochs(
            client, [NS(signer=EVALUATOR, origin="http://127.0.0.1:19579")], [TOKEN]
        )
        assert await observer.sample([EVALUATOR_ID]) == {EVALUATOR_ID: state[0]}
        state[0] = "22" * 32
        clock[0] = 29
        assert await observer.sample([EVALUATOR_ID]) == {EVALUATOR_ID: "11" * 32}
        assert len(calls) == 1
        clock[0] = 30
        assert await observer.sample([EVALUATOR_ID]) == {EVALUATOR_ID: "22" * 32}
        clock[0], state[0] = 60, None
        assert await observer.sample([EVALUATOR_ID]) == {}
        assert len(calls) == 3
        # An unconfigured producer remains unknown and cannot choose a URL.
        assert await observer.sample(["unknown"]) == {}
        assert len(calls) == 3


@pytest.mark.parametrize(
    "fault",
    ["old_peer", "oversized", "malformed", "wrong_signer", "disabled", "bad_epoch", "timeout"],
)
async def test_old_unavailable_or_invalid_peer_never_supplies_a_rate_epoch(fault):
    def respond(request):
        if fault == "timeout":
            raise httpx.ReadTimeout("diagnostic timeout", request=request)
        if fault == "old_peer":
            return httpx.Response(404)
        if fault == "oversized":
            return httpx.Response(200, content=b" " * 2049)
        if fault == "malformed":
            return httpx.Response(200, json=[])
        body = dict(
            schema="umi-execution-producer-epoch/1",
            evaluator=EVALUATOR_ID,
            epoch_sha256="11" * 32,
            execution_enabled=True,
        )
        body.update(
            {
                "wrong_signer": {"evaluator": "other"},
                "disabled": {"execution_enabled": False},
                "bad_epoch": {"epoch_sha256": "not-an-epoch"},
            }[fault]
        )
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = ExecutionProducerEpochs(
            client, [NS(signer=EVALUATOR, origin="https://review.example")], [TOKEN]
        )
        assert await observer.sample([EVALUATOR_ID]) == {}


async def test_slow_drip_body_is_closed_at_the_diagnostic_refresh_deadline(monkeypatch):
    monkeypatch.setattr(module, "_REFRESH_SECONDS", 0.01)

    class Slow(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            while True:
                yield b" "
                await asyncio.sleep(0.001)

        async def aclose(self):
            self.closed = True

    stream = Slow()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream))
    ) as client:
        observer = ExecutionProducerEpochs(
            client, [NS(signer=EVALUATOR, origin="https://review.example")], [TOKEN]
        )
        assert await asyncio.wait_for(observer.sample([EVALUATOR_ID]), timeout=0.5) == {}
        assert stream.closed


async def test_diagnostic_pool_serves_while_business_connection_is_occupied():
    import json
    from contextlib import AsyncExitStack

    held, release = asyncio.Event(), asyncio.Event()

    async def serve(reader, writer):
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            if header.startswith(b"GET /business "):
                held.set()
                await release.wait()
                body = b"{}"
            else:
                assert module.PRODUCER_EPOCH_PATH.encode() in header
                body = json.dumps(
                    dict(
                        schema="umi-execution-producer-epoch/1",
                        evaluator=EVALUATOR_ID,
                        epoch_sha256="11" * 32,
                        execution_enabled=True,
                    )
                ).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    async with server, AsyncExitStack() as resources:
        business = await resources.enter_async_context(
            httpx.AsyncClient(
                limits=httpx.Limits(max_connections=1),
                trust_env=False,
            )
        )
        diagnostic = await resources.enter_async_context(module.producer_epoch_client())
        request = asyncio.create_task(business.get(origin + "/business"))
        try:
            await asyncio.wait_for(held.wait(), 1)
            observer = ExecutionProducerEpochs(
                diagnostic,
                [NS(signer=EVALUATOR, origin=origin)],
                [TOKEN],
            )
            assert await asyncio.wait_for(observer.sample([EVALUATOR_ID]), 1) == {
                EVALUATOR_ID: "11" * 32
            }
            assert not request.done()
            expected = dict(
                rate_probe_status="current",
                rate_probe_http_status=200,
                rate_probe_attempts=1,
                rate_probe_failures=0,
                rate_probe_timeouts=0,
            )
            report = observer.diagnostics([EVALUATOR_ID])
            assert {key: report[key] for key in expected} == expected
            assert report["rate_probe_phase"] == "validate"
            assert report["rate_probe_in_flight"] == report["rate_probe_coalesced_waiters"] == 0
        finally:
            release.set()
            await request
    assert business.is_closed and diagnostic.is_closed


@pytest.mark.parametrize("status", [401, 404, 429, 503])
async def test_failed_probe_diagnostics_retain_numeric_status_without_private_errors(status):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(status, text=TOKEN + " sensitive provider diagnostic")
        )
    ) as client:
        observer = ExecutionProducerEpochs(
            client, [NS(signer=EVALUATOR, origin="https://review.example")], [TOKEN]
        )
        assert await observer.sample([EVALUATOR_ID]) == {}
        report = observer.diagnostics([EVALUATOR_ID])
        assert report["rate_probe_http_status"] == status
        assert report["rate_probe_failures"] == 1 and report["rate_probe_attempts"] == 1
        assert TOKEN not in str(report) and "review.example" not in str(report)
        await observer.sample([EVALUATOR_ID])
        cached = observer.diagnostics([EVALUATOR_ID])
        assert cached.pop("rate_probe_cache_age_seconds") >= report.pop(
            "rate_probe_cache_age_seconds"
        )
        assert cached == report  # cached, not a second request


async def test_public_progress_keeps_bounded_probe_diagnostics_without_polling_peers():
    from umi.competition_cohort_public_progress import CohortProgressSnapshots

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(503, text=TOKEN))
    ) as client:
        observer = ExecutionProducerEpochs(
            client, [NS(signer=EVALUATOR, origin="https://review.example")], [TOKEN]
        )
        await observer.sample([EVALUATOR_ID])
        public = CohortProgressSnapshots()
        public.record(
            "execution",
            dict(
                cohort_sha256="11" * 32,
                phase="requests",
                stage="model_evaluation",
                **observer.diagnostics([EVALUATOR_ID]),
            ),
        )
        for _ in range(2):
            current = public.snapshot("11" * 32)["components"]["execution"]
            assert current["rate_probe_http_status"] == 503
            assert current["rate_probe_attempts"] == current["rate_probe_failures"] == 1
            assert TOKEN not in str(current)


def epoch_body(epoch="11" * 32):
    return dict(
        schema="umi-execution-producer-epoch/1",
        evaluator=EVALUATOR_ID,
        epoch_sha256=epoch,
        execution_enabled=True,
    )


def observer_for(client):
    return ExecutionProducerEpochs(
        client, [NS(signer=EVALUATOR, origin="https://review.example")], [TOKEN]
    )


async def joined_waiter(observer):
    async def joined():
        while observer.waiters != 1:
            await asyncio.sleep(0)

    await asyncio.wait_for(joined(), 1)


@pytest.mark.parametrize("refresh_status", [200, 503])
async def test_concurrent_expired_refresh_is_one_request_and_one_cached_result(
    monkeypatch, refresh_status
):
    clock = [0]
    monkeypatch.setattr(
        module, "time", NS(monotonic=lambda: clock[0], time_ns=lambda: int(clock[0] * 1e9))
    )
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def respond(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json=epoch_body())
        assert len(calls) == 2, "concurrent refresh must not make a stale second request"
        entered.set()
        await release.wait()
        return httpx.Response(refresh_status, json=epoch_body("22" * 32))

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = observer_for(client)
        assert await observer.sample([EVALUATOR_ID]) == {EVALUATOR_ID: "11" * 32}
        clock[0] = 31
        first = asyncio.create_task(observer.sample([EVALUATOR_ID]))
        second = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            second = asyncio.create_task(observer.sample([EVALUATOR_ID]))
            await joined_waiter(observer)
            report = observer.diagnostics([EVALUATOR_ID])
            assert report["rate_probe_attempts"] == 2
            assert report["rate_probe_in_flight"] == report["rate_probe_coalesced_waiters"] == 1
            release.set()
            expected = {EVALUATOR_ID: "22" * 32} if refresh_status == 200 else {}
            assert await asyncio.wait_for(asyncio.gather(first, second), 1) == [expected, expected]
            clock[0] = 40
            assert await observer.sample([EVALUATOR_ID]) == expected
            report = observer.diagnostics([EVALUATOR_ID])
            assert len(calls) == 2 and report["rate_probe_attempts"] == 2
            assert report["rate_probe_failures"] == int(refresh_status != 200)
            assert report["rate_probe_cache_age_seconds"] == 9
            assert report["rate_probe_in_flight"] == report["rate_probe_coalesced_waiters"] == 0
        finally:
            release.set()
            for task in (first, second):
                if task is not None:
                    task.cancel()
            await asyncio.gather(
                *(t for t in (first, second) if t is not None), return_exceptions=True
            )


@pytest.mark.parametrize(
    "timeout, reason",
    [
        (httpx.ConnectTimeout, "http_connect_timeout"),
        (httpx.ReadTimeout, "http_read_timeout"),
        (httpx.WriteTimeout, "http_write_timeout"),
        (httpx.PoolTimeout, "http_pool_timeout"),
    ],
)
async def test_http_timeout_types_keep_bounded_phase_and_timing(monkeypatch, timeout, reason):
    clock = [10.0]
    monkeypatch.setattr(
        module, "time", NS(monotonic=lambda: clock[0], time_ns=lambda: int(clock[0] * 1e9))
    )

    def respond(request):
        clock[0] = 12.0
        raise timeout(TOKEN + " https://review.example/private", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = observer_for(client)
        assert await observer.sample([EVALUATOR_ID]) == {}
        report = observer.diagnostics([EVALUATOR_ID])
        assert report["rate_probe_status"] == "timeout"
        assert report["rate_probe_failure_type"] == reason
        assert report["rate_probe_phase"] == "http_headers"
        assert report["rate_probe_elapsed_seconds"] == report["rate_probe_http_seconds"] == 2
        assert report["rate_probe_queue_seconds"] == report["rate_probe_received_bytes"] == 0
        assert report["rate_probe_deadline_overrun_seconds"] == 0
        assert report["rate_probe_started_unix_ms"] == 10000
        assert report["rate_probe_finished_unix_ms"] == 12000
        assert report["rate_probe_failures"] == report["rate_probe_timeouts"] == 1
        assert TOKEN not in str(report) and "review.example" not in str(report)


async def test_outer_deadline_identifies_capacity_queue_without_http_request(monkeypatch):
    monkeypatch.setattr(module, "_REFRESH_SECONDS", 0.01)

    def forbidden(request):
        pytest.fail("queued probe must not claim an HTTP request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(forbidden)) as client:
        observer = observer_for(client)
        observer.capacity = asyncio.Semaphore(0)
        assert await asyncio.wait_for(observer.sample([EVALUATOR_ID]), 1) == {}
        report = observer.diagnostics([EVALUATOR_ID])
        assert report["rate_probe_failure_type"] == "outer_deadline"
        assert report["rate_probe_phase"] == "capacity_queue"
        assert report["rate_probe_queue_seconds"] == report["rate_probe_elapsed_seconds"]
        assert report["rate_probe_http_seconds"] is None
        assert report["rate_probe_http_status"] is None
        assert report["rate_probe_in_flight"] == 0


async def test_body_deadline_keeps_status_partial_bytes_and_overrun(monkeypatch):
    monkeypatch.setattr(module, "_REFRESH_SECONDS", 0.01)
    clock = [10.0]
    monkeypatch.setattr(
        module, "time", NS(monotonic=lambda: clock[0], time_ns=lambda: int(clock[0] * 1e9))
    )

    class Slow(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield b"{"
            await asyncio.Event().wait()

        async def aclose(self):
            clock[0] = 14.0
            self.closed = True

    stream = Slow()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream))
    ) as client:
        observer = observer_for(client)
        assert await asyncio.wait_for(observer.sample([EVALUATOR_ID]), 1) == {}
        report = observer.diagnostics([EVALUATOR_ID])
        assert stream.closed and report["rate_probe_http_status"] == 200
        assert report["rate_probe_phase"] == "http_body"
        assert report["rate_probe_failure_type"] == "outer_deadline"
        assert report["rate_probe_received_bytes"] == 1
        assert report["rate_probe_elapsed_seconds"] == report["rate_probe_http_seconds"] == 4
        assert report["rate_probe_deadline_overrun_seconds"] == 3.99
        assert report["rate_probe_in_flight"] == 0


@pytest.mark.parametrize(
    "body, reason",
    [
        ([], "invalid_shape"),
        (epoch_body() | {"evaluator": "wrong"}, "invalid_binding"),
        (epoch_body() | {"execution_enabled": False}, "execution_disabled"),
        (epoch_body() | {"epoch_sha256": "bad"}, "invalid_epoch"),
    ],
)
async def test_rejected_http_200_is_invalid_response(body, reason):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    ) as client:
        observer = observer_for(client)
        assert await observer.sample([EVALUATOR_ID]) == {}
        report = observer.diagnostics([EVALUATOR_ID])
        assert report["rate_probe_status"] == "invalid_response"
        assert report["rate_probe_failure_type"] == reason
        assert report["rate_probe_http_status"] == 200
        assert report["rate_probe_received_bytes"] > 0


async def test_cancelled_waiter_does_not_cancel_active_refresh():
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def respond(request):
        calls.append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json=epoch_body())

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = observer_for(client)
        first = asyncio.create_task(observer.sample([EVALUATOR_ID]))
        second = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            second = asyncio.create_task(observer.sample([EVALUATOR_ID]))
            await joined_waiter(observer)
            second.cancel()
            with pytest.raises(asyncio.CancelledError):
                await second
            assert observer.in_flight == 1 and observer.waiters == 0 and not first.done()
            release.set()
            assert await asyncio.wait_for(first, 1) == {EVALUATOR_ID: "11" * 32}
            assert len(calls) == observer.attempts == 1
        finally:
            release.set()
            first.cancel()
            if second is not None:
                second.cancel()
            await asyncio.gather(
                *(t for t in (first, second) if t is not None), return_exceptions=True
            )


async def test_cancelled_refresh_closes_stream_before_waiter_retries():
    entered, closing, release_close, closed = (asyncio.Event() for _ in range(4))
    calls = []

    class Paused(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"{"
            entered.set()
            await asyncio.Event().wait()

        async def aclose(self):
            closing.set()
            await release_close.wait()
            closed.set()

    def respond(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, stream=Paused())
        assert closed.is_set(), "cancelled owner must drain before handing off refresh lock"
        return httpx.Response(200, json=epoch_body())

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = observer_for(client)
        observer.capacity = asyncio.Semaphore(1)
        first = asyncio.create_task(observer.sample([EVALUATOR_ID]))
        second = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            second = asyncio.create_task(observer.sample([EVALUATOR_ID]))
            await joined_waiter(observer)
            first.cancel()
            await asyncio.wait_for(closing.wait(), 1)
            first.cancel()
            await asyncio.sleep(0)
            first.cancel()
            await asyncio.sleep(0)
            assert not first.done() and not second.done() and not closed.is_set()
            assert observer.refresh_locks[EVALUATOR_ID].locked()
            assert observer.capacity.locked()
            assert observer.in_flight == observer.waiters == 1 and len(calls) == 1
            release_close.set()
            with pytest.raises(asyncio.CancelledError):
                await first
            assert await asyncio.wait_for(second, 1) == {EVALUATOR_ID: "11" * 32}
            report = observer.diagnostics([EVALUATOR_ID])
            assert closed.is_set() and len(calls) == report["rate_probe_attempts"] == 2
            assert report["rate_probe_failures"] == report["rate_probe_timeouts"] == 0
            assert observer.in_flight == observer.waiters == 0
            assert not observer.refresh_locks[EVALUATOR_ID].locked()
        finally:
            release_close.set()
            for task in (first, second):
                if task is not None:
                    task.cancel()
            await asyncio.gather(
                *(t for t in (first, second) if t is not None), return_exceptions=True
            )
