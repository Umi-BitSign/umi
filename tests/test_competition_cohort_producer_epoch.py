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
        return httpx.Response(200, json=dict(
            schema="umi-execution-producer-epoch/1", evaluator=EVALUATOR_ID,
            epoch_sha256=state[0], execution_enabled=True,
        ))

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


@pytest.mark.parametrize("fault", ["old_peer", "oversized", "malformed", "wrong_signer",
                                   "disabled", "bad_epoch", "timeout"])
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
        body = dict(schema="umi-execution-producer-epoch/1", evaluator=EVALUATOR_ID,
                    epoch_sha256="11" * 32, execution_enabled=True)
        body.update({"wrong_signer": {"evaluator": "other"},
                     "disabled": {"execution_enabled": False},
                     "bad_epoch": {"epoch_sha256": "not-an-epoch"}}[fault])
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
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, stream=stream)
    )) as client:
        observer = ExecutionProducerEpochs(
            client, [NS(signer=EVALUATOR, origin="https://review.example")], [TOKEN]
        )
        assert await asyncio.wait_for(observer.sample([EVALUATOR_ID]), timeout=0.5) == {}
        assert stream.closed
