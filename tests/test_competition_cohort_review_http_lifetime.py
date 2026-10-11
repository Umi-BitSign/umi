"""Response ownership tests with real ASGI routing and blocked network sends."""

import asyncio

import pytest
from fastapi import FastAPI

from umi import competition_cohort_review_http as module
from umi.protocol import StrictProtocolModel


class ReviewRequest(StrictProtocolModel):
    challenge: str


class Exporter:
    timeout_seconds = 30
    maximum_bytes = 1024 * 1024

    def __init__(self):
        self.calls = []
        self.payload = b'{"evidence":"' + b"x" * (192 * 1024 + 3) + b'"}'

    async def respond(self, request):
        self.calls.append(request.challenge)
        return self.payload


def application(exporter):
    app = FastAPI()
    app.include_router(
        module.phase_review_routes(
            exporter,
            token="credential-" * 4,
            path="/review",
            request_model=ReviewRequest,
        )
    )
    return app


async def invoke(app, send, challenge="first"):
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "https",
        "method": "POST",
        "path": "/review",
        "raw_path": b"/review",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"authorization", b"Bearer " + b"credential-" * 4),
            (b"content-type", b"application/json"),
        ],
        "server": ("owner.example", 443),
        "client": ("127.0.0.1", 1234),
    }
    received = False

    async def receive():
        nonlocal received
        if received:
            await asyncio.Future()
        received = True
        return {
            "type": "http.request",
            "body": ('{"challenge":"' + challenge + '"}').encode(),
            "more_body": False,
        }

    await app(scope, receive, send)


async def test_blocked_asgi_send_keeps_capacity_and_exact_wire_bytes():
    exporter = Exporter()
    app = application(exporter)
    entered, release = asyncio.Event(), asyncio.Event()
    messages = [[], []]

    async def first_send(message):
        messages[0].append(message)
        if message["type"] == "http.response.body" and not entered.is_set():
            entered.set()
            await release.wait()

    async def second_send(message):
        messages[1].append(message)

    first = asyncio.create_task(invoke(app, first_send))
    second = None
    try:
        await asyncio.wait_for(entered.wait(), 5)
        second = asyncio.create_task(invoke(app, second_send, "second"))
        for _ in range(10):
            await asyncio.sleep(0)
        assert exporter.calls == ["first"]
        assert not second.done()
    finally:
        release.set()
        await asyncio.gather(first, *([] if second is None else [second]))
    assert exporter.calls == ["first", "second"]
    for sent in messages:
        bodies = [m for m in sent if m["type"] == "http.response.body"]
        assert b"".join(m["body"] for m in bodies) == exporter.payload
        assert all(len(m["body"]) <= 64 * 1024 for m in bodies)
        assert bodies[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
        headers = dict(sent[0]["headers"])
        assert int(headers[b"content-length"]) == len(exporter.payload)
        assert headers[b"cache-control"] == b"no-store"
        assert headers[b"content-type"] == b"application/json"


@pytest.mark.parametrize("failure", ["start", "body", "final", "cancel"])
async def test_failed_send_discards_body_and_allows_next_request(monkeypatch, failure):
    responses = []
    original = module._OwnedReviewResponse

    class Retained(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            responses.append(self)

    monkeypatch.setattr(module, "_OwnedReviewResponse", Retained)
    exporter = Exporter()
    app = application(exporter)
    entered = asyncio.Event()

    async def failing_send(message):
        kind = (
            "start"
            if message["type"] == "http.response.start"
            else "body"
            if message.get("more_body")
            else "final"
        )
        if kind == failure:
            raise OSError("transport disconnected")
        if failure == "cancel" and kind == "body":
            entered.set()
            await asyncio.Future()

    first = asyncio.create_task(invoke(app, failing_send))
    if failure == "cancel":
        await asyncio.wait_for(entered.wait(), 5)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
    else:
        with pytest.raises(OSError, match="disconnected"):
            await first
    assert responses[0].body == b""
    assert responses[0]._capacity is None
    successful = []

    async def send(message):
        successful.append(message)

    await asyncio.wait_for(invoke(app, send, "retry"), 5)
    assert exporter.calls == ["first", "retry"]
    assert responses[-1].body == b""
    assert b"".join(m.get("body", b"") for m in successful) == exporter.payload
