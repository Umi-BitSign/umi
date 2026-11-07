"""Keep completed review work while an owner rejects a request before admission."""

import asyncio
import json
import logging
import time

import httpx
import pytest

from umi.competition_cohort_review_http import PhaseReviewHTTPClient, PhaseReviewHTTPUnavailable
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Request(StrictProtocolModel):
    challenge: str


def exchange(client, *, timeout=5, maximum_bytes=1024):
    return PhaseReviewHTTPClient(
        client,
        "https://private-owner.example",
        token="private-credential-" * 3,
        path="/internal/cohorts/intake-review",
        timeout_seconds=timeout,
        maximum_bytes=maximum_bytes,
    )


class RejectedBody(httpx.AsyncByteStream):
    def __init__(self):
        self.closed = asyncio.Event()

    async def __aiter__(self):
        raise AssertionError("admission retry must not consume a private error body")
        yield b""  # pragma: no cover

    async def aclose(self):
        self.closed.set()


@pytest.mark.parametrize("reason", ["http_request_capacity", "http_queue_timeout"])
async def test_fresh_challenge_retry_keeps_completed_first_review(
    reason, caplog, http_log_redaction
):
    calls, bodies = [], []
    first, fresh = Request(challenge="first"), Request(challenge="fresh-private-challenge")
    rejected = RejectedBody()

    def handle(request):
        calls.append(request.content)
        if request.content == canonical_json_bytes(fresh) and calls.count(request.content) == 1:
            bodies.append(rejected)
            return httpx.Response(503, headers={"x-umi-reason-code": reason}, stream=rejected)
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}")

    caplog.set_level(logging.INFO)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        fetch = exchange(client)
        assert await fetch(first) == b"{}"
        assert await fetch(fresh) == b"{}"
    assert calls == [
        canonical_json_bytes(first),
        canonical_json_bytes(fresh),
        canonical_json_bytes(fresh),
    ]
    assert all(body.closed.is_set() for body in bodies)
    reports = [
        json.loads(r.message.split(" ", 1)[1])
        for r in caplog.records
        if r.message.startswith("phase_review_admission_progress ")
    ]
    assert [r["status"] for r in reports] == ["retrying", "completed"]
    assert reports[0]["retries"] == 1 and reports[-1]["completed"] == 1
    assert reports[0]["eta_scope"] == "retry_delay_only_not_review_completion"
    assert reports[0]["remaining_budget_seconds"] > 0
    assert all(not r["certification_authority"] for r in reports)
    text = json.dumps(reports)
    for private in ("private-owner.example", "private-credential", "fresh-private-challenge"):
        assert private not in text


@pytest.mark.parametrize(
    "status,reason",
    [
        (401, "http_request_capacity"),
        (307, "http_request_capacity"),
        (503, None),
        (503, "input_byte_bound"),
        (503, "http_shutdown"),
        (503, "unrecognized_reason"),
    ],
)
async def test_other_failures_do_not_retry(status, reason):
    calls = []

    def handle(request):
        calls.append(request.content)
        return httpx.Response(
            status, headers={} if reason is None else {"x-umi-reason-code": reason}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(PhaseReviewHTTPUnavailable) as caught:
            await exchange(client)(Request(challenge="unchanged"))
    assert caught.value.reason_code == f"phase_owner_http_{status}"
    assert len(calls) == 1


async def test_one_deadline_includes_admission_delay_and_response():
    calls, closed = [], asyncio.Event()

    async def handle(request):
        calls.append(request.content)
        if len(calls) == 1:
            await asyncio.sleep(0.2)
            return httpx.Response(503, headers={"x-umi-reason-code": "http_request_capacity"})
        try:
            await asyncio.sleep(1)
        finally:
            closed.set()
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}")

    started = time.monotonic()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(asyncio.TimeoutError):
            await exchange(client, timeout=2)(Request(challenge="same-deadline"))
    assert len(calls) == 2 and calls[0] == calls[1]
    assert closed.is_set() and time.monotonic() - started < 2.8


async def test_cancellation_closes_rejection_without_another_request():
    calls, rejected = [], RejectedBody()

    def handle(request):
        calls.append(request.content)
        return httpx.Response(
            503, headers={"x-umi-reason-code": "http_request_capacity"}, stream=rejected
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        task = asyncio.create_task(exchange(client)(Request(challenge="cancelled")))
        await asyncio.wait_for(rejected.closed.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(calls) == 1


@pytest.mark.parametrize("bad_response", ["oversized", "non_json"])
async def test_admission_retry_preserves_response_validation(bad_response):
    calls = []

    def handle(request):
        calls.append(request.content)
        if len(calls) == 1:
            return httpx.Response(503, headers={"x-umi-reason-code": "http_request_capacity"})
        return httpx.Response(
            200,
            headers={
                "content-type": "text/plain" if bad_response == "non_json" else "application/json"
            },
            content=b"x" * 1025,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError):
            await exchange(client)(Request(challenge="validate-response"))
    assert len(calls) == 2 and calls[0] == calls[1]
