"""Service-wide request ownership survives independent ASGI task contexts."""

import asyncio
from types import SimpleNamespace

import pytest

from umi.host_memory_runtime import WorkloadASGIBinding, selected_memory
from umi.host_memory_workload_profile import selected_workload


def controller(*, inflight=2, queued=64):
    workload = SimpleNamespace(
        sha256="b" * 64,
        role="phase_reviewer",
        bounds=SimpleNamespace(maximum_input_bytes=64, maximum_json_values=1000),
        profile=SimpleNamespace(maximum_http_inflight=inflight, maximum_queued_input_bytes=queued),
    )
    return SimpleNamespace(policy_sha256="a" * 64, workload_profile=workload)


def scope(length=b"4", path="/internal/first"):
    return dict(
        type="http",
        method="POST",
        path=path,
        headers=[] if length is None else [(b"content-length", length)],
    )


def receiver(body=b"null"):
    calls = []

    async def receive():
        calls.append(True)
        return {"type": "http.request", "body": body, "more_body": False}

    return receive, calls


async def success(send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def test_all_routes_share_request_lifetime_before_any_body_read():
    selected = controller(inflight=1)
    entered, release = asyncio.Event(), asyncio.Event()

    async def app(scope, receive, send):
        assert selected_memory() is selected
        assert selected_workload() is selected.workload_profile
        assert (await receive())["body"] == b"null"
        entered.set()
        await release.wait()  # A parsed request can wait for the native graph slot.
        await success(send)

    bound = WorkloadASGIBinding(app, controller=selected)
    sent = []

    async def send(message):
        sent.append(message)

    first, calls = receiver()
    running = asyncio.create_task(bound(scope(), first, send))
    await entered.wait()
    assert selected_memory() is None and selected_workload() is None
    second, rejected_calls = receiver()
    await bound(scope(path="/internal/another-route"), second, send)
    assert not rejected_calls
    assert sent[0]["status"] == 503
    assert bound.inflight == 1 and bound.reserved == 4
    release.set()
    await running
    assert len(calls) == 1 and bound.inflight == bound.reserved == 0
    assert sent[-2]["status"] == 200


async def test_unknown_lengths_reserve_capacity_without_buffering_bodies():
    selected = controller(inflight=8, queued=64)
    entered, release = asyncio.Event(), asyncio.Event()

    async def app(scope, receive, send):
        await receive()
        entered.set()
        await release.wait()
        await success(send)

    bound = WorkloadASGIBinding(app, controller=selected)
    sent = []

    async def send(message):
        sent.append(message)

    first, _ = receiver()
    running = asyncio.create_task(bound(scope(None), first, send))
    await entered.wait()
    second, calls = receiver()
    await bound(scope(), second, send)
    assert not calls and sent[0]["status"] == 503
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert bound.inflight == bound.reserved == 0


@pytest.mark.parametrize("length", [b"65", b"-1", b"abc", b"9" * 30])
async def test_invalid_or_unqualified_length_never_reads_request(length):
    async def app(*args):
        raise AssertionError("unqualified request reached application")

    bound = WorkloadASGIBinding(app, controller=controller())
    receive, calls = receiver()
    sent = []

    async def send(message):
        sent.append(message)

    await bound(scope(length), receive, send)
    assert not calls and sent[0]["status"] == 503
    assert bound.inflight == bound.reserved == 0


async def test_body_exceeding_its_reservation_is_pending_and_releases_capacity():
    async def app(scope, receive, send):
        await receive()
        await success(send)

    bound = WorkloadASGIBinding(app, controller=controller())
    sent = []

    async def send(message):
        sent.append(message)

    receive, _ = receiver()
    await bound(scope(b"1"), receive, send)
    assert sent[0]["status"] == 503 and bound.inflight == bound.reserved == 0
    await bound(scope(), receive, send)
    assert sent[-2]["status"] == 200 and bound.inflight == bound.reserved == 0


async def test_response_keeps_request_reserved_through_send_and_error_cleanup():
    selected = controller(inflight=1)
    bound = None

    async def app(scope, receive, send):
        await receive()
        await success(send)

    bound = WorkloadASGIBinding(app, controller=selected)

    async def interrupted_send(message):
        assert bound.inflight == 1 and bound.reserved == 4
        if message["type"] == "http.response.body":
            raise ConnectionError("client disconnected")

    receive, _ = receiver()
    with pytest.raises(ConnectionError):
        await bound(scope(), receive, interrupted_send)
    assert bound.inflight == bound.reserved == 0
