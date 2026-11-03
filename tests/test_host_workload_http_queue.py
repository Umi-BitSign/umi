"""Qualify bounded pre-body fairness and coalesced public responses."""

import asyncio
import json
import os
import time
from pathlib import Path

import pytest
from umi.host_memory_runtime import WorkloadASGIBinding

from .test_host_workload_asgi import controller, receiver, success


def request(path="/v1/competition/status", *, method="GET", query=b"", headers=()):
    return dict(type="http", method=method, path=path, query_string=query, headers=list(headers))


def binding(app, *, reads=64, controls=8, timeout=1):
    selected = controller(inflight=1, queued=128)
    selected.workload_profile.bounds.maximum_object_bytes = 32
    return WorkloadASGIBinding(
        app,
        controller=selected,
        maximum_waiting=reads,
        maximum_control_waiting=controls,
        wait_seconds=timeout,
    )


async def until(predicate):
    async def wait():
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(wait(), 2)


def invoke(bound, scope, *, send=None, body=b""):
    receive, reads = receiver(body)
    messages = []

    async def collect(message):
        messages.append(message)

    return asyncio.create_task(bound(scope, receive, send or collect)), messages, reads


def test_control_only_waiting_still_requires_a_positive_bounded_timeout():
    with pytest.raises(ValueError, match="public timeout"):
        binding(None, reads=0, controls=8, timeout=0)


def direct_status(value="b", *, by_upload=False):
    base = "/v1/competition/cohorts/" + "a" * 64 + "/direct-model-uploads/"
    return base + ("by-upload/" if by_upload else "") + value * 64


@pytest.mark.parametrize("by_upload", [False, True])
async def test_identical_direct_status_polls_share_one_current_response(by_upload):
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope)
        await release.wait()
        await success(send)

    bound = binding(app)
    scope = request(direct_status(by_upload=by_upload))
    first, first_messages, _ = invoke(bound, scope)
    await until(lambda: entered)
    second, messages, calls = invoke(bound, scope)
    await until(lambda: bound.waiting == 1)
    assert (
        bound.inflight == 1 and bound.reserved <= bound.workload.profile.maximum_queued_input_bytes
    )
    release.set()
    await asyncio.gather(first, second)
    assert len(entered) == 1 and messages == first_messages and not calls
    await invoke(bound, scope)[0]
    assert len(entered) == 2  # Completion never becomes a stale status cache.
    assert bound.shared_bytes == bound.inflight == bound.waiting == bound.reserved == 0


@pytest.mark.parametrize(
    "difference", ["reservation", "cohort", "query", "authorization", "cookie"]
)
async def test_direct_status_sharing_preserves_identity_and_private_inputs(difference):
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope)
        await release.wait()
        await success(send)

    bound = binding(app)
    left, right = request(direct_status()), request(direct_status())
    if difference == "reservation":
        right["path"] = direct_status("c")
    elif difference == "cohort":
        right["path"] = right["path"].replace("a" * 64, "d" * 64)
    elif difference == "query":
        right["query_string"] = b"nonce=different"
    else:
        right["headers"] = [(difference.encode(), b"private")]
    first = invoke(bound, left)[0]
    await until(lambda: entered)
    second = invoke(bound, right)[0]
    await until(lambda: bound.waiting == 1)
    release.set()
    await asyncio.gather(first, second)
    assert len(entered) == 2


async def test_status_polling_cannot_consume_mutating_upload_waiters():
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope["path"])
        if len(entered) == 1:
            await release.wait()
        await success(send)

    bound = binding(app, reads=2, controls=1)
    first = invoke(bound, request(direct_status()))[0]
    await until(lambda: entered)
    reads = [invoke(bound, request(direct_status(value)))[0] for value in ("c", "d")]
    await until(lambda: bound.waiting_groups["read"] == 2)
    write_path = direct_status() + "/parts"
    mutation, _, body_reads = invoke(bound, request(write_path, method="POST"))
    await until(lambda: bound.waiting_groups["write"] == 1)
    assert not body_reads and bound.inflight == 1
    release.set()
    await asyncio.gather(first, mutation, *reads)
    assert entered[1] == write_path and bound.inflight == bound.waiting == 0


@pytest.mark.parametrize(
    "path",
    [
        "/v1/competition/cohorts/" + "a" * 64 + "/direct-model-uploads/not-a-digest",
        "/v1/competition/cohorts/" + "a" * 64 + "/direct-model-uploads/" + "b" * 64 + "/parts",
        "/v1/competition/cohorts/" + "a" * 64 + "/direct-model-uploads/by-upload/not-a-digest",
    ],
)
def test_unrecognized_upload_paths_are_not_response_shared(path):
    assert binding(None)._share_key(request(path)) is None


async def test_selected_production_byte_bounds_allow_coalescing_and_one_owned_graph():
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope)
        await release.wait()
        await success(send)

    bound = binding(app)
    bound.workload.profile.maximum_queued_input_bytes = 536870912
    bound.workload.bounds.maximum_input_bytes = 536870912
    bound.workload.bounds.maximum_object_bytes = 16777216
    bound.capture_limit = 16777216
    first = invoke(bound, request())[0]
    await until(lambda: entered)
    second, messages, _ = invoke(bound, request())
    await until(lambda: bound.waiting == 1)
    assert bound.reserved == 536870912 and bound.inflight == 1
    release.set()
    await asyncio.gather(first, second)
    assert messages[0]["status"] == 200 and len(entered) == 1
    assert bound.reserved == bound.shared_bytes == 0


async def test_control_burst_and_fifo_allow_uploads_and_reads_to_advance():
    entered, release = [], asyncio.Event()

    async def app(scope, receive, send):
        entered.append(scope["path"])
        if len(entered) == 1:
            await release.wait()
        await success(send)

    bound = binding(app, reads=3, controls=2)
    first = invoke(bound, request("/owner"))[0]
    await until(lambda: len(entered) == 1)
    reads = [invoke(bound, request(f"/read/{i}"))[0] for i in range(2)]
    writes = [invoke(bound, request(f"/upload/{i}", method="POST"))[0] for i in range(2)]
    await until(lambda: bound.waiting == 4)
    rejected, messages, body_reads = invoke(bound, request("/upload/full", method="POST"))
    await rejected
    assert messages[0]["status"] == 503 and not body_reads
    release.set()
    await asyncio.gather(first, *reads, *writes)
    assert entered == ["/owner", "/upload/0", "/upload/1", "/read/0", "/read/1"]
    assert bound.waiting == bound.inflight == bound.reserved == 0


async def test_upload_status_get_uses_read_queue_without_reading_a_body():
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope["path"])
        if len(entered) == 1:
            await release.wait()
        await success(send)

    bound = binding(app)
    owner = invoke(bound, request("/owner"))[0]
    await until(lambda: entered)
    poll = invoke(bound, request("/read"))[0]
    control, _, body_reads = invoke(bound, request("/v1/competition/direct-model-uploads/id"))
    await until(lambda: bound.waiting == 2)
    assert bound.waiting_groups == {"read": 2, "write": 0}
    assert not body_reads
    release.set()
    await asyncio.gather(owner, poll, control)
    assert entered[1:] == ["/read", "/v1/competition/direct-model-uploads/id"]


async def test_cancel_queued_request_and_grant_race_release_capacity():
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope["path"])
        if len(entered) == 1:
            await release.wait()
        await success(send)

    bound = binding(app)
    owner = invoke(bound, request("/owner"))[0]
    await until(lambda: entered)
    cancelled, _, body_reads = invoke(bound, request("/cancelled"))
    await until(lambda: bound.waiting == 1)
    cancelled.cancel()
    await asyncio.gather(cancelled, return_exceptions=True)
    assert not body_reads and bound.waiting == 0
    raced, _, race_reads = invoke(bound, request("/raced"))
    await until(lambda: bound.waiting == 1)
    original_grant = bound._grant

    def grant(ticket):
        original_grant(ticket)
        raced.cancel()

    bound._grant = grant
    release.set()
    await asyncio.gather(owner, raced, return_exceptions=True)
    assert entered == ["/owner"] and not race_reads
    assert bound.waiting == bound.inflight == bound.reserved == 0


async def test_identical_reads_share_inflight_response_but_not_later_snapshot():
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope)
        await release.wait()
        await success(send)

    bound = binding(app)
    first, first_messages, _ = invoke(bound, request())
    await until(lambda: entered)
    second, second_messages, second_reads = invoke(bound, request())
    await until(lambda: bound.waiting == 1)
    release.set()
    await asyncio.gather(first, second)
    assert len(entered) == 1 and not second_reads
    assert first_messages == second_messages
    assert bound.shared_bytes == bound.waiting == bound.reserved == 0
    await invoke(bound, request())[0]
    assert len(entered) == 2


@pytest.mark.parametrize(
    "difference",
    ["query", "host", "origin", "accept", "cookie", "auth", "accept-encoding", "nonce"],
)
async def test_different_response_inputs_and_private_requests_are_never_shared(
    difference,
):
    release, entered = asyncio.Event(), []

    async def app(scope, receive, send):
        entered.append(scope)
        await release.wait()
        await success(send)

    bound = binding(app)
    left, right = request(), request()
    if difference == "query":
        right["query_string"] = b"page=2"
    elif difference == "nonce":
        left["path"] = right["path"] = "/v1/competition/readiness"
        right["query_string"] = b"nonce=2"
    else:
        name = {"auth": b"authorization"}.get(difference, difference.encode())
        right["headers"] = [(name, b"different")]
    first = invoke(bound, left)[0]
    await until(lambda: entered)
    second = invoke(bound, right)[0]
    await until(lambda: bound.waiting == 1)
    release.set()
    await asyncio.gather(first, second)
    assert len(entered) == 2


def test_forwarded_trace_identifiers_do_not_prevent_equivalent_public_coalescing():
    bound = binding(None)
    left = request(
        headers=[
            (b"host", b"api.umi.vision"),
            (b"cf-ray", b"first"),
            (b"x-forwarded-for", b"192.0.2.1"),
        ]
    )
    right = request(
        headers=[
            (b"host", b"api.umi.vision"),
            (b"cf-ray", b"second"),
            (b"x-forwarded-for", b"192.0.2.2"),
        ]
    )
    assert bound._share_key(left) == bound._share_key(right)


@pytest.mark.parametrize("variant", ["oversize", "cookie", "vary", "trailers"])
async def test_unshareable_response_does_not_leak_to_followers(variant):
    release = asyncio.Event()

    async def app(scope, receive, send):
        await release.wait()
        start = dict(type="http.response.start", status=200, headers=[])
        if variant == "cookie":
            start["headers"] = [(b"set-cookie", b"private=1")]
        if variant == "vary":
            start["headers"] = [(b"vary", b"x-not-supported")]
        if variant == "trailers":
            start["trailers"] = True
        await send(start)
        await send(
            dict(
                type="http.response.body",
                body=b"x" * (33 if variant == "oversize" else 2),
            )
        )

    bound = binding(app)
    first = invoke(bound, request())[0]
    await until(lambda: bound.inflight == 1)
    second, messages, _ = invoke(bound, request())
    await until(lambda: bound.waiting == 1)
    release.set()
    await asyncio.gather(first, second)
    assert messages[0]["status"] == 503
    assert bound.shared_bytes == bound.waiting == bound.reserved == 0


async def test_shared_response_charge_survives_slow_follower_and_releases_on_disconnect():
    release, sending, disconnected = asyncio.Event(), asyncio.Event(), asyncio.Event()
    entered = []

    async def app(scope, receive, send):
        entered.append(scope["path"])
        await release.wait()
        await success(send)

    bound = binding(app)
    bound.workload.bounds.maximum_input_bytes = 128

    async def slow_send(message):
        sending.set()
        await disconnected.wait()
        raise ConnectionError("disconnected")

    first = invoke(bound, request())[0]
    await until(lambda: bound.inflight == 1)
    second = invoke(bound, request(), send=slow_send)[0]
    await until(lambda: bound.waiting == 1)
    release.set()
    await first
    await sending.wait()
    assert bound.shared_bytes == 2 and bound.inflight == 0
    third = invoke(bound, request("/unrelated"))[0]
    await until(lambda: bound.waiting == 2)
    assert len(entered) == 1 and bound.reserved + bound.shared_bytes <= 128
    disconnected.set()
    result = await asyncio.gather(second, third, return_exceptions=True)
    assert isinstance(result[0], ConnectionError)
    assert entered == ["/v1/competition/status", "/unrelated"]
    assert bound.shared_bytes == bound.inflight == bound.waiting == bound.reserved == 0


async def test_shared_send_timeout_does_not_emit_second_response_start():
    release = asyncio.Event()
    messages = []

    async def app(scope, receive, send):
        await release.wait()
        await success(send)

    async def stalled_send(message):
        messages.append(message)
        await asyncio.Event().wait()

    bound = binding(app, timeout=0.02)
    first = invoke(bound, request())[0]
    await until(lambda: bound.inflight == 1)
    second = invoke(bound, request(), send=stalled_send)[0]
    await until(lambda: bound.waiting == 1)
    release.set()
    await first
    with pytest.raises(asyncio.TimeoutError):
        await second
    assert len(messages) == 1 and messages[0]["status"] == 200
    assert bound.shared_bytes == bound.waiting == 0


async def test_shutdown_rejects_waiters_and_followers_but_drains_owned_work():
    release = asyncio.Event()

    async def app(scope, receive, send):
        await release.wait()
        await success(send)

    bound = binding(app)
    first = invoke(bound, request())[0]
    await until(lambda: bound.inflight == 1)
    follower, shared_messages, _ = invoke(bound, request())
    queued, queued_messages, queued_reads = invoke(bound, request("/upload", method="POST"))
    await until(lambda: bound.waiting == 2)
    bound.close()
    await asyncio.gather(follower, queued)
    assert not first.done() and bound.inflight == 1 and not queued_reads
    assert shared_messages[0]["status"] == queued_messages[0]["status"] == 503
    release.set()
    await first
    assert bound.shared_bytes == bound.reserved == bound.inflight == bound.waiting == 0


async def test_owner_cancel_resolves_shared_followers_without_native_retry():
    entered = []

    async def app(scope, receive, send):
        entered.append(scope)
        await asyncio.Event().wait()

    bound = binding(app)
    first = invoke(bound, request())[0]
    await until(lambda: entered)
    follower, messages, _ = invoke(bound, request())
    await until(lambda: bound.waiting == 1)
    first.cancel()
    await asyncio.gather(first, follower, return_exceptions=True)
    assert len(entered) == 1 and messages[0]["status"] == 503
    assert bound.inflight == bound.reserved == bound.shared_bytes == bound.waiting == 0


async def test_completed_response_survives_owner_disconnect_without_retaining_failed_frames():
    release = asyncio.Event()

    async def app(scope, receive, send):
        await release.wait()
        await success(send)

    async def disconnected_send(message):
        if message["type"] == "http.response.body":
            raise ConnectionError("owner disconnected")

    bound = binding(app)
    owner = invoke(bound, request(), send=disconnected_send)[0]
    await until(lambda: bound.inflight == 1)
    follower, messages, _ = invoke(bound, request())
    await until(lambda: bound.waiting == 1)
    release.set()
    failure, _ = await asyncio.gather(owner, follower, return_exceptions=True)
    assert isinstance(failure, ConnectionError)
    frames = []
    trace = failure.__traceback__
    while trace is not None:
        frames.append(trace.tb_frame.f_code.co_name)
        trace = trace.tb_next
    assert "disconnected_send" not in frames and "tracked_send" not in frames
    assert messages[0]["status"] == 200 and messages[1]["body"] == b"ok"
    assert bound.inflight == bound.reserved == bound.shared_bytes == bound.waiting == 0


async def test_queue_timeout_and_full_follower_capacity_do_not_read_bodies():
    release = asyncio.Event()

    async def app(scope, receive, send):
        await release.wait()
        await success(send)

    bound = binding(app, reads=1, timeout=0.02)
    owner = invoke(bound, request())[0]
    await until(lambda: bound.inflight == 1)
    follower, follower_messages, follower_reads = invoke(bound, request())
    await until(lambda: bound.waiting == 1)
    full, full_messages, full_reads = invoke(bound, request())
    await full
    assert full_messages[0]["status"] == 503 and not full_reads
    await follower
    assert follower_messages[0]["status"] == 503 and not follower_reads
    queued, queued_messages, queued_reads = invoke(bound, request("/different"))
    await queued
    assert queued_messages[0]["status"] == 503 and not queued_reads
    assert bound.waiting == 0 and bound.inflight == 1
    release.set()
    await owner
    assert bound.shared_bytes == bound.reserved == bound.inflight == 0


async def test_signed_upload_bytes_are_unchanged_after_queued_admission():
    release, received = asyncio.Event(), []
    signed = b'{"signature":"unaltered", "nonce":1}\n'

    async def app(scope, receive, send):
        if scope["method"] == "GET":
            await release.wait()
        else:
            received.append((await receive())["body"])
        await success(send)

    bound = binding(app)
    first = invoke(bound, request())[0]
    await until(lambda: bound.inflight == 1)
    upload, _, calls = invoke(
        bound,
        request(
            "/upload",
            method="POST",
            headers=[(b"content-length", str(len(signed)).encode())],
        ),
        body=signed,
    )
    await until(lambda: bound.waiting == 1)
    assert not calls
    release.set()
    await asyncio.gather(first, upload)
    assert received == [signed]


async def test_representative_poll_upload_burst_measures_useful_completions():
    async def measure(waiting):
        active = peak = executions = uploads = 0

        async def app(scope, receive, send):
            nonlocal active, peak, executions, uploads
            active += 1
            peak = max(peak, active)
            executions += 1
            uploads += scope["method"] == "POST"
            try:
                await asyncio.sleep(0.002)
                await success(send)
            finally:
                active -= 1

        bound = binding(app, reads=64 if waiting else 0, controls=8 if waiting else 0)
        paths = [
            "/v1/competition/status",
            "/v1/competition/cohorts",
            "/v1/competition/service-work",
        ]
        started = time.monotonic()
        calls = [invoke(bound, request(paths[i % 3])) for i in range(30)]
        calls += [invoke(bound, request(f"/upload/{i}", method="POST")) for i in range(8)]
        await asyncio.gather(*(call[0] for call in calls))
        elapsed = time.monotonic() - started
        completed = sum(messages[0]["status"] == 200 for _, messages, _ in calls)
        return dict(
            completed=completed,
            rejected=38 - completed,
            uploads=uploads,
            native_executions=executions,
            maximum_active=peak,
            elapsed_seconds=elapsed,
            useful_responses_per_second=completed / elapsed,
        )

    original, changed = await measure(False), await measure(True)
    assert original["completed"] == 1 and original["uploads"] == 0
    assert changed["completed"] == 38 and changed["uploads"] == 8
    assert changed["native_executions"] == 11 and changed["maximum_active"] == 1
    result = dict(
        schema="umi-http-queue-simulation/1",
        basis="synthetic_2ms_handler_no_production_requests",
        original=original,
        changed=changed,
    )
    if os.environ.get("UMI_HTTP_SIMULATION_OUTPUT"):
        Path(os.environ["UMI_HTTP_SIMULATION_OUTPUT"]).write_text(
            json.dumps(result, indent=2) + "\n"
        )
