"""Small process/ASGI lifetime tests; these do not qualify native RSS."""

import asyncio
import gc
import hashlib
import json
import os
import stat
import weakref
from pathlib import Path

import pytest
from fastapi import HTTPException, Request

from umi import host_memory_admission as admission
from umi.competition_cohort_review_http import phase_review_routes
from umi.concurrency import run_owned_thread
from umi.protocol import StrictProtocolModel


@pytest.fixture
def provisioned(tmp_path, monkeypatch):
    # Production has no owner override. Pure tests use their isolated account
    # under the task root; do not install host files or change service accounts.
    monkeypatch.setattr(admission, "_root_uid", os.geteuid)
    original_directory_check = admission._directory

    def directory_check(descriptor):
        resolved = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        # The existing task root is user/group writable. Test its isolated
        # descendants strictly without modifying that shared workspace.
        if resolved != tmp_path and resolved in tmp_path.parents:
            return os.fstat(descriptor)
        return original_directory_check(descriptor)

    monkeypatch.setattr(admission, "_directory", directory_check)
    root = tmp_path / "capacity"
    root.mkdir(mode=0o750)
    # CLI tests may leave a private umask; provision the exact selected mode.
    root.chmod(0o750)
    monkeypatch.setattr(admission, "_available_memory", lambda: 24 * 1024**3 + 100000)
    slots = []
    for lane, role in (
        ("owner_export", None),
        ("transient", None),
        ("settlement_retained", "coordinator"),
        ("settlement_retained", "reviewer"),
    ):
        path = root / f"{role or lane}.slot"
        path.write_bytes(b"")
        path.chmod(0o440)
        details = path.stat()
        slots.append(
            {
                "name": path.name,
                "lane": lane,
                "device": details.st_dev,
                "inode": details.st_ino,
                "reservation_bytes": 1024,
                "settlement_role": role,
            }
        )

    def control(name):
        path = root / (name + ".slot")
        path.write_bytes(b"")
        path.chmod(0o440)
        details = path.stat()
        return {"name": path.name, "device": details.st_dev, "inode": details.st_ino}

    transaction, gate = control("transaction"), control("settlement_gate")
    signals = [dict(control(f"cohort_{i}"), cohort_sha256=f"{i:064x}") for i in range(6)]
    details = root.stat()
    policy = {
        "schema": "umi-host-memory-admission/2",
        "host_identity_sha256": admission._host_identity(),
        "directory": str(root),
        "directory_device": details.st_dev,
        "directory_inode": details.st_ino,
        "group_id": os.getgid(),
        "minimum_available_bytes": 24 * 1024**3,
        "incremental_budget_bytes": 4096,
        "background_reservation_bytes": 0,
        "maximum_aggregate_bytes": 1024 * 1024,
        "qualification_sha256": "a" * 64,
        "slots": slots,
        "transaction_lock": transaction,
        "settlement_gate": gate,
        "settlement_signals": signals,
    }
    path = tmp_path / "policy.json"

    def write(value=None):
        raw = json.dumps(policy if value is None else value).encode()
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o440)
        return hashlib.sha256(raw).hexdigest()

    selected = write()
    return root, path, policy, write, selected


def selected(provisioned):
    return admission.HostMemoryAdmission(provisioned[1], expected_sha256=provisioned[4])


def test_independent_opens_serialize_and_owner_lane_never_waits_for_reviewer(provisioned):
    first, second = selected(provisioned), selected(provisioned)
    transient = first.try_acquire("transient")
    owner = second.try_acquire("owner_export")
    retained = second.try_settlement("0" * 64, "coordinator")
    assert transient and owner and retained
    assert second.try_acquire("transient") is None
    assert first.try_acquire("owner_export") is None
    assert not os.get_inheritable(transient._descriptor)
    transient.close()
    transient.close()
    following = second.try_acquire("transient")
    assert following is not None
    following.close()
    owner.close()
    retained.close()


async def test_queued_cancellation_cannot_acquire_later(provisioned):
    controller = selected(provisioned)
    held = await controller.acquire("transient")
    task = asyncio.create_task(controller.acquire("transient"))
    await asyncio.sleep(0)
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    held.close()
    following = controller.try_acquire("transient")
    assert following is not None
    following.close()


async def test_owned_thread_drains_before_context_releases(provisioned):
    import threading

    controller = selected(provisioned)
    entered, release = threading.Event(), threading.Event()

    def native():
        entered.set()
        assert release.wait(timeout=10)

    async def operation():
        async with controller.hold("transient"):
            await run_owned_thread(native)

    task = asyncio.create_task(operation())
    while not entered.is_set():
        await asyncio.sleep(0.01)
    task.cancel()
    await asyncio.sleep(0)
    assert controller.try_acquire("transient") is None
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    following = controller.try_acquire("transient")
    assert following is not None
    following.close()


def test_fork_descendant_keeps_reservation_after_parent_close(provisioned):
    controller = selected(provisioned)
    held = controller.try_acquire("transient")
    assert held is not None
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(writer)
            assert os.read(reader, 1) == b"x"
            held.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(reader)
    try:
        held.close()
        assert controller.try_acquire("transient") is None
    finally:
        os.write(writer, b"x")
        os.close(writer)
        _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    following = controller.try_acquire("transient")
    assert following is not None
    following.close()


@pytest.mark.parametrize(
    "mutation", ["digest", "host", "floor", "budget", "shared_inode", "missing_lane", "bool_bytes"]
)
def test_invalid_or_unqualified_policy_refused(provisioned, mutation):
    _, path, policy, write, _original = provisioned
    if mutation == "digest":
        expected = "b" * 64
    else:
        if mutation == "host":
            policy["host_identity_sha256"] = "0" * 64
        elif mutation == "floor":
            policy["minimum_available_bytes"] -= 1
        elif mutation == "budget":
            policy["incremental_budget_bytes"] -= 1
        elif mutation == "shared_inode":
            policy["slots"][1]["inode"] = policy["slots"][0]["inode"]
        elif mutation == "missing_lane":
            policy["slots"][1]["lane"] = "owner_export"
        else:
            policy["slots"][1]["reservation_bytes"] = True
        expected = write(policy)
    with pytest.raises(ValueError):
        admission.HostMemoryAdmission(path, expected_sha256=expected)


@pytest.mark.parametrize(
    "mutation",
    ["mode", "symlink", "hardlink", "contents", "replacement", "parent_mode", "root_replacement"],
)
def test_slots_revalidated_before_every_acquisition(provisioned, mutation):
    controller = selected(provisioned)
    root = provisioned[0]
    path = root / "transient.slot"
    if mutation == "mode":
        path.chmod(0o660)
    elif mutation == "symlink":
        path.unlink()
        path.symlink_to(root / "owner_export.slot")
    elif mutation == "hardlink":
        os.link(path, root / "alias.slot")
    elif mutation == "contents":
        path.chmod(0o600)
        path.write_bytes(b"unexpected")
        path.chmod(0o440)
    elif mutation == "replacement":
        path.rename(root / "old.slot")
        path.write_bytes(b"")
        path.chmod(0o440)
    elif mutation == "parent_mode":
        root.chmod(0o770)
    else:
        root.rename(root.with_name("previous"))
        root.mkdir(mode=0o750)
    with pytest.raises((ValueError, OSError)):
        controller.try_acquire("transient")


def test_policy_path_rejects_symlink_and_mutable_parent(provisioned):
    root, path, _, _, expected = provisioned
    alias = path.with_name("alias.json")
    alias.symlink_to(path)
    with pytest.raises(OSError):
        admission.HostMemoryAdmission(alias, expected_sha256=expected)
    mode = stat.S_IMODE(root.parent.stat().st_mode)
    root.parent.chmod(mode | 0o020)
    try:
        with pytest.raises(ValueError, match="immutable"):
            admission.HostMemoryAdmission(path, expected_sha256=expected)
    finally:
        root.parent.chmod(mode)


class SmallRequest(StrictProtocolModel):
    value: int


def request():
    delivered = False

    async def receive():
        nonlocal delivered
        assert not delivered
        delivered = True
        return {"type": "http.request", "body": b'{"value":1}', "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/export",
            "headers": [
                (b"authorization", b"Bearer " + b"s" * 32),
                (b"content-type", b"application/json"),
            ],
        },
        receive,
    )


class Exporter:
    timeout_seconds = 30
    maximum_bytes = 1024 * 1024

    def __init__(self):
        self.calls = 0
        self.output = b'{"value":"' + b"a" * (256 * 1024) + b'"}'

    async def respond(self, value):
        self.calls += 1
        return self.output


def endpoint(exporter, controller):
    router = phase_review_routes(
        exporter, token="s" * 32, path="/export", request_model=SmallRequest, admission=controller
    )
    return router.routes[0].endpoint


async def send_response(response, send):
    async def receive():
        raise AssertionError("plain byte response does not consume receive")

    await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)


async def test_owner_capacity_covers_slow_response_and_uses_bounded_wire_chunks(provisioned):
    controller = selected(provisioned)
    exporter = Exporter()
    review = endpoint(exporter, controller)
    reviewer = controller.try_acquire("transient")
    response = await review(request())
    assert controller.try_acquire("owner_export") is None
    second = asyncio.create_task(review(request()))
    await asyncio.sleep(0)
    assert exporter.calls == 1 and not second.done()
    entered, release = asyncio.Event(), asyncio.Event()
    messages = []

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body" and message["body"]:
            entered.set()
            await release.wait()

    work = asyncio.create_task(send_response(response, send))
    await entered.wait()
    assert controller.try_acquire("owner_export") is None
    assert exporter.calls == 1 and not second.done()
    release.set()
    await work
    assert response.body == b""
    bodies = [m["body"] for m in messages if m["type"] == "http.response.body"]
    assert b"".join(bodies) == exporter.output
    assert max(map(len, bodies)) <= 64 * 1024
    assert messages[-1]["more_body"] is False
    following = await asyncio.wait_for(second, timeout=2)
    assert exporter.calls == 2

    async def discard(message):
        pass

    await send_response(following, discard)
    reviewer.close()
    free = controller.try_acquire("owner_export")
    assert free is not None
    free.close()


@pytest.mark.parametrize("failure", ["cancel", "disconnect"])
async def test_send_failure_drops_body_before_owner_capacity_release(provisioned, failure):
    controller = selected(provisioned)
    response = await endpoint(Exporter(), controller)(request())
    entered = asyncio.Event()

    async def send(message):
        if message["type"] == "http.response.body":
            entered.set()
            if failure == "disconnect":
                raise OSError("client disconnected")
            await asyncio.Event().wait()

    work = asyncio.create_task(send_response(response, send))
    await entered.wait()
    if failure == "cancel":
        assert controller.try_acquire("owner_export") is None
        work.cancel()
    with pytest.raises(asyncio.CancelledError if failure == "cancel" else OSError):
        await work
    assert response.body == b""
    free = controller.try_acquire("owner_export")
    assert free is not None
    free.close()


async def test_abandoned_response_keeps_capacity_until_last_reference(provisioned):
    controller = selected(provisioned)
    response = await endpoint(Exporter(), controller)(request())
    assert controller.try_acquire("owner_export") is None
    del response
    gc.collect()
    free = controller.try_acquire("owner_export")
    assert free is not None
    free.close()


async def test_export_cancellation_drains_cleanup_before_releasing_lease(provisioned):
    controller = selected(provisioned)
    entered, cleanup, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    exporter = Exporter()

    async def respond(value):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleanup.set()
            await release.wait()

    exporter.respond = respond
    work = asyncio.create_task(endpoint(exporter, controller)(request()))
    await entered.wait()
    work.cancel()
    await cleanup.wait()
    assert not work.done() and controller.try_acquire("owner_export") is None
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await work
    free = controller.try_acquire("owner_export")
    assert free is not None
    free.close()


async def test_rejected_native_input_not_retained_by_http_error_after_release(provisioned):
    controller = selected(provisioned)
    exporter = Exporter()
    observed = []

    class Graph:
        pass

    async def respond(value):
        graph = Graph()
        observed.append(weakref.ref(graph))
        # Pydantic keeps the invalid input itself inside ValidationError.
        SmallRequest.model_validate({"value": graph})
        raise AssertionError("invalid graph accepted")

    exporter.respond = respond
    with pytest.raises(HTTPException) as failed:
        await endpoint(exporter, controller)(request())
    assert failed.value.status_code == 503
    assert failed.value.__cause__ is None and failed.value.__context__ is None
    assert observed and observed[0]() is None
    free = controller.try_acquire("owner_export")
    assert free is not None
    free.close()


async def test_chunked_asgi_response_preserves_exact_bytes_and_length(provisioned):
    import httpx
    from fastapi import FastAPI

    controller = selected(provisioned)
    exporter = Exporter()
    app = FastAPI()
    app.include_router(
        phase_review_routes(
            exporter,
            token="s" * 32,
            path="/export",
            request_model=SmallRequest,
            admission=controller,
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://capacity.invalid"
    ) as client:
        response = await client.post(
            "/export", json={"value": 1}, headers={"authorization": "Bearer " + "s" * 32}
        )
    assert response.status_code == 200
    assert response.content == exporter.output
    assert int(response.headers["content-length"]) == len(exporter.output)
    assert response.headers["cache-control"] == "no-store"
    free = controller.try_acquire("owner_export")
    assert free is not None
    free.close()
