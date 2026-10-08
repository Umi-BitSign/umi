"""Native clip publisher against a synthetic implementation of the clip HTTP contract."""

import hashlib
import logging
from types import SimpleNamespace

import httpx
import pytest

import umi.competition_cohort_clip_delivery as delivery
from umi.private_files import ensure_private_directory


@pytest.fixture
async def clips(tmp_path, monkeypatch):
    root = tmp_path / "clips"
    ensure_private_directory(root)
    body = b"\0\0\0\x10ftyp" + b"retained-test-video" * 100
    sha = hashlib.sha256(body).hexdigest()
    (root / (sha + ".mp4")).write_bytes(body)
    state = SimpleNamespace(
        now=1790630000, objects={}, uploads=[], lost=False, fault=None, transport_error=None
    )
    monkeypatch.setattr(delivery.time, "time", lambda: state.now)
    cfg = delivery.ClipDeliveryConfig(
        schema="umi-cohort-clip-delivery-config/1",
        directory=str(tmp_path / "journal"),
        videos_directory=str(root),
        origin="https://clips.example",
        upload_token_file=str(tmp_path / "credential"),
        timeout_seconds=1,
    )

    async def route(request):
        path = request.url.path
        if state.fault == "redirect":
            return httpx.Response(302, headers={"location": "https://other.example/private"})
        if request.method == "PUT":
            assert request.headers["authorization"] == "Bearer " + "a" * 64
            assert request.headers["content-type"] == "video/mp4"
            assert request.content == body
            state.uploads.append(path)
            state.objects[path] = request.content
            if state.lost:
                state.lost = False
                raise httpx.ReadError("lost upload acknowledgement")
            return httpx.Response(201)
        assert request.method == "GET" and "authorization" not in request.headers
        if state.transport_error is not None:
            raise state.transport_error("private clip transport failed", request=request)
        if path not in state.objects:
            return httpx.Response(404)
        value = state.objects[path]
        headers = {"content-type": "video/mp4", "content-length": str(len(value))}
        if state.fault == "digest":
            value = b"!" + value[1:]
        if state.fault == "oversize":
            value += b"!"
        return httpx.Response(200, content=value, headers=headers)

    async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
        state.open = lambda: delivery.CohortClipDelivery(cfg, client, "a" * 64)
        state.sha, state.body, state.root = sha, body, root
        yield state


async def test_upload_recovers_lost_ack_and_automatically_renews(clips):
    c = clips
    c.lost = True
    uploader = c.open()
    with pytest.raises(OSError, match="transport is unavailable") as failed:
        await uploader(c.sha)
    assert isinstance(failed.value.__cause__, httpx.ReadError)
    slot, intent, _ = uploader._select(c.sha, c.now)
    assert uploader.journal.get("complete", slot) is None
    first = await c.open()(c.sha)
    assert first == intent.video
    assert len(c.uploads) == 1
    assert c.uploads[0] in first.url
    # Deletion is repaired at the exact same capability; no new signed request.
    c.objects.clear()
    assert await c.open()(c.sha) == first
    assert c.uploads[0] == c.uploads[1]
    c.now += 10 * 86400
    next_ = await c.open()(c.sha)
    assert next_.url != first.url and next_.sha256 == first.sha256
    assert len(c.uploads) == 3


@pytest.mark.parametrize("error", [httpx.ReadError, httpx.ConnectError, httpx.ReadTimeout])
async def test_transport_failure_retries_original_intent_without_republishing(clips, error):
    uploader = clips.open()
    slot, intent, body = uploader._select(clips.sha, clips.now)
    path = httpx.URL(intent.video.url).path
    clips.objects[path] = body
    clips.transport_error = error
    with pytest.raises(OSError, match="transport is unavailable") as failed:
        await uploader(clips.sha)
    assert isinstance(failed.value.__cause__, error)
    assert uploader.journal.get("complete", slot) is None
    assert not clips.uploads
    clips.transport_error = None
    assert await clips.open()(clips.sha) == intent.video
    assert uploader.journal.get("complete", slot) == {"intent": delivery.digest(intent)}
    assert not clips.uploads


@pytest.mark.parametrize("fault", ["digest", "oversize", "redirect"])
async def test_bad_delivery_does_not_return_a_video(clips, fault):
    await clips.open()(clips.sha)
    clips.fault = fault
    with pytest.raises((OSError, ValueError)):
        await clips.open()(clips.sha)


async def test_changed_local_original_is_not_uploaded(clips):
    (clips.root / (clips.sha + ".mp4")).write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest"):
        await clips.open()(clips.sha)
    assert not clips.uploads


async def test_capabilities_and_credentials_stay_out_of_logs(clips, caplog):
    with caplog.at_level(logging.DEBUG):
        video = await clips.open()(clips.sha)
    assert "[redacted]" in caplog.text
    assert video.url not in caplog.text and "a" * 64 not in caplog.text


async def test_cancelled_upload_keeps_original_intent(clips, monkeypatch):
    import asyncio

    uploader = clips.open()
    entered = asyncio.Event()
    verify = uploader._verify

    async def stuck(video):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(uploader, "_verify", stuck)
    task = asyncio.create_task(uploader(clips.sha))
    await asyncio.wait_for(entered.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    monkeypatch.setattr(uploader, "_verify", verify)
    assert await clips.open()(clips.sha) == await uploader(clips.sha)
    assert len(clips.uploads) == 1


async def test_slow_clip_does_not_block_other_clips_or_duplicate_its_upload(tmp_path):
    import asyncio

    root = tmp_path / "videos"
    ensure_private_directory(root)
    bodies = [b"\0\0\0\x10ftyp" + bytes([n]) * 100 for n in range(2)]
    videos = {hashlib.sha256(body).hexdigest(): body for body in bodies}
    for sha, body in videos.items():
        (root / (sha + ".mp4")).write_bytes(body)
    slow, fast = videos
    entered, release = asyncio.Event(), asyncio.Event()
    objects, uploads = {}, []
    active = peak = 0

    async def route(request):
        nonlocal active, peak
        sha = request.url.path.rsplit("/", 1)[-1][:-4]
        if request.method == "PUT":
            assert request.content == videos[sha]
            objects[str(request.url)] = request.content
            uploads.append(sha)
            return httpx.Response(201)
        assert request.method == "GET"
        if sha == slow:
            active += 1
            peak = max(peak, active)
            entered.set()
            try:
                await release.wait()
            finally:
                active -= 1
        if str(request.url) not in objects:
            return httpx.Response(404)
        body = objects[str(request.url)]
        return httpx.Response(
            200,
            content=body,
            headers={"content-type": "video/mp4", "content-length": str(len(body))},
        )

    cfg = delivery.ClipDeliveryConfig(
        schema="umi-cohort-clip-delivery-config/1",
        directory=str(tmp_path / "journal"),
        videos_directory=str(root),
        origin="https://clips.example",
        upload_token_file=str(tmp_path / "credential"),
        timeout_seconds=120,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
        publisher = delivery.CohortClipDelivery(cfg, client, "a" * 64)
        first = asyncio.create_task(publisher(slow))
        duplicate = None
        try:
            await asyncio.wait_for(entered.wait(), timeout=120)
            duplicate = asyncio.create_task(publisher(slow))
            delivered = await asyncio.wait_for(publisher(fast), timeout=120)
            assert delivered.sha256 == fast and not first.done() and not duplicate.done()
            assert peak == 1
            release.set()
            original, repeated = await asyncio.wait_for(
                asyncio.gather(first, duplicate), timeout=120
            )
            assert original == repeated and uploads.count(slow) == uploads.count(fast) == 1
            assert peak == 1 and not publisher.clip_locks
        finally:
            release.set()
            for task in (first, duplicate):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (first, duplicate) if task is not None), return_exceptions=True
            )


@pytest.mark.parametrize("concurrency", [1, 2])
async def test_clip_capacity_bounds_transfers_and_canceled_waiters_leave_no_owner(
    tmp_path, concurrency
):
    import asyncio

    root = tmp_path / "videos"
    ensure_private_directory(root)
    videos = {}
    for n in range(3):
        body = b"\0\0\0\x10ftyp" + bytes([n]) * 100
        sha = hashlib.sha256(body).hexdigest()
        videos[sha] = body
        (root / (sha + ".mp4")).write_bytes(body)
    started, release = asyncio.Event(), asyncio.Event()
    objects = {}
    active = peak = 0

    async def route(request):
        nonlocal active, peak
        sha = request.url.path.rsplit("/", 1)[-1][:-4]
        if request.method == "PUT":
            assert request.content == videos[sha]
            objects[str(request.url)] = request.content
            return httpx.Response(201)
        assert request.method == "GET"
        active += 1
        peak = max(peak, active)
        if active == concurrency:
            started.set()
        try:
            await release.wait()
        finally:
            active -= 1
        if str(request.url) not in objects:
            return httpx.Response(404)
        body = objects[str(request.url)]
        return httpx.Response(
            200,
            content=body,
            headers={"content-type": "video/mp4", "content-length": str(len(body))},
        )

    cfg = delivery.ClipDeliveryConfig(
        schema="umi-cohort-clip-delivery-config/1",
        directory=str(tmp_path / "journal"),
        videos_directory=str(root),
        origin="https://clips.example",
        upload_token_file=str(tmp_path / "credential"),
        timeout_seconds=120,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
        publisher = delivery.CohortClipDelivery(cfg, client, "a" * 64, concurrency=concurrency)
        tasks = [asyncio.create_task(publisher(sha)) for sha in videos]
        try:
            await asyncio.wait_for(started.wait(), timeout=120)
            assert active == peak == concurrency and not any(task.done() for task in tasks)
            for task in tasks[concurrency:]:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert len(publisher.clip_locks) == concurrency
            release.set()
            completed = await asyncio.wait_for(asyncio.gather(*tasks[:concurrency]), timeout=120)
            assert len(completed) == concurrency and peak == concurrency
            assert not publisher.clip_locks
        finally:
            release.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
