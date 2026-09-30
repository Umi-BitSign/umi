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
    state = SimpleNamespace(now=1790630000, objects={}, uploads=[], lost=False, fault=None)
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
    with pytest.raises(httpx.ReadError):
        await c.open()(c.sha)
    first = await c.open()(c.sha)
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
