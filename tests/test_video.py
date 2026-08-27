from __future__ import annotations

import asyncio
import hashlib

import httpx
import pytest

from umi.protocol import Video
from umi.video import HttpVideoFetcher, VideoFetchError


def descriptor(body: bytes, *, url: str = "https://objects.example/opaque") -> Video:
    return Video.model_validate(
        {
            "url": url,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body),
            "media_type": "video/mp4",
        }
    )


def fetcher(handler) -> HttpVideoFetcher:
    return HttpVideoFetcher(
        allowed_hosts=frozenset({"objects.example"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_video_is_streamed_and_verified_exactly() -> None:
    body = b"video bytes"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "objects.example"
        return httpx.Response(
            200,
            headers={
                "Content-Length": str(len(body)),
                "Content-Type": "video/mp4",
            },
            content=body,
        )

    assert await fetcher(handler).fetch(descriptor(body)) == body


@pytest.mark.asyncio
async def test_video_hash_mismatch_fails_closed() -> None:
    declared = b"right bytes"
    delivered = b"wrong bytes"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "video/mp4"},
            content=delivered,
        )

    with pytest.raises(VideoFetchError, match="SHA-256"):
        await fetcher(handler).fetch(descriptor(declared))


@pytest.mark.asyncio
async def test_video_declared_or_streamed_oversize_aborts() -> None:
    body = b"1234"

    def wrong_length(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "8", "Content-Type": "video/mp4"},
            content=body,
        )

    with pytest.raises(VideoFetchError, match="Content-Length"):
        await fetcher(wrong_length).fetch(descriptor(body))

    streaming_fetcher = HttpVideoFetcher(
        allowed_hosts=frozenset({"objects.example"}),
        maximum_clip_size_bytes=2,
        timeout_seconds=5,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                content=body,
            )
        ),
    )
    with pytest.raises(VideoFetchError, match="declared video size"):
        await streaming_fetcher.fetch(descriptor(body))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://objects.example/opaque",
        "https://not-allowed.example/opaque",
        "https://user:password@objects.example/opaque",
        "https://objects.example:8443/opaque",
        "https://objects.example/opaque#label",
    ],
)
async def test_video_url_boundary_rejects_untrusted_origins(url: str) -> None:
    body = b"video"
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=body)

    with pytest.raises(VideoFetchError):
        await fetcher(handler).fetch(descriptor(body, url=url))
    assert called is False


@pytest.mark.asyncio
async def test_nonstandard_video_port_must_be_explicitly_allowlisted() -> None:
    body = b"video"
    custom = HttpVideoFetcher(
        allowed_hosts=frozenset({"objects.example"}),
        allowed_ports=frozenset({8443}),
        maximum_clip_size_bytes=32,
        timeout_seconds=5,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                content=body,
            )
        ),
    )
    assert await custom.fetch(descriptor(body, url="https://objects.example:8443/opaque")) == body


@pytest.mark.asyncio
async def test_video_fetch_timeout_is_total_not_per_chunk() -> None:
    body = b"video"

    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for byte in body:
                await asyncio.sleep(0.01)
                yield bytes([byte])

        async def aclose(self) -> None:
            return None

    slow = HttpVideoFetcher(
        allowed_hosts=frozenset({"objects.example"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=0.02,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                stream=SlowStream(),
            )
        ),
    )
    with pytest.raises(VideoFetchError, match="total deadline"):
        await slow.fetch(descriptor(body))
