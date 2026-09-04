from __future__ import annotations

import asyncio
import gzip
import hashlib

import httpx
import pytest

from umi.protocol import Video
from umi.video import HttpVideoFetcher, VideoFetchError


async def public_resolver(_hostname: str, _port: int) -> tuple[str, ...]:
    return ("93.184.216.34",)


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
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=public_resolver,
    )


@pytest.mark.asyncio
async def test_video_is_streamed_and_verified_exactly() -> None:
    body = b"video bytes"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "93.184.216.34"
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200,
            headers={
                "Content-Length": str(len(body)),
                "Content-Type": "video/mp4",
            },
            content=body,
        )

    selected = fetcher(handler)
    assert await selected.fetch(descriptor(body)) == body
    receipt = await selected.fetch_with_receipt(descriptor(body))
    assert receipt.data == body
    assert receipt.wire_bytes > len(body)


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

    with pytest.raises(VideoFetchError, match="SHA-256") as error:
        await fetcher(handler).fetch(descriptor(declared))
    assert error.value.wire_bytes >= len(delivered)


@pytest.mark.asyncio
async def test_video_rejects_oversized_response_headers_before_body() -> None:
    body = b"video"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[
                (b"content-type", b"video/mp4"),
                (b"x-bloat", b"a" * 128),
            ],
            content=body,
        )

    bounded = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=32,
        maximum_http_header_bytes=64,
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=public_resolver,
    )
    with pytest.raises(VideoFetchError, match="headers exceed"):
        await bounded.fetch(descriptor(body))


@pytest.mark.asyncio
async def test_video_rejects_content_encoding_before_decoding_or_hashing() -> None:
    body = b"video"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200,
            headers={
                "Content-Type": "video/mp4",
                "Content-Encoding": "gzip",
            },
            content=gzip.compress(body),
        )

    with pytest.raises(VideoFetchError, match="encoded video responses"):
        await fetcher(handler).fetch(descriptor(body))


@pytest.mark.asyncio
async def test_video_rejects_oversized_generated_request_headers_before_send() -> None:
    body = b"video"
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=body)

    bounded = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=32,
        maximum_http_header_bytes=8,
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=public_resolver,
    )
    with pytest.raises(VideoFetchError, match="request headers exceed") as error:
        await bounded.fetch(descriptor(body))
    assert error.value.wire_bytes > 8
    assert called is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maximum_clip_size_bytes", True),
        ("maximum_http_header_bytes", 1.5),
        ("timeout_seconds", float("nan")),
        ("allowed_origins", frozenset({"ftp://objects.example"})),
    ],
)
def test_video_fetcher_rejects_ambiguous_limit_types(field: str, value: object) -> None:
    values = {
        "allowed_origins": frozenset({"https://objects.example"}),
        "maximum_clip_size_bytes": 32,
        "maximum_http_header_bytes": 16,
        "timeout_seconds": 5,
    }
    values[field] = value
    with pytest.raises(ValueError):
        HttpVideoFetcher(**values)


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
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=2,
        timeout_seconds=5,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                content=body,
            )
        ),
        resolver=public_resolver,
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
async def test_nonstandard_video_port_must_be_in_exact_allowlisted_origin() -> None:
    body = b"video"
    custom = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example:8443"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=5,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                content=body,
            )
        ),
        resolver=public_resolver,
    )
    assert await custom.fetch(descriptor(body, url="https://objects.example:8443/opaque")) == body


@pytest.mark.asyncio
async def test_video_origin_allowlist_does_not_cross_product_hosts_and_ports() -> None:
    body = b"video"
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(
            200,
            headers={"Content-Type": "video/mp4"},
            content=body,
        )

    exact = HttpVideoFetcher(
        allowed_origins=frozenset(
            {
                "https://objects-a.example",
                "https://objects-b.example:8443",
            }
        ),
        maximum_clip_size_bytes=32,
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=public_resolver,
    )
    with pytest.raises(VideoFetchError, match="origin is not allowlisted"):
        await exact.fetch(descriptor(body, url="https://objects-a.example:8443/opaque"))
    assert called is False


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
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=0.02,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                stream=SlowStream(),
            )
        ),
        resolver=public_resolver,
    )
    with pytest.raises(VideoFetchError, match="total deadline"):
        await slow.fetch(descriptor(body))


@pytest.mark.asyncio
async def test_video_fetch_pins_public_dns_result_and_preserves_https_authority() -> None:
    body = b"video"

    async def resolver(hostname: str, port: int) -> tuple[str, ...]:
        assert (hostname, port) == ("objects.example", 443)
        return ("93.184.216.34",)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "93.184.216.34"
        assert request.headers["host"] == "objects.example"
        assert request.extensions["sni_hostname"] == "objects.example"
        return httpx.Response(
            200,
            headers={"Content-Type": "video/mp4"},
            content=body,
        )

    pinned = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )
    assert await pinned.fetch(descriptor(body)) == body


@pytest.mark.asyncio
async def test_video_fetch_timeout_includes_hostname_resolution() -> None:
    body = b"video"
    called = False

    async def slow_resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        await asyncio.sleep(0.05)
        return ("93.184.216.34",)

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=body)

    pinned = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=0.01,
        transport=httpx.MockTransport(handler),
        resolver=slow_resolver,
    )
    with pytest.raises(VideoFetchError, match="total deadline"):
        await pinned.fetch(descriptor(body))
    assert called is False


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ("127.0.0.1", "10.0.0.1", "::1", "169.254.1.1"))
async def test_video_fetch_rejects_nonpublic_dns_results_before_connect(address: str) -> None:
    body = b"video"
    called = False

    async def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        return (address,)

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=body)

    pinned = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=32,
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )
    with pytest.raises(VideoFetchError, match="non-public"):
        await pinned.fetch(descriptor(body))
    assert called is False
