from __future__ import annotations

import gzip
from datetime import datetime, timezone

import httpx
import pytest

from umi.competition_cohort_direct_model_upload import DirectModelUploadPart
from umi.r2_multipart import R2MultipartClient
from umi.r2_sigv4 import R2Credentials, R2SigV4

AT = datetime(2026, 10, 2, 20, 0, tzinfo=timezone.utc)
KEY = "incoming/v2/aa/bb/cc/payload"


def signer():
    return R2SigV4(
        endpoint="https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
        bucket="umi-model-artifacts",
        credentials=R2Credentials("0123456789ABCDEF", "secret-access-key-value"),
    )


@pytest.mark.asyncio
async def test_create_complete_head_and_abort_are_exactly_scoped():
    requests = []

    async def send(request):
        requests.append(request)
        assert request.headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=")
        assert "secret-access-key-value" not in str(request.headers)
        if request.method == "POST" and request.url.params.get("uploads") == "":
            return httpx.Response(
                200,
                content=(
                    b'<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    b"<UploadId>provider+/id=</UploadId></InitiateMultipartUploadResult>"
                ),
            )
        if request.method == "POST":
            assert request.url.params["uploadId"] == "provider+/id="
            assert request.content == (
                b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                b'<ETag>"abababababababababababababababab"</ETag></Part>'
                b"</CompleteMultipartUpload>"
            )
            return httpx.Response(200, content=b"<Result><ETag>object-etag-1</ETag></Result>")
        if request.method == "HEAD":
            return httpx.Response(200, headers={"Content-Length": "7", "ETag": '"object-etag-1"'})
        if request.method == "DELETE":
            assert request.url.params["uploadId"] == "provider+/id="
            return httpx.Response(204)
        raise AssertionError(request.method)

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    upload_id = await client.create(KEY, at=AT)
    assert upload_id == "provider+/id="
    etag = await client.complete(
        KEY,
        upload_id=upload_id,
        parts=(DirectModelUploadPart(part_number=1, size_bytes=7, etag="ab" * 16),),
        at=AT,
    )
    assert etag == "object-etag-1"
    assert (await client.head(KEY, at=AT)).size_bytes == 7
    await client.abort(KEY, upload_id=upload_id, at=AT)
    assert [request.method for request in requests] == ["POST", "POST", "HEAD", "DELETE"]


@pytest.mark.asyncio
async def test_head_404_is_absent_without_parsing_error_body():
    client = R2MultipartClient(
        signer(), transport=httpx.MockTransport(lambda _: httpx.Response(404, content=b"missing"))
    )
    assert await client.head(KEY, at=AT) is None


@pytest.mark.asyncio
async def test_provider_errors_are_bounded_and_do_not_echo_body():
    client = R2MultipartClient(
        signer(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(503, content=b"credential-bearing provider detail")
        ),
    )
    with pytest.raises(OSError, match="HTTP 503") as observed:
        await client.create(KEY, at=AT)
    assert "credential-bearing" not in str(observed.value)


@pytest.mark.asyncio
async def test_success_response_stops_at_configured_byte_bound():
    chunks_read = 0

    class Oversized(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal chunks_read
            for _ in range(3):
                chunks_read += 1
                yield b"x" * (32 * 1024)

    client = R2MultipartClient(
        signer(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=Oversized())),
    )
    with pytest.raises(ValueError, match="too large"):
        await client.create(KEY, at=AT)
    assert chunks_read == 3


@pytest.mark.asyncio
async def test_read_range_requires_exact_identity_encoded_bytes():
    async def send(request):
        assert request.method == "GET"
        assert request.headers["range"] == "bytes=7-10"
        return httpx.Response(
            206,
            headers={"Content-Range": "bytes 7-10/20", "Content-Encoding": "identity"},
            content=b"data",
        )

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    assert await client.read_range(KEY, offset=7, size_bytes=4, at=AT) == b"data"


@pytest.mark.asyncio
async def test_read_range_rejects_partial_or_reencoded_response():
    for response in (
        httpx.Response(206, headers={"Content-Range": "bytes 7-9/20"}, content=b"data"),
        httpx.Response(
            206,
            headers={"Content-Range": "bytes 7-10/20", "Content-Encoding": "gzip"},
            content=gzip.compress(b"data"),
        ),
    ):
        client = R2MultipartClient(
            signer(), transport=httpx.MockTransport(lambda _, value=response: value)
        )
        with pytest.raises(ValueError):
            await client.read_range(KEY, offset=7, size_bytes=4, at=AT)
