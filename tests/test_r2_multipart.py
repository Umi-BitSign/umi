from __future__ import annotations

import asyncio
import gzip
from datetime import datetime, timezone

import httpx
import pytest

from umi import r2_multipart as module
from umi.competition_cohort_direct_model_upload import DirectModelUploadPart
from umi.competition_transport_verification import TransferProgress
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


@pytest.mark.parametrize("cancel", [False, True])
async def test_range_reports_partial_response_without_completing_parent(cancel):
    entered, release = asyncio.Event(), asyncio.Event()
    closed, requests, events = [], [], []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"ab"
            entered.set()
            await release.wait()
            yield b"cd"

        async def aclose(self):
            closed.append(True)

    async def send(request):
        requests.append(request)
        return httpx.Response(206, headers={"Content-Range": "bytes 0-3/4"}, stream=Stream())

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    with TransferProgress("materialize", 4, events.append) as parent:
        task = asyncio.create_task(client.read_range(KEY, offset=0, size_bytes=4, at=AT))
        await entered.wait()
        assert parent.completed == 0
        assert parent.child["stage"] == "r2_response_read"
        assert parent.child["completed_units"] == 2
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert parent.child["status"] == "retrying"
        else:
            release.set()
            assert await task == b"abcd"
            assert parent.child["status"] == "completed"
        assert parent.completed == 0
    assert len(requests) == len(closed) == 1
    assert events[-1]["status"] == "retrying"


async def test_response_diagnostics_cannot_fail_a_valid_read(monkeypatch):
    from umi import competition_transport_verification as progress

    client = R2MultipartClient(
        signer(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(206, headers={"Content-Range": "bytes 0-3/4"}, content=b"abcd")
        ),
    )
    with TransferProgress("materialize", 4) as parent:

        def unavailable(_):
            raise RuntimeError("diagnostic thread unavailable")

        monkeypatch.setattr(progress.Thread, "start", unavailable)
        assert await client.read_range(KEY, offset=0, size_bytes=4, at=AT) == b"abcd"
        assert progress._CURRENT.get() is parent


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
async def test_exact_multipart_probe_and_absent_abort_are_idempotent():
    responses = iter((httpx.Response(200, content=b"<ListPartsResult/>"), httpx.Response(404)))
    requests = []

    async def send(request):
        requests.append(request)
        if request.method == "GET":
            return next(responses)
        assert request.method == "DELETE"
        return httpx.Response(404)

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    assert await client.multipart_exists(KEY, upload_id="provider+/id=", at=AT) is True
    assert await client.multipart_exists(KEY, upload_id="provider+/id=", at=AT) is False
    await client.abort(KEY, upload_id="provider+/id=", at=AT)
    assert [request.url.params["uploadId"] for request in requests] == [
        "provider+/id=",
        "provider+/id=",
        "provider+/id=",
    ]


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


@pytest.mark.parametrize("method", ["HEAD", "GET"])
@pytest.mark.parametrize("status", [429, 503])
async def test_transient_reads_retry_same_scope_without_echoing_provider_body(
    monkeypatch, caplog, method, status
):
    requests, waits = [], []

    async def pause(seconds):
        waits.append(seconds)

    async def send(request):
        requests.append(request)
        if len(requests) < 3:
            return httpx.Response(status, content=b"credential-bearing provider detail")
        return httpx.Response(200, content=b"verified response")

    monkeypatch.setattr(module.asyncio, "sleep", pause)
    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    response = await client._exchange(method, KEY, at=AT)
    assert response.status_code == 200 and len(requests) == 3
    assert waits == [0.25, 0.5]
    assert all(request.url == requests[0].url for request in requests)
    assert all(
        request.headers["authorization"] == requests[0].headers["authorization"]
        for request in requests
    )
    assert f'"http_status":{status}' in caplog.text
    assert "credential-bearing" not in caplog.text and KEY not in caplog.text


@pytest.mark.parametrize(
    "method,status,attempts", [("GET", 503, 3), ("GET", 403, 1), ("POST", 503, 1), ("PUT", 503, 1)]
)
async def test_read_retries_are_bounded_and_never_replay_mutations(
    monkeypatch, method, status, attempts
):
    calls = []

    async def pause(_):
        pass

    def send(request):
        calls.append(request)
        return httpx.Response(status, content=b"private provider body")

    monkeypatch.setattr(module.asyncio, "sleep", pause)
    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    with pytest.raises(OSError, match=f"HTTP {status}"):
        await client._exchange(method, KEY, at=AT)
    assert len(calls) == attempts


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


@pytest.mark.asyncio
async def test_copy_part_signs_exact_source_range_and_object_delete_is_idempotent():
    requests = []

    async def send(request):
        requests.append(request)
        if request.method == "PUT":
            assert dict(request.url.params) == {
                "partNumber": "2",
                "uploadId": "provider-id",
            }
            assert request.headers["x-amz-copy-source"] == (
                "/umi-model-artifacts/incoming/v2/source/payload"
            )
            assert request.headers["x-amz-copy-source-range"] == "bytes=0-5242879"
            assert "x-amz-copy-source-range" in request.headers["authorization"]
            return httpx.Response(
                200,
                content=b'<CopyPartResult><ETag>"ab' + b"ab" * 15 + b'"</ETag></CopyPartResult>',
            )
        if len([value for value in requests if value.method == "DELETE"]) == 1:
            return httpx.Response(204)
        return httpx.Response(404)

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    part = await client.copy_part(
        "preservation/v1/model/payload",
        source_key="incoming/v2/source/payload",
        upload_id="provider-id",
        part_number=2,
        offset=0,
        size_bytes=5 * 1024**2,
        source_size_bytes=6 * 1024**2,
        at=AT,
    )
    assert part == DirectModelUploadPart(part_number=2, size_bytes=5 * 1024**2, etag="ab" * 16)
    await client.delete_object("incoming/v2/source/payload", at=AT)
    await client.delete_object("incoming/v2/source/payload", at=AT)


@pytest.mark.asyncio
async def test_whole_object_copy_omits_range_header():
    async def send(request):
        assert "x-amz-copy-source-range" not in request.headers
        return httpx.Response(
            200,
            content=b'<CopyPartResult><ETag>"' + b"cd" * 16 + b'"</ETag></CopyPartResult>',
        )

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(send))
    part = await client.copy_part(
        "preservation/v1/model/payload",
        source_key="incoming/v2/source/payload",
        upload_id="provider-id",
        part_number=1,
        offset=0,
        size_bytes=20,
        source_size_bytes=20,
        at=AT,
    )
    assert part.size_bytes == 20
