from __future__ import annotations

import asyncio
import hashlib
import io
import logging

import httpcore
import httpx
import pytest

from umi.http_logging import (
    install_http_log_redaction,
    redact_http_secrets,
    video_fetch_logging,
)
from umi.protocol import Video
from umi.video import HttpVideoFetcher, VideoFetchError

CAP = "clip-capability-DO-NOT-LOG"
QUERY = "query-credential-DO-NOT-LOG"
COOKIE = "response-cookie-DO-NOT-LOG"
BODY = b"video"
PATH = f"/v1/clips/1790100000/1790200000/{CAP}/{'a' * 64}.mp4"
URL = f"https://objects.example{PATH}?signature={QUERY}"


@pytest.fixture(autouse=True)
def restore_factory():
    previous = logging.getLogRecordFactory()
    try:
        yield
    finally:
        logging.setLogRecordFactory(previous)


def assert_private(text):
    assert CAP not in text
    assert QUERY not in text
    assert COOKIE not in text


class WireStream(httpcore.AsyncMockStream):
    def __init__(self, status=200, failure=None):
        raw = (
            f"HTTP/1.1 {status} status\r\nContent-Type: video/mp4\r\nContent-Length: 5\r\n"
            f"Location: {URL}\r\nSet-Cookie: session={COOKIE}\r\n\r\n"
        ).encode() + BODY
        super().__init__([raw])
        self.failure = failure
        self.writes = []

    async def write(self, buffer, timeout=None):
        self.writes.append(buffer)

    async def read(self, max_bytes, timeout=None):
        if self.failure == "read":
            raise httpcore.ReadError(f"read failed for {URL}")
        if self.failure == "timeout":
            raise httpcore.ReadTimeout(f"timed out for {URL}")
        return await super().read(max_bytes, timeout)

    async def aclose(self):
        await super().aclose()
        if self.failure == "close":
            raise httpcore.WriteError(f"close failed for {URL}")


class WireBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, stream, failure=None):
        self.stream = stream
        self.failure = failure

    async def connect_tcp(self, host, port, **kwargs):
        assert (host, port) == ("93.184.216.34", 443)
        if self.failure == "connect":
            raise httpcore.ConnectError(f"connect failed for {URL}")
        return self.stream


def video_fetcher(status=200, failure=None):
    stream = WireStream(status, failure)
    transport = httpx.AsyncHTTPTransport(trust_env=False)
    # Exercise the installed HTTPX -> HTTPCORE trace/HTTP parsing path. Only
    # sockets are replaced; MockTransport would miss HTTPCORE's logging entirely.
    transport._pool = httpcore.AsyncConnectionPool(network_backend=WireBackend(stream, failure))

    async def resolve(host, port):
        assert (host, port) == ("objects.example", 443)
        return ("93.184.216.34",)

    fetcher = HttpVideoFetcher(
        allowed_origins=frozenset({"https://objects.example"}),
        maximum_clip_size_bytes=1024,
        timeout_seconds=2,
        transport=transport,
        resolver=resolve,
    )
    descriptor = Video(
        url=URL,
        sha256=hashlib.sha256(BODY).hexdigest(),
        size_bytes=len(BODY),
        media_type="video/mp4",
    )
    return fetcher, descriptor, stream


@pytest.mark.asyncio
@pytest.mark.parametrize("level", [logging.INFO, logging.DEBUG])
@pytest.mark.parametrize("status", [200, 403, 429, 503])
async def test_real_http_logs_redacted_without_changing_request(caplog, level, status):
    caplog.set_level(level)
    fetcher, descriptor, stream = video_fetcher(status)
    if status == 200:
        receipt = await fetcher.fetch_with_receipt(descriptor)
        assert receipt.data == BODY
        assert receipt.wire_bytes > len(BODY)
    else:
        with pytest.raises(VideoFetchError, match=f"HTTP {status}"):
            await fetcher.fetch(descriptor)
    raw_request = b"".join(stream.writes)
    assert f"GET {PATH}?signature={QUERY} HTTP/1.1".encode() in raw_request
    assert b"Host: objects.example\r\n" in raw_request
    assert str(descriptor.url) == URL
    assert_private(caplog.text)
    assert (
        f'HTTP Request: GET https://93.184.216.34/v1/clips/[redacted] "HTTP/1.1 {status}'
        in caplog.text
    )
    records = [r for r in caplog.records if r.name.startswith(("httpx", "httpcore"))]
    assert records
    assert_private(repr([vars(r) for r in records]))
    if level == logging.DEBUG:
        assert any(r.name == "httpcore.http11" for r in records)
        assert "receive_response_headers.complete [video fetch details redacted]" in caplog.text
        assert "response_closed.complete" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("level", [logging.INFO, logging.DEBUG])
@pytest.mark.parametrize("failure", ["connect", "read", "timeout", "close"])
async def test_real_http_failures_and_later_caller_traceback_redacted(caplog, level, failure):
    caplog.set_level(level)
    fetcher, descriptor, _ = video_fetcher(failure=failure)
    with pytest.raises((VideoFetchError, httpx.HTTPError)) as caught:
        try:
            await fetcher.fetch(descriptor)
        except Exception:
            # Log after the fetch context has exited, as an embedding caller can.
            logging.getLogger("application.caller").exception("video request failed")
            raise
    assert_private(caplog.text)
    assert "video request failed" in caplog.text
    assert "Traceback" in caplog.text
    # Redaction must not change transport exception objects or their causes.
    error = caught.value
    while error.__cause__ is not None:
        error = error.__cause__
    assert CAP in str(error)
    assert QUERY in str(error)
    if level == logging.DEBUG:
        assert ".failed [video fetch details redacted]" in caplog.text


@pytest.mark.parametrize(
    "message",
    [
        URL,
        repr(URL.encode()),
        f"target=b'{PATH}?signature={QUERY}'",
        f"https://objects.example{PATH.replace('/', '%2F')}?token={QUERY}",
        f"https://alice:{QUERY}@objects.example/public?key={CAP}#private",
        f"authorization=b'Bearer {CAP}'",
        f"https://[broken/{CAP}?key={QUERY}",
    ],
)
def test_url_and_bearer_formats_are_redacted_idempotently(message):
    result = redact_http_secrets(message)
    assert_private(result)
    assert "[redacted" in result
    assert redact_http_secrets(result) == result


def test_ordinary_http_diagnostics_remain_unchanged():
    value = 'HTTP Request: POST https://api.umi.vision/v1/competition/assignments/query "200 OK"'
    assert redact_http_secrets(value) == value


def test_factory_chaining_idempotence_and_late_child_direct_handler():
    previous = logging.getLogRecordFactory()

    def custom_factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        record.application_field = "preserved"
        return record

    logging.setLogRecordFactory(custom_factory)
    install_http_log_redaction()
    installed = logging.getLogRecordFactory()
    install_http_log_redaction()
    assert logging.getLogRecordFactory() is installed
    logger = logging.getLogger("httpcore.newly_created_child")
    old_level, old_propagate = logger.level, logger.propagate
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(logging.Formatter("%(application_field)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        with video_fetch_logging():
            logger.debug("receive_response_headers.complete return_value=%r", COOKIE)
        logger.info("request %s", URL)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        logger.propagate = old_propagate
    assert_private(output.getvalue())
    assert "preserved receive_response_headers.complete" in output.getvalue()
    assert "preserved request https://objects.example/v1/clips/[redacted]" in output.getvalue()


@pytest.mark.asyncio
async def test_trace_suppression_is_task_local_and_resets_after_cancellation(caplog):
    caplog.set_level(logging.DEBUG)
    entered = asyncio.Event()
    wait = asyncio.Event()
    core = logging.getLogger("httpcore.http2")

    async def clip_task():
        with video_fetch_logging():
            entered.set()
            core.debug("receive_response_headers.complete return_value=%r", COOKIE)
            await wait.wait()

    task = asyncio.create_task(clip_task())
    await entered.wait()
    core.debug("ordinary_request headers=public-diagnostic")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    core.debug("after_cancel headers=still-public")
    assert_private(caplog.text)
    assert "ordinary_request headers=public-diagnostic" in caplog.text
    assert "after_cancel headers=still-public" in caplog.text


def test_nested_context_restores_outer_protection(caplog):
    caplog.set_level(logging.DEBUG)
    core = logging.getLogger("httpcore.http11")
    with video_fetch_logging():
        with video_fetch_logging():
            core.debug("inner return_value=%s", COOKIE)
        core.debug("outer return_value=%s", COOKIE)
    core.debug("outside ordinary diagnostic")
    assert_private(caplog.text)
    assert "outside ordinary diagnostic" in caplog.text
