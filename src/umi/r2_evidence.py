"""Bounded synchronous R2 evidence transport for owned filesystem/SQL workers.

These requests move exact immutable bytes. They confer no native proof or
signing authority, and never delete or overwrite an existing remote object.
"""

from __future__ import annotations

import base64
import hashlib
import os
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from threading import local

import httpx

from .r2_sigv4 import R2SigV4

# Bound the retry body cost when a prior successful PUT lost its acknowledgement.
# Larger objects keep the HEAD-first path so recovery never resends their bytes.
_PUT_FIRST_MAX_BYTES = 4 * 1024


@dataclass(frozen=True, slots=True)
class EvidenceObjectHead:
    size_bytes: int
    etag: str
    content_sha256: str


class R2EvidenceHTTPError(OSError):
    """A bounded HTTP status, without response bytes, URL or credentials."""

    reason_code = "r2_http_failure"

    def __init__(self, status_code: int):
        if type(status_code) is not int or not 100 <= status_code <= 599:
            raise ValueError("R2 evidence HTTP status is invalid")
        self.status_code = status_code
        super().__init__(f"R2 evidence request failed with HTTP {status_code}")


class R2EvidenceClient:
    def __init__(self, signer: R2SigV4, *, timeout_seconds=60, transport=None):
        if not 1 <= timeout_seconds <= 300:
            raise ValueError("R2 evidence transport timeout differs")
        self.signer, self.transport = signer, transport
        self.timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 15))
        self._connections = local()

    def _new_client(self):
        return httpx.Client(
            transport=self.transport,
            timeout=self.timeout,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            follow_redirects=False,
            trust_env=False,
        )

    @contextmanager
    def connection_scope(self):
        """Reuse one connection within a synchronous owned operation.

        Each worker thread owns its client. Nested publications share that
        client; the outer scope always closes it, including on a failed frame.
        No retry, response cache or new operation deadline is introduced.
        """
        retained = getattr(self._connections, "owned", None)
        if retained is not None:
            if retained[0] != os.getpid():
                raise RuntimeError("R2 evidence connection scope belongs to another process")
            yield
            return
        with self._new_client() as client:
            self._connections.owned = (os.getpid(), client)
            try:
                yield
            finally:
                del self._connections.owned

    def _request_client(self):
        retained = getattr(self._connections, "owned", None)
        if retained is None:
            return self._new_client()
        if retained[0] != os.getpid():
            raise RuntimeError("R2 evidence connection scope belongs to another process")
        return nullcontext(retained[1])

    def _exchange(self, method, key, *, body=b"", headers=None, maximum=0, statuses=(200,)):
        signed = self.signer.authorized_headers(
            method, key, body=body, additional_headers=headers
        ) | {"Accept-Encoding": "identity", "Content-Length": str(len(body))}
        try:
            with (
                self._request_client() as client,
                client.stream(
                    method, self.signer.object_url(key), headers=signed, content=body
                ) as response,
            ):
                if response.status_code not in statuses:
                    if method == "GET" and response.status_code in {404, 412}:
                        raise ValueError("R2 evidence object disappeared or changed generation")
                    raise R2EvidenceHTTPError(response.status_code)
                if response.headers.get("content-encoding") not in {None, "identity"}:
                    raise ValueError("R2 evidence response used content encoding")
                if method == "HEAD":
                    return response.status_code, dict(response.headers), b""
                raw = bytearray()
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    if len(raw) + len(chunk) > maximum:
                        raise ValueError("R2 evidence response exceeded its byte bound")
                    raw.extend(chunk)
                return response.status_code, dict(response.headers), bytes(raw)
        except httpx.HTTPError as error:
            raise OSError("R2 evidence transport unavailable") from error

    def head(self, key: str) -> EvidenceObjectHead | None:
        status, headers, _ = self._exchange("HEAD", key, statuses=(200, 404))
        if status == 404:
            return None
        try:
            size = int(headers["content-length"])
            etag = headers["etag"].strip('"')
            sha = headers["x-amz-meta-sha256"]
        except (KeyError, ValueError) as error:
            raise ValueError("R2 evidence object metadata differs") from error
        if (
            size < 1
            or len(etag) != 32
            or any(c not in "0123456789abcdef" for c in etag)
            or len(sha) != 64
            or any(c not in "0123456789abcdef" for c in sha)
        ):
            raise ValueError("R2 evidence object metadata differs")
        return EvidenceObjectHead(size, etag, sha)

    def publish(self, key: str, raw: bytes, sha256: str) -> EvidenceObjectHead:
        with self.connection_scope():
            return self._publish(key, raw, sha256)

    def _publish(self, key: str, raw: bytes, sha256: str) -> EvidenceObjectHead:
        md5 = hashlib.md5(raw, usedforsecurity=False).digest()
        expected = EvidenceObjectHead(len(raw), md5.hex(), sha256)
        if len(raw) > _PUT_FIRST_MAX_BYTES:
            retained = self.head(key)
            if retained is not None:
                if retained != expected:
                    raise ValueError("immutable R2 evidence object conflicts with publication")
                return retained
        # A simultaneous publisher cannot replace another original. The same
        # conditional request is safe after an unacknowledged successful PUT.
        status, headers, _ = self._exchange(
            "PUT",
            key,
            body=raw,
            headers={
                "If-None-Match": "*",
                "Content-MD5": base64.b64encode(md5).decode(),
                "x-amz-meta-sha256": sha256,
            },
            maximum=64 * 1024,
            statuses=(200, 201, 412),
        )
        if status in {200, 201} and "etag" in headers:
            # This single-part conditional PUT carried Content-MD5 and the
            # signed SHA metadata. Its exact ETag acknowledges these original
            # bytes; a second HEAD adds no publication evidence. Keep the
            # original HEAD path for a racing writer (412) or an incomplete
            # acknowledgement. Never turn an explicit mismatch into success.
            if headers["etag"] not in {expected.etag, '"' + expected.etag + '"'}:
                raise ValueError("R2 evidence publication acknowledgement differs")
            return expected
        retained = self.head(key)
        if retained != expected:
            if status == 412:
                raise ValueError("immutable R2 evidence object conflicts with publication")
            raise ValueError("R2 evidence publication acknowledgement differs")
        return retained

    def read(self, key: str, head: EvidenceObjectHead, *, maximum: int) -> bytes:
        if not 0 < head.size_bytes <= maximum:
            raise ValueError("R2 evidence object exceeds the selected read bound")
        _, headers, raw = self._exchange(
            "GET", key, headers={"If-Match": '"' + head.etag + '"'}, maximum=head.size_bytes
        )
        if (
            len(raw) != head.size_bytes
            or headers.get("etag", "").strip('"') != head.etag
            or hashlib.sha256(raw).hexdigest() != head.content_sha256
        ):
            raise ValueError("R2 evidence bytes differ from their immutable identity")
        return raw


def r2_evidence_connection_scope(client):
    """Select native transport ownership without changing injected test clients."""
    return client.connection_scope() if isinstance(client, R2EvidenceClient) else nullcontext()
