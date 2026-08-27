"""Bounded retrieval of challenge video objects."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from .protocol import Video


class VideoFetchError(RuntimeError):
    """A challenge video could not be retrieved exactly as declared."""


class VideoFetcher(Protocol):
    async def fetch(self, descriptor: Video) -> bytes: ...


@dataclass(frozen=True)
class HttpVideoFetcher:
    """HTTPS-only streaming fetcher with an explicit hostname allowlist."""

    allowed_hosts: frozenset[str]
    maximum_clip_size_bytes: int
    timeout_seconds: float
    maximum_http_header_bytes: int = 16 * 1024
    allowed_ports: frozenset[int] = frozenset()
    allow_http_for_tests: bool = False
    transport: httpx.AsyncBaseTransport | None = None

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("at least one allowed video hostname is required")
        if self.maximum_clip_size_bytes <= 0:
            raise ValueError("maximum_clip_size_bytes must be positive")
        if self.maximum_http_header_bytes <= 0:
            raise ValueError("maximum_http_header_bytes must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if any(isinstance(port, bool) or not 1 <= port <= 65535 for port in self.allowed_ports):
            raise ValueError("allowed video ports must be integers from 1 through 65535")

    async def fetch(self, descriptor: Video) -> bytes:
        parsed = urlsplit(str(descriptor.url))
        allowed_schemes = {"https"}
        if self.allow_http_for_tests:
            allowed_schemes.add("http")
        if parsed.scheme not in allowed_schemes:
            raise VideoFetchError("video URL scheme is not allowed")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if hostname not in {host.lower().rstrip(".") for host in self.allowed_hosts}:
            raise VideoFetchError("video URL hostname is not allowlisted")
        if parsed.username is not None or parsed.password is not None:
            raise VideoFetchError("video URL must not contain user information")
        if parsed.fragment:
            raise VideoFetchError("video URL must not contain a fragment")
        try:
            port = parsed.port
        except ValueError as error:
            raise VideoFetchError("video URL port is invalid") from error
        expected_port = 443 if parsed.scheme == "https" else 80
        actual_port = port or expected_port
        allowed_ports = self.allowed_ports or frozenset({expected_port})
        if actual_port not in allowed_ports:
            raise VideoFetchError("video URL port is not allowlisted")
        if descriptor.size_bytes > self.maximum_clip_size_bytes:
            raise VideoFetchError("declared video size exceeds the clip ceiling")

        try:
            return await asyncio.wait_for(
                self._fetch_verified(descriptor),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise VideoFetchError("video fetch exceeded its total deadline") from error

    async def _fetch_verified(self, descriptor: Video) -> bytes:
        timeout = httpx.Timeout(self.timeout_seconds)
        try:
            async with (
                httpx.AsyncClient(
                    timeout=timeout,
                    follow_redirects=False,
                    transport=self.transport,
                ) as client,
                client.stream("GET", str(descriptor.url)) as response,
            ):
                if response.status_code != 200:
                    raise VideoFetchError(f"video fetch returned HTTP {response.status_code}")
                if _raw_header_size(response.headers) > self.maximum_http_header_bytes:
                    raise VideoFetchError("video response headers exceed the byte ceiling")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
                if content_type != descriptor.media_type:
                    raise VideoFetchError("video Content-Type does not match the request")
                declared_length = response.headers.get("content-length")
                if declared_length is not None:
                    try:
                        content_length = int(declared_length)
                    except ValueError as error:
                        raise VideoFetchError("video Content-Length is invalid") from error
                    if content_length != descriptor.size_bytes:
                        raise VideoFetchError("video Content-Length does not match the request")

                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > descriptor.size_bytes:
                        raise VideoFetchError("video body exceeds its declared size")
                    if len(body) + len(chunk) > self.maximum_clip_size_bytes:
                        raise VideoFetchError("video body exceeds the clip ceiling")
                    body.extend(chunk)
        except VideoFetchError:
            raise
        except httpx.HTTPError as error:
            raise VideoFetchError(f"video fetch failed: {type(error).__name__}") from error

        if len(body) != descriptor.size_bytes:
            raise VideoFetchError("video body is shorter than its declared size")
        if hashlib.sha256(body).hexdigest() != descriptor.sha256:
            raise VideoFetchError("video SHA-256 does not match the request")
        return bytes(body)


def _raw_header_size(headers: httpx.Headers) -> int:
    return sum(len(name) + len(value) + 4 for name, value in headers.raw)
