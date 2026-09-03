"""Bounded retrieval of challenge video objects."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import math
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from .protocol import Video


class VideoFetchError(RuntimeError):
    """A challenge video could not be retrieved exactly as declared."""

    def __init__(self, message: str, *, wire_bytes: int = 0) -> None:
        super().__init__(message)
        if isinstance(wire_bytes, bool) or not isinstance(wire_bytes, int) or wire_bytes < 0:
            raise ValueError("video fetch wire bytes must be a non-negative integer")
        self.wire_bytes = wire_bytes


@dataclass(frozen=True)
class VideoFetchResult:
    data: bytes
    wire_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("video fetch data must be bytes")
        if (
            isinstance(self.wire_bytes, bool)
            or not isinstance(self.wire_bytes, int)
            or self.wire_bytes < len(self.data)
        ):
            raise ValueError("video fetch wire bytes cannot be smaller than its body")


class VideoFetcher(Protocol):
    async def fetch(self, descriptor: Video) -> bytes: ...


AddressResolver = Callable[[str, int], Awaitable[Sequence[str]]]


@dataclass(frozen=True)
class HttpVideoFetcher:
    """HTTPS streaming fetcher with an allowlist and a public-IP connection pin."""

    allowed_hosts: frozenset[str]
    maximum_clip_size_bytes: int
    timeout_seconds: float
    maximum_http_header_bytes: int = 16 * 1024
    allowed_ports: frozenset[int] = frozenset()
    allow_http_for_tests: bool = False
    transport: httpx.AsyncBaseTransport | None = None
    resolver: AddressResolver | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_hosts, frozenset) or not self.allowed_hosts:
            raise ValueError("at least one allowed video hostname is required")
        if any(not isinstance(host, str) or not host.strip() for host in self.allowed_hosts):
            raise ValueError("allowed video hostnames must be nonempty strings")
        if (
            isinstance(self.maximum_clip_size_bytes, bool)
            or not isinstance(self.maximum_clip_size_bytes, int)
            or self.maximum_clip_size_bytes <= 0
        ):
            raise ValueError("maximum_clip_size_bytes must be positive")
        if (
            isinstance(self.maximum_http_header_bytes, bool)
            or not isinstance(self.maximum_http_header_bytes, int)
            or self.maximum_http_header_bytes <= 0
        ):
            raise ValueError("maximum_http_header_bytes must be positive")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(self.allowed_ports, frozenset) or any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in self.allowed_ports
        ):
            raise ValueError("allowed video ports must be integers from 1 through 65535")
        if not isinstance(self.allow_http_for_tests, bool):
            raise TypeError("allow_http_for_tests must be boolean")

    async def fetch(self, descriptor: Video) -> bytes:
        return (await self.fetch_with_receipt(descriptor)).data

    async def fetch_with_receipt(self, descriptor: Video) -> VideoFetchResult:
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

        wire_counter = [0]
        try:
            data = await asyncio.wait_for(
                self._resolve_and_fetch(
                    descriptor,
                    hostname=hostname,
                    actual_port=actual_port,
                    expected_port=expected_port,
                    wire_counter=wire_counter,
                ),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise VideoFetchError(
                "video fetch exceeded its total deadline",
                wire_bytes=wire_counter[0],
            ) from error
        return VideoFetchResult(data=data, wire_bytes=wire_counter[0])

    async def _resolve_and_fetch(
        self,
        descriptor: Video,
        *,
        hostname: str,
        actual_port: int,
        expected_port: int,
        wire_counter: list[int],
    ) -> bytes:
        address = await _resolve_public_address(
            hostname,
            actual_port,
            resolver=self.resolver,
        )
        request_url = httpx.URL(str(descriptor.url)).copy_with(host=address)
        authority_host = f"[{hostname}]" if ":" in hostname else hostname
        request_headers = {
            "Accept-Encoding": "identity",
            "Host": (
                authority_host
                if actual_port == expected_port
                else f"{authority_host}:{actual_port}"
            ),
        }
        return await self._fetch_verified(
            descriptor,
            request_url=request_url,
            request_headers=request_headers,
            request_extensions={"sni_hostname": hostname},
            wire_counter=wire_counter,
        )

    async def _fetch_verified(
        self,
        descriptor: Video,
        *,
        request_url: httpx.URL,
        request_headers: dict[str, str],
        request_extensions: dict[str, str],
        wire_counter: list[int],
    ) -> bytes:
        timeout = httpx.Timeout(self.timeout_seconds)
        response: httpx.Response | None = None
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                transport=self.transport,
                trust_env=False,
            ) as client:
                request = client.build_request(
                    "GET",
                    request_url,
                    headers=request_headers,
                    extensions=request_extensions,
                )
                request_header_bytes = _raw_header_size(request.headers)
                wire_counter[0] += request_header_bytes
                if request_header_bytes > self.maximum_http_header_bytes:
                    raise VideoFetchError("video request headers exceed the byte ceiling")
                response = await client.send(request, stream=True)
                wire_counter[0] += _raw_header_size(response.headers)
                if response.status_code != 200:
                    raise VideoFetchError(f"video fetch returned HTTP {response.status_code}")
                if _raw_header_size(response.headers) > self.maximum_http_header_bytes:
                    raise VideoFetchError("video response headers exceed the byte ceiling")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
                if content_type != descriptor.media_type:
                    raise VideoFetchError("video Content-Type does not match the request")
                content_encoding = response.headers.get("content-encoding")
                if content_encoding is not None and content_encoding.strip().lower() != "identity":
                    raise VideoFetchError("encoded video responses are not allowed")
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
                    wire_counter[0] += len(chunk)
                    if len(body) + len(chunk) > descriptor.size_bytes:
                        raise VideoFetchError("video body exceeds its declared size")
                    if len(body) + len(chunk) > self.maximum_clip_size_bytes:
                        raise VideoFetchError("video body exceeds the clip ceiling")
                    body.extend(chunk)
        except VideoFetchError as error:
            error.wire_bytes = wire_counter[0]
            raise
        except httpx.HTTPError as error:
            raise VideoFetchError(
                f"video fetch failed: {type(error).__name__}",
                wire_bytes=wire_counter[0],
            ) from error
        finally:
            if response is not None:
                await response.aclose()

        if len(body) != descriptor.size_bytes:
            raise VideoFetchError(
                "video body is shorter than its declared size",
                wire_bytes=wire_counter[0],
            )
        if hashlib.sha256(body).hexdigest() != descriptor.sha256:
            raise VideoFetchError(
                "video SHA-256 does not match the request",
                wire_bytes=wire_counter[0],
            )
        return bytes(body)


async def _resolve_public_address(
    hostname: str,
    port: int,
    *,
    resolver: AddressResolver | None,
) -> str:
    if resolver is None:
        try:
            literal = ipaddress.ip_address(hostname)
            addresses = (str(literal),)
        except ValueError:
            loop = asyncio.get_running_loop()
            try:
                results = await loop.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
            except OSError as error:
                raise VideoFetchError("video hostname resolution failed") from error
            addresses = tuple(str(result[4][0]) for result in results)
    else:
        try:
            addresses = tuple(await resolver(hostname, port))
        except Exception as error:
            raise VideoFetchError("video hostname resolution failed") from error
    if not addresses:
        raise VideoFetchError("video hostname resolved to no addresses")

    parsed: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for address in addresses:
        try:
            value = ipaddress.ip_address(address)
        except ValueError as error:
            raise VideoFetchError("video hostname returned an invalid address") from error
        if not value.is_global:
            raise VideoFetchError("video hostname resolved to a non-public address")
        parsed.add(value)
    selected = min(parsed, key=lambda value: (value.version, value.packed))
    return str(selected)


def _raw_header_size(headers: httpx.Headers) -> int:
    return sum(len(name) + len(value) + 4 for name, value in headers.raw)
