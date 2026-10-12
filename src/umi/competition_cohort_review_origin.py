"""Explicit private review origins, including same-host native listeners."""

import re

import httpx

_LOOPBACK = re.compile(r"http://(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})/?")


def private_review_origin(origin: str) -> httpx.URL:
    """Keep HTTPS behavior; HTTP requires an exact loopback literal and port.

    No DNS resolution authorizes plaintext transport. Returning HTTP therefore
    identifies an explicitly selected same-host connection. This validates local
    deployment placement only; bearer authentication and native signed evidence
    remain required by every private review route and consumer.
    """
    try:
        url = httpx.URL(origin)
    except httpx.InvalidURL:
        raise ValueError("private review origin is invalid") from None
    loopback = _LOOPBACK.fullmatch(origin)
    local = loopback is not None and 1 <= int(loopback[1]) <= 65535
    if (
        not (url.scheme == "https" or local)
        or not url.host
        or url.userinfo
        or url.query
        or url.fragment
        or url.path not in ("", "/")
    ):
        raise ValueError("private review requires HTTPS or explicit literal-loopback HTTP")
    return url
