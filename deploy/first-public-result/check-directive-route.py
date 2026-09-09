#!/usr/bin/env python3
"""Verify one curl-captured validator-directive response from the public edge."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from pathlib import Path

MAX_BODY_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="verify exact bytes and cache controls on one public directive response"
    )
    parser.add_argument("--headers", required=True, type=Path)
    parser.add_argument("--body", required=True, type=Path)
    parser.add_argument("--expected-page-sha256", required=True)
    parser.add_argument("--expected-head-sha256", required=True)
    parser.add_argument("--expected-sequence", required=True, type=int)
    parser.add_argument("--require-cloudflare-edge", action="store_true")
    return parser


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= maximum_bytes
    ):
        raise ValueError("probe_file_invalid")
    payload = path.read_bytes()
    if len(payload) != metadata.st_size:
        raise ValueError("probe_file_changed")
    return payload


def _final_header_block(payload: bytes) -> tuple[int, dict[str, list[str]]]:
    try:
        normalized = payload.decode("iso-8859-1").replace("\r\n", "\n")
    except UnicodeError as error:
        raise ValueError("response_headers_invalid") from error
    blocks = [item for item in normalized.split("\n\n") if item.startswith("HTTP/")]
    if not blocks:
        raise ValueError("response_headers_invalid")
    lines = blocks[-1].splitlines()
    status_fields = lines[0].split()
    if len(status_fields) < 2 or not status_fields[1].isdigit():
        raise ValueError("response_status_invalid")
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        if line[0].isspace() or ":" not in line:
            raise ValueError("response_headers_invalid")
        name, value = line.split(":", 1)
        key = name.strip().casefold()
        if not key:
            raise ValueError("response_headers_invalid")
        headers.setdefault(key, []).append(value.strip())
    return int(status_fields[1]), headers


def _one_header(headers: dict[str, list[str]], name: str, *, optional: bool = False) -> str:
    values = headers.get(name, [])
    if optional and not values:
        return ""
    if len(values) != 1:
        raise ValueError(f"response_{name.replace('-', '_')}_invalid")
    return values[0]


def verify_directive_response(
    *,
    header_bytes: bytes,
    body: bytes,
    expected_page_sha256: str,
    expected_head_sha256: str,
    expected_sequence: int,
    require_cloudflare_edge: bool,
) -> None:
    if (
        _HEX32_RE.fullmatch(expected_page_sha256) is None
        or _HEX32_RE.fullmatch(expected_head_sha256) is None
        or isinstance(expected_sequence, bool)
        or not 1 <= expected_sequence <= (1 << 53) - 1
    ):
        raise ValueError("probe_expectation_invalid")
    status, headers = _final_header_block(header_bytes)
    if status != 200:
        raise ValueError("response_status_invalid")
    encoding = _one_header(headers, "content-encoding", optional=True).casefold()
    if encoding not in {"", "identity"}:
        raise ValueError("response_content_encoding_invalid")
    cache_control = {
        item.strip().casefold()
        for value in headers.get("cache-control", [])
        for item in value.split(",")
    }
    if not {"no-cache", "no-store", "must-revalidate", "no-transform"}.issubset(cache_control):
        raise ValueError("response_cache_control_invalid")
    if "age" in headers:
        raise ValueError("response_cache_age_present")
    if _one_header(headers, "content-length") != str(len(body)):
        raise ValueError("response_content_length_invalid")
    if _one_header(headers, "x-umi-directive-page-sha256") != expected_page_sha256:
        raise ValueError("response_page_sha256_header_invalid")
    if _one_header(headers, "x-umi-directive-head") != expected_head_sha256:
        raise ValueError("response_head_sha256_header_invalid")
    if _one_header(headers, "x-umi-directive-sequence") != str(expected_sequence):
        raise ValueError("response_sequence_header_invalid")
    if _one_header(headers, "etag") != f'"{expected_page_sha256}"':
        raise ValueError("response_etag_invalid")
    if hashlib.sha256(body).hexdigest() != expected_page_sha256:
        raise ValueError("response_body_sha256_invalid")
    if require_cloudflare_edge:
        if not _one_header(headers, "cf-ray"):
            raise ValueError("response_cloudflare_ray_invalid")
        cache_status = _one_header(headers, "cf-cache-status").casefold()
        if cache_status not in {"bypass", "dynamic"}:
            raise ValueError("response_cloudflare_cache_status_invalid")


def main() -> int:
    args = _parser().parse_args()
    try:
        header_bytes = _read_regular(args.headers, maximum_bytes=MAX_HEADER_BYTES)
        body = _read_regular(args.body, maximum_bytes=MAX_BODY_BYTES)
        verify_directive_response(
            header_bytes=header_bytes,
            body=body,
            expected_page_sha256=args.expected_page_sha256,
            expected_head_sha256=args.expected_head_sha256,
            expected_sequence=args.expected_sequence,
            require_cloudflare_edge=args.require_cloudflare_edge,
        )
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("validator_directive_route_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
