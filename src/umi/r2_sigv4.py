"""Small AWS Signature Version 4 surface for private Cloudflare R2 operations."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

_ACCOUNT_HOST = re.compile(r"^[0-9a-f]{32}\.r2\.cloudflarestorage\.com$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_ACCESS_KEY = re.compile(r"^[A-Za-z0-9]{16,128}$")
_MAXIMUM_EXPIRY_SECONDS = 7 * 24 * 60 * 60
_MAXIMUM_CREDENTIAL_BYTES = 16 * 1024


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _mac(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode(), hashlib.sha256).digest()


def _encode(value: str) -> str:
    return quote(value, safe="-_.~")


def _canonical_query(values: tuple[tuple[str, str], ...]) -> str:
    encoded = sorted((_encode(key), _encode(value)) for key, value in values)
    return "&".join(f"{key}={value}" for key, value in encoded)


def _signing_key(secret: str, date: str) -> bytes:
    dated = _mac(("AWS4" + secret).encode(), date)
    regional = _mac(dated, "auto")
    service = _mac(regional, "s3")
    return _mac(service, "aws4_request")


def _timestamp(value: datetime | None) -> tuple[str, str]:
    current = datetime.now(timezone.utc) if value is None else value
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("R2 signing time must be timezone-aware")
    current = current.astimezone(timezone.utc)
    return current.strftime("%Y%m%dT%H%M%SZ"), current.strftime("%Y%m%d")


@dataclass(frozen=True, slots=True)
class R2Credentials:
    access_key_id: str
    secret_access_key: str = field(repr=False)

    def __post_init__(self) -> None:
        if _ACCESS_KEY.fullmatch(self.access_key_id) is None:
            raise ValueError("R2 access key differs")
        if not 16 <= len(self.secret_access_key) <= 256 or any(
            ord(character) < 33 or ord(character) > 126 for character in self.secret_access_key
        ):
            raise ValueError("R2 secret key differs")


@dataclass(frozen=True, slots=True)
class LoadedR2Credentials:
    endpoint: str
    credentials: R2Credentials


def load_r2_credentials(path: Path) -> LoadedR2Credentials:
    """Read one exact private Cloudflare credential export without following links."""

    path = Path(path)
    if not path.is_absolute():
        raise ValueError("R2 credentials path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o077
            or not 0 < before.st_size <= _MAXIMUM_CREDENTIAL_BYTES
        ):
            raise ValueError("R2 credentials file is unsafe")
        body = bytearray()
        while chunk := os.read(descriptor, min(8192, _MAXIMUM_CREDENTIAL_BYTES + 1 - len(body))):
            body.extend(chunk)
            if len(body) > _MAXIMUM_CREDENTIAL_BYTES:
                raise ValueError("R2 credentials file exceeds its bound")
        after = os.fstat(descriptor)
        if len(body) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("R2 credentials file changed while reading")
    finally:
        os.close(descriptor)
    try:
        values = {}
        for line in body.decode("utf-8").splitlines():
            if not line:
                continue
            key, separator, value = line.partition("=")
            if separator != "=" or not key or key in values:
                raise ValueError("R2 credentials file differs")
            values[key] = value.strip().strip('"').strip("'")
        if set(values) != {
            "TOKEN_VALUE",
            "ACCESS_KEY_ID",
            "SECRET_ACCESS_KEY",
            "DEFAULT_ENDPOINT",
        }:
            raise ValueError("R2 credentials file differs")
        credentials = R2Credentials(values["ACCESS_KEY_ID"], values["SECRET_ACCESS_KEY"])
        # Reuse the signer parser for the exact account endpoint requirement.
        R2SigV4(values["DEFAULT_ENDPOINT"], "validation-bucket", credentials)
        return LoadedR2Credentials(values["DEFAULT_ENDPOINT"], credentials)
    except (UnicodeDecodeError, KeyError) as error:
        raise ValueError("R2 credentials file differs") from error
    finally:
        body[:] = b"\x00" * len(body)


@dataclass(frozen=True, slots=True)
class R2SigV4:
    endpoint: str
    bucket: str
    credentials: R2Credentials

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.netloc != parsed.hostname
            or parsed.path
            or parsed.query
            or parsed.fragment
            or _ACCOUNT_HOST.fullmatch(parsed.hostname) is None
        ):
            raise ValueError("R2 endpoint must be the account S3 HTTPS origin")
        if _BUCKET.fullmatch(self.bucket) is None or ".." in self.bucket:
            raise ValueError("R2 bucket name differs")

    def _path(self, key: str) -> str:
        if (
            not key
            or len(key.encode()) > 1024
            or key.startswith("/")
            or "//" in key
            or any(part in {"", ".", ".."} for part in key.split("/"))
            or any(ord(character) < 32 for character in key)
        ):
            raise ValueError("R2 object key differs")
        return "/" + quote(f"{self.bucket}/{key}", safe="/-_.~")

    def presign(
        self,
        method: str,
        key: str,
        *,
        query: tuple[tuple[str, str], ...] = (),
        expires_seconds: int,
        at: datetime | None = None,
    ) -> str:
        """Issue one method- and query-bound bearer URL without exposing the secret."""

        if method not in {"GET", "HEAD", "PUT", "DELETE"}:
            raise ValueError("R2 presigned method differs")
        if isinstance(expires_seconds, bool) or not 1 <= expires_seconds <= _MAXIMUM_EXPIRY_SECONDS:
            raise ValueError("R2 presigned expiry differs")
        if any(not key or len(key) > 128 or len(value) > 2048 for key, value in query):
            raise ValueError("R2 presigned query differs")
        timestamp, date = _timestamp(at)
        scope = f"{date}/auto/s3/aws4_request"
        values = (
            *query,
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self.credentials.access_key_id}/{scope}"),
            ("X-Amz-Date", timestamp),
            ("X-Amz-Expires", str(expires_seconds)),
            ("X-Amz-SignedHeaders", "host"),
        )
        canonical_query = _canonical_query(values)
        canonical_request = "\n".join(
            (
                method,
                self._path(key),
                canonical_query,
                f"host:{urlsplit(self.endpoint).hostname}\n",
                "host",
                "UNSIGNED-PAYLOAD",
            )
        )
        string_to_sign = "\n".join(
            ("AWS4-HMAC-SHA256", timestamp, scope, _digest(canonical_request.encode()))
        )
        signature = hmac.new(
            _signing_key(self.credentials.secret_access_key, date),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{self.endpoint}{self._path(key)}?{canonical_query}&X-Amz-Signature={signature}"

    def authorized_headers(
        self,
        method: str,
        key: str,
        *,
        query: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
        additional_headers: Mapping[str, str] | None = None,
        at: datetime | None = None,
    ) -> dict[str, str]:
        """Sign one trusted issuer request without placing credentials in its URL."""

        if method not in {"GET", "HEAD", "POST", "PUT", "DELETE"}:
            raise ValueError("R2 authorized method differs")
        if any(not name or len(name) > 128 or len(value) > 2048 for name, value in query):
            raise ValueError("R2 authorized query differs")
        timestamp, date = _timestamp(at)
        scope = f"{date}/auto/s3/aws4_request"
        host = urlsplit(self.endpoint).hostname
        payload_sha256 = _digest(body)
        headers = {
            "host": host,
            "x-amz-content-sha256": payload_sha256,
            "x-amz-date": timestamp,
        }
        for name, value in (additional_headers or {}).items():
            if type(name) is not str or type(value) is not str:
                raise ValueError("R2 signed additional header differs")
            canonical_name = name.lower()
            canonical_value = " ".join(value.strip().split())
            if (
                canonical_name not in {"x-amz-copy-source", "x-amz-copy-source-range"}
                or canonical_name in headers
                or not canonical_value
                or len(canonical_value) > 4096
                or "\r" in value
                or "\n" in value
            ):
                raise ValueError("R2 signed additional header differs")
            headers[canonical_name] = canonical_value
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
        canonical_request = "\n".join(
            (
                method,
                self._path(key),
                _canonical_query(query),
                canonical_headers,
                signed_headers,
                payload_sha256,
            )
        )
        string_to_sign = "\n".join(
            ("AWS4-HMAC-SHA256", timestamp, scope, _digest(canonical_request.encode()))
        )
        signature = hmac.new(
            _signing_key(self.credentials.secret_access_key, date),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        return {
            "Authorization": (
                "AWS4-HMAC-SHA256 "
                f"Credential={self.credentials.access_key_id}/{scope}, "
                f"SignedHeaders={signed_headers}, Signature={signature}"
            ),
            "Host": host,
            "X-Amz-Content-SHA256": payload_sha256,
            "X-Amz-Date": timestamp,
        } | {name: value for name, value in headers.items() if name.startswith("x-amz-copy-")}

    def copy_source_header(self, key: str) -> str:
        """Return the encoded bucket/key value required by UploadPartCopy."""

        return self._path(key)

    def object_url(self, key: str, *, query: tuple[tuple[str, str], ...] = ()) -> str:
        suffix = "" if not query else "?" + _canonical_query(query)
        return f"{self.endpoint}{self._path(key)}{suffix}"

    def upload_part_url(
        self,
        key: str,
        *,
        upload_id: str,
        part_number: int,
        expires_seconds: int,
        at: datetime | None = None,
    ) -> str:
        if not upload_id or len(upload_id) > 2048 or any(ord(c) < 33 for c in upload_id):
            raise ValueError("R2 multipart upload identity differs")
        if isinstance(part_number, bool) or not 1 <= part_number <= 10_000:
            raise ValueError("R2 multipart part number differs")
        return self.presign(
            "PUT",
            key,
            query=(("partNumber", str(part_number)), ("uploadId", upload_id)),
            expires_seconds=expires_seconds,
            at=at,
        )
