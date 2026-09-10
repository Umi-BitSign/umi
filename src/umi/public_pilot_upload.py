"""Authenticated, create-only uploads for public-pilot automation artifacts."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import httpx

UPLOAD_AUTHORIZATION_SCHEME = "UMI-HMAC-SHA256"
UPLOAD_AUTHENTICATION_DOMAIN = b"umi-r2-upload-v1"
MAX_UPLOAD_SECRET_FILE_BYTES = 256
MAX_AUTOMATION_RESULT_BYTES = 256 * 1024
MAX_VALIDATOR_BOOTSTRAP_RESULT_BYTES = 4 * 1024 * 1024

_LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_READ_CHUNK_BYTES = 1024 * 1024


def _is_systemd_credential(path: Path, metadata: os.stat_result) -> bool:
    """Recognize systemd's root-owned, service-scoped credential mount."""

    credential_directory_value = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credential_directory_value:
        return False
    credential_directory_path = Path(credential_directory_value)
    if not credential_directory_path.is_absolute():
        return False
    try:
        credential_directory = credential_directory_path.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return (
        path.parent == credential_directory
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) in {0o400, 0o440}
    )


def _normalized_https_origin(value: str, *, label: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError(f"{label} must be a bounded HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{label} must be a normalized HTTPS origin") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value.endswith("/")
    ):
        raise ValueError(f"{label} must be a normalized HTTPS origin")
    default_port = port in {None, 443}
    expected_netloc = parsed.hostname if default_port else f"{parsed.hostname}:{port}"
    if parsed.netloc != expected_netloc:
        raise ValueError(f"{label} must be a normalized HTTPS origin")
    return value


def load_hex_secret(path: Path) -> bytes:
    """Load one tightly permissioned 32-byte HMAC key from a regular file."""

    resolved = path.expanduser().resolve(strict=True)
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        owner_only = metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o077
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not (owner_only or _is_systemd_credential(resolved, metadata))
            or metadata.st_size > MAX_UPLOAD_SECRET_FILE_BYTES
        ):
            raise ValueError("public-pilot secret file is unsafe")
        raw = os.read(descriptor, MAX_UPLOAD_SECRET_FILE_BYTES + 1)
        if len(raw) != metadata.st_size:
            raise ValueError("public-pilot secret file changed while it was read")
    finally:
        os.close(descriptor)
    try:
        encoded = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError("public-pilot secret is not ASCII") from error
    if _LOWER_HEX_64.fullmatch(encoded) is None:
        raise ValueError("public-pilot secret must encode exactly 32 bytes")
    return bytes.fromhex(encoded)


def upload_authentication_message(
    *,
    path: str,
    timestamp: int,
    content_length: int,
    content_type: str,
    content_sha256: str,
) -> bytes:
    """Construct the exact Worker upload-authentication message."""

    if not path.startswith("/") or "?" in path or "#" in path or "\n" in path:
        raise ValueError("upload path is invalid")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ValueError("upload timestamp is invalid")
    if (
        isinstance(content_length, bool)
        or not isinstance(content_length, int)
        or content_length <= 0
    ):
        raise ValueError("upload content length is invalid")
    if content_type not in {"application/gzip", "application/json"}:
        raise ValueError("upload content type is invalid")
    if _LOWER_HEX_64.fullmatch(content_sha256) is None:
        raise ValueError("upload content digest is invalid")
    return b"\n".join(
        (
            UPLOAD_AUTHENTICATION_DOMAIN,
            b"PUT",
            path.encode("ascii"),
            str(timestamp).encode("ascii"),
            str(content_length).encode("ascii"),
            content_type.encode("ascii"),
            content_sha256.encode("ascii"),
        )
    )


def _headers(
    *,
    secret: bytes,
    path: str,
    timestamp: int,
    content_length: int,
    content_type: str,
    content_sha256: str,
) -> dict[str, str]:
    message = upload_authentication_message(
        path=path,
        timestamp=timestamp,
        content_length=content_length,
        content_type=content_type,
        content_sha256=content_sha256,
    )
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return {
        "Authorization": f"{UPLOAD_AUTHORIZATION_SCHEME} {signature}",
        "Content-Length": str(content_length),
        "Content-Type": content_type,
        "X-UMI-Content-SHA256": content_sha256,
        "X-UMI-Timestamp": str(timestamp),
    }


def _file_chunks(descriptor: int, size: int) -> Iterator[bytes]:
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise ValueError("upload source ended before its declared length")
        remaining -= len(chunk)
        yield chunk
    if os.read(descriptor, 1):
        raise ValueError("upload source grew while it was read")


def _digest_descriptor(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    for chunk in _file_chunks(descriptor, size):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _verify_public_copy(
    client: httpx.Client,
    *,
    url: str,
    content_length: int,
    content_sha256: str,
) -> None:
    with client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as response:
        response.raise_for_status()
        if response.headers.get("Content-Encoding") is not None:
            raise RuntimeError("public artifact readback unexpectedly used content encoding")
        digest = hashlib.sha256()
        total = 0
        for chunk in response.iter_raw():
            total += len(chunk)
            if total > content_length:
                raise RuntimeError("public artifact readback exceeded its expected size")
            digest.update(chunk)
    if total != content_length or not hmac.compare_digest(digest.hexdigest(), content_sha256):
        raise RuntimeError("public artifact readback does not match the uploaded bytes")


def upload_public_pilot_file(
    source: Path,
    *,
    path: str,
    content_type: str,
    maximum_bytes: int,
    upload_origin: str,
    public_origin: str,
    secret: bytes,
    client: httpx.Client | None = None,
    timestamp: int | None = None,
) -> tuple[str, int, str]:
    """Create one immutable object and verify it through the unauthenticated origin."""

    uploader = _normalized_https_origin(upload_origin, label="upload origin")
    public = _normalized_https_origin(public_origin, label="public origin")
    resolved = source.expanduser().resolve(strict=True)
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    owns_client = client is None
    active_client = client or httpx.Client(timeout=httpx.Timeout(120.0, connect=15.0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > maximum_bytes
        ):
            raise ValueError("public-pilot upload source is invalid")
        digest = _digest_descriptor(descriptor, metadata.st_size)
        now = int(time.time()) if timestamp is None else timestamp
        response = active_client.put(
            f"{uploader}{path}",
            headers=_headers(
                secret=secret,
                path=path,
                timestamp=now,
                content_length=metadata.st_size,
                content_type=content_type,
                content_sha256=digest,
            ),
            content=_file_chunks(descriptor, metadata.st_size),
        )
        if response.status_code not in {201, 409, 412}:
            raise RuntimeError(f"public-pilot upload failed with HTTP {response.status_code}")
        public_url = f"{public}{path}"
        _verify_public_copy(
            active_client,
            url=public_url,
            content_length=metadata.st_size,
            content_sha256=digest,
        )
        return digest, metadata.st_size, public_url
    finally:
        os.close(descriptor)
        if owns_client:
            active_client.close()


def upload_public_pilot_result(
    body: bytes,
    *,
    authorization_id: str,
    result_hmac_key: bytes,
    upload_origin: str,
    public_origin: str,
    secret: bytes,
    client: httpx.Client | None = None,
    timestamp: int | None = None,
) -> tuple[str, int, str]:
    """Publish a bounded canonical result envelope at its authorization-bound path."""

    if _LOWER_HEX_64.fullmatch(authorization_id) is None:
        raise ValueError("automation authorization ID is invalid")
    if not body or len(body) > MAX_AUTOMATION_RESULT_BYTES:
        raise ValueError("automation result body has an invalid size")
    from .public_pilot_github import parse_public_pilot_automation_result_envelope

    envelope = parse_public_pilot_automation_result_envelope(
        body,
        hmac_key=result_hmac_key,
    )
    if not hmac.compare_digest(
        envelope.payload.authorization_id,
        authorization_id,
    ):
        raise ValueError("automation result body binds another authorization ID")
    temporary_directory = Path(os.environ.get("TMPDIR", "/tmp")).resolve()
    import tempfile

    descriptor, name = tempfile.mkstemp(prefix="umi-public-pilot-result-", dir=temporary_directory)
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(body):
            written = os.write(descriptor, body[offset:])
            if written <= 0:
                raise OSError("automation result write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        return upload_public_pilot_file(
            path,
            path=f"/public-pilot-automation/results/{authorization_id}.json",
            content_type="application/json",
            maximum_bytes=MAX_AUTOMATION_RESULT_BYTES,
            upload_origin=upload_origin,
            public_origin=public_origin,
            secret=secret,
            client=client,
            timestamp=timestamp,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)


def upload_validator_bootstrap_result(
    body: bytes,
    *,
    submission_id: str,
    upload_origin: str,
    public_origin: str,
    secret: bytes,
    client: httpx.Client | None = None,
    timestamp: int | None = None,
) -> tuple[str, int, str]:
    """Publish one signed validator result at its immutable submission path."""

    if _LOWER_HEX_64.fullmatch(submission_id) is None:
        raise ValueError("validator bootstrap submission ID is invalid")
    if not body or len(body) > MAX_VALIDATOR_BOOTSTRAP_RESULT_BYTES:
        raise ValueError("validator bootstrap result body has an invalid size")
    from .validator_supervisor_publication import (
        parse_canonical_signed_supervisor_bootstrap_result,
    )

    signed = parse_canonical_signed_supervisor_bootstrap_result(body)
    if not hmac.compare_digest(signed.result.submission_id, submission_id):
        raise ValueError("validator bootstrap result binds another submission ID")
    temporary_directory = Path(os.environ.get("TMPDIR", "/tmp")).resolve()
    import tempfile

    descriptor, name = tempfile.mkstemp(
        prefix="umi-validator-bootstrap-result-",
        dir=temporary_directory,
    )
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(body):
            written = os.write(descriptor, body[offset:])
            if written <= 0:
                raise OSError("validator bootstrap result write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        return upload_public_pilot_file(
            path,
            path=f"/validator-bootstrap-results/{submission_id}.json",
            content_type="application/json",
            maximum_bytes=MAX_VALIDATOR_BOOTSTRAP_RESULT_BYTES,
            upload_origin=upload_origin,
            public_origin=public_origin,
            secret=secret,
            client=client,
            timestamp=timestamp,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)


__all__ = [
    "MAX_AUTOMATION_RESULT_BYTES",
    "MAX_VALIDATOR_BOOTSTRAP_RESULT_BYTES",
    "UPLOAD_AUTHENTICATION_DOMAIN",
    "UPLOAD_AUTHORIZATION_SCHEME",
    "load_hex_secret",
    "upload_authentication_message",
    "upload_public_pilot_file",
    "upload_public_pilot_result",
    "upload_validator_bootstrap_result",
]
