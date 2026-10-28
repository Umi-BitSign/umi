"""Fresh R2 metadata over an explicitly selected, authenticated Worker transport.

The account endpoint/bucket, object keys, sizes, etags and native verification
rules stay unchanged. This never caches responses or grants payload authority.
The Worker receives a purpose-derived key, not the native S3 signing secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

import httpx

from .protocol import canonical_json_bytes
from .r2_connection_pool import R2ConnectionPool
from .r2_sigv4 import R2SigV4

HEAD_BATCH_PATH = "/v1/internal/r2/heads"
MAX_HEAD_KEYS = 32
MAX_METADATA_BYTES = 64 * 1024
KEY_PURPOSE = b"umi-r2-metadata-batch-key/1"


class R2MetadataBatchUnavailable(OSError):
    """A redacted transport diagnostic; the native reader may use direct S3."""

    def __init__(self, reason_code: str, http_status: int | None = None):
        self.reason_code, self.http_status = reason_code, http_status
        super().__init__("R2 metadata batch transport unavailable")


@dataclass(frozen=True, slots=True)
class BatchObjectHead:
    size_bytes: int
    etag: str


def derived_metadata_key(secret_access_key: str) -> bytes:
    return hmac.digest(secret_access_key.encode(), KEY_PURPOSE, "sha256")


class R2MetadataBatch:
    def __init__(self, signer: R2SigV4, connections: R2ConnectionPool):
        if signer.credentials.metadata_batch_origin is None:
            raise ValueError("R2 metadata batch requires an explicit origin")
        self.signer, self.connections = signer, connections
        self.origin = signer.credentials.metadata_batch_origin

    async def heads(self, keys: tuple[str, ...]) -> dict[str, BatchObjectHead | int | None]:
        """Return exact ordered results;503 denotes an individually failed head."""
        if (
            type(keys) is not tuple
            or not 1 <= len(keys) <= MAX_HEAD_KEYS
            or any(
                type(k) is not str
                or not k
                or len(k.encode()) > 1024
                or any(ord(c) < 32 or ord(c) == 127 for c in k)
                for k in keys
            )
            or len(set(keys)) != len(keys)
        ):
            raise ValueError("R2 metadata batch keys exceed their bound")
        nonce = secrets.token_hex(16)
        body = canonical_json_bytes(
            dict(
                schema="umi-r2-head-batch/1",
                nonce=nonce,
                issued_at_unix_ms=int(time.time() * 1000),
                endpoint=self.signer.endpoint,
                bucket=self.signer.bucket,
                keys=keys,
            )
        )
        if len(body) > MAX_METADATA_BYTES:
            raise ValueError("R2 metadata batch exceeds its byte bound")
        signed = b"POST\n" + HEAD_BATCH_PATH.encode() + b"\n" + body
        signature = hmac.new(
            derived_metadata_key(self.signer.credentials.secret_access_key), signed, hashlib.sha256
        ).hexdigest()
        headers = {
            "authorization": "UMI-R2-Metadata/1 "
            + self.signer.credentials.access_key_id
            + ":"
            + signature,
            "content-type": "application/json",
            "cache-control": "no-store",
            "user-agent": "umi/r2-metadata-batch",
        }
        raw = bytearray()
        try:
            async with (
                self.connections.request_client() as client,
                client.stream(
                    "POST", self.origin + HEAD_BATCH_PATH, headers=headers, content=body
                ) as response,
            ):
                if response.status_code != 200:
                    raise R2MetadataBatchUnavailable(
                        "r2_batch_http_" + str(response.status_code), response.status_code
                    )
                if (
                    response.headers.get("content-type", "").split(";", 1)[0].strip()
                    != "application/json"
                ):
                    raise R2MetadataBatchUnavailable("r2_batch_response_type_invalid")
                async for part in response.aiter_bytes():
                    if len(raw) + len(part) > MAX_METADATA_BYTES:
                        raise R2MetadataBatchUnavailable("r2_batch_response_oversized")
                    raw.extend(part)
        except httpx.HTTPError as error:
            raise R2MetadataBatchUnavailable("r2_batch_transport_error") from error
        try:
            value = json.loads(raw)
            if (
                type(value) is not dict
                or set(value) != {"schema", "nonce", "endpoint", "bucket", "objects"}
                or value["schema"] != "umi-r2-head-batch-response/1"
                or value["nonce"] != nonce
                or value["endpoint"] != self.signer.endpoint
                or value["bucket"] != self.signer.bucket
                or type(value["objects"]) is not list
                or len(value["objects"]) != len(keys)
            ):
                raise ValueError("batch source binding differs")
            out: dict[str, BatchObjectHead | int | None] = {}
            for key, item in zip(keys, value["objects"], strict=True):
                if type(item) is not dict or item.get("key") != key:
                    raise ValueError("batch object order or identity differs")
                status = item.get("status")
                if type(status) is not int:
                    raise ValueError("batch object status differs")
                if status in (404, 503) and set(item) == {"key", "status"}:
                    out[key] = None if status == 404 else 503
                elif (
                    status == 200
                    and set(item) == {"key", "status", "size_bytes", "etag"}
                    and type(item["size_bytes"]) is int
                    and 0 <= item["size_bytes"] <= 2**53 - 1
                    and type(item["etag"]) is str
                    and 1 <= len(item["etag"]) <= 256
                ):
                    out[key] = BatchObjectHead(item["size_bytes"], item["etag"].strip('"'))
                    if not out[key].etag:
                        raise ValueError("batch etag differs")
                else:
                    raise ValueError("batch object metadata differs")
            return out
        except (ValueError, TypeError, KeyError, UnicodeError) as error:
            raise R2MetadataBatchUnavailable("r2_batch_response_invalid") from error
