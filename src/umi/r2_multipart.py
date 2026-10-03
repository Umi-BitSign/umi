"""Trusted Cloudflare R2 multipart operations for the direct model issuer."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime

import httpx

from .competition_cohort_direct_model_upload import DirectModelUploadPart
from .r2_limits import R2_MAXIMUM_PART_BYTES, R2_MAXIMUM_PARTS, R2_MINIMUM_PART_BYTES
from .r2_sigv4 import R2SigV4

_MAXIMUM_RESPONSE_BYTES = 64 * 1024
MAXIMUM_RANGE_BYTES = 64 * 1024**2


def _element(root: ET.Element, name: str) -> str:
    for value in root.iter():
        if value.tag.rsplit("}", 1)[-1] == name and value.text:
            return value.text
    raise ValueError(f"R2 multipart response has no {name}")


def _xml(raw: bytes) -> ET.Element:
    if not raw or len(raw) > _MAXIMUM_RESPONSE_BYTES or b"<!DOCTYPE" in raw.upper():
        raise ValueError("R2 multipart response differs")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as error:
        raise ValueError("R2 multipart response is not XML") from error


@dataclass(frozen=True, slots=True)
class R2ObjectHead:
    size_bytes: int
    etag: str


class R2MultipartClient:
    def __init__(
        self,
        signer: R2SigV4,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 60,
    ):
        if not 1 <= timeout_seconds <= 300:
            raise ValueError("R2 multipart timeout differs")
        self.signer = signer
        self.transport = transport
        self.timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 15))

    async def _exchange(
        self,
        method: str,
        key: str,
        *,
        query: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
        expected_status: tuple[int, ...] = (200,),
        extra_headers: dict[str, str] | None = None,
        signed_headers: dict[str, str] | None = None,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
        at: datetime | None = None,
    ) -> httpx.Response:
        if not 0 <= maximum_response_bytes <= MAXIMUM_RANGE_BYTES:
            raise ValueError("R2 response byte bound differs")
        headers = self.signer.authorized_headers(
            method,
            key,
            query=query,
            body=body,
            additional_headers=signed_headers,
            at=at,
        ) | {
            "Accept-Encoding": "identity",
            "Content-Length": str(len(body)),
        }
        if extra_headers:
            if any(
                not name
                or name.lower() in {"authorization", "host", "x-amz-content-sha256", "x-amz-date"}
                or name.lower().startswith("x-amz-")
                or "\r" in value
                or "\n" in value
                for name, value in extra_headers.items()
            ):
                raise ValueError("R2 additional header differs")
            headers.update(extra_headers)
        if body:
            headers["Content-Type"] = "application/xml"
        try:
            async with (
                httpx.AsyncClient(
                    transport=self.transport,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    method,
                    self.signer.object_url(key, query=query),
                    headers=headers,
                    content=body,
                ) as streamed,
            ):
                if streamed.status_code not in expected_status:
                    raise OSError(f"R2 multipart request failed with HTTP {streamed.status_code}")
                if streamed.headers.get("content-encoding") not in {None, "identity"}:
                    raise ValueError("R2 multipart response used content encoding")
                content = bytearray()
                async for chunk in streamed.aiter_bytes():
                    if len(content) + len(chunk) > maximum_response_bytes:
                        raise ValueError("R2 multipart response is too large")
                    content.extend(chunk)
                response = httpx.Response(
                    streamed.status_code,
                    headers=streamed.headers,
                    content=bytes(content),
                    request=streamed.request,
                )
        except httpx.HTTPError as error:
            raise OSError("R2 multipart transport unavailable") from error
        return response

    async def copy_part(
        self,
        destination_key: str,
        *,
        source_key: str,
        upload_id: str,
        part_number: int,
        offset: int,
        size_bytes: int,
        source_size_bytes: int,
        at: datetime | None = None,
    ) -> DirectModelUploadPart:
        """Copy one exact source range into a destination multipart upload."""

        if (
            not upload_id
            or len(upload_id) > 2048
            or any(ord(character) < 33 for character in upload_id)
            or isinstance(part_number, bool)
            or not 1 <= part_number <= R2_MAXIMUM_PARTS
            or isinstance(offset, bool)
            or type(offset) is not int
            or offset < 0
            or isinstance(size_bytes, bool)
            or type(size_bytes) is not int
            or not 1 <= size_bytes <= R2_MAXIMUM_PART_BYTES
            or isinstance(source_size_bytes, bool)
            or type(source_size_bytes) is not int
            or source_size_bytes < size_bytes
            or offset + size_bytes > source_size_bytes
            or (offset + size_bytes < source_size_bytes and size_bytes < R2_MINIMUM_PART_BYTES)
            or (
                (offset or size_bytes != source_size_bytes)
                and source_size_bytes <= R2_MINIMUM_PART_BYTES
            )
        ):
            raise ValueError("R2 multipart copy part differs")
        signed = {"x-amz-copy-source": self.signer.copy_source_header(source_key)}
        if offset or size_bytes != source_size_bytes:
            signed["x-amz-copy-source-range"] = f"bytes={offset}-{offset + size_bytes - 1}"
        response = await self._exchange(
            "PUT",
            destination_key,
            query=(("partNumber", str(part_number)), ("uploadId", upload_id)),
            signed_headers=signed,
            at=at,
        )
        etag = _element(_xml(response.content), "ETag").strip('"')
        return DirectModelUploadPart(part_number=part_number, size_bytes=size_bytes, etag=etag)

    async def delete_object(self, key: str, *, at: datetime | None = None) -> None:
        """Delete one exact object; an already absent source is an idempotent success."""

        await self._exchange("DELETE", key, expected_status=(204, 404), at=at)

    async def create(self, key: str, *, at: datetime | None = None) -> str:
        response = await self._exchange("POST", key, query=(("uploads", ""),), at=at)
        upload_id = _element(_xml(response.content), "UploadId")
        if len(upload_id) > 2048 or any(ord(character) < 33 for character in upload_id):
            raise ValueError("R2 multipart upload identity differs")
        return upload_id

    async def complete(
        self,
        key: str,
        *,
        upload_id: str,
        parts: tuple[DirectModelUploadPart, ...],
        at: datetime | None = None,
    ) -> str:
        if not parts or tuple(p.part_number for p in parts) != tuple(range(1, len(parts) + 1)):
            raise ValueError("R2 multipart completion parts differ")
        body = (
            "<CompleteMultipartUpload>"
            + "".join(
                f"<Part><PartNumber>{part.part_number}</PartNumber>"
                f'<ETag>"{part.etag}"</ETag></Part>'
                for part in parts
            )
            + "</CompleteMultipartUpload>"
        ).encode()
        response = await self._exchange(
            "POST",
            key,
            query=(("uploadId", upload_id),),
            body=body,
            at=at,
        )
        etag = _element(_xml(response.content), "ETag").strip('"')
        if not etag or len(etag) > 256 or any(ord(character) < 33 for character in etag):
            raise ValueError("R2 completed object ETag differs")
        return etag

    async def abort(self, key: str, *, upload_id: str, at: datetime | None = None) -> None:
        await self._exchange(
            "DELETE",
            key,
            query=(("uploadId", upload_id),),
            expected_status=(204, 404),
            at=at,
        )

    async def multipart_exists(
        self, key: str, *, upload_id: str, at: datetime | None = None
    ) -> bool:
        """Probe one exact multipart generation without listing other uploads."""

        response = await self._exchange(
            "GET",
            key,
            query=(("uploadId", upload_id),),
            expected_status=(200, 404),
            maximum_response_bytes=8 * 1024**2,
            at=at,
        )
        return response.status_code == 200

    async def head(self, key: str, *, at: datetime | None = None) -> R2ObjectHead | None:
        response = await self._exchange("HEAD", key, expected_status=(200, 404), at=at)
        if response.status_code == 404:
            return None
        try:
            size = int(response.headers["content-length"])
            etag = response.headers["etag"].strip('"')
        except (KeyError, ValueError) as error:
            raise ValueError("R2 object metadata differs") from error
        if size < 0 or not etag or len(etag) > 256:
            raise ValueError("R2 object metadata differs")
        return R2ObjectHead(size_bytes=size, etag=etag)

    async def read_range(
        self,
        key: str,
        *,
        offset: int,
        size_bytes: int,
        at: datetime | None = None,
    ) -> bytes:
        """Read one exact bounded range; callers authenticate the returned bytes."""

        if (
            isinstance(offset, bool)
            or type(offset) is not int
            or offset < 0
            or isinstance(size_bytes, bool)
            or type(size_bytes) is not int
            or not 1 <= size_bytes <= MAXIMUM_RANGE_BYTES
        ):
            raise ValueError("R2 range differs")
        end = offset + size_bytes - 1
        response = await self._exchange(
            "GET",
            key,
            expected_status=(206,),
            extra_headers={"Range": f"bytes={offset}-{end}"},
            maximum_response_bytes=size_bytes,
            at=at,
        )
        content_range = response.headers.get("content-range", "")
        prefix = f"bytes {offset}-{end}/"
        if (
            len(response.content) != size_bytes
            or not content_range.startswith(prefix)
            or not content_range[len(prefix) :].isdigit()
            or int(content_range[len(prefix) :]) < end + 1
        ):
            raise ValueError("R2 range response differs")
        return bytes(response.content)
