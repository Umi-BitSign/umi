"""In-memory multipart provider for native direct-delivery lifecycle rehearsals.

Only fixture credentials and MockTransport are used. Objects are assembled from
the bytes actually streamed by the native miner client, never fixture payloads.
The first PUT-backed completion persists its object and loses its reply once;
the native owner's HEAD recovery must discover that completed object.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime
from urllib.parse import unquote

import httpx

from umi.competition_cohort_direct_model_upload import DirectModelUploadPart
from umi.r2_limits import R2_MAXIMUM_PART_BYTES, R2_MAXIMUM_PARTS, R2_MINIMUM_PART_BYTES
from umi.r2_multipart import MAXIMUM_RANGE_BYTES, R2ObjectHead
from umi.r2_sigv4 import R2Credentials, R2SigV4


def _etag(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


class NativeMultipart:
    """Native multipart interface plus a streaming UploadPart HTTP transport.

    ``objects`` contains real completed bytes; ``uploads`` contains real parts
    scoped by (key, upload ID). ``counts`` and ``operations`` expose all calls.
    ``reader(role)`` supplies a separate read-only client for each reviewer.
    Closing a reader or provider records the close but keeps durable synthetic
    objects, so a new native owner can resume against the same provider state.
    """

    def __init__(self, *, lose_first_complete_reply: bool = True):
        self.signer = R2SigV4(
            endpoint="https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
            bucket="umi-model-artifacts",
            credentials=R2Credentials("0123456789ABCDEF", "synthetic-fixture-secret-key"),
        )
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[tuple[str, str], dict[int, bytes]] = {}
        self._put_uploads: set[tuple[str, str]] = set()
        self._next_upload = 0
        self.lose_first_complete_reply = lose_first_complete_reply
        self.lost_complete_replies = 0
        self.counts: Counter[str] = Counter()
        self.operations: list[dict] = []
        self.reader_operations: list[dict] = []
        self.create_calls: list[tuple] = []
        self.complete_calls: list[tuple] = []
        self.copy_calls: list[tuple] = []
        self.delete_calls: list[tuple] = []
        self.abort_calls: list[tuple] = []
        self.put_calls: list[tuple] = []
        self.read_calls = 0
        self.bytes_uploaded = 0
        self.bytes_copied = 0
        self.bytes_read = 0
        self.transport = httpx.MockTransport(self.put_part)

    def _record(self, operation: str, **values) -> None:
        self.counts[operation] += 1
        self.operations.append({"operation": operation, **values})

    def _key(self, key: str) -> None:
        # Use the real signer's canonical key validation without external I/O.
        self.signer.object_url(key)

    def _parts(self, key: str, upload_id: str) -> dict[int, bytes]:
        try:
            return self.uploads[key, upload_id]
        except KeyError as error:
            raise OSError("synthetic multipart upload is absent") from error

    async def create(self, key: str, *, at: datetime | None = None) -> str:
        self._key(key)
        self._next_upload += 1
        upload_id = f"synthetic-upload-{self._next_upload}"
        self.uploads[key, upload_id] = {}
        self.create_calls.append((key, at))
        self._record("create", key=key, upload_id=upload_id)
        return upload_id

    async def multipart_exists(
        self, key: str, *, upload_id: str, at: datetime | None = None
    ) -> bool:
        self._key(key)
        result = (key, upload_id) in self.uploads
        self._record("multipart_exists", key=key, upload_id=upload_id, exists=result)
        return result

    async def exists(self, key: str, *, upload_id: str, at: datetime | None = None) -> bool:
        return await self.multipart_exists(key, upload_id=upload_id, at=at)

    async def put_part(self, request: httpx.Request) -> httpx.Response:
        """Consume actual native-client HTTP streams into a scoped real part."""
        _require(request.method == "PUT", "synthetic provider only accepts UploadPart PUT")
        origin = httpx.URL(self.signer.endpoint)
        _require(
            request.url.scheme == origin.scheme
            and request.url.host == origin.host
            and request.url.port == origin.port,
            "synthetic PUT origin differs",
        )
        prefix = f"/{self.signer.bucket}/"
        path = unquote(request.url.raw_path.split(b"?", 1)[0].decode("ascii"))
        _require(path.startswith(prefix), "synthetic PUT bucket differs")
        key = path[len(prefix) :]
        self._key(key)
        upload_ids = request.url.params.get_list("uploadId")
        part_numbers = request.url.params.get_list("partNumber")
        _require(len(upload_ids) == len(part_numbers) == 1, "synthetic PUT identity differs")
        upload_id = upload_ids[0]
        try:
            number = int(part_numbers[0])
        except ValueError as error:
            raise ValueError("synthetic PUT part number differs") from error
        _require(
            str(number) == part_numbers[0] and 1 <= number <= R2_MAXIMUM_PARTS,
            "synthetic PUT part number differs",
        )
        self._record("put_part", key=key, upload_id=upload_id, part_number=number)
        if (key, upload_id) not in self.uploads:
            return httpx.Response(404)
        data = bytearray()
        async for chunk in request.stream:
            _require(
                len(data) + len(chunk) <= R2_MAXIMUM_PART_BYTES,
                "synthetic PUT part exceeds native bound",
            )
            data.extend(chunk)
        _require(bool(data), "synthetic PUT part is empty")
        if "content-length" in request.headers:
            _require(
                int(request.headers["content-length"]) == len(data),
                "synthetic PUT declared size differs",
            )
        actual = bytes(data)
        self._parts(key, upload_id)[number] = actual
        self._put_uploads.add((key, upload_id))
        self.put_calls.append((key, upload_id, number, len(actual), _etag(actual)))
        self.bytes_uploaded += len(actual)
        return httpx.Response(200, headers={"ETag": f'"{_etag(actual)}"'})

    async def head(self, key: str, *, at: datetime | None = None) -> R2ObjectHead | None:
        self._key(key)
        self._record("head", key=key)
        data = self.objects.get(key)
        return None if data is None else R2ObjectHead(size_bytes=len(data), etag=_etag(data))

    async def complete(
        self,
        key: str,
        *,
        upload_id: str,
        parts: tuple[DirectModelUploadPart, ...],
        at: datetime | None = None,
    ) -> str:
        self._key(key)
        self.complete_calls.append((key, upload_id, parts, at))
        self._record("complete", key=key, upload_id=upload_id, part_count=len(parts))
        stored = self._parts(key, upload_id)
        _require(0 < len(parts) <= R2_MAXIMUM_PARTS, "synthetic completion part count differs")
        numbers = tuple(range(1, len(parts) + 1))
        _require(
            tuple(part.part_number for part in parts) == numbers and set(stored) == set(numbers),
            "synthetic completion ordered parts differ",
        )
        for part in parts:
            data = stored[part.part_number]
            _require(
                part.size_bytes == len(data) and part.etag == _etag(data),
                "synthetic completion part bytes/ETag differ",
            )
            _require(
                0 < len(data) <= R2_MAXIMUM_PART_BYTES, "synthetic completion part size differs"
            )
            if part.part_number < len(parts):
                _require(
                    len(data) >= R2_MINIMUM_PART_BYTES,
                    "synthetic completion nonfinal part is too small",
                )
        data = b"".join(stored[number] for number in numbers)
        self.objects[key] = data
        del self.uploads[key, upload_id]
        staging = (key, upload_id) in self._put_uploads
        self._put_uploads.discard((key, upload_id))
        self._record("object_persisted", key=key, bytes=len(data), etag=_etag(data))
        if staging and self.lose_first_complete_reply and not self.lost_complete_replies:
            self.lost_complete_replies += 1
            self._record("lost_complete_reply", key=key, upload_id=upload_id)
            raise OSError("synthetic response lost after successful staging completion")
        return _etag(data)

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
        self._key(destination_key)
        self._key(source_key)
        _require(
            type(part_number) is int and 1 <= part_number <= R2_MAXIMUM_PARTS,
            "synthetic copy part number differs",
        )
        _require(
            type(offset) is int
            and type(size_bytes) is int
            and type(source_size_bytes) is int
            and offset >= 0
            and 1 <= size_bytes <= R2_MAXIMUM_PART_BYTES,
            "synthetic copy range differs",
        )
        try:
            source = self.objects[source_key]
        except KeyError as error:
            raise OSError("synthetic copy source is absent") from error
        _require(
            source_size_bytes == len(source) and offset + size_bytes <= len(source),
            "synthetic copy source size differs",
        )
        if offset + size_bytes < len(source):
            _require(
                size_bytes >= R2_MINIMUM_PART_BYTES, "synthetic copy nonfinal part is too small"
            )
        if source_size_bytes <= R2_MINIMUM_PART_BYTES:
            _require(
                offset == 0 and size_bytes == source_size_bytes,
                "synthetic copy of small source must be whole",
            )
        data = source[offset : offset + size_bytes]
        self._parts(destination_key, upload_id)[part_number] = data
        self.copy_calls.append(
            (destination_key, source_key, upload_id, part_number, offset, size_bytes, at)
        )
        self.bytes_copied += len(data)
        self._record(
            "copy_part",
            key=destination_key,
            source_key=source_key,
            upload_id=upload_id,
            part_number=part_number,
            offset=offset,
            bytes=len(data),
        )
        return DirectModelUploadPart(
            part_number=part_number, size_bytes=len(data), etag=_etag(data)
        )

    async def delete_object(self, key: str, *, at: datetime | None = None) -> None:
        self._key(key)
        self.delete_calls.append((key, at))
        self.objects.pop(key, None)
        self._record("delete_object", key=key)

    async def delete(self, key: str, *, at: datetime | None = None) -> None:
        await self.delete_object(key, at=at)

    async def abort(self, key: str, *, upload_id: str, at: datetime | None = None) -> None:
        self._key(key)
        self.abort_calls.append((key, upload_id, at))
        self.uploads.pop((key, upload_id), None)
        self._put_uploads.discard((key, upload_id))
        self._record("abort", key=key, upload_id=upload_id)

    async def read_range(
        self,
        key: str,
        *,
        offset: int,
        size_bytes: int,
        at: datetime | None = None,
    ) -> bytes:
        self._key(key)
        _require(
            type(offset) is int
            and offset >= 0
            and type(size_bytes) is int
            and 1 <= size_bytes <= MAXIMUM_RANGE_BYTES,
            "synthetic read range differs",
        )
        try:
            data = self.objects[key]
        except KeyError as error:
            raise OSError("synthetic read object is absent") from error
        _require(offset + size_bytes <= len(data), "synthetic read range is truncated")
        result = data[offset : offset + size_bytes]
        self.read_calls += 1
        self.bytes_read += len(result)
        self._record("read_range", key=key, offset=offset, bytes=len(result))
        return result

    async def aclose(self) -> None:
        self._record("aclose")

    def reader(self, role: str) -> NativeMultipartReader:
        return NativeMultipartReader(self, role)


class NativeMultipartReader:
    """Role-scoped read-only interface; no signer or mutation methods exposed."""

    def __init__(self, provider: NativeMultipart, role: str):
        _require(isinstance(role, str) and bool(role), "synthetic reader role is required")
        self._provider = provider
        self.role = role
        self.read_calls = 0
        self.head_calls = 0
        self.bytes_read = 0
        self.operations: list[dict] = []
        self.counts: Counter[str] = Counter()

    def _record(self, operation: str, **values) -> None:
        record = {"operation": operation, "role": self.role, **values}
        self.operations.append(record)
        self._provider.reader_operations.append(record)
        self.counts[operation] += 1

    async def head(self, key: str, *, at: datetime | None = None) -> R2ObjectHead | None:
        result = await self._provider.head(key, at=at)
        self.head_calls += 1
        self._record("head", key=key, bytes=None if result is None else result.size_bytes)
        return result

    async def read_range(
        self,
        key: str,
        *,
        offset: int,
        size_bytes: int,
        at: datetime | None = None,
    ) -> bytes:
        result = await self._provider.read_range(key, offset=offset, size_bytes=size_bytes, at=at)
        self.read_calls += 1
        self.bytes_read += len(result)
        self._record(
            "read_range",
            key=key,
            offset=offset,
            bytes=len(result),
            sha256=hashlib.sha256(result).hexdigest(),
        )
        return result

    async def aclose(self) -> None:
        self._record("aclose")
