"""Dependency-light server helper for the local UMI model sidecar protocol."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import math
import os
import re
import secrets
import stat
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias

MODEL_SIDECAR_PROTOCOL = "umi-model-sidecar/1"
MODEL_SIDECAR_CAPACITY_SCHEMA = "umi-model-sidecar-capacity/1"
MODEL_REQUEST_MAGIC = b"umi-model-request-v1\0"
MODEL_RESPONSE_MAGIC = b"umi-model-response-v1\0"
MODEL_REQUEST_PREFIX_BYTES = len(MODEL_REQUEST_MAGIC) + 4 + 8 + 32 + 32
MODEL_RESPONSE_PREFIX_BYTES = len(MODEL_RESPONSE_MAGIC) + 32 + 32 + 4

_REQUEST_DIGEST_DOMAIN = b"umi-request-v1\0"
_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
LOGGER = logging.getLogger("umi.model_sidecar")


@dataclass(frozen=True)
class CanonicalModelRequest:
    """Canonical request bytes and their decoded JSON document."""

    canonical_json: bytes
    document: dict[str, Any]


ModelResult: TypeAlias = Awaitable[str]
ModelCallback: TypeAlias = Callable[[bytes, CanonicalModelRequest], ModelResult]


@dataclass
class ModelSidecarServer:
    """Running Unix server with replacement-safe socket cleanup."""

    server: asyncio.AbstractServer
    socket_path: str
    socket_device: int
    socket_inode: int
    capacity_path: str
    capacity_device: int
    capacity_inode: int

    async def serve_forever(self) -> None:
        await self.server.serve_forever()

    async def close(self) -> None:
        self.server.close()
        await self.server.wait_closed()
        try:
            metadata = os.lstat(self.socket_path)
        except FileNotFoundError:
            pass
        else:
            if (
                stat.S_ISSOCK(metadata.st_mode)
                and metadata.st_dev == self.socket_device
                and metadata.st_ino == self.socket_inode
            ):
                os.unlink(self.socket_path)
        try:
            capacity = os.lstat(self.capacity_path)
        except FileNotFoundError:
            return
        if (
            stat.S_ISREG(capacity.st_mode)
            and capacity.st_dev == self.capacity_device
            and capacity.st_ino == self.capacity_inode
        ):
            os.unlink(self.capacity_path)

    async def __aenter__(self) -> ModelSidecarServer:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()


async def start_model_sidecar(
    socket_path: str | Path,
    callback: ModelCallback,
    *,
    model_revision: str | None,
    maximum_request_metadata_bytes: int = 64 * 1024,
    maximum_video_bytes: int = 16 * 1024 * 1024,
    maximum_response_bytes: int = 4 * 1024,
    maximum_concurrency: int = 1,
    maximum_inference_seconds: float = 120.0,
    scoring_policy_sha256: str | None = None,
    validator_slot_count: int = 1,
) -> ModelSidecarServer:
    """Start an owner-private, one-request-per-connection model server.

    This helper deliberately has no model-framework dependency. The callback gets
    the exact digest-verified MP4 bytes and the exact canonical request bytes.
    """

    if not callable(callback):
        raise TypeError("model callback must be callable")
    if not _is_async_callable(callback):
        raise TypeError("model callback must be an async callable")
    for name, value in (
        ("maximum_request_metadata_bytes", maximum_request_metadata_bytes),
        ("maximum_video_bytes", maximum_video_bytes),
        ("maximum_response_bytes", maximum_response_bytes),
        ("maximum_concurrency", maximum_concurrency),
        ("validator_slot_count", validator_slot_count),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if maximum_request_metadata_bytes > 0xFFFFFFFF:
        raise ValueError("maximum_request_metadata_bytes exceeds the U32 frame limit")
    if maximum_video_bytes > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("maximum_video_bytes exceeds the U64 frame limit")
    if maximum_response_bytes > 0xFFFFFFFF:
        raise ValueError("maximum_response_bytes exceeds the U32 frame limit")
    if maximum_concurrency < validator_slot_count:
        raise ValueError("maximum_concurrency must reserve one slot per validator")
    maximum_inference_milliseconds = _inference_milliseconds(maximum_inference_seconds)
    if scoring_policy_sha256 is not None and _HEX_32_RE.fullmatch(scoring_policy_sha256) is None:
        raise ValueError("scoring_policy_sha256 must be a lowercase SHA-256 digest")
    revision = _revision_bytes(model_revision)
    path = Path(socket_path)
    if not path.is_absolute():
        raise ValueError("model socket path must be absolute")
    if os.path.lexists(path):
        raise FileExistsError("model socket path already exists")
    _validate_private_socket_parent(path)

    semaphore = asyncio.Semaphore(maximum_concurrency)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with semaphore:
            try:
                request_digest, request_revision, request = await _read_request(
                    reader,
                    maximum_request_metadata_bytes=maximum_request_metadata_bytes,
                    maximum_video_bytes=maximum_video_bytes,
                )
                if request_revision != revision:
                    raise ValueError("model revision binding does not match")
                result = await _run_callback(
                    reader,
                    callback,
                    request[0],
                    request[1],
                    maximum_inference_seconds=maximum_inference_milliseconds / 1_000,
                )
                if not isinstance(result, str):
                    raise TypeError("model callback must return text")
                body = result.encode("utf-8", errors="strict")
                if len(body) > maximum_response_bytes:
                    raise ValueError("model result exceeds the response ceiling")
                writer.write(
                    MODEL_RESPONSE_MAGIC
                    + request_digest
                    + revision
                    + len(body).to_bytes(4, "big")
                    + body
                )
                await writer.drain()
            except asyncio.CancelledError:
                raise
            except Exception as error:
                LOGGER.warning("model sidecar request failed: %s", type(error).__name__)
            finally:
                writer.close()
                with suppress(ConnectionError):
                    await writer.wait_closed()

    server = await asyncio.start_unix_server(handle, path=str(path))
    try:
        os.chmod(path, 0o600)
        metadata = os.lstat(path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RuntimeError("model socket did not enter the required private state")
        capacity_path, capacity_metadata = _write_capacity_descriptor(
            path,
            socket_metadata=metadata,
            model_revision=model_revision,
            scoring_policy_sha256=scoring_policy_sha256,
            validator_slot_count=validator_slot_count,
            maximum_concurrency=maximum_concurrency,
            maximum_inference_milliseconds=maximum_inference_milliseconds,
        )
    except Exception:
        server.close()
        await server.wait_closed()
        with suppress(FileNotFoundError):
            os.unlink(path)
        raise
    return ModelSidecarServer(
        server=server,
        socket_path=str(path),
        socket_device=metadata.st_dev,
        socket_inode=metadata.st_ino,
        capacity_path=str(capacity_path),
        capacity_device=capacity_metadata.st_dev,
        capacity_inode=capacity_metadata.st_ino,
    )


def validate_model_sidecar_capacity(
    socket_path: str | Path,
    *,
    expected_model_revision: str | None,
    expected_scoring_policy_sha256: str,
    required_validator_slots: int,
    maximum_inference_seconds: float = 120.0,
) -> int:
    """Validate the private descriptor bound to one live sidecar socket."""

    if _HEX_32_RE.fullmatch(expected_scoring_policy_sha256) is None:
        raise ValueError("expected scoring policy hash must be lowercase SHA-256")
    if (
        isinstance(required_validator_slots, bool)
        or not isinstance(required_validator_slots, int)
        or required_validator_slots <= 0
    ):
        raise ValueError("required validator slots must be a positive integer")
    _revision_bytes(expected_model_revision)
    maximum_inference_milliseconds = _inference_milliseconds(maximum_inference_seconds)
    socket = Path(socket_path)
    _validate_private_socket_parent(socket)
    socket_metadata = socket.lstat()
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(socket_metadata.st_mode) != 0o600
    ):
        raise RuntimeError("model sidecar socket is not owner-private")
    descriptor_path = _capacity_path(socket)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(descriptor_path, flags)
    except OSError as error:
        raise RuntimeError("model sidecar capacity descriptor is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > 4096
        ):
            raise RuntimeError("model sidecar capacity descriptor is unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, 4097 - len(raw)):
            raw.extend(chunk)
            if len(raw) > 4096:
                raise RuntimeError("model sidecar capacity descriptor exceeds its ceiling")
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after) or len(raw) != before.st_size:
            raise RuntimeError("model sidecar capacity descriptor changed while read")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(bytes(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("model sidecar capacity descriptor is invalid") from error
    if not isinstance(document, dict) or _canonical_json(document) != bytes(raw):
        raise RuntimeError("model sidecar capacity descriptor is not canonical")
    expected_keys = {
        "schema",
        "socket_device",
        "socket_inode",
        "process_id",
        "startup_nonce",
        "model_revision",
        "scoring_policy_sha256",
        "validator_slot_count",
        "maximum_concurrency",
        "maximum_inference_milliseconds",
    }
    if set(document) != expected_keys:
        raise RuntimeError("model sidecar capacity descriptor has unexpected fields")
    socket_after = socket.lstat()
    if _stat_identity(socket_metadata) != _stat_identity(socket_after):
        raise RuntimeError("model sidecar socket changed during capacity validation")
    maximum_concurrency = document.get("maximum_concurrency")
    validator_slot_count = document.get("validator_slot_count")
    process_id = document.get("process_id")
    declared_inference_milliseconds = document.get("maximum_inference_milliseconds")
    if (
        document.get("schema") != MODEL_SIDECAR_CAPACITY_SCHEMA
        or document.get("socket_device") != socket_metadata.st_dev
        or document.get("socket_inode") != socket_metadata.st_ino
        or document.get("model_revision") != expected_model_revision
        or document.get("scoring_policy_sha256") != expected_scoring_policy_sha256
        or validator_slot_count != required_validator_slots
        or isinstance(maximum_concurrency, bool)
        or not isinstance(maximum_concurrency, int)
        or maximum_concurrency < required_validator_slots
        or isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or process_id <= 0
        or isinstance(declared_inference_milliseconds, bool)
        or not isinstance(declared_inference_milliseconds, int)
        or declared_inference_milliseconds <= 0
        or declared_inference_milliseconds > maximum_inference_milliseconds
        or not isinstance(document.get("startup_nonce"), str)
        or _HEX_32_RE.fullmatch(document["startup_nonce"]) is None
    ):
        raise RuntimeError("model sidecar capacity descriptor binding does not match")
    try:
        os.kill(process_id, 0)
    except OSError as error:
        raise RuntimeError("model sidecar capacity descriptor names a dead process") from error
    return maximum_concurrency


def _write_capacity_descriptor(
    socket_path: Path,
    *,
    socket_metadata: os.stat_result,
    model_revision: str | None,
    scoring_policy_sha256: str | None,
    validator_slot_count: int,
    maximum_concurrency: int,
    maximum_inference_milliseconds: int,
) -> tuple[Path, os.stat_result]:
    descriptor_path = _capacity_path(socket_path)
    if os.path.lexists(descriptor_path):
        raise FileExistsError("model sidecar capacity descriptor already exists")
    document = {
        "schema": MODEL_SIDECAR_CAPACITY_SCHEMA,
        "socket_device": socket_metadata.st_dev,
        "socket_inode": socket_metadata.st_ino,
        "process_id": os.getpid(),
        "startup_nonce": secrets.token_hex(32),
        "model_revision": model_revision,
        "scoring_policy_sha256": scoring_policy_sha256,
        "validator_slot_count": validator_slot_count,
        "maximum_concurrency": maximum_concurrency,
        "maximum_inference_milliseconds": maximum_inference_milliseconds,
    }
    raw = _canonical_json(document)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(descriptor_path, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RuntimeError("model sidecar capacity descriptor is unsafe")
    except Exception:
        os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(descriptor_path)
        raise
    else:
        os.close(descriptor)
    _fsync_directory(descriptor_path.parent)
    return descriptor_path, metadata


def _capacity_path(socket_path: Path) -> Path:
    return Path(f"{socket_path}.capacity.json")


def _canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_nlink,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


async def _read_request(
    reader: asyncio.StreamReader,
    *,
    maximum_request_metadata_bytes: int,
    maximum_video_bytes: int,
) -> tuple[bytes, bytes, tuple[bytes, CanonicalModelRequest]]:
    prefix = await reader.readexactly(MODEL_REQUEST_PREFIX_BYTES)
    if not prefix.startswith(MODEL_REQUEST_MAGIC):
        raise ValueError("invalid model request protocol marker")
    offset = len(MODEL_REQUEST_MAGIC)
    metadata_length = int.from_bytes(prefix[offset : offset + 4], "big")
    offset += 4
    video_length = int.from_bytes(prefix[offset : offset + 8], "big")
    offset += 8
    claimed_digest = prefix[offset : offset + 32]
    offset += 32
    revision = prefix[offset : offset + 32]
    if metadata_length > maximum_request_metadata_bytes:
        raise ValueError("model request metadata exceeds its ceiling")
    if video_length > maximum_video_bytes:
        raise ValueError("model request video exceeds its ceiling")

    metadata = await reader.readexactly(metadata_length)
    actual_digest = hashlib.sha256(_REQUEST_DIGEST_DOMAIN + metadata).digest()
    if claimed_digest != actual_digest:
        raise ValueError("model request digest does not match")
    document = _decode_request(metadata)
    video = await reader.readexactly(video_length)
    descriptor = document.get("video")
    if not isinstance(descriptor, dict):
        raise ValueError("model request lacks a video descriptor")
    expected_size = descriptor.get("size_bytes")
    expected_digest = descriptor.get("sha256")
    if (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size != video_length
        or not isinstance(expected_digest, str)
        or _HEX_32_RE.fullmatch(expected_digest) is None
        or hashlib.sha256(video).hexdigest() != expected_digest
    ):
        raise ValueError("model request video binding does not match")
    return (
        claimed_digest,
        revision,
        (
            video,
            CanonicalModelRequest(canonical_json=metadata, document=document),
        ),
    )


def _decode_request(value: bytes) -> dict[str, Any]:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("model request JSON contains a duplicate key")
            result[key] = item
        return result

    try:
        decoded = json.loads(value, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("model request metadata is not valid UTF-8 JSON") from error
    if not isinstance(decoded, dict):
        raise ValueError("model request metadata must be a JSON object")
    return decoded


async def _run_callback(
    reader: asyncio.StreamReader,
    callback: ModelCallback,
    video: bytes,
    request: CanonicalModelRequest,
    *,
    maximum_inference_seconds: float,
) -> str:
    result = callback(video, request)
    if not inspect.isawaitable(result):
        raise TypeError("async model callback must return an awaitable")
    callback_task = asyncio.create_task(result)
    disconnect_task = asyncio.create_task(reader.read(1))
    try:
        completed, _pending = await asyncio.wait(
            (callback_task, disconnect_task),
            timeout=maximum_inference_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if callback_task in completed:
            return callback_task.result()
        if disconnect_task in completed:
            trailing = disconnect_task.result()
            if trailing:
                raise ValueError("model request contains trailing bytes")
            raise ConnectionError("model client disconnected before inference completed")
        raise TimeoutError("model callback exceeded its inference deadline")
    finally:
        for task in (callback_task, disconnect_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(callback_task, disconnect_task, return_exceptions=True)


def _is_async_callable(callback: ModelCallback) -> bool:
    return inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
        type(callback).__call__
    )


def _inference_milliseconds(value: float) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
        or value > 86_400
    ):
        raise ValueError("maximum_inference_seconds must be in (0, 86400]")
    return math.ceil(value * 1_000)


def _revision_bytes(value: str | None) -> bytes:
    if value is None:
        return bytes(32)
    if not isinstance(value, str) or _HEX_32_RE.fullmatch(value) is None:
        raise ValueError("model revision must be a lowercase SHA-256 digest")
    return bytes.fromhex(value)


def _validate_private_socket_parent(path: Path) -> None:
    try:
        metadata = path.parent.lstat()
    except OSError as error:
        raise RuntimeError("model socket parent directory is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("model socket parent must name a directory directly")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("model socket parent must be owned by this user with mode 0700")


__all__ = [
    "MODEL_REQUEST_MAGIC",
    "MODEL_REQUEST_PREFIX_BYTES",
    "MODEL_RESPONSE_MAGIC",
    "MODEL_RESPONSE_PREFIX_BYTES",
    "MODEL_SIDECAR_CAPACITY_SCHEMA",
    "MODEL_SIDECAR_PROTOCOL",
    "CanonicalModelRequest",
    "ModelCallback",
    "ModelSidecarServer",
    "start_model_sidecar",
    "validate_model_sidecar_capacity",
]
