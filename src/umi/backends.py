"""Translation backend boundary.

The protocol does not prescribe a model.  A miner supplies a trusted Python
callable at startup; UMI never substitutes a canned hypothesis when it fails.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import math
import os
import stat
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeAlias, cast

from .model_sidecar import (
    MODEL_REQUEST_MAGIC,
    MODEL_RESPONSE_MAGIC,
    MODEL_RESPONSE_PREFIX_BYTES,
    validate_model_sidecar_capacity,
)
from .protocol import TranslationRequest, canonical_json_bytes, request_digest

TranslationResult: TypeAlias = str | Awaitable[str]
TranslationCallable: TypeAlias = Callable[[bytes, TranslationRequest], TranslationResult]


class Translator(Protocol):
    async def translate(self, video: bytes, request: TranslationRequest) -> str: ...


def _is_async_callable(function: Callable[..., object]) -> bool:
    """Recognize async functions and instances with an async ``__call__``."""

    return inspect.iscoroutinefunction(function) or inspect.iscoroutinefunction(
        type(function).__call__
    )


@dataclass(frozen=True)
class PythonPluginTranslator:
    """Adapter for a configured ``module:callable`` translation backend."""

    function: TranslationCallable
    executor: ThreadPoolExecutor | None = None
    declared_model_revision: str | None = None

    async def startup(self) -> None:
        """Run an optional async backend startup hook before serving traffic."""

        await _run_optional_lifecycle_hook(self.function, "startup")

    async def shutdown(self) -> None:
        """Run an optional async backend shutdown hook and close local workers."""

        try:
            await _run_optional_lifecycle_hook(self.function, "shutdown")
        finally:
            if self.executor is not None:
                self.executor.shutdown(wait=False, cancel_futures=True)

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        if _is_async_callable(self.function):
            result = self.function(video, request)
        else:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(self.executor, self.function, video, request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, str):
            raise TypeError("translation backend must return str")
        return result


@dataclass(frozen=True)
class UnixSocketTranslator:
    """Async boundary to a trusted model in a separately isolated environment.

    Each inference uses a new local Unix-stream connection. The request frame is
    ``magic || U32BE(metadata_len) || U64BE(video_len) || request_digest ||
    model_revision || metadata || video``. Metadata is the canonical UMI request,
    model revision is either its configured raw digest or 32 zero bytes, and video
    is the exact verified MP4. The response frame is ``magic || request_digest ||
    model_revision || U32BE(hypothesis_len) || hypothesis``. Fixed-size prefixes
    are read before bounded payload allocation, and one connection carries one
    request and one response.
    """

    socket_path: str
    maximum_request_metadata_bytes: int
    maximum_response_bytes: int
    expected_model_revision: str | None = None
    expected_scoring_policy_sha256: str | None = None
    required_validator_slots: int = 1
    maximum_inference_seconds: float = 120.0

    def __post_init__(self) -> None:
        if not isinstance(self.socket_path, str) or not self.socket_path:
            raise ValueError("model socket path must be nonempty text")
        for name in ("maximum_request_metadata_bytes", "maximum_response_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be positive")
            if value > 0xFFFFFFFF:
                raise ValueError(f"{name} exceeds the U32 frame limit")
        if self.expected_model_revision is not None:
            try:
                revision = bytes.fromhex(self.expected_model_revision)
            except (TypeError, ValueError) as error:
                raise ValueError("expected model revision must be a SHA-256 digest") from error
            if len(revision) != 32 or revision.hex() != self.expected_model_revision:
                raise ValueError("expected model revision must be a lowercase SHA-256 digest")
        if (
            isinstance(self.required_validator_slots, bool)
            or not isinstance(self.required_validator_slots, int)
            or self.required_validator_slots <= 0
        ):
            raise ValueError("required_validator_slots must be a positive integer")
        if self.expected_scoring_policy_sha256 is None:
            if self.required_validator_slots != 1:
                raise ValueError(
                    "a scoring policy hash is required for multiple sidecar validator slots"
                )
        else:
            try:
                policy_hash = bytes.fromhex(self.expected_scoring_policy_sha256)
            except (TypeError, ValueError) as error:
                raise ValueError("expected scoring policy hash must be SHA-256") from error
            if len(policy_hash) != 32 or policy_hash.hex() != self.expected_scoring_policy_sha256:
                raise ValueError("expected scoring policy hash must be lowercase SHA-256")
        if (
            isinstance(self.maximum_inference_seconds, bool)
            or not isinstance(self.maximum_inference_seconds, (int, float))
            or not math.isfinite(self.maximum_inference_seconds)
            or self.maximum_inference_seconds <= 0
            or self.maximum_inference_seconds > 86_400
        ):
            raise ValueError("maximum_inference_seconds must be in (0, 86400]")
        _validate_private_unix_socket(self.socket_path)
        self._validate_capacity()

    def _validate_capacity(self) -> None:
        if self.expected_scoring_policy_sha256 is None:
            return
        validate_model_sidecar_capacity(
            self.socket_path,
            expected_model_revision=self.expected_model_revision,
            expected_scoring_policy_sha256=self.expected_scoring_policy_sha256,
            required_validator_slots=self.required_validator_slots,
            maximum_inference_seconds=self.maximum_inference_seconds,
        )

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        if not isinstance(request, TranslationRequest):
            raise TypeError("model request must be a TranslationRequest")
        if not isinstance(video, bytes):
            raise TypeError("verified model input must be bytes")
        if len(video) != request.video.size_bytes:
            raise ValueError("verified model input size does not match the request")
        import hashlib

        if hashlib.sha256(video).hexdigest() != request.video.sha256:
            raise ValueError("verified model input digest does not match the request")

        metadata = canonical_json_bytes(request)
        if len(metadata) > self.maximum_request_metadata_bytes:
            raise ValueError("model request metadata exceeds the byte ceiling")
        digest = bytes.fromhex(request_digest(request))
        revision = (
            bytes.fromhex(self.expected_model_revision)
            if self.expected_model_revision is not None
            else bytes(32)
        )
        request_prefix = (
            MODEL_REQUEST_MAGIC
            + len(metadata).to_bytes(4, "big")
            + len(video).to_bytes(8, "big")
            + digest
            + revision
        )

        _validate_private_unix_socket(self.socket_path)
        self._validate_capacity()
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.open_unix_connection(self.socket_path)
            writer.write(request_prefix)
            writer.write(metadata)
            writer.write(video)
            await writer.drain()

            response_prefix = await reader.readexactly(MODEL_RESPONSE_PREFIX_BYTES)
            if not response_prefix.startswith(MODEL_RESPONSE_MAGIC):
                raise ValueError("model response has an invalid protocol marker")
            offset = len(MODEL_RESPONSE_MAGIC)
            echoed_digest = response_prefix[offset : offset + 32]
            offset += 32
            echoed_revision = response_prefix[offset : offset + 32]
            offset += 32
            response_length = int.from_bytes(response_prefix[offset : offset + 4], "big")
            if echoed_digest != digest:
                raise ValueError("model response request binding does not match")
            if echoed_revision != revision:
                raise ValueError("model response revision binding does not match")
            if response_length > self.maximum_response_bytes:
                raise ValueError("model response exceeds the byte ceiling")
            body = await reader.readexactly(response_length)
        except asyncio.IncompleteReadError as error:
            raise RuntimeError("model sidecar returned a truncated frame") from error
        finally:
            if writer is not None:
                writer.close()
                with suppress(ConnectionError):
                    await writer.wait_closed()
        try:
            return body.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError("model response is not valid UTF-8") from error


def load_translator(
    spec: str,
    *,
    maximum_concurrency: int = 1,
    allow_synchronous: bool = False,
    expected_model_revision: str | None = None,
) -> PythonPluginTranslator:
    """Load a trusted backend named ``module:callable``.

    The callable receives verified video bytes and the validated request and must
    return an English string. Synchronous callables require explicit opt-in.
    """

    if (
        isinstance(maximum_concurrency, bool)
        or not isinstance(maximum_concurrency, int)
        or maximum_concurrency <= 0
    ):
        raise ValueError("maximum_concurrency must be a positive integer")
    if not isinstance(allow_synchronous, bool):
        raise TypeError("allow_synchronous must be boolean")
    expected_model_revision = _model_revision(
        expected_model_revision,
        label="expected model revision",
    )
    if not isinstance(spec, str):
        raise TypeError("translator spec must be a string")
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("translator must be named as 'module:callable'")
    function = getattr(importlib.import_module(module_name), attribute, None)
    if not callable(function):
        raise ValueError(f"translator {spec!r} is not callable")
    for hook_name in ("startup", "shutdown"):
        hook = getattr(function, hook_name, None)
        if hook is not None and (not callable(hook) or not _is_async_callable(hook)):
            raise ValueError(f"translator {hook_name} hook must be async")
    declared_model_revision = _model_revision(
        getattr(function, "model_revision", None),
        label="translator model revision",
    )
    if expected_model_revision is not None and declared_model_revision is None:
        raise ValueError("a versioned in-process translator must declare its model revision")
    if declared_model_revision is not None and expected_model_revision is None:
        raise ValueError("a translator-declared model revision must be bound by the miner")
    if declared_model_revision != expected_model_revision:
        raise ValueError("translator model revision does not match the configured revision")
    is_async = _is_async_callable(function)
    if not is_async and not allow_synchronous:
        raise ValueError(
            "synchronous translators require explicit unsafe opt-in because Python cannot "
            "terminate a hung worker thread"
        )
    executor = (
        None
        if is_async
        else ThreadPoolExecutor(
            max_workers=maximum_concurrency,
            thread_name_prefix="umi-translator",
        )
    )
    return PythonPluginTranslator(
        cast(TranslationCallable, function),
        executor,
        declared_model_revision,
    )


async def _run_optional_lifecycle_hook(function: object, hook_name: str) -> None:
    hook = getattr(function, hook_name, None)
    if hook is None:
        return
    result = hook()
    if not inspect.isawaitable(result):  # pragma: no cover - rejected by load_translator
        raise TypeError(f"translator {hook_name} hook must return an awaitable")
    await result


def _model_revision(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    try:
        digest = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest") from error
    if len(digest) != 32 or digest.hex() != value:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_private_unix_socket(value: str) -> None:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("model socket path must be absolute")
    _validate_private_socket_parent(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RuntimeError("model socket is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
        raise RuntimeError("model socket path must name a Unix socket directly")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError("model socket must be owned by this user with mode 0600")


def _validate_private_socket_parent(path: Path) -> None:
    try:
        metadata = path.parent.lstat()
    except OSError as error:
        raise RuntimeError("model socket parent directory is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("model socket parent must name a directory directly")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("model socket parent must be owned by this user with mode 0700")
