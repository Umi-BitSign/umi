from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import tempfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, contextmanager, suppress

import pytest

from umi.backends import UnixSocketTranslator, load_translator
from umi.model_sidecar import (
    MODEL_REQUEST_MAGIC,
    MODEL_RESPONSE_MAGIC,
    CanonicalModelRequest,
    start_model_sidecar,
)
from umi.protocol import TranslationRequest, canonical_json_bytes

from .factories import VIDEO_BYTES, challenge_request

POLICY_HASH = "20" * 32


async def async_translator(_video, _request) -> str:
    return "translation"


class AsyncCallableTranslator:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, object]] = []

    async def __call__(self, video, request) -> str:
        self.calls.append((video, request))
        return "model output"


async_callable_translator = AsyncCallableTranslator()


class LifecycleTranslator:
    model_revision = "ab" * 32

    def __init__(self) -> None:
        self.events: list[str] = []

    async def startup(self) -> None:
        self.events.append("startup")

    async def shutdown(self) -> None:
        self.events.append("shutdown")

    async def __call__(self, _video, _request) -> str:
        return "model output"


lifecycle_translator = LifecycleTranslator()


class InvalidLifecycleTranslator:
    async def __call__(self, _video, _request) -> str:
        return "model output"

    def startup(self) -> None:
        return None


invalid_lifecycle_translator = InvalidLifecycleTranslator()


def slow_synchronous_translator(_video, _request) -> str:
    time.sleep(0.05)
    return "late translation"


def test_asynchronous_translator_is_the_safe_default() -> None:
    translator = load_translator("tests.test_backends:async_translator")
    assert translator.function is async_translator
    assert translator.executor is None


def test_synchronous_translator_requires_explicit_unsafe_opt_in() -> None:
    with pytest.raises(ValueError, match="explicit unsafe opt-in"):
        load_translator("hashlib:sha256")

    translator = load_translator("hashlib:sha256", allow_synchronous=True)
    assert translator.executor is not None
    translator.executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_unsafe_synchronous_translator_does_not_block_async_timeout() -> None:
    translator = load_translator(
        "tests.test_backends:slow_synchronous_translator",
        allow_synchronous=True,
    )
    try:
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                translator.translate(VIDEO_BYTES, challenge_request()),
                timeout=0.001,
            )
    finally:
        assert translator.executor is not None
        translator.executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_async_callable_object_receives_verified_bytes_and_request() -> None:
    translator = load_translator("tests.test_backends:async_callable_translator")
    request = challenge_request()

    result = await translator.translate(VIDEO_BYTES, request)

    assert result == "model output"
    assert async_callable_translator.calls[-1] == (VIDEO_BYTES, request)
    assert translator.executor is None


@pytest.mark.asyncio
async def test_plugin_lifecycle_and_model_revision_are_bound() -> None:
    lifecycle_translator.events.clear()
    translator = load_translator(
        "tests.test_backends:lifecycle_translator",
        expected_model_revision=lifecycle_translator.model_revision,
    )

    await translator.startup()
    await translator.shutdown()

    assert translator.declared_model_revision == lifecycle_translator.model_revision
    assert lifecycle_translator.events == ["startup", "shutdown"]


@pytest.mark.parametrize(
    ("expected_revision", "message"),
    (
        (None, "must be bound"),
        ("cd" * 32, "does not match"),
    ),
)
def test_plugin_rejects_unbound_or_mismatched_declared_revision(
    expected_revision: str | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        load_translator(
            "tests.test_backends:lifecycle_translator",
            expected_model_revision=expected_revision,
        )


def test_plugin_rejects_synchronous_lifecycle_hook() -> None:
    with pytest.raises(ValueError, match="startup hook must be async"):
        load_translator("tests.test_backends:invalid_lifecycle_translator")


@pytest.mark.parametrize("value", (None, 1.5, True, "2"))
def test_translator_concurrency_requires_a_positive_integer(value: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        load_translator("tests.test_backends:async_translator", maximum_concurrency=value)


@pytest.mark.asyncio
async def test_unix_sidecar_boundary_sends_exact_video_and_canonical_request() -> None:
    request = challenge_request()
    revision = "ab" * 32

    async def model(video: bytes, metadata: CanonicalModelRequest) -> str:
        assert metadata.canonical_json == canonical_json_bytes(request)
        assert TranslationRequest.model_validate(metadata.document) == request
        assert video == VIDEO_BYTES
        return "hello from isolated model"

    with _private_socket_path() as path:
        server = await start_model_sidecar(
            path,
            model,
            model_revision=revision,
            scoring_policy_sha256=POLICY_HASH,
            validator_slot_count=4,
            maximum_concurrency=4,
        )
        async with server:
            translator = UnixSocketTranslator(
                socket_path=path,
                maximum_request_metadata_bytes=64 * 1024,
                maximum_response_bytes=128,
                expected_model_revision=revision,
                expected_scoring_policy_sha256=POLICY_HASH,
                required_validator_slots=4,
            )
            assert await translator.translate(VIDEO_BYTES, request) == "hello from isolated model"


@pytest.mark.asyncio
async def test_unix_sidecar_boundary_rejects_oversized_output() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            digest, revision, _metadata, _video = await _read_model_request(reader)
            writer.write(MODEL_RESPONSE_MAGIC + digest + revision + (5).to_bytes(4, "big"))
            await writer.drain()
        finally:
            writer.close()

    async with _model_worker(handler) as path:
        translator = UnixSocketTranslator(
            socket_path=path,
            maximum_request_metadata_bytes=64 * 1024,
            maximum_response_bytes=4,
        )
        with pytest.raises(ValueError, match="byte ceiling"):
            await translator.translate(VIDEO_BYTES, challenge_request())


@pytest.mark.asyncio
async def test_unix_sidecar_boundary_rejects_a_reply_for_another_request() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            _digest, revision, _metadata, _video = await _read_model_request(reader)
            _write_model_response(
                writer,
                digest=bytes.fromhex("ff" * 32),
                revision=revision,
                body=b"wrong answer binding",
            )
            await writer.drain()
        finally:
            writer.close()

    async with _model_worker(handler) as path:
        translator = UnixSocketTranslator(
            socket_path=path,
            maximum_request_metadata_bytes=64 * 1024,
            maximum_response_bytes=128,
        )
        with pytest.raises(ValueError, match="request binding"):
            await translator.translate(VIDEO_BYTES, challenge_request())


@pytest.mark.asyncio
async def test_unix_sidecar_boundary_rejects_wrong_model_revision() -> None:
    expected_revision = "ab" * 32

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            digest, _revision, _metadata, _video = await _read_model_request(reader)
            _write_model_response(
                writer,
                digest=digest,
                revision=bytes.fromhex("cd" * 32),
                body=b"wrong revision binding",
            )
            await writer.drain()
        finally:
            writer.close()

    async with _model_worker(handler) as path:
        translator = UnixSocketTranslator(
            socket_path=path,
            maximum_request_metadata_bytes=64 * 1024,
            maximum_response_bytes=128,
            expected_model_revision=expected_revision,
        )
        with pytest.raises(ValueError, match="revision binding"):
            await translator.translate(VIDEO_BYTES, challenge_request())


@pytest.mark.asyncio
async def test_unix_sidecar_call_is_cancellable_at_the_miner_timeout_boundary() -> None:
    release = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await _read_model_request(reader)
            await release.wait()
        finally:
            writer.close()

    async with _model_worker(handler) as path:
        translator = UnixSocketTranslator(
            socket_path=path,
            maximum_request_metadata_bytes=64 * 1024,
            maximum_response_bytes=128,
        )
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                translator.translate(VIDEO_BYTES, challenge_request()),
                timeout=0.01,
            )
        release.set()


@pytest.mark.asyncio
async def test_sidecar_cancels_model_work_when_miner_disconnects_and_releases_slot() -> None:
    first_started = asyncio.Event()
    first_cancelled = asyncio.Event()
    call_count = 0

    async def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            first_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                first_cancelled.set()
                raise
        return "second request completed"

    with _private_socket_path() as path:
        server = await start_model_sidecar(
            path,
            model,
            model_revision=None,
            maximum_inference_seconds=1,
        )
        async with server:
            translator = UnixSocketTranslator(
                socket_path=path,
                maximum_request_metadata_bytes=64 * 1024,
                maximum_response_bytes=128,
            )
            first = asyncio.create_task(translator.translate(VIDEO_BYTES, challenge_request()))
            await asyncio.wait_for(first_started.wait(), timeout=1)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            await asyncio.wait_for(first_cancelled.wait(), timeout=1)

            assert (
                await asyncio.wait_for(
                    translator.translate(VIDEO_BYTES, challenge_request(2)),
                    timeout=1,
                )
                == "second request completed"
            )


@pytest.mark.asyncio
async def test_sidecar_enforces_its_own_inference_deadline() -> None:
    first_cancelled = asyncio.Event()
    call_count = 0

    async def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                first_cancelled.set()
                raise
        return "second request completed"

    with _private_socket_path() as path:
        server = await start_model_sidecar(
            path,
            model,
            model_revision=None,
            maximum_inference_seconds=0.01,
        )
        async with server:
            translator = UnixSocketTranslator(
                socket_path=path,
                maximum_request_metadata_bytes=64 * 1024,
                maximum_response_bytes=128,
            )
            with pytest.raises(RuntimeError, match="truncated frame"):
                await asyncio.wait_for(
                    translator.translate(VIDEO_BYTES, challenge_request()),
                    timeout=1,
                )
            await asyncio.wait_for(first_cancelled.wait(), timeout=1)
            assert (
                await asyncio.wait_for(
                    translator.translate(VIDEO_BYTES, challenge_request(2)),
                    timeout=1,
                )
                == "second request completed"
            )


@pytest.mark.asyncio
async def test_model_sidecar_rejects_synchronous_callback() -> None:
    def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        return "unsafe"

    with (
        _private_socket_path() as path,
        pytest.raises(
            TypeError,
            match="async callable",
        ),
    ):
        await start_model_sidecar(path, model, model_revision=None)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets unavailable")
def test_unix_sidecar_requires_an_owner_private_socket() -> None:
    with _private_socket_path() as path:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(path)
            os.chmod(path, 0o666)
            with pytest.raises(RuntimeError, match="mode 0600"):
                UnixSocketTranslator(
                    socket_path=path,
                    maximum_request_metadata_bytes=64 * 1024,
                    maximum_response_bytes=128,
                )

            os.chmod(path, 0o600)
            translator = UnixSocketTranslator(
                socket_path=path,
                maximum_request_metadata_bytes=64 * 1024,
                maximum_response_bytes=128,
            )
            assert translator.socket_path == path
        finally:
            server.close()


@pytest.mark.asyncio
@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets unavailable")
async def test_model_sidecar_rejects_nonprivate_parent_directory() -> None:
    async def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        return "unused"

    with (
        _private_socket_path(parent_mode=0o755) as path,
        pytest.raises(RuntimeError, match=r"parent.*mode 0700"),
    ):
        await start_model_sidecar(path, model, model_revision=None)


@pytest.mark.asyncio
async def test_model_sidecar_rejects_oversized_request_before_payload_read() -> None:
    calls = 0

    async def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        nonlocal calls
        calls += 1
        return "unused"

    with _private_socket_path() as path:
        server = await start_model_sidecar(
            path,
            model,
            model_revision=None,
            maximum_request_metadata_bytes=4,
        )
        async with server:
            reader, writer = await asyncio.open_unix_connection(path)
            writer.write(
                MODEL_REQUEST_MAGIC + (5).to_bytes(4, "big") + (0).to_bytes(8, "big") + bytes(64)
            )
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), timeout=1) == b""
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()
    assert calls == 0


@pytest.mark.asyncio
async def test_model_sidecar_rejects_capacity_below_policy_validator_count() -> None:
    async def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        return "unused"

    with (
        _private_socket_path() as path,
        pytest.raises(
            ValueError,
            match="one slot per validator",
        ),
    ):
        await start_model_sidecar(
            path,
            model,
            model_revision=None,
            scoring_policy_sha256=POLICY_HASH,
            validator_slot_count=4,
            maximum_concurrency=3,
        )


@pytest.mark.asyncio
async def test_sidecar_keeps_one_runnable_model_slot_per_validator() -> None:
    started: asyncio.Queue[str] = asyncio.Queue()
    release = asyncio.Event()

    async def model(_video: bytes, metadata: CanonicalModelRequest) -> str:
        challenge_id = metadata.document["challenge_id"]
        assert isinstance(challenge_id, str)
        await started.put(challenge_id)
        await release.wait()
        return "model output"

    with _private_socket_path() as path:
        server = await start_model_sidecar(
            path,
            model,
            model_revision=None,
            scoring_policy_sha256=POLICY_HASH,
            validator_slot_count=4,
            maximum_concurrency=4,
        )
        async with server:
            translator = UnixSocketTranslator(
                socket_path=path,
                maximum_request_metadata_bytes=64 * 1024,
                maximum_response_bytes=128,
                expected_scoring_policy_sha256=POLICY_HASH,
                required_validator_slots=4,
            )
            requests = [challenge_request(index) for index in range(1, 5)]
            tasks = [
                asyncio.create_task(translator.translate(VIDEO_BYTES, request))
                for request in requests
            ]
            try:
                observed = {
                    await asyncio.wait_for(started.get(), timeout=1) for _request in requests
                }
                assert observed == {request.challenge_id for request in requests}
            finally:
                release.set()
                assert await asyncio.gather(*tasks) == ["model output"] * 4


@pytest.mark.asyncio
async def test_sidecar_capacity_descriptor_is_rechecked_before_each_request() -> None:
    async def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        return "model output"

    with _private_socket_path() as path:
        server = await start_model_sidecar(
            path,
            model,
            model_revision=None,
            scoring_policy_sha256=POLICY_HASH,
            validator_slot_count=4,
            maximum_concurrency=4,
        )
        async with server:
            translator = UnixSocketTranslator(
                socket_path=path,
                maximum_request_metadata_bytes=64 * 1024,
                maximum_response_bytes=128,
                expected_scoring_policy_sha256=POLICY_HASH,
                required_validator_slots=4,
            )
            descriptor_path = f"{path}.capacity.json"
            with open(descriptor_path, encoding="utf-8") as descriptor:
                document = json.load(descriptor)
            document["maximum_concurrency"] = 3
            with open(descriptor_path, "w", encoding="utf-8") as descriptor:
                json.dump(document, descriptor, sort_keys=True, separators=(",", ":"))
            os.chmod(descriptor_path, 0o600)

            with pytest.raises(RuntimeError, match="binding does not match"):
                await translator.translate(VIDEO_BYTES, challenge_request())


@pytest.mark.asyncio
async def test_sidecar_deadline_must_not_exceed_miner_deadline() -> None:
    async def model(_video: bytes, _metadata: CanonicalModelRequest) -> str:
        return "model output"

    with _private_socket_path() as path:
        server = await start_model_sidecar(
            path,
            model,
            model_revision=None,
            scoring_policy_sha256=POLICY_HASH,
            validator_slot_count=4,
            maximum_concurrency=4,
            maximum_inference_seconds=121,
        )
        async with server:
            with pytest.raises(RuntimeError, match="binding does not match"):
                UnixSocketTranslator(
                    socket_path=path,
                    maximum_request_metadata_bytes=64 * 1024,
                    maximum_response_bytes=128,
                    expected_scoring_policy_sha256=POLICY_HASH,
                    required_validator_slots=4,
                    maximum_inference_seconds=120,
                )


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets unavailable")
def test_unix_sidecar_rejects_a_symlink_to_a_private_socket() -> None:
    with _private_socket_path() as path:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        link = os.path.join(os.path.dirname(path), "model-link.sock")
        try:
            server.bind(path)
            os.chmod(path, 0o600)
            os.symlink(path, link)
            with pytest.raises(RuntimeError, match="Unix socket directly"):
                UnixSocketTranslator(
                    socket_path=link,
                    maximum_request_metadata_bytes=64 * 1024,
                    maximum_response_bytes=128,
                )
        finally:
            server.close()
            with suppress(FileNotFoundError):
                os.unlink(link)


@pytest.mark.asyncio
@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets unavailable")
async def test_unix_sidecar_rechecks_socket_mode_before_connect() -> None:
    with _private_socket_path() as path:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(path)
            os.chmod(path, 0o600)
            translator = UnixSocketTranslator(
                socket_path=path,
                maximum_request_metadata_bytes=64 * 1024,
                maximum_response_bytes=128,
            )
            os.chmod(path, 0o666)
            with pytest.raises(RuntimeError, match="mode 0600"):
                await translator.translate(VIDEO_BYTES, challenge_request())
        finally:
            server.close()


@pytest.mark.asyncio
@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets unavailable")
async def test_unix_sidecar_rechecks_socket_type_before_connect() -> None:
    with _private_socket_path() as path:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        os.chmod(path, 0o600)
        translator = UnixSocketTranslator(
            socket_path=path,
            maximum_request_metadata_bytes=64 * 1024,
            maximum_response_bytes=128,
        )
        server.close()
        os.unlink(path)
        os.mkdir(path, mode=0o700)
        try:
            with pytest.raises(RuntimeError, match="Unix socket directly"):
                await translator.translate(VIDEO_BYTES, challenge_request())
        finally:
            os.rmdir(path)


_ModelHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@asynccontextmanager
async def _model_worker(handler: _ModelHandler) -> AsyncIterator[str]:
    with _private_socket_path() as path:
        server = await asyncio.start_unix_server(handler, path=path)
        os.chmod(path, 0o600)
        try:
            yield path
        finally:
            server.close()
            await server.wait_closed()


@contextmanager
def _private_socket_path(*, parent_mode: int = 0o700):
    parent = tempfile.mkdtemp(prefix="umi-ms-")
    os.chmod(parent, parent_mode)
    path = os.path.join(parent, "model.sock")
    try:
        yield path
    finally:
        with suppress(FileNotFoundError):
            metadata = os.lstat(path)
            if stat.S_ISDIR(metadata.st_mode):
                os.rmdir(path)
            else:
                os.unlink(path)
        os.chmod(parent, 0o700)
        os.rmdir(parent)


async def _read_model_request(
    reader: asyncio.StreamReader,
) -> tuple[bytes, bytes, bytes, bytes]:
    prefix_size = len(MODEL_REQUEST_MAGIC) + 4 + 8 + 32 + 32
    prefix = await reader.readexactly(prefix_size)
    assert prefix.startswith(MODEL_REQUEST_MAGIC)
    offset = len(MODEL_REQUEST_MAGIC)
    metadata_size = int.from_bytes(prefix[offset : offset + 4], "big")
    offset += 4
    video_size = int.from_bytes(prefix[offset : offset + 8], "big")
    offset += 8
    digest = prefix[offset : offset + 32]
    offset += 32
    revision = prefix[offset : offset + 32]
    metadata = await reader.readexactly(metadata_size)
    video = await reader.readexactly(video_size)
    return digest, revision, metadata, video


def _write_model_response(
    writer: asyncio.StreamWriter,
    *,
    digest: bytes,
    revision: bytes,
    body: bytes,
) -> None:
    writer.write(MODEL_RESPONSE_MAGIC + digest + revision + len(body).to_bytes(4, "big") + body)
