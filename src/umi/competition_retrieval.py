"""Bounded retrieval of signed competition model bundles.

The HTTPS source is an untrusted location hint on the standard port.  A model
submission signature binds the manifest, and the manifest binds every accepted
byte.  Retrieved files are staged privately and remain data; this module never
imports, unpacks or executes them.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import math
import os
import shutil
import stat
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.parse import quote, urlsplit

import httpx

from .competition_artifacts import (
    preserve_bundle,
    verify_bundle_directory,
    verify_preserved_bundle,
)
from .competition_policy_lineage import submission_policy_admitted
from .open_competition import (
    BundleFile,
    CompetitionPolicy,
    ModelBundle,
    SignedSubmission,
    digest,
    validate_bundle_policy,
)
from .protocol import canonical_json_bytes
from .validator_supervisor_adapters import (
    PinnedHTTPSClient,
    ValidatorSupervisorAdapterError,
)

_MAX_MANIFEST_FILES = 4096
_MAX_MANIFEST_BYTES = 1024**4
_MAX_REQUEST_TIMEOUT_SECONDS = 300.0
_MAX_TOTAL_DOWNLOAD_SECONDS = 24 * 60 * 60.0
_MAX_SOURCE_BASE_BYTES = 2048


class CompetitionRetrievalError(RuntimeError):
    """Stable, non-sensitive failure while retrieving a model bundle."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ArtifactRetrievalLimits:
    """Explicit operational ceilings; these values are not competition policy."""

    maximum_files: int
    maximum_file_bytes: int
    maximum_total_bytes: int
    request_timeout_seconds: float
    total_download_timeout_seconds: float

    def __post_init__(self) -> None:
        _integer_bound(self.maximum_files, "maximum files", maximum=_MAX_MANIFEST_FILES)
        _integer_bound(
            self.maximum_file_bytes,
            "maximum file bytes",
            maximum=_MAX_MANIFEST_BYTES,
        )
        _integer_bound(
            self.maximum_total_bytes,
            "maximum total bytes",
            maximum=_MAX_MANIFEST_BYTES,
        )
        if self.maximum_file_bytes > self.maximum_total_bytes:
            raise ValueError("maximum file bytes cannot exceed maximum total bytes")
        _timeout_bound(
            self.request_timeout_seconds,
            "request timeout",
            maximum=_MAX_REQUEST_TIMEOUT_SECONDS,
        )
        _timeout_bound(
            self.total_download_timeout_seconds,
            "total download timeout",
            maximum=_MAX_TOTAL_DOWNLOAD_SECONDS,
        )


ChunkConsumer = Callable[[bytes], Awaitable[None]]


class ArtifactStreamTransport(Protocol):
    """Stream one object; the retrieval layer still verifies all bytes."""

    async def stream_file(
        self,
        url: str,
        *,
        maximum_bytes: int,
        expected_size_bytes: int,
        consume: ChunkConsumer,
    ) -> None: ...


class PinnedHTTPSArtifactTransport:
    """Production HTTPS adapter backed by the repository's pinned-IP client."""

    def __init__(
        self,
        *,
        timeout_seconds: float,
        resolver: Callable[[str, int], Awaitable[Sequence[str]]] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = PinnedHTTPSClient(
            timeout_seconds=timeout_seconds,
            resolver=resolver,
            transport=transport,
        )

    async def stream_file(
        self,
        url: str,
        *,
        maximum_bytes: int,
        expected_size_bytes: int,
        consume: ChunkConsumer,
    ) -> None:
        try:
            # The shared client resolves every request, rejects any non-public
            # answer, connects to one validated IP, preserves TLS SNI/Host, and
            # disables redirects and proxy environment configuration.
            await self._client._fetch(
                url,
                maximum_bytes=maximum_bytes,
                expected_size_bytes=expected_size_bytes,
                consume=consume,
            )
        except ValidatorSupervisorAdapterError as error:
            raise CompetitionRetrievalError(f"artifact_{error.reason_code}") from error


async def retrieve_signed_model_bundle(
    signed: SignedSubmission,
    *,
    source_base_url: str,
    archive: Path,
    policy: CompetitionPolicy,
    limits: ArtifactRetrievalLimits,
    transport: ArtifactStreamTransport | None = None,
) -> Path:
    """Retrieve, verify and atomically preserve one signed model submission.

    ``source_base_url`` is not signed evidence.  It only locates objects whose
    exact sizes and SHA-256 digests are authenticated by ``signed``.
    """

    try:
        signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
        policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    except Exception as error:
        raise CompetitionRetrievalError("artifact_submission_invalid") from error
    submission = signed.submission
    bundle = submission.model_bundle
    if submission.track != "model" or bundle is None:
        raise CompetitionRetrievalError("artifact_submission_not_model")
    if not submission_policy_admitted(policy, submission.policy_sha256):
        raise CompetitionRetrievalError("artifact_policy_mismatch")
    if submission.accepted_terms_sha256 != policy.contribution_terms_sha256:
        raise CompetitionRetrievalError("artifact_terms_mismatch")
    if (
        submission.valid_from_block < policy.valid_from_block
        or submission.valid_through_block > policy.valid_through_block
        or submission.valid_through_block - submission.valid_from_block
        > policy.maximum_submission_lifetime_blocks
    ):
        raise CompetitionRetrievalError("artifact_submission_lifetime_invalid")
    try:
        validate_bundle_policy(bundle, policy)
    except ValueError as error:
        raise CompetitionRetrievalError("artifact_policy_limit") from error

    source_base_url = _canonical_source_base(source_base_url)
    _validate_operational_limits(bundle, limits)
    file_urls = tuple(_artifact_url(source_base_url, record.path) for record in bundle.files)
    _prepare_private_archive(archive)

    final = archive / digest(bundle)
    if final.exists() or final.is_symlink():
        try:
            verify_preserved_bundle(bundle, archive, policy)
        except (OSError, ValueError) as error:
            raise CompetitionRetrievalError("artifact_existing_archive_invalid") from error
        return final

    selected_transport = transport or PinnedHTTPSArtifactTransport(
        timeout_seconds=limits.request_timeout_seconds
    )
    stage = Path(tempfile.mkdtemp(prefix=".retrieval-", dir=archive))
    try:
        stage.chmod(0o700)
        model_root = stage / "model"
        model_root.mkdir(mode=0o700)
        aggregate = [0]

        async def download_all() -> None:
            for record, file_url in zip(bundle.files, file_urls, strict=True):
                await _retrieve_file(
                    record,
                    file_url=file_url,
                    model_root=model_root,
                    limits=limits,
                    aggregate=aggregate,
                    transport=selected_transport,
                )

        try:
            await asyncio.wait_for(
                download_all(),
                timeout=limits.total_download_timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise CompetitionRetrievalError("artifact_total_timeout") from error

        if aggregate[0] != sum(record.size_bytes for record in bundle.files):
            raise CompetitionRetrievalError("artifact_total_size_mismatch")
        try:
            verify_bundle_directory(bundle, model_root, policy)
            return preserve_bundle(bundle, model_root, archive, policy)
        except (OSError, ValueError) as error:
            raise CompetitionRetrievalError("artifact_archive_verification_failed") from error
    finally:
        if stage.exists():
            # This is the exact private directory allocated above.  Published
            # content-addressed archive directories are never removed here.
            shutil.rmtree(stage)


async def _retrieve_file(
    record: BundleFile,
    *,
    file_url: str,
    model_root: Path,
    limits: ArtifactRetrievalLimits,
    aggregate: list[int],
    transport: ArtifactStreamTransport,
) -> None:
    target = model_root / record.path
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for parent in (target.parent, *target.parent.parents):
        if parent == model_root.parent:
            break
        with contextlib.suppress(OSError):
            parent.chmod(0o700)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    hasher = hashlib.sha256()
    file_total = 0

    async def consume(chunk: bytes) -> None:
        nonlocal file_total
        if not isinstance(chunk, bytes):
            raise CompetitionRetrievalError("artifact_chunk_invalid")
        if not chunk:
            return
        file_total += len(chunk)
        aggregate[0] += len(chunk)
        if aggregate[0] > limits.maximum_total_bytes:
            raise CompetitionRetrievalError("artifact_total_body_limit")
        if file_total > record.size_bytes or file_total > limits.maximum_file_bytes:
            raise CompetitionRetrievalError("artifact_file_body_limit")
        hasher.update(chunk)
        try:
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
        except OSError as error:
            raise CompetitionRetrievalError("artifact_write_failed") from error

    try:
        descriptor = os.open(target, flags, 0o600)
        await transport.stream_file(
            file_url,
            maximum_bytes=max(1, min(record.size_bytes, limits.maximum_file_bytes)),
            expected_size_bytes=record.size_bytes,
            consume=consume,
        )
        if file_total != record.size_bytes:
            raise CompetitionRetrievalError("artifact_file_size_mismatch")
        if hasher.hexdigest() != record.sha256:
            raise CompetitionRetrievalError("artifact_file_sha256_mismatch")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    except BaseException:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            descriptor = -1
        with contextlib.suppress(OSError):
            target.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_source_base(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value
        or len(value.encode("ascii")) > _MAX_SOURCE_BASE_BYTES
    ):
        raise CompetitionRetrievalError("artifact_source_url_invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise CompetitionRetrievalError("artifact_source_url_invalid") from error
    hostname = parsed.hostname
    path = parsed.path
    if hostname is None:
        raise CompetitionRetrievalError("artifact_source_url_invalid")
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    expected_authority = authority_host if port is None else f"{authority_host}:443"
    canonical_path = "" if not path else PurePosixPath(path).as_posix()
    reconstructed = f"https://{expected_authority}{path}"
    if (
        parsed.scheme != "https"
        or hostname != hostname.lower()
        or hostname.endswith(".")
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.netloc != expected_authority
        or parsed.query
        or parsed.fragment
        or value != reconstructed
        or (path and not path.startswith("/"))
        or path == "/"
        or path.endswith("/")
        or "%" in path
        or "\\" in path
        or "//" in path
        or canonical_path != path
        or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts[1:])
    ):
        raise CompetitionRetrievalError("artifact_source_url_invalid")
    return value


def _artifact_url(source_base_url: str, relative_path: str) -> str:
    suffix = quote(relative_path, safe="/-._~")
    url = f"{source_base_url}/{suffix}"
    if len(url.encode("ascii")) > _MAX_SOURCE_BASE_BYTES:
        raise CompetitionRetrievalError("artifact_source_url_invalid")
    return url


def _prepare_private_archive(archive: Path) -> None:
    if not isinstance(archive, Path) or not archive.is_absolute():
        raise ValueError("archive must be an absolute Path")
    if archive.is_symlink():
        raise CompetitionRetrievalError("artifact_archive_unsafe")
    try:
        archive.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = archive.stat()
    except OSError as error:
        raise CompetitionRetrievalError("artifact_archive_unavailable") from error
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise CompetitionRetrievalError("artifact_archive_permissions_unsafe")


def _validate_operational_limits(
    bundle: ModelBundle,
    limits: ArtifactRetrievalLimits,
) -> None:
    total = sum(record.size_bytes for record in bundle.files)
    if len(bundle.files) > limits.maximum_files:
        raise CompetitionRetrievalError("artifact_file_count_limit")
    if any(record.size_bytes > limits.maximum_file_bytes for record in bundle.files):
        raise CompetitionRetrievalError("artifact_file_size_limit")
    if total > limits.maximum_total_bytes:
        raise CompetitionRetrievalError("artifact_total_size_limit")


def _integer_bound(value: int, label: str, *, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise ValueError(f"{label} must be an integer in [1, {maximum}]")


def _timeout_bound(value: float, label: str, *, maximum: float) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= maximum
    ):
        raise ValueError(f"{label} must be finite and in (0, {maximum}]")


__all__ = [
    "ArtifactRetrievalLimits",
    "ArtifactStreamTransport",
    "CompetitionRetrievalError",
    "PinnedHTTPSArtifactTransport",
    "retrieve_signed_model_bundle",
]
