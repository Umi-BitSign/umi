"""Bounded production adapters for the install-once validator supervisor.

The directive channel can select only typed modes and immutable release identities.
It cannot provide process arguments, environment names, container names, mount
destinations, or local paths.  This module translates an authenticated activation
into one fixed rootless-Podman profile.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import socket
import stat
import struct
import tempfile
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import quote, urlsplit

import httpx
from pydantic import Field, model_validator
from typing_extensions import Self

from .bootstrap_direct_weights import (
    DirectBootstrapOperationalPreflight,
    DirectBootstrapTransitionAuthorization,
    OwnerFenceReceipt,
)
from .bootstrap_weights import SignedBootstrapEligibilityManifest
from .crypto import verify_response_signature
from .encoding import account_id32
from .grandpa_finality import (
    FINNEY_BOOTSTRAP_BLOCK_HASH,
    FINNEY_BOOTSTRAP_BLOCK_NUMBER,
    FINNEY_CHAIN_SPEC_SHA256,
    FINNEY_GENESIS_HASH,
    GrandpaFinalityObserver,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .simple_bootstrap_validator import (
    SignedSimpleBootstrapLease,
    verify_simple_bootstrap_lease,
)
from .validator_supervisor import (
    COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
    COMMON_SUPERVISOR_CHANNELS,
    COMMON_SUPERVISOR_RELEASE_ORIGIN,
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
    SupervisorEntrypointProfile,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    ValidatorSupervisorConfig,
)
from .validator_supervisor_runtime import SupervisorWorkerActivation

SUPERVISOR_RELEASE_MANIFEST_SCHEMA = "umi-validator-supervisor-release-manifest/1"
SUPERVISOR_RELEASE_BUNDLE_MAGIC = b"UMI-VALIDATOR-OCI-BUNDLE-V1\0"
SUPERVISOR_RELEASE_SIGNATURE_DOMAIN = b"umi-validator-supervisor-release-manifest-v1\0"
SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA = "umi-validator-supervisor-bootstrap-input-bundle/1"
SUPERVISOR_BOOTSTRAP_INPUT_PROFILE = "umi-bootstrap-direct-inputs/2"
SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_BUNDLE_SCHEMA = (
    "umi-validator-supervisor-simple-bootstrap-input-bundle/1"
)
SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE = "umi-simple-bootstrap-common-inputs/1"
SUPERVISOR_HOST_ARTIFACT_MANIFEST_SCHEMA = "umi-validator-supervisor-host-artifacts/1"
SUPERVISOR_SIGNED_HOST_ARTIFACT_MANIFEST_SCHEMA = "umi-validator-supervisor-signed-host-artifacts/1"
SUPERVISOR_HOST_ARTIFACT_SIGNATURE_DOMAIN = b"umi-validator-supervisor-host-artifacts-v1\0"

MAX_HTTPS_HEADER_BYTES = 64 * 1024
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
DEFAULT_NETWORK_TIMEOUT_SECONDS = 30.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300.0
DEFAULT_STOP_TIMEOUT_SECONDS = 30.0
DEFAULT_START_GRACE_SECONDS = 1.0
MAX_FINALIZED_HEAD_AGE_SECONDS = 30.0
MAX_FINALIZED_FUTURE_SKEW_SECONDS = 30.0

WORKER_CONTAINER_NAME = "umi-validator-supervised-worker"
WORKER_ENTRYPOINT = "/usr/local/bin/umi-validator-supervisor-worker"
SIMPLE_BOOTSTRAP_WORKER_ENTRYPOINT = "/usr/local/bin/umi-simple-bootstrap-validator"
WORKER_RELEASE_MANIFEST_PATH = "/run/umi/release/release-manifest.json"
WORKER_OPERATOR_INPUT_PATH = "/run/umi/operator-inputs"
WORKER_WALLET_PATH = "/run/umi/wallets"
WORKER_WALLET_NAME = "runtime"
WORKER_STATE_PATH = "/var/lib/umi-worker"
BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL = Path(
    "/var/lib/umi-validator-bootstrap-upload/bootstrap-result-upload.key"
)
WORKER_BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL_PATH = "/run/umi/credentials/bootstrap-result-upload.key"

_MODE_ARGUMENT = {
    "inactive_shadow": "run-inactive-shadow",
    "bootstrap_service_weights": "run-bootstrap-service-weights",
    "translation_weights": "run-translation-weights",
}
_TARGET_ARCHITECTURE = {"linux/amd64": "amd64", "linux/arm64": "arm64"}
_HOST_ARCHITECTURE = {
    "x86_64": "linux/amd64",
    "amd64": "linux/amd64",
    "aarch64": "linux/arm64",
    "arm64": "linux/arm64",
}
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")


class ValidatorSupervisorAdapterError(RuntimeError):
    """Stable, non-sensitive failure from a production adapter."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class OwnedFinalizedBlock:
    """Exact block identity accepted by the owned GRANDPA verifier."""

    number: int
    block_hash: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.number, bool)
            or not isinstance(self.number, int)
            or not 1 <= self.number <= (1 << 53) - 1
            or not isinstance(self.block_hash, str)
            or _BLOCK_HASH_RE.fullmatch(self.block_hash) is None
        ):
            raise ValueError("owned finalized block identity is invalid")


class SupervisorReleaseManifest(StrictProtocolModel):
    """Signed description of the one OCI archive inside a release bundle."""

    schema_: Literal[SUPERVISOR_RELEASE_MANIFEST_SCHEMA] = Field(alias="schema")
    oci_repository: Annotated[str, Field(min_length=1, max_length=512)]
    oci_manifest_sha256: Hex32
    oci_archive_sha256: Hex32
    oci_archive_size_bytes: Annotated[int, Field(gt=0, le=1024 * 1024 * 1024)]
    target_platform: Literal["linux/amd64", "linux/arm64"]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    umi_source_tree_sha256: Hex32
    entrypoint_profile: SupervisorEntrypointProfile
    state_schema_minimum: Annotated[int, Field(ge=1, le=(1 << 53) - 1)]
    state_schema_maximum: Annotated[int, Field(ge=1, le=(1 << 53) - 1)]

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if self.state_schema_maximum < self.state_schema_minimum:
            raise ValueError("release state schema range is inverted")
        return self


class SupervisorBootstrapInputBundle(StrictProtocolModel):
    """Canonical bootstrap inputs staged together under one directive-bound hash."""

    schema_: Literal[SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA] = Field(alias="schema")
    profile: Literal[SUPERVISOR_BOOTSTRAP_INPUT_PROFILE]
    signed_manifest: SignedBootstrapEligibilityManifest
    transition_authorization: DirectBootstrapTransitionAuthorization
    drain_checkpoint: DirectBootstrapOperationalPreflight
    owner_fence_receipt: OwnerFenceReceipt

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        signed = self.signed_manifest
        authorization = self.transition_authorization
        if authorization.manifest_sha256 != signed.manifest_sha256:
            raise ValueError("bootstrap input authorization binds another manifest")
        if authorization.original_policy_sha256 != signed.manifest.policy_sha256:
            raise ValueError("bootstrap input authorization binds another policy")
        if self.drain_checkpoint.signed_manifest != signed:
            raise ValueError("bootstrap drain checkpoint binds another signed manifest")
        fence = self.owner_fence_receipt
        fence_preflight = fence.call_material.preflight
        if (
            fence_preflight.network != "finney"
            or fence_preflight.netuid != 78
            or fence.observed_weights_version_key != authorization.weights_version_key
            or fence.observed_min_allowed_weights != authorization.required_min_allowed_weights
            or fence.observed_commit_reveal_enabled != authorization.required_commit_reveal_enabled
        ):
            raise ValueError("bootstrap owner-fence receipt has the wrong target tuple")
        if (
            fence_preflight.subnet_owner_hotkey_account_id32
            != self.drain_checkpoint.chain.subnet_owner_hotkey_account_id32
        ):
            raise ValueError("bootstrap owner-fence receipt binds another subnet owner")
        return self


class SupervisorSimpleBootstrapInputBundle(StrictProtocolModel):
    """Common manifest and lease used by every permitted bootstrap validator."""

    schema_: Literal[SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_BUNDLE_SCHEMA] = Field(alias="schema")
    profile: Literal[SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE]
    signed_manifest: SignedBootstrapEligibilityManifest
    signed_lease: SignedSimpleBootstrapLease

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        verify_simple_bootstrap_lease(
            self.signed_lease,
            signed_manifest=self.signed_manifest,
            expected_revision=self.signed_lease.body.umi_git_revision,
            current_block=self.signed_lease.body.valid_from_block,
        )
        return self


class SupervisorHostArtifact(StrictProtocolModel):
    """One immutable host-side file needed before the first directive fetch."""

    url: Annotated[str, Field(min_length=1, max_length=2_048)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=256 * 1024 * 1024)]

    @model_validator(mode="after")
    def validate_url(self) -> Self:
        target = _canonical_https_url(self.url)
        parts = urlsplit(target)
        if f"https://{parts.netloc}" != COMMON_SUPERVISOR_RELEASE_ORIGIN:
            raise ValueError("host artifact uses an untrusted origin")
        return self


class SupervisorHostArtifactManifest(StrictProtocolModel):
    """Platform-specific host bootstrap selected by a fixed common channel."""

    schema_: Literal[SUPERVISOR_HOST_ARTIFACT_MANIFEST_SCHEMA] = Field(alias="schema")
    channel_id: Hex32
    authority_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    target_platform: Literal["linux/amd64", "linux/arm64"]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    uv: SupervisorHostArtifact
    finality_verifier: SupervisorHostArtifact
    finney_chain_spec: SupervisorHostArtifact

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        account_id32(self.authority_hotkey)
        if self.authority_hotkey != COMMON_SUPERVISOR_AUTHORITY_HOTKEY:
            raise ValueError("host artifact authority is not the common UMI authority")
        if self.channel_id != COMMON_SUPERVISOR_CHANNELS[self.target_platform]:
            raise ValueError("host artifact channel does not match its platform")
        return self


class SignedSupervisorHostArtifactManifest(StrictProtocolModel):
    """Coordinator signature over one host-artifact manifest."""

    schema_: Literal[SUPERVISOR_SIGNED_HOST_ARTIFACT_MANIFEST_SCHEMA] = Field(alias="schema")
    manifest: SupervisorHostArtifactManifest
    manifest_sha256: Hex32
    manifest_digest: Hex32
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        payload = canonical_json_bytes(self.manifest)
        digest = hashlib.sha256(SUPERVISOR_HOST_ARTIFACT_SIGNATURE_DOMAIN + payload).digest()
        if self.signature_scheme != "sr25519":
            raise ValueError("host artifact manifest signature scheme is invalid")
        if not hmac.compare_digest(self.manifest_sha256, hashlib.sha256(payload).hexdigest()):
            raise ValueError("host artifact manifest hash is invalid")
        if not hmac.compare_digest(self.manifest_digest, digest.hex()):
            raise ValueError("host artifact manifest digest is invalid")
        if not verify_response_signature(
            digest,
            hotkey_ss58=self.manifest.authority_hotkey,
            scheme=self.signature_scheme,
            signature=self.signature,
        ):
            raise ValueError("host artifact manifest signature is invalid")
        return self


@dataclass(frozen=True, slots=True)
class StagedSupervisorRelease:
    """Verified immutable local release selected by one activation."""

    root: Path
    manifest_path: Path
    archive_path: Path
    image_reference: str
    manifest: SupervisorReleaseManifest
    operator_input_root: Path | None = None


class AddressResolver(Protocol):
    async def __call__(self, hostname: str, port: int) -> Sequence[str]: ...


@dataclass(frozen=True, slots=True)
class _HTTPSession:
    client: httpx.AsyncClient
    request_origin: str
    host_header: str | None
    sni_hostname: str | None


class PinnedHTTPSClient:
    """Resolve once, reject non-public addresses, pin one IP, and never redirect."""

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_NETWORK_TIMEOUT_SECONDS,
        resolver: AddressResolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 300
        ):
            raise ValueError("HTTPS timeout must be finite and in (0, 300]")
        self.timeout_seconds = float(timeout_seconds)
        self.resolver = resolver or _system_resolver
        self.transport = transport

    async def fetch_bytes(self, url: str, *, maximum_bytes: int) -> bytes:
        """Fetch one exact HTTPS object into bounded memory."""

        target = _canonical_https_url(url)
        output = bytearray()

        async def consume(chunk: bytes) -> None:
            output.extend(chunk)

        await self._fetch(target, maximum_bytes=maximum_bytes, consume=consume)
        return bytes(output)

    async def download_file(
        self,
        url: str,
        *,
        destination: Path,
        maximum_bytes: int,
        expected_size_bytes: int,
        expected_sha256: str,
    ) -> None:
        """Download an exact object to a new private file and verify it while streaming."""

        if not isinstance(destination, Path) or not destination.is_absolute():
            raise ValueError("download destination must be an absolute Path")
        _positive_bound(maximum_bytes, "download maximum bytes")
        _positive_bound(expected_size_bytes, "download expected size")
        if expected_size_bytes > maximum_bytes or _HEX32_RE.fullmatch(expected_sha256) is None:
            raise ValueError("download expectation is invalid")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(destination, flags, 0o600)
        except OSError as error:
            raise ValidatorSupervisorAdapterError("release_destination_unsafe") from error
        digest = hashlib.sha256()
        total = 0

        async def consume(chunk: bytes) -> None:
            nonlocal total
            total += len(chunk)
            digest.update(chunk)
            try:
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short write")
                    view = view[written:]
            except OSError as error:
                raise ValidatorSupervisorAdapterError("release_write_failed") from error

        try:
            await self._fetch(
                _canonical_https_url(url),
                maximum_bytes=maximum_bytes,
                expected_size_bytes=expected_size_bytes,
                consume=consume,
            )
            if total != expected_size_bytes:
                raise ValidatorSupervisorAdapterError("release_size_mismatch")
            if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
                raise ValidatorSupervisorAdapterError("release_sha256_mismatch")
            os.fsync(descriptor)
        except Exception:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            with contextlib.suppress(OSError):
                destination.unlink()
            raise
        os.close(descriptor)

    async def _fetch(
        self,
        target: str,
        *,
        maximum_bytes: int,
        consume: Callable[[bytes], Awaitable[None]],
        expected_size_bytes: int | None = None,
    ) -> None:
        _positive_bound(maximum_bytes, "HTTPS maximum bytes")
        parsed = urlsplit(target)
        async with self._session(parsed) as session:
            host_path = parsed.path
            request_url = f"{session.request_origin}{quote(host_path, safe='/%-._~')}"
            headers = {
                "Accept": "application/octet-stream, application/json",
                "Accept-Encoding": "identity",
                "Cache-Control": "no-cache, no-store",
            }
            if session.host_header is not None:
                headers["Host"] = session.host_header
            try:
                await asyncio.wait_for(
                    self._stream_response(
                        session,
                        request_url=request_url,
                        headers=headers,
                        maximum_bytes=maximum_bytes,
                        expected_size_bytes=expected_size_bytes,
                        consume=consume,
                    ),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError as error:
                raise ValidatorSupervisorAdapterError("https_timeout") from error
            except ValidatorSupervisorAdapterError:
                raise
            except httpx.HTTPError as error:
                raise ValidatorSupervisorAdapterError("https_transport_failed") from error

    async def _stream_response(
        self,
        session: _HTTPSession,
        *,
        request_url: str,
        headers: dict[str, str],
        maximum_bytes: int,
        expected_size_bytes: int | None,
        consume: Callable[[bytes], Awaitable[None]],
    ) -> None:
        async with session.client.stream(
            "GET",
            request_url,
            headers=headers,
            extensions=(
                {} if session.sni_hostname is None else {"sni_hostname": session.sni_hostname}
            ),
        ) as response:
            if _header_size(response.headers) > MAX_HTTPS_HEADER_BYTES:
                raise ValidatorSupervisorAdapterError("https_header_limit")
            if response.status_code == 404:
                raise ValidatorSupervisorAdapterError("https_not_found")
            if response.status_code != 200:
                raise ValidatorSupervisorAdapterError("https_status_invalid")
            if response.headers.get("content-encoding", "").lower() not in {"", "identity"}:
                raise ValidatorSupervisorAdapterError("https_content_encoding")
            declared = _content_length(response.headers.get("content-length"))
            if declared is not None:
                if declared > maximum_bytes:
                    raise ValidatorSupervisorAdapterError("https_body_limit")
                if expected_size_bytes is not None and declared != expected_size_bytes:
                    raise ValidatorSupervisorAdapterError("release_size_mismatch")
            total = 0
            async for chunk in response.aiter_raw():
                total += len(chunk)
                if total > maximum_bytes:
                    raise ValidatorSupervisorAdapterError("https_body_limit")
                await consume(chunk)
            if declared is not None and total != declared:
                raise ValidatorSupervisorAdapterError("https_partial_body")

    @contextlib.asynccontextmanager
    async def _session(self, parsed: Any) -> AsyncIterator[_HTTPSession]:
        hostname = parsed.hostname
        if not isinstance(hostname, str):
            raise ValidatorSupervisorAdapterError("https_url_invalid")
        in_process = isinstance(self.transport, (httpx.MockTransport, httpx.ASGITransport))
        if in_process:
            request_origin = "https://" + hostname
            host_header = None
            sni_hostname = None
        else:
            try:
                answers = await asyncio.wait_for(
                    self.resolver(hostname, 443), timeout=self.timeout_seconds
                )
            except Exception as error:
                raise ValidatorSupervisorAdapterError("https_dns_failed") from error
            addresses: list[str] = []
            for raw in answers:
                try:
                    address = ipaddress.ip_address(raw)
                except ValueError as error:
                    raise ValidatorSupervisorAdapterError("https_dns_answer_invalid") from error
                if not address.is_global:
                    raise ValidatorSupervisorAdapterError("https_dns_address_not_global")
                addresses.append(address.compressed)
            if not addresses:
                raise ValidatorSupervisorAdapterError("https_dns_empty")
            selected = sorted(set(addresses))[0]
            address_host = f"[{selected}]" if ":" in selected else selected
            request_origin = f"https://{address_host}:443"
            host_header = hostname
            sni_hostname = hostname
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
        ) as client:
            yield _HTTPSession(client, request_origin, host_header, sni_hostname)


class HTTPSDirectiveFetcher:
    """Fetch cursor-bound pages beneath one exact locally configured HTTPS base."""

    def __init__(
        self, config: ValidatorSupervisorConfig, *, client: PinnedHTTPSClient | None = None
    ):
        self._url = _canonical_https_url(config.directive_url)
        self._client = client or PinnedHTTPSClient()

    async def fetch_directive_page(
        self,
        *,
        after_sequence: int,
        after_directive_sha256: str | None,
    ) -> bytes | None:
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or not 0 <= after_sequence <= (1 << 53) - 1
            or (after_sequence == 0) != (after_directive_sha256 is None)
            or (
                after_directive_sha256 is not None
                and _HEX32_RE.fullmatch(after_directive_sha256) is None
            )
        ):
            raise ValidatorSupervisorAdapterError("directive_cursor_invalid")
        digest = "initial" if after_directive_sha256 is None else after_directive_sha256
        page_url = f"{self._url}/after/{after_sequence}/{digest}.json"
        try:
            return await self._client.fetch_bytes(
                page_url, maximum_bytes=MAX_SUPERVISOR_DOCUMENT_BYTES
            )
        except ValidatorSupervisorAdapterError as error:
            if error.reason_code == "https_not_found":
                return None
            raise


class FinneyFinalizedBlockReader:
    """Read fresh Finney finality from the hash-pinned owned smoldot verifier."""

    def __init__(
        self,
        config: ValidatorSupervisorConfig,
        *,
        timeout_seconds: float = 30.0,
        observer: GrandpaFinalityObserver | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= MAX_FINALIZED_HEAD_AGE_SECONDS
        ):
            raise ValueError("finalized-head timeout exceeds the freshness bound")
        self.timeout_seconds = float(timeout_seconds)
        self.observer = observer or GrandpaFinalityObserver(
            binary_path=config.finality_verifier_binary,
            expected_binary_sha256=config.finality_verifier_sha256,
            chain_spec_path=config.finality_chain_spec_path,
            expected_chain_spec_sha256=FINNEY_CHAIN_SPEC_SHA256,
            expected_genesis_hash=f"0x{FINNEY_GENESIS_HASH}",
            bootstrap_block_number=FINNEY_BOOTSTRAP_BLOCK_NUMBER,
            bootstrap_block_hash=f"0x{FINNEY_BOOTSTRAP_BLOCK_HASH}",
            record_timeout_seconds=self.timeout_seconds,
        )
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._head: Any | None = None
        self._accepted_at: datetime | None = None
        self._observer_error: Exception | None = None
        self._stop_requested = threading.Event()
        self._head_available = asyncio.Event()
        self._start_lock = asyncio.Lock()
        self._observer_task: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._last_returned_height = FINNEY_BOOTSTRAP_BLOCK_NUMBER

    async def start(self) -> None:
        """Start one long-lived owned finality stream once per supervisor process."""

        async with self._start_lock:
            if self._observer_task is not None and not self._observer_task.done():
                return
            self._stop_requested.clear()
            self._loop = asyncio.get_running_loop()
            self._observer_error = None
            self._observer_task = asyncio.create_task(
                asyncio.to_thread(self._observe_forever),
                name="umi-supervisor-finney-finality",
            )

    async def stop(self) -> None:
        """Stop the smoldot stream and wait for its bounded shutdown."""

        self._stop_requested.set()
        task, self._observer_task = self._observer_task, None
        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=self.timeout_seconds + 5)
            except asyncio.TimeoutError as error:
                raise ValidatorSupervisorAdapterError("finality_stop_timeout") from error
        self._loop = None

    async def read_finalized_block(self) -> int:
        """Return one new owned finalized height for the supervisor runtime."""

        return (await self.read_finalized_identity()).number

    async def read_finalized_identity(self) -> OwnedFinalizedBlock:
        """Return one new owned finalized height and its exact block hash."""

        await self.start()
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.timeout_seconds
            while self._head is None or self._head.block.number <= self._last_returned_height:
                if self._observer_error is not None:
                    raise ValidatorSupervisorAdapterError("finality_observer_failed")
                self._head_available.clear()
                if self._head is not None and self._head.block.number > self._last_returned_height:
                    continue
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise ValidatorSupervisorAdapterError("finalized_block_timeout")
                await asyncio.wait_for(self._head_available.wait(), timeout=remaining)
            if self._observer_error is not None:
                raise ValidatorSupervisorAdapterError("finality_observer_failed")
            attestation = self._head
            accepted_at = self._accepted_at
            if attestation is None or accepted_at is None:
                raise ValidatorSupervisorAdapterError("finalized_block_unavailable")
            block = attestation.block
            observed = self.clock()
            if observed.tzinfo is None or observed.utcoffset() is None:
                raise ValidatorSupervisorAdapterError("finalized_clock_invalid")
            observed_ms = int(observed.astimezone(timezone.utc).timestamp() * 1000)
            age_seconds = (observed_ms - block.timestamp_ms) / 1000
            acceptance_age = (
                observed.astimezone(timezone.utc) - accepted_at.astimezone(timezone.utc)
            ).total_seconds()
            if age_seconds > MAX_FINALIZED_HEAD_AGE_SECONDS:
                raise ValidatorSupervisorAdapterError("finalized_head_stale")
            if age_seconds < -MAX_FINALIZED_FUTURE_SKEW_SECONDS:
                raise ValidatorSupervisorAdapterError("finalized_head_from_future")
            if acceptance_age < 0 or acceptance_age > MAX_FINALIZED_HEAD_AGE_SECONDS:
                raise ValidatorSupervisorAdapterError("finality_acceptance_stale")
            if not FINNEY_BOOTSTRAP_BLOCK_NUMBER < block.number <= (1 << 53) - 1:
                raise ValidatorSupervisorAdapterError("finalized_block_invalid")
            identity = OwnedFinalizedBlock(number=block.number, block_hash=block.hash)
            self._last_returned_height = identity.number
            return identity
        except asyncio.CancelledError:
            raise
        except ValidatorSupervisorAdapterError:
            raise
        except asyncio.TimeoutError as error:
            raise ValidatorSupervisorAdapterError("finalized_block_timeout") from error
        except Exception as error:
            raise ValidatorSupervisorAdapterError("finalized_block_read_failed") from error

    def _observe_forever(self) -> None:
        minimum = FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1
        while not self._stop_requested.is_set():
            try:
                records = self.observer.attestations(
                    minimum_finalized_block=minimum,
                    maximum_records=100_000,
                    startup_timeout_seconds=max(1, math.ceil(self.timeout_seconds)),
                    stop_requested=self._stop_requested.is_set,
                )
                for attestation in records:
                    minimum = attestation.block.number + 1
                    loop = self._loop
                    if loop is None or self._stop_requested.is_set():
                        return
                    loop.call_soon_threadsafe(self._accept_attestation, attestation)
                if not self._stop_requested.is_set():
                    self._stop_requested.wait(1.0)
            except Exception as error:
                loop = self._loop
                if loop is not None:
                    loop.call_soon_threadsafe(self._record_observer_error, error)
                return

    def _accept_attestation(self, attestation: Any) -> None:
        prior = self._head
        if prior is not None and attestation.block.number <= prior.block.number:
            self._record_observer_error(
                ValidatorSupervisorAdapterError("finality_observer_regression")
            )
            return
        accepted_at = self.clock()
        if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
            self._record_observer_error(ValidatorSupervisorAdapterError("finalized_clock_invalid"))
            return
        self._head = attestation
        self._accepted_at = accepted_at
        self._head_available.set()

    def _record_observer_error(self, error: Exception) -> None:
        self._observer_error = error
        self._head_available.set()


class AsyncCommandRunner(Protocol):
    async def __call__(
        self, arguments: tuple[str, ...], *, timeout_seconds: float, maximum_output_bytes: int
    ) -> bytes: ...


class SpawnedProcess(Protocol):
    returncode: int | None

    async def wait(self) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


ProcessFactory = Callable[[tuple[str, ...]], Awaitable[SpawnedProcess]]


class RootlessPodmanWorkerAdapter:
    """Stage a signed release and own one fixed foreground rootless Podman worker."""

    def __init__(
        self,
        config: ValidatorSupervisorConfig,
        *,
        https: PinnedHTTPSClient | None = None,
        command_runner: AsyncCommandRunner | None = None,
        process_factory: ProcessFactory | None = None,
        command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
        stop_timeout_seconds: float = DEFAULT_STOP_TIMEOUT_SECONDS,
        start_grace_seconds: float = DEFAULT_START_GRACE_SECONDS,
    ) -> None:
        self.config = config
        self.https = https or PinnedHTTPSClient()
        self.command_runner = command_runner or _run_bounded_command
        self.process_factory = process_factory or _spawn_foreground
        self.command_timeout_seconds = _bounded_timeout(command_timeout_seconds, 900.0)
        self.stop_timeout_seconds = _bounded_timeout(stop_timeout_seconds, 120.0)
        self.start_grace_seconds = _bounded_timeout(start_grace_seconds, 30.0)
        self._process: SpawnedProcess | None = None
        self._hold = False
        self._expected_activation: SupervisorWorkerActivation | None = None
        self._staged: dict[str, StagedSupervisorRelease] = {}

    async def check_host(self) -> None:
        """Validate fixed local roots, wallet binding, architecture, and rootless Podman."""

        expected_target = _HOST_ARCHITECTURE.get(platform.machine().lower())
        if platform.system() != "Linux" or expected_target != self.config.target_platform:
            raise ValidatorSupervisorAdapterError("supervisor_host_platform_mismatch")
        for value in (
            self.config.state_root,
            self.config.worker_state_root,
            self.config.release_root,
            self.config.operator_input_root,
            self.config.wallet.path,
        ):
            _safe_podman_source(Path(value))
        wallet_root = Path(self.config.wallet.path)
        wallet_directory = wallet_root / self.config.wallet.name
        _require_wallet_root(wallet_root)
        _require_wallet_tree(
            wallet_directory,
            self.config.wallet.hotkey,
            expected_hotkey=self.config.validator_hotkey,
        )
        _require_directory(
            Path(self.config.operator_input_root), "operator_input_root_unsafe", private=True
        )
        _require_directory(Path(self.config.state_root), "state_root_unsafe", private=True)
        _require_directory(
            Path(self.config.worker_state_root), "worker_state_root_unsafe", private=True
        )
        _require_directory(Path(self.config.release_root), "release_root_unsafe", private=True)
        runtime = Path(self.config.container_runtime)
        if runtime != Path("/usr/bin/podman"):
            raise ValidatorSupervisorAdapterError("container_runtime_invalid")
        _require_safe_executable(runtime)
        payload = await self._command((str(runtime), "info", "--format", "json"), 30.0)
        try:
            info = json.loads(payload)
        except (TypeError, ValueError) as error:
            raise ValidatorSupervisorAdapterError("podman_info_invalid") from error
        if not isinstance(info, Mapping):
            raise ValidatorSupervisorAdapterError("podman_info_invalid")
        host = info.get("host") or info.get("Host")
        store = info.get("store") or info.get("Store")
        if not isinstance(host, Mapping) or not isinstance(store, Mapping):
            raise ValidatorSupervisorAdapterError("podman_info_invalid")
        rootless = (
            host.get("security", {}).get("rootless")
            if isinstance(host.get("security"), Mapping)
            else host.get("rootless")
        )
        cgroups = host.get("cgroupVersion") or host.get("CgroupsVersion")
        graph_root = store.get("graphRoot") or store.get("GraphRoot")
        run_root = store.get("runRoot") or store.get("RunRoot")
        if rootless is not True:
            raise ValidatorSupervisorAdapterError("podman_not_rootless")
        if str(cgroups).lower() not in {"v2", "2"}:
            raise ValidatorSupervisorAdapterError("podman_cgroup_v2_required")
        _require_path_below(
            graph_root,
            Path("/var/lib/umi-validator-supervisor/container-data"),
            "podman_graph_root_unsafe",
        )
        _require_path_below(
            run_root,
            Path("/run/umi-validator-supervisor"),
            "podman_run_root_unsafe",
        )

    async def preflight_activation(self, *, activation: SupervisorWorkerActivation) -> None:
        staged = await self._stage_release(activation)
        await self._ensure_image(staged, activation)
        self._staged[activation.directive_sha256] = staged

    async def stop_worker(self) -> None:
        process, self._process = self._process, None
        self._expected_activation = None
        self._hold = False
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=self.stop_timeout_seconds)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(process.wait(), timeout=5.0)
        await self._command(
            (
                self.config.container_runtime,
                "rm",
                "--force",
                "--time",
                str(max(1, min(30, math.ceil(self.stop_timeout_seconds)))),
                WORKER_CONTAINER_NAME,
            ),
            self.stop_timeout_seconds,
            allow_failure=True,
        )
        if await self._container_exists():
            raise ValidatorSupervisorAdapterError("podman_worker_stop_failed")

    async def worker_is_healthy(self) -> bool:
        if self._hold:
            return self._process is None and not await self._container_exists()
        activation = self._expected_activation
        if activation is None or self._process is None or self._process.returncode is not None:
            return False
        try:
            raw = await self._command(
                (
                    self.config.container_runtime,
                    "container",
                    "inspect",
                    "--format",
                    "json",
                    WORKER_CONTAINER_NAME,
                ),
                10.0,
            )
            value = json.loads(raw)
            record = value[0] if isinstance(value, list) and len(value) == 1 else None
            if not isinstance(record, Mapping):
                return False
            state = record.get("State") or record.get("state")
            config = record.get("Config") or record.get("config")
            labels = config.get("Labels") if isinstance(config, Mapping) else None
            return bool(
                isinstance(state, Mapping)
                and state.get("Running") is True
                and isinstance(labels, Mapping)
                and labels.get("vision.umi.supervisor.directive-sha256")
                == activation.directive_sha256
                and labels.get("vision.umi.supervisor.mode") == activation.mode
            )
        except Exception:
            return False

    async def start_hold(self, *, reason_code: str) -> None:
        if not isinstance(reason_code, str) or not reason_code or len(reason_code) > 256:
            raise ValidatorSupervisorAdapterError("hold_reason_invalid")
        if await self._container_exists():
            raise ValidatorSupervisorAdapterError("hold_worker_still_present")
        self._hold = True

    async def start_inactive_shadow(self, *, activation: SupervisorWorkerActivation) -> None:
        await self._start_worker(activation, "inactive_shadow")

    async def start_bootstrap_service_weights(
        self, *, activation: SupervisorWorkerActivation
    ) -> None:
        await self._start_worker(activation, "bootstrap_service_weights")

    async def start_translation_weights(self, *, activation: SupervisorWorkerActivation) -> None:
        await self._start_worker(activation, "translation_weights")

    async def public_status(self) -> dict[str, object]:
        """Return bounded local status without fetching, loading a wallet, or reading chain."""

        exists = await self._container_exists()
        return {
            "container_name": WORKER_CONTAINER_NAME,
            "managed_container_present": exists,
            "runtime": "rootless_podman",
            "target_platform": self.config.target_platform,
        }

    async def _start_worker(self, activation: SupervisorWorkerActivation, mode: str) -> None:
        if activation.mode != mode or mode not in _MODE_ARGUMENT:
            raise ValidatorSupervisorAdapterError("worker_mode_binding_mismatch")
        wallet_root = Path(self.config.wallet.path)
        wallet_directory = wallet_root / self.config.wallet.name
        _require_wallet_root(wallet_root)
        _require_wallet_tree(
            wallet_directory,
            self.config.wallet.hotkey,
            expected_hotkey=self.config.validator_hotkey,
        )
        _require_directory(
            Path(self.config.operator_input_root), "operator_input_root_unsafe", private=True
        )
        _require_directory(
            Path(self.config.worker_state_root), "worker_state_root_unsafe", private=True
        )
        if activation.release.entrypoint_profile == "umi-bootstrap-weight-validator/2":
            _require_bootstrap_result_upload_credential(
                BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL,
            )
        staged = self._staged.get(activation.directive_sha256)
        if staged is None:
            raise ValidatorSupervisorAdapterError("worker_release_not_preflighted")
        await self._verify_staged_release(staged, activation)
        await self._ensure_image(staged, activation)
        arguments = self._worker_arguments(staged, activation)
        process = await self.process_factory(arguments)
        self._process = process
        self._expected_activation = activation
        self._hold = False
        await asyncio.sleep(self.start_grace_seconds)
        if process.returncode is not None or not await self.worker_is_healthy():
            raise ValidatorSupervisorAdapterError("podman_worker_start_failed")

    def _worker_arguments(
        self, staged: StagedSupervisorRelease, activation: SupervisorWorkerActivation
    ) -> tuple[str, ...]:
        cpu = _cpu_limit(self.config.worker_cpu_millis)
        worker_state = Path(self.config.worker_state_root)
        wallet_directory = Path(self.config.wallet.path) / self.config.wallet.name
        operator_input_root = staged.operator_input_root
        if activation.mode == "bootstrap_service_weights":
            if operator_input_root is None:
                raise ValidatorSupervisorAdapterError("staged_operator_input_missing")
        else:
            operator_input_root = Path(self.config.operator_input_root)
        mounts = [
            _bind_mount(
                wallet_directory,
                f"{WORKER_WALLET_PATH}/{WORKER_WALLET_NAME}",
                read_only=True,
            ),
            _bind_mount(operator_input_root, WORKER_OPERATOR_INPUT_PATH, read_only=True),
            _bind_mount(
                staged.manifest_path,
                WORKER_RELEASE_MANIFEST_PATH,
                read_only=True,
            ),
            _bind_mount(worker_state, WORKER_STATE_PATH, read_only=False),
        ]
        legacy_bootstrap = (
            activation.release.entrypoint_profile == "umi-bootstrap-weight-validator/2"
        )
        simple_bootstrap = (
            activation.release.entrypoint_profile == "umi-simple-bootstrap-validator/1"
        )
        if legacy_bootstrap:
            mounts.append(
                _bind_mount(
                    BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL,
                    WORKER_BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL_PATH,
                    read_only=True,
                )
            )
        environment = [
            f"UMI_SUPERVISOR_DIRECTIVE_SHA256={activation.directive_sha256}",
            f"UMI_SUPERVISOR_POLICY_SHA256={activation.policy_sha256}",
            f"UMI_SUPERVISOR_SEQUENCE={activation.sequence}",
            f"UMI_SUPERVISOR_VALID_FROM_BLOCK={activation.valid_from_block}",
            f"UMI_SUPERVISOR_VALID_THROUGH_BLOCK={activation.valid_through_block}",
            f"UMI_RELEASE_MANIFEST_SHA256={activation.release.release_manifest_sha256}",
            "UMI_NETWORK=finney",
            "UMI_NETUID=78",
            "UMI_MECHANISM_ID=0",
            f"UMI_WALLET_PATH={WORKER_WALLET_PATH}",
            f"UMI_WALLET_NAME={WORKER_WALLET_NAME}",
            f"UMI_WALLET_HOTKEY={self.config.wallet.hotkey}",
            f"UMI_EXPECTED_VALIDATOR_HOTKEY={self.config.validator_hotkey}",
            f"UMI_OPERATOR_INPUT_ROOT={WORKER_OPERATOR_INPUT_PATH}",
            f"UMI_WORKER_STATE_ROOT={WORKER_STATE_PATH}",
            f"UMI_RELEASE_MANIFEST={WORKER_RELEASE_MANIFEST_PATH}",
        ]
        entrypoint = WORKER_ENTRYPOINT
        worker_arguments = [_MODE_ARGUMENT[activation.mode]]
        if simple_bootstrap:
            entrypoint = SIMPLE_BOOTSTRAP_WORKER_ENTRYPOINT
            environment.extend(
                (
                    f"UMI_MANIFEST_PATH={WORKER_OPERATOR_INPUT_PATH}/bootstrap/signed-manifest.json",
                    f"UMI_LEASE_PATH={WORKER_OPERATOR_INPUT_PATH}/bootstrap/bootstrap-lease.json",
                    f"UMI_HOTKEY={self.config.wallet.hotkey}",
                    f"UMI_GIT_REVISION={activation.release.umi_git_revision}",
                    "UMI_IMAGE_REVISION_PATH=/opt/umi-image-revision",
                    f"UMI_IMAGE_SOURCE_TREE_SHA256={activation.release.umi_source_tree_sha256}",
                )
            )
            worker_arguments = ["run", "--state-dir", WORKER_STATE_PATH]
        arguments: list[str] = [
            self.config.container_runtime,
            "run",
            "--rm",
            "--name",
            WORKER_CONTAINER_NAME,
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--image-volume=ignore",
            "--pull=never",
            "--userns",
            f"keep-id:uid={self.config.worker_uid},gid={self.config.worker_gid}",
            "--user",
            f"{self.config.worker_uid}:{self.config.worker_gid}",
            "--cpus",
            cpu,
            "--memory",
            str(self.config.worker_memory_bytes),
            "--pids-limit",
            str(self.config.worker_pids_limit),
            "--network",
            "slirp4netns:allow_host_loopback=false",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=268435456",
            "--entrypoint",
            entrypoint,
            "--label",
            f"vision.umi.supervisor.directive-sha256={activation.directive_sha256}",
            "--label",
            f"vision.umi.supervisor.mode={activation.mode}",
        ]
        for mount in mounts:
            arguments.extend(("--mount", mount))
        for value in environment:
            arguments.extend(("--env", value))
        arguments.append(staged.image_reference)
        arguments.extend(worker_arguments)
        return tuple(arguments)

    async def _stage_release(
        self, activation: SupervisorWorkerActivation
    ) -> StagedSupervisorRelease:
        root = Path(self.config.release_root)
        final = root / activation.directive_sha256
        if final.exists():
            staged = _staged_release(final)
            await self._verify_staged_release(staged, activation)
            return staged
        temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
        try:
            bundle = temporary / "release-bundle.bin"
            target = activation.release
            await self.https.download_file(
                target.release_bundle_url,
                destination=bundle,
                maximum_bytes=target.release_bundle_size_bytes,
                expected_size_bytes=target.release_bundle_size_bytes,
                expected_sha256=target.release_bundle_sha256,
            )
            _manifest, archive = _extract_release_bundle(bundle, temporary, target)
            if activation.operator_inputs is not None:
                await self._stage_operator_inputs(
                    temporary,
                    activation.operator_inputs,
                )
            for item in (bundle, temporary / "release-manifest.json", archive):
                item.chmod(0o400)
            temporary.chmod(0o500)
            try:
                os.rename(temporary, final)
            except FileExistsError:
                shutil.rmtree(temporary)
            staged = _staged_release(final)
            await self._verify_staged_release(staged, activation)
            return staged
        except Exception:
            with contextlib.suppress(OSError):
                temporary.chmod(0o700)
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    async def _verify_staged_release(
        self, staged: StagedSupervisorRelease, activation: SupervisorWorkerActivation
    ) -> None:
        target = activation.release
        _require_directory(staged.root, "staged_release_unsafe", private=True, modes={0o500, 0o700})
        bundle = staged.root / "release-bundle.bin"
        _require_regular_file(bundle, "staged_release_unsafe", modes={0o400})
        _require_regular_file(staged.manifest_path, "staged_release_unsafe", modes={0o400})
        _require_regular_file(staged.archive_path, "staged_release_unsafe", modes={0o400})
        if bundle.stat().st_size != target.release_bundle_size_bytes:
            raise ValidatorSupervisorAdapterError("staged_release_size_mismatch")
        if _sha256_file(bundle) != target.release_bundle_sha256:
            raise ValidatorSupervisorAdapterError("staged_release_sha256_mismatch")
        manifest = _parse_release_manifest(
            _read_regular_file_bounded(
                staged.manifest_path,
                MAX_RELEASE_MANIFEST_BYTES,
                "staged_release_unsafe",
            )
        )
        _verify_manifest_binding(manifest, target)
        if _sha256_file(staged.manifest_path) != target.release_manifest_sha256:
            raise ValidatorSupervisorAdapterError("release_manifest_sha256_mismatch")
        if staged.archive_path.stat().st_size != manifest.oci_archive_size_bytes:
            raise ValidatorSupervisorAdapterError("oci_archive_size_mismatch")
        if _sha256_file(staged.archive_path) != manifest.oci_archive_sha256:
            raise ValidatorSupervisorAdapterError("oci_archive_sha256_mismatch")
        await self._verify_staged_operator_inputs(staged, activation.operator_inputs)
        if (
            activation.operator_inputs is not None
            and activation.operator_inputs.profile == SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE
        ):
            bundle = _parse_bootstrap_input_bundle(
                _read_regular_file_bounded(
                    staged.root / "operator-input-bundle.json",
                    MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
                    "operator_input_bundle_unsafe",
                )
            )
            if not isinstance(bundle, SupervisorSimpleBootstrapInputBundle):
                raise ValidatorSupervisorAdapterError("operator_input_profile_mismatch")
            if (
                bundle.signed_lease.body.umi_git_revision != activation.release.umi_git_revision
                or bundle.signed_lease.body.policy_sha256 != activation.policy_sha256
            ):
                raise ValidatorSupervisorAdapterError("operator_input_release_binding_mismatch")

    async def _stage_operator_inputs(
        self,
        release_root: Path,
        target: SupervisorOperatorInputTarget,
    ) -> None:
        bundle_path = release_root / "operator-input-bundle.json"
        await self.https.download_file(
            target.bundle_url,
            destination=bundle_path,
            maximum_bytes=target.bundle_size_bytes,
            expected_size_bytes=target.bundle_size_bytes,
            expected_sha256=target.bundle_sha256,
        )
        bundle = _parse_bootstrap_input_bundle(
            _read_regular_file_bounded(
                bundle_path,
                MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
                "operator_input_bundle_unsafe",
            )
        )
        if bundle.profile != target.profile:
            raise ValidatorSupervisorAdapterError("operator_input_profile_mismatch")
        input_root = release_root / "operator-inputs"
        bootstrap_root = input_root / "bootstrap"
        input_root.mkdir(mode=0o700)
        bootstrap_root.mkdir(mode=0o700)
        _write_private_bytes(
            bootstrap_root / "signed-manifest.json",
            canonical_json_bytes(bundle.signed_manifest),
        )
        if isinstance(bundle, SupervisorSimpleBootstrapInputBundle):
            _write_private_bytes(
                bootstrap_root / "bootstrap-lease.json",
                canonical_json_bytes(bundle.signed_lease),
            )
        else:
            _write_private_bytes(
                bootstrap_root / "direct-transition-authorization.json",
                canonical_json_bytes(bundle.transition_authorization),
            )
            _write_private_bytes(
                bootstrap_root / "drain-checkpoint.json",
                canonical_json_bytes(bundle.drain_checkpoint),
            )
            _write_private_bytes(
                bootstrap_root / "owner-fence-receipt.json",
                canonical_json_bytes(bundle.owner_fence_receipt),
            )
        bundle_path.chmod(0o400)
        for item in bootstrap_root.iterdir():
            item.chmod(0o400)
        bootstrap_root.chmod(0o500)
        input_root.chmod(0o500)

    async def _verify_staged_operator_inputs(
        self,
        staged: StagedSupervisorRelease,
        target: SupervisorOperatorInputTarget | None,
    ) -> None:
        bundle_path = staged.root / "operator-input-bundle.json"
        if target is None:
            if bundle_path.exists() or staged.operator_input_root is not None:
                raise ValidatorSupervisorAdapterError("unexpected_staged_operator_input")
            return
        if staged.operator_input_root is None:
            raise ValidatorSupervisorAdapterError("staged_operator_input_missing")
        _require_regular_file(bundle_path, "operator_input_bundle_unsafe", modes={0o400})
        if bundle_path.stat().st_size != target.bundle_size_bytes:
            raise ValidatorSupervisorAdapterError("operator_input_bundle_size_mismatch")
        if _sha256_file(bundle_path) != target.bundle_sha256:
            raise ValidatorSupervisorAdapterError("operator_input_bundle_sha256_mismatch")
        bundle = _parse_bootstrap_input_bundle(
            _read_regular_file_bounded(
                bundle_path,
                MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
                "operator_input_bundle_unsafe",
            )
        )
        if bundle.profile != target.profile:
            raise ValidatorSupervisorAdapterError("operator_input_profile_mismatch")
        input_root = staged.operator_input_root
        bootstrap_root = input_root / "bootstrap"
        _require_directory(input_root, "operator_input_root_unsafe", private=True, modes={0o500})
        _require_directory(
            bootstrap_root,
            "operator_input_root_unsafe",
            private=True,
            modes={0o500},
        )
        expected = {"signed-manifest.json": canonical_json_bytes(bundle.signed_manifest)}
        if isinstance(bundle, SupervisorSimpleBootstrapInputBundle):
            expected["bootstrap-lease.json"] = canonical_json_bytes(bundle.signed_lease)
        else:
            expected.update(
                {
                    "direct-transition-authorization.json": canonical_json_bytes(
                        bundle.transition_authorization
                    ),
                    "drain-checkpoint.json": canonical_json_bytes(bundle.drain_checkpoint),
                    "owner-fence-receipt.json": canonical_json_bytes(bundle.owner_fence_receipt),
                }
            )
        try:
            names = {item.name for item in bootstrap_root.iterdir()}
        except OSError as error:
            raise ValidatorSupervisorAdapterError("operator_input_root_unsafe") from error
        if names != set(expected):
            raise ValidatorSupervisorAdapterError("operator_input_file_set_mismatch")
        for name, payload in expected.items():
            path = bootstrap_root / name
            _require_regular_file(path, "operator_input_file_unsafe", modes={0o400})
            if (
                _read_regular_file_bounded(
                    path,
                    MAX_SUPERVISOR_DOCUMENT_BYTES,
                    "operator_input_file_unsafe",
                )
                != payload
            ):
                raise ValidatorSupervisorAdapterError("operator_input_file_binding_mismatch")

    async def _ensure_image(
        self, staged: StagedSupervisorRelease, activation: SupervisorWorkerActivation
    ) -> None:
        if await self._image_is_valid(staged, activation):
            return
        await self._command(
            (
                self.config.container_runtime,
                "load",
                "--input",
                str(staged.archive_path),
            ),
            self.command_timeout_seconds,
        )
        if not await self._image_is_valid(staged, activation):
            raise ValidatorSupervisorAdapterError("podman_image_binding_mismatch")

    async def _image_is_valid(
        self, staged: StagedSupervisorRelease, activation: SupervisorWorkerActivation
    ) -> bool:
        try:
            raw = await self._command(
                (
                    self.config.container_runtime,
                    "image",
                    "inspect",
                    "--format",
                    "json",
                    staged.image_reference,
                ),
                30.0,
            )
            records = json.loads(raw)
            record = records[0] if isinstance(records, list) and len(records) == 1 else None
            if not isinstance(record, Mapping):
                return False
            architecture = str(record.get("Architecture", "")).lower()
            os_name = str(record.get("Os", record.get("OS", ""))).lower()
            digest = record.get("Digest")
            repo_digests = record.get("RepoDigests")
            config = record.get("Config")
            labels = config.get("Labels") if isinstance(config, Mapping) else None
            expected_digest = f"sha256:{activation.release.oci_manifest_sha256}"
            digest_match = digest == expected_digest or (
                isinstance(repo_digests, list) and staged.image_reference in repo_digests
            )
            return bool(
                digest_match
                and os_name == "linux"
                and architecture == _TARGET_ARCHITECTURE[self.config.target_platform]
                and isinstance(labels, Mapping)
                and labels.get("org.opencontainers.image.revision")
                == activation.release.umi_git_revision
                and labels.get("vision.umi.source-tree-sha256")
                == activation.release.umi_source_tree_sha256
                and labels.get("vision.umi.entrypoint-profile")
                == activation.release.entrypoint_profile
            )
        except Exception:
            return False

    async def _container_exists(self) -> bool:
        raw = await self._command(
            (
                self.config.container_runtime,
                "ps",
                "--all",
                "--filter",
                f"name=^{WORKER_CONTAINER_NAME}$",
                "--format",
                "json",
            ),
            10.0,
        )
        try:
            records = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise ValidatorSupervisorAdapterError("podman_container_list_invalid") from error
        if not isinstance(records, list) or len(records) > 1:
            raise ValidatorSupervisorAdapterError("podman_container_list_invalid")
        if not records:
            return False
        record = records[0]
        if not isinstance(record, Mapping):
            raise ValidatorSupervisorAdapterError("podman_container_list_invalid")
        names = record.get("Names", record.get("names"))
        if names == WORKER_CONTAINER_NAME:
            return True
        if isinstance(names, list) and names == [WORKER_CONTAINER_NAME]:
            return True
        raise ValidatorSupervisorAdapterError("podman_container_identity_mismatch")

    async def _command(
        self,
        arguments: tuple[str, ...],
        timeout_seconds: float,
        *,
        allow_failure: bool = False,
    ) -> bytes:
        try:
            return await self.command_runner(
                arguments,
                timeout_seconds=timeout_seconds,
                maximum_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
            )
        except ValidatorSupervisorAdapterError as error:
            if allow_failure and error.reason_code == "podman_command_failed":
                return b""
            raise
        except Exception as error:
            raise ValidatorSupervisorAdapterError("podman_command_failed") from error


def _extract_release_bundle(
    bundle: Path, destination: Path, target: SupervisorReleaseTarget
) -> tuple[SupervisorReleaseManifest, Path]:
    try:
        with bundle.open("rb", buffering=0) as source:
            if source.read(len(SUPERVISOR_RELEASE_BUNDLE_MAGIC)) != SUPERVISOR_RELEASE_BUNDLE_MAGIC:
                raise ValidatorSupervisorAdapterError("release_bundle_magic_invalid")
            encoded_length = source.read(4)
            if len(encoded_length) != 4:
                raise ValidatorSupervisorAdapterError("release_bundle_truncated")
            manifest_size = struct.unpack(">I", encoded_length)[0]
            if not 1 <= manifest_size <= MAX_RELEASE_MANIFEST_BYTES:
                raise ValidatorSupervisorAdapterError("release_manifest_size_invalid")
            manifest_bytes = source.read(manifest_size)
            signature = source.read(64)
            if len(manifest_bytes) != manifest_size or len(signature) != 64:
                raise ValidatorSupervisorAdapterError("release_bundle_truncated")
            if hashlib.sha256(manifest_bytes).hexdigest() != target.release_manifest_sha256:
                raise ValidatorSupervisorAdapterError("release_manifest_sha256_mismatch")
            manifest = _parse_release_manifest(manifest_bytes)
            _verify_manifest_binding(manifest, target)
            digest = hashlib.sha256(SUPERVISOR_RELEASE_SIGNATURE_DOMAIN + manifest_bytes).digest()
            if not verify_response_signature(
                digest,
                hotkey_ss58=target.release_authority_hotkey,
                scheme=target.release_authority_signature_scheme,
                signature="0x" + signature.hex(),
            ):
                raise ValidatorSupervisorAdapterError("release_signature_invalid")
            manifest_path = destination / "release-manifest.json"
            archive_path = destination / "image.oci.tar"
            manifest_path.write_bytes(manifest_bytes)
            archive_digest = hashlib.sha256()
            total = 0
            with archive_path.open("xb", buffering=0) as archive:
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > manifest.oci_archive_size_bytes:
                        raise ValidatorSupervisorAdapterError("oci_archive_size_mismatch")
                    archive_digest.update(chunk)
                    archive.write(chunk)
                archive.flush()
                os.fsync(archive.fileno())
            if total != manifest.oci_archive_size_bytes:
                raise ValidatorSupervisorAdapterError("oci_archive_size_mismatch")
            if not hmac.compare_digest(archive_digest.hexdigest(), manifest.oci_archive_sha256):
                raise ValidatorSupervisorAdapterError("oci_archive_sha256_mismatch")
            return manifest, archive_path
    except ValidatorSupervisorAdapterError:
        raise
    except OSError as error:
        raise ValidatorSupervisorAdapterError("release_bundle_read_failed") from error


def _parse_release_manifest(payload: bytes) -> SupervisorReleaseManifest:
    if not payload or len(payload) > MAX_RELEASE_MANIFEST_BYTES:
        raise ValidatorSupervisorAdapterError("release_manifest_size_invalid")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        manifest = SupervisorReleaseManifest.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorAdapterError("release_manifest_invalid") from error
    if canonical_json_bytes(manifest) != payload:
        raise ValidatorSupervisorAdapterError("release_manifest_noncanonical")
    return manifest


def parse_canonical_signed_supervisor_host_artifact_manifest(
    payload: bytes,
) -> SignedSupervisorHostArtifactManifest:
    if not payload or len(payload) > MAX_SUPERVISOR_DOCUMENT_BYTES:
        raise ValidatorSupervisorAdapterError("host_artifact_manifest_size_invalid")
    try:
        json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        signed = SignedSupervisorHostArtifactManifest.model_validate_json(payload)
    except Exception as error:
        raise ValidatorSupervisorAdapterError("host_artifact_manifest_invalid") from error
    if canonical_json_bytes(signed) != payload:
        raise ValidatorSupervisorAdapterError("host_artifact_manifest_noncanonical")
    return signed


def _parse_bootstrap_input_bundle(
    payload: bytes,
) -> SupervisorBootstrapInputBundle | SupervisorSimpleBootstrapInputBundle:
    if not payload or len(payload) > MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES:
        raise ValidatorSupervisorAdapterError("operator_input_bundle_size_invalid")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, Mapping):
            raise ValueError("operator input bundle must be an object")
        model = {
            SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA: SupervisorBootstrapInputBundle,
            SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_BUNDLE_SCHEMA: (SupervisorSimpleBootstrapInputBundle),
        }.get(value.get("schema"))
        if model is None:
            raise ValueError("operator input bundle schema is unsupported")
        bundle = model.model_validate_json(payload)
    except Exception as error:
        raise ValidatorSupervisorAdapterError("operator_input_bundle_invalid") from error
    if canonical_json_bytes(bundle) != payload:
        raise ValidatorSupervisorAdapterError("operator_input_bundle_noncanonical")
    return bundle


def _verify_manifest_binding(
    manifest: SupervisorReleaseManifest, target: SupervisorReleaseTarget
) -> None:
    fields = (
        "oci_repository",
        "oci_manifest_sha256",
        "target_platform",
        "umi_git_revision",
        "umi_source_tree_sha256",
        "entrypoint_profile",
        "state_schema_minimum",
        "state_schema_maximum",
    )
    if any(getattr(manifest, field) != getattr(target, field) for field in fields):
        raise ValidatorSupervisorAdapterError("release_manifest_binding_mismatch")


def _staged_release(root: Path) -> StagedSupervisorRelease:
    manifest_path = root / "release-manifest.json"
    _require_directory(root, "staged_release_unsafe", private=True, modes={0o500, 0o700})
    _require_regular_file(manifest_path, "staged_release_unsafe", modes={0o400})
    manifest = _parse_release_manifest(
        _read_regular_file_bounded(
            manifest_path,
            MAX_RELEASE_MANIFEST_BYTES,
            "staged_release_unsafe",
        )
    )
    return StagedSupervisorRelease(
        root=root,
        manifest_path=manifest_path,
        archive_path=root / "image.oci.tar",
        image_reference=f"{manifest.oci_repository}@sha256:{manifest.oci_manifest_sha256}",
        manifest=manifest,
        operator_input_root=(
            root / "operator-inputs" if (root / "operator-inputs").exists() else None
        ),
    )


def _write_private_bytes(path: Path, payload: bytes) -> None:
    if not payload or len(payload) > MAX_SUPERVISOR_DOCUMENT_BYTES:
        raise ValidatorSupervisorAdapterError("operator_input_file_size_invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as error:
        raise ValidatorSupervisorAdapterError("operator_input_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


async def _run_bounded_command(
    arguments: tuple[str, ...], *, timeout_seconds: float, maximum_output_bytes: int
) -> bytes:
    if not arguments or any(not isinstance(item, str) or "\x00" in item for item in arguments):
        raise ValidatorSupervisorAdapterError("podman_arguments_invalid")
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        raise ValidatorSupervisorAdapterError("podman_command_failed")

    async def collect() -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await process.stdout.read(min(64 * 1024, maximum_output_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_output_bytes:
                process.kill()
                await process.wait()
                raise ValidatorSupervisorAdapterError("podman_output_limit")
            chunks.append(chunk)
        returncode = await process.wait()
        if returncode != 0:
            raise ValidatorSupervisorAdapterError("podman_command_failed")
        return b"".join(chunks)

    try:
        return await asyncio.wait_for(collect(), timeout=timeout_seconds)
    except asyncio.TimeoutError as error:
        process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        raise ValidatorSupervisorAdapterError("podman_command_timeout") from error


async def _spawn_foreground(arguments: tuple[str, ...]) -> SpawnedProcess:
    return await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
    )


async def _system_resolver(hostname: str, port: int) -> Sequence[str]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return tuple(record[4][0] for record in records)


def _canonical_https_url(value: str) -> str:
    if not isinstance(value, str) or not value.isascii() or len(value) > 2_048:
        raise ValidatorSupervisorAdapterError("https_url_invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValidatorSupervisorAdapterError("https_url_invalid") from error
    hostname = parsed.hostname
    path = PurePosixPath(parsed.path)
    if (
        parsed.scheme != "https"
        or hostname is None
        or hostname != hostname.lower()
        or hostname.endswith(".")
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or "%" in parsed.path
        or "//" in parsed.path
        or path.as_posix() != parsed.path
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or parsed.netloc != (hostname if port is None else f"{hostname}:443")
    ):
        raise ValidatorSupervisorAdapterError("https_url_invalid")
    return value


def _header_size(headers: httpx.Headers) -> int:
    try:
        return (
            sum(
                len(key.encode("ascii")) + len(value.encode("latin-1")) + 4
                for key, value in headers.multi_items()
            )
            + 2
        )
    except UnicodeError as error:
        raise ValidatorSupervisorAdapterError("https_header_invalid") from error


def _content_length(value: str | None) -> int | None:
    if value is None:
        return None
    if re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        raise ValidatorSupervisorAdapterError("https_content_length_invalid")
    return int(value)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant: {value}")


def _positive_bound(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _bounded_timeout(value: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= maximum
    ):
        raise ValueError("adapter timeout is outside the supported range")
    return float(value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise ValidatorSupervisorAdapterError("staged_release_read_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or total != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise ValidatorSupervisorAdapterError("staged_release_read_failed")
    return digest.hexdigest()


def _safe_podman_source(path: Path) -> None:
    encoded = str(path)
    if (
        not path.is_absolute()
        or path != Path(os.path.normpath(path))
        or not encoded.isascii()
        or any(item in encoded for item in (",", ":", "\n", "\r", "\x00"))
    ):
        raise ValidatorSupervisorAdapterError("podman_mount_source_invalid")


def _bind_mount(source: Path, destination: str, *, read_only: bool) -> str:
    _safe_podman_source(source)
    return (
        f"type=bind,src={source},dst={destination},"
        f"ro={'true' if read_only else 'false'},bind-propagation=private"
    )


def _require_directory(
    path: Path,
    reason: str,
    *,
    private: bool,
    modes: set[int] | None = None,
) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise ValidatorSupervisorAdapterError(reason) from error
    accepted_modes = modes or ({0o700} if private else {0o700, 0o750})
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) not in accepted_modes
    ):
        raise ValidatorSupervisorAdapterError(reason)


def _require_regular_file(path: Path, reason: str, *, modes: set[int]) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise ValidatorSupervisorAdapterError(reason) from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) not in modes
    ):
        raise ValidatorSupervisorAdapterError(reason)


def _require_regular_private_file(path: Path, reason: str) -> None:
    _require_regular_file(path, reason, modes={0o400, 0o600})


def _require_bootstrap_result_upload_credential(path: Path) -> None:
    reason = "bootstrap_result_upload_credential_unsafe"
    _require_regular_private_file(path, reason)
    payload = _read_regular_file_bounded(path, 65, reason)
    if len(payload) == 65 and payload.endswith(b"\n"):
        payload = payload[:-1]
    try:
        encoded = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValidatorSupervisorAdapterError(reason) from error
    if _HEX32_RE.fullmatch(encoded) is None:
        raise ValidatorSupervisorAdapterError(reason)


def _require_wallet_root(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise ValidatorSupervisorAdapterError("wallet_root_unsafe") from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != os.getegid()
        or stat.S_IMODE(details.st_mode) != 0o750
    ):
        raise ValidatorSupervisorAdapterError("wallet_root_unsafe")


def _require_wallet_tree(
    wallet_directory: Path,
    hotkey_name: str,
    *,
    expected_hotkey: str,
) -> None:
    _require_directory(wallet_directory, "wallet_directory_unsafe", private=True)
    hotkeys = wallet_directory / "hotkeys"
    _require_directory(hotkeys, "wallet_hotkeys_directory_unsafe", private=True)
    try:
        wallet_entries = {item.name for item in wallet_directory.iterdir()}
        hotkey_entries = {item.name for item in hotkeys.iterdir()}
    except OSError as error:
        raise ValidatorSupervisorAdapterError("wallet_tree_unsafe") from error
    if not wallet_entries <= {"hotkeys", "coldkeypub.txt"} or "hotkeys" not in wallet_entries:
        raise ValidatorSupervisorAdapterError("wallet_tree_unsafe")
    if hotkey_entries != {hotkey_name}:
        raise ValidatorSupervisorAdapterError("wallet_tree_unsafe")
    hotkey_path = hotkeys / hotkey_name
    _require_regular_private_file(hotkey_path, "wallet_hotkey_unsafe")
    _require_wallet_hotkey_identity(hotkey_path, expected_hotkey)
    coldkeypub = wallet_directory / "coldkeypub.txt"
    if os.path.lexists(coldkeypub):
        _require_regular_private_file(coldkeypub, "wallet_coldkeypub_unsafe")


def _require_wallet_hotkey_identity(path: Path, expected_hotkey: str) -> None:
    """Require one plaintext, parseable hotkey that matches the configured validator."""

    try:
        from bittensor.keyfiles import (
            deserialize_keypair_from_keyfile_data,
            keyfile_data_is_encrypted,
        )

        payload = _read_regular_file_bounded(path, 64 * 1024, "wallet_hotkey_unsafe")
        if keyfile_data_is_encrypted(payload):
            raise ValidatorSupervisorAdapterError("wallet_hotkey_interactive_unlock_unsupported")
        keypair = deserialize_keypair_from_keyfile_data(payload)
        if not hmac.compare_digest(keypair.ss58_address, expected_hotkey):
            raise ValidatorSupervisorAdapterError("wallet_hotkey_identity_mismatch")
    except ValidatorSupervisorAdapterError:
        raise
    except Exception as error:
        raise ValidatorSupervisorAdapterError("wallet_hotkey_identity_invalid") from error


def _read_regular_file_bounded(path: Path, maximum_bytes: int, reason: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValidatorSupervisorAdapterError(reason) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise ValidatorSupervisorAdapterError(reason)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ValidatorSupervisorAdapterError(reason)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if total != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValidatorSupervisorAdapterError(reason)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_safe_executable(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise ValidatorSupervisorAdapterError("container_runtime_unsafe") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_mode & 0o022
        or not details.st_mode & stat.S_IXUSR
    ):
        raise ValidatorSupervisorAdapterError("container_runtime_unsafe")


def _require_path_below(value: object, root: Path, reason: str) -> None:
    if not isinstance(value, str):
        raise ValidatorSupervisorAdapterError(reason)
    path = Path(value)
    if not path.is_absolute() or (path != root and root not in path.parents):
        raise ValidatorSupervisorAdapterError(reason)


def _cpu_limit(value: int) -> str:
    _positive_bound(value, "worker CPU millis")
    whole, remainder = divmod(value, 1000)
    return str(whole) if remainder == 0 else f"{whole}.{remainder:03d}".rstrip("0")


__all__ = [
    "SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA",
    "SUPERVISOR_BOOTSTRAP_INPUT_PROFILE",
    "SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_BUNDLE_SCHEMA",
    "SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE",
    "FinneyFinalizedBlockReader",
    "HTTPSDirectiveFetcher",
    "OwnedFinalizedBlock",
    "PinnedHTTPSClient",
    "RootlessPodmanWorkerAdapter",
    "SignedSupervisorHostArtifactManifest",
    "StagedSupervisorRelease",
    "SupervisorBootstrapInputBundle",
    "SupervisorHostArtifact",
    "SupervisorHostArtifactManifest",
    "SupervisorReleaseManifest",
    "SupervisorSimpleBootstrapInputBundle",
    "ValidatorSupervisorAdapterError",
    "parse_canonical_signed_supervisor_host_artifact_manifest",
]
