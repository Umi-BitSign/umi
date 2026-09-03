"""Concrete read-only network and finality ports for live validator stages.

The pool and reveal effects intentionally accept narrow ports instead of owning
HTTP, drand, timelock, or chain clients.  This module supplies those production
adapters without exposing a wallet, transaction composer, generic RPC method, or
weight-submission capability.

Pool artifacts are discovered through one canonical document whose exact SHA-256
is pinned by the scoring policy.  Production candidate membership comes from the
verified closing snapshot: each eligible anchor and its committed graph are fetched
through digest-derived object paths.  The per-window index remains a compatibility
entry point for isolated tooling, never the live effect's membership authority.
Retrieval is HTTPS-only, streams before buffering, resolves and pins one public IP
for each request, never follows redirects, and durably accounts attempts and bytes
in SQLite with FULL synchronization.

The policy does not currently carry deployment mirror origins or credentials, so
the hash-pinned discovery bytes and request headers are explicit constructor
inputs.  Likewise, the reveal-stage port cannot derive the shared
``weight_commit_close_block`` from :class:`~umi.validator_state.StageWorkItem`.
The audit-release adapter therefore accepts one narrow proof-bound boundary port,
then independently requires the exact block from the durable GRANDPA finality
store.  It never substitutes the current head for the required release block.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Protocol
from urllib.parse import unquote, urlsplit

import httpx
from pydantic import Field, model_validator
from typing_extensions import Self

from .artifacts import PublicBatchManifest, validate_public_batch_manifest
from .crypto import SealedResponse, decrypt_response
from .drand import DrandPulse, DrandVerificationError, QuicknetClient
from .encoding import account_id32, u32be
from .policy import ScoringPolicy, scoring_policy_hash
from .pool import parse_pool_manifest_bytes, verify_availability_certificate_member
from .protocol import (
    PROTOCOL_VERSION,
    StrictProtocolModel,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)
from .validator_delivery import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    DELIVERY_ISSUANCE_EVIDENCE_SCHEMA,
    MIRROR_DISCOVERY_SCHEMA,
    IssuedVideoDeliverySet,
    MirrorDiscoveryRule,
    VideoDeliveryAttemptEvidence,
    VideoDeliveryIssuanceEvidence,
    VideoDeliveryIssuanceRequest,
    VideoDeliveryIssuanceResponse,
    build_delivery_request,
    normalized_https_origin,
    validate_delivery_issuance,
    validate_delivery_response,
)
from .validator_delivery import (
    parse_canonical_model as parse_canonical_delivery_model,
)
from .validator_plans import VerifiedFinalizedBlock
from .validator_pool_effect import (
    CertifiedPoolArtifactUnavailable,
    ClosingSnapshotPort,
    DeliveryIssuanceContext,
    DeliveryIssuancePort,
    PoolAnchorAttemptEvidence,
    PoolAnchorRetrievalEvidence,
    PoolBatchSource,
    PoolEffectPorts,
    PoolSourcePackage,
    PoolSourceRequest,
    PreparedAssignmentsPort,
    VideoDeliverySource,
)
from .validator_reveal_effect import (
    REVEAL_AUDIT_RELEASE_SCHEMA,
    RevealAuditRelease,
    RevealEffectPorts,
    VerifiedRevealAuditRelease,
)
from .validator_state import StagePending, StageWorkItem, WindowStage
from .validator_weight_build_effect import (
    WeightScheduleCapture,
    WeightSchedulePort,
    materialize_weight_schedule_evidence,
)
from .validator_weight_schedule import WeightCommitSchedulePending
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

if TYPE_CHECKING:
    from .mirror_readiness import VerifiedLiveMirrorReadiness

MIRROR_WINDOW_INDEX_SCHEMA = "umi-pool-mirror-index/1"
MIRROR_RETRIEVAL_EVIDENCE_SCHEMA = "umi-pool-mirror-retrieval/1"
REVEAL_RELEASE_BOUNDARY_SCHEMA = "umi-reveal-release-boundary/1"
REVEAL_RELEASE_EVIDENCE_SCHEMA = "umi-finalized-reveal-audit-release/1"

MAX_MIRROR_OBJECTS = 32_768
MAX_MIRROR_URL_BYTES = 8_192
MAX_MIRROR_HEADER_COUNT = 64
MAX_MIRROR_WINDOWS = 65_536
MAX_MIRROR_CACHE_BYTES = 1 << 40
DEFAULT_MIRROR_CACHE_BYTES = 8 * 1024 * 1024 * 1024
MAX_RELEASE_BOUNDARY_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_FINALITY_EVIDENCE_BYTES = 64 * 1024 * 1024
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_SCHEMA_VERSION = "3"
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "te",
        "transfer-encoding",
        "upgrade",
    }
)
_KIND_ORDER = {
    "pool_manifest": 0,
    "public_manifest": 1,
    "ground_truth_envelope": 2,
    "video": 3,
}
_CERTIFIED_CHILD_UNAVAILABLE_REASONS = frozenset(
    {
        "mirror_origins_exhausted",
        "mirror_http_status_invalid",
        "mirror_request_timeout",
        "mirror_transport_failed",
        "mirror_content_encoding_not_identity",
        "mirror_content_type_mismatch",
        "mirror_response_header_size_limit",
        "mirror_content_length_invalid",
        "mirror_content_length_mismatch",
        "mirror_declared_body_size_limit",
        "mirror_streamed_body_size_limit",
        "mirror_streamed_body_exceeds_commitment",
        "mirror_body_size_mismatch",
        "mirror_body_digest_mismatch",
        "mirror_resource_attempt_count_limit",
        "mirror_dns_resolution_failed",
        "mirror_dns_empty",
        "mirror_dns_address_invalid",
        "mirror_dns_non_public",
    }
)


class LiveValidatorPortError(RuntimeError):
    """Stable fail-closed failure at a read-only live port boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = _reason_code(reason_code)
        super().__init__(self.reason_code)


class MirrorRetrievalError(LiveValidatorPortError):
    """A mirror object or its durable accounting could not be reproduced."""

    def __init__(
        self,
        reason_code: str,
        *,
        observed_wire_bytes: int = 0,
        response_body_sha256: str | None = None,
        response_body_size_bytes: int = 0,
    ) -> None:
        super().__init__(reason_code)
        self.observed_wire_bytes = _bounded_int(
            observed_wire_bytes,
            0,
            _MAX_SQLITE_INTEGER,
            "observed failed mirror wire bytes",
        )
        if response_body_sha256 is not None and _HEX32_RE.fullmatch(response_body_sha256) is None:
            raise ValueError("failed mirror response digest must be lowercase SHA-256")
        self.response_body_size_bytes = _bounded_int(
            response_body_size_bytes,
            0,
            _MAX_SQLITE_INTEGER,
            "failed mirror response body bytes",
        )
        if response_body_sha256 is None and self.response_body_size_bytes != 0:
            raise ValueError("failed mirror response size lacks its digest")
        self.response_body_sha256 = response_body_sha256


class MirrorBindingError(MirrorRetrievalError):
    """Mirror material is valid in isolation but bound to another policy/window."""


class MirrorLimitError(MirrorRetrievalError):
    """A retrieval would exceed a policy or durable cache ceiling."""


class _MirrorDeliveryLease:
    __slots__ = ("_descriptor",)

    def __init__(self, descriptor: int) -> None:
        self._descriptor: int | None = descriptor

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


class QuicknetPortError(LiveValidatorPortError):
    """A verified Quicknet adapter returned invalid or incorrectly bound data."""


class TimelockRevealPortError(LiveValidatorPortError):
    """A reveal decrypt request did not carry the exact verified pulse/round."""


class RevealAuditReleasePortError(LiveValidatorPortError):
    """The proof-bound audit release observation is absent or inconsistent."""


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class MirrorObjectDescriptor(StrictProtocolModel):
    """One exact object address in a policy/window-bound mirror index."""

    kind: Literal[
        "pool_manifest",
        "public_manifest",
        "ground_truth_envelope",
        "video",
    ]
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    batch_id: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    path: Annotated[str, Field(min_length=1, max_length=MAX_MIRROR_URL_BYTES)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    media_type: Literal["application/json", "application/octet-stream", "video/mp4"]

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        _relative_mirror_path(self.path)
        if self.kind == "pool_manifest":
            if (
                self.publisher_hotkey is None
                or self.batch_id is not None
                or self.challenge_id is not None
            ):
                raise ValueError("pool-manifest descriptors require only publisher_hotkey")
            account_id32(self.publisher_hotkey)
            if self.media_type != "application/json":
                raise ValueError("pool manifests must use application/json")
        elif self.kind in {"public_manifest", "ground_truth_envelope"}:
            if (
                self.publisher_hotkey is not None
                or self.batch_id is None
                or self.challenge_id is not None
            ):
                raise ValueError("batch descriptors require only batch_id")
            _opaque_id(self.batch_id, "mirror batch ID")
            expected = (
                "application/json" if self.kind == "public_manifest" else "application/octet-stream"
            )
            if self.media_type != expected:
                raise ValueError("batch descriptor media type disagrees with its kind")
        else:
            if (
                self.publisher_hotkey is not None
                or self.batch_id is None
                or self.challenge_id is None
            ):
                raise ValueError("video descriptors require batch_id and challenge_id")
            _opaque_id(self.batch_id, "mirror video batch ID")
            _opaque_id(self.challenge_id, "mirror video challenge ID")
            if self.media_type != "video/mp4":
                raise ValueError("video descriptors must use video/mp4")
        return self

    @property
    def resource_key(self) -> str:
        return ":".join(
            (
                self.kind,
                self.publisher_hotkey or "-",
                self.batch_id or "-",
                self.challenge_id or "-",
                self.sha256,
            )
        )


class MirrorWindowIndex(StrictProtocolModel):
    """Canonical complete source index for one pool-and-selection stage."""

    schema_: Literal[MIRROR_WINDOW_INDEX_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    objects: Annotated[
        list[MirrorObjectDescriptor], Field(min_length=4, max_length=MAX_MIRROR_OBJECTS)
    ]

    @model_validator(mode="after")
    def validate_complete_index(self) -> Self:
        keys = [_descriptor_sort_key(item) for item in self.objects]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("mirror objects must be unique and canonically ordered")
        pools = [item for item in self.objects if item.kind == "pool_manifest"]
        public = {item.batch_id for item in self.objects if item.kind == "public_manifest"}
        envelopes = {item.batch_id for item in self.objects if item.kind == "ground_truth_envelope"}
        video_batches = {item.batch_id for item in self.objects if item.kind == "video"}
        if (
            not pools
            or not public
            or public != envelopes
            or not video_batches
            or video_batches != public
        ):
            raise ValueError("mirror index is not a complete pool/batch/video object graph")
        video_keys = [
            (item.batch_id, item.challenge_id) for item in self.objects if item.kind == "video"
        ]
        if len(video_keys) != len(set(video_keys)):
            raise ValueError("mirror index repeats a video delivery identity")
        return self


class MirrorAttemptEvidence(StrictProtocolModel):
    resource_key_sha256: Hex32
    url_sha256: Hex32
    attempt_index: Annotated[int, Field(ge=0, le=255)]
    status: Literal["pending_after_restart", "failed", "success"]
    observed_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    accounted_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    error_code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")] | None
    response_body_sha256: Hex32 | None
    response_body_size_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if (self.status == "success") != (self.error_code is None):
            raise ValueError("mirror attempt status and error code disagree")
        if self.response_body_sha256 is None and self.response_body_size_bytes != 0:
            raise ValueError("mirror attempt body size lacks its digest")
        return self


class MirrorRetrievedObject(StrictProtocolModel):
    kind: Literal[
        "index",
        "pool_manifest",
        "public_manifest",
        "ground_truth_envelope",
        "video",
    ]
    resource_key_sha256: Hex32
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    media_type: Literal["application/json", "application/octet-stream", "video/mp4"]
    selected_origin: Annotated[str, Field(min_length=1, max_length=MAX_MIRROR_URL_BYTES)]


class MirrorRetrievalEvidence(StrictProtocolModel):
    schema_: Literal[MIRROR_RETRIEVAL_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    discovery_rule_sha256: Hex32
    authentication_profile: Annotated[str, Field(min_length=1, max_length=128)]
    index_sha256: Hex32
    index_size_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    retrieved_objects: Annotated[
        list[MirrorRetrievedObject],
        Field(min_length=5, max_length=MAX_MIRROR_OBJECTS + 1),
    ]
    attempts: Annotated[
        list[MirrorAttemptEvidence],
        Field(min_length=1, max_length=(MAX_MIRROR_OBJECTS + 1) * 255),
    ]
    observed_window_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    accounted_window_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        object_keys = [
            (item.kind, item.resource_key_sha256, item.sha256) for item in self.retrieved_objects
        ]
        if object_keys != sorted(object_keys) or len(set(object_keys)) != len(object_keys):
            raise ValueError("retrieved mirror objects are not canonical")
        attempt_keys = [(item.resource_key_sha256, item.attempt_index) for item in self.attempts]
        if attempt_keys != sorted(attempt_keys) or len(set(attempt_keys)) != len(attempt_keys):
            raise ValueError("mirror attempts are not canonical")
        if self.accounted_window_wire_bytes < self.observed_window_wire_bytes:
            raise ValueError("ceiling-accounted wire bytes cannot be below observed bytes")
        return self


@dataclass(frozen=True, slots=True)
class _FetchedObject:
    resource_key: str
    data: bytes
    media_type: str
    selected_origin: str
    selected_url: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


AddressResolver = Callable[[str, int], Awaitable[Sequence[str]]]


class DurablePoolMirrorSource:
    """Policy-bound, restart-safe implementation of ``PoolSourcePort``."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        discovery_rule_bytes: bytes,
        state_path: str | os.PathLike[str],
        request_headers: Mapping[str, Mapping[str, str]] | Mapping[str, str],
        mirror_readiness: VerifiedLiveMirrorReadiness | None = None,
        require_mirror_readiness: bool = False,
        timeout_seconds: float = 30.0,
        maximum_cache_bytes: int = DEFAULT_MIRROR_CACHE_BYTES,
        maximum_windows: int = 4_096,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: AddressResolver | None = None,
        allow_http_for_tests: bool = False,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("mirror source policy must be ScoringPolicy")
        if not isinstance(discovery_rule_bytes, bytes) or not discovery_rule_bytes:
            raise TypeError("mirror discovery rule must be nonempty exact bytes")
        self.policy = policy
        self._policy_hash = scoring_policy_hash(policy)
        self._discovery_bytes = discovery_rule_bytes
        self._discovery_hash = hashlib.sha256(discovery_rule_bytes).hexdigest()
        expected_discovery = policy.implementation_pins.rules.mirror_discovery_rule_sha256
        if self._discovery_hash != expected_discovery:
            raise MirrorBindingError("mirror_discovery_policy_digest_mismatch")
        self.discovery = _parse_canonical_model(
            discovery_rule_bytes,
            MirrorDiscoveryRule,
            maximum_bytes=policy.limits.maximum_manifest_bytes,
            reason_code="mirror_discovery_not_canonical",
        )
        if (
            self.discovery.authentication_profile
            != policy.implementation_pins.rules.mirror_authentication_profile
        ):
            raise MirrorBindingError("mirror_authentication_profile_mismatch")
        # The strict model validates HTTPS.  Tests may explicitly opt into HTTP;
        # reparsing origins here is the only relaxation and never exists by default.
        if allow_http_for_tests:
            for origin in self.discovery.origins:
                _mirror_origin(origin, allow_http_for_tests=True)
        self._allow_http_for_tests = bool(allow_http_for_tests)
        self._headers_by_origin = _origin_request_headers(
            request_headers,
            origins=self.discovery.origins,
            maximum_bytes=policy.limits.maximum_http_header_bytes,
        )
        if mirror_readiness is not None:
            from .mirror_readiness import VerifiedLiveMirrorReadiness

            if not isinstance(mirror_readiness, VerifiedLiveMirrorReadiness):
                raise TypeError("mirror readiness has another type")
        self._mirror_readiness = mirror_readiness
        if not isinstance(require_mirror_readiness, bool):
            raise TypeError("mirror readiness requirement must be boolean")
        self._require_mirror_readiness = require_mirror_readiness
        if self._require_mirror_readiness and self._mirror_readiness is None:
            raise MirrorBindingError("mirror_readiness_missing")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise TypeError("mirror timeout must be numeric")
        if not 0 < float(timeout_seconds) <= 300:
            raise ValueError("mirror timeout must be in (0, 300]")
        self._timeout = float(timeout_seconds)
        self._maximum_cache_bytes = _bounded_int(
            maximum_cache_bytes,
            policy.limits.maximum_manifest_bytes,
            MAX_MIRROR_CACHE_BYTES,
            "mirror cache byte ceiling",
        )
        self._maximum_windows = _bounded_int(
            maximum_windows,
            1,
            MAX_MIRROR_WINDOWS,
            "mirror window-count ceiling",
        )
        self._busy_timeout_ms = _bounded_int(busy_timeout_ms, 1, 60_000, "busy timeout")
        self._transport = transport
        self._resolver = resolver
        self._path = Path(state_path)
        _prepare_database_path(self._path)
        self._lock = asyncio.Lock()
        self._initialize()
        self._audit_persisted_state()

    def _headers_for_origin(self, origin: str) -> Mapping[str, str]:
        """Return only the credential material assigned to one exact origin."""

        try:
            return self._headers_by_origin[origin]
        except KeyError as error:  # construction requires an exact origin set
            raise MirrorBindingError("mirror_request_headers_origin_missing") from error

    async def __call__(self, request: PoolSourceRequest | StageWorkItem) -> PoolSourcePackage:
        work = request.work if isinstance(request, PoolSourceRequest) else request
        self._validate_work(work)
        async with self._lock:
            lease = await self._acquire_collection_lease()
            try:
                # SQLite calls in this section intentionally remain synchronous.
                # Cancelling ``asyncio.to_thread`` does not stop its worker; a
                # late worker could otherwise mutate attempts after the kernel
                # lease or even a completed package had been released.
                if isinstance(request, PoolSourceRequest):
                    return await self._collect_from_eligible_anchors(request)
                cached = self._load_completed_package(work)
                if cached is not None:
                    return cached
                index_fetched = await self._load_or_fetch_index(work)
                index = _parse_canonical_model(
                    index_fetched.data,
                    MirrorWindowIndex,
                    maximum_bytes=self.policy.limits.maximum_manifest_bytes,
                    reason_code="mirror_index_not_canonical",
                )
                self._validate_index(index, work)
                fetched: list[tuple[MirrorObjectDescriptor, _FetchedObject]] = []
                for descriptor in index.objects:
                    maximum = self._descriptor_ceiling(descriptor)
                    if descriptor.size_bytes > maximum:
                        raise MirrorLimitError("mirror_declared_object_size_limit")
                    value = await self._load_or_fetch_descriptor(work, descriptor, maximum)
                    fetched.append((descriptor, value))
                evidence = self._finalize_package(
                    work,
                    index_fetched,
                    index,
                    tuple(fetched),
                )
                authoritative = self._load_completed_package(work)
                if authoritative is None:  # pragma: no cover - committed above
                    raise MirrorBindingError("mirror_completed_package_missing")
                if authoritative.artifact_retrieval_evidence_bytes != evidence:
                    raise MirrorBindingError("mirror_completed_evidence_changed")
                return authoritative
            finally:
                lease.release()

    async def _collect_from_eligible_anchors(
        self,
        request: PoolSourceRequest,
    ) -> PoolSourcePackage:
        """Discover only chain-eligible anchors through their committed digests."""

        work = request.work
        self._validate_work(work)
        readiness = self._mirror_readiness
        if readiness is not None and (
            readiness.readiness.window_id != work.window.plan.window_id
            or readiness.readiness.window_index != work.window.plan.window_index
            or readiness.readiness.scoring_policy_sha256 != work.window.plan.scoring_policy_hash
        ):
            raise MirrorBindingError("mirror_readiness_window_mismatch")
        accepted: list[tuple[bytes, object]] = []
        outcomes: list[dict[str, str]] = []
        for publisher, digest in request.timely_anchor_hashes:
            resource_key = f"anchor:{publisher}:{digest}"
            try:
                fetched = await self._load_or_fetch_by_digest(
                    work,
                    resource_key=resource_key,
                    digest=digest,
                    maximum=self.policy.limits.maximum_manifest_bytes,
                    media_type="application/json",
                )
            except MirrorRetrievalError:
                outcomes.append(
                    {
                        "publisher_hotkey": publisher,
                        "sha256": digest,
                        "status": "ignored_unavailable",
                    }
                )
                continue
            try:
                manifest = parse_pool_manifest_bytes(fetched.data, policy=self.policy)
                if account_id32(manifest.publisher_hotkey) != account_id32(publisher):
                    raise ValueError("publisher mismatch")
                if readiness is None and self._require_mirror_readiness:
                    raise MirrorBindingError("mirror_readiness_missing")
                if readiness is not None:
                    expected_digest = (
                        readiness.expected_pool_manifest_sha256_by_publisher_account.get(
                            account_id32(publisher)
                        )
                    )
                    if expected_digest != digest:
                        raise ValueError("pool manifest is absent from mirror readiness")
                verify_availability_certificate_member(
                    manifest.availability_certificate,
                    manifest.body(),
                    active_validator_hotkeys=request.active_validator_hotkeys,
                    policy=self.policy,
                )
            except (TypeError, ValueError):
                outcomes.append(
                    {
                        "publisher_hotkey": publisher,
                        "sha256": digest,
                        "status": "ignored_invalid",
                    }
                )
                continue
            accepted.append((fetched.data, manifest))
            outcomes.append(
                {"publisher_hotkey": publisher, "sha256": digest, "status": "qualified"}
            )

        certificates = {
            canonical_json_bytes(manifest.availability_certificate) for _raw, manifest in accepted
        }
        if len(certificates) > 1:
            raise MirrorBindingError("mirror_conflicting_quorum_certificates")
        if accepted and readiness is not None:
            certificate_signers = {
                account_id32(item.validator_hotkey)
                for item in accepted[0][1].availability_certificate.signatures
            }
            if certificate_signers != set(readiness.signer_accounts):
                raise MirrorBindingError("mirror_readiness_certificate_signer_mismatch")
        artifacts: list[PoolBatchSource] = []
        videos: list[VideoDeliverySource] = []
        for raw, manifest in accepted:
            for entry in manifest.batches:
                public_resource_key = f"public:{entry.batch_id}:{entry.public_manifest_sha256}"
                public_fetched = await self._load_certified_child(
                    work=work,
                    outcomes=outcomes,
                    final_pool_manifest_bytes=raw,
                    artifact_kind="public_manifest",
                    batch_id=entry.batch_id,
                    expected_sha256=entry.public_manifest_sha256,
                    resource_key=public_resource_key,
                    maximum=self.policy.limits.maximum_manifest_bytes,
                    media_type="application/json",
                )
                try:
                    public = PublicBatchManifest.model_validate_json(public_fetched.data)
                    if canonical_json_bytes(public) != public_fetched.data:
                        raise ValueError("noncanonical public manifest")
                    validate_public_batch_manifest(public, self.policy)
                except (TypeError, ValueError) as error:
                    raise MirrorBindingError("mirror_certified_public_manifest_invalid") from error
                envelope_resource_key = f"envelope:{entry.batch_id}:{entry.ciphertext_sha256}"
                envelope = await self._load_certified_child(
                    work=work,
                    outcomes=outcomes,
                    final_pool_manifest_bytes=raw,
                    artifact_kind="ground_truth_envelope",
                    batch_id=entry.batch_id,
                    expected_sha256=entry.ciphertext_sha256,
                    resource_key=envelope_resource_key,
                    maximum=self.policy.limits.maximum_ground_truth_envelope_bytes,
                    media_type="application/octet-stream",
                )
                artifacts.append(
                    PoolBatchSource(
                        batch_id=entry.batch_id,
                        public_manifest_bytes=public_fetched.data,
                        ground_truth_envelope_bytes=envelope.data,
                    )
                )
                for item in public.items:
                    video_resource_key = (
                        f"video:{entry.batch_id}:{item.challenge_id}:{item.media.sha256}"
                    )
                    video = await self._load_certified_child(
                        work=work,
                        outcomes=outcomes,
                        final_pool_manifest_bytes=raw,
                        artifact_kind="video",
                        batch_id=entry.batch_id,
                        challenge_id=item.challenge_id,
                        expected_sha256=item.media.sha256,
                        expected_size=item.media.size_bytes,
                        parent_public_manifest_bytes=public_fetched.data,
                        resource_key=video_resource_key,
                        maximum=self.policy.limits.maximum_clip_size_bytes,
                        media_type="video/mp4",
                    )
                    videos.append(
                        VideoDeliverySource(
                            batch_id=entry.batch_id,
                            challenge_id=item.challenge_id,
                            url=video.selected_url,
                            sha256=item.media.sha256,
                            size_bytes=item.media.size_bytes,
                        )
                    )
        evidence = self._anchor_evidence(work, outcomes)
        artifacts.sort(key=lambda item: base64url_decode(item.batch_id))
        videos.sort(
            key=lambda item: (
                base64url_decode(item.batch_id),
                base64url_decode(item.challenge_id),
            )
        )
        accepted.sort(key=lambda item: account_id32(item[1].publisher_hotkey))
        return PoolSourcePackage(
            final_pool_manifest_bytes=tuple(raw for raw, _manifest in accepted),
            batch_artifacts=tuple(artifacts),
            video_deliveries=tuple(videos),
            artifact_retrieval_evidence_bytes=evidence,
            mirror_discovery_rule_bytes=(
                self._discovery_bytes if self._mirror_readiness is not None else None
            ),
            mirror_readiness_set_bytes=(
                None if self._mirror_readiness is None else self._mirror_readiness.raw
            ),
        )

    async def _load_certified_child(
        self,
        *,
        work: StageWorkItem,
        outcomes: list[dict[str, str]],
        final_pool_manifest_bytes: bytes,
        artifact_kind: Literal["public_manifest", "ground_truth_envelope", "video"],
        batch_id: str,
        expected_sha256: str,
        resource_key: str,
        maximum: int,
        media_type: str,
        challenge_id: str | None = None,
        expected_size: int | None = None,
        parent_public_manifest_bytes: bytes | None = None,
    ) -> _FetchedObject:
        try:
            return await self._load_or_fetch_by_digest(
                work,
                resource_key=resource_key,
                digest=expected_sha256,
                maximum=maximum,
                media_type=media_type,
                expected_size=expected_size,
            )
        except MirrorRetrievalError as error:
            if error.reason_code not in _CERTIFIED_CHILD_UNAVAILABLE_REASONS:
                raise
            raise CertifiedPoolArtifactUnavailable(
                final_pool_manifest_bytes=final_pool_manifest_bytes,
                artifact_retrieval_evidence_bytes=self._anchor_evidence(work, outcomes),
                discovery_rule_bytes=self._discovery_bytes,
                mirror_readiness_set_bytes=(
                    None if self._mirror_readiness is None else self._mirror_readiness.raw
                ),
                artifact_kind=artifact_kind,
                batch_id=batch_id,
                challenge_id=challenge_id,
                expected_sha256=expected_sha256,
                expected_size_bytes=expected_size,
                resource_key=resource_key,
                parent_public_manifest_bytes=parent_public_manifest_bytes,
            ) from error

    async def _load_or_fetch_by_digest(
        self,
        work: StageWorkItem,
        *,
        resource_key: str,
        digest: str,
        maximum: int,
        media_type: str,
        expected_size: int | None = None,
    ) -> _FetchedObject:
        cached = self._load_successful_resource(
            work.window.plan.window_id,
            resource_key,
            digest,
            expected_size,
            media_type,
        )
        if cached is not None:
            return _FetchedObject(
                resource_key,
                cached.data,
                media_type,
                cached.selected_origin,
                cached.selected_origin + f"/v1/umi/objects/{digest}",
            )
        return await self._fetch_from_origins(
            work=work,
            resource_key=resource_key,
            path=f"/v1/umi/objects/{digest}",
            maximum_body_bytes=maximum,
            expected_sha256=digest,
            expected_size=expected_size,
            media_type=media_type,
        )

    def _anchor_evidence(self, work: StageWorkItem, outcomes: list[dict[str, str]]) -> bytes:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT resource_key, attempt_index, url_sha256, status, error_code, "
                "observed_wire_bytes, accounted_wire_bytes, response_body_sha256, "
                "response_body_size_bytes FROM attempts "
                "WHERE window_id = ? ORDER BY resource_key, attempt_index",
                (work.window.plan.window_id,),
            ).fetchall()
        artifact_rows = [
            row for row in rows if not row["resource_key"].startswith("delivery-issuance:")
        ]
        attempts = [
            PoolAnchorAttemptEvidence(
                resource_key_sha256=hashlib.sha256(row["resource_key"].encode()).hexdigest(),
                attempt_index=row["attempt_index"],
                url_sha256=row["url_sha256"],
                status=("pending_after_restart" if row["status"] == "pending" else row["status"]),
                observed_wire_bytes=row["observed_wire_bytes"],
                accounted_wire_bytes=row["accounted_wire_bytes"],
                error_code=(
                    "mirror_attempt_interrupted"
                    if row["status"] == "pending"
                    else row["error_code"]
                ),
                response_body_sha256=row["response_body_sha256"],
                response_body_size_bytes=row["response_body_size_bytes"],
            )
            for row in artifact_rows
        ]
        attempts.sort(key=lambda item: (item.resource_key_sha256, item.attempt_index))
        return canonical_json_bytes(
            PoolAnchorRetrievalEvidence(
                schema="umi-pool-anchor-retrieval/1",
                protocol=PROTOCOL_VERSION,
                window_id=work.window.plan.window_id,
                window_index=work.window.plan.window_index,
                scoring_policy_hash=self._policy_hash,
                discovery_rule_sha256=self._discovery_hash,
                anchor_outcomes=outcomes,
                attempts=attempts,
                artifact_observed_wire_bytes=sum(
                    row["observed_wire_bytes"] for row in artifact_rows
                ),
                artifact_accounted_wire_bytes=sum(
                    row["accounted_wire_bytes"] for row in artifact_rows
                ),
            )
        )

    def _validate_work(self, work: StageWorkItem) -> None:
        if not isinstance(work, StageWorkItem) or work.stage is not WindowStage.POOL_AND_SELECTION:
            raise MirrorBindingError("mirror_source_wrong_stage")
        if work.window.plan.scoring_policy_hash != self._policy_hash:
            raise MirrorBindingError("mirror_source_policy_hash_mismatch")

    def _validate_index(self, index: MirrorWindowIndex, work: StageWorkItem) -> None:
        expected = (
            work.window.plan.window_id,
            work.window.plan.window_index,
            self._policy_hash,
        )
        actual = (index.window_id, index.window_index, index.scoring_policy_hash)
        if actual != expected:
            raise MirrorBindingError("mirror_index_window_binding_mismatch")
        counts = {kind: 0 for kind in _KIND_ORDER}
        for item in index.objects:
            counts[item.kind] += 1
        if counts["pool_manifest"] > self.policy.limits.max_active_publishers:
            raise MirrorLimitError("mirror_pool_manifest_count_limit")
        if counts["public_manifest"] > self.policy.limits.max_candidate_batches_total:
            raise MirrorLimitError("mirror_batch_count_limit")
        maximum_videos = self.policy.limits.max_candidate_batches_total * (
            self.policy.limits.emission_bearing_clips_per_batch
            + max(
                1,
                (
                    self.policy.limits.emission_bearing_clips_per_batch
                    * self.policy.thresholds.canary_fraction.numerator
                    + self.policy.thresholds.canary_fraction.denominator
                    - 1
                )
                // self.policy.thresholds.canary_fraction.denominator,
            )
        )
        if counts["video"] > maximum_videos:
            raise MirrorLimitError("mirror_video_count_limit")

    async def _load_or_fetch_index(self, work: StageWorkItem) -> _FetchedObject:
        resource_key = "index"
        cached = self._load_successful_resource(
            work.window.plan.window_id,
            resource_key,
            None,
            None,
            "application/json",
        )
        if cached is not None:
            return cached
        path = self.discovery.index_path_template.format(window_id=work.window.plan.window_id)
        return await self._fetch_from_origins(
            work=work,
            resource_key=resource_key,
            path=path,
            maximum_body_bytes=self.policy.limits.maximum_manifest_bytes,
            expected_sha256=None,
            expected_size=None,
            media_type="application/json",
        )

    async def _load_or_fetch_descriptor(
        self,
        work: StageWorkItem,
        descriptor: MirrorObjectDescriptor,
        maximum: int,
    ) -> _FetchedObject:
        cached = self._load_successful_resource(
            work.window.plan.window_id,
            descriptor.resource_key,
            descriptor.sha256,
            descriptor.size_bytes,
            descriptor.media_type,
        )
        if cached is not None:
            return cached
        return await self._fetch_from_origins(
            work=work,
            resource_key=descriptor.resource_key,
            path=descriptor.path,
            maximum_body_bytes=maximum,
            expected_sha256=descriptor.sha256,
            expected_size=descriptor.size_bytes,
            media_type=descriptor.media_type,
        )

    async def _fetch_from_origins(
        self,
        *,
        work: StageWorkItem,
        resource_key: str,
        path: str,
        maximum_body_bytes: int,
        expected_sha256: str | None,
        expected_size: int | None,
        media_type: str,
    ) -> _FetchedObject:
        last_error: MirrorRetrievalError | None = None
        resume_index = self._artifact_resume_origin_index(
            work.window.plan.window_id,
            resource_key,
            path,
        )
        for origin in self.discovery.origins[resume_index:]:
            url = origin + path
            reservation = (
                maximum_body_bytes
                + 2 * self.policy.limits.maximum_http_header_bytes
                + MAX_MIRROR_URL_BYTES
                + 64
            )
            try:
                attempt_index = self._reserve_attempt(
                    work,
                    resource_key,
                    url,
                    reservation,
                )
            except MirrorLimitError as error:
                # When earlier permitted attempts already established why the
                # certified object could not be fetched, keep that concrete
                # retrieval failure.  The attempt ceiling only prevents another
                # origin from being tried; it must not erase the certificate-
                # breach evidence with a local limit classification.
                if last_error is None:
                    last_error = error
                break
            try:
                data, observed_wire = await self._fetch_streaming(
                    url,
                    maximum_body_bytes=maximum_body_bytes,
                    expected_sha256=expected_sha256,
                    expected_size=expected_size,
                    media_type=media_type,
                )
            except MirrorRetrievalError as error:
                self._finish_failed_attempt(
                    work.window.plan.window_id,
                    resource_key,
                    attempt_index,
                    error.reason_code,
                    error.observed_wire_bytes,
                    error.response_body_sha256,
                    error.response_body_size_bytes,
                )
                last_error = error
                continue
            fetched = _FetchedObject(
                resource_key=resource_key,
                data=data,
                media_type=media_type,
                selected_origin=origin,
                selected_url=url,
            )
            self._finish_successful_attempt(
                work.window.plan.window_id,
                resource_key,
                attempt_index,
                fetched,
                observed_wire,
            )
            return fetched
        if last_error is not None:
            raise last_error
        raise MirrorRetrievalError("mirror_origins_exhausted")

    def _artifact_resume_origin_index(
        self,
        window_id: str,
        resource_key: str,
        path: str,
    ) -> int:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT attempt_index, url_sha256, status FROM attempts "
                "WHERE window_id = ? AND resource_key = ? ORDER BY attempt_index",
                (window_id, resource_key),
            ).fetchall()
        if [row["attempt_index"] for row in rows] != list(range(len(rows))):
            raise MirrorBindingError("mirror_attempt_indices_invalid")
        if any(row["status"] == "success" for row in rows):
            raise MirrorBindingError("mirror_cached_success_lookup_conflict")
        if len(rows) > len(self.discovery.origins):
            raise MirrorBindingError("mirror_attempt_origin_count_invalid")
        expected_hashes = [
            hashlib.sha256((origin + path).encode("utf-8")).hexdigest()
            for origin in self.discovery.origins[: len(rows)]
        ]
        if [row["url_sha256"] for row in rows] != expected_hashes:
            raise MirrorBindingError("mirror_attempt_origin_history_invalid")
        return len(rows)

    async def _fetch_streaming(
        self,
        url: str,
        *,
        maximum_body_bytes: int,
        expected_sha256: str | None,
        expected_size: int | None,
        media_type: str,
    ) -> tuple[bytes, int]:
        parsed = urlsplit(url)
        origin = _mirror_origin_from_url(url, allow_http_for_tests=self._allow_http_for_tests)
        if origin not in self.discovery.origins:
            raise MirrorBindingError("mirror_url_origin_not_pinned")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        expected_port = 443 if parsed.scheme == "https" else 80
        actual_port = parsed.port or expected_port
        address = await _resolve_public_address(hostname, actual_port, resolver=self._resolver)
        request_url = httpx.URL(url).copy_with(host=address)
        authority_host = f"[{hostname}]" if ":" in hostname else hostname
        host_header = (
            authority_host if actual_port == expected_port else f"{authority_host}:{actual_port}"
        )
        headers = {
            **self._headers_for_origin(origin),
            "Accept-Encoding": "identity",
            "Host": host_header,
        }
        if _mapping_header_size(headers) > self.policy.limits.maximum_http_header_bytes:
            raise MirrorLimitError("mirror_request_header_size_limit")
        request_header_bytes = 0
        response_header_bytes = 0
        body = bytearray()
        try:
            async with (
                httpx.AsyncClient(
                    timeout=httpx.Timeout(self._timeout),
                    follow_redirects=False,
                    transport=self._transport,
                    trust_env=False,
                ) as client,
                client.stream(
                    "GET",
                    request_url,
                    headers=headers,
                    extensions={"sni_hostname": hostname},
                ) as response,
            ):
                request_header_bytes = _request_header_accounting(
                    response.request.url,
                    response.request.headers,
                )
                response_header_bytes = _raw_header_size(response.headers)
                if response_header_bytes > self.policy.limits.maximum_http_header_bytes:
                    raise MirrorLimitError("mirror_response_header_size_limit")
                if response.status_code != 200:
                    raise MirrorRetrievalError("mirror_http_status_invalid")
                content_encoding = response.headers.get("content-encoding", "").strip().lower()
                if content_encoding not in {"", "identity"}:
                    raise MirrorBindingError("mirror_content_encoding_not_identity")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
                if content_type != media_type:
                    raise MirrorBindingError("mirror_content_type_mismatch")
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        content_length = int(declared)
                    except ValueError as error:
                        raise MirrorBindingError("mirror_content_length_invalid") from error
                    if content_length < 0 or content_length > maximum_body_bytes:
                        raise MirrorLimitError("mirror_declared_body_size_limit")
                    if expected_size is not None and content_length != expected_size:
                        raise MirrorBindingError("mirror_content_length_mismatch")
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > maximum_body_bytes:
                        raise MirrorLimitError("mirror_streamed_body_size_limit")
                    if expected_size is not None and len(body) + len(chunk) > expected_size:
                        raise MirrorLimitError("mirror_streamed_body_exceeds_commitment")
                    body.extend(chunk)
        except MirrorRetrievalError as error:
            error.observed_wire_bytes = request_header_bytes + response_header_bytes + len(body)
            error.response_body_sha256 = hashlib.sha256(body).hexdigest() if body else None
            error.response_body_size_bytes = len(body)
            raise
        except httpx.TimeoutException as error:
            raise MirrorRetrievalError(
                "mirror_request_timeout",
                observed_wire_bytes=(request_header_bytes + response_header_bytes + len(body)),
                response_body_sha256=(hashlib.sha256(body).hexdigest() if body else None),
                response_body_size_bytes=len(body),
            ) from error
        except httpx.HTTPError as error:
            raise MirrorRetrievalError(
                "mirror_transport_failed",
                observed_wire_bytes=(request_header_bytes + response_header_bytes + len(body)),
                response_body_sha256=(hashlib.sha256(body).hexdigest() if body else None),
                response_body_size_bytes=len(body),
            ) from error
        data = bytes(body)
        observed_wire = request_header_bytes + response_header_bytes + len(data)
        response_digest = hashlib.sha256(data).hexdigest() if data else None
        if expected_size is not None and len(data) != expected_size:
            raise MirrorBindingError(
                "mirror_body_size_mismatch",
                observed_wire_bytes=observed_wire,
                response_body_sha256=response_digest,
                response_body_size_bytes=len(data),
            )
        actual = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise MirrorBindingError(
                "mirror_body_digest_mismatch",
                observed_wire_bytes=observed_wire,
                response_body_sha256=response_digest,
                response_body_size_bytes=len(data),
            )
        return data, observed_wire

    def _descriptor_ceiling(self, descriptor: MirrorObjectDescriptor) -> int:
        if descriptor.kind in {"pool_manifest", "public_manifest"}:
            return self.policy.limits.maximum_manifest_bytes
        if descriptor.kind == "ground_truth_envelope":
            return self.policy.limits.maximum_ground_truth_envelope_bytes
        return self.policy.limits.maximum_clip_size_bytes

    def _reserve_attempt(
        self,
        work: StageWorkItem,
        resource_key: str,
        url: str,
        reservation: int,
    ) -> int:
        if reservation > self.policy.limits.maximum_validator_window_wire_bytes:
            raise MirrorLimitError("mirror_single_attempt_window_wire_limit")
        window_id = work.window.plan.window_id
        with self._transaction() as connection:
            package = connection.execute(
                "SELECT 1 FROM packages WHERE window_id = ?", (window_id,)
            ).fetchone()
            if package is not None:
                raise MirrorBindingError("mirror_package_completed_during_retrieval")
            row = connection.execute(
                "SELECT attempt_count, accounted_wire_bytes FROM windows WHERE window_id = ?",
                (window_id,),
            ).fetchone()
            if row is None:
                count = connection.execute("SELECT COUNT(*) FROM windows").fetchone()[0]
                if count >= self._maximum_windows:
                    raise MirrorLimitError("mirror_window_count_limit")
                connection.execute(
                    "INSERT INTO windows (window_id, window_index, scoring_policy_hash, "
                    "attempt_count, observed_wire_bytes, accounted_wire_bytes) "
                    "VALUES (?, ?, ?, 0, 0, 0)",
                    (window_id, work.window.plan.window_index, self._policy_hash),
                )
                total_attempts = 0
                accounted = 0
            else:
                total_attempts = row["attempt_count"]
                accounted = row["accounted_wire_bytes"]
            resource_attempts = connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE window_id = ? AND resource_key = ?",
                (window_id, resource_key),
            ).fetchone()[0]
            if resource_attempts >= self.policy.limits.maximum_video_fetch_attempts_per_actor:
                raise MirrorLimitError("mirror_resource_attempt_count_limit")
            if accounted + reservation > self.policy.limits.maximum_validator_window_wire_bytes:
                raise MirrorLimitError("mirror_window_wire_size_limit")
            attempt_index = resource_attempts
            connection.execute(
                "INSERT INTO attempts (window_id, resource_key, attempt_index, url_sha256, "
                "selected_origin, status, observed_wire_bytes, accounted_wire_bytes, "
                "error_code, response_body_sha256, response_body_size_bytes, object_sha256, "
                "object_size_bytes, media_type) "
                "VALUES (?, ?, ?, ?, NULL, 'pending', 0, ?, NULL, NULL, 0, NULL, NULL, NULL)",
                (
                    window_id,
                    resource_key,
                    attempt_index,
                    hashlib.sha256(url.encode("utf-8")).hexdigest(),
                    reservation,
                ),
            )
            connection.execute(
                "UPDATE windows SET attempt_count = ?, accounted_wire_bytes = ? "
                "WHERE window_id = ?",
                (total_attempts + 1, accounted + reservation, window_id),
            )
        return attempt_index

    def _finish_failed_attempt(
        self,
        window_id: str,
        resource_key: str,
        attempt_index: int,
        error_code: str,
        observed_wire: int,
        response_body_sha256: str | None = None,
        response_body_size_bytes: int = 0,
    ) -> None:
        with self._transaction() as connection:
            completed = connection.execute(
                "SELECT 1 FROM packages WHERE window_id = ?", (window_id,)
            ).fetchone()
            if completed is not None:
                raise MirrorBindingError("mirror_package_completed_during_retrieval")
            attempt = connection.execute(
                "SELECT accounted_wire_bytes FROM attempts WHERE window_id = ? "
                "AND resource_key = ? AND attempt_index = ? AND status = 'pending'",
                (window_id, resource_key, attempt_index),
            ).fetchone()
            if attempt is None:
                raise MirrorBindingError("mirror_attempt_state_conflict")
            if observed_wire > attempt["accounted_wire_bytes"]:
                raise MirrorLimitError("mirror_observed_wire_exceeds_reservation")
            changed = connection.execute(
                "UPDATE attempts SET status = 'failed', error_code = ?, observed_wire_bytes = ?, "
                "response_body_sha256 = ?, response_body_size_bytes = ? "
                "WHERE window_id = ? AND resource_key = ? AND attempt_index = ? "
                "AND status = 'pending'",
                (
                    error_code,
                    observed_wire,
                    response_body_sha256,
                    response_body_size_bytes,
                    window_id,
                    resource_key,
                    attempt_index,
                ),
            ).rowcount
            if changed != 1:
                raise MirrorBindingError("mirror_attempt_state_conflict")
            connection.execute(
                "UPDATE windows SET observed_wire_bytes = observed_wire_bytes + ? "
                "WHERE window_id = ?",
                (observed_wire, window_id),
            )

    def _finish_successful_attempt(
        self,
        window_id: str,
        resource_key: str,
        attempt_index: int,
        fetched: _FetchedObject,
        observed_wire: int,
    ) -> None:
        with self._transaction() as connection:
            completed = connection.execute(
                "SELECT 1 FROM packages WHERE window_id = ?", (window_id,)
            ).fetchone()
            if completed is not None:
                raise MirrorBindingError("mirror_package_completed_during_retrieval")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE window_id = ? AND resource_key = ? "
                "AND attempt_index = ?",
                (window_id, resource_key, attempt_index),
            ).fetchone()
            if attempt is None or attempt["status"] != "pending":
                raise MirrorBindingError("mirror_attempt_state_conflict")
            if observed_wire > attempt["accounted_wire_bytes"]:
                raise MirrorLimitError("mirror_observed_wire_exceeds_reservation")
            existing = connection.execute(
                "SELECT * FROM objects WHERE sha256 = ?", (fetched.sha256,)
            ).fetchone()
            if existing is None:
                cache_total = connection.execute(
                    "SELECT COALESCE(SUM(size_bytes), 0) FROM objects"
                ).fetchone()[0]
                if cache_total + len(fetched.data) > self._maximum_cache_bytes:
                    raise MirrorLimitError("mirror_cache_size_limit")
                connection.execute(
                    "INSERT INTO objects (sha256, size_bytes, media_type, data) "
                    "VALUES (?, ?, ?, ?)",
                    (fetched.sha256, len(fetched.data), fetched.media_type, fetched.data),
                )
            else:
                _verify_object_row(existing, fetched.sha256, len(fetched.data), fetched.media_type)
                if bytes(existing["data"]) != fetched.data:
                    raise MirrorBindingError("mirror_content_address_conflict")
            prior_accounted = attempt["accounted_wire_bytes"]
            connection.execute(
                "UPDATE attempts SET selected_origin = ?, status = 'success', "
                "observed_wire_bytes = ?, accounted_wire_bytes = ?, error_code = NULL, "
                "response_body_sha256 = ?, response_body_size_bytes = ?, "
                "object_sha256 = ?, object_size_bytes = ?, media_type = ? "
                "WHERE window_id = ? AND resource_key = ? AND attempt_index = ?",
                (
                    fetched.selected_origin,
                    observed_wire,
                    observed_wire,
                    fetched.sha256,
                    len(fetched.data),
                    fetched.sha256,
                    len(fetched.data),
                    fetched.media_type,
                    window_id,
                    resource_key,
                    attempt_index,
                ),
            )
            connection.execute(
                "UPDATE windows SET observed_wire_bytes = observed_wire_bytes + ?, "
                "accounted_wire_bytes = accounted_wire_bytes - ? + ? WHERE window_id = ?",
                (observed_wire, prior_accounted, observed_wire, window_id),
            )

    def _load_successful_resource(
        self,
        window_id: str,
        resource_key: str,
        expected_sha256: str | None,
        expected_size: int | None,
        expected_media_type: str,
    ) -> _FetchedObject | None:
        with self._connection() as connection:
            attempts = connection.execute(
                "SELECT * FROM attempts WHERE window_id = ? AND resource_key = ? "
                "AND status = 'success' ORDER BY attempt_index",
                (window_id, resource_key),
            ).fetchall()
            if not attempts:
                return None
            if len(attempts) != 1:
                raise MirrorBindingError("mirror_duplicate_successful_resource")
            attempt = attempts[0]
            digest = attempt["object_sha256"]
            size = attempt["object_size_bytes"]
            media_type = attempt["media_type"]
            if expected_sha256 is not None and digest != expected_sha256:
                raise MirrorBindingError("mirror_cached_digest_mismatch")
            if expected_size is not None and size != expected_size:
                raise MirrorBindingError("mirror_cached_size_mismatch")
            if media_type != expected_media_type:
                raise MirrorBindingError("mirror_cached_media_type_mismatch")
            row = connection.execute("SELECT * FROM objects WHERE sha256 = ?", (digest,)).fetchone()
            if row is None:
                raise MirrorBindingError("mirror_cached_object_missing")
            data = _verify_object_row(row, digest, size, media_type)
            origin = attempt["selected_origin"]
            if not isinstance(origin, str) or origin not in self.discovery.origins:
                raise MirrorBindingError("mirror_cached_origin_invalid")
            # The exact relative path is reconstructed by callers from the index.
            return _FetchedObject(resource_key, data, media_type, origin, origin)

    def _finalize_package(
        self,
        work: StageWorkItem,
        index_fetched: _FetchedObject,
        index: MirrorWindowIndex,
        fetched: tuple[tuple[MirrorObjectDescriptor, _FetchedObject], ...],
    ) -> bytes:
        window_id = work.window.plan.window_id
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM packages WHERE window_id = ?", (window_id,)
            ).fetchone()
            if existing is not None:
                evidence = bytes(existing["evidence_bytes"])
                if existing["index_sha256"] != index_fetched.sha256:
                    raise MirrorBindingError("mirror_completed_index_conflict")
                parsed = self._parse_retrieval_evidence(evidence, work)
                self._reconcile_completed_package(connection, parsed)
                return evidence
            rows = connection.execute(
                "SELECT * FROM attempts WHERE window_id = ? ORDER BY resource_key, attempt_index",
                (window_id,),
            ).fetchall()
            successful = {row["resource_key"]: row for row in rows if row["status"] == "success"}
            if sum(row["status"] == "success" for row in rows) != len(successful):
                raise MirrorBindingError("mirror_duplicate_successful_resource")
            required = {"index", *(item.resource_key for item in index.objects)}
            if set(successful) != required:
                raise MirrorBindingError("mirror_completed_resource_set_mismatch")
            retrieved: list[MirrorRetrievedObject] = []
            for kind, resource_key, digest, size, media_type in (
                (
                    "index",
                    "index",
                    index_fetched.sha256,
                    len(index_fetched.data),
                    "application/json",
                ),
                *(
                    (item.kind, item.resource_key, value.sha256, len(value.data), item.media_type)
                    for item, value in fetched
                ),
            ):
                row = successful[resource_key]
                if row["object_sha256"] != digest or row["object_size_bytes"] != size:
                    raise MirrorBindingError("mirror_successful_attempt_object_mismatch")
                retrieved.append(
                    MirrorRetrievedObject(
                        kind=kind,
                        resource_key_sha256=hashlib.sha256(resource_key.encode()).hexdigest(),
                        sha256=digest,
                        size_bytes=size,
                        media_type=media_type,
                        selected_origin=row["selected_origin"],
                    )
                )
            retrieved.sort(key=lambda item: (item.kind, item.resource_key_sha256, item.sha256))
            attempts = [self._attempt_evidence_from_row(row) for row in rows]
            attempts.sort(key=lambda item: (item.resource_key_sha256, item.attempt_index))
            counters = connection.execute(
                "SELECT * FROM windows WHERE window_id = ?", (window_id,)
            ).fetchone()
            if counters is None:
                raise MirrorBindingError("mirror_window_counter_missing")
            evidence_model = MirrorRetrievalEvidence(
                schema=MIRROR_RETRIEVAL_EVIDENCE_SCHEMA,
                protocol=PROTOCOL_VERSION,
                window_id=window_id,
                window_index=work.window.plan.window_index,
                scoring_policy_hash=self._policy_hash,
                discovery_rule_sha256=self._discovery_hash,
                authentication_profile=self.discovery.authentication_profile,
                index_sha256=index_fetched.sha256,
                index_size_bytes=len(index_fetched.data),
                retrieved_objects=retrieved,
                attempts=attempts,
                observed_window_wire_bytes=counters["observed_wire_bytes"],
                accounted_window_wire_bytes=counters["accounted_wire_bytes"],
            )
            evidence = canonical_json_bytes(evidence_model)
            if len(evidence) > 64 * 1024 * 1024:
                raise MirrorLimitError("mirror_retrieval_evidence_size_limit")
            connection.execute(
                "INSERT INTO packages (window_id, scoring_policy_hash, index_sha256, "
                "index_size_bytes, evidence_sha256, evidence_bytes) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    window_id,
                    self._policy_hash,
                    index_fetched.sha256,
                    len(index_fetched.data),
                    hashlib.sha256(evidence).hexdigest(),
                    evidence,
                ),
            )
        return evidence

    @staticmethod
    def _attempt_evidence_from_row(row: sqlite3.Row) -> MirrorAttemptEvidence:
        status = row["status"]
        return MirrorAttemptEvidence(
            resource_key_sha256=hashlib.sha256(row["resource_key"].encode()).hexdigest(),
            url_sha256=row["url_sha256"],
            attempt_index=row["attempt_index"],
            status=("pending_after_restart" if status == "pending" else status),
            observed_wire_bytes=row["observed_wire_bytes"],
            accounted_wire_bytes=row["accounted_wire_bytes"],
            error_code=("mirror_attempt_interrupted" if status == "pending" else row["error_code"]),
            response_body_sha256=row["response_body_sha256"],
            response_body_size_bytes=row["response_body_size_bytes"],
        )

    def _reconcile_completed_package(
        self,
        connection: sqlite3.Connection,
        evidence: MirrorRetrievalEvidence,
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM attempts WHERE window_id = ? ORDER BY resource_key, attempt_index",
            (evidence.window_id,),
        ).fetchall()
        attempts = [self._attempt_evidence_from_row(row) for row in rows]
        attempts.sort(key=lambda item: (item.resource_key_sha256, item.attempt_index))
        if attempts != evidence.attempts:
            raise MirrorBindingError("mirror_completed_attempt_evidence_changed")

        counters = connection.execute(
            "SELECT observed_wire_bytes, accounted_wire_bytes FROM windows WHERE window_id = ?",
            (evidence.window_id,),
        ).fetchone()
        if counters is None or (
            counters["observed_wire_bytes"] != evidence.observed_window_wire_bytes
            or counters["accounted_wire_bytes"] != evidence.accounted_window_wire_bytes
        ):
            raise MirrorBindingError("mirror_completed_counter_evidence_changed")

        successful: dict[str, tuple[sqlite3.Row, str]] = {}
        for row in rows:
            if row["status"] != "success":
                continue
            key = hashlib.sha256(row["resource_key"].encode()).hexdigest()
            if key in successful:
                raise MirrorBindingError("mirror_duplicate_successful_resource")
            kind = (
                "index" if row["resource_key"] == "index" else row["resource_key"].split(":", 1)[0]
            )
            successful[key] = (row, kind)
        retrieved_keys = [item.resource_key_sha256 for item in evidence.retrieved_objects]
        if len(retrieved_keys) != len(set(retrieved_keys)) or set(successful) != set(
            retrieved_keys
        ):
            raise MirrorBindingError("mirror_completed_object_evidence_changed")
        for item in evidence.retrieved_objects:
            row, kind = successful[item.resource_key_sha256]
            if (
                kind != item.kind
                or row["object_sha256"] != item.sha256
                or row["object_size_bytes"] != item.size_bytes
                or row["media_type"] != item.media_type
                or row["selected_origin"] != item.selected_origin
            ):
                raise MirrorBindingError("mirror_completed_object_evidence_changed")

    def _package_from_material(
        self,
        index: MirrorWindowIndex,
        fetched: tuple[tuple[MirrorObjectDescriptor, _FetchedObject], ...],
        evidence: bytes,
    ) -> PoolSourcePackage:
        pools: list[tuple[bytes, bytes]] = []
        batch_data: dict[str, dict[str, bytes]] = {}
        videos: list[VideoDeliverySource] = []
        for descriptor, value in fetched:
            if descriptor.kind == "pool_manifest":
                if descriptor.publisher_hotkey is None:  # pragma: no cover - model narrowed
                    raise RuntimeError("pool descriptor lost publisher")
                pools.append((account_id32(descriptor.publisher_hotkey), value.data))
            elif descriptor.kind in {"public_manifest", "ground_truth_envelope"}:
                if descriptor.batch_id is None:  # pragma: no cover - model narrowed
                    raise RuntimeError("batch descriptor lost batch ID")
                batch_data.setdefault(descriptor.batch_id, {})[descriptor.kind] = value.data
            else:
                if descriptor.batch_id is None or descriptor.challenge_id is None:
                    raise RuntimeError("video descriptor lost identifiers")
                videos.append(
                    VideoDeliverySource(
                        batch_id=descriptor.batch_id,
                        challenge_id=descriptor.challenge_id,
                        url=value.selected_origin + descriptor.path,
                        sha256=descriptor.sha256,
                        size_bytes=descriptor.size_bytes,
                    )
                )
        pools.sort(key=lambda item: item[0])
        artifacts = [
            PoolBatchSource(
                batch_id=batch_id,
                public_manifest_bytes=parts["public_manifest"],
                ground_truth_envelope_bytes=parts["ground_truth_envelope"],
            )
            for batch_id, parts in sorted(
                batch_data.items(), key=lambda item: base64url_decode(item[0])
            )
        ]
        videos.sort(
            key=lambda item: (base64url_decode(item.batch_id), base64url_decode(item.challenge_id))
        )
        return PoolSourcePackage(
            final_pool_manifest_bytes=tuple(value for _publisher, value in pools),
            batch_artifacts=tuple(artifacts),
            video_deliveries=tuple(videos),
            artifact_retrieval_evidence_bytes=evidence,
            mirror_discovery_rule_bytes=(
                self._discovery_bytes if self._mirror_readiness is not None else None
            ),
            mirror_readiness_set_bytes=(
                None if self._mirror_readiness is None else self._mirror_readiness.raw
            ),
        )

    def _load_completed_package(self, work: StageWorkItem) -> PoolSourcePackage | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM packages WHERE window_id = ?", (work.window.plan.window_id,)
            ).fetchone()
            if row is None:
                return None
            if row["scoring_policy_hash"] != self._policy_hash:
                raise MirrorBindingError("mirror_completed_policy_mismatch")
            evidence = bytes(row["evidence_bytes"])
            if hashlib.sha256(evidence).hexdigest() != row["evidence_sha256"]:
                raise MirrorBindingError("mirror_completed_evidence_tampered")
            parsed_evidence = self._parse_retrieval_evidence(evidence, work)
            self._reconcile_completed_package(connection, parsed_evidence)
            index_row = connection.execute(
                "SELECT * FROM objects WHERE sha256 = ?", (row["index_sha256"],)
            ).fetchone()
            if index_row is None:
                raise MirrorBindingError("mirror_completed_index_missing")
            index_bytes = _verify_object_row(
                index_row,
                row["index_sha256"],
                row["index_size_bytes"],
                "application/json",
            )
            index = _parse_canonical_model(
                index_bytes,
                MirrorWindowIndex,
                maximum_bytes=self.policy.limits.maximum_manifest_bytes,
                reason_code="mirror_index_not_canonical",
            )
            self._validate_index(index, work)
            by_key = {item.resource_key_sha256: item for item in parsed_evidence.retrieved_objects}
            fetched: list[tuple[MirrorObjectDescriptor, _FetchedObject]] = []
            for descriptor in index.objects:
                key_hash = hashlib.sha256(descriptor.resource_key.encode()).hexdigest()
                record = by_key.get(key_hash)
                if record is None or record.sha256 != descriptor.sha256:
                    raise MirrorBindingError("mirror_completed_object_index_mismatch")
                object_row = connection.execute(
                    "SELECT * FROM objects WHERE sha256 = ?", (descriptor.sha256,)
                ).fetchone()
                if object_row is None:
                    raise MirrorBindingError("mirror_completed_object_missing")
                data = _verify_object_row(
                    object_row,
                    descriptor.sha256,
                    descriptor.size_bytes,
                    descriptor.media_type,
                )
                fetched.append(
                    (
                        descriptor,
                        _FetchedObject(
                            descriptor.resource_key,
                            data,
                            descriptor.media_type,
                            record.selected_origin,
                            record.selected_origin + descriptor.path,
                        ),
                    )
                )
            return self._package_from_material(index, tuple(fetched), evidence)

    def _parse_retrieval_evidence(
        self,
        evidence: bytes,
        work: StageWorkItem,
    ) -> MirrorRetrievalEvidence:
        model = _parse_canonical_model(
            evidence,
            MirrorRetrievalEvidence,
            maximum_bytes=64 * 1024 * 1024,
            reason_code="mirror_retrieval_evidence_not_canonical",
        )
        if (
            model.window_id != work.window.plan.window_id
            or model.window_index != work.window.plan.window_index
            or model.scoring_policy_hash != self._policy_hash
            or model.discovery_rule_sha256 != self._discovery_hash
            or model.authentication_profile != self.discovery.authentication_profile
        ):
            raise MirrorBindingError("mirror_retrieval_evidence_binding_mismatch")
        if any(
            item.selected_origin not in self.discovery.origins for item in model.retrieved_objects
        ):
            raise MirrorBindingError("mirror_retrieval_origin_not_pinned")
        return model

    def _initialize(self) -> None:
        with self._connection() as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise MirrorRetrievalError("mirror_sqlite_wal_unavailable")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS windows (
                    window_id TEXT PRIMARY KEY,
                    window_index INTEGER NOT NULL,
                    scoring_policy_hash TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
                    observed_wire_bytes INTEGER NOT NULL CHECK(observed_wire_bytes >= 0),
                    accounted_wire_bytes INTEGER NOT NULL CHECK(accounted_wire_bytes >= 0)
                ) STRICT;
                CREATE TABLE IF NOT EXISTS attempts (
                    window_id TEXT NOT NULL REFERENCES windows(window_id),
                    resource_key TEXT NOT NULL,
                    attempt_index INTEGER NOT NULL CHECK(attempt_index >= 0),
                    url_sha256 TEXT NOT NULL,
                    selected_origin TEXT,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'failed', 'success')),
                    observed_wire_bytes INTEGER NOT NULL CHECK(observed_wire_bytes >= 0),
                    accounted_wire_bytes INTEGER NOT NULL CHECK(accounted_wire_bytes > 0),
                    error_code TEXT,
                    response_body_sha256 TEXT,
                    response_body_size_bytes INTEGER NOT NULL CHECK(response_body_size_bytes >= 0),
                    object_sha256 TEXT,
                    object_size_bytes INTEGER,
                    media_type TEXT,
                    PRIMARY KEY(window_id, resource_key, attempt_index)
                ) STRICT;
                CREATE TABLE IF NOT EXISTS objects (
                    sha256 TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
                    media_type TEXT NOT NULL,
                    data BLOB NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS packages (
                    window_id TEXT PRIMARY KEY REFERENCES windows(window_id),
                    scoring_policy_hash TEXT NOT NULL,
                    index_sha256 TEXT NOT NULL,
                    index_size_bytes INTEGER NOT NULL CHECK(index_size_bytes > 0),
                    evidence_sha256 TEXT NOT NULL,
                    evidence_bytes BLOB NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS delivery_requests (
                    window_id TEXT PRIMARY KEY REFERENCES windows(window_id),
                    request_sha256 TEXT NOT NULL,
                    request_bytes BLOB NOT NULL
                ) STRICT;
                """
            )
            expected = {
                "schema_version": _SCHEMA_VERSION,
                "scoring_policy_hash": self._policy_hash,
                "discovery_rule_sha256": self._discovery_hash,
            }
            for key, value in expected.items():
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO metadata (key, value) VALUES (?, ?)", (key, value)
                    )
                elif row["value"] != value:
                    raise MirrorBindingError("mirror_store_identity_conflict")

    def _audit_persisted_state(self) -> None:
        with self._connection() as connection:
            quick = connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick != "ok":
                raise MirrorRetrievalError("mirror_store_quick_check_failed")
            windows = connection.execute("SELECT * FROM windows ORDER BY window_id").fetchall()
            if len(windows) > self._maximum_windows:
                raise MirrorLimitError("mirror_persisted_window_count_limit")
            objects = connection.execute("SELECT * FROM objects ORDER BY sha256").fetchall()
            total = 0
            for row in objects:
                data = _verify_object_row(
                    row,
                    row["sha256"],
                    row["size_bytes"],
                    row["media_type"],
                )
                total += len(data)
                if total > self._maximum_cache_bytes:
                    raise MirrorLimitError("mirror_persisted_cache_size_limit")
            for window in windows:
                attempts = connection.execute(
                    "SELECT * FROM attempts WHERE window_id = ?", (window["window_id"],)
                ).fetchall()
                if len(attempts) != window["attempt_count"]:
                    raise MirrorBindingError("mirror_attempt_counter_mismatch")
                observed = sum(row["observed_wire_bytes"] for row in attempts)
                accounted = sum(row["accounted_wire_bytes"] for row in attempts)
                if (
                    observed != window["observed_wire_bytes"]
                    or accounted != window["accounted_wire_bytes"]
                ):
                    raise MirrorBindingError("mirror_wire_counter_mismatch")
                if accounted > self.policy.limits.maximum_validator_window_wire_bytes:
                    raise MirrorLimitError("mirror_persisted_window_wire_limit")
                per_resource: dict[str, int] = {}
                for attempt in attempts:
                    per_resource[attempt["resource_key"]] = (
                        per_resource.get(attempt["resource_key"], 0) + 1
                    )
                    body_digest = attempt["response_body_sha256"]
                    body_size = attempt["response_body_size_bytes"]
                    if (body_digest is None and body_size != 0) or (
                        body_digest is not None and _HEX32_RE.fullmatch(body_digest) is None
                    ):
                        raise MirrorBindingError("mirror_attempt_response_evidence_invalid")
                    if attempt["status"] == "success":
                        digest = attempt["object_sha256"]
                        if (
                            attempt["error_code"] is not None
                            or attempt["selected_origin"] not in self.discovery.origins
                            or body_digest != digest
                            or body_size != attempt["object_size_bytes"]
                        ):
                            raise MirrorBindingError("mirror_success_attempt_state_invalid")
                        object_row = connection.execute(
                            "SELECT * FROM objects WHERE sha256 = ?", (digest,)
                        ).fetchone()
                        if object_row is None:
                            raise MirrorBindingError("mirror_success_object_missing")
                        _verify_object_row(
                            object_row,
                            digest,
                            attempt["object_size_bytes"],
                            attempt["media_type"],
                        )
                    elif (
                        attempt["selected_origin"] is not None
                        or attempt["object_sha256"] is not None
                        or attempt["object_size_bytes"] is not None
                        or attempt["media_type"] is not None
                        or (attempt["status"] == "failed") != (attempt["error_code"] is not None)
                    ):
                        raise MirrorBindingError("mirror_non_success_attempt_state_invalid")
                if any(
                    count > self.policy.limits.maximum_video_fetch_attempts_per_actor
                    for count in per_resource.values()
                ):
                    raise MirrorLimitError("mirror_persisted_attempt_count_limit")
            delivery_requests = connection.execute(
                "SELECT * FROM delivery_requests ORDER BY window_id"
            ).fetchall()
            window_by_id = {row["window_id"]: row for row in windows}
            for row in delivery_requests:
                request_bytes = bytes(row["request_bytes"])
                window = window_by_id.get(row["window_id"])
                if (
                    window is None
                    or not request_bytes
                    or len(request_bytes) > self.policy.limits.maximum_manifest_bytes
                    or hashlib.sha256(request_bytes).hexdigest() != row["request_sha256"]
                ):
                    raise MirrorBindingError("delivery_request_store_invalid")
                request = _parse_canonical_model(
                    request_bytes,
                    VideoDeliveryIssuanceRequest,
                    maximum_bytes=self.policy.limits.maximum_manifest_bytes,
                    reason_code="delivery_request_store_invalid",
                )
                if (
                    request.window_id != row["window_id"]
                    or request.window_index != window["window_index"]
                    or request.scoring_policy_hash != self._policy_hash
                ):
                    raise MirrorBindingError("delivery_request_store_binding_invalid")
            packages = connection.execute("SELECT * FROM packages ORDER BY window_id").fetchall()
            for package in packages:
                evidence = bytes(package["evidence_bytes"])
                if hashlib.sha256(evidence).hexdigest() != package["evidence_sha256"]:
                    raise MirrorBindingError("mirror_completed_evidence_tampered")
                parsed = _parse_canonical_model(
                    evidence,
                    MirrorRetrievalEvidence,
                    maximum_bytes=64 * 1024 * 1024,
                    reason_code="mirror_retrieval_evidence_not_canonical",
                )
                self._reconcile_completed_package(connection, parsed)
                window = connection.execute(
                    "SELECT * FROM windows WHERE window_id = ?", (package["window_id"],)
                ).fetchone()
                if (
                    window is None
                    or parsed.window_id != package["window_id"]
                    or parsed.window_index != window["window_index"]
                    or parsed.scoring_policy_hash != self._policy_hash
                    or parsed.discovery_rule_sha256 != self._discovery_hash
                    or parsed.index_sha256 != package["index_sha256"]
                    or parsed.index_size_bytes != package["index_size_bytes"]
                ):
                    raise MirrorBindingError("mirror_completed_package_binding_mismatch")
                index_row = connection.execute(
                    "SELECT * FROM objects WHERE sha256 = ?", (package["index_sha256"],)
                ).fetchone()
                if index_row is None:
                    raise MirrorBindingError("mirror_completed_index_missing")
                _verify_object_row(
                    index_row,
                    package["index_sha256"],
                    package["index_size_bytes"],
                    "application/json",
                )

    def _delivery_attempt_accounting(
        self,
        window_id: str,
        resource_key: str,
        *,
        response_sha256: str,
        response_size_bytes: int,
    ) -> tuple[tuple[VideoDeliveryAttemptEvidence, ...], int, int, int, int]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE window_id = ? AND resource_key = ? "
                "ORDER BY attempt_index",
                (window_id, resource_key),
            ).fetchall()
            counters = connection.execute(
                "SELECT observed_wire_bytes, accounted_wire_bytes FROM windows WHERE window_id = ?",
                (window_id,),
            ).fetchone()
        if counters is None or not rows:
            raise MirrorBindingError("delivery_attempt_accounting_missing")
        if [row["attempt_index"] for row in rows] != list(range(len(rows))):
            raise MirrorBindingError("delivery_attempt_indices_invalid")
        if sum(row["status"] == "success" for row in rows) != 1 or rows[-1]["status"] != "success":
            raise MirrorBindingError("delivery_success_attempt_cardinality_invalid")
        success = rows[-1]
        if (
            success["object_sha256"] != response_sha256
            or success["object_size_bytes"] != response_size_bytes
            or success["response_body_sha256"] != response_sha256
            or success["response_body_size_bytes"] != response_size_bytes
        ):
            raise MirrorBindingError("delivery_success_response_evidence_mismatch")
        attempts = tuple(
            VideoDeliveryAttemptEvidence(
                attempt_index=row["attempt_index"],
                url_sha256=row["url_sha256"],
                status=("pending_after_restart" if row["status"] == "pending" else row["status"]),
                observed_wire_bytes=row["observed_wire_bytes"],
                accounted_wire_bytes=row["accounted_wire_bytes"],
                error_code=(
                    "delivery_issuance_interrupted"
                    if row["status"] == "pending"
                    else row["error_code"]
                ),
                response_body_sha256=row["response_body_sha256"],
                response_body_size_bytes=row["response_body_size_bytes"],
            )
            for row in rows
        )
        return (
            attempts,
            sum(row["observed_wire_bytes"] for row in rows),
            sum(row["accounted_wire_bytes"] for row in rows),
            counters["observed_wire_bytes"],
            counters["accounted_wire_bytes"],
        )

    def _load_or_create_delivery_request(
        self,
        work: StageWorkItem,
        context: DeliveryIssuanceContext,
    ) -> tuple[VideoDeliveryIssuanceRequest, bytes]:
        window_id = work.window.plan.window_id
        with self._transaction() as connection:
            completed = connection.execute(
                "SELECT 1 FROM packages WHERE window_id = ?", (window_id,)
            ).fetchone()
            if completed is not None:
                raise MirrorBindingError("mirror_package_completed_during_retrieval")
            row = connection.execute(
                "SELECT request_sha256, request_bytes FROM delivery_requests WHERE window_id = ?",
                (window_id,),
            ).fetchone()
            if row is None:
                window = connection.execute(
                    "SELECT window_index, scoring_policy_hash FROM windows WHERE window_id = ?",
                    (window_id,),
                ).fetchone()
                if window is None:
                    count = connection.execute("SELECT COUNT(*) FROM windows").fetchone()[0]
                    if count >= self._maximum_windows:
                        raise MirrorLimitError("mirror_window_count_limit")
                    connection.execute(
                        "INSERT INTO windows (window_id, window_index, scoring_policy_hash, "
                        "attempt_count, observed_wire_bytes, accounted_wire_bytes) "
                        "VALUES (?, ?, ?, 0, 0, 0)",
                        (window_id, work.window.plan.window_index, self._policy_hash),
                    )
                elif (
                    window["window_index"] != work.window.plan.window_index
                    or window["scoring_policy_hash"] != self._policy_hash
                ):
                    raise MirrorBindingError("mirror_window_identity_conflict")
                request = build_delivery_request(
                    context.window,
                    context.selected_video_commitments,
                    delivery_token_seed=base64url_encode(secrets.token_bytes(32)),
                )
                request_bytes = canonical_json_bytes(request)
                if len(request_bytes) > self.policy.limits.maximum_manifest_bytes:
                    raise MirrorLimitError("delivery_issuance_request_size_limit")
                request_digest = hashlib.sha256(request_bytes).hexdigest()
                connection.execute(
                    "INSERT INTO delivery_requests "
                    "(window_id, request_sha256, request_bytes) VALUES (?, ?, ?)",
                    (window_id, request_digest, request_bytes),
                )
                return request, request_bytes

            request_bytes = bytes(row["request_bytes"])
            if hashlib.sha256(request_bytes).hexdigest() != row["request_sha256"]:
                raise MirrorBindingError("delivery_request_store_invalid")
            request = _parse_canonical_model(
                request_bytes,
                VideoDeliveryIssuanceRequest,
                maximum_bytes=self.policy.limits.maximum_manifest_bytes,
                reason_code="delivery_request_store_invalid",
            )
            expected = build_delivery_request(
                context.window,
                context.selected_video_commitments,
                delivery_token_seed=request.delivery_token_seed,
            )
            if request != expected:
                raise MirrorBindingError("delivery_request_context_conflict")
            return request, request_bytes

    def _delivery_resume_origin_index(self, window_id: str, resource_key: str) -> int:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT attempt_index, url_sha256, status FROM attempts "
                "WHERE window_id = ? AND resource_key = ? ORDER BY attempt_index",
                (window_id, resource_key),
            ).fetchall()
        if [row["attempt_index"] for row in rows] != list(range(len(rows))):
            raise MirrorBindingError("delivery_attempt_indices_invalid")
        if any(row["status"] == "success" for row in rows):
            raise MirrorBindingError("delivery_cached_success_lookup_conflict")
        if len(rows) > len(self.discovery.origins):
            raise MirrorBindingError("delivery_attempt_origin_count_invalid")
        expected_hashes = [
            hashlib.sha256(
                (origin + self.discovery.delivery_issuance_path).encode("utf-8")
            ).hexdigest()
            for origin in self.discovery.origins[: len(rows)]
        ]
        if [row["url_sha256"] for row in rows] != expected_hashes:
            raise MirrorBindingError("delivery_attempt_origin_history_invalid")
        return len(rows)

    async def _acquire_collection_lease(self) -> _MirrorDeliveryLease:
        while True:
            lease = self._try_collection_lease()
            if lease is not None:
                return lease
            # Nonblocking flock plus an async retry keeps another process from
            # blocking this event loop. Cancellation while waiting owns no lease.
            await asyncio.sleep(0.05)

    def _try_collection_lease(self) -> _MirrorDeliveryLease | None:
        return self._try_kernel_lease(
            suffix="collection",
            unsafe_code="mirror_collection_lease_path_unsafe",
            open_code="mirror_collection_lease_open_failed",
            acquisition_code="mirror_collection_lease_acquisition_failed",
        )

    def _try_delivery_lease(self) -> _MirrorDeliveryLease | None:
        return self._try_kernel_lease(
            suffix="delivery",
            unsafe_code="delivery_issuance_lease_path_unsafe",
            open_code="delivery_issuance_lease_open_failed",
            acquisition_code="delivery_issuance_lease_acquisition_failed",
        )

    def _try_kernel_lease(
        self,
        *,
        suffix: str,
        unsafe_code: str,
        open_code: str,
        acquisition_code: str,
    ) -> _MirrorDeliveryLease | None:
        path = Path(f"{self._path}.{suffix}.lock")
        if os.path.lexists(path) and path.is_symlink():
            raise MirrorBindingError(unsafe_code)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as error:
            raise MirrorBindingError(open_code) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid()
            ):
                raise MirrorBindingError(unsafe_code)
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    os.close(descriptor)
                    return None
                raise MirrorBindingError(acquisition_code) from error
            return _MirrorDeliveryLease(descriptor)
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        _reject_database_symlinks(self._path)
        connection = sqlite3.connect(
            self._path,
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        _reject_database_symlinks(self._path)
        with suppress(OSError):
            for suffix in ("", "-wal", "-shm"):
                os.chmod(Path(f"{self._path}{suffix}"), 0o600, follow_symlinks=False)
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            connection.close()
            raise MirrorRetrievalError("mirror_sqlite_foreign_keys_unavailable")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            connection.close()
            raise MirrorRetrievalError("mirror_sqlite_full_sync_unavailable")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")


@dataclass(frozen=True, slots=True)
class AuthenticatedMirrorDeliveryIssuer:
    """Issue credential-free miner URLs through the authenticated mirror API."""

    policy: ScoringPolicy
    source: DurablePoolMirrorSource

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ScoringPolicy):
            raise TypeError("delivery issuer policy must be ScoringPolicy")
        if not isinstance(self.source, DurablePoolMirrorSource):
            raise TypeError("delivery issuer requires DurablePoolMirrorSource")
        if self.source.policy != self.policy:
            raise ValueError("delivery issuer source is bound to another policy")

    async def __call__(
        self,
        context: DeliveryIssuanceContext,
        work: StageWorkItem,
    ) -> IssuedVideoDeliverySet:
        if not isinstance(context, DeliveryIssuanceContext):
            raise TypeError("delivery issuer context has another type")
        if (
            not isinstance(work, StageWorkItem)
            or work.stage is not WindowStage.POOL_AND_SELECTION
            or work.window.plan != context.window
            or context.window.scoring_policy_hash != scoring_policy_hash(self.policy)
        ):
            raise MirrorBindingError("delivery_issuance_work_mismatch")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.source._timeout * len(self.source.discovery.origins) + 5
        lease: _MirrorDeliveryLease | None = None
        while lease is None:
            lease = self.source._try_delivery_lease()
            if lease is not None:
                break
            if loop.time() >= deadline:
                raise MirrorRetrievalError("delivery_issuance_lease_busy")
            await asyncio.sleep(0.05)
        try:
            return await self._issue_exclusive(context, work)
        finally:
            lease.release()

    async def _issue_exclusive(
        self,
        context: DeliveryIssuanceContext,
        work: StageWorkItem,
    ) -> IssuedVideoDeliverySet:
        # These SQLite operations are intentionally synchronous while the kernel
        # lease is held. A cancelled ``asyncio.to_thread`` keeps running after its
        # awaiter exits, which could otherwise mutate the store after lease release.
        request, request_bytes = self.source._load_or_create_delivery_request(
            work,
            context,
        )
        maximum = self.policy.limits.maximum_manifest_bytes
        if len(request_bytes) > maximum:
            raise MirrorLimitError("delivery_issuance_request_size_limit")
        request_digest = hashlib.sha256(request_bytes).hexdigest()
        resource_key = f"delivery-issuance:{request_digest}"
        cached = self.source._load_successful_resource(
            context.window.window_id,
            resource_key,
            None,
            None,
            "application/json",
        )
        if cached is None:
            fetched = await self._issue_from_origins(
                work=work,
                context=context,
                request=request,
                resource_key=resource_key,
                request_bytes=request_bytes,
                maximum_response_bytes=maximum,
            )
            response_bytes = fetched.data
            issuance_origin = fetched.selected_origin
        else:
            response_bytes = cached.data
            issuance_origin = cached.selected_origin
        try:
            response = parse_canonical_delivery_model(
                response_bytes,
                VideoDeliveryIssuanceResponse,
                maximum_bytes=maximum,
                label="video delivery issuance response",
            )
        except (TypeError, ValueError) as error:
            raise MirrorBindingError("delivery_issuance_response_invalid") from error
        response_digest = hashlib.sha256(response_bytes).hexdigest()
        (
            attempts,
            delivery_observed,
            delivery_accounted,
            window_observed,
            window_accounted,
        ) = self.source._delivery_attempt_accounting(
            context.window.window_id,
            resource_key,
            response_sha256=response_digest,
            response_size_bytes=len(response_bytes),
        )
        evidence = VideoDeliveryIssuanceEvidence(
            schema=DELIVERY_ISSUANCE_EVIDENCE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=context.window.window_id,
            window_index=context.window.window_index,
            scoring_policy_hash=context.window.scoring_policy_hash,
            discovery_rule_sha256=self.source._discovery_hash,
            authentication_profile=self.source.discovery.authentication_profile,
            issuance_origin=issuance_origin,
            issuance_path=self.source.discovery.delivery_issuance_path,
            request_sha256=request_digest,
            request_size_bytes=len(request_bytes),
            response_sha256=response_digest,
            response_size_bytes=len(response_bytes),
            attempts=list(attempts),
            delivery_observed_wire_bytes=delivery_observed,
            delivery_accounted_wire_bytes=delivery_accounted,
            observed_window_wire_bytes=window_observed,
            accounted_window_wire_bytes=window_accounted,
        )
        result = IssuedVideoDeliverySet(
            deliveries=tuple(response.deliveries),
            discovery_rule_bytes=self.source._discovery_bytes,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            evidence_bytes=canonical_json_bytes(evidence),
        )
        try:
            validate_delivery_issuance(
                policy=self.policy,
                window=context.window,
                expected_commitments=context.selected_video_commitments,
                result=result,
            )
        except (TypeError, ValueError) as error:
            raise MirrorBindingError("delivery_issuance_response_invalid") from error
        return result

    async def _issue_from_origins(
        self,
        *,
        work: StageWorkItem,
        context: DeliveryIssuanceContext,
        request: VideoDeliveryIssuanceRequest,
        resource_key: str,
        request_bytes: bytes,
        maximum_response_bytes: int,
    ) -> _FetchedObject:
        last_error: MirrorRetrievalError | None = None
        resume_index = self.source._delivery_resume_origin_index(
            work.window.plan.window_id,
            resource_key,
        )
        for origin in self.source.discovery.origins[resume_index:]:
            url = origin + self.source.discovery.delivery_issuance_path
            reservation = (
                len(request_bytes)
                + maximum_response_bytes
                + 2 * self.policy.limits.maximum_http_header_bytes
                + MAX_MIRROR_URL_BYTES
                + 64
            )
            try:
                attempt_index = self.source._reserve_attempt(
                    work,
                    resource_key,
                    url,
                    reservation,
                )
            except MirrorLimitError as error:
                last_error = error
                break
            try:
                response_bytes, observed = await self._post_canonical(
                    url,
                    request_bytes=request_bytes,
                    maximum_response_bytes=maximum_response_bytes,
                )
            except MirrorRetrievalError as error:
                self.source._finish_failed_attempt(
                    work.window.plan.window_id,
                    resource_key,
                    attempt_index,
                    error.reason_code,
                    error.observed_wire_bytes,
                    error.response_body_sha256,
                    error.response_body_size_bytes,
                )
                last_error = error
                continue
            try:
                response = parse_canonical_delivery_model(
                    response_bytes,
                    VideoDeliveryIssuanceResponse,
                    maximum_bytes=maximum_response_bytes,
                    label="video delivery issuance response",
                )
                validate_delivery_response(
                    policy=self.policy,
                    window=context.window,
                    discovery=self.source.discovery,
                    request=request,
                    response=response,
                    expected_commitments=context.selected_video_commitments,
                )
            except (TypeError, ValueError):
                failed = MirrorBindingError(
                    "delivery_issuance_response_invalid",
                    observed_wire_bytes=observed,
                    response_body_sha256=hashlib.sha256(response_bytes).hexdigest(),
                    response_body_size_bytes=len(response_bytes),
                )
                self.source._finish_failed_attempt(
                    work.window.plan.window_id,
                    resource_key,
                    attempt_index,
                    failed.reason_code,
                    failed.observed_wire_bytes,
                    failed.response_body_sha256,
                    failed.response_body_size_bytes,
                )
                last_error = failed
                continue
            fetched = _FetchedObject(
                resource_key=resource_key,
                data=response_bytes,
                media_type="application/json",
                selected_origin=origin,
                selected_url=url,
            )
            self.source._finish_successful_attempt(
                work.window.plan.window_id,
                resource_key,
                attempt_index,
                fetched,
                observed,
            )
            return fetched
        if last_error is not None:
            raise last_error
        raise MirrorRetrievalError("delivery_issuance_origins_exhausted")

    async def _post_canonical(
        self,
        url: str,
        *,
        request_bytes: bytes,
        maximum_response_bytes: int,
    ) -> tuple[bytes, int]:
        parsed = urlsplit(url)
        origin = _mirror_origin_from_url(
            url,
            allow_http_for_tests=self.source._allow_http_for_tests,
        )
        if origin not in self.source.discovery.origins:
            raise MirrorBindingError("delivery_issuance_origin_not_pinned")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        expected_port = 443 if parsed.scheme == "https" else 80
        actual_port = parsed.port or expected_port
        address = await _resolve_public_address(
            hostname,
            actual_port,
            resolver=self.source._resolver,
        )
        request_url = httpx.URL(url).copy_with(host=address)
        authority_host = f"[{hostname}]" if ":" in hostname else hostname
        host_header = (
            authority_host if actual_port == expected_port else f"{authority_host}:{actual_port}"
        )
        headers = {
            **self.source._headers_for_origin(origin),
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
            "Host": host_header,
        }
        if _mapping_header_size(headers) > self.policy.limits.maximum_http_header_bytes:
            raise MirrorLimitError("delivery_issuance_request_header_size_limit")
        request_header_bytes = 0
        response_header_bytes = 0
        body = bytearray()
        try:
            async with (
                httpx.AsyncClient(
                    timeout=httpx.Timeout(self.source._timeout),
                    follow_redirects=False,
                    transport=self.source._transport,
                    trust_env=False,
                ) as client,
                client.stream(
                    "POST",
                    request_url,
                    headers=headers,
                    content=request_bytes,
                    extensions={"sni_hostname": hostname},
                ) as response,
            ):
                request_header_bytes = _request_header_accounting(
                    response.request.url,
                    response.request.headers,
                    method="POST",
                )
                response_header_bytes = _raw_header_size(response.headers)
                if response_header_bytes > self.policy.limits.maximum_http_header_bytes:
                    raise MirrorLimitError("delivery_issuance_response_header_size_limit")
                if response.status_code != 200:
                    raise MirrorRetrievalError("delivery_issuance_http_status_invalid")
                encoding = response.headers.get("content-encoding", "").strip().lower()
                if encoding not in {"", "identity"}:
                    raise MirrorBindingError("delivery_issuance_content_encoding_invalid")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
                if content_type != "application/json":
                    raise MirrorBindingError("delivery_issuance_content_type_invalid")
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        content_length = int(declared)
                    except ValueError as error:
                        raise MirrorBindingError(
                            "delivery_issuance_content_length_invalid"
                        ) from error
                    if not 0 < content_length <= maximum_response_bytes:
                        raise MirrorLimitError("delivery_issuance_declared_body_size_limit")
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > maximum_response_bytes:
                        raise MirrorLimitError("delivery_issuance_streamed_body_size_limit")
                    body.extend(chunk)
        except MirrorRetrievalError as error:
            error.observed_wire_bytes = (
                request_header_bytes + len(request_bytes) + response_header_bytes + len(body)
            )
            error.response_body_sha256 = hashlib.sha256(body).hexdigest() if body else None
            error.response_body_size_bytes = len(body)
            raise
        except httpx.TimeoutException as error:
            raise MirrorRetrievalError(
                "delivery_issuance_timeout",
                observed_wire_bytes=(
                    request_header_bytes + len(request_bytes) + response_header_bytes + len(body)
                ),
                response_body_sha256=(hashlib.sha256(body).hexdigest() if body else None),
                response_body_size_bytes=len(body),
            ) from error
        except httpx.HTTPError as error:
            raise MirrorRetrievalError(
                "delivery_issuance_transport_failed",
                observed_wire_bytes=(
                    request_header_bytes + len(request_bytes) + response_header_bytes + len(body)
                ),
                response_body_sha256=(hashlib.sha256(body).hexdigest() if body else None),
                response_body_size_bytes=len(body),
            ) from error
        data = bytes(body)
        if not data:
            raise MirrorBindingError(
                "delivery_issuance_response_empty",
                observed_wire_bytes=(
                    request_header_bytes + len(request_bytes) + response_header_bytes
                ),
            )
        return (
            data,
            request_header_bytes + len(request_bytes) + response_header_bytes + len(data),
        )


@dataclass(frozen=True, slots=True)
class QuicknetSelectionPulseAdapter:
    """Fetch and canonicalize the exact verified selection pulse."""

    policy: ScoringPolicy
    client: QuicknetClient

    def __post_init__(self) -> None:
        _validate_quicknet_adapter(self.policy, self.client)

    async def __call__(self, work: StageWorkItem) -> bytes:
        _validate_pulse_work(work, self.policy, WindowStage.POOL_AND_SELECTION)
        pulse = await _fetch_quicknet(self.client, work.window.plan.selection_round, "selection")
        return _pulse_bytes(pulse)


@dataclass(frozen=True, slots=True)
class QuicknetRevealPulseAdapter:
    """Fetch and canonicalize the exact verified ground-truth reveal pulse."""

    policy: ScoringPolicy
    client: QuicknetClient

    def __post_init__(self) -> None:
        _validate_quicknet_adapter(self.policy, self.client)

    async def __call__(self, work: StageWorkItem) -> bytes:
        _validate_pulse_work(work, self.policy, WindowStage.REVEAL_AND_SCORE)
        pulse = await _fetch_quicknet(self.client, work.window.plan.reveal_round, "reveal")
        return _pulse_bytes(pulse)


@dataclass(frozen=True, slots=True)
class TLERevealDecryptAdapter:
    """Open one already committed timelock only with its verified reveal pulse."""

    policy: ScoringPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ScoringPolicy):
            raise TypeError("timelock decrypt policy must be ScoringPolicy")
        _validate_quicknet_policy(self.policy)

    async def __call__(self, sealed: SealedResponse, pulse: DrandPulse) -> bytes:
        if not isinstance(sealed, SealedResponse) or not isinstance(pulse, DrandPulse):
            raise TypeError("timelock decrypt requires SealedResponse and DrandPulse")
        try:
            pulse.verify()
        except DrandVerificationError as error:
            raise TimelockRevealPortError("timelock_reveal_pulse_invalid") from error
        if pulse.round != sealed.reveal_round:
            raise TimelockRevealPortError("timelock_reveal_round_mismatch")
        try:
            return await asyncio.to_thread(
                decrypt_response,
                sealed,
                reveal_round=sealed.reveal_round,
                sha256_hex=sealed.sha256_hex,
                wait=False,
                timeout=None,
            )
        except (TypeError, ValueError) as error:
            raise TimelockRevealPortError("timelock_reveal_binding_invalid") from error


class RevealAuditReleaseBoundary(StrictProtocolModel):
    """Claim produced by the schedule/proof collector for pre-commit release."""

    schema_: Literal[REVEAL_RELEASE_BOUNDARY_SCHEMA] = Field(alias="schema")
    window_id: Hex32
    scoring_policy_hash: Hex32
    reason_code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")]
    audit_release_block: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    derivation_profile: Literal["umi-weight-commit-close-boundary/1"]
    derivation_evidence_sha256: Hex32


@dataclass(frozen=True, slots=True)
class VerifiedRevealAuditReleaseBoundary:
    """Typed boundary plus exact schedule/finality derivation evidence."""

    fact: RevealAuditReleaseBoundary
    evidence_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.fact, RevealAuditReleaseBoundary):
            raise TypeError("reveal release boundary fact has another type")
        if (
            not isinstance(self.evidence_bytes, bytes)
            or not self.evidence_bytes
            or len(self.evidence_bytes) > MAX_RELEASE_BOUNDARY_EVIDENCE_BYTES
        ):
            raise ValueError("reveal release boundary evidence has an invalid size")
        if hashlib.sha256(self.evidence_bytes).hexdigest() != (
            self.fact.derivation_evidence_sha256
        ):
            raise ValueError("reveal release boundary evidence digest does not reproduce")


class RevealAuditReleaseBoundaryPort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
        reason_code: str,
    ) -> VerifiedRevealAuditReleaseBoundary | Awaitable[VerifiedRevealAuditReleaseBoundary]: ...


@dataclass(frozen=True, slots=True)
class ProofBackedRevealAuditReleaseBoundaryPort:
    """Derive a reveal-void release boundary from the common weight schedule."""

    policy: ScoringPolicy
    schedule: WeightSchedulePort

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ScoringPolicy) or self.policy.translation_weights_active:
            raise ValueError("reveal release boundary requires an inactive scoring policy")
        if not callable(self.schedule):
            raise TypeError("reveal release boundary requires a schedule port")

    async def __call__(
        self,
        work: StageWorkItem,
        reason_code: str,
    ) -> VerifiedRevealAuditReleaseBoundary:
        if not isinstance(work, StageWorkItem) or work.stage is not WindowStage.REVEAL_AND_SCORE:
            raise RevealAuditReleasePortError("reveal_release_boundary_wrong_stage")
        reason_code = _reason_code(reason_code)
        value = self.schedule(work)
        if isinstance(value, Awaitable):
            value = await value
        if not isinstance(value, WeightScheduleCapture):
            raise RevealAuditReleasePortError("reveal_release_schedule_capture_invalid")
        material = materialize_weight_schedule_evidence(
            value,
            work=work,
            policy=self.policy,
        )
        if isinstance(material, WeightCommitSchedulePending):
            raise StagePending(f"reveal_release_{material.reason_code}")
        if len(material.evidence_bytes) > MAX_RELEASE_BOUNDARY_EVIDENCE_BYTES:
            raise RevealAuditReleasePortError("reveal_release_boundary_evidence_size_limit")
        policy_hash = scoring_policy_hash(self.policy)
        evidence_digest = hashlib.sha256(material.evidence_bytes).hexdigest()
        return VerifiedRevealAuditReleaseBoundary(
            fact=RevealAuditReleaseBoundary(
                schema=REVEAL_RELEASE_BOUNDARY_SCHEMA,
                window_id=work.window.plan.window_id,
                scoring_policy_hash=policy_hash,
                reason_code=reason_code,
                audit_release_block=(
                    material.schedule.weight_commit_close_block.snapshot.block_number
                ),
                derivation_profile="umi-weight-commit-close-boundary/1",
                derivation_evidence_sha256=evidence_digest,
            ),
            evidence_bytes=material.evidence_bytes,
        )


class VerifiedFinalityReadPort(Protocol):
    @property
    def chain_observation(self): ...

    @property
    def finality_verifier_sha256(self) -> str: ...

    async def finalized_head_height(self) -> int: ...

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None: ...


@dataclass(frozen=True, slots=True)
class FinalizedRevealAuditReleaseAdapter:
    """Observe the exact schedule-derived audit release block through GRANDPA."""

    policy: ScoringPolicy
    finality: VerifiedFinalityReadPort
    boundary: RevealAuditReleaseBoundaryPort

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ScoringPolicy):
            raise TypeError("audit-release policy must be ScoringPolicy")
        if not callable(self.boundary):
            raise TypeError("audit-release boundary port must be callable")
        for name in ("finalized_head_height", "verified_block_at"):
            if not callable(getattr(self.finality, name, None)):
                raise TypeError("audit-release finality port lacks required methods")
        pins = self.policy.implementation_pins
        if pins.live_chain is None or pins.finality_verifier is None:
            raise ValueError("audit-release observation requires live finality policy pins")
        if getattr(self.finality, "chain_observation", None) != pins.live_chain:
            raise ValueError("audit-release finality port names another chain")
        digest = getattr(self.finality, "finality_verifier_sha256", None)
        if digest not in pins.finality_verifier.release_sha256_by_target.values():
            raise ValueError("audit-release finality verifier is absent from policy pins")

    async def __call__(
        self,
        work: StageWorkItem,
        reason_code: str,
    ) -> VerifiedRevealAuditRelease:
        if not isinstance(work, StageWorkItem) or work.stage is not WindowStage.REVEAL_AND_SCORE:
            raise RevealAuditReleasePortError("reveal_audit_release_wrong_stage")
        policy_hash = scoring_policy_hash(self.policy)
        if work.window.plan.scoring_policy_hash != policy_hash:
            raise RevealAuditReleasePortError("reveal_audit_release_policy_mismatch")
        reason_code = _reason_code(reason_code)
        value = self.boundary(work, reason_code)
        if isinstance(value, Awaitable):
            value = await value
        if not isinstance(value, VerifiedRevealAuditReleaseBoundary):
            raise RevealAuditReleasePortError("reveal_release_boundary_invalid")
        boundary = value.fact
        if (
            boundary.window_id != work.window.plan.window_id
            or boundary.scoring_policy_hash != policy_hash
            or boundary.reason_code != reason_code
        ):
            raise RevealAuditReleasePortError("reveal_release_boundary_mismatch")
        if boundary.audit_release_block <= work.window.plan.closing_block:
            raise RevealAuditReleasePortError("reveal_release_boundary_too_early")
        try:
            head = await self.finality.finalized_head_height()
        except Exception as error:
            raise StagePending("reveal_audit_release_finality_pending") from error
        if head < boundary.audit_release_block:
            raise StagePending("reveal_audit_release_finality_pending")
        try:
            block = await self.finality.verified_block_at(boundary.audit_release_block)
        except Exception as error:
            raise RevealAuditReleasePortError("reveal_audit_release_block_read_failed") from error
        if block is None:
            raise StagePending("reveal_audit_release_finality_pending")
        pins = self.policy.implementation_pins
        if (
            block.height != boundary.audit_release_block
            or block.scoring_policy_hash != policy_hash
            or block.chain_observation != pins.live_chain
            or block.finality_verifier_sha256 != self.finality.finality_verifier_sha256
        ):
            raise RevealAuditReleasePortError("reveal_audit_release_block_mismatch")
        reveal_time_ms = (
            QUICKNET_GENESIS_MS + (work.window.plan.reveal_round - 1) * QUICKNET_PERIOD_MS
        )
        if block.timestamp_ms < reveal_time_ms:
            raise RevealAuditReleasePortError("reveal_audit_release_before_reveal")
        if len(block.finality_evidence) > MAX_RELEASE_FINALITY_EVIDENCE_BYTES:
            raise RevealAuditReleasePortError("reveal_audit_release_finality_size_limit")
        evidence_manifest = canonical_json_bytes(
            {
                "schema": REVEAL_RELEASE_EVIDENCE_SCHEMA,
                "protocol": PROTOCOL_VERSION,
                "window_id": work.window.plan.window_id,
                "scoring_policy_hash": policy_hash,
                "reason_code": reason_code,
                "audit_release_block": block.height,
                "audit_release_block_hash": block.block_hash,
                "audit_release_state_root": block.state_root,
                "audit_release_timestamp_ms": block.timestamp_ms,
                "chain_genesis_hash": block.chain_observation.genesis_block_hash,
                "finality_verifier_sha256": block.finality_verifier_sha256,
                "finality_evidence_sha256": block.finality_evidence_sha256,
                "boundary": boundary.model_dump(mode="json", by_alias=True),
                "boundary_evidence_sha256": hashlib.sha256(value.evidence_bytes).hexdigest(),
            }
        )
        evidence = b"".join(
            (
                b"umi-finalized-reveal-audit-release-v1\0",
                u32be(len(evidence_manifest)),
                evidence_manifest,
                u32be(len(value.evidence_bytes)),
                value.evidence_bytes,
                u32be(len(block.finality_evidence)),
                block.finality_evidence,
            )
        )
        if len(evidence) > 64 * 1024 * 1024:
            raise RevealAuditReleasePortError("reveal_audit_release_evidence_size_limit")
        return VerifiedRevealAuditRelease(
            fact=RevealAuditRelease(
                schema=REVEAL_AUDIT_RELEASE_SCHEMA,
                window_id=work.window.plan.window_id,
                reason_code=reason_code,
                audit_release_block=block.height,
                evidence_sha256=hashlib.sha256(evidence).hexdigest(),
            ),
            evidence_bytes=evidence,
        )


def build_live_pool_effect_ports(
    *,
    policy: ScoringPolicy,
    source: DurablePoolMirrorSource,
    closing_snapshot: ClosingSnapshotPort,
    delivery_issuance: DeliveryIssuancePort,
    prepared_assignments: PreparedAssignmentsPort,
    quicknet_client: QuicknetClient,
) -> PoolEffectPorts:
    """Assemble the existing pool effect port bundle without widening a port."""

    if source.policy != policy:
        raise ValueError("pool mirror source is bound to another policy")
    if not callable(delivery_issuance):
        raise TypeError("pool delivery issuance port must be callable")
    return PoolEffectPorts(
        source=source,
        closing_snapshot=closing_snapshot,
        selection_pulse=QuicknetSelectionPulseAdapter(policy, quicknet_client),
        delivery_issuance=delivery_issuance,
        prepared_assignments=prepared_assignments,
    )


def build_live_reveal_effect_ports(
    *,
    policy: ScoringPolicy,
    quicknet_client: QuicknetClient,
    audit_release: FinalizedRevealAuditReleaseAdapter,
) -> RevealEffectPorts:
    """Assemble the existing reveal effect ports from concrete read-only adapters."""

    if audit_release.policy != policy:
        raise ValueError("reveal audit-release adapter is bound to another policy")
    return RevealEffectPorts(
        reveal_pulse=QuicknetRevealPulseAdapter(policy, quicknet_client),
        decrypt=TLERevealDecryptAdapter(policy),
        audit_release=audit_release,
    )


async def _fetch_quicknet(
    client: QuicknetClient,
    round_number: int,
    label: str,
) -> DrandPulse:
    try:
        pulse = await client.fetch(round_number, require_published=True)
    except DrandVerificationError as error:
        if "not published" in str(error):
            raise StagePending(f"quicknet_{label}_pulse_pending") from error
        raise QuicknetPortError(f"quicknet_{label}_verification_failed") from error
    if not isinstance(pulse, DrandPulse) or pulse.round != round_number:
        raise QuicknetPortError(f"quicknet_{label}_pulse_mismatch")
    try:
        pulse.verify()
    except DrandVerificationError as error:
        raise QuicknetPortError(f"quicknet_{label}_verification_failed") from error
    return pulse


def _pulse_bytes(pulse: DrandPulse) -> bytes:
    return canonical_json_bytes(
        {"randomness": pulse.randomness, "round": pulse.round, "signature": pulse.signature}
    )


def _validate_quicknet_adapter(policy: ScoringPolicy, client: QuicknetClient) -> None:
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("Quicknet adapter policy must be ScoringPolicy")
    if not isinstance(client, QuicknetClient):
        raise TypeError("Quicknet adapter requires the verified QuicknetClient")
    _validate_quicknet_policy(policy)


def _validate_quicknet_policy(policy: ScoringPolicy) -> None:
    pin = policy.implementation_pins.timelock
    expected = (
        pin.beacon_id,
        pin.chain_hash,
        pin.scheme_id,
        pin.period_seconds,
        pin.genesis_time,
    )
    actual = (
        "quicknet",
        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "bls-unchained-g1-rfc9380",
        3,
        1692803367,
    )
    if expected != actual:
        raise QuicknetPortError("quicknet_policy_tuple_mismatch")


def _validate_pulse_work(
    work: StageWorkItem,
    policy: ScoringPolicy,
    expected_stage: WindowStage,
) -> None:
    if not isinstance(work, StageWorkItem) or work.stage is not expected_stage:
        raise QuicknetPortError("quicknet_port_wrong_stage")
    if work.window.plan.scoring_policy_hash != scoring_policy_hash(policy):
        raise QuicknetPortError("quicknet_port_policy_hash_mismatch")


def _descriptor_sort_key(item: MirrorObjectDescriptor) -> tuple[object, ...]:
    publisher = account_id32(item.publisher_hotkey) if item.publisher_hotkey is not None else b""
    batch = base64url_decode(item.batch_id) if item.batch_id is not None else b""
    challenge = base64url_decode(item.challenge_id) if item.challenge_id is not None else b""
    return (_KIND_ORDER[item.kind], publisher, batch, challenge, bytes.fromhex(item.sha256))


def _parse_canonical_model(data: bytes, model_type, *, maximum_bytes: int, reason_code: str):
    if not isinstance(data, bytes) or not data or len(data) > maximum_bytes:
        raise MirrorLimitError(f"{reason_code}_size")
    try:
        value = json.loads(data)
        model = model_type.model_validate(value)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise MirrorBindingError(reason_code) from error
    if canonical_json_bytes(model) != data:
        raise MirrorBindingError(reason_code)
    return model


def _mirror_origin(value: str, *, allow_http_for_tests: bool) -> str:
    return normalized_https_origin(value, allow_http_for_tests=allow_http_for_tests)


def _mirror_origin_from_url(value: str, *, allow_http_for_tests: bool) -> str:
    parsed = urlsplit(value)
    root = f"{parsed.scheme}://{parsed.netloc}"
    return _mirror_origin(root, allow_http_for_tests=allow_http_for_tests)


def _relative_mirror_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\\" in value:
        raise ValueError("mirror object path must be an absolute-origin relative path")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        raise ValueError("mirror object path cannot change origin or carry a fragment")
    decoded_segments = unquote(parsed.path).split("/")
    if any(segment in {".", ".."} or "\x00" in segment for segment in decoded_segments):
        raise ValueError("mirror object path contains traversal or NUL")
    return value


def _request_headers(value: Mapping[str, str], *, maximum_bytes: int) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > MAX_MIRROR_HEADER_COUNT:
        raise TypeError("mirror request headers must be a bounded mapping")
    result: dict[str, str] = {}
    total = 0
    for name, header_value in value.items():
        if not isinstance(name, str) or _HEADER_NAME_RE.fullmatch(name) is None:
            raise ValueError("mirror request header name is invalid")
        lower = name.lower()
        if lower in _FORBIDDEN_REQUEST_HEADERS or lower in result:
            raise ValueError("mirror request header is forbidden or duplicated")
        if not isinstance(header_value, str) or "\r" in header_value or "\n" in header_value:
            raise ValueError("mirror request header value is invalid")
        total += len(name.encode("ascii")) + len(header_value.encode("utf-8")) + 4
        result[lower] = header_value
    if total > maximum_bytes:
        raise ValueError("mirror request headers exceed the policy ceiling")
    return dict(sorted(result.items()))


def _origin_request_headers(
    value: Mapping[str, Mapping[str, str]] | Mapping[str, str],
    *,
    origins: Sequence[str],
    maximum_bytes: int,
) -> dict[str, dict[str, str]]:
    """Validate an exact origin-to-private-header map.

    A flat map remains accepted only for isolated single-origin adapters.  It can
    never become a credential-sharing fallback for a multi-origin production
    discovery rule.
    """

    if not isinstance(value, Mapping) or not value:
        raise TypeError("mirror origin request headers must be a nonempty mapping")
    values = tuple(value.values())
    if all(isinstance(item, str) for item in values):
        if len(origins) != 1:
            raise ValueError("multi-origin mirror retrieval requires per-origin headers")
        flat = _request_headers(value, maximum_bytes=maximum_bytes)  # type: ignore[arg-type]
        if not flat:
            raise ValueError("authenticated mirror retrieval requires request headers")
        return {origins[0]: flat}
    if not all(isinstance(item, Mapping) for item in values):
        raise TypeError("mirror origin request headers mix flat and nested values")
    if tuple(value.keys()) != tuple(origins):
        raise ValueError("mirror request-header origin set or ordering disagrees with discovery")
    result: dict[str, dict[str, str]] = {}
    authorization_values: list[str] = []
    for origin in origins:
        headers = _request_headers(value[origin], maximum_bytes=maximum_bytes)  # type: ignore[arg-type]
        if not headers:
            raise ValueError("authenticated mirror retrieval requires request headers")
        authorization = headers.get("authorization")
        if authorization is None:
            raise ValueError("each mirror origin requires one Authorization header")
        authorization_values.append(authorization)
        result[origin] = headers
    if len(set(authorization_values)) != len(authorization_values):
        raise ValueError("mirror origins must not share an Authorization credential")
    return result


async def _resolve_public_address(
    hostname: str,
    port: int,
    *,
    resolver: AddressResolver | None,
) -> str:
    if resolver is None:
        try:
            literal = ipaddress.ip_address(hostname)
            addresses = (str(literal),)
        except ValueError:
            loop = asyncio.get_running_loop()
            try:
                results = await loop.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
            except OSError as error:
                raise MirrorRetrievalError("mirror_dns_resolution_failed") from error
            addresses = tuple(str(result[4][0]) for result in results)
    else:
        try:
            addresses = tuple(await resolver(hostname, port))
        except Exception as error:
            raise MirrorRetrievalError("mirror_dns_resolution_failed") from error
    if not addresses:
        raise MirrorRetrievalError("mirror_dns_empty")
    parsed: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for address in addresses:
        try:
            candidate = ipaddress.ip_address(address)
        except ValueError as error:
            raise MirrorRetrievalError("mirror_dns_address_invalid") from error
        if not candidate.is_global:
            raise MirrorRetrievalError("mirror_dns_non_public")
        parsed.add(candidate)
    selected = min(parsed, key=lambda item: (item.version, item.packed))
    return str(selected)


def _request_header_accounting(
    url: httpx.URL,
    headers: Mapping[str, str],
    *,
    method: str = "GET",
) -> int:
    target = url.raw_path
    return (
        len(method.encode("ascii"))
        + 1
        + len(target)
        + len(b" HTTP/1.1\r\n")
        + sum(
            len(name.encode("ascii")) + len(value.encode("utf-8")) + 4
            for name, value in headers.items()
        )
        + 2
    )


def _mapping_header_size(headers: Mapping[str, str]) -> int:
    return sum(
        len(name.encode("ascii")) + len(value.encode("utf-8")) + 4
        for name, value in headers.items()
    )


def _raw_header_size(headers: httpx.Headers) -> int:
    return sum(len(name) + len(value) + 4 for name, value in headers.raw)


def _verify_object_row(
    row: sqlite3.Row,
    expected_sha256: str,
    expected_size: int,
    expected_media_type: str,
) -> bytes:
    data = bytes(row["data"])
    if (
        row["sha256"] != expected_sha256
        or row["size_bytes"] != expected_size
        or row["media_type"] != expected_media_type
        or len(data) != expected_size
        or hashlib.sha256(data).hexdigest() != expected_sha256
    ):
        raise MirrorBindingError("mirror_cached_object_tampered")
    return data


def _prepare_database_path(path: Path) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise MirrorRetrievalError("mirror_state_parent_not_real_directory")
    _reject_database_symlinks(path)


def _reject_database_symlinks(path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(f"{path}{suffix}")
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (suffix == "" and not stat.S_ISREG(info.st_mode)):
            raise MirrorRetrievalError("mirror_database_path_unsafe")


def _opaque_id(value: str, label: str) -> bytes:
    try:
        decoded = base64url_decode(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is invalid") from error
    if len(decoded) != 16:
        raise ValueError(f"{label} must encode exactly 16 bytes")
    return decoded


def _bounded_int(value: int, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _reason_code(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", value) is None:
        raise ValueError("reason code is invalid")
    return value


__all__ = [
    "DEFAULT_DELIVERY_ISSUANCE_PATH",
    "DEFAULT_MIRROR_INDEX_PATH",
    "MIRROR_DISCOVERY_SCHEMA",
    "MIRROR_RETRIEVAL_EVIDENCE_SCHEMA",
    "MIRROR_WINDOW_INDEX_SCHEMA",
    "REVEAL_RELEASE_BOUNDARY_SCHEMA",
    "AuthenticatedMirrorDeliveryIssuer",
    "DurablePoolMirrorSource",
    "FinalizedRevealAuditReleaseAdapter",
    "LiveValidatorPortError",
    "MirrorBindingError",
    "MirrorDiscoveryRule",
    "MirrorLimitError",
    "MirrorObjectDescriptor",
    "MirrorRetrievalError",
    "MirrorRetrievalEvidence",
    "MirrorWindowIndex",
    "ProofBackedRevealAuditReleaseBoundaryPort",
    "QuicknetPortError",
    "QuicknetRevealPulseAdapter",
    "QuicknetSelectionPulseAdapter",
    "RevealAuditReleaseBoundary",
    "RevealAuditReleaseBoundaryPort",
    "RevealAuditReleasePortError",
    "TLERevealDecryptAdapter",
    "TimelockRevealPortError",
    "VerifiedRevealAuditReleaseBoundary",
    "build_live_pool_effect_ports",
    "build_live_reveal_effect_ports",
]
