"""Verified, last-good ingestion of public inactive-validator bundle feeds.

Publisher indexes are discovery hints.  This module downloads every referenced
byte through a bounded, DNS-pinned HTTPS client and runs the production bundle
replay verifier before committing a dashboard projection to durable state.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import sqlite3
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import quote, urlsplit

import httpx
from bittensor_core import decrypt_with_signature
from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .audit_publication import (
    MAX_PUBLIC_INDEX_BYTES,
    MAX_REMOTE_FILES,
    MAX_REMOTE_HEADER_BYTES,
    PUBLICATION_MODE,
    AuditPublicationError,
    PublicBundleIndex,
    PublicBundleIndexEntry,
    _bind_tree_to_entry,
    _inspect_bundle_tree,
    _parse_bundle_manifest,
    _read_regular_file,
    load_production_publication_definition,
)
from .calibration_bundle import (
    MAX_CALIBRATION_BUNDLE_BYTES,
    MAX_CALIBRATION_MANIFEST_BYTES,
    MAX_CALIBRATION_OBJECT_BYTES,
    CalibrationStageEvidence,
)
from .canary import evaluate_canary
from .policy import ScoringPolicy
from .protocol import (
    PROTOCOL_VERSION,
    GroundTruthPayload,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
)
from .scoring import score_cer_with_trace, score_wer_with_trace
from .validator import (
    ComponentResponseError,
    validate_response_envelope,
    validate_response_plaintext,
)
from .validator_assignments import AttemptOutcomeEvidence, PreparedAttemptEvidence
from .validator_delivery import normalized_https_origin
from .validator_journal import StageObject, StageReceipt
from .validator_readiness import PublishedBundleVerifier, VerifiedPublishedBundle
from .validator_reveal_effect import (
    MAX_REVEAL_ASSIGNMENTS,
    REVEAL_RESULT_SCHEMA,
    REVEAL_STAGE_SCHEMA,
    RevealResult,
    RevealStageManifest,
    _response_hypothesis,
    _ResponseStageManifest,
)
from .validator_weight_build_effect import (
    WEIGHT_BUILD_RESULT_SCHEMA,
    WEIGHT_BUILD_STAGE_SCHEMA,
    WeightBuildResultEvidence,
    WeightBuildStageManifest,
)

OBSERVER_BUNDLE_FEED_CONFIG_SCHEMA = "umi-observer-bundle-feed-config/1"
OBSERVER_BUNDLE_FEED_STATE_SCHEMA = "umi-observer-bundle-feed-state/3"
DEFAULT_MAXIMUM_STATE_DATABASE_BYTES = 4 * 1024**3
_MINIMUM_STATE_DATABASE_BYTES = 1024**2
_MAXIMUM_STATE_DATABASE_BYTES = 1024**4
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_REASON_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")

# One worker for the process keeps every download, replay, projection, and
# durable promotion away from the public API event loop. A stuck native call can
# occupy this worker, but it cannot create an unbounded series of stuck threads.
_REFRESH_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="umi-observer-feed",
)


class ObserverBundleFeedError(RuntimeError):
    """Bounded reason for rejecting untrusted feed data."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ObserverFeedTargetConfig(StrictProtocolModel):
    publication_config_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    public_origin: Annotated[str, Field(min_length=1, max_length=8_192)]

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        path = Path(self.publication_config_path)
        if not path.is_absolute() or os.path.normpath(self.publication_config_path) != str(path):
            raise ValueError("publication config path must be absolute and normalized")
        if normalized_https_origin(self.public_origin) != self.public_origin:
            raise ValueError("public origin must be one normalized HTTPS origin")
        return self


class ObserverBundleFeedConfig(StrictProtocolModel):
    schema_: Literal[OBSERVER_BUNDLE_FEED_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[PUBLICATION_MODE]
    translation_weights_active: Literal[False]
    wallet_loading_capability: Literal[False]
    chain_write_capability: Literal[False]
    weight_submission_capability: Literal[False]
    state_database_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    temporary_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    poll_seconds: Annotated[float, Field(ge=1, le=3_600)] = 15
    maximum_stale_seconds: Annotated[float, Field(ge=1, le=86_400)] = 300
    request_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 30
    maximum_new_entries_per_refresh: Annotated[int, Field(ge=1, le=16)] = 2
    maximum_target_refresh_seconds: Annotated[float, Field(gt=0, le=3_600)] = 600
    maximum_concurrent_targets: Annotated[int, Field(ge=1, le=16)] = 4
    maximum_state_database_bytes: Annotated[
        int,
        Field(ge=_MINIMUM_STATE_DATABASE_BYTES, le=_MAXIMUM_STATE_DATABASE_BYTES),
    ] = DEFAULT_MAXIMUM_STATE_DATABASE_BYTES
    targets: Annotated[list[ObserverFeedTargetConfig], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def validate_config(self) -> Self:
        state = Path(self.state_database_path)
        temporary = Path(self.temporary_root)
        for raw, path in ((self.state_database_path, state), (self.temporary_root, temporary)):
            if not path.is_absolute() or os.path.normpath(raw) != str(path):
                raise ValueError("observer feed paths must be absolute and normalized")
        if state == temporary or state in temporary.parents or temporary in state.parents:
            raise ValueError("observer feed state and temporary root must be disjoint")
        publication_paths = [item.publication_config_path for item in self.targets]
        if len(publication_paths) != len(set(publication_paths)):
            raise ValueError("observer feed targets must be unique")
        return self


@dataclass(frozen=True, slots=True)
class ValidatorLocalScore:
    miner_root_account_id32: str
    assigned_clips: int
    accuracy_numerator: int
    accuracy_denominator: int
    eligible: bool
    utility_numerator: int
    utility_denominator: int

    def __post_init__(self) -> None:
        if _HEX32_RE.fullmatch(self.miner_root_account_id32) is None:
            raise ValueError("miner root is invalid")
        if self.assigned_clips < 0:
            raise ValueError("assigned clips must be nonnegative")
        for numerator, denominator in (
            (self.accuracy_numerator, self.accuracy_denominator),
            (self.utility_numerator, self.utility_denominator),
        ):
            if denominator <= 0 or numerator < 0 or numerator > denominator:
                raise ValueError("validator-local score must be an exact unit-interval rational")


@dataclass(frozen=True, slots=True)
class VerifiedEvidenceObject:
    sha256: str
    media_type: str
    size_bytes: int

    def __post_init__(self) -> None:
        if _HEX32_RE.fullmatch(self.sha256) is None:
            raise ValueError("evidence-object hash is invalid")
        if not self.media_type or len(self.media_type) > 256:
            raise ValueError("evidence-object media type is invalid")
        if self.size_bytes < 0 or self.size_bytes > MAX_CALIBRATION_OBJECT_BYTES:
            raise ValueError("evidence-object size is invalid")


@dataclass(frozen=True, slots=True)
class VerifiedSolutionEvidence:
    prepared_attempt: VerifiedEvidenceObject
    request: VerifiedEvidenceObject
    attempt_outcome: VerifiedEvidenceObject
    retained_response: VerifiedEvidenceObject | None
    response_plaintext: VerifiedEvidenceObject | None
    response_decryption: VerifiedEvidenceObject
    ground_truth_plaintext: VerifiedEvidenceObject | None
    ground_truth_decryption: VerifiedEvidenceObject | None


@dataclass(frozen=True, slots=True)
class VerifiedMinerSolution:
    assignment_id: str
    request_leaf: str
    batch_id: str
    challenge_id: str
    miner_hotkey: str
    miner_root_account_id32: str
    stratum: Literal["fingerspelling", "short_utterance", "continuous"]
    metric: Literal["wer", "cer"] | None
    canary: bool | None
    outer_disposition: Literal["sealed", "missing", "late", "outer_invalid", "resource_limit"]
    zero_score_reason: str | None
    response_plaintext_valid: bool
    response_status: Literal["ok", "error"] | None
    hypothesis: str | None
    response_error_code: str | None
    model_revision: str | None
    references: tuple[str, ...]
    canary_actual_references: tuple[str, ...]
    score_numerator: int | None
    score_denominator: int | None
    score_trace: dict[str, Any] | None
    canary_result: dict[str, Any] | None
    evidence: VerifiedSolutionEvidence

    def __post_init__(self) -> None:
        for value, label in (
            (self.assignment_id, "assignment ID"),
            (self.request_leaf, "request leaf"),
            (self.miner_root_account_id32, "miner root"),
        ):
            if _HEX32_RE.fullmatch(value) is None:
                raise ValueError(f"{label} is invalid")
        if not self.batch_id or not self.challenge_id or not self.miner_hotkey:
            raise ValueError("solution identity is incomplete")
        if (self.score_numerator is None) != (self.score_denominator is None):
            raise ValueError("solution score rational is incomplete")
        if self.score_denominator is not None and (
            self.score_denominator <= 0
            or self.score_numerator is None
            or self.score_numerator < 0
            or self.score_numerator > self.score_denominator
        ):
            raise ValueError("solution score is outside the unit interval")
        if self.response_plaintext_valid != (self.response_status is not None):
            raise ValueError("response plaintext validity and status disagree")
        if self.response_status == "ok" and self.hypothesis is None:
            raise ValueError("a valid ok response requires its hypothesis")
        if self.response_status == "error" and self.response_error_code is None:
            raise ValueError("a valid error response requires its error code")
        if self.canary is False and self.metric is None:
            raise ValueError("a scored assignment requires its metric")


@dataclass(frozen=True, slots=True)
class VerifiedFeedWindow:
    validator_account_id32: str
    window_id: str
    window_index: int
    terminal_classification: str
    reason_codes: tuple[str, ...]
    scoring_policy_hash: str
    audit_release_block: int
    audit_release_block_hash: str
    manifest_sha256: str
    tree_sha256: str
    public_origin: str
    bundle_relative_path: str
    reveal_stage_manifest: VerifiedEvidenceObject | None
    reveal_result: VerifiedEvidenceObject | None
    solutions: tuple[VerifiedMinerSolution, ...]
    scores: tuple[ValidatorLocalScore, ...]
    observer_verified_unix: int | None = None
    solution_count: int | None = None

    def __post_init__(self) -> None:
        if _HEX32_RE.fullmatch(self.validator_account_id32) is None:
            raise ValueError("validator account is invalid")
        if _HEX32_RE.fullmatch(self.window_id) is None:
            raise ValueError("window ID is invalid")
        if _HEX32_RE.fullmatch(self.scoring_policy_hash) is None:
            raise ValueError("scoring policy hash is invalid")
        if _HEX32_RE.fullmatch(self.manifest_sha256) is None:
            raise ValueError("manifest hash is invalid")
        if _HEX32_RE.fullmatch(self.tree_sha256) is None:
            raise ValueError("bundle tree hash is invalid")
        if normalized_https_origin(self.public_origin) != self.public_origin:
            raise ValueError("bundle public origin is invalid")
        _safe_relative_path(self.bundle_relative_path)
        if _BLOCK_HASH_RE.fullmatch(self.audit_release_block_hash) is None:
            raise ValueError("audit release block hash is invalid")
        if self.solution_count is not None and self.solution_count < len(self.solutions):
            raise ValueError("solution count is smaller than materialized solutions")
        if self.window_index < 0 or self.audit_release_block <= 0:
            raise ValueError("window and release positions are invalid")
        if self.observer_verified_unix is not None and self.observer_verified_unix < 0:
            raise ValueError("observer verification time is invalid")
        roots = [item.miner_root_account_id32 for item in self.scores]
        if len(roots) != len(set(roots)):
            raise ValueError("validator-local score roots must be unique")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason codes must be unique and sorted")
        assignments = [item.assignment_id for item in self.solutions]
        if assignments != sorted(set(assignments)):
            raise ValueError("solutions must be unique and sorted by assignment ID")
        if len(assignments) > MAX_REVEAL_ASSIGNMENTS:
            raise ValueError("solution count exceeds the reveal ceiling")
        if (self.reveal_stage_manifest is None) != (self.reveal_result is None):
            raise ValueError("reveal evidence locators must appear together")


@dataclass(frozen=True, slots=True)
class FeedHealth:
    validator_account_id32: str
    status: Literal["current", "degraded", "stale", "not_started"]
    last_error_code: str | None
    last_checked_unix: int | None
    accepted_entries: int

    def __post_init__(self) -> None:
        if _HEX32_RE.fullmatch(self.validator_account_id32) is None:
            raise ValueError("feed-health validator account is invalid")
        if self.last_error_code is not None and (
            _REASON_CODE_RE.fullmatch(self.last_error_code) is None
        ):
            raise ValueError("feed-health reason code is invalid")
        if self.last_checked_unix is not None and self.last_checked_unix < 0:
            raise ValueError("feed-health check time is invalid")
        if self.accepted_entries < 0:
            raise ValueError("feed-health accepted entry count is invalid")
        if self.status == "current" and self.last_error_code is not None:
            raise ValueError("current feed health cannot contain an error")
        if self.status == "degraded" and self.last_error_code is None:
            raise ValueError("degraded feed health requires a reason code")


@dataclass(frozen=True, slots=True)
class BundleFeedSnapshot:
    windows: tuple[VerifiedFeedWindow, ...]
    health: tuple[FeedHealth, ...]


@dataclass(frozen=True, slots=True)
class _CachedFeedState:
    last_checked_unix: int | None
    last_error_code: str | None
    accepted_entries: int
    binding_sha256: str


@dataclass(frozen=True, slots=True)
class _FeedMetadataCache:
    windows: tuple[VerifiedFeedWindow, ...]
    states: Mapping[str, _CachedFeedState]
    entries_by_validator: Mapping[str, tuple[PublicBundleIndexEntry, ...]]
    windows_by_identity: Mapping[tuple[str, str], VerifiedFeedWindow]


@dataclass(frozen=True, slots=True)
class ObserverFeedTarget:
    validator_account_id32: str
    scoring_policy_hash: str
    release_manifest_sha256: str
    public_origin: str
    verifier: PublishedBundleVerifier

    def __post_init__(self) -> None:
        if _HEX32_RE.fullmatch(self.validator_account_id32) is None:
            raise ValueError("validator account is not AccountId32 hexadecimal")
        if _HEX32_RE.fullmatch(self.scoring_policy_hash) is None:
            raise ValueError("policy hash is invalid")
        if _HEX32_RE.fullmatch(self.release_manifest_sha256) is None:
            raise ValueError("release manifest hash is invalid")
        if normalized_https_origin(self.public_origin) != self.public_origin:
            raise ValueError("public origin is not normalized HTTPS")
        if not callable(getattr(self.verifier, "verify", None)):
            raise TypeError("target verifier must implement verify")


class AddressResolver(Protocol):
    async def __call__(self, hostname: str, port: int) -> Sequence[str]: ...


@dataclass(frozen=True, slots=True)
class _Session:
    client: httpx.AsyncClient
    request_origin: str
    host_header: str | None
    sni_hostname: str | None


class BoundedHTTPSFetcher:
    """One-pass DNS-pinned client with exact byte ceilings and no redirects."""

    def __init__(
        self,
        origin: str,
        *,
        timeout_seconds: float = 30,
        resolver: AddressResolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        allow_http_for_tests: bool = False,
    ) -> None:
        normalized = normalized_https_origin(origin, allow_http_for_tests=allow_http_for_tests)
        if normalized != origin:
            raise ValueError("feed origin is not normalized")
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise ValueError("feed timeout must be finite, positive, and at most 300 seconds")
        self.origin = origin
        self.timeout_seconds = timeout_seconds
        self.resolver = resolver or _default_resolver
        self.transport = transport
        self.allow_http_for_tests = allow_http_for_tests

    @asynccontextmanager
    async def session(self) -> AsyncIterator[_Session]:
        parsed = urlsplit(self.origin)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        in_process = isinstance(self.transport, (httpx.MockTransport, httpx.ASGITransport))
        if in_process:
            request_origin, host_header, sni = self.origin, None, None
        else:
            try:
                answers = await asyncio.wait_for(
                    self.resolver(hostname, port), timeout=self.timeout_seconds
                )
            except Exception as error:
                raise ObserverBundleFeedError("feed_dns_failed") from error
            normalized_answers: list[str] = []
            for raw in answers:
                try:
                    address = ipaddress.ip_address(raw)
                except ValueError as error:
                    raise ObserverBundleFeedError("feed_dns_answer_invalid") from error
                if not address.is_global:
                    raise ObserverBundleFeedError("feed_dns_address_not_global")
                normalized_answers.append(address.compressed)
            if not normalized_answers:
                raise ObserverBundleFeedError("feed_dns_empty")
            selected = sorted(set(normalized_answers))[0]
            host = f"[{selected}]" if ":" in selected else selected
            request_origin = f"{parsed.scheme}://{host}:{port}"
            default_port = 443 if parsed.scheme == "https" else 80
            authority_host = f"[{hostname}]" if ":" in hostname else hostname
            authority = (
                authority_host
                if parsed.port in {None, default_port}
                else f"{authority_host}:{port}"
            )
            host_header, sni = authority, hostname
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
        ) as client:
            yield _Session(client, request_origin, host_header, sni)

    async def fetch(self, session: _Session, relative_path: str, maximum_bytes: int) -> bytes:
        _safe_relative_path(relative_path)
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int):
            raise TypeError("maximum bytes must be an integer")
        if maximum_bytes <= 0:
            raise ValueError("maximum bytes must be positive")
        try:
            return await asyncio.wait_for(
                self._fetch_stream(session, relative_path, maximum_bytes),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise ObserverBundleFeedError("feed_timeout") from error

    async def _fetch_stream(
        self, session: _Session, relative_path: str, maximum_bytes: int
    ) -> bytes:
        url = f"{session.request_origin}/{quote(relative_path, safe='/-._~')}"
        headers = {"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"}
        if session.host_header is not None:
            headers["Host"] = session.host_header
        try:
            async with session.client.stream(
                "GET",
                url,
                headers=headers,
                extensions=(
                    {} if session.sni_hostname is None else {"sni_hostname": session.sni_hostname}
                ),
            ) as response:
                if _header_size(response.headers) > MAX_REMOTE_HEADER_BYTES:
                    raise ObserverBundleFeedError("feed_header_limit")
                if response.status_code != 200:
                    raise ObserverBundleFeedError("feed_http_status")
                if response.headers.get("content-encoding", "").lower() not in {"", "identity"}:
                    raise ObserverBundleFeedError("feed_content_encoding")
                declared = response.headers.get("content-length")
                if declared is not None:
                    if re.fullmatch(r"(?:0|[1-9][0-9]*)", declared) is None:
                        raise ObserverBundleFeedError("feed_content_length_invalid")
                    if int(declared) > maximum_bytes:
                        raise ObserverBundleFeedError("feed_body_limit")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    body.extend(chunk)
                    if len(body) > maximum_bytes:
                        raise ObserverBundleFeedError("feed_body_limit")
                if declared is not None and len(body) != int(declared):
                    raise ObserverBundleFeedError("feed_partial_body")
                return bytes(body)
        except ObserverBundleFeedError:
            raise
        except Exception as error:
            raise ObserverBundleFeedError("feed_transport_failed") from error


class ObserverBundleFeed:
    """Durable verified feed with append-only cursor and last-good reads."""

    def __init__(
        self,
        *,
        targets: Sequence[ObserverFeedTarget],
        state_database_path: Path,
        temporary_root: Path,
        maximum_stale_seconds: float = 300,
        timeout_seconds: float = 30,
        maximum_new_entries_per_refresh: int = 2,
        maximum_target_refresh_seconds: float = 600,
        maximum_concurrent_targets: int = 4,
        maximum_state_database_bytes: int = DEFAULT_MAXIMUM_STATE_DATABASE_BYTES,
        fetcher_factory: Callable[[str, float], BoundedHTTPSFetcher] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not targets:
            raise ValueError("at least one feed target is required")
        accounts = [item.validator_account_id32 for item in targets]
        if len(accounts) != len(set(accounts)):
            raise ValueError("feed validator accounts must be unique")
        self.targets = tuple(sorted(targets, key=lambda item: item.validator_account_id32))
        self.state_path = state_database_path
        self.temporary_root = temporary_root
        for name, value, ceiling in (
            ("maximum stale seconds", maximum_stale_seconds, 86_400),
            ("request timeout seconds", timeout_seconds, 300),
            ("maximum target refresh seconds", maximum_target_refresh_seconds, 3_600),
        ):
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0 or value > ceiling:
                raise ValueError(f"{name} must be finite, positive, and at most {ceiling}")
        self.maximum_stale_seconds = float(maximum_stale_seconds)
        self.timeout_seconds = float(timeout_seconds)
        if not 1 <= maximum_new_entries_per_refresh <= 16:
            raise ValueError("maximum new entries per refresh must be from 1 through 16")
        self.maximum_new_entries_per_refresh = maximum_new_entries_per_refresh
        if not 1 <= maximum_concurrent_targets <= 16:
            raise ValueError("maximum concurrent targets must be from 1 through 16")
        if (
            isinstance(maximum_state_database_bytes, bool)
            or not isinstance(maximum_state_database_bytes, int)
            or not _MINIMUM_STATE_DATABASE_BYTES
            <= maximum_state_database_bytes
            <= _MAXIMUM_STATE_DATABASE_BYTES
        ):
            raise ValueError("maximum state database bytes must be from 1 MiB through 1 TiB")
        if not callable(fetcher_factory) and fetcher_factory is not None:
            raise TypeError("fetcher factory must be callable")
        if not callable(clock):
            raise TypeError("feed clock must be callable")
        self.maximum_target_refresh_seconds = float(maximum_target_refresh_seconds)
        self.maximum_concurrent_targets = maximum_concurrent_targets
        self.maximum_state_database_bytes = maximum_state_database_bytes
        self.fetcher_factory = fetcher_factory or (
            lambda origin, timeout: BoundedHTTPSFetcher(origin, timeout_seconds=timeout)
        )
        self.clock = clock
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._worker_job: concurrent.futures.Future[bool] | None = None
        self._metadata_cache = _FeedMetadataCache(
            (), MappingProxyType({}), MappingProxyType({}), MappingProxyType({})
        )
        self._prepare()

    async def refresh(self, finalized_height: int) -> bool:
        if isinstance(finalized_height, bool) or not isinstance(finalized_height, int):
            raise TypeError("finalized height must be an integer")
        if finalized_height < 0:
            raise ValueError("finalized height must be nonnegative")
        async with self._lock:
            job = self._worker_job
            if job is None or job.done():
                job = _REFRESH_EXECUTOR.submit(self._run_refresh_worker, finalized_height)
                self._worker_job = job
            try:
                return await asyncio.shield(asyncio.wrap_future(job))
            finally:
                if job.done() and self._worker_job is job:
                    self._worker_job = None

    def _run_refresh_worker(self, finalized_height: int) -> bool:
        return asyncio.run(self._refresh_all(finalized_height))

    async def _refresh_all(self, finalized_height: int) -> bool:
        semaphore = asyncio.Semaphore(self.maximum_concurrent_targets)

        async def refresh_target(target: ObserverFeedTarget) -> bool:
            async with semaphore:
                try:
                    caught_up = await asyncio.wait_for(
                        self._refresh_target(target, finalized_height),
                        timeout=self.maximum_target_refresh_seconds,
                    )
                except Exception as error:
                    code = (
                        "feed_refresh_timeout"
                        if isinstance(error, asyncio.TimeoutError)
                        else error.reason_code
                        if isinstance(error, ObserverBundleFeedError)
                        else "feed_refresh_failed"
                    )
                    self._record_failure(target.validator_account_id32, code)
                    return False
                return caught_up

        return all(await asyncio.gather(*(refresh_target(target) for target in self.targets)))

    def snapshot(self) -> BundleFeedSnapshot:
        now = int(self.clock())
        metadata = self._metadata_cache
        health: list[FeedHealth] = []
        for target in self.targets:
            row = metadata.states.get(target.validator_account_id32)
            stored_count = len(metadata.entries_by_validator.get(target.validator_account_id32, ()))
            if row is None:
                if stored_count:
                    raise ObserverBundleFeedError("feed_state_cursor_missing")
                status, checked, count, error = "not_started", None, 0, None
            elif row.last_checked_unix is None:
                checked = None
                count = row.accepted_entries
                error = row.last_error_code
                status = "degraded" if error is not None else "not_started"
            else:
                checked = row.last_checked_unix
                error = row.last_error_code
                count = row.accepted_entries
                if now - checked > self.maximum_stale_seconds:
                    status = "stale"
                elif error is not None:
                    status = "degraded"
                else:
                    status = "current"
            if row is not None and (
                row.binding_sha256 != _target_binding(target) or count != stored_count
            ):
                raise ObserverBundleFeedError("feed_state_cursor_mismatch")
            health.append(FeedHealth(target.validator_account_id32, status, error, checked, count))
        return BundleFeedSnapshot(metadata.windows, tuple(health))

    async def start(self, finalized_height: Callable[[], int], poll_seconds: float) -> None:
        if not callable(finalized_height):
            raise TypeError("finalized height source must be callable")
        if (
            isinstance(poll_seconds, bool)
            or not math.isfinite(poll_seconds)
            or poll_seconds < 1
            or poll_seconds > 3_600
        ):
            raise ValueError("feed poll interval must be finite and from 1 through 3600 seconds")
        if self._task is not None:
            return
        self._stop.clear()
        await self.refresh(finalized_height())

        async def run() -> None:
            while not self._stop.is_set():
                with suppress(Exception):
                    await self.refresh(finalized_height())
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), timeout=poll_seconds)

        self._task = asyncio.create_task(run(), name="umi-observer-bundle-feed")

    async def close(self) -> None:
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    async def _refresh_target(self, target: ObserverFeedTarget, finalized_height: int) -> bool:
        fetcher = self.fetcher_factory(target.public_origin, self.timeout_seconds)
        route = f"validators/{target.validator_account_id32}/index.json"
        async with fetcher.session() as session:
            encoded = await fetcher.fetch(session, route, MAX_PUBLIC_INDEX_BYTES)
            try:
                index = PublicBundleIndex.model_validate_json(encoded)
            except Exception as error:
                raise ObserverBundleFeedError("feed_index_invalid") from error
            if canonical_json_bytes(index) != encoded:
                raise ObserverBundleFeedError("feed_index_noncanonical")
            if (
                index.validator_account_id32 != target.validator_account_id32
                or index.scoring_policy_hash != target.scoring_policy_hash
                or index.release_manifest_sha256 != target.release_manifest_sha256
            ):
                raise ObserverBundleFeedError("feed_index_binding_mismatch")
            prior = self._stored_entries(target.validator_account_id32)
            if len(index.entries) < len(prior) or index.entries[: len(prior)] != list(prior):
                raise ObserverBundleFeedError("feed_index_append_only_violation")
            projections: list[tuple[PublicBundleIndexEntry, bytes]] = []
            new_entries = index.entries[
                len(prior) : len(prior) + self.maximum_new_entries_per_refresh
            ]
            for entry in new_entries:
                if entry.audit_release_block > finalized_height:
                    raise ObserverBundleFeedError("feed_release_block_in_future")
                projection = await self._download_and_verify(fetcher, session, target, entry)
                projection = replace(projection, observer_verified_unix=int(self.clock()))
                projections.append((entry, _projection_bytes(projection)))
        accepted = index.entries[: len(prior) + len(projections)]
        caught_up = len(accepted) == len(index.entries)
        self._commit_success(
            target,
            accepted,
            projections,
            last_error_code=None if caught_up else "feed_backlog_pending",
        )
        return caught_up

    async def _download_and_verify(
        self,
        fetcher: BoundedHTTPSFetcher,
        session: _Session,
        target: ObserverFeedTarget,
        entry: PublicBundleIndexEntry,
    ) -> VerifiedFeedWindow:
        root = Path(tempfile.mkdtemp(prefix=".observer-bundle-", dir=self.temporary_root))
        try:
            objects = root / "objects"
            objects.mkdir(mode=0o700)
            manifest_bytes = await fetcher.fetch(
                session,
                f"{entry.relative_path}/manifest.json",
                MAX_CALIBRATION_MANIFEST_BYTES,
            )
            if hashlib.sha256(manifest_bytes).hexdigest() != entry.manifest_sha256:
                raise ObserverBundleFeedError("feed_manifest_digest_mismatch")
            try:
                manifest = _parse_bundle_manifest(manifest_bytes)
            except AuditPublicationError as error:
                raise ObserverBundleFeedError("feed_manifest_invalid") from error
            references = {item.sha256: item for item in manifest.objects}
            if len(references) != len(manifest.objects) or len(references) > MAX_REMOTE_FILES:
                raise ObserverBundleFeedError("feed_object_set_invalid")
            (root / "manifest.json").write_bytes(manifest_bytes)
            total = len(manifest_bytes)
            for digest, reference in references.items():
                data = await fetcher.fetch(
                    session,
                    f"{entry.relative_path}/objects/{digest}",
                    min(MAX_CALIBRATION_OBJECT_BYTES, reference.size_bytes + 1),
                )
                if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != digest:
                    raise ObserverBundleFeedError("feed_object_digest_mismatch")
                total += len(data)
                if total > MAX_CALIBRATION_BUNDLE_BYTES:
                    raise ObserverBundleFeedError("feed_bundle_byte_limit")
                (objects / digest).write_bytes(data)
            if total != entry.audit_bundle_bytes or total != manifest.audit_bundle_bytes:
                raise ObserverBundleFeedError("feed_bundle_byte_accounting_mismatch")
            tree = _inspect_bundle_tree(root)
            try:
                _bind_tree_to_entry(tree, entry, target.validator_account_id32)
            except AuditPublicationError as error:
                raise ObserverBundleFeedError("feed_tree_index_binding_mismatch") from error
            binding = await target.verifier.verify(root)
            _bind_replay(binding, entry)
            return _extract_projection(
                root,
                manifest_bytes,
                entry,
                target.validator_account_id32,
                target.public_origin,
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def _stored_entries(self, validator: str) -> tuple[PublicBundleIndexEntry, ...]:
        if not any(item.validator_account_id32 == validator for item in self.targets):
            raise ObserverBundleFeedError("feed_state_unconfigured_validator")
        return self._metadata_cache.entries_by_validator.get(validator, ())

    @staticmethod
    def _decode_stored_row(
        row: sqlite3.Row,
        target: ObserverFeedTarget,
    ) -> tuple[PublicBundleIndexEntry, VerifiedFeedWindow]:
        entry_bytes = bytes(row["entry_bytes"])
        try:
            entry = PublicBundleIndexEntry.model_validate_json(entry_bytes)
        except Exception as error:
            raise ObserverBundleFeedError("feed_state_entry_invalid") from error
        if canonical_json_bytes(entry) != entry_bytes:
            raise ObserverBundleFeedError("feed_state_entry_noncanonical")
        try:
            projection = _projection_from_bytes(bytes(row["projection_bytes"]))
        except ObserverBundleFeedError:
            raise
        except Exception as error:
            raise ObserverBundleFeedError("feed_state_projection_invalid") from error
        if (
            row["validator_account"] != target.validator_account_id32
            or row["sequence"] != entry.sequence
            or row["window_id"] != entry.window_id
            or row["window_index"] != entry.window_index
            or row["manifest_sha256"] != entry.manifest_sha256
            or entry.scoring_policy_hash != target.scoring_policy_hash
        ):
            raise ObserverBundleFeedError("feed_state_row_binding_mismatch")
        _bind_projection_to_entry(projection, entry, target.validator_account_id32)
        if projection.public_origin != target.public_origin:
            raise ObserverBundleFeedError("feed_state_projection_origin_mismatch")
        return entry, projection

    def _commit_success(
        self,
        target: ObserverFeedTarget,
        entries: Sequence[PublicBundleIndexEntry],
        additions: Sequence[tuple[PublicBundleIndexEntry, bytes]],
        *,
        last_error_code: str | None,
    ) -> None:
        now = int(self.clock())
        if last_error_code is not None and _REASON_CODE_RE.fullmatch(last_error_code) is None:
            raise ObserverBundleFeedError("feed_state_error_code_invalid")
        current = self._metadata_cache
        prior_entries = current.entries_by_validator.get(target.validator_account_id32, ())
        accepted_entries = tuple(entries)
        addition_entries = tuple(entry for entry, _ in additions)
        if (
            accepted_entries[: len(prior_entries)] != prior_entries
            or accepted_entries[len(prior_entries) :] != addition_entries
        ):
            raise ObserverBundleFeedError("feed_state_cache_prefix_mismatch")
        prepared: list[tuple[PublicBundleIndexEntry, VerifiedFeedWindow, VerifiedFeedWindow]] = []
        for entry, projection_bytes in additions:
            projection = _projection_from_bytes(projection_bytes)
            _bind_projection_to_entry(projection, entry, target.validator_account_id32)
            if projection.public_origin != target.public_origin or projection.solution_count != len(
                projection.solutions
            ):
                raise ObserverBundleFeedError("feed_state_projection_binding_mismatch")
            prepared.append(
                (
                    entry,
                    projection,
                    replace(projection, solutions=()),
                )
            )

        windows = [*current.windows, *(stored for _, _, stored in prepared)]
        windows.sort(key=lambda item: (item.window_index, item.validator_account_id32))
        windows_by_identity = dict(current.windows_by_identity)
        for _, _, stored in prepared:
            identity = (stored.validator_account_id32, stored.window_id)
            if identity in windows_by_identity:
                raise ObserverBundleFeedError("feed_state_cache_duplicate_window")
            windows_by_identity[identity] = stored
        states = dict(current.states)
        states[target.validator_account_id32] = _CachedFeedState(
            last_checked_unix=now,
            last_error_code=last_error_code,
            accepted_entries=len(accepted_entries),
            binding_sha256=_target_binding(target),
        )
        entries_by_validator = dict(current.entries_by_validator)
        entries_by_validator[target.validator_account_id32] = accepted_entries
        next_cache = _FeedMetadataCache(
            tuple(windows),
            MappingProxyType(states),
            MappingProxyType(entries_by_validator),
            MappingProxyType(windows_by_identity),
        )
        with self._transaction() as connection:
            for entry, projection, stored in prepared:
                connection.execute(
                    "INSERT INTO bundles VALUES(?,?,?,?,?,?,?)",
                    (
                        target.validator_account_id32,
                        entry.sequence,
                        entry.window_id,
                        entry.window_index,
                        canonical_json_bytes(entry),
                        _projection_bytes(stored),
                        entry.manifest_sha256,
                    ),
                )
                for ordinal, solution in enumerate(projection.solutions):
                    connection.execute(
                        "INSERT INTO solutions VALUES(?,?,?,?)",
                        (
                            target.validator_account_id32,
                            entry.window_id,
                            ordinal,
                            canonical_json_bytes(_solution_dict(solution)),
                        ),
                    )
            connection.execute(
                "INSERT INTO feeds VALUES(?,?,?,?,?) ON CONFLICT(validator_account) DO UPDATE SET "
                "last_checked_unix=excluded.last_checked_unix,"
                "last_error_code=excluded.last_error_code,"
                "accepted_entries=excluded.accepted_entries,binding_sha256=excluded.binding_sha256",
                (
                    target.validator_account_id32,
                    now,
                    last_error_code,
                    len(entries),
                    _target_binding(target),
                ),
            )
        self._metadata_cache = next_cache

    def _record_failure(self, validator: str, code: str) -> None:
        if _REASON_CODE_RE.fullmatch(code) is None:
            raise ObserverBundleFeedError("feed_state_error_code_invalid")
        current = self._metadata_cache
        existing = current.states.get(validator)
        state = _CachedFeedState(
            last_checked_unix=None if existing is None else existing.last_checked_unix,
            last_error_code=code,
            accepted_entries=0 if existing is None else existing.accepted_entries,
            binding_sha256=self._target_binding_by_account(validator),
        )
        states = dict(current.states)
        states[validator] = state
        next_cache = _FeedMetadataCache(
            current.windows,
            MappingProxyType(states),
            current.entries_by_validator,
            current.windows_by_identity,
        )
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO feeds VALUES(?,?,?,?,?) ON CONFLICT(validator_account) DO UPDATE SET "
                "last_error_code=excluded.last_error_code",
                (validator, None, code, 0, self._target_binding_by_account(validator)),
            )
        self._metadata_cache = next_cache

    def solution_page(
        self, validator: str, window_id: str, *, offset: int, limit: int
    ) -> tuple[int, tuple[VerifiedMinerSolution, ...]]:
        """Load one bounded solution page without materializing feed history."""

        if offset < 0 or limit < 1 or limit > 100:
            raise ValueError("solution page bounds are invalid")
        window = self._metadata_cache.windows_by_identity.get((validator, window_id))
        if window is None:
            raise ObserverBundleFeedError("feed_state_solution_window_missing")
        total = (
            window.solution_count if window.solution_count is not None else len(window.solutions)
        )
        values: list[VerifiedMinerSolution] = []
        expected_ordinal = offset
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT ordinal,solution_bytes FROM solutions "
                "WHERE validator_account=? AND window_id=? AND ordinal>=? "
                "ORDER BY ordinal LIMIT ?",
                (validator, window_id, offset, limit),
            )
            for row in rows:
                if row["ordinal"] != expected_ordinal:
                    raise ObserverBundleFeedError("feed_state_solution_set_invalid")
                expected_ordinal += 1
                encoded = bytes(row["solution_bytes"])
                value = json.loads(encoded)
                if canonical_json_bytes(value) != encoded:
                    raise ObserverBundleFeedError("feed_state_solution_noncanonical")
                values.append(_solution_from_dict(value))
        expected_end = offset if offset >= total else min(total, offset + limit)
        if expected_ordinal != expected_end:
            raise ObserverBundleFeedError("feed_state_solution_set_invalid")
        return total, tuple(values)

    def _target_binding_by_account(self, account: str) -> str:
        target = next(item for item in self.targets if item.validator_account_id32 == account)
        return _target_binding(target)

    def _prepare(self) -> None:
        for path in (self.state_path, self.temporary_root):
            if not path.is_absolute() or Path(os.path.normpath(path)) != path:
                raise ObserverBundleFeedError("feed_state_path_invalid")
        if (
            self.state_path == self.temporary_root
            or self.state_path in self.temporary_root.parents
            or self.temporary_root in self.state_path.parents
        ):
            raise ObserverBundleFeedError("feed_state_path_overlap")
        if self.temporary_root.exists() and (
            self.temporary_root.is_symlink() or not self.temporary_root.is_dir()
        ):
            raise ObserverBundleFeedError("feed_temporary_root_unsafe")
        if self.state_path.exists() and (
            self.state_path.is_symlink() or not self.state_path.is_file()
        ):
            raise ObserverBundleFeedError("feed_state_database_unsafe")
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.temporary_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.temporary_root.chmod(0o700)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata(
                  key TEXT PRIMARY KEY,value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS feeds(
                  validator_account TEXT PRIMARY KEY,last_checked_unix INTEGER,
                  last_error_code TEXT,accepted_entries INTEGER NOT NULL,
                  binding_sha256 TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS bundles(
                  validator_account TEXT NOT NULL,sequence INTEGER NOT NULL,window_id TEXT NOT NULL,
                  window_index INTEGER NOT NULL,entry_bytes BLOB NOT NULL,
                  projection_bytes BLOB NOT NULL,
                  manifest_sha256 TEXT NOT NULL,
                  PRIMARY KEY(validator_account,sequence),UNIQUE(validator_account,window_id)
                ) STRICT;
                CREATE TABLE IF NOT EXISTS solutions(
                  validator_account TEXT NOT NULL,window_id TEXT NOT NULL,
                  ordinal INTEGER NOT NULL,solution_bytes BLOB NOT NULL,
                  PRIMARY KEY(validator_account,window_id,ordinal)
                ) STRICT;
                """
            )
            row = connection.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO metadata VALUES('schema',?)", (OBSERVER_BUNDLE_FEED_STATE_SCHEMA,)
                )
            elif row[0] != OBSERVER_BUNDLE_FEED_STATE_SCHEMA:
                raise ObserverBundleFeedError("feed_state_schema_mismatch")
            binding = hashlib.sha256(
                canonical_json_bytes([_target_binding(item) for item in self.targets])
            ).hexdigest()
            row = connection.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
            if row is None:
                connection.execute("INSERT INTO metadata VALUES('binding',?)", (binding,))
            elif row[0] != binding:
                raise ObserverBundleFeedError("feed_state_binding_mismatch")
            for target in self.targets:
                existing = connection.execute(
                    "SELECT binding_sha256 FROM feeds WHERE validator_account=?",
                    (target.validator_account_id32,),
                ).fetchone()
                if existing is not None and existing[0] != _target_binding(target):
                    raise ObserverBundleFeedError("feed_state_binding_mismatch")
            configured = {item.validator_account_id32 for item in self.targets}
            stored = {
                row[0] for row in connection.execute("SELECT validator_account FROM feeds")
            } | {row[0] for row in connection.execute("SELECT validator_account FROM bundles")}
            if not stored <= configured:
                raise ObserverBundleFeedError("feed_state_unconfigured_validator")
            connection.commit()
        self.state_path.chmod(0o600)
        self._metadata_cache = self._audit_state()

    def _audit_state(self) -> _FeedMetadataCache:
        targets = {item.validator_account_id32: item for item in self.targets}
        windows: list[VerifiedFeedWindow] = []
        entries: dict[str, list[PublicBundleIndexEntry]] = {account: [] for account in targets}
        states: dict[str, _CachedFeedState] = {}
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT validator_account,sequence,window_id,window_index,entry_bytes,"
                "projection_bytes,manifest_sha256 FROM bundles "
                "ORDER BY validator_account,sequence"
            )
            for row in rows:
                account = row["validator_account"]
                target = targets.get(account)
                if target is None:
                    raise ObserverBundleFeedError("feed_state_unconfigured_validator")
                if row["sequence"] != len(entries[account]):
                    raise ObserverBundleFeedError("feed_state_sequence_invalid")
                entry, projection = self._decode_stored_row(row, target)
                entries[account].append(entry)
                windows.append(projection)
                expected_count = (
                    len(projection.solutions)
                    if projection.solution_count is None
                    else projection.solution_count
                )
                solution_rows = connection.execute(
                    "SELECT ordinal,solution_bytes FROM solutions "
                    "WHERE validator_account=? AND window_id=? ORDER BY ordinal",
                    (account, row["window_id"]),
                )
                seen = 0
                for solution_row in solution_rows:
                    if solution_row["ordinal"] != seen:
                        raise ObserverBundleFeedError("feed_state_solution_set_invalid")
                    seen += 1
                    encoded = bytes(solution_row["solution_bytes"])
                    value = json.loads(encoded)
                    if canonical_json_bytes(value) != encoded:
                        raise ObserverBundleFeedError("feed_state_solution_noncanonical")
                    _solution_from_dict(value)
                if seen != expected_count:
                    raise ObserverBundleFeedError("feed_state_solution_set_invalid")
            for row in connection.execute("SELECT * FROM feeds ORDER BY validator_account"):
                account = row["validator_account"]
                if account not in targets:
                    raise ObserverBundleFeedError("feed_state_unconfigured_validator")
                states[account] = _CachedFeedState(
                    last_checked_unix=(
                        None if row["last_checked_unix"] is None else int(row["last_checked_unix"])
                    ),
                    last_error_code=row["last_error_code"],
                    accepted_entries=int(row["accepted_entries"]),
                    binding_sha256=row["binding_sha256"],
                )
        for account, values in entries.items():
            state = states.get(account)
            if state is None and values:
                raise ObserverBundleFeedError("feed_state_cursor_missing")
            if state is not None and (
                state.accepted_entries != len(values)
                or state.binding_sha256 != _target_binding(targets[account])
            ):
                raise ObserverBundleFeedError("feed_state_cursor_mismatch")
        windows.sort(key=lambda item: (item.window_index, item.validator_account_id32))
        window_index = {(item.validator_account_id32, item.window_id): item for item in windows}
        if len(window_index) != len(windows):
            raise ObserverBundleFeedError("feed_state_row_binding_mismatch")
        return _FeedMetadataCache(
            tuple(windows),
            MappingProxyType(states),
            MappingProxyType({account: tuple(values) for account, values in entries.items()}),
            MappingProxyType(window_index),
        )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self.state_path.exists() and (
            self.state_path.is_symlink() or not self.state_path.is_file()
        ):
            raise ObserverBundleFeedError("feed_state_database_unsafe")
        connection = sqlite3.connect(self.state_path, timeout=5)
        connection.row_factory = sqlite3.Row
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        maximum_pages = self.maximum_state_database_bytes // page_size
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_count > maximum_pages:
            connection.close()
            raise ObserverBundleFeedError("feed_state_database_byte_limit")
        configured_pages = int(
            connection.execute(f"PRAGMA max_page_count={maximum_pages}").fetchone()[0]
        )
        if configured_pages != maximum_pages:
            connection.close()
            raise ObserverBundleFeedError("feed_state_database_byte_limit")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
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
                connection.rollback()
                raise
            else:
                connection.commit()


def load_observer_bundle_feed_config(path: str | Path) -> ObserverBundleFeedConfig:
    try:
        encoded = _read_regular_file(Path(path), maximum_bytes=256 * 1024, empty_allowed=False)
    except AuditPublicationError as error:
        raise ObserverBundleFeedError("feed_config_invalid") from error
    payload = encoded[:-1] if encoded.endswith(b"\n") and not encoded.endswith(b"\n\n") else encoded
    try:
        config = ObserverBundleFeedConfig.model_validate_json(payload)
    except (ValidationError, ValueError) as error:
        raise ObserverBundleFeedError("feed_config_invalid") from error
    if canonical_json_bytes(config) != payload:
        raise ObserverBundleFeedError("feed_config_noncanonical")
    return config


def build_production_observer_bundle_feed(path: str | Path) -> tuple[ObserverBundleFeed, float]:
    config = load_observer_bundle_feed_config(path)
    targets: list[ObserverFeedTarget] = []
    for item in config.targets:
        definition = load_production_publication_definition(item.publication_config_path)
        published_origin = definition.publication_config.public_origin
        if published_origin != item.public_origin:
            raise ObserverBundleFeedError("feed_origin_release_binding_mismatch")
        targets.append(
            ObserverFeedTarget(
                validator_account_id32=definition.validator_config.validator_account_id32,
                scoring_policy_hash=definition.validator_config.scoring_policy_sha256,
                release_manifest_sha256=definition.release_manifest_sha256,
                public_origin=item.public_origin,
                verifier=definition.verifier,
            )
        )
    return (
        ObserverBundleFeed(
            targets=targets,
            state_database_path=Path(config.state_database_path),
            temporary_root=Path(config.temporary_root),
            maximum_stale_seconds=config.maximum_stale_seconds,
            timeout_seconds=config.request_timeout_seconds,
            maximum_new_entries_per_refresh=config.maximum_new_entries_per_refresh,
            maximum_target_refresh_seconds=config.maximum_target_refresh_seconds,
            maximum_concurrent_targets=config.maximum_concurrent_targets,
            maximum_state_database_bytes=config.maximum_state_database_bytes,
        ),
        config.poll_seconds,
    )


def _bind_replay(binding: VerifiedPublishedBundle, entry: PublicBundleIndexEntry) -> None:
    if not isinstance(binding, VerifiedPublishedBundle) or (
        binding.manifest_sha256 != entry.manifest_sha256
        or binding.window_id != entry.window_id
        or binding.window_index != entry.window_index
        or binding.scoring_policy_hash != entry.scoring_policy_hash
        or binding.terminal_classification != entry.terminal_classification
        or binding.highest_stage != entry.highest_stage
        or binding.audit_release_block != entry.audit_release_block
        or binding.audit_release_block_hash != entry.audit_release_block_hash
        or binding.reason_codes != tuple(entry.reason_codes)
    ):
        raise ObserverBundleFeedError("feed_replay_binding_mismatch")


def _strict_json_object(encoded: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(encoded, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("JSON value is not an object")
    return value


def _verified_reference(
    object_table: dict[str, Any],
    reference: Any,
) -> VerifiedEvidenceObject:
    try:
        digest = reference.sha256
        media_type = reference.media_type
        size_bytes = reference.size_bytes
    except AttributeError:
        try:
            parsed = StageObject.model_validate(reference)
        except Exception as error:
            raise ObserverBundleFeedError("feed_evidence_reference_invalid") from error
        digest, media_type, size_bytes = parsed.sha256, parsed.media_type, parsed.size_bytes
    declared = object_table.get(digest)
    if declared is None or (declared.media_type != media_type or declared.size_bytes != size_bytes):
        raise ObserverBundleFeedError("feed_evidence_reference_mismatch")
    return VerifiedEvidenceObject(digest, media_type, size_bytes)


def _read_object(root: Path, object_table: dict[str, Any], reference: Any) -> bytes:
    verified = _verified_reference(object_table, reference)
    path = root / "objects" / verified.sha256
    try:
        encoded = path.read_bytes()
    except OSError as error:
        raise ObserverBundleFeedError("feed_evidence_object_missing") from error
    if (
        len(encoded) != verified.size_bytes
        or hashlib.sha256(encoded).hexdigest() != verified.sha256
    ):
        raise ObserverBundleFeedError("feed_evidence_object_mismatch")
    return encoded


def _parse_object_model(
    root: Path,
    object_table: dict[str, Any],
    reference: Any,
    model: type[Any],
    error_code: str,
) -> Any:
    encoded = _read_object(root, object_table, reference)
    try:
        value = model.model_validate_json(encoded)
    except Exception as error:
        raise ObserverBundleFeedError(error_code) from error
    if canonical_json_bytes(value) != encoded:
        raise ObserverBundleFeedError(error_code)
    return value


def _schema_references(
    root: Path,
    object_table: dict[str, Any],
    references: Sequence[Any],
    schema: str,
) -> list[tuple[Any, dict[str, Any]]]:
    matches: list[tuple[Any, dict[str, Any]]] = []
    for reference in references:
        if reference.media_type != "application/json":
            continue
        encoded = _read_object(root, object_table, reference)
        try:
            value = _strict_json_object(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            continue
        if value.get("schema") == schema:
            matches.append((reference, value))
    return matches


def _inline_reference(object_table: dict[str, Any], value: Any) -> VerifiedEvidenceObject | None:
    if value is None:
        return None
    return _verified_reference(object_table, value)


def _inline_json_reference(object_table: dict[str, Any], value: Any) -> VerifiedEvidenceObject:
    if not isinstance(value, dict):
        raise ObserverBundleFeedError("feed_solution_decryption_invalid")
    encoded = canonical_json_bytes(value)
    digest = hashlib.sha256(encoded).hexdigest()
    declared = object_table.get(digest)
    if (
        declared is None
        or declared.media_type != "application/json"
        or (declared.size_bytes != len(encoded))
    ):
        raise ObserverBundleFeedError("feed_solution_decryption_reference_missing")
    return VerifiedEvidenceObject(digest, declared.media_type, declared.size_bytes)


def _exact_fraction(value: Any) -> tuple[int, int] | tuple[None, None]:
    if value is None:
        return None, None
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise ObserverBundleFeedError("feed_solution_score_invalid")
    numerator, denominator = value["numerator"], value["denominator"]
    if (
        isinstance(numerator, bool)
        or isinstance(denominator, bool)
        or not isinstance(numerator, int)
        or not isinstance(denominator, int)
        or denominator <= 0
        or numerator < 0
        or numerator > denominator
    ):
        raise ObserverBundleFeedError("feed_solution_score_invalid")
    return numerator, denominator


def _extract_solutions(
    *,
    root: Path,
    object_table: dict[str, Any],
    reveal_manifest: RevealStageManifest,
    result: RevealResult,
) -> tuple[VerifiedMinerSolution, ...]:
    policy = _parse_object_model(
        root,
        object_table,
        reveal_manifest.policy_object,
        ScoringPolicy,
        "feed_solution_policy_invalid",
    )
    if policy.translation_weights_active:
        raise ObserverBundleFeedError("feed_solution_policy_invalid")
    pulse = _strict_json_object(_read_object(root, object_table, reveal_manifest.reveal_pulse))
    pulse_signature = pulse.get("signature")
    if not isinstance(pulse_signature, str):
        raise ObserverBundleFeedError("feed_solution_reveal_pulse_invalid")
    response_receipt = _parse_object_model(
        root,
        object_table,
        reveal_manifest.response_stage_receipt,
        StageReceipt,
        "feed_response_receipt_invalid",
    )
    transcript_matches = _schema_references(
        root,
        object_table,
        response_receipt.objects,
        "umi-validator-transcript-stage/1",
    )
    if len(transcript_matches) != 1:
        raise ObserverBundleFeedError("feed_response_manifest_missing_or_duplicate")
    transcript_ref, transcript_value = transcript_matches[0]
    del transcript_ref
    try:
        transcript = _ResponseStageManifest.model_validate(transcript_value)
    except Exception as error:
        raise ObserverBundleFeedError("feed_response_manifest_invalid") from error
    transcript_bytes = canonical_json_bytes(transcript)
    if (
        transcript.window_id != result.window_id
        or transcript.scoring_policy_hash != result.scoring_policy_hash
        or transcript_bytes != _read_object(root, object_table, transcript_matches[0][0])
    ):
        raise ObserverBundleFeedError("feed_response_manifest_binding_mismatch")
    assignments = {item.assignment_id: item for item in transcript.assignments}
    response_ids = [item.get("assignment_id") for item in result.responses]
    if (
        len(result.responses) != result.issued_request_count
        or response_ids != sorted(assignments)
        or len(response_ids) > MAX_REVEAL_ASSIGNMENTS
    ):
        raise ObserverBundleFeedError("feed_solution_assignment_set_mismatch")

    ground_truth: dict[
        str,
        tuple[
            GroundTruthPayload | None,
            VerifiedEvidenceObject | None,
            VerifiedEvidenceObject | None,
            bool,
        ],
    ] = {}
    for candidate in result.candidate_reveals:
        if not isinstance(candidate, dict):
            raise ObserverBundleFeedError("feed_candidate_reveal_invalid")
        batch_id = candidate.get("batch_id")
        if not isinstance(batch_id, str) or batch_id in ground_truth:
            raise ObserverBundleFeedError("feed_candidate_reveal_invalid")
        plaintext_ref = _inline_reference(object_table, candidate.get("plaintext"))
        parsed: GroundTruthPayload | None = None
        if plaintext_ref is not None:
            plaintext_bytes = _read_object(root, object_table, plaintext_ref)
            try:
                candidate_payload = GroundTruthPayload.model_validate_json(plaintext_bytes)
            except Exception:
                candidate_payload = None
            if (
                candidate_payload is not None
                and canonical_json_bytes(candidate_payload) == plaintext_bytes
            ):
                parsed = candidate_payload
        shape_valid = candidate.get("ground_truth_shape_valid") is True
        if parsed is not None and (
            parsed.window_id != result.window_id
            or parsed.batch_id != batch_id
            or parsed.scoring_policy_hash != result.scoring_policy_hash
        ):
            parsed = None
        ground_truth[batch_id] = (
            parsed,
            plaintext_ref,
            _inline_json_reference(object_table, candidate.get("decryption")),
            shape_valid,
        )

    solutions: list[VerifiedMinerSolution] = []
    for record in result.responses:
        assignment_id = record.get("assignment_id")
        if not isinstance(assignment_id, str) or assignment_id not in assignments:
            raise ObserverBundleFeedError("feed_solution_record_invalid")
        manifest_assignment = assignments[assignment_id]
        selected_attempt = next(
            (item for item in manifest_assignment.attempts if item.final),
            manifest_assignment.attempts[-1],
        )
        prepared = _parse_object_model(
            root,
            object_table,
            selected_attempt.prepared_evidence,
            PreparedAttemptEvidence,
            "feed_solution_prepared_evidence_invalid",
        )
        request = _parse_object_model(
            root,
            object_table,
            prepared.request_object,
            TranslationRequest,
            "feed_solution_request_invalid",
        )
        outcome = _parse_object_model(
            root,
            object_table,
            selected_attempt.outcome_evidence,
            AttemptOutcomeEvidence,
            "feed_solution_outcome_invalid",
        )
        request_leaf = record.get("request_leaf")
        batch_id = record.get("batch_id")
        challenge_id = record.get("challenge_id")
        miner_hotkey = record.get("miner_hotkey")
        miner_root = record.get("miner_root")
        outer_disposition = record.get("outer_disposition")
        if (
            not isinstance(request_leaf, str)
            or _HEX32_RE.fullmatch(request_leaf) is None
            or not isinstance(miner_root, str)
            or _HEX32_RE.fullmatch(miner_root) is None
            or not isinstance(batch_id, str)
            or not isinstance(challenge_id, str)
            or not isinstance(miner_hotkey, str)
            or outer_disposition
            not in {"sealed", "missing", "late", "outer_invalid", "resource_limit"}
            or manifest_assignment.miner_hotkey != miner_hotkey
            or prepared.assignment_id != assignment_id
            or prepared.miner_hotkey != miner_hotkey
            or request.window_id != result.window_id
            or request.scoring_policy_hash != result.scoring_policy_hash
            or request.batch_id != batch_id
            or request.challenge_id != challenge_id
            or outcome.assignment_id != assignment_id
            or outcome.attempt_index != selected_attempt.attempt_index
            or outcome.sealed_response_record.disposition != outer_disposition
        ):
            raise ObserverBundleFeedError("feed_solution_record_binding_mismatch")

        response_ref = _inline_reference(object_table, record.get("plaintext"))
        response_valid = False
        response_status: Literal["ok", "error"] | None = None
        hypothesis: str | None = None
        response_error: str | None = None
        model_revision: str | None = None
        if response_ref is not None:
            response_bytes = _read_object(root, object_table, response_ref)
            retained = outcome.retained_body
            signature = outcome.sealed_response_record.signature
            if retained is not None and signature is not None:
                envelope_bytes = _read_object(root, object_table, retained)
                try:
                    envelope, sealed = validate_response_envelope(
                        envelope_bytes,
                        signature,
                        request=request,
                        validator_hotkey=prepared.validator_hotkey,
                        miner_hotkey=prepared.miner_hotkey,
                    )
                    parsed_response = validate_response_plaintext(
                        response_bytes,
                        envelope=envelope,
                        request=request,
                    )
                    if (
                        decrypt_with_signature(sealed.portable_bytes, pulse_signature)
                        != response_bytes
                    ):
                        raise ObserverBundleFeedError("feed_solution_plaintext_ciphertext_mismatch")
                except ComponentResponseError as error:
                    parsed_response = None
                    recomputed_zero_reason = error.code
                except (TypeError, ValueError):
                    parsed_response = None
                    recomputed_zero_reason = "plaintext_invalid"
                if parsed_response is not None:
                    response_valid = True
                    response_status = parsed_response.status
                    hypothesis, recomputed_zero_reason = _response_hypothesis(
                        parsed_response, request=request, policy=policy
                    )
                    response_error = parsed_response.error_code
                    model_revision = parsed_response.model_revision
            else:
                recomputed_zero_reason = "plaintext_invalid"
        else:
            recomputed_zero_reason = (
                outer_disposition if outer_disposition != "sealed" else "undecryptable"
            )

        payload, ground_ref, ground_decryption, shape_valid = ground_truth.get(
            batch_id, (None, None, None, False)
        )
        ground_item = (
            None
            if payload is None or not shape_valid
            else next((item for item in payload.items if item.challenge_id == challenge_id), None)
        )
        metric = None if ground_item is None else ground_item.metric
        canary = record.get("canary")
        if canary is not None and not isinstance(canary, bool):
            raise ObserverBundleFeedError("feed_solution_record_invalid")
        if ground_item is not None and canary != ground_item.canary:
            raise ObserverBundleFeedError("feed_solution_ground_truth_mismatch")
        zero_reason = record.get("zero_score_reason")
        if zero_reason is not None and (
            not isinstance(zero_reason, str) or _REASON_CODE_RE.fullmatch(zero_reason) is None
        ):
            raise ObserverBundleFeedError("feed_solution_record_invalid")
        if zero_reason != recomputed_zero_reason:
            raise ObserverBundleFeedError("feed_solution_zero_reason_mismatch")
        score_numerator, score_denominator = _exact_fraction(record.get("score"))
        score_trace = record.get("score_trace")
        canary_result = record.get("canary_result")
        if score_trace is not None and not isinstance(score_trace, dict):
            raise ObserverBundleFeedError("feed_solution_score_trace_invalid")
        if canary_result is not None and not isinstance(canary_result, dict):
            raise ObserverBundleFeedError("feed_solution_canary_result_invalid")
        if ground_item is not None:
            if ground_item.canary:
                recomputed_canary = evaluate_canary(
                    ground_item,
                    hypothesis,
                    cer_threshold=policy.thresholds.canary_cer_hit_threshold.fraction,
                    wer_threshold=policy.thresholds.canary_wer_hit_threshold.fraction,
                )
                expected_canary = {
                    "metric": recomputed_canary.metric,
                    "score": {
                        "numerator": recomputed_canary.score.numerator,
                        "denominator": recomputed_canary.score.denominator,
                    },
                    "threshold": {
                        "numerator": recomputed_canary.threshold.numerator,
                        "denominator": recomputed_canary.threshold.denominator,
                    },
                    "hit": recomputed_canary.hit,
                    "trace": (
                        None
                        if recomputed_canary.trace is None
                        else recomputed_canary.trace.to_record()
                    ),
                }
                if (
                    record.get("score") is not None
                    or score_trace is not None
                    or canary_result != expected_canary
                ):
                    raise ObserverBundleFeedError("feed_solution_canary_replay_mismatch")
            else:
                if hypothesis is None:
                    expected_score = {"numerator": 0, "denominator": 1}
                    expected_trace = None
                else:
                    trace = (
                        score_cer_with_trace(hypothesis, ground_item.references)
                        if ground_item.metric == "cer"
                        else score_wer_with_trace(hypothesis, ground_item.references)
                    )
                    expected_score = {
                        "numerator": trace.score.numerator,
                        "denominator": trace.score.denominator,
                    }
                    expected_trace = trace.to_record()
                if (
                    record.get("score") != expected_score
                    or score_trace != expected_trace
                    or canary_result is not None
                ):
                    raise ObserverBundleFeedError("feed_solution_score_replay_mismatch")
        solutions.append(
            VerifiedMinerSolution(
                assignment_id=assignment_id,
                request_leaf=request_leaf,
                batch_id=batch_id,
                challenge_id=challenge_id,
                miner_hotkey=miner_hotkey,
                miner_root_account_id32=miner_root,
                stratum=request.task.stratum,
                metric=metric,
                canary=canary,
                outer_disposition=outer_disposition,
                zero_score_reason=zero_reason,
                response_plaintext_valid=response_valid,
                response_status=response_status,
                hypothesis=hypothesis,
                response_error_code=response_error,
                model_revision=model_revision,
                references=() if ground_item is None else tuple(ground_item.references),
                canary_actual_references=(
                    ()
                    if ground_item is None or ground_item.canary_evidence is None
                    else tuple(ground_item.canary_evidence.actual_references)
                ),
                score_numerator=score_numerator,
                score_denominator=score_denominator,
                score_trace=score_trace,
                canary_result=canary_result,
                evidence=VerifiedSolutionEvidence(
                    prepared_attempt=_verified_reference(
                        object_table, selected_attempt.prepared_evidence
                    ),
                    request=_verified_reference(object_table, prepared.request_object),
                    attempt_outcome=_verified_reference(
                        object_table, selected_attempt.outcome_evidence
                    ),
                    retained_response=_inline_reference(object_table, outcome.retained_body),
                    response_plaintext=response_ref,
                    response_decryption=_inline_json_reference(
                        object_table, record.get("decryption")
                    ),
                    ground_truth_plaintext=ground_ref,
                    ground_truth_decryption=ground_decryption,
                ),
            )
        )
    return tuple(solutions)


def _extract_projection(
    root: Path,
    manifest_bytes: bytes,
    entry: PublicBundleIndexEntry,
    validator: str,
    public_origin: str,
) -> VerifiedFeedWindow:
    manifest = _parse_bundle_manifest(manifest_bytes)
    object_table = {item.sha256: item for item in manifest.objects}
    scores: tuple[ValidatorLocalScore, ...] = ()
    weight_manifest: WeightBuildStageManifest | None = None
    for child in (root / "objects").iterdir():
        data = child.read_bytes()
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict) or value.get("schema") != WEIGHT_BUILD_STAGE_SCHEMA:
            continue
        if canonical_json_bytes(value) != data:
            raise ObserverBundleFeedError("feed_score_object_noncanonical")
        if weight_manifest is not None:
            raise ObserverBundleFeedError("feed_weight_manifest_duplicate")
        try:
            weight_manifest = WeightBuildStageManifest.model_validate(value)
        except Exception as error:
            raise ObserverBundleFeedError("feed_weight_manifest_invalid") from error
        if (
            weight_manifest.window_id != entry.window_id
            or weight_manifest.window_index != entry.window_index
            or weight_manifest.scoring_policy_hash != entry.scoring_policy_hash
        ):
            raise ObserverBundleFeedError("feed_weight_manifest_binding_mismatch")
    if weight_manifest is not None:
        reference = weight_manifest.weight_build_result
        result_bytes = (root / "objects" / reference.sha256).read_bytes()
        if (
            len(result_bytes) != reference.size_bytes
            or hashlib.sha256(result_bytes).hexdigest() != reference.sha256
        ):
            raise ObserverBundleFeedError("feed_score_reference_mismatch")
        try:
            result = WeightBuildResultEvidence.model_validate_json(result_bytes)
        except Exception as error:
            raise ObserverBundleFeedError("feed_score_object_invalid") from error
        if (
            canonical_json_bytes(result) != result_bytes
            or result.schema_ != WEIGHT_BUILD_RESULT_SCHEMA
        ):
            raise ObserverBundleFeedError("feed_score_object_noncanonical")
        if (
            result.window_id != entry.window_id
            or result.window_index != entry.window_index
            or result.scoring_policy_hash != entry.scoring_policy_hash
        ):
            raise ObserverBundleFeedError("feed_score_object_binding_mismatch")
        parsed: list[ValidatorLocalScore] = []
        for score in result.miner_scores:
            parsed.append(
                ValidatorLocalScore(
                    miner_root_account_id32=score.miner_root,
                    assigned_clips=score.assigned_clips,
                    accuracy_numerator=int(score.accuracy.numerator),
                    accuracy_denominator=int(score.accuracy.denominator),
                    eligible=score.eligible,
                    utility_numerator=int(score.utility.numerator),
                    utility_denominator=int(score.utility.denominator),
                )
            )
        scores = tuple(parsed)
    reveal_stage_ref: VerifiedEvidenceObject | None = None
    reveal_result_ref: VerifiedEvidenceObject | None = None
    solutions: tuple[VerifiedMinerSolution, ...] = ()
    reveal_stage_record = next(
        (item for item in manifest.stages if item.stage_id == "reveal_and_score"),
        None,
    )
    if reveal_stage_record is not None and reveal_stage_record.status == "reached":
        stage_evidence = _parse_object_model(
            root,
            object_table,
            reveal_stage_record.evidence_object,
            CalibrationStageEvidence,
            "feed_reveal_stage_evidence_invalid",
        )
        if (
            stage_evidence.stage_id != "reveal_and_score"
            or stage_evidence.window_id != entry.window_id
            or stage_evidence.scoring_policy_hash != entry.scoring_policy_hash
        ):
            raise ObserverBundleFeedError("feed_reveal_stage_evidence_binding_mismatch")
        receipt = _parse_object_model(
            root,
            object_table,
            stage_evidence.receipt_object,
            StageReceipt,
            "feed_reveal_receipt_invalid",
        )
        reveal_matches = _schema_references(
            root,
            object_table,
            receipt.objects,
            REVEAL_STAGE_SCHEMA,
        )
        if len(reveal_matches) > 1:
            raise ObserverBundleFeedError("feed_reveal_manifest_duplicate")
        if reveal_matches:
            raw_ref, reveal_manifest = reveal_matches[0]
            try:
                reveal_manifest = RevealStageManifest.model_validate(reveal_manifest)
            except Exception as error:
                raise ObserverBundleFeedError("feed_reveal_manifest_invalid") from error
            reveal_bytes = _read_object(root, object_table, raw_ref)
            if canonical_json_bytes(reveal_manifest) != reveal_bytes:
                raise ObserverBundleFeedError("feed_reveal_manifest_noncanonical")
            if (
                reveal_manifest.window_id != entry.window_id
                or reveal_manifest.window_index != entry.window_index
                or reveal_manifest.scoring_policy_hash != entry.scoring_policy_hash
            ):
                raise ObserverBundleFeedError("feed_reveal_manifest_binding_mismatch")
            reveal_stage_ref = _verified_reference(object_table, raw_ref)
            result_bytes = _read_object(root, object_table, reveal_manifest.reveal_result)
            reveal_result_ref = _verified_reference(object_table, reveal_manifest.reveal_result)
            try:
                result_document = _strict_json_object(result_bytes)
            except ValueError as error:
                raise ObserverBundleFeedError("feed_reveal_result_invalid") from error
            if canonical_json_bytes(result_document) != result_bytes:
                raise ObserverBundleFeedError("feed_reveal_result_noncanonical")
            if result_document.get("schema") == REVEAL_RESULT_SCHEMA:
                try:
                    result = RevealResult.model_validate(result_document)
                except Exception as error:
                    raise ObserverBundleFeedError("feed_reveal_result_invalid") from error
                if (
                    result.window_id != entry.window_id
                    or result.window_index != entry.window_index
                    or result.scoring_policy_hash != entry.scoring_policy_hash
                ):
                    raise ObserverBundleFeedError("feed_reveal_result_binding_mismatch")
                solutions = _extract_solutions(
                    root=root,
                    object_table=object_table,
                    reveal_manifest=reveal_manifest,
                    result=result,
                )
    return VerifiedFeedWindow(
        validator_account_id32=validator,
        window_id=entry.window_id,
        window_index=entry.window_index,
        terminal_classification=entry.terminal_classification,
        reason_codes=tuple(entry.reason_codes),
        scoring_policy_hash=entry.scoring_policy_hash,
        audit_release_block=entry.audit_release_block,
        audit_release_block_hash=entry.audit_release_block_hash,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        tree_sha256=entry.tree_sha256,
        public_origin=public_origin,
        bundle_relative_path=entry.relative_path,
        reveal_stage_manifest=reveal_stage_ref,
        reveal_result=reveal_result_ref,
        solutions=solutions,
        scores=scores,
        solution_count=len(solutions),
    )


def _projection_bytes(value: VerifiedFeedWindow) -> bytes:
    return canonical_json_bytes(
        {
            "audit_release_block": value.audit_release_block,
            "audit_release_block_hash": value.audit_release_block_hash,
            "manifest_sha256": value.manifest_sha256,
            "observer_verified_unix": value.observer_verified_unix,
            "bundle_relative_path": value.bundle_relative_path,
            "public_origin": value.public_origin,
            "reason_codes": list(value.reason_codes),
            "reveal_result": _evidence_dict(value.reveal_result),
            "reveal_stage_manifest": _evidence_dict(value.reveal_stage_manifest),
            "scores": [
                {
                    "accuracy_denominator": score.accuracy_denominator,
                    "accuracy_numerator": score.accuracy_numerator,
                    "assigned_clips": score.assigned_clips,
                    "eligible": score.eligible,
                    "miner_root_account_id32": score.miner_root_account_id32,
                    "utility_denominator": score.utility_denominator,
                    "utility_numerator": score.utility_numerator,
                }
                for score in value.scores
            ],
            "scoring_policy_hash": value.scoring_policy_hash,
            "solutions": [_solution_dict(item) for item in value.solutions],
            "solution_count": (
                len(value.solutions) if value.solution_count is None else value.solution_count
            ),
            "terminal_classification": value.terminal_classification,
            "tree_sha256": value.tree_sha256,
            "validator_account_id32": value.validator_account_id32,
            "window_id": value.window_id,
            "window_index": value.window_index,
        }
    )


def _projection_from_bytes(encoded: bytes) -> VerifiedFeedWindow:
    value = json.loads(encoded)
    if canonical_json_bytes(value) != encoded:
        raise ObserverBundleFeedError("feed_state_projection_noncanonical")
    return VerifiedFeedWindow(
        validator_account_id32=value["validator_account_id32"],
        window_id=value["window_id"],
        window_index=value["window_index"],
        terminal_classification=value["terminal_classification"],
        reason_codes=tuple(value["reason_codes"]),
        scoring_policy_hash=value["scoring_policy_hash"],
        audit_release_block=value["audit_release_block"],
        audit_release_block_hash=value["audit_release_block_hash"],
        manifest_sha256=value["manifest_sha256"],
        tree_sha256=value["tree_sha256"],
        public_origin=value["public_origin"],
        bundle_relative_path=value["bundle_relative_path"],
        reveal_stage_manifest=_evidence_from_dict(value["reveal_stage_manifest"]),
        reveal_result=_evidence_from_dict(value["reveal_result"]),
        solutions=tuple(_solution_from_dict(item) for item in value["solutions"]),
        scores=tuple(ValidatorLocalScore(**item) for item in value["scores"]),
        observer_verified_unix=value["observer_verified_unix"],
        solution_count=value.get("solution_count", len(value["solutions"])),
    )


def _evidence_dict(value: VerifiedEvidenceObject | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return {
        "media_type": value.media_type,
        "sha256": value.sha256,
        "size_bytes": value.size_bytes,
    }


def _evidence_from_dict(value: Any) -> VerifiedEvidenceObject | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ObserverBundleFeedError("feed_state_evidence_reference_invalid")
    return VerifiedEvidenceObject(**value)


def _solution_dict(value: VerifiedMinerSolution) -> dict[str, Any]:
    return {
        "assignment_id": value.assignment_id,
        "batch_id": value.batch_id,
        "canary": value.canary,
        "canary_actual_references": list(value.canary_actual_references),
        "canary_result": value.canary_result,
        "challenge_id": value.challenge_id,
        "evidence": {
            "attempt_outcome": _evidence_dict(value.evidence.attempt_outcome),
            "ground_truth_decryption": _evidence_dict(value.evidence.ground_truth_decryption),
            "ground_truth_plaintext": _evidence_dict(value.evidence.ground_truth_plaintext),
            "prepared_attempt": _evidence_dict(value.evidence.prepared_attempt),
            "request": _evidence_dict(value.evidence.request),
            "response_decryption": _evidence_dict(value.evidence.response_decryption),
            "response_plaintext": _evidence_dict(value.evidence.response_plaintext),
            "retained_response": _evidence_dict(value.evidence.retained_response),
        },
        "hypothesis": value.hypothesis,
        "metric": value.metric,
        "miner_hotkey": value.miner_hotkey,
        "miner_root_account_id32": value.miner_root_account_id32,
        "model_revision": value.model_revision,
        "outer_disposition": value.outer_disposition,
        "references": list(value.references),
        "request_leaf": value.request_leaf,
        "response_error_code": value.response_error_code,
        "response_plaintext_valid": value.response_plaintext_valid,
        "response_status": value.response_status,
        "score_denominator": value.score_denominator,
        "score_numerator": value.score_numerator,
        "score_trace": value.score_trace,
        "stratum": value.stratum,
        "zero_score_reason": value.zero_score_reason,
    }


def _solution_from_dict(value: Any) -> VerifiedMinerSolution:
    if not isinstance(value, dict):
        raise ObserverBundleFeedError("feed_state_solution_invalid")
    fields = dict(value)
    evidence = fields.pop("evidence", None)
    if not isinstance(evidence, dict):
        raise ObserverBundleFeedError("feed_state_solution_evidence_invalid")
    required = {
        "attempt_outcome",
        "ground_truth_decryption",
        "ground_truth_plaintext",
        "prepared_attempt",
        "request",
        "response_decryption",
        "response_plaintext",
        "retained_response",
    }
    if set(evidence) != required:
        raise ObserverBundleFeedError("feed_state_solution_evidence_invalid")
    fields["references"] = tuple(fields["references"])
    fields["canary_actual_references"] = tuple(fields["canary_actual_references"])
    fields["evidence"] = VerifiedSolutionEvidence(
        prepared_attempt=_required_evidence(evidence["prepared_attempt"]),
        request=_required_evidence(evidence["request"]),
        attempt_outcome=_required_evidence(evidence["attempt_outcome"]),
        retained_response=_evidence_from_dict(evidence["retained_response"]),
        response_plaintext=_evidence_from_dict(evidence["response_plaintext"]),
        response_decryption=_required_evidence(evidence["response_decryption"]),
        ground_truth_plaintext=_evidence_from_dict(evidence["ground_truth_plaintext"]),
        ground_truth_decryption=_evidence_from_dict(evidence["ground_truth_decryption"]),
    )
    return VerifiedMinerSolution(**fields)


def _required_evidence(value: Any) -> VerifiedEvidenceObject:
    parsed = _evidence_from_dict(value)
    if parsed is None:
        raise ObserverBundleFeedError("feed_state_solution_evidence_invalid")
    return parsed


def _bind_projection_to_entry(
    projection: VerifiedFeedWindow,
    entry: PublicBundleIndexEntry,
    validator_account: str,
) -> None:
    if (
        projection.validator_account_id32 != validator_account
        or projection.window_id != entry.window_id
        or projection.window_index != entry.window_index
        or projection.terminal_classification != entry.terminal_classification
        or projection.reason_codes != tuple(entry.reason_codes)
        or projection.scoring_policy_hash != entry.scoring_policy_hash
        or projection.audit_release_block != entry.audit_release_block
        or projection.audit_release_block_hash != entry.audit_release_block_hash
        or projection.manifest_sha256 != entry.manifest_sha256
        or projection.tree_sha256 != entry.tree_sha256
        or projection.bundle_relative_path != entry.relative_path
    ):
        raise ObserverBundleFeedError("feed_state_projection_binding_mismatch")


def _target_binding(target: ObserverFeedTarget) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "origin": target.public_origin,
                "policy": target.scoring_policy_hash,
                "release": target.release_manifest_sha256,
                "validator": target.validator_account_id32,
            }
        )
    ).hexdigest()


def _safe_relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise ObserverBundleFeedError("feed_path_invalid")
    if value != path.as_posix() or any(not part.isascii() for part in path.parts):
        raise ObserverBundleFeedError("feed_path_invalid")


def _header_size(headers: httpx.Headers) -> int:
    return (
        sum(
            len(key.encode("ascii")) + len(value.encode("latin-1")) + 4
            for key, value in headers.multi_items()
        )
        + 2
    )


async def _default_resolver(hostname: str, port: int) -> Sequence[str]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return tuple(record[4][0] for record in records)


__all__ = [
    "OBSERVER_BUNDLE_FEED_CONFIG_SCHEMA",
    "BoundedHTTPSFetcher",
    "BundleFeedSnapshot",
    "FeedHealth",
    "ObserverBundleFeed",
    "ObserverBundleFeedConfig",
    "ObserverBundleFeedError",
    "ObserverFeedTarget",
    "ValidatorLocalScore",
    "VerifiedEvidenceObject",
    "VerifiedFeedWindow",
    "VerifiedMinerSolution",
    "VerifiedSolutionEvidence",
    "build_production_observer_bundle_feed",
    "load_observer_bundle_feed_config",
]
