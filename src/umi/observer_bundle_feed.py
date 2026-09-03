"""Verified, last-good ingestion of public inactive-validator bundle feeds.

Publisher indexes are discovery hints.  This module downloads every referenced
byte through a bounded, DNS-pinned HTTPS client and runs the production bundle
replay verifier before committing a dashboard projection to durable state.
"""

from __future__ import annotations

import asyncio
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
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Protocol
from urllib.parse import quote, urlsplit

import httpx
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
)
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_delivery import normalized_https_origin
from .validator_readiness import PublishedBundleVerifier, VerifiedPublishedBundle
from .validator_weight_build_effect import (
    WEIGHT_BUILD_RESULT_SCHEMA,
    WEIGHT_BUILD_STAGE_SCHEMA,
    WeightBuildResultEvidence,
    WeightBuildStageManifest,
)

OBSERVER_BUNDLE_FEED_CONFIG_SCHEMA = "umi-observer-bundle-feed-config/1"
OBSERVER_BUNDLE_FEED_STATE_SCHEMA = "umi-observer-bundle-feed-state/1"
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_REASON_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")


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
    scores: tuple[ValidatorLocalScore, ...]
    observer_verified_unix: int | None = None

    def __post_init__(self) -> None:
        if _HEX32_RE.fullmatch(self.validator_account_id32) is None:
            raise ValueError("validator account is invalid")
        if _HEX32_RE.fullmatch(self.window_id) is None:
            raise ValueError("window ID is invalid")
        if _HEX32_RE.fullmatch(self.scoring_policy_hash) is None:
            raise ValueError("scoring policy hash is invalid")
        if _HEX32_RE.fullmatch(self.manifest_sha256) is None:
            raise ValueError("manifest hash is invalid")
        if _BLOCK_HASH_RE.fullmatch(self.audit_release_block_hash) is None:
            raise ValueError("audit release block hash is invalid")
        if self.window_index < 0 or self.audit_release_block <= 0:
            raise ValueError("window and release positions are invalid")
        if self.observer_verified_unix is not None and self.observer_verified_unix < 0:
            raise ValueError("observer verification time is invalid")
        roots = [item.miner_root_account_id32 for item in self.scores]
        if len(roots) != len(set(roots)):
            raise ValueError("validator-local score roots must be unique")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason codes must be unique and sorted")


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
        if not callable(fetcher_factory) and fetcher_factory is not None:
            raise TypeError("fetcher factory must be callable")
        if not callable(clock):
            raise TypeError("feed clock must be callable")
        self.maximum_target_refresh_seconds = float(maximum_target_refresh_seconds)
        self.maximum_concurrent_targets = maximum_concurrent_targets
        self.fetcher_factory = fetcher_factory or (
            lambda origin, timeout: BoundedHTTPSFetcher(origin, timeout_seconds=timeout)
        )
        self.clock = clock
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._prepare()

    async def refresh(self, finalized_height: int) -> bool:
        if isinstance(finalized_height, bool) or not isinstance(finalized_height, int):
            raise TypeError("finalized height must be an integer")
        if finalized_height < 0:
            raise ValueError("finalized height must be nonnegative")
        async with self._lock:
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
        windows: list[VerifiedFeedWindow] = []
        health: list[FeedHealth] = []
        with self._connection() as connection:
            for row in connection.execute(
                "SELECT validator_account,sequence,window_id,window_index,entry_bytes,"
                "projection_bytes,manifest_sha256 FROM bundles "
                "ORDER BY window_index,validator_account"
            ):
                target = next(
                    (
                        item
                        for item in self.targets
                        if item.validator_account_id32 == row["validator_account"]
                    ),
                    None,
                )
                if target is None:
                    raise ObserverBundleFeedError("feed_state_unconfigured_validator")
                _, projection = self._decode_stored_row(row, target)
                windows.append(projection)
            states = {
                row["validator_account"]: row
                for row in connection.execute("SELECT * FROM feeds ORDER BY validator_account")
            }
        for target in self.targets:
            row = states.get(target.validator_account_id32)
            stored_count = sum(
                item.validator_account_id32 == target.validator_account_id32 for item in windows
            )
            if row is None:
                if stored_count:
                    raise ObserverBundleFeedError("feed_state_cursor_missing")
                status, checked, count, error = "not_started", None, 0, None
            elif row["last_checked_unix"] is None:
                checked = None
                count = int(row["accepted_entries"])
                error = row["last_error_code"]
                status = "degraded" if error is not None else "not_started"
            else:
                checked = int(row["last_checked_unix"])
                error = row["last_error_code"]
                count = int(row["accepted_entries"])
                if now - checked > self.maximum_stale_seconds:
                    status = "stale"
                elif error is not None:
                    status = "degraded"
                else:
                    status = "current"
            if row is not None and (
                row["binding_sha256"] != _target_binding(target) or count != stored_count
            ):
                raise ObserverBundleFeedError("feed_state_cursor_mismatch")
            health.append(FeedHealth(target.validator_account_id32, status, error, checked, count))
        return BundleFeedSnapshot(tuple(windows), tuple(health))

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
            return _extract_projection(root, manifest_bytes, entry, target.validator_account_id32)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def _stored_entries(self, validator: str) -> tuple[PublicBundleIndexEntry, ...]:
        target = next(
            (item for item in self.targets if item.validator_account_id32 == validator),
            None,
        )
        if target is None:
            raise ObserverBundleFeedError("feed_state_unconfigured_validator")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT validator_account,sequence,window_id,window_index,entry_bytes,"
                "projection_bytes,manifest_sha256 FROM bundles "
                "WHERE validator_account=? ORDER BY sequence",
                (validator,),
            ).fetchall()
        values: list[PublicBundleIndexEntry] = []
        for row in rows:
            entry, _ = self._decode_stored_row(row, target)
            values.append(entry)
        return tuple(values)

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
        with self._transaction() as connection:
            for entry, projection in additions:
                connection.execute(
                    "INSERT INTO bundles VALUES(?,?,?,?,?,?,?)",
                    (
                        target.validator_account_id32,
                        entry.sequence,
                        entry.window_id,
                        entry.window_index,
                        canonical_json_bytes(entry),
                        projection,
                        entry.manifest_sha256,
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

    def _record_failure(self, validator: str, code: str) -> None:
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO feeds VALUES(?,?,?,?,?) ON CONFLICT(validator_account) DO UPDATE SET "
                "last_error_code=excluded.last_error_code",
                (validator, None, code, 0, self._target_binding_by_account(validator)),
            )

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
        self._audit_state()

    def _audit_state(self) -> None:
        with self._connection() as connection:
            for target in self.targets:
                rows = connection.execute(
                    "SELECT validator_account,sequence,window_id,window_index,entry_bytes,"
                    "projection_bytes,manifest_sha256 FROM bundles "
                    "WHERE validator_account=? ORDER BY sequence",
                    (target.validator_account_id32,),
                ).fetchall()
                if [row["sequence"] for row in rows] != list(range(len(rows))):
                    raise ObserverBundleFeedError("feed_state_sequence_invalid")
                feed_row = connection.execute(
                    "SELECT accepted_entries FROM feeds WHERE validator_account=?",
                    (target.validator_account_id32,),
                ).fetchone()
                if feed_row is None and rows:
                    raise ObserverBundleFeedError("feed_state_cursor_missing")
                if feed_row is not None and feed_row[0] != len(rows):
                    raise ObserverBundleFeedError("feed_state_cursor_mismatch")
                for row in rows:
                    self._decode_stored_row(row, target)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self.state_path.exists() and (
            self.state_path.is_symlink() or not self.state_path.is_file()
        ):
            raise ObserverBundleFeedError("feed_state_database_unsafe")
        connection = sqlite3.connect(self.state_path, timeout=5)
        connection.row_factory = sqlite3.Row
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


def _extract_projection(
    root: Path,
    manifest_bytes: bytes,
    entry: PublicBundleIndexEntry,
    validator: str,
) -> VerifiedFeedWindow:
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
        scores=scores,
    )


def _projection_bytes(value: VerifiedFeedWindow) -> bytes:
    return canonical_json_bytes(
        {
            "audit_release_block": value.audit_release_block,
            "audit_release_block_hash": value.audit_release_block_hash,
            "manifest_sha256": value.manifest_sha256,
            "observer_verified_unix": value.observer_verified_unix,
            "reason_codes": list(value.reason_codes),
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
            "terminal_classification": value.terminal_classification,
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
        scores=tuple(ValidatorLocalScore(**item) for item in value["scores"]),
        observer_verified_unix=value["observer_verified_unix"],
    )


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
    "VerifiedFeedWindow",
    "build_production_observer_bundle_feed",
    "load_observer_bundle_feed_config",
]
