"""Durable public publication for verified inactive-validator bundles.

The process has no wallet, signer, chain client, or extrinsic surface. It copies a
terminal local bundle into a private same-filesystem staging directory, runs the
production seven-stage replay verifier against that snapshot, installs the exact
tree atomically below a static document root, and reads every byte back through a
public HTTPS origin before adding the route to its canonical index.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import stat
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Annotated, Literal, Protocol
from urllib.parse import quote, urlsplit

import httpx
from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .calibration_bundle import (
    CALIBRATION_BUNDLE_SCHEMA,
    MAX_CALIBRATION_BUNDLE_BYTES,
    MAX_CALIBRATION_MANIFEST_BYTES,
    MAX_CALIBRATION_OBJECT_BYTES,
    CalibrationBundleManifest,
)
from .encoding import account_id32
from .policy import scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_delivery import normalized_https_origin
from .validator_incident_bundle import INCIDENT_BUNDLE_SCHEMA, IncidentBundleManifest
from .validator_readiness import ReplayPublishedBundleVerifier, VerifiedPublishedBundle

if TYPE_CHECKING:
    from .policy import ScoringPolicy
    from .shadow_release import LiveShadowReleaseManifest
    from .validator_live import LiveValidatorConfig

AUDIT_PUBLICATION_CONFIG_SCHEMA = "umi-validator-audit-publication-config/1"
PUBLIC_BUNDLE_INDEX_SCHEMA = "umi-validator-public-bundle-index/1"
PUBLICATION_STATE_SCHEMA = "umi-validator-audit-publication-state/1"
PUBLICATION_MODE = "live_shadow_calibration"

MAX_PUBLICATION_CONFIG_BYTES = 256 * 1024
MAX_PUBLIC_INDEX_BYTES = 16 * 1024 * 1024
MAX_REMOTE_HEADER_BYTES = 64 * 1024
MAX_REMOTE_FILES = 200_000
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_STATE_EVENT_DOMAIN = b"umi-validator-audit-publication-state-event-v1\0"
_TREE_DOMAIN = b"umi-validator-public-bundle-tree-v1\0"

BundleManifest = CalibrationBundleManifest | IncidentBundleManifest
PublicationPhase = Literal[
    "discovered",
    "local_installed",
    "remote_tree_verified",
    "index_local",
    "complete",
    "failed",
]


class AuditPublicationError(RuntimeError):
    """Stable, non-sensitive publication failure."""

    def __init__(self, reason_code: str, *, retryable: bool = False) -> None:
        if _REASON_RE.fullmatch(reason_code) is None:
            raise ValueError("publication reason code is invalid")
        self.reason_code = reason_code
        self.retryable = retryable
        super().__init__(reason_code)


class AuditPublicationConfig(StrictProtocolModel):
    """Canonical local configuration for one validator's publication worker."""

    schema_: Literal[AUDIT_PUBLICATION_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[PUBLICATION_MODE]
    translation_weights_active: Literal[False]
    wallet_loading_capability: Literal[False]
    chain_write_capability: Literal[False]
    weight_submission_capability: Literal[False]
    validator_config_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    expected_release_authority_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    state_database_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    public_docroot: Annotated[str, Field(min_length=1, max_length=4_096)]
    private_staging_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    public_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    poll_seconds: Annotated[float, Field(ge=0.25, le=3_600)] = 5.0
    remote_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 30.0
    maximum_remote_concurrency: Annotated[int, Field(ge=1, le=32)] = 4

    @model_validator(mode="after")
    def validate_boundaries(self) -> Self:
        account_id32(self.expected_release_authority_hotkey)
        values = (
            self.validator_config_path,
            self.state_database_path,
            self.public_docroot,
            self.private_staging_root,
        )
        paths = tuple(Path(value) for value in values)
        if any(
            not path.is_absolute() or os.path.normpath(value) != value or ".." in path.parts
            for path, value in zip(paths, values, strict=True)
        ):
            raise ValueError("publication paths must be absolute and normalized")
        if len(set(paths)) != len(paths):
            raise ValueError("publication paths must be distinct")
        state, docroot, staging = paths[1:]
        if _overlap(state, docroot) or _overlap(state, staging) or _overlap(docroot, staging):
            raise ValueError("publication state, staging, and public roots must be disjoint")
        if normalized_https_origin(self.public_origin) != self.public_origin:
            raise ValueError("public origin must be one normalized HTTPS origin")
        _validate_public_origin_name(self.public_origin)
        return self


class PublicBundleIndexEntry(StrictProtocolModel):
    """One immutable public route backed by a fully replayed validator bundle."""

    sequence: Annotated[int, Field(ge=0)]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    window_index: Annotated[int, Field(ge=0)]
    terminal_classification: Literal["calibration_no_weight", "skipped", "void", "failed"]
    bundle_schema: Literal[CALIBRATION_BUNDLE_SCHEMA, INCIDENT_BUNDLE_SCHEMA]
    highest_stage: Annotated[str, Field(min_length=1, max_length=64)]
    reason_codes: list[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$")]]
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    audit_release_block: Annotated[int, Field(gt=0)]
    audit_release_block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    manifest_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    audit_bundle_bytes: Annotated[int, Field(gt=0, le=MAX_CALIBRATION_BUNDLE_BYTES)]
    tree_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    relative_path: Annotated[str, Field(min_length=1, max_length=1_024)]

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if self.reason_codes != sorted(set(self.reason_codes)):
            raise ValueError("public bundle reason codes must be unique and sorted")
        expected = _public_bundle_relative_path(
            self.window_id,
            self.terminal_classification,
            validator_account_id32=None,
        )
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or "." in path.parts or ".." in path.parts:
            raise ValueError("public bundle route must be a safe relative path")
        if tuple(path.parts[-3:]) != tuple(PurePosixPath(expected).parts[-3:]):
            raise ValueError("public bundle route does not match its window and classification")
        if self.bundle_schema == CALIBRATION_BUNDLE_SCHEMA:
            if self.terminal_classification != "calibration_no_weight":
                raise ValueError("calibration bundle route has another classification")
        elif self.terminal_classification == "calibration_no_weight":
            raise ValueError("incident bundle route has the calibration classification")
        return self


class PublicBundleIndex(StrictProtocolModel):
    """Canonical append-only routing index for one validator."""

    schema_: Literal[PUBLIC_BUNDLE_INDEX_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[PUBLICATION_MODE]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    validator_account_id32: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    release_manifest_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    entries: list[PublicBundleIndexEntry]

    @model_validator(mode="after")
    def validate_index(self) -> Self:
        if [item.sequence for item in self.entries] != list(range(len(self.entries))):
            raise ValueError("public bundle index sequence is not contiguous")
        windows = [item.window_id for item in self.entries]
        routes = [item.relative_path for item in self.entries]
        if len(set(windows)) != len(windows) or len(set(routes)) != len(routes):
            raise ValueError("public bundle index contains a duplicate window or route")
        account = self.validator_account_id32
        if any(
            PurePosixPath(item.relative_path).parts[:2] != ("validators", account)
            for item in self.entries
        ):
            raise ValueError("public bundle route belongs to another validator")
        if any(item.scoring_policy_hash != self.scoring_policy_hash for item in self.entries):
            raise ValueError("public bundle index mixes scoring policies")
        return self


@dataclass(frozen=True, slots=True)
class PublicationCandidate:
    source_kind: Literal["calibration", "incident"]
    window_id: str
    root: Path

    @property
    def source_key(self) -> str:
        return f"{self.source_kind}:{self.window_id}"


@dataclass(frozen=True, slots=True)
class PublishedFile:
    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class BundleTree:
    root: Path
    manifest: BundleManifest
    manifest_bytes: bytes
    files: tuple[PublishedFile, ...]
    tree_sha256: str


@dataclass(frozen=True, slots=True)
class PublicationRecord:
    source_key: str
    source_kind: str
    window_id: str
    phase: PublicationPhase
    attempt: int
    entry: PublicBundleIndexEntry | None
    failure_code: str | None
    retryable: bool
    event_sequence: int
    event_sha256: str


@dataclass(frozen=True, slots=True)
class PublicationRunSummary:
    discovered: int
    completed: int
    failed: int
    already_complete: int

    def as_dict(self) -> dict[str, object]:
        return {
            "already_complete": self.already_complete,
            "chain_write_capability": False,
            "completed": self.completed,
            "discovered": self.discovered,
            "failed": self.failed,
            "mode": PUBLICATION_MODE,
            "translation_weights_active": False,
            "wallet_loading_capability": False,
            "weight_submission_capability": False,
        }


class PublishedBundleReplayPort(Protocol):
    async def verify(self, root: Path) -> VerifiedPublishedBundle: ...


class AddressResolver(Protocol):
    async def __call__(self, hostname: str, port: int) -> Sequence[str]: ...


@dataclass(frozen=True, slots=True)
class _RemoteSession:
    client: httpx.AsyncClient
    request_origin: str
    host_header: str | None
    sni_hostname: str | None


@dataclass(frozen=True, slots=True)
class ProductionPublicationDefinition:
    publication_config_path: Path
    publication_config_bytes: bytes
    publication_config: AuditPublicationConfig
    validator_config: LiveValidatorConfig
    policy: ScoringPolicy
    release_manifest: LiveShadowReleaseManifest
    release_manifest_sha256: str
    verifier: ReplayPublishedBundleVerifier


class PublicationState:
    """SQLite event chain recording every durable publication transition."""

    def __init__(self, path: Path, *, binding: Mapping[str, object]) -> None:
        self.path = path
        self.binding_bytes = canonical_json_bytes(dict(binding))
        _prepare_private_database(path)
        try:
            self._initialize()
            self._database_identity = _database_file_identity(path)
            self._audit()
        except AuditPublicationError:
            raise
        except sqlite3.Error as error:
            raise AuditPublicationError("publication_state_invalid") from error

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        expected_identity = getattr(self, "_database_identity", None)
        if expected_identity is not None:
            self._assert_database_identity(expected_identity)
        _reject_database_links(self.path)
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        _secure_database_files(self.path)
        if expected_identity is not None and not self._database_identity_matches(expected_identity):
            connection.close()
            raise AuditPublicationError("publication_state_database_replaced")
        try:
            yield connection
        finally:
            try:
                connection.close()
            finally:
                _secure_database_files(self.path)
                if expected_identity is not None:
                    self._assert_database_identity(expected_identity)

    def _database_identity_matches(self, expected: tuple[int, int]) -> bool:
        try:
            return _database_file_identity(self.path) == expected
        except AuditPublicationError:
            return False

    def _assert_database_identity(self, expected: tuple[int, int]) -> None:
        if not self._database_identity_matches(expected):
            raise AuditPublicationError("publication_state_database_replaced")

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

    def _initialize(self) -> None:
        with self._connection() as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise AuditPublicationError("publication_state_wal_unavailable")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY,
                    source_key TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    window_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK(attempt > 0),
                    entry_bytes BLOB,
                    failure_code TEXT,
                    retryable INTEGER NOT NULL CHECK(retryable IN (0, 1)),
                    previous_event_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL UNIQUE
                ) STRICT;
                CREATE TABLE IF NOT EXISTS publications (
                    source_key TEXT PRIMARY KEY,
                    source_kind TEXT NOT NULL,
                    window_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK(attempt > 0),
                    entry_bytes BLOB,
                    failure_code TEXT,
                    retryable INTEGER NOT NULL CHECK(retryable IN (0, 1)),
                    event_sequence INTEGER NOT NULL UNIQUE,
                    event_sha256 TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(event_sequence) REFERENCES events(sequence)
                ) STRICT;
                """
            )
            expected = {
                "binding": self.binding_bytes,
                "event_head": b"0" * 64,
                "schema": PUBLICATION_STATE_SCHEMA.encode("ascii"),
            }
            rows = {
                row["key"]: bytes(row["value"])
                for row in connection.execute("SELECT key, value FROM metadata")
            }
            if not rows:
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES(?, ?)", expected.items()
                )
            elif (
                rows.get("binding") != self.binding_bytes
                or rows.get("schema") != expected["schema"]
            ):
                raise AuditPublicationError("publication_state_binding_mismatch")
        _secure_database_files(self.path)
        _fsync_directory(self.path.parent)

    def _audit(self) -> None:
        previous = "0" * 64
        latest: dict[str, PublicationRecord] = {}
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM events ORDER BY sequence").fetchall()
            for expected_sequence, row in enumerate(rows):
                if row["sequence"] != expected_sequence or row["previous_event_sha256"] != previous:
                    raise AuditPublicationError("publication_state_event_chain_invalid")
                record = _record_from_row(row, event=True)
                calculated = _publication_event_sha256(record, previous)
                if calculated != record.event_sha256:
                    raise AuditPublicationError("publication_state_event_digest_invalid")
                previous = record.event_sha256
                latest[record.source_key] = record
            head = connection.execute(
                "SELECT value FROM metadata WHERE key = 'event_head'"
            ).fetchone()
            if head is None or bytes(head[0]).decode("ascii") != previous:
                raise AuditPublicationError("publication_state_event_head_invalid")
            current = {
                row["source_key"]: _record_from_row(row, event=False)
                for row in connection.execute("SELECT * FROM publications")
            }
        if set(current) != set(latest):
            raise AuditPublicationError("publication_state_current_set_invalid")
        for key, record in current.items():
            if record != latest[key]:
                raise AuditPublicationError("publication_state_current_record_invalid")

    def records(self) -> dict[str, PublicationRecord]:
        with self._connection() as connection:
            return {
                row["source_key"]: _record_from_row(row, event=False)
                for row in connection.execute("SELECT * FROM publications")
            }

    def get(self, source_key: str) -> PublicationRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM publications WHERE source_key = ?", (source_key,)
            ).fetchone()
        return None if row is None else _record_from_row(row, event=False)

    def begin(self, candidate: PublicationCandidate) -> PublicationRecord:
        current = self.get(candidate.source_key)
        if current is not None and current.phase == "complete":
            return current
        if current is not None and current.phase == "failed" and not current.retryable:
            return current
        attempt = 1 if current is None else current.attempt + 1
        return self._append(
            source_key=candidate.source_key,
            source_kind=candidate.source_kind,
            window_id=candidate.window_id,
            phase="discovered",
            attempt=attempt,
            entry=None if current is None else current.entry,
            failure_code=None,
            retryable=False,
        )

    def transition(
        self,
        candidate: PublicationCandidate,
        phase: PublicationPhase,
        *,
        entry: PublicBundleIndexEntry | None,
        failure_code: str | None = None,
        retryable: bool = False,
    ) -> PublicationRecord:
        current = self.get(candidate.source_key)
        if current is None:
            raise AuditPublicationError("publication_state_transition_without_attempt")
        if current.phase == "complete" and phase != "complete":
            raise AuditPublicationError("publication_state_complete_regression")
        return self._append(
            source_key=candidate.source_key,
            source_kind=candidate.source_kind,
            window_id=candidate.window_id,
            phase=phase,
            attempt=current.attempt,
            entry=entry,
            failure_code=failure_code,
            retryable=retryable,
        )

    def _append(
        self,
        *,
        source_key: str,
        source_kind: str,
        window_id: str,
        phase: PublicationPhase,
        attempt: int,
        entry: PublicBundleIndexEntry | None,
        failure_code: str | None,
        retryable: bool,
    ) -> PublicationRecord:
        _validate_state_values(source_key, source_kind, window_id, phase, failure_code)
        entry_bytes = None if entry is None else canonical_json_bytes(entry)
        with self._transaction() as connection:
            head_row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'event_head'"
            ).fetchone()
            if head_row is None:
                raise AuditPublicationError("publication_state_event_head_missing")
            previous = bytes(head_row[0]).decode("ascii")
            sequence = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            provisional = PublicationRecord(
                source_key=source_key,
                source_kind=source_kind,
                window_id=window_id,
                phase=phase,
                attempt=attempt,
                entry=entry,
                failure_code=failure_code,
                retryable=retryable,
                event_sequence=sequence,
                event_sha256="0" * 64,
            )
            digest = _publication_event_sha256(provisional, previous)
            connection.execute(
                """INSERT INTO events(
                       sequence, source_key, source_kind, window_id, phase, attempt,
                       entry_bytes, failure_code, retryable, previous_event_sha256,
                       event_sha256
                   ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sequence,
                    source_key,
                    source_kind,
                    window_id,
                    phase,
                    attempt,
                    entry_bytes,
                    failure_code,
                    int(retryable),
                    previous,
                    digest,
                ),
            )
            connection.execute(
                """INSERT INTO publications(
                       source_key, source_kind, window_id, phase, attempt, entry_bytes,
                       failure_code, retryable, event_sequence, event_sha256
                   ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key) DO UPDATE SET
                       source_kind=excluded.source_kind,
                       window_id=excluded.window_id,
                       phase=excluded.phase,
                       attempt=excluded.attempt,
                       entry_bytes=excluded.entry_bytes,
                       failure_code=excluded.failure_code,
                       retryable=excluded.retryable,
                       event_sequence=excluded.event_sequence,
                       event_sha256=excluded.event_sha256""",
                (
                    source_key,
                    source_kind,
                    window_id,
                    phase,
                    attempt,
                    entry_bytes,
                    failure_code,
                    int(retryable),
                    sequence,
                    digest,
                ),
            )
            connection.execute(
                "UPDATE metadata SET value = ? WHERE key = 'event_head'",
                (digest.encode("ascii"),),
            )
        return PublicationRecord(
            source_key=source_key,
            source_kind=source_kind,
            window_id=window_id,
            phase=phase,
            attempt=attempt,
            entry=entry,
            failure_code=failure_code,
            retryable=retryable,
            event_sequence=sequence,
            event_sha256=digest,
        )


class PublicOriginVerifier:
    """Stream exact static files through one DNS-pinned HTTPS origin."""

    def __init__(
        self,
        origin: str,
        *,
        timeout_seconds: float,
        maximum_concurrency: int,
        resolver: AddressResolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        allow_http_for_tests: bool = False,
    ) -> None:
        normalized = normalized_https_origin(origin, allow_http_for_tests=allow_http_for_tests)
        if normalized != origin:
            raise ValueError("public origin is not normalized")
        if not allow_http_for_tests:
            _validate_public_origin_name(origin)
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValueError("remote timeout is outside the supported range")
        if maximum_concurrency < 1 or maximum_concurrency > 32:
            raise ValueError("remote concurrency is outside the supported range")
        self.origin = origin
        self.timeout_seconds = timeout_seconds
        self.maximum_concurrency = maximum_concurrency
        self.resolver = resolver
        self.transport = transport
        self.allow_http_for_tests = allow_http_for_tests

    async def verify_tree(self, entry: PublicBundleIndexEntry, tree: BundleTree) -> None:
        async with self._session() as session:
            pending = iter(tree.files)

            async def worker() -> None:
                while True:
                    try:
                        item = next(pending)
                    except StopIteration:
                        return
                    relative = f"{entry.relative_path}/{item.relative_path}"
                    await self._fetch(
                        session,
                        relative,
                        item.sha256,
                        item.size_bytes,
                        retain=False,
                    )

            workers = min(self.maximum_concurrency, len(tree.files))
            await asyncio.gather(*(worker() for _ in range(workers)))

    async def verify_exact(self, relative_path: str, expected: bytes) -> None:
        digest = hashlib.sha256(expected).hexdigest()
        async with self._session() as session:
            received = await self._fetch(
                session,
                relative_path,
                digest,
                len(expected),
                retain=True,
            )
        if received != expected:
            raise AuditPublicationError("public_origin_bytes_mismatch", retryable=True)

    async def verify_digest(self, relative_path: str, sha256: str, size_bytes: int) -> None:
        async with self._session() as session:
            await self._fetch(session, relative_path, sha256, size_bytes, retain=False)

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[_RemoteSession]:
        parsed = urlsplit(self.origin)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        in_process = isinstance(self.transport, (httpx.MockTransport, httpx.ASGITransport))
        if in_process:
            request_origin = self.origin
            host_header = None
            sni_hostname = None
        else:
            try:
                address = await asyncio.wait_for(
                    _resolve_public_address(hostname, port, self.resolver),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError as error:
                raise AuditPublicationError("public_origin_timeout", retryable=True) from error
            host = f"[{address}]" if ":" in address else address
            request_origin = f"{parsed.scheme}://{host}:{port}"
            authority = f"[{hostname}]" if ":" in hostname else hostname
            default_port = 443 if parsed.scheme == "https" else 80
            host_header = (
                authority if parsed.port in {None, default_port} else f"{authority}:{port}"
            )
            sni_hostname = hostname
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
        ) as client:
            yield _RemoteSession(
                client=client,
                request_origin=request_origin,
                host_header=host_header,
                sni_hostname=sni_hostname,
            )

    async def _fetch(
        self,
        session: _RemoteSession,
        relative_path: str,
        expected_sha256: str,
        expected_size: int,
        *,
        retain: bool,
    ) -> bytes:
        _safe_public_relative_path(relative_path)
        if _HEX32_RE.fullmatch(expected_sha256) is None or expected_size < 0:
            raise ValueError("remote verification expectation is invalid")
        try:
            return await asyncio.wait_for(
                self._fetch_stream(
                    session,
                    relative_path,
                    expected_sha256,
                    expected_size,
                    retain=retain,
                ),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise AuditPublicationError("public_origin_timeout", retryable=True) from error

    async def _fetch_stream(
        self,
        session: _RemoteSession,
        relative_path: str,
        expected_sha256: str,
        expected_size: int,
        *,
        retain: bool,
    ) -> bytes:
        encoded_path = quote(relative_path, safe="/-._~")
        request_url = f"{session.request_origin}/{encoded_path}?umi-sha256={expected_sha256}"
        headers = {
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache, no-store, max-age=0",
        }
        if session.host_header is not None:
            headers["Host"] = session.host_header
        try:
            async with session.client.stream(
                "GET",
                request_url,
                headers=headers,
                extensions=(
                    {} if session.sni_hostname is None else {"sni_hostname": session.sni_hostname}
                ),
            ) as response:
                if _header_bytes(response.headers) > MAX_REMOTE_HEADER_BYTES:
                    raise AuditPublicationError("public_origin_header_limit", retryable=True)
                if response.status_code != 200:
                    raise AuditPublicationError("public_origin_http_status", retryable=True)
                encoding = response.headers.get("content-encoding", "").strip().lower()
                if encoding not in {"", "identity"}:
                    raise AuditPublicationError("public_origin_content_encoding", retryable=True)
                declared = response.headers.get("content-length")
                if declared is not None:
                    if (
                        not declared.isascii()
                        or re.fullmatch(r"(?:0|[1-9][0-9]*)", declared) is None
                    ):
                        raise AuditPublicationError(
                            "public_origin_content_length_invalid", retryable=True
                        )
                    if int(declared) != expected_size:
                        raise AuditPublicationError(
                            "public_origin_content_length_mismatch", retryable=True
                        )
                digest = hashlib.sha256()
                total = 0
                retained = bytearray()
                async for chunk in response.aiter_raw():
                    total += len(chunk)
                    if total > expected_size:
                        raise AuditPublicationError("public_origin_body_limit", retryable=True)
                    digest.update(chunk)
                    if retain:
                        retained.extend(chunk)
                if total != expected_size or digest.hexdigest() != expected_sha256:
                    raise AuditPublicationError("public_origin_digest_mismatch", retryable=True)
                return bytes(retained)
        except AuditPublicationError:
            raise
        except httpx.TimeoutException as error:
            raise AuditPublicationError("public_origin_timeout", retryable=True) from error
        except httpx.HTTPError as error:
            raise AuditPublicationError("public_origin_transport", retryable=True) from error


class AuditBundlePublisher:
    """Publish one validator's complete terminal namespace without chain access."""

    def __init__(
        self,
        *,
        policy_hash: str,
        validator_account_id32: bytes,
        release_manifest_sha256: str,
        calibration_root: Path,
        incident_root: Path,
        public_docroot: Path,
        private_staging_root: Path,
        state_database_path: Path,
        bundle_verifier: PublishedBundleReplayPort,
        origin_verifier: PublicOriginVerifier,
    ) -> None:
        if _HEX32_RE.fullmatch(policy_hash) is None:
            raise ValueError("publication policy hash is invalid")
        if not isinstance(validator_account_id32, bytes) or len(validator_account_id32) != 32:
            raise ValueError("publication validator account must be 32 bytes")
        if _HEX32_RE.fullmatch(release_manifest_sha256) is None:
            raise ValueError("publication release manifest hash is invalid")
        if not callable(getattr(bundle_verifier, "verify", None)):
            raise TypeError("bundle verifier must implement verify")
        if not isinstance(origin_verifier, PublicOriginVerifier):
            raise TypeError("origin verifier must be PublicOriginVerifier")
        self.policy_hash = policy_hash
        self.validator_account_id32 = validator_account_id32
        self.validator_hex = validator_account_id32.hex()
        self.release_manifest_sha256 = release_manifest_sha256
        self.calibration_root = calibration_root
        self.incident_root = incident_root
        self.public_docroot = public_docroot
        self.private_staging_root = private_staging_root
        self.state_database_path = state_database_path
        self.bundle_verifier = bundle_verifier
        self.origin_verifier = origin_verifier
        self._validate_roots()
        self._prepare_public_layout()
        binding = {
            "calibration_root": str(calibration_root),
            "incident_root": str(incident_root),
            "policy_hash": policy_hash,
            "public_docroot": str(public_docroot),
            "public_origin": origin_verifier.origin,
            "release_manifest_sha256": release_manifest_sha256,
            "schema": PUBLICATION_STATE_SCHEMA,
            "staging_root": str(private_staging_root),
            "validator_account_id32": self.validator_hex,
        }
        self.state = PublicationState(state_database_path, binding=binding)
        self.lock_path = private_staging_root / f"{self.validator_hex}.publication.lock"
        self._audit_index_and_state()

    @property
    def index_relative_path(self) -> str:
        return f"validators/{self.validator_hex}/index.json"

    @property
    def index_path(self) -> Path:
        return self.public_docroot / PurePosixPath(self.index_relative_path)

    def _base_index(self) -> PublicBundleIndex:
        return PublicBundleIndex(
            schema=PUBLIC_BUNDLE_INDEX_SCHEMA,
            protocol=PROTOCOL_VERSION,
            mode=PUBLICATION_MODE,
            netuid=78,
            mechanism_id=0,
            translation_weights_active=False,
            validator_account_id32=self.validator_hex,
            scoring_policy_hash=self.policy_hash,
            release_manifest_sha256=self.release_manifest_sha256,
            entries=[],
        )

    async def run_once(self) -> PublicationRunSummary:
        completed = 0
        failed = 0
        already = 0
        candidates = self._discover_candidates()
        with _exclusive_process_lock(self.lock_path):
            self._audit_index_and_state()
            for candidate in candidates:
                record = self.state.get(candidate.source_key)
                if record is not None and record.phase == "complete":
                    already += 1
                    continue
                if record is not None and record.phase == "failed" and not record.retryable:
                    failed += 1
                    continue
                record = self.state.begin(candidate)
                try:
                    await self._publish_candidate(candidate, record)
                except AuditPublicationError as error:
                    retained = self.state.get(candidate.source_key)
                    entry = None if retained is None else retained.entry
                    self.state.transition(
                        candidate,
                        "failed",
                        entry=entry,
                        failure_code=error.reason_code,
                        retryable=error.retryable,
                    )
                    failed += 1
                except Exception as error:
                    retained = self.state.get(candidate.source_key)
                    entry = None if retained is None else retained.entry
                    self.state.transition(
                        candidate,
                        "failed",
                        entry=entry,
                        failure_code="publication_unexpected_failure",
                        retryable=False,
                    )
                    failed += 1
                    raise AuditPublicationError("publication_unexpected_failure") from error
                else:
                    completed += 1
        return PublicationRunSummary(
            discovered=len(candidates),
            completed=completed,
            failed=failed,
            already_complete=already,
        )

    async def _publish_candidate(
        self,
        candidate: PublicationCandidate,
        record: PublicationRecord,
    ) -> None:
        index = self._load_index()
        existing_route = next(
            (item for item in index.entries if item.window_id == candidate.window_id), None
        )
        entry = record.entry
        tree: BundleTree
        if entry is not None:
            if existing_route is not None and existing_route != entry:
                raise AuditPublicationError("public_index_window_conflict")
            target = self.public_docroot / PurePosixPath(entry.relative_path)
            tree = _inspect_bundle_tree(target)
            _bind_tree_to_entry(tree, entry, self.validator_hex)
            source_manifest = _read_regular_file(
                candidate.root / "manifest.json",
                maximum_bytes=MAX_CALIBRATION_MANIFEST_BYTES,
                empty_allowed=False,
            )
            if hashlib.sha256(source_manifest).hexdigest() != entry.manifest_sha256:
                raise AuditPublicationError("terminal_source_changed_after_install")
        elif existing_route is not None:
            raise AuditPublicationError("public_index_state_conflict")
        else:
            staging = _snapshot_bundle(candidate.root, self.private_staging_root)
            try:
                try:
                    binding = await self.bundle_verifier.verify(staging)
                except Exception as error:
                    raise AuditPublicationError("terminal_bundle_replay_failed") from error
                tree = _inspect_bundle_tree(staging)
                _bind_verified_bundle(
                    candidate,
                    binding,
                    tree.manifest,
                    policy_hash=self.policy_hash,
                    validator_account_id32=self.validator_hex,
                )
                relative = _public_bundle_relative_path(
                    candidate.window_id,
                    binding.terminal_classification,
                    validator_account_id32=self.validator_hex,
                )
                entry = _entry_from_verified_bundle(
                    sequence=len(index.entries),
                    relative_path=relative,
                    binding=binding,
                    manifest=tree.manifest,
                    tree_sha256=tree.tree_sha256,
                )
                target = self.public_docroot / PurePosixPath(relative)
                _install_snapshot(staging, target, self.public_docroot)
                staging = None
                tree = _inspect_bundle_tree(target)
                _bind_tree_to_entry(tree, entry, self.validator_hex)
                self.state.transition(candidate, "local_installed", entry=entry)
            finally:
                if staging is not None:
                    shutil.rmtree(staging, ignore_errors=True)
        if entry is None:  # pragma: no cover - all branches above assign it
            raise RuntimeError("publication entry was not constructed")

        await self.origin_verifier.verify_tree(entry, tree)
        self.state.transition(candidate, "remote_tree_verified", entry=entry)

        index = self._load_index()
        existing_route = next(
            (item for item in index.entries if item.window_id == candidate.window_id), None
        )
        if existing_route is None:
            if entry.sequence != len(index.entries):
                entry = entry.model_copy(update={"sequence": len(index.entries)})
                self.state.transition(candidate, "remote_tree_verified", entry=entry)
            index = self._append_index_entry(index, entry)
        elif existing_route != entry:
            raise AuditPublicationError("public_index_window_conflict")
        index_bytes = canonical_json_bytes(index)
        self.state.transition(candidate, "index_local", entry=entry)
        await self.origin_verifier.verify_exact(self.index_relative_path, index_bytes)
        self.state.transition(candidate, "complete", entry=entry)

    def _append_index_entry(
        self,
        index: PublicBundleIndex,
        entry: PublicBundleIndexEntry,
    ) -> PublicBundleIndex:
        if entry.sequence != len(index.entries):
            raise AuditPublicationError("public_index_sequence_conflict")
        updated = index.model_copy(update={"entries": [*index.entries, entry]})
        encoded = canonical_json_bytes(updated)
        if len(encoded) > MAX_PUBLIC_INDEX_BYTES:
            raise AuditPublicationError("public_index_byte_limit")
        _atomic_replace_public_file(
            self.index_path,
            encoded,
            self.public_docroot,
            self.private_staging_root,
        )
        reproduced = self._load_index()
        if reproduced != updated:
            raise AuditPublicationError("public_index_atomic_write_mismatch")
        return updated

    def _load_index(self) -> PublicBundleIndex:
        if not self.index_path.exists():
            return self._base_index()
        encoded = _read_regular_file(
            self.index_path,
            maximum_bytes=MAX_PUBLIC_INDEX_BYTES,
            empty_allowed=False,
        )
        try:
            value = PublicBundleIndex.model_validate_json(encoded)
        except Exception as error:
            raise AuditPublicationError("public_index_invalid") from error
        if canonical_json_bytes(value) != encoded:
            raise AuditPublicationError("public_index_noncanonical")
        expected = self._base_index().model_copy(update={"entries": value.entries})
        if value != expected:
            raise AuditPublicationError("public_index_binding_mismatch")
        return value

    def _audit_index_and_state(self) -> None:
        index = self._load_index()
        by_window = {item.window_id: item for item in index.entries}
        records = self.state.records()
        for entry in index.entries:
            tree = _inspect_bundle_tree(self.public_docroot / PurePosixPath(entry.relative_path))
            _bind_tree_to_entry(tree, entry, self.validator_hex)
            matches = [record for record in records.values() if record.window_id == entry.window_id]
            if len(matches) != 1 or matches[0].entry != entry:
                raise AuditPublicationError("public_index_state_missing")
            if matches[0].phase not in {
                "remote_tree_verified",
                "index_local",
                "complete",
                "failed",
            }:
                raise AuditPublicationError("public_index_state_phase_invalid")
        for record in records.values():
            if record.phase == "complete" and (
                record.entry is None or by_window.get(record.window_id) != record.entry
            ):
                raise AuditPublicationError("publication_complete_index_missing")
            if record.entry is not None:
                expected = _public_bundle_relative_path(
                    record.window_id,
                    record.entry.terminal_classification,
                    validator_account_id32=self.validator_hex,
                )
                if record.entry.relative_path != expected:
                    raise AuditPublicationError("publication_state_route_invalid")

    def _discover_candidates(self) -> tuple[PublicationCandidate, ...]:
        values: list[PublicationCandidate] = []
        for kind, root in (
            ("calibration", self.calibration_root),
            ("incident", self.incident_root),
        ):
            if not root.exists():
                continue
            if root.is_symlink() or not root.is_dir():
                raise AuditPublicationError(f"{kind}_bundle_namespace_unsafe")
            for child in sorted(root.iterdir(), key=lambda item: item.name):
                if _HEX32_RE.fullmatch(child.name) is None:
                    continue
                try:
                    (child / "manifest.json").lstat()
                except (FileNotFoundError, NotADirectoryError):
                    # Bundle writers install the manifest last. Until it exists,
                    # this directory is still being assembled and is not terminal.
                    continue
                except OSError as error:
                    raise AuditPublicationError(
                        f"{kind}_bundle_namespace_unavailable", retryable=True
                    ) from error
                values.append(
                    PublicationCandidate(
                        source_kind=kind,  # type: ignore[arg-type]
                        window_id=child.name,
                        root=child,
                    )
                )
        return tuple(values)

    def _validate_roots(self) -> None:
        values = (
            self.calibration_root,
            self.incident_root,
            self.public_docroot,
            self.private_staging_root,
            self.state_database_path,
        )
        if any(not path.is_absolute() or Path(os.path.normpath(path)) != path for path in values):
            raise AuditPublicationError("publication_runtime_path_invalid")
        if _overlap(self.public_docroot, self.private_staging_root):
            raise AuditPublicationError("publication_public_staging_overlap")
        if _overlap(self.public_docroot, self.state_database_path):
            raise AuditPublicationError("publication_public_state_overlap")
        if _overlap(self.private_staging_root, self.state_database_path):
            raise AuditPublicationError("publication_staging_state_overlap")
        for source in (self.calibration_root, self.incident_root):
            if _overlap(source, self.public_docroot) or _overlap(source, self.private_staging_root):
                raise AuditPublicationError("publication_source_destination_overlap")
        _validate_existing_directory(self.public_docroot, private=False)
        _validate_existing_directory(self.private_staging_root, private=True)
        if self.public_docroot.stat().st_dev != self.private_staging_root.stat().st_dev:
            raise AuditPublicationError("publication_staging_cross_device")

    def _prepare_public_layout(self) -> None:
        validators = self.public_docroot / "validators"
        account = validators / self.validator_hex
        windows = account / "windows"
        for path in (validators, account, windows):
            _mkdir_public(path)


def load_audit_publication_config(path: str | Path) -> tuple[AuditPublicationConfig, bytes]:
    """Load one exact canonical publication config from a regular local file."""

    encoded = _read_regular_file(
        Path(path),
        maximum_bytes=MAX_PUBLICATION_CONFIG_BYTES,
        empty_allowed=False,
    )
    try:
        config = AuditPublicationConfig.model_validate_json(encoded)
    except (ValidationError, ValueError) as error:
        raise AuditPublicationError("publication_config_invalid") from error
    if canonical_json_bytes(config) != encoded:
        raise AuditPublicationError("publication_config_noncanonical")
    return config, encoded


def load_production_publication_definition(
    path: str | Path,
) -> ProductionPublicationDefinition:
    """Authenticate the signed release, local config, policy, and replay binaries."""

    from .shadow_release import verify_shadow_release_directory
    from .substrate_proof import SubprocessStorageProofVerifier
    from .validator_bundle_ports import build_production_calibration_bundle_verifier
    from .validator_live import (
        load_live_policy,
        load_live_validator_config,
        validate_live_startup,
    )

    config_path = Path(path)
    config, config_bytes = load_audit_publication_config(config_path)
    try:
        validator_config = load_live_validator_config(config.validator_config_path)
        release_root = Path(validator_config.conformance_release_root)
        release = verify_shadow_release_directory(
            release_root,
            expected_authority_hotkey=config.expected_release_authority_hotkey,
        )
        _bind_materialized_validator_config(validator_config, release_root, release)
        policy = load_live_policy(validator_config)
        runtime = validate_live_startup(validator_config, policy)
        proof = SubprocessStorageProofVerifier(
            binary_path=validator_config.storage_proof_verifier_binary,
            expected_sha256=runtime.storage_proof_verifier_sha256,
        )
        calibration = build_production_calibration_bundle_verifier(
            policy=policy,
            target_triple=validator_config.target_triple,
            finality_verifier_binary=validator_config.finality_verifier_binary,
            finality_chain_spec=validator_config.finality_chain_spec_path,
            storage_proof_verifier=proof,
        )
        verifier = ReplayPublishedBundleVerifier(calibration.ports)
        manifest_bytes = _read_regular_file(
            release_root / "release-manifest.json",
            maximum_bytes=8 * 1024 * 1024,
            empty_allowed=False,
        )
    except AuditPublicationError:
        raise
    except Exception as error:
        raise AuditPublicationError("publication_signed_runtime_invalid") from error
    if scoring_policy_hash(policy) != validator_config.scoring_policy_sha256:
        raise AuditPublicationError("publication_policy_binding_mismatch")
    return ProductionPublicationDefinition(
        publication_config_path=config_path,
        publication_config_bytes=config_bytes,
        publication_config=config,
        validator_config=validator_config,
        policy=policy,
        release_manifest=release,
        release_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        verifier=verifier,
    )


def build_production_audit_publisher(
    definition: ProductionPublicationDefinition,
) -> AuditBundlePublisher:
    """Open the durable publication worker from an authenticated definition."""

    from .validator_live import LiveValidatorPaths

    if not isinstance(definition, ProductionPublicationDefinition):
        raise TypeError("definition must be ProductionPublicationDefinition")
    config = definition.publication_config
    paths = LiveValidatorPaths.below(definition.validator_config.state_root)
    _validate_production_destinations(definition)
    origin = PublicOriginVerifier(
        config.public_origin,
        timeout_seconds=config.remote_timeout_seconds,
        maximum_concurrency=config.maximum_remote_concurrency,
    )
    return AuditBundlePublisher(
        policy_hash=scoring_policy_hash(definition.policy),
        validator_account_id32=account_id32(definition.validator_config.validator_hotkey),
        release_manifest_sha256=definition.release_manifest_sha256,
        calibration_root=paths.bundles,
        incident_root=paths.incident_bundles,
        public_docroot=Path(config.public_docroot),
        private_staging_root=Path(config.private_staging_root),
        state_database_path=Path(config.state_database_path),
        bundle_verifier=definition.verifier,
        origin_verifier=origin,
    )


def _bind_materialized_validator_config(
    config: LiveValidatorConfig,
    release_root: Path,
    release: LiveShadowReleaseManifest,
) -> None:
    from .shadow_release import ReleaseRelativeValidatorConfig
    from .validator_live import LiveValidatorConfig

    account = account_id32(config.validator_hotkey).hex()
    if account_id32(config.validator_hotkey) not in {
        account_id32(item) for item in release.validator_hotkeys
    }:
        raise AuditPublicationError("publication_validator_not_in_signed_release")
    relative = f"operator-templates/{account}.validator-template.json"
    template_bytes = _read_regular_file(
        release_root / PurePosixPath(relative),
        maximum_bytes=2 * 1024 * 1024,
        empty_allowed=False,
    )
    try:
        template = ReleaseRelativeValidatorConfig.model_validate_json(template_bytes)
    except Exception as error:
        raise AuditPublicationError("publication_validator_template_invalid") from error
    if canonical_json_bytes(template) != template_bytes:
        raise AuditPublicationError("publication_validator_template_noncanonical")
    values = template.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "schema": config.schema_,
            "conformance_release_root": str(release_root),
            "state_root": config.state_root,
            "policy_path": str(release_root / template.policy_path),
            "storage_proof_verifier_binary": str(
                release_root / template.storage_proof_verifier_binary
            ),
            "finality_verifier_binary": str(release_root / template.finality_verifier_binary),
            "finality_chain_spec_path": str(release_root / template.finality_chain_spec_path),
        }
    )
    try:
        expected = LiveValidatorConfig.model_validate(values)
    except Exception as error:
        raise AuditPublicationError("publication_validator_template_binding_invalid") from error
    if config != expected:
        raise AuditPublicationError("publication_validator_config_not_signed_template")


def _snapshot_bundle(source: Path, staging_root: Path) -> Path:
    """Copy one exact terminal tree into a private same-filesystem snapshot."""

    if source.is_symlink() or not source.is_dir():
        raise AuditPublicationError("terminal_bundle_root_unsafe")
    try:
        staging = Path(tempfile.mkdtemp(prefix=".bundle-", dir=staging_root))
        staging.chmod(0o700)
        objects_out = staging / "objects"
        objects_out.mkdir(mode=0o700)
        manifest_bytes = _read_regular_file(
            source / "manifest.json",
            maximum_bytes=MAX_CALIBRATION_MANIFEST_BYTES,
            empty_allowed=False,
        )
        manifest = _parse_bundle_manifest(manifest_bytes)
        expected = {item.sha256: item for item in manifest.objects}
        if len(expected) != len(manifest.objects) or len(expected) > MAX_REMOTE_FILES:
            raise AuditPublicationError("terminal_bundle_object_set_invalid")
        _require_exact_source_paths(source, set(expected))
        _write_new_file(staging / "manifest.json", manifest_bytes, mode=0o600)
        total = len(manifest_bytes)
        for digest, reference in expected.items():
            data = _read_regular_file(
                source / "objects" / digest,
                maximum_bytes=MAX_CALIBRATION_OBJECT_BYTES,
                empty_allowed=True,
            )
            if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != digest:
                raise AuditPublicationError("terminal_bundle_object_digest_mismatch")
            total += len(data)
            if total > MAX_CALIBRATION_BUNDLE_BYTES:
                raise AuditPublicationError("terminal_bundle_byte_limit")
            _write_new_file(objects_out / digest, data, mode=0o600)
        _require_exact_source_paths(source, set(expected))
        _fsync_directory(objects_out)
        _fsync_directory(staging)
        return staging
    except AuditPublicationError:
        with suppress(UnboundLocalError):
            shutil.rmtree(staging, ignore_errors=True)
        raise
    except Exception as error:
        with suppress(UnboundLocalError):
            shutil.rmtree(staging, ignore_errors=True)
        raise AuditPublicationError("terminal_bundle_snapshot_failed", retryable=True) from error


def _inspect_bundle_tree(root: Path) -> BundleTree:
    if not root.exists() or root.is_symlink() or not root.is_dir():
        raise AuditPublicationError("published_bundle_tree_missing")
    manifest_bytes = _read_regular_file(
        root / "manifest.json",
        maximum_bytes=MAX_CALIBRATION_MANIFEST_BYTES,
        empty_allowed=False,
    )
    manifest = _parse_bundle_manifest(manifest_bytes)
    expected = {item.sha256: item for item in manifest.objects}
    if len(expected) != len(manifest.objects) or len(expected) > MAX_REMOTE_FILES:
        raise AuditPublicationError("published_bundle_object_set_invalid")
    _require_exact_source_paths(root, set(expected))
    files = [
        PublishedFile(
            relative_path="manifest.json",
            sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            size_bytes=len(manifest_bytes),
        )
    ]
    total = len(manifest_bytes)
    for digest, reference in expected.items():
        path = root / "objects" / digest
        actual_digest, size = _hash_regular_file(path, MAX_CALIBRATION_OBJECT_BYTES)
        if actual_digest != digest or size != reference.size_bytes:
            raise AuditPublicationError("published_bundle_object_digest_mismatch")
        total += size
        files.append(PublishedFile(f"objects/{digest}", digest, size))
    if total != manifest.audit_bundle_bytes or total > MAX_CALIBRATION_BUNDLE_BYTES:
        raise AuditPublicationError("published_bundle_byte_accounting_mismatch")
    values = tuple(sorted(files, key=lambda item: item.relative_path.encode("ascii")))
    return BundleTree(
        root=root,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        files=values,
        tree_sha256=_bundle_tree_sha256(values),
    )


def _bind_verified_bundle(
    candidate: PublicationCandidate,
    binding: VerifiedPublishedBundle,
    manifest: BundleManifest,
    *,
    policy_hash: str,
    validator_account_id32: str,
) -> None:
    expected_schema = (
        CALIBRATION_BUNDLE_SCHEMA
        if candidate.source_kind == "calibration"
        else INCIDENT_BUNDLE_SCHEMA
    )
    if manifest.schema_ != expected_schema:
        raise AuditPublicationError("terminal_bundle_namespace_schema_mismatch")
    if (
        binding.window_id != candidate.window_id
        or manifest.window_id != candidate.window_id
        or binding.scoring_policy_hash != policy_hash
        or manifest.scoring_policy_hash != policy_hash
        or binding.manifest_sha256 != hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
        or binding.terminal_classification != manifest.terminal_classification
        or binding.audit_release_block != manifest.audit_release_block
        or binding.audit_release_block_hash != manifest.audit_release_block_hash
        or binding.reason_codes != tuple(manifest.reason_codes)
        or manifest.validator_account_id32 != validator_account_id32
    ):
        raise AuditPublicationError("terminal_bundle_verified_binding_mismatch")


def _entry_from_verified_bundle(
    *,
    sequence: int,
    relative_path: str,
    binding: VerifiedPublishedBundle,
    manifest: BundleManifest,
    tree_sha256: str,
) -> PublicBundleIndexEntry:
    return PublicBundleIndexEntry(
        sequence=sequence,
        window_id=binding.window_id,
        window_index=binding.window_index,
        terminal_classification=binding.terminal_classification,
        bundle_schema=manifest.schema_,
        highest_stage=binding.highest_stage,
        reason_codes=list(binding.reason_codes),
        scoring_policy_hash=binding.scoring_policy_hash,
        audit_release_block=binding.audit_release_block,
        audit_release_block_hash=binding.audit_release_block_hash,
        manifest_sha256=binding.manifest_sha256,
        audit_bundle_bytes=manifest.audit_bundle_bytes,
        tree_sha256=tree_sha256,
        relative_path=relative_path,
    )


def _bind_tree_to_entry(
    tree: BundleTree,
    entry: PublicBundleIndexEntry,
    validator_account_id32: str,
) -> None:
    manifest = tree.manifest
    if (
        manifest.schema_ != entry.bundle_schema
        or manifest.window_id != entry.window_id
        or manifest.window_index != entry.window_index
        or manifest.terminal_classification != entry.terminal_classification
        or manifest.highest_stage != entry.highest_stage
        or manifest.reason_codes != entry.reason_codes
        or manifest.scoring_policy_hash != entry.scoring_policy_hash
        or manifest.audit_release_block != entry.audit_release_block
        or manifest.audit_release_block_hash != entry.audit_release_block_hash
        or manifest.validator_account_id32 != validator_account_id32
        or hashlib.sha256(tree.manifest_bytes).hexdigest() != entry.manifest_sha256
        or manifest.audit_bundle_bytes != entry.audit_bundle_bytes
        or tree.tree_sha256 != entry.tree_sha256
    ):
        raise AuditPublicationError("published_bundle_entry_binding_mismatch")


def _parse_bundle_manifest(data: bytes) -> BundleManifest:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditPublicationError("terminal_bundle_manifest_invalid") from error
    if canonical_json_bytes(value) != data or not isinstance(value, dict):
        raise AuditPublicationError("terminal_bundle_manifest_noncanonical")
    schema = value.get("schema")
    try:
        if schema == CALIBRATION_BUNDLE_SCHEMA:
            return CalibrationBundleManifest.model_validate(value)
        if schema == INCIDENT_BUNDLE_SCHEMA:
            return IncidentBundleManifest.model_validate(value)
    except Exception as error:
        raise AuditPublicationError("terminal_bundle_manifest_invalid") from error
    raise AuditPublicationError("terminal_bundle_schema_unsupported")


def _install_snapshot(staging: Path, target: Path, public_docroot: Path) -> None:
    renamed = False
    try:
        _validate_public_parent_chain(target.parent.parent, public_docroot)
        target.parent.mkdir(mode=0o755, exist_ok=True)
        _validate_public_parent_chain(target.parent, public_docroot)
        if target.exists():
            staged = _inspect_bundle_tree(staging)
            installed = _inspect_bundle_tree(target)
            if staged.tree_sha256 != installed.tree_sha256:
                raise AuditPublicationError("public_bundle_immutable_conflict")
            shutil.rmtree(staging)
            _make_tree_readonly(target)
            _fsync_directory(target.parent)
            return
        os.rename(staging, target)
        renamed = True
        _make_tree_readonly(target)
        _fsync_directory(target.parent)
    except AuditPublicationError:
        raise
    except OSError as error:
        if renamed:
            _remove_unindexed_tree(target)
        reason = (
            "publication_staging_cross_device"
            if error.errno == errno.EXDEV
            else "public_bundle_atomic_install_failed"
        )
        raise AuditPublicationError(reason) from error


def _remove_unindexed_tree(root: Path) -> None:
    with suppress(OSError):
        root.chmod(0o700)
    objects = root / "objects"
    with suppress(OSError):
        objects.chmod(0o700)
    if objects.exists():
        for path in objects.iterdir():
            with suppress(OSError):
                path.chmod(0o600, follow_symlinks=False)
    with suppress(OSError):
        (root / "manifest.json").chmod(0o600, follow_symlinks=False)
    shutil.rmtree(root, ignore_errors=True)


def _make_tree_readonly(root: Path) -> None:
    objects = root / "objects"
    for path in objects.iterdir():
        path.chmod(0o444, follow_symlinks=False)
    (root / "manifest.json").chmod(0o444, follow_symlinks=False)
    objects.chmod(0o555)
    root.chmod(0o555)
    _fsync_directory(root)


def _public_bundle_relative_path(
    window_id: str,
    classification: str,
    *,
    validator_account_id32: str | None,
) -> str:
    if _HEX32_RE.fullmatch(window_id) is None:
        raise ValueError("public bundle window ID is invalid")
    if classification not in {"calibration_no_weight", "skipped", "void", "failed"}:
        raise ValueError("public bundle classification is invalid")
    prefix = (
        "validators/account"
        if validator_account_id32 is None
        else f"validators/{validator_account_id32}"
    )
    return f"{prefix}/windows/{window_id}/{classification}"


def _bundle_tree_sha256(files: Sequence[PublishedFile]) -> str:
    digest = hashlib.sha256()
    digest.update(_TREE_DOMAIN)
    digest.update(len(files).to_bytes(4, "big"))
    for item in files:
        path = item.relative_path.encode("ascii")
        digest.update(len(path).to_bytes(4, "big"))
        digest.update(path)
        digest.update(bytes.fromhex(item.sha256))
        digest.update(item.size_bytes.to_bytes(8, "big"))
    return digest.hexdigest()


def _require_exact_source_paths(root: Path, object_digests: set[str]) -> None:
    if root.is_symlink() or not root.is_dir():
        raise AuditPublicationError("terminal_bundle_root_unsafe")
    try:
        if {item.name for item in root.iterdir()} != {"manifest.json", "objects"}:
            raise AuditPublicationError("terminal_bundle_top_level_set_invalid")
        objects = root / "objects"
        if objects.is_symlink() or not objects.is_dir():
            raise AuditPublicationError("terminal_bundle_objects_unsafe")
        children = tuple(objects.iterdir())
        if {item.name for item in children} != object_digests:
            raise AuditPublicationError("terminal_bundle_object_set_invalid")
        if any(item.is_symlink() or not item.is_file() for item in children):
            raise AuditPublicationError("terminal_bundle_object_path_unsafe")
    except OSError as error:
        raise AuditPublicationError("terminal_bundle_tree_unavailable", retryable=True) from error


def _read_regular_file(path: Path, *, maximum_bytes: int, empty_allowed: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        reason = (
            "publication_file_unsafe"
            if error.errno == errno.ELOOP
            else "publication_file_unavailable"
        )
        raise AuditPublicationError(reason) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or before.st_size > maximum_bytes
            or (before.st_size == 0 and not empty_allowed)
        ):
            raise AuditPublicationError("publication_file_unsafe")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes - len(data) + 1))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum_bytes:
                raise AuditPublicationError("publication_file_byte_limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    if identity(before) != identity(after) or len(data) != before.st_size:
        raise AuditPublicationError("publication_file_changed")
    return bytes(data)


def _hash_regular_file(path: Path, maximum_bytes: int) -> tuple[str, int]:
    data = _read_regular_file(path, maximum_bytes=maximum_bytes, empty_allowed=True)
    return hashlib.sha256(data).hexdigest(), len(data)


def _write_new_file(path: Path, data: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("publication write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_replace_public_file(
    path: Path,
    data: bytes,
    public_docroot: Path,
    private_staging_root: Path,
) -> None:
    _validate_public_parent_chain(path.parent, public_docroot)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=private_staging_root)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("public index write made no progress")
            offset += written
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _record_from_row(row: sqlite3.Row, *, event: bool) -> PublicationRecord:
    entry_bytes = row["entry_bytes"]
    entry = None
    if entry_bytes is not None:
        try:
            entry = PublicBundleIndexEntry.model_validate_json(bytes(entry_bytes))
        except Exception as error:
            raise AuditPublicationError("publication_state_entry_invalid") from error
        if canonical_json_bytes(entry) != bytes(entry_bytes):
            raise AuditPublicationError("publication_state_entry_noncanonical")
    sequence_column = "sequence" if event else "event_sequence"
    return PublicationRecord(
        source_key=row["source_key"],
        source_kind=row["source_kind"],
        window_id=row["window_id"],
        phase=row["phase"],
        attempt=row["attempt"],
        entry=entry,
        failure_code=row["failure_code"],
        retryable=bool(row["retryable"]),
        event_sequence=row[sequence_column],
        event_sha256=row["event_sha256"],
    )


def _publication_event_sha256(record: PublicationRecord, previous: str) -> str:
    payload = canonical_json_bytes(
        {
            "attempt": record.attempt,
            "entry": None if record.entry is None else record.entry.model_dump(mode="json"),
            "event_sequence": record.event_sequence,
            "failure_code": record.failure_code,
            "phase": record.phase,
            "retryable": record.retryable,
            "source_key": record.source_key,
            "source_kind": record.source_kind,
            "window_id": record.window_id,
        }
    )
    return hashlib.sha256(_STATE_EVENT_DOMAIN + bytes.fromhex(previous) + payload).hexdigest()


def _validate_state_values(
    source_key: str,
    source_kind: str,
    window_id: str,
    phase: str,
    failure_code: str | None,
) -> None:
    if source_kind not in {"calibration", "incident"} or source_key != f"{source_kind}:{window_id}":
        raise AuditPublicationError("publication_state_source_invalid")
    if _HEX32_RE.fullmatch(window_id) is None:
        raise AuditPublicationError("publication_state_window_invalid")
    if phase not in {
        "discovered",
        "local_installed",
        "remote_tree_verified",
        "index_local",
        "complete",
        "failed",
    }:
        raise AuditPublicationError("publication_state_phase_invalid")
    if failure_code is not None and _REASON_RE.fullmatch(failure_code) is None:
        raise AuditPublicationError("publication_state_failure_invalid")
    if (phase == "failed") != (failure_code is not None):
        raise AuditPublicationError("publication_state_failure_shape_invalid")


def _validate_public_origin_name(origin: str) -> None:
    parsed = urlsplit(origin)
    hostname = parsed.hostname
    if parsed.scheme != "https" or hostname is None:
        raise ValueError("public origin must use HTTPS")
    try:
        canonical = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("public origin hostname is invalid") from error
    if canonical != hostname.lower().rstrip("."):
        raise ValueError("public origin hostname must be canonical ASCII")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("literal public origin address must be globally routable")


async def _system_resolver(hostname: str, port: int) -> Sequence[str]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return tuple(str(item[4][0]) for item in records)


async def _resolve_public_address(
    hostname: str,
    port: int,
    resolver: AddressResolver | None,
) -> str:
    try:
        values = await (resolver or _system_resolver)(hostname, port)
        addresses = {ipaddress.ip_address(value) for value in values}
    except Exception as error:
        raise AuditPublicationError("public_origin_dns_failed", retryable=True) from error
    if not addresses or any(not item.is_global for item in addresses):
        raise AuditPublicationError("public_origin_dns_non_public", retryable=True)
    return str(min(addresses, key=lambda item: (item.version, item.packed)))


def _header_bytes(headers: httpx.Headers) -> int:
    return sum(len(name) + len(value) + 4 for name, value in headers.raw)


def _safe_public_relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or any(re.fullmatch(r"[A-Za-z0-9._-]+", part) is None for part in path.parts)
    ):
        raise ValueError("public verification path is unsafe")


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _validate_existing_directory(path: Path, *, private: bool) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise AuditPublicationError("publication_directory_unavailable") from error
    forbidden = 0o077 if private else 0o022
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & forbidden
    ):
        raise AuditPublicationError("publication_directory_unsafe")


def _mkdir_public(path: Path) -> None:
    try:
        path.mkdir(mode=0o755, exist_ok=True)
    except OSError as error:
        raise AuditPublicationError("publication_public_layout_failed") from error
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise AuditPublicationError("publication_public_layout_unsafe")


def _validate_public_parent_chain(path: Path, boundary: Path) -> None:
    current = path
    while True:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise AuditPublicationError("publication_public_parent_unsafe")
        if current == boundary:
            break
        if boundary not in current.parents:
            raise AuditPublicationError("publication_public_parent_outside_docroot")
        current = current.parent


def _prepare_private_database(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise AuditPublicationError("publication_state_path_invalid")
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_existing_directory(parent, private=True)
    _reject_database_links(path)


def _reject_database_links(path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(f"{path}{suffix}")
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
        ):
            raise AuditPublicationError("publication_state_path_unsafe")


def _database_file_identity(path: Path) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as error:
        raise AuditPublicationError("publication_state_path_unsafe") from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        raise AuditPublicationError("publication_state_path_unsafe")
    return info.st_dev, info.st_ino


def _secure_database_files(path: Path) -> None:
    _reject_database_links(path)
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(f"{path}{suffix}")
        if candidate.exists():
            candidate.chmod(0o600, follow_symlinks=False)
    _reject_database_links(path)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_process_lock(path: Path) -> Iterator[None]:
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as error:
        raise AuditPublicationError("publication_worker_lock_unsafe") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise AuditPublicationError("publication_worker_lock_unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise AuditPublicationError("publication_worker_already_running") from error
    except Exception:
        os.close(descriptor)
        raise
    try:
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _production_check(definition: ProductionPublicationDefinition) -> dict[str, object]:
    config = definition.publication_config
    _validate_production_destinations(definition)
    _validate_existing_directory(Path(config.public_docroot), private=False)
    _validate_existing_directory(Path(config.private_staging_root), private=True)
    if Path(config.public_docroot).stat().st_dev != Path(config.private_staging_root).stat().st_dev:
        raise AuditPublicationError("publication_staging_cross_device")
    return {
        "chain_write_capability": False,
        "public_origin": config.public_origin,
        "release_manifest_sha256": definition.release_manifest_sha256,
        "scoring_policy_sha256": scoring_policy_hash(definition.policy),
        "signed_validator_template_verified": True,
        "status": "ready",
        "translation_weights_active": False,
        "validator_account_id32": account_id32(definition.validator_config.validator_hotkey).hex(),
        "wallet_loading_capability": False,
        "weight_submission_capability": False,
    }


def _validate_production_destinations(definition: ProductionPublicationDefinition) -> None:
    config = definition.publication_config
    protected = (
        Path(definition.validator_config.state_root),
        Path(definition.validator_config.conformance_release_root),
        Path(config.validator_config_path),
    )
    destinations = (
        Path(config.public_docroot),
        Path(config.private_staging_root),
        Path(config.state_database_path),
    )
    if any(_overlap(left, right) for left in protected for right in destinations):
        raise AuditPublicationError("publication_signed_input_destination_overlap")


async def _watch(publisher: AuditBundlePublisher, poll_seconds: float) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for item in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(item, stop.set)
            installed.append(item)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        while not stop.is_set():
            summary = await publisher.run_once()
            _write_stdout(summary.as_dict())
            try:
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
            except asyncio.TimeoutError:
                continue
    finally:
        for item in installed:
            loop.remove_signal_handler(item)


def _write_stdout(value: Mapping[str, object]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(dict(value)) + b"\n")
    sys.stdout.buffer.flush()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Publish fully replayed UMI validator bundles through a static HTTPS origin"
    )
    parser.add_argument("--config", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify signed inputs without writes")
    mode.add_argument("--once", action="store_true", help="scan once and exit")
    args = parser.parse_args(argv)
    try:
        definition = load_production_publication_definition(args.config)
        if args.check:
            _write_stdout(_production_check(definition))
            return 0
        publisher = build_production_audit_publisher(definition)
        if args.once:
            summary = asyncio.run(publisher.run_once())
            _write_stdout(summary.as_dict())
            return 1 if summary.failed else 0
        asyncio.run(_watch(publisher, definition.publication_config.poll_seconds))
        return 0
    except AuditPublicationError as error:
        _write_stdout(
            {
                "chain_write_capability": False,
                "reason_code": error.reason_code,
                "status": "blocked",
                "translation_weights_active": False,
                "wallet_loading_capability": False,
                "weight_submission_capability": False,
            }
        )
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception:
        _write_stdout(
            {
                "chain_write_capability": False,
                "reason_code": "publication_startup_failed",
                "status": "blocked",
                "translation_weights_active": False,
                "wallet_loading_capability": False,
                "weight_submission_capability": False,
            }
        )
        return 2


__all__ = [
    "AUDIT_PUBLICATION_CONFIG_SCHEMA",
    "PUBLIC_BUNDLE_INDEX_SCHEMA",
    "AuditBundlePublisher",
    "AuditPublicationConfig",
    "AuditPublicationError",
    "BundleTree",
    "ProductionPublicationDefinition",
    "PublicBundleIndex",
    "PublicBundleIndexEntry",
    "PublicOriginVerifier",
    "PublicationCandidate",
    "PublicationRunSummary",
    "PublicationState",
    "build_production_audit_publisher",
    "load_audit_publication_config",
    "load_production_publication_definition",
    "main",
]
