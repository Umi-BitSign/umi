"""Reference authenticated mirror and short-lived video delivery service.

The service is deliberately a narrow data-plane component.  It reads one
certified publisher release, serves only the exact content-addressed objects in
that release, and persists deterministic miner-delivery tokens before returning
them.  It imports no chain client, wallet, signing, extrinsic, or weight code.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import stat
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Request
from pydantic import Field, model_validator
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from typing_extensions import Self

from .artifacts import PublicBatchManifest, validate_public_batch_manifest
from .crypto import verify_response_signature
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .pool import (
    availability_digest,
    batch_commitment,
    parse_pool_manifest_bytes,
    verify_availability_certificate_member,
)
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, base64url_decode, canonical_json_bytes
from .publisher_availability import (
    ANCHOR_INTENTS_FILENAME,
    CERTIFIED_RELEASE_FILENAME,
    QUALIFICATION_RECEIPTS_DIRECTORY,
    CertifiedPoolRelease,
    PoolAnchorIntent,
    parse_qualification_receipt_bytes,
    qualification_receipt_digest,
)
from .validator_delivery import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_DELIVERY_OBJECT_PATH_PREFIX,
    DELIVERY_ISSUANCE_RESPONSE_SCHEMA,
    IssuedVideoDelivery,
    MirrorDiscoveryRule,
    VideoDeliveryIssuanceRequest,
    VideoDeliveryIssuanceResponse,
    derive_delivery_token,
    normalized_https_origin,
    parse_canonical_model,
    validate_mirror_discovery_quorum,
)
from .validator_live_ports import MirrorWindowIndex
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

MIRROR_SERVICE_CONFIG_SCHEMA = "umi-reference-mirror-service-config/1"
MIRROR_SERVICE_MODE = "live_shadow_calibration"
MIRROR_AUTHENTICATION_PROFILE = "umi-authenticated-content-mirror/1"
MIRROR_SERVICE_STATE_SCHEMA = "umi-reference-mirror-service-state/1"
MIRROR_SERVICE_CONFIG_ENV = "UMI_MIRROR_SERVICE_CONFIG"

MAX_CONFIG_BYTES = 64 * 1024
MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_DISCOVERY_BYTES = 256 * 1024
MAX_CERTIFIED_RELEASE_BYTES = 16 * 1024 * 1024
MAX_TREE_FILES = 100_000
MAX_ERROR_REASON_BYTES = 128
_MAX_INTEGER = (1 << 53) - 1
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
_SAFE_PATH_RE = re.compile(rb"^/[A-Za-z0-9._~/-]*$")
_CONTENT_LENGTH_RE = re.compile(rb"^(?:0|[1-9][0-9]*)$")


class MirrorServiceError(RuntimeError):
    """Stable, non-sensitive service failure."""

    def __init__(self, reason_code: str, status_code: int = 503) -> None:
        if (
            not isinstance(reason_code, str)
            or not reason_code
            or len(reason_code.encode("ascii", "ignore")) > MAX_ERROR_REASON_BYTES
            or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", reason_code) is None
        ):
            raise ValueError("mirror service reason code is invalid")
        self.reason_code = reason_code
        self.status_code = status_code
        super().__init__(reason_code)


class MirrorValidatorCredential(StrictProtocolModel):
    """One owner-provisioned validator identity and independent bearer secret."""

    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    bearer_token: Annotated[str, Field(min_length=43, max_length=43)]

    @model_validator(mode="after")
    def validate_credential(self) -> Self:
        account_id32(self.validator_hotkey)
        try:
            token = base64url_decode(self.bearer_token)
        except (TypeError, ValueError) as error:
            raise ValueError("mirror bearer token must be canonical base64url") from error
        if len(token) != 32:
            raise ValueError("mirror bearer token must encode exactly 256 bits")
        return self


class MirrorServiceConfig(StrictProtocolModel):
    """Owner-private configuration for one certified release tree."""

    schema_: Literal[MIRROR_SERVICE_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[MIRROR_SERVICE_MODE]
    translation_weights_active: Literal[False]
    chain_write_capability: Literal[False]
    weight_submission_capability: Literal[False]
    policy_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    scoring_policy_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    discovery_rule_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    discovery_rule_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    certified_tree_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    certified_release_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    state_database_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    validator_credentials: Annotated[
        list[MirrorValidatorCredential], Field(min_length=1, max_length=256)
    ]
    retrieval_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    delivery_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    listen_host: Annotated[str, Field(min_length=1, max_length=64)] = "127.0.0.1"
    listen_port: Annotated[int, Field(ge=1, le=65_535)] = 8787
    workers: Annotated[int, Field(ge=1, le=32)] = 1

    @model_validator(mode="after")
    def validate_boundaries(self) -> Self:
        paths = (
            self.policy_path,
            self.discovery_rule_path,
            self.certified_tree_root,
            self.state_database_path,
        )
        normalized: list[Path] = []
        for value in paths:
            path = Path(value)
            if (
                not path.is_absolute()
                or str(path) != value
                or ".." in path.parts
                or os.path.normpath(value) != value
            ):
                raise ValueError("mirror service paths must be absolute and normalized")
            normalized.append(path)
        if len(set(normalized)) != len(normalized):
            raise ValueError("mirror service paths must be distinct")
        state = normalized[3]
        tree = normalized[2]
        if state == tree or tree in state.parents:
            raise ValueError("mirror state must be outside the certified tree")
        credential_accounts = [
            account_id32(item.validator_hotkey) for item in self.validator_credentials
        ]
        if credential_accounts != sorted(credential_accounts) or len(
            set(credential_accounts)
        ) != len(credential_accounts):
            raise ValueError("validator credentials must be unique and account-sorted")
        credential_tokens = [
            base64url_decode(item.bearer_token) for item in self.validator_credentials
        ]
        if len(set(credential_tokens)) != len(credential_tokens):
            raise ValueError("validator bearer tokens must be unique")
        if normalized_https_origin(self.retrieval_origin) != self.retrieval_origin:
            raise ValueError("retrieval origin must be canonical HTTPS")
        if normalized_https_origin(self.delivery_origin) != self.delivery_origin:
            raise ValueError("delivery origin must be canonical HTTPS")
        _validate_public_origin_name(self.retrieval_origin)
        _validate_public_origin_name(self.delivery_origin)
        if self.retrieval_origin == self.delivery_origin:
            raise ValueError("retrieval and delivery origins must be distinct")
        try:
            address = ipaddress.ip_address(self.listen_host)
        except ValueError as error:
            raise ValueError("listen host must be an IP address") from error
        if address.is_multicast or (
            address.is_unspecified and self.listen_host not in {"0.0.0.0", "::"}
        ):
            raise ValueError("listen host is invalid")
        return self


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mode: int
    uid: int
    links: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    relative_path: str
    path: Path
    sha256: str
    size_bytes: int
    media_type: str
    identity: _FileIdentity


@dataclass(frozen=True, slots=True)
class _LoadedService:
    config_path: Path
    config_bytes: bytes
    config_identity: _FileIdentity
    config: MirrorServiceConfig
    policy_path: Path
    policy_bytes: bytes
    policy_identity: _FileIdentity
    policy: ScoringPolicy
    discovery_path: Path
    discovery_bytes: bytes
    discovery_identity: _FileIdentity
    discovery: MirrorDiscoveryRule
    tree_root: Path
    tree_snapshot: Mapping[str, _FileIdentity]
    release: CertifiedPoolRelease
    release_bytes: bytes
    index: MirrorWindowIndex
    index_bytes: bytes
    index_entry: _TreeEntry
    objects: Mapping[str, _TreeEntry]
    videos: Mapping[tuple[str, str], _TreeEntry]
    batch_publishers: Mapping[str, str]
    static_entries: Mapping[str, _TreeEntry]


@dataclass(frozen=True, slots=True)
class MirrorServiceCheckResult:
    """Non-secret result of the no-network, no-write service readiness check."""

    scoring_policy_sha256: str
    discovery_rule_sha256: str
    certified_release_sha256: str
    anchor_intents_sha256: str
    mirror_index_sha256: str
    window_id: str
    window_index: int
    retrieval_origin: str
    delivery_origin: str
    credential_validator_hotkeys: tuple[str, ...]


class _MirrorState:
    def __init__(self, loaded: _LoadedService, *, busy_timeout_ms: int = 5_000) -> None:
        self.loaded = loaded
        self.path = Path(loaded.config.state_database_path)
        self.busy_timeout_ms = busy_timeout_ms
        self._integrity_key = hashlib.sha256(
            b"umi-reference-mirror-service-state-key-v1\0" + loaded.config_bytes
        ).digest()
        _prepare_private_state_path(self.path)
        try:
            self._initialize()
            self._audit()
        except MirrorServiceError:
            raise
        except sqlite3.Error as error:
            raise MirrorServiceError("mirror_state_database_invalid") from error

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        _reject_state_links(self.path)
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        _secure_state_files(self.path)
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            connection.close()
            raise MirrorServiceError("mirror_state_foreign_keys_unavailable")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            connection.close()
            raise MirrorServiceError("mirror_state_full_sync_unavailable")
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

    def _initialize(self) -> None:
        with self._connection() as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise MirrorServiceError("mirror_state_wal_unavailable")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS requests (
                    request_sha256 TEXT PRIMARY KEY,
                    window_id TEXT NOT NULL,
                    validator_hotkey TEXT NOT NULL,
                    delivery_token_seed TEXT NOT NULL,
                    request_bytes BLOB NOT NULL,
                    response_sha256 TEXT NOT NULL,
                    response_bytes BLOB NOT NULL,
                    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
                    record_hmac TEXT NOT NULL,
                    UNIQUE(window_id, validator_hotkey),
                    UNIQUE(window_id, delivery_token_seed)
                ) STRICT;
                CREATE TABLE IF NOT EXISTS deliveries (
                    token TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL REFERENCES requests(request_sha256),
                    batch_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    object_sha256 TEXT NOT NULL,
                    object_size_bytes INTEGER NOT NULL CHECK(object_size_bytes > 0),
                    source_relative_path TEXT NOT NULL,
                    expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms > 0),
                    record_hmac TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS clock_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    last_seen_unix_ms INTEGER NOT NULL CHECK(last_seen_unix_ms >= 0),
                    record_hmac TEXT NOT NULL
                ) STRICT;
                """
            )
            expected = {
                "schema": MIRROR_SERVICE_STATE_SCHEMA,
                "config_sha256": hashlib.sha256(self.loaded.config_bytes).hexdigest(),
                "policy_sha256": hashlib.sha256(self.loaded.policy_bytes).hexdigest(),
                "discovery_sha256": hashlib.sha256(self.loaded.discovery_bytes).hexdigest(),
                "certified_release_sha256": hashlib.sha256(self.loaded.release_bytes).hexdigest(),
                "mirror_index_sha256": hashlib.sha256(self.loaded.index_bytes).hexdigest(),
            }
            connection.execute("BEGIN IMMEDIATE")
            try:
                for key, value in expected.items():
                    row = connection.execute(
                        "SELECT value FROM metadata WHERE key = ?", (key,)
                    ).fetchone()
                    if row is None:
                        connection.execute(
                            "INSERT INTO metadata (key, value) VALUES (?, ?)", (key, value)
                        )
                    elif row["value"] != value:
                        raise MirrorServiceError("mirror_state_identity_conflict")
            except BaseException:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")
        _secure_state_files(self.path)
        _fsync_directory(self.path.parent)

    def _mac(self, domain: bytes, value: Mapping[str, object]) -> str:
        return hmac.new(
            self._integrity_key,
            domain + canonical_json_bytes(dict(value)),
            hashlib.sha256,
        ).hexdigest()

    def _clock_mac(self, now_ms: int) -> str:
        return self._mac(
            b"umi-reference-mirror-clock-row-v1\0",
            {"last_seen_unix_ms": now_ms},
        )

    def _request_mac(
        self,
        *,
        request_sha256: str,
        window_id: str,
        validator_hotkey: str,
        delivery_token_seed: str,
        response_sha256: str,
        created_at_unix_ms: int,
    ) -> str:
        return self._mac(
            b"umi-reference-mirror-request-row-v1\0",
            {
                "created_at_unix_ms": created_at_unix_ms,
                "delivery_token_seed": delivery_token_seed,
                "request_sha256": request_sha256,
                "response_sha256": response_sha256,
                "validator_hotkey": validator_hotkey,
                "window_id": window_id,
            },
        )

    def _delivery_mac(
        self,
        *,
        token: str,
        request_sha256: str,
        batch_id: str,
        challenge_id: str,
        object_sha256: str,
        object_size_bytes: int,
        source_relative_path: str,
        expires_at_unix_ms: int,
    ) -> str:
        return self._mac(
            b"umi-reference-mirror-delivery-row-v1\0",
            {
                "batch_id": batch_id,
                "challenge_id": challenge_id,
                "expires_at_unix_ms": expires_at_unix_ms,
                "object_sha256": object_sha256,
                "object_size_bytes": object_size_bytes,
                "request_sha256": request_sha256,
                "source_relative_path": source_relative_path,
                "token": token,
            },
        )

    def _advance_clock(self, connection: sqlite3.Connection, now_ms: int) -> None:
        if (
            isinstance(now_ms, bool)
            or not isinstance(now_ms, int)
            or not 0 <= now_ms <= _MAX_INTEGER
        ):
            raise MirrorServiceError("mirror_clock_invalid")
        row = connection.execute(
            "SELECT last_seen_unix_ms, record_hmac FROM clock_state WHERE singleton = 1"
        ).fetchone()
        if row is not None and not hmac.compare_digest(
            row["record_hmac"], self._clock_mac(row["last_seen_unix_ms"])
        ):
            raise MirrorServiceError("mirror_clock_state_tampered")
        if row is not None and now_ms < row["last_seen_unix_ms"]:
            raise MirrorServiceError("mirror_clock_rollback")
        if row is None:
            connection.execute(
                "INSERT INTO clock_state (singleton, last_seen_unix_ms, record_hmac) "
                "VALUES (1, ?, ?)",
                (now_ms, self._clock_mac(now_ms)),
            )
        else:
            connection.execute(
                "UPDATE clock_state SET last_seen_unix_ms = ?, record_hmac = ? WHERE singleton = 1",
                (now_ms, self._clock_mac(now_ms)),
            )

    def observe_clock(self, now_ms: int) -> None:
        with self._transaction() as connection:
            self._advance_clock(connection, now_ms)

    def issue(
        self,
        validator_hotkey: str,
        request: VideoDeliveryIssuanceRequest,
        request_bytes: bytes,
        response: VideoDeliveryIssuanceResponse,
        response_bytes: bytes,
        mappings: Sequence[tuple[str, _TreeEntry, int]],
        *,
        now_ms: int,
    ) -> bytes:
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        response_sha256 = hashlib.sha256(response_bytes).hexdigest()
        with self._transaction() as connection:
            self._advance_clock(connection, now_ms)
            existing_validator = connection.execute(
                "SELECT request_sha256 FROM requests WHERE window_id = ? AND validator_hotkey = ?",
                (request.window_id, validator_hotkey),
            ).fetchone()
            if (
                existing_validator is not None
                and existing_validator["request_sha256"] != request_sha256
            ):
                raise MirrorServiceError("mirror_delivery_validator_replay_conflict", 409)
            existing_seed = connection.execute(
                "SELECT request_sha256 FROM requests WHERE window_id = ? "
                "AND delivery_token_seed = ?",
                (request.window_id, request.delivery_token_seed),
            ).fetchone()
            if existing_seed is not None and existing_seed["request_sha256"] != request_sha256:
                raise MirrorServiceError("mirror_delivery_seed_conflict", 409)
            existing = connection.execute(
                "SELECT * FROM requests WHERE request_sha256 = ?", (request_sha256,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["validator_hotkey"] != validator_hotkey
                    or bytes(existing["request_bytes"]) != request_bytes
                    or existing["response_sha256"] != response_sha256
                    or bytes(existing["response_bytes"]) != response_bytes
                    or not hmac.compare_digest(
                        existing["record_hmac"],
                        self._request_mac(
                            request_sha256=existing["request_sha256"],
                            window_id=existing["window_id"],
                            validator_hotkey=existing["validator_hotkey"],
                            delivery_token_seed=existing["delivery_token_seed"],
                            response_sha256=existing["response_sha256"],
                            created_at_unix_ms=existing["created_at_unix_ms"],
                        ),
                    )
                ):
                    raise MirrorServiceError("mirror_delivery_request_conflict", 409)
                self._verify_request_rows(connection, request, response, mappings)
                return bytes(existing["response_bytes"])

            connection.execute(
                "INSERT INTO requests (request_sha256, window_id, validator_hotkey, "
                "delivery_token_seed, "
                "request_bytes, response_sha256, response_bytes, created_at_unix_ms, "
                "record_hmac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_sha256,
                    request.window_id,
                    validator_hotkey,
                    request.delivery_token_seed,
                    request_bytes,
                    response_sha256,
                    response_bytes,
                    now_ms,
                    self._request_mac(
                        request_sha256=request_sha256,
                        window_id=request.window_id,
                        validator_hotkey=validator_hotkey,
                        delivery_token_seed=request.delivery_token_seed,
                        response_sha256=response_sha256,
                        created_at_unix_ms=now_ms,
                    ),
                ),
            )
            for delivery, (token, entry, expires_at) in zip(
                response.deliveries, mappings, strict=True
            ):
                try:
                    connection.execute(
                        "INSERT INTO deliveries (token, request_sha256, batch_id, challenge_id, "
                        "object_sha256, object_size_bytes, source_relative_path, "
                        "expires_at_unix_ms, record_hmac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            token,
                            request_sha256,
                            delivery.batch_id,
                            delivery.challenge_id,
                            entry.sha256,
                            entry.size_bytes,
                            entry.relative_path,
                            expires_at,
                            self._delivery_mac(
                                token=token,
                                request_sha256=request_sha256,
                                batch_id=delivery.batch_id,
                                challenge_id=delivery.challenge_id,
                                object_sha256=entry.sha256,
                                object_size_bytes=entry.size_bytes,
                                source_relative_path=entry.relative_path,
                                expires_at_unix_ms=expires_at,
                            ),
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise MirrorServiceError("mirror_delivery_token_conflict", 409) from error
        return response_bytes

    def _verify_request_rows(
        self,
        connection: sqlite3.Connection,
        request: VideoDeliveryIssuanceRequest,
        response: VideoDeliveryIssuanceResponse,
        mappings: Sequence[tuple[str, _TreeEntry, int]],
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM deliveries WHERE request_sha256 = ? ORDER BY batch_id, challenge_id",
            (hashlib.sha256(canonical_json_bytes(request)).hexdigest(),),
        ).fetchall()
        if len(rows) != len(response.deliveries) or len(rows) != len(mappings):
            raise MirrorServiceError("mirror_delivery_state_incomplete")
        expected = {
            (delivery.batch_id, delivery.challenge_id): (delivery, mapping)
            for delivery, mapping in zip(response.deliveries, mappings, strict=True)
        }
        for row in rows:
            key = (row["batch_id"], row["challenge_id"])
            value = expected.get(key)
            if value is None:
                raise MirrorServiceError("mirror_delivery_state_conflict")
            delivery, (token, entry, expires_at) = value
            if (
                row["token"] != token
                or row["object_sha256"] != entry.sha256
                or row["object_size_bytes"] != entry.size_bytes
                or row["source_relative_path"] != entry.relative_path
                or row["expires_at_unix_ms"] != expires_at
                or delivery.expires_at_unix_ms != expires_at
                or not hmac.compare_digest(
                    row["record_hmac"],
                    self._delivery_mac(
                        token=row["token"],
                        request_sha256=row["request_sha256"],
                        batch_id=row["batch_id"],
                        challenge_id=row["challenge_id"],
                        object_sha256=row["object_sha256"],
                        object_size_bytes=row["object_size_bytes"],
                        source_relative_path=row["source_relative_path"],
                        expires_at_unix_ms=row["expires_at_unix_ms"],
                    ),
                )
            ):
                raise MirrorServiceError("mirror_delivery_state_conflict")

    def lookup_delivery(self, token: str, *, now_ms: int) -> _TreeEntry:
        # Unknown public tokens must remain a read-only miss.  Advancing the
        # durable clock before proving that a token exists would let unauthenticated
        # random probes grow the WAL and contend with issuance transactions.
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM deliveries WHERE token = ?", (token,)
            ).fetchone()
            clock = connection.execute(
                "SELECT last_seen_unix_ms, record_hmac FROM clock_state WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise MirrorServiceError("mirror_delivery_not_found", 404)
            if not hmac.compare_digest(
                row["record_hmac"],
                self._delivery_mac(
                    token=row["token"],
                    request_sha256=row["request_sha256"],
                    batch_id=row["batch_id"],
                    challenge_id=row["challenge_id"],
                    object_sha256=row["object_sha256"],
                    object_size_bytes=row["object_size_bytes"],
                    source_relative_path=row["source_relative_path"],
                    expires_at_unix_ms=row["expires_at_unix_ms"],
                ),
            ):
                raise MirrorServiceError("mirror_delivery_state_tampered")
            if clock is not None and not hmac.compare_digest(
                clock["record_hmac"], self._clock_mac(clock["last_seen_unix_ms"])
            ):
                raise MirrorServiceError("mirror_clock_state_tampered")

        # A known capability token is security-sensitive.  Reconcile the whole
        # durable mapping set before advancing any state so deletion of the clock
        # high-water row cannot silently reset rollback protection.
        self.audit()
        expires_at = row["expires_at_unix_ms"]
        last_seen = clock["last_seen_unix_ms"] if clock is not None else None
        if now_ms >= expires_at:
            # Persist the first expiry observation.  Later probes of an already
            # expired token are read-only, while a rollback below last_seen still
            # goes through _advance_clock and fails closed.
            if last_seen is None or last_seen < expires_at or now_ms < last_seen:
                self.observe_clock(now_ms)
            raise MirrorServiceError("mirror_delivery_expired", 410)

        # A live delivery is security-sensitive, so every successful read is
        # ordered after a durable monotonic-clock observation.
        self.observe_clock(now_ms)
        with self._connection() as connection:
            current = connection.execute(
                "SELECT * FROM deliveries WHERE token = ?", (token,)
            ).fetchone()
            if current is None or dict(current) != dict(row):
                raise MirrorServiceError("mirror_delivery_state_conflict")
            entry = self.loaded.objects.get(row["object_sha256"])
            if (
                entry is None
                or entry.relative_path != row["source_relative_path"]
                or entry.size_bytes != row["object_size_bytes"]
                or entry.media_type != "video/mp4"
            ):
                raise MirrorServiceError("mirror_delivery_state_conflict")
            return entry

    def _audit(self) -> None:
        with self._connection() as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise MirrorServiceError("mirror_state_quick_check_failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise MirrorServiceError("mirror_state_foreign_key_check_failed")
            schema_rows = connection.execute(
                "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' "
                "ORDER BY type, name"
            ).fetchall()
            expected_tables = {"clock_state", "deliveries", "metadata", "requests"}
            if {
                row["name"] for row in schema_rows if row["type"] == "table"
            } != expected_tables or any(row["type"] != "table" for row in schema_rows):
                raise MirrorServiceError("mirror_state_schema_changed")
            expected_columns = {
                "metadata": ("key", "value"),
                "requests": (
                    "request_sha256",
                    "window_id",
                    "validator_hotkey",
                    "delivery_token_seed",
                    "request_bytes",
                    "response_sha256",
                    "response_bytes",
                    "created_at_unix_ms",
                    "record_hmac",
                ),
                "deliveries": (
                    "token",
                    "request_sha256",
                    "batch_id",
                    "challenge_id",
                    "object_sha256",
                    "object_size_bytes",
                    "source_relative_path",
                    "expires_at_unix_ms",
                    "record_hmac",
                ),
                "clock_state": ("singleton", "last_seen_unix_ms", "record_hmac"),
            }
            if any(
                tuple(row["name"] for row in connection.execute(f"PRAGMA table_info({table})"))
                != columns
                for table, columns in expected_columns.items()
            ):
                raise MirrorServiceError("mirror_state_schema_changed")
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            expected_metadata = {
                "schema": MIRROR_SERVICE_STATE_SCHEMA,
                "config_sha256": hashlib.sha256(self.loaded.config_bytes).hexdigest(),
                "policy_sha256": hashlib.sha256(self.loaded.policy_bytes).hexdigest(),
                "discovery_sha256": hashlib.sha256(self.loaded.discovery_bytes).hexdigest(),
                "certified_release_sha256": hashlib.sha256(self.loaded.release_bytes).hexdigest(),
                "mirror_index_sha256": hashlib.sha256(self.loaded.index_bytes).hexdigest(),
            }
            if metadata != expected_metadata:
                raise MirrorServiceError("mirror_state_identity_conflict")
            requests = connection.execute(
                "SELECT * FROM requests ORDER BY request_sha256"
            ).fetchall()
            if (
                len(requests) > len(self.loaded.config.validator_credentials)
                or len({row["request_sha256"] for row in requests}) != len(requests)
                or len({(row["window_id"], row["validator_hotkey"]) for row in requests})
                != len(requests)
                or len({(row["window_id"], row["delivery_token_seed"]) for row in requests})
                != len(requests)
            ):
                raise MirrorServiceError("mirror_delivery_state_cardinality_invalid")
            for row in requests:
                request_bytes = bytes(row["request_bytes"])
                response_bytes = bytes(row["response_bytes"])
                try:
                    request = parse_canonical_model(
                        request_bytes,
                        VideoDeliveryIssuanceRequest,
                        maximum_bytes=self.loaded.policy.limits.maximum_request_body_bytes,
                        label="persisted delivery request",
                    )
                    _validate_delivery_request(self.loaded, request)
                    response, mappings = _build_delivery_response(self.loaded, request)
                except (TypeError, ValueError, MirrorServiceError) as error:
                    raise MirrorServiceError("mirror_delivery_state_invalid") from error
                if (
                    hashlib.sha256(request_bytes).hexdigest() != row["request_sha256"]
                    or request.window_id != row["window_id"]
                    or row["validator_hotkey"]
                    not in {
                        item.validator_hotkey for item in self.loaded.config.validator_credentials
                    }
                    or request.delivery_token_seed != row["delivery_token_seed"]
                    or canonical_json_bytes(response) != response_bytes
                    or hashlib.sha256(response_bytes).hexdigest() != row["response_sha256"]
                    or not hmac.compare_digest(
                        row["record_hmac"],
                        self._request_mac(
                            request_sha256=row["request_sha256"],
                            window_id=row["window_id"],
                            validator_hotkey=row["validator_hotkey"],
                            delivery_token_seed=row["delivery_token_seed"],
                            response_sha256=row["response_sha256"],
                            created_at_unix_ms=row["created_at_unix_ms"],
                        ),
                    )
                ):
                    raise MirrorServiceError("mirror_delivery_state_invalid")
                self._verify_request_rows(connection, request, response, mappings)
            delivery_rows = connection.execute(
                "SELECT token, request_sha256 FROM deliveries"
            ).fetchall()
            if len({row["token"] for row in delivery_rows}) != len(delivery_rows) or {
                row["request_sha256"] for row in delivery_rows
            } - {row["request_sha256"] for row in requests}:
                raise MirrorServiceError("mirror_delivery_state_cardinality_invalid")
            clocks = connection.execute(
                "SELECT singleton, last_seen_unix_ms, record_hmac FROM clock_state"
            ).fetchall()
            if (
                len(clocks) > 1
                or (requests and len(clocks) != 1)
                or (clocks and clocks[0]["singleton"] != 1)
            ):
                raise MirrorServiceError("mirror_clock_state_tampered")
            clock = clocks[0] if clocks else None
            if clock is not None and not hmac.compare_digest(
                clock["record_hmac"], self._clock_mac(clock["last_seen_unix_ms"])
            ):
                raise MirrorServiceError("mirror_clock_state_tampered")

    def audit(self) -> None:
        try:
            self._audit()
        except MirrorServiceError:
            raise
        except sqlite3.Error as error:
            raise MirrorServiceError("mirror_state_database_invalid") from error


class MirrorServiceRuntime:
    """Immutable tree plus durable issuance state used by the ASGI boundary."""

    def __init__(
        self,
        loaded: _LoadedService,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.loaded = loaded
        self.state = _MirrorState(loaded)
        self._clock = clock or (lambda: time.time_ns() // 1_000_000)
        self._credential_hashes = tuple(
            (
                item.validator_hotkey,
                hashlib.sha256(("Bearer " + item.bearer_token).encode("ascii")).digest(),
            )
            for item in loaded.config.validator_credentials
        )
        self._retrieval_host = _origin_authority(loaded.config.retrieval_origin)
        self._delivery_host = _origin_authority(loaded.config.delivery_origin)

    def now_ms(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_INTEGER:
            raise MirrorServiceError("mirror_clock_invalid")
        return value

    def assert_immutable(self) -> None:
        _assert_file_unchanged(
            self.loaded.config_path,
            self.loaded.config_identity,
            self.loaded.config_bytes,
            maximum_bytes=MAX_CONFIG_BYTES,
            private=True,
        )
        _assert_file_unchanged(
            self.loaded.policy_path,
            self.loaded.policy_identity,
            self.loaded.policy_bytes,
            maximum_bytes=MAX_POLICY_BYTES,
        )
        _assert_file_unchanged(
            self.loaded.discovery_path,
            self.loaded.discovery_identity,
            self.loaded.discovery_bytes,
            maximum_bytes=MAX_DISCOVERY_BYTES,
        )
        if _snapshot_tree(self.loaded.tree_root) != self.loaded.tree_snapshot:
            raise MirrorServiceError("mirror_certified_tree_changed")

    def require_authentication(self, request: Request) -> str:
        values = [
            value for name, value in request.scope["headers"] if name.lower() == b"authorization"
        ]
        supplied = values[0] if len(values) == 1 else b""
        supplied_digest = hashlib.sha256(supplied).digest()
        matches = tuple(
            hmac.compare_digest(supplied_digest, expected)
            for _hotkey, expected in self._credential_hashes
        )
        if sum(int(value) for value in matches) != 1:
            raise MirrorServiceError("mirror_authentication_failed", 401)
        return next(
            hotkey
            for (hotkey, _expected), matched in zip(self._credential_hashes, matches, strict=True)
            if matched
        )

    def require_route_origin(self, request: Request, *, public_delivery: bool) -> None:
        hosts = [value for name, value in request.scope["headers"] if name.lower() == b"host"]
        expected = self._delivery_host if public_delivery else self._retrieval_host
        supplied = hosts[0].lower() if len(hosts) == 1 else b""
        if not hmac.compare_digest(supplied, expected):
            raise MirrorServiceError("mirror_http_origin_mismatch", 421)

    def read_entry(self, entry: _TreeEntry) -> bytes:
        data, identity = _read_owned_file(
            entry.path,
            maximum_bytes=entry.size_bytes,
            private=False,
        )
        if (
            identity != entry.identity
            or len(data) != entry.size_bytes
            or hashlib.sha256(data).hexdigest() != entry.sha256
        ):
            raise MirrorServiceError("mirror_certified_object_changed")
        return data

    def issue(self, request_bytes: bytes, *, validator_hotkey: str) -> bytes:
        try:
            request = parse_canonical_model(
                request_bytes,
                VideoDeliveryIssuanceRequest,
                maximum_bytes=self.loaded.policy.limits.maximum_request_body_bytes,
                label="video delivery issuance request",
            )
            _validate_delivery_request(self.loaded, request)
            response, mappings = _build_delivery_response(self.loaded, request)
        except (TypeError, ValueError) as error:
            raise MirrorServiceError("mirror_delivery_request_invalid", 400) from error
        now_ms = self.now_ms()
        # Commit the observation independently, including when schedule checks
        # reject the request, so a later wall-clock rollback cannot reopen it.
        self.state.observe_clock(now_ms)
        selection_ms = _round_time_ms(self.loaded.release.window.selection_round)
        issue_close_ms = _round_time_ms(self.loaded.release.window.issue_close_round)
        if now_ms < selection_ms:
            raise MirrorServiceError("mirror_delivery_selection_not_available", 425)
        if now_ms >= issue_close_ms:
            raise MirrorServiceError("mirror_delivery_issuance_closed", 410)
        response_bytes = canonical_json_bytes(response)
        if len(response_bytes) > min(
            self.loaded.policy.limits.maximum_manifest_bytes,
            self.loaded.policy.limits.maximum_response_body_bytes,
        ):
            raise MirrorServiceError("mirror_delivery_response_size_limit")
        return self.state.issue(
            validator_hotkey,
            request,
            request_bytes,
            response,
            response_bytes,
            mappings,
            now_ms=now_ms,
        )


def _validate_delivery_request(self: _LoadedService, request: VideoDeliveryIssuanceRequest) -> None:
    policy_hash = scoring_policy_hash(self.policy)
    window = self.release.window
    if (
        request.window_id != window.window_id
        or request.window_index != window.window_index
        or request.scoring_policy_hash != policy_hash
        or request.response_close_round != window.response_close_round
    ):
        raise ValueError("delivery request window does not match the certified release")
    expected: dict[tuple[str, str], _TreeEntry] = self.videos
    request_by_key = {(item.batch_id, item.challenge_id): item for item in request.items}
    if any(key not in expected for key in request_by_key):
        raise ValueError("delivery request contains an uncertified video")
    selected_batches = {item.batch_id for item in request.items}
    if len(selected_batches) != self.policy.limits.batches_selected_per_window:
        raise ValueError("delivery request does not contain the selected batch count")
    publisher_groups = {
        account_id32(item.publisher_hotkey): item.control_group_id
        for item in self.policy.publisher_registry
    }
    selected_groups = {
        publisher_groups[account_id32(self.batch_publishers[batch_id])]
        for batch_id in selected_batches
    }
    if len(selected_groups) != len(selected_batches):
        raise ValueError("delivery request batches share one publisher control group")
    for batch_id in selected_batches:
        requested = {key for key in request_by_key if key[0] == batch_id}
        certified = {key for key in expected if key[0] == batch_id}
        if requested != certified:
            raise ValueError("delivery request omits part of a selected batch")
    for key, item in request_by_key.items():
        entry = expected[key]
        if item.sha256 != entry.sha256 or item.size_bytes != entry.size_bytes:
            raise ValueError("delivery request changes a certified video commitment")


def _build_delivery_response(
    self: _LoadedService,
    request: VideoDeliveryIssuanceRequest,
) -> tuple[VideoDeliveryIssuanceResponse, tuple[tuple[str, _TreeEntry, int], ...]]:
    expires_at = _round_time_ms(request.response_close_round) + (
        self.policy.clock.delivery_grace_seconds * 1_000
    )
    deliveries: list[IssuedVideoDelivery] = []
    mappings: list[tuple[str, _TreeEntry, int]] = []
    for item in request.items:
        entry = self.videos[(item.batch_id, item.challenge_id)]
        token = derive_delivery_token(request, item)
        deliveries.append(
            IssuedVideoDelivery(
                batch_id=item.batch_id,
                challenge_id=item.challenge_id,
                sha256=item.sha256,
                size_bytes=item.size_bytes,
                url=self.config.delivery_origin + DEFAULT_DELIVERY_OBJECT_PATH_PREFIX + token,
                expires_at_unix_ms=expires_at,
            )
        )
        mappings.append((token, entry, expires_at))
    return (
        VideoDeliveryIssuanceResponse(
            schema=DELIVERY_ISSUANCE_RESPONSE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=request.window_id,
            window_index=request.window_index,
            scoring_policy_hash=request.scoring_policy_hash,
            response_close_round=request.response_close_round,
            deliveries=deliveries,
        ),
        tuple(mappings),
    )


def _load_mirror_service_definition(
    config_path: str | Path,
) -> _LoadedService:
    path = Path(config_path)
    config_bytes, config_identity = _read_owned_file(
        path,
        maximum_bytes=MAX_CONFIG_BYTES,
        private=True,
    )
    try:
        config = MirrorServiceConfig.model_validate_json(config_bytes)
    except Exception as error:
        raise MirrorServiceError("mirror_config_invalid") from error
    if canonical_json_bytes(config) != config_bytes:
        raise MirrorServiceError("mirror_config_noncanonical")

    policy_path = Path(config.policy_path)
    policy_bytes, policy_identity = _read_owned_file(
        policy_path,
        maximum_bytes=MAX_POLICY_BYTES,
        private=False,
    )
    try:
        policy = ScoringPolicy.model_validate_json(policy_bytes)
    except Exception as error:
        raise MirrorServiceError("mirror_policy_invalid") from error
    if (
        canonical_json_bytes(policy) != policy_bytes
        or scoring_policy_hash(policy) != config.scoring_policy_sha256
        or policy.translation_weights_active is not False
    ):
        raise MirrorServiceError("mirror_policy_binding_mismatch")
    configured_validators = [
        account_id32(item.validator_hotkey) for item in config.validator_credentials
    ]
    policy_validators = sorted(
        account_id32(item.validator_hotkey) for item in policy.validator_registry
    )
    if configured_validators != policy_validators:
        raise MirrorServiceError("mirror_validator_credential_set_mismatch")

    discovery_path = Path(config.discovery_rule_path)
    discovery_bytes, discovery_identity = _read_owned_file(
        discovery_path,
        maximum_bytes=MAX_DISCOVERY_BYTES,
        private=False,
    )
    try:
        discovery = parse_canonical_model(
            discovery_bytes,
            MirrorDiscoveryRule,
            maximum_bytes=MAX_DISCOVERY_BYTES,
            label="mirror discovery rule",
        )
    except ValueError as error:
        raise MirrorServiceError("mirror_discovery_invalid") from error
    try:
        validate_mirror_discovery_quorum(policy, discovery)
    except (TypeError, ValueError) as error:
        raise MirrorServiceError("mirror_discovery_quorum_invalid") from error
    if (
        hashlib.sha256(discovery_bytes).hexdigest() != config.discovery_rule_sha256
        or config.discovery_rule_sha256
        != policy.implementation_pins.rules.mirror_discovery_rule_sha256
        or discovery.authentication_profile != MIRROR_AUTHENTICATION_PROFILE
        or discovery.authentication_profile
        != policy.implementation_pins.rules.mirror_authentication_profile
        or config.retrieval_origin not in discovery.origins
        or config.delivery_origin not in discovery.delivery_origins
    ):
        raise MirrorServiceError("mirror_discovery_binding_mismatch")

    root = Path(config.certified_tree_root)
    tree_snapshot = _snapshot_tree(root)
    release_path = root / CERTIFIED_RELEASE_FILENAME
    release_bytes, _release_identity = _read_owned_file(
        release_path,
        maximum_bytes=MAX_CERTIFIED_RELEASE_BYTES,
        private=False,
    )
    try:
        release = CertifiedPoolRelease.model_validate_json(release_bytes)
    except Exception as error:
        raise MirrorServiceError("mirror_certified_release_invalid") from error
    if (
        canonical_json_bytes(release) != release_bytes
        or hashlib.sha256(release_bytes).hexdigest() != config.certified_release_sha256
        or release.window.scoring_policy_hash != scoring_policy_hash(policy)
        or release.translation_weights_active is not False
        or release.weight_submission_capability is not False
        or release.broadcast_performed is not False
    ):
        raise MirrorServiceError("mirror_certified_release_binding_mismatch")

    expected_index_relative = release.mirror_index_path.format(
        window_id=release.window.window_id
    ).removeprefix("/")
    index_path = root / expected_index_relative
    index_bytes, index_identity = _read_owned_file(
        index_path,
        maximum_bytes=policy.limits.maximum_manifest_bytes,
        private=False,
    )
    try:
        index = parse_canonical_model(
            index_bytes,
            MirrorWindowIndex,
            maximum_bytes=policy.limits.maximum_manifest_bytes,
            label="mirror window index",
        )
    except ValueError as error:
        raise MirrorServiceError("mirror_index_invalid") from error
    if (
        hashlib.sha256(index_bytes).hexdigest() != release.mirror_index_sha256
        or len(index_bytes) != release.mirror_index_size_bytes
        or (index.window_id, index.window_index, index.scoring_policy_hash)
        != (
            release.window.window_id,
            release.window.window_index,
            release.window.scoring_policy_hash,
        )
    ):
        raise MirrorServiceError("mirror_index_binding_mismatch")

    objects: dict[str, _TreeEntry] = {}
    videos: dict[tuple[str, str], _TreeEntry] = {}
    descriptor_by_batch_kind: dict[tuple[str, str], _TreeEntry] = {}
    pool_descriptors: list[tuple[str, _TreeEntry]] = []
    for descriptor in index.objects:
        expected_relative = f"v1/umi/objects/{descriptor.sha256}"
        if descriptor.path != "/" + expected_relative:
            raise MirrorServiceError("mirror_object_path_not_content_addressed")
        object_path = root / expected_relative
        data, identity = _read_owned_file(
            object_path,
            maximum_bytes=_object_ceiling(policy, descriptor.media_type),
            private=False,
        )
        if (
            len(data) != descriptor.size_bytes
            or hashlib.sha256(data).hexdigest() != descriptor.sha256
        ):
            raise MirrorServiceError("mirror_certified_object_binding_mismatch")
        entry = _TreeEntry(
            relative_path=expected_relative,
            path=object_path,
            sha256=descriptor.sha256,
            size_bytes=descriptor.size_bytes,
            media_type=descriptor.media_type,
            identity=identity,
        )
        prior = objects.setdefault(descriptor.sha256, entry)
        if prior != entry:
            raise MirrorServiceError("mirror_certified_object_conflict")
        if descriptor.kind == "video":
            key = (descriptor.batch_id or "", descriptor.challenge_id or "")
            if key in videos:
                raise MirrorServiceError("mirror_certified_video_duplicate")
            videos[key] = entry
        elif descriptor.kind in {"public_manifest", "ground_truth_envelope"}:
            key = (descriptor.batch_id or "", descriptor.kind)
            if key in descriptor_by_batch_kind:
                raise MirrorServiceError("mirror_batch_descriptor_duplicate")
            descriptor_by_batch_kind[key] = entry
        elif descriptor.kind == "pool_manifest":
            pool_descriptors.append((descriptor.publisher_hotkey or "", entry))

    batch_publishers = _verify_certified_graph(
        policy=policy,
        release=release,
        index=index,
        pool_descriptors=pool_descriptors,
        descriptor_by_batch_kind=descriptor_by_batch_kind,
        objects=objects,
        videos=videos,
    )
    _verify_exact_tree(root, tree_snapshot, release, index, policy)
    index_entry = _TreeEntry(
        relative_path=expected_index_relative,
        path=index_path,
        sha256=release.mirror_index_sha256,
        size_bytes=release.mirror_index_size_bytes,
        media_type="application/json",
        identity=index_identity,
    )
    static_entries = _build_static_entries(
        root=root,
        snapshot=tree_snapshot,
        index_entry=index_entry,
        objects=objects,
        policy=policy,
    )
    loaded = _LoadedService(
        config_path=path,
        config_bytes=config_bytes,
        config_identity=config_identity,
        config=config,
        policy_path=policy_path,
        policy_bytes=policy_bytes,
        policy_identity=policy_identity,
        policy=policy,
        discovery_path=discovery_path,
        discovery_bytes=discovery_bytes,
        discovery_identity=discovery_identity,
        discovery=discovery,
        tree_root=root,
        tree_snapshot=tree_snapshot,
        release=release,
        release_bytes=release_bytes,
        index=index,
        index_bytes=index_bytes,
        index_entry=index_entry,
        objects=objects,
        videos=videos,
        batch_publishers=batch_publishers,
        static_entries=static_entries,
    )
    return loaded


def check_mirror_service(config_path: str | Path) -> MirrorServiceCheckResult:
    """Validate one exact service definition without network or filesystem writes."""

    loaded = _load_mirror_service_definition(config_path)
    return MirrorServiceCheckResult(
        scoring_policy_sha256=scoring_policy_hash(loaded.policy),
        discovery_rule_sha256=hashlib.sha256(loaded.discovery_bytes).hexdigest(),
        certified_release_sha256=hashlib.sha256(loaded.release_bytes).hexdigest(),
        anchor_intents_sha256=loaded.release.anchor_intents_sha256,
        mirror_index_sha256=hashlib.sha256(loaded.index_bytes).hexdigest(),
        window_id=loaded.release.window.window_id,
        window_index=loaded.release.window.window_index,
        retrieval_origin=loaded.config.retrieval_origin,
        delivery_origin=loaded.config.delivery_origin,
        credential_validator_hotkeys=tuple(
            item.validator_hotkey for item in loaded.config.validator_credentials
        ),
    )


def load_mirror_service(
    config_path: str | Path,
    *,
    clock: Callable[[], int] | None = None,
) -> MirrorServiceRuntime:
    try:
        return MirrorServiceRuntime(
            _load_mirror_service_definition(config_path),
            clock=clock,
        )
    except MirrorServiceError:
        raise
    except Exception:
        raise MirrorServiceError("mirror_service_startup_failed") from None


def create_app(
    config_path: str | Path,
    *,
    clock: Callable[[], int] | None = None,
) -> FastAPI:
    runtime = load_mirror_service(config_path, clock=clock)
    app = FastAPI(
        title="UMI reference mirror",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
    )
    app.state.runtime = runtime

    @app.middleware("http")
    async def enforce_boundary(request: Request, call_next):
        try:
            _validate_http_boundary(request, runtime.loaded.policy)
            return await call_next(request)
        except MirrorServiceError as error:
            return _error_response(error)
        except Exception:
            return _error_response(MirrorServiceError("mirror_internal_failure", 500))

    async def serve_index(request: Request) -> Response:
        runtime.require_route_origin(request, public_delivery=False)
        runtime.require_authentication(request)
        runtime.assert_immutable()
        runtime.state.audit()
        runtime.state.observe_clock(runtime.now_ms())
        return _exact_response(
            runtime.read_entry(runtime.loaded.index_entry),
            media_type="application/json",
            public=False,
        )

    async def serve_object(digest: str, request: Request) -> Response:
        runtime.require_route_origin(request, public_delivery=False)
        runtime.require_authentication(request)
        if _HEX32_RE.fullmatch(digest) is None:
            raise MirrorServiceError("mirror_object_not_found", 404)
        entry = runtime.loaded.objects.get(digest)
        if entry is None:
            raise MirrorServiceError("mirror_object_not_found", 404)
        runtime.assert_immutable()
        runtime.state.audit()
        runtime.state.observe_clock(runtime.now_ms())
        return _exact_response(
            runtime.read_entry(entry),
            media_type=entry.media_type,
            public=False,
        )

    async def issue_deliveries(request: Request) -> Response:
        runtime.require_route_origin(request, public_delivery=False)
        validator_hotkey = runtime.require_authentication(request)
        body = await _read_request_body(request, runtime.loaded.policy)
        runtime.assert_immutable()
        runtime.state.audit()
        return _exact_response(
            runtime.issue(body, validator_hotkey=validator_hotkey),
            media_type="application/json",
            public=False,
        )

    async def serve_delivery(token: str, request: Request) -> Response:
        runtime.require_route_origin(request, public_delivery=True)
        if _TOKEN_RE.fullmatch(token) is None:
            raise MirrorServiceError("mirror_delivery_not_found", 404)
        try:
            if len(base64url_decode(token)) != 24:
                raise ValueError
        except (TypeError, ValueError):
            raise MirrorServiceError("mirror_delivery_not_found", 404) from None
        now_ms = runtime.now_ms()
        entry = runtime.state.lookup_delivery(token, now_ms=now_ms)
        runtime.assert_immutable()
        return _exact_response(
            runtime.read_entry(entry),
            media_type="video/mp4",
            public=True,
        )

    async def serve_static(relative_path: str, request: Request) -> Response:
        runtime.require_route_origin(request, public_delivery=False)
        runtime.require_authentication(request)
        entry = runtime.loaded.static_entries.get(relative_path)
        if entry is None:
            raise MirrorServiceError("mirror_static_object_not_found", 404)
        runtime.assert_immutable()
        runtime.state.audit()
        runtime.state.observe_clock(runtime.now_ms())
        return _exact_response(
            runtime.read_entry(entry),
            media_type=entry.media_type,
            public=False,
        )

    index_path = runtime.loaded.release.mirror_index_path.format(
        window_id=runtime.loaded.release.window.window_id
    )
    app.add_api_route(index_path, serve_index, methods=["GET"])
    app.add_api_route("/v1/umi/objects/{digest}", serve_object, methods=["GET"])
    app.add_api_route(DEFAULT_DELIVERY_ISSUANCE_PATH, issue_deliveries, methods=["POST"])
    app.add_api_route(
        DEFAULT_DELIVERY_OBJECT_PATH_PREFIX + "{token}",
        serve_delivery,
        methods=["GET"],
    )
    app.add_api_route("/{relative_path:path}", serve_static, methods=["GET"])
    return app


def create_app_from_env() -> FastAPI:
    value = os.environ.get(MIRROR_SERVICE_CONFIG_ENV)
    if value is None:
        raise RuntimeError(f"{MIRROR_SERVICE_CONFIG_ENV} is required")
    return create_app(value)


def _verify_certified_graph(
    *,
    policy: ScoringPolicy,
    release: CertifiedPoolRelease,
    index: MirrorWindowIndex,
    pool_descriptors: Sequence[tuple[str, _TreeEntry]],
    descriptor_by_batch_kind: Mapping[tuple[str, str], _TreeEntry],
    objects: Mapping[str, _TreeEntry],
    videos: Mapping[tuple[str, str], _TreeEntry],
) -> dict[str, str]:
    release_pools = [
        (item.publisher_hotkey, item.sha256, item.size_bytes) for item in release.pool_manifests
    ]
    index_pools = [
        (publisher, entry.sha256, entry.size_bytes) for publisher, entry in pool_descriptors
    ]
    if release_pools != index_pools:
        raise MirrorServiceError("mirror_release_pool_set_mismatch")
    active_validators = tuple(item.validator_hotkey for item in policy.validator_registry)
    registered_publishers = {
        account_id32(item.publisher_hotkey) for item in policy.publisher_registry
    }
    certificates: set[bytes] = set()
    batch_entries: dict[str, tuple[object, str]] = {}
    for publisher, entry in pool_descriptors:
        raw = _read_entry_at_start(entry)
        try:
            manifest = parse_pool_manifest_bytes(raw, policy=policy)
            if account_id32(publisher) not in registered_publishers:
                raise ValueError("publisher is not policy registered")
            if account_id32(manifest.publisher_hotkey) != account_id32(publisher):
                raise ValueError("publisher mismatch")
            verify_availability_certificate_member(
                manifest.availability_certificate,
                manifest.body(),
                active_validator_hotkeys=active_validators,
                policy=policy,
            )
        except (TypeError, ValueError) as error:
            raise MirrorServiceError("mirror_pool_manifest_invalid") from error
        certificates.add(canonical_json_bytes(manifest.availability_certificate))
        for item in manifest.batches:
            if item.batch_id in batch_entries:
                raise MirrorServiceError("mirror_batch_duplicate")
            batch_entries[item.batch_id] = (item, publisher)
    if len(certificates) != 1:
        raise MirrorServiceError("mirror_certificate_set_mismatch")
    publisher_groups = {
        account_id32(item.publisher_hotkey): item.control_group_id
        for item in policy.publisher_registry
    }
    candidate_groups = [
        publisher_groups[account_id32(publisher)]
        for _batch_id, (_entry, publisher) in batch_entries.items()
    ]
    candidate_publishers = [account_id32(publisher) for _entry, publisher in batch_entries.values()]
    if (
        len(pool_descriptors) > policy.limits.max_active_publishers
        or len(set(candidate_groups)) > policy.limits.max_active_control_groups
        or len(batch_entries) > policy.limits.max_candidate_batches_total
        or any(
            count > policy.limits.max_candidate_batches_per_publisher
            for count in Counter(candidate_publishers).values()
        )
        or any(
            count > policy.limits.max_candidate_batches_per_group
            for count in Counter(candidate_groups).values()
        )
    ):
        raise MirrorServiceError("mirror_candidate_pool_limit")
    certificate_bytes = next(iter(certificates))
    certificate = next(
        parse_pool_manifest_bytes(
            _read_entry_at_start(entry), policy=policy
        ).availability_certificate
        for _publisher, entry in pool_descriptors
    )
    if (
        hashlib.sha256(certificate_bytes).hexdigest() != release.availability_certificate_sha256
        or certificate.availability_set_root != release.availability_set_root
        or certificate.qualified_pool_leaves != release.qualified_pool_leaves
    ):
        raise MirrorServiceError("mirror_release_certificate_mismatch")
    expected_video_keys: set[tuple[str, str]] = set()
    expected_video_hashes: set[str] = set()
    expected_frame_hashes: set[str] = set()
    batch_publishers: dict[str, str] = {}
    for batch_id, (pool_entry, publisher) in batch_entries.items():
        batch_publishers[batch_id] = publisher
        public_entry = descriptor_by_batch_kind.get((batch_id, "public_manifest"))
        envelope_entry = descriptor_by_batch_kind.get((batch_id, "ground_truth_envelope"))
        if public_entry is None or envelope_entry is None:
            raise MirrorServiceError("mirror_batch_artifact_missing")
        public_bytes = _read_entry_at_start(public_entry)
        envelope_bytes = _read_entry_at_start(envelope_entry)
        try:
            public = PublicBatchManifest.model_validate_json(public_bytes)
            if canonical_json_bytes(public) != public_bytes:
                raise ValueError("public manifest is noncanonical")
            validate_public_batch_manifest(public, policy)
        except (TypeError, ValueError) as error:
            raise MirrorServiceError("mirror_public_manifest_invalid") from error
        if (
            public.batch_id != batch_id
            or account_id32(public.publisher_hotkey) != account_id32(publisher)
            or public.window_id != release.window.window_id
            or public.scoring_policy_hash != release.window.scoring_policy_hash
            or public.response_close_round != release.window.response_close_round
            or public.reveal_round != release.window.reveal_round
            or public.ciphertext_sha256 != envelope_entry.sha256
            or pool_entry.public_manifest_sha256 != public_entry.sha256
            or pool_entry.ciphertext_sha256 != envelope_entry.sha256
            or pool_entry.reveal_round != public.reveal_round
            or pool_entry.batch_commitment
            != batch_commitment(public, envelope_bytes, public.reveal_round)
        ):
            raise MirrorServiceError("mirror_batch_artifact_binding_mismatch")
        for item in public.items:
            key = (batch_id, item.challenge_id)
            expected_video_keys.add(key)
            if (
                item.media.sha256 in expected_video_hashes
                or item.media.frame_digest in expected_frame_hashes
            ):
                raise MirrorServiceError("mirror_public_video_duplicate")
            expected_video_hashes.add(item.media.sha256)
            expected_frame_hashes.add(item.media.frame_digest)
            object_entry = videos.get(key)
            if (
                object_entry is None
                or object_entry.media_type != "video/mp4"
                or object_entry.sha256 != item.media.sha256
                or object_entry.size_bytes != item.media.size_bytes
            ):
                raise MirrorServiceError("mirror_public_video_missing")
    if set(videos) != expected_video_keys:
        raise MirrorServiceError("mirror_video_descriptor_set_mismatch")
    if set(descriptor_by_batch_kind) != {
        *((batch_id, "public_manifest") for batch_id in batch_entries),
        *((batch_id, "ground_truth_envelope") for batch_id in batch_entries),
    }:
        raise MirrorServiceError("mirror_batch_descriptor_set_mismatch")
    return batch_publishers


def _verify_exact_tree(
    root: Path,
    snapshot: Mapping[str, _FileIdentity],
    release: CertifiedPoolRelease,
    index: MirrorWindowIndex,
    policy: ScoringPolicy,
) -> None:
    expected = {
        CERTIFIED_RELEASE_FILENAME,
        ANCHOR_INTENTS_FILENAME,
        release.mirror_index_path.format(window_id=release.window.window_id).removeprefix("/"),
        *(f"v1/umi/objects/{item.sha256}" for item in index.objects),
        *(
            f"{QUALIFICATION_RECEIPTS_DIRECTORY}/{digest}.json"
            for digest in release.signer_receipt_sha256s
        ),
    }
    if set(snapshot) != expected:
        raise MirrorServiceError("mirror_certified_tree_file_set_mismatch")
    anchor_bytes, _identity = _read_owned_file(
        root / ANCHOR_INTENTS_FILENAME,
        maximum_bytes=MAX_CERTIFIED_RELEASE_BYTES,
        private=False,
    )
    if hashlib.sha256(anchor_bytes).hexdigest() != release.anchor_intents_sha256:
        raise MirrorServiceError("mirror_anchor_intents_digest_mismatch")
    try:
        raw_intents = json.loads(anchor_bytes)
        intents = tuple(PoolAnchorIntent.model_validate(item) for item in raw_intents)
    except Exception as error:
        raise MirrorServiceError("mirror_anchor_intents_invalid") from error
    if (
        canonical_json_bytes([item.model_dump(mode="json", by_alias=True) for item in intents])
        != anchor_bytes
    ):
        raise MirrorServiceError("mirror_anchor_intents_noncanonical")
    if any(
        item.broadcast_authorized
        or item.translation_weights_active
        or item.weight_submission_capability
        for item in intents
    ):
        raise MirrorServiceError("mirror_anchor_intents_unsafe")
    released_by_publisher = {
        account_id32(item.publisher_hotkey): item for item in release.pool_manifests
    }
    if len(intents) != len(released_by_publisher) or any(
        account_id32(intent.publisher_hotkey) not in released_by_publisher
        or intent.netuid != policy.netuid
        or intent.window_id != release.window.window_id
        or intent.closing_block != release.window.closing_block
        or intent.pool_manifest_sha256
        != released_by_publisher[account_id32(intent.publisher_hotkey)].sha256
        for intent in intents
    ):
        raise MirrorServiceError("mirror_anchor_intents_binding_mismatch")
    receipt_signers: set[bytes] = set()
    receipt_context: tuple[object, ...] | None = None
    registered_validators = {
        account_id32(item.validator_hotkey) for item in policy.validator_registry
    }
    for digest in release.signer_receipt_sha256s:
        receipt_path = root / QUALIFICATION_RECEIPTS_DIRECTORY / f"{digest}.json"
        receipt, _identity = _read_owned_file(
            receipt_path,
            maximum_bytes=MAX_CERTIFIED_RELEASE_BYTES,
            private=False,
        )
        if hashlib.sha256(receipt).hexdigest() != digest:
            raise MirrorServiceError("mirror_qualification_receipt_digest_mismatch")
        try:
            parsed = parse_qualification_receipt_bytes(receipt)
        except (TypeError, ValueError, RuntimeError) as error:
            raise MirrorServiceError("mirror_qualification_receipt_invalid") from error
        signer = account_id32(parsed.validator_hotkey)
        current_context: tuple[object, ...] = (
            tuple(parsed.active_validator_hotkeys),
            parsed.announcement_block_hash,
            parsed.announcement_timestamp_ms,
            parsed.announcement_finality_evidence_sha256,
            parsed.active_validator_set_evidence_sha256,
            parsed.announcement_validator_proof_evidence_sha256,
            parsed.protocol_state_continuity_evidence_sha256,
            parsed.spent_registry_root,
            parsed.spent_registry_evidence_sha256,
            parsed.spent_leaf_set_sha256,
        )
        if (
            signer in receipt_signers
            or parsed.window_id != release.window.window_id
            or parsed.window_index != release.window.window_index
            or parsed.scoring_policy_hash != release.window.scoring_policy_hash
            or parsed.candidate_set_sha256 != release.candidate_set_sha256
            or parsed.availability_set_root != release.availability_set_root
            or parsed.qualified_pool_leaves != release.qualified_pool_leaves
            or parsed.translation_weights_active is not False
            or parsed.weight_submission_capability is not False
            or parsed.mirror_retention_required_through_round < release.window.reveal_round
            or not (
                release.window.announcement_block
                <= parsed.qualified_at_finalized_block
                < release.window.proposal_close_block
            )
            or len(parsed.active_validator_hotkeys) < 4
            or {account_id32(value) for value in parsed.active_validator_hotkeys}
            - registered_validators
            or (receipt_context is not None and current_context != receipt_context)
            or not verify_response_signature(
                availability_digest(parsed.window_id, parsed.availability_set_root),
                hotkey_ss58=parsed.validator_hotkey,
                scheme=parsed.scheme,
                signature=parsed.signature,
            )
            or not verify_response_signature(
                qualification_receipt_digest(parsed),
                hotkey_ss58=parsed.validator_hotkey,
                scheme=parsed.scheme,
                signature=parsed.receipt_signature,
            )
        ):
            raise MirrorServiceError("mirror_qualification_receipt_binding_mismatch")
        receipt_signers.add(signer)
        receipt_context = current_context
    if receipt_signers != {
        account_id32(item.validator_hotkey)
        for item in next(
            parse_pool_manifest_bytes(
                _read_owned_file(
                    root / descriptor.path.removeprefix("/"),
                    maximum_bytes=policy.limits.maximum_manifest_bytes,
                    private=False,
                )[0],
                policy=policy,
            )
            for descriptor in index.objects
            if descriptor.kind == "pool_manifest"
        ).availability_certificate.signatures
    }:
        raise MirrorServiceError("mirror_qualification_receipt_signer_set_mismatch")


def _build_static_entries(
    *,
    root: Path,
    snapshot: Mapping[str, _FileIdentity],
    index_entry: _TreeEntry,
    objects: Mapping[str, _TreeEntry],
    policy: ScoringPolicy,
) -> dict[str, _TreeEntry]:
    by_path = {item.relative_path: item for item in objects.values()}
    by_path[index_entry.relative_path] = index_entry
    result: dict[str, _TreeEntry] = {}
    for relative_path, expected_identity in snapshot.items():
        known = by_path.get(relative_path)
        if known is not None:
            result[relative_path] = known
            continue
        path = root / relative_path
        data, identity = _read_owned_file(
            path,
            maximum_bytes=max(
                MAX_CERTIFIED_RELEASE_BYTES,
                policy.limits.maximum_manifest_bytes,
            ),
            private=False,
        )
        if identity != expected_identity:
            raise MirrorServiceError("mirror_certified_tree_changed")
        result[relative_path] = _TreeEntry(
            relative_path=relative_path,
            path=path,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            media_type="application/json",
            identity=identity,
        )
    return result


def _object_ceiling(policy: ScoringPolicy, media_type: str) -> int:
    if media_type == "video/mp4":
        return policy.limits.maximum_clip_size_bytes
    if media_type == "application/octet-stream":
        return policy.limits.maximum_ground_truth_envelope_bytes
    return policy.limits.maximum_manifest_bytes


def _round_time_ms(round_number: int) -> int:
    return QUICKNET_GENESIS_MS + (round_number - 1) * QUICKNET_PERIOD_MS


def _origin_authority(origin: str) -> bytes:
    parsed = urlsplit(origin)
    hostname = parsed.hostname
    if hostname is None:
        raise MirrorServiceError("mirror_origin_invalid")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        authority += f":{parsed.port}"
    return authority.encode("ascii")


def _validate_public_origin_name(origin: str) -> None:
    hostname = urlsplit(origin).hostname
    if hostname is None:
        raise ValueError("mirror origin has no hostname")
    hostname = hostname.lower().rstrip(".")
    if hostname == "localhost" or hostname.endswith((".localhost", ".local")):
        raise ValueError("mirror origin cannot name a local host")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("mirror origin IP must be globally routable")


def _read_entry_at_start(entry: _TreeEntry) -> bytes:
    data, identity = _read_owned_file(
        entry.path,
        maximum_bytes=entry.size_bytes,
        private=False,
    )
    if identity != entry.identity or hashlib.sha256(data).hexdigest() != entry.sha256:
        raise MirrorServiceError("mirror_certified_object_changed")
    return data


async def _read_request_body(request: Request, policy: ScoringPolicy) -> bytes:
    headers = request.scope["headers"]
    content_types = [value for name, value in headers if name.lower() == b"content-type"]
    encodings = [value for name, value in headers if name.lower() == b"content-encoding"]
    lengths = [value for name, value in headers if name.lower() == b"content-length"]
    if (
        len(content_types) != 1
        or content_types[0].split(b";", 1)[0].strip().lower() != b"application/json"
    ):
        raise MirrorServiceError("mirror_request_content_type_invalid", 415)
    if len(encodings) > 1 or (encodings and encodings[0].strip().lower() not in {b"", b"identity"}):
        raise MirrorServiceError("mirror_request_content_encoding_invalid", 415)
    maximum = policy.limits.maximum_request_body_bytes
    declared: int | None = None
    if lengths:
        if len(lengths) != 1 or _CONTENT_LENGTH_RE.fullmatch(lengths[0]) is None:
            raise MirrorServiceError("mirror_request_content_length_invalid", 400)
        declared = int(lengths[0])
        if declared <= 0 or declared > maximum:
            raise MirrorServiceError("mirror_request_body_size_limit", 413)
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > maximum:
                raise MirrorServiceError("mirror_request_body_size_limit", 413)
            body.extend(chunk)
    except ClientDisconnect as error:
        raise MirrorServiceError("mirror_request_disconnected", 400) from error
    if not body or (declared is not None and len(body) != declared):
        raise MirrorServiceError("mirror_request_content_length_invalid", 400)
    return bytes(body)


def _validate_http_boundary(request: Request, policy: ScoringPolicy) -> None:
    raw_path = request.scope.get("raw_path") or request.scope["path"].encode("ascii", "strict")
    query = request.scope.get("query_string", b"")
    if (
        not isinstance(raw_path, bytes)
        or len(raw_path) > 8_192
        or _SAFE_PATH_RE.fullmatch(raw_path) is None
        or b"%" in raw_path
        or b"\\" in raw_path
        or b"//" in raw_path
        or any(part in {b".", b".."} for part in raw_path.split(b"/"))
        or query
    ):
        raise MirrorServiceError("mirror_http_target_invalid", 400)
    header_bytes = sum(len(name) + len(value) + 4 for name, value in request.scope["headers"])
    if header_bytes > policy.limits.maximum_http_header_bytes:
        raise MirrorServiceError("mirror_http_header_size_limit", 431)


def _exact_response(data: bytes, *, media_type: str, public: bool) -> Response:
    headers = {
        "Content-Length": str(len(data)),
        "Content-Type": media_type,
        "Content-Encoding": "identity",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store, max-age=0" if public else "no-store",
    }
    return Response(content=data, status_code=200, headers=headers)


def _error_response(error: MirrorServiceError) -> Response:
    body = canonical_json_bytes({"reason_code": error.reason_code})
    headers = {
        "Content-Length": str(len(body)),
        "Content-Type": "application/json",
        "Content-Encoding": "identity",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if error.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return Response(content=body, status_code=error.status_code, headers=headers)


def _read_owned_file(
    path: Path,
    *,
    maximum_bytes: int,
    private: bool,
) -> tuple[bytes, _FileIdentity]:
    if not path.is_absolute() or str(path) != str(Path(str(path))):
        raise MirrorServiceError("mirror_file_path_invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MirrorServiceError("mirror_file_open_failed") from error
    try:
        before = os.fstat(descriptor)
        _validate_file_stat(before, private=private)
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            raise MirrorServiceError("mirror_file_size_limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise MirrorServiceError("mirror_file_short_read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise MirrorServiceError("mirror_file_grew_during_read")
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise MirrorServiceError("mirror_file_changed_during_read")
        try:
            named = path.lstat()
        except OSError as error:
            raise MirrorServiceError("mirror_file_path_changed") from error
        if named.st_dev != after.st_dev or named.st_ino != after.st_ino:
            raise MirrorServiceError("mirror_file_path_changed")
        return b"".join(chunks), _file_identity(after)
    finally:
        os.close(descriptor)


def _assert_file_unchanged(
    path: Path,
    identity: _FileIdentity,
    data: bytes,
    *,
    maximum_bytes: int,
    private: bool = False,
) -> None:
    current, current_identity = _read_owned_file(
        path,
        maximum_bytes=maximum_bytes,
        private=private,
    )
    if current_identity != identity or not hmac.compare_digest(
        hashlib.sha256(current).digest(), hashlib.sha256(data).digest()
    ):
        raise MirrorServiceError("mirror_configuration_changed")


def _validate_file_stat(value: os.stat_result, *, private: bool) -> None:
    forbidden = 0o077 if private else 0o022
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) & forbidden
    ):
        raise MirrorServiceError("mirror_file_ownership_or_mode_invalid")


def _file_identity(value: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        mode=stat.S_IMODE(value.st_mode),
        uid=value.st_uid,
        links=value.st_nlink,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _snapshot_tree(root: Path) -> dict[str, _FileIdentity]:
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise MirrorServiceError("mirror_certified_tree_missing") from error
    _validate_directory_stat(root_stat, private=True)
    files: dict[str, _FileIdentity] = {}
    for directories, (current, directory_names, file_names) in enumerate(
        os.walk(root, topdown=True, followlinks=False),
        start=1,
    ):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        _validate_directory_stat(current_path.lstat(), private=True)
        if directories + len(files) > MAX_TREE_FILES:
            raise MirrorServiceError("mirror_certified_tree_entry_limit")
        for name in directory_names:
            child = current_path / name
            _validate_directory_stat(child.lstat(), private=True)
        for name in file_names:
            child = current_path / name
            info = child.lstat()
            _validate_file_stat(info, private=False)
            relative = child.relative_to(root).as_posix()
            if PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
                raise MirrorServiceError("mirror_certified_tree_path_invalid")
            files[relative] = _file_identity(info)
            if directories + len(files) > MAX_TREE_FILES:
                raise MirrorServiceError("mirror_certified_tree_entry_limit")
    return files


def _validate_directory_stat(value: os.stat_result, *, private: bool) -> None:
    forbidden = 0o077 if private else 0o022
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) & forbidden
    ):
        raise MirrorServiceError("mirror_directory_ownership_or_mode_invalid")


def _prepare_private_state_path(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise MirrorServiceError("mirror_state_path_invalid")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _validate_directory_stat(parent.lstat(), private=True)
    _reject_state_links(path)


def _reject_state_links(path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(f"{path}{suffix}")
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise MirrorServiceError("mirror_state_path_unsafe")


def _secure_state_files(path: Path) -> None:
    _reject_state_links(path)
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(f"{path}{suffix}")
        if candidate.exists():
            os.chmod(candidate, 0o600, follow_symlinks=False)
    _reject_state_links(path)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MirrorServiceError("mirror_state_directory_sync_failed") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise MirrorServiceError("mirror_state_directory_sync_failed") from error
    finally:
        os.close(descriptor)


def _write_stdout(value: Mapping[str, object]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(dict(value)) + b"\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the UMI reference mirror service")
    parser.add_argument("--config", required=True, help="owner-private canonical service config")
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate config and certified tree without network or filesystem writes",
    )
    args = parser.parse_args(argv)
    try:
        loaded = _load_mirror_service_definition(Path(args.config))
    except MirrorServiceError as error:
        _write_stdout(
            {
                "reason_code": error.reason_code,
                "status": "blocked",
                "translation_weights_active": False,
                "weight_submission_capability": False,
            }
        )
        return 2
    except Exception:
        _write_stdout(
            {
                "reason_code": "mirror_service_startup_failed",
                "status": "blocked",
                "translation_weights_active": False,
                "weight_submission_capability": False,
            }
        )
        return 2
    if args.check:
        _write_stdout(
            {
                "certified_release_sha256": hashlib.sha256(loaded.release_bytes).hexdigest(),
                "mirror_index_sha256": hashlib.sha256(loaded.index_bytes).hexdigest(),
                "status": "ready",
                "translation_weights_active": False,
                "weight_submission_capability": False,
            }
        )
        return 0
    try:
        runtime = MirrorServiceRuntime(loaded)
    except MirrorServiceError as error:
        _write_stdout(
            {
                "reason_code": error.reason_code,
                "status": "blocked",
                "translation_weights_active": False,
                "weight_submission_capability": False,
            }
        )
        return 2
    except Exception:
        _write_stdout(
            {
                "reason_code": "mirror_service_startup_failed",
                "status": "blocked",
                "translation_weights_active": False,
                "weight_submission_capability": False,
            }
        )
        return 2
    os.environ[MIRROR_SERVICE_CONFIG_ENV] = str(Path(args.config))
    uvicorn.run(
        "umi.mirror_service:create_app_from_env",
        factory=True,
        host=runtime.loaded.config.listen_host,
        port=runtime.loaded.config.listen_port,
        workers=runtime.loaded.config.workers,
        access_log=False,
        proxy_headers=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "MIRROR_SERVICE_CONFIG_SCHEMA",
    "MIRROR_SERVICE_MODE",
    "MirrorServiceConfig",
    "MirrorServiceError",
    "MirrorServiceRuntime",
    "create_app",
    "create_app_from_env",
    "load_mirror_service",
    "main",
]
