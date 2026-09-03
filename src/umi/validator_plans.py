"""Deterministic, evidence-bound selection-window plan production.

This module does not verify GRANDPA finality, query a node, or decide whether a
header is finalized.  ``VerifiedFinalizedAnnouncementPort`` is a narrow trust
boundary: its implementation must do that work before returning the typed record.
The source validates policy bindings, durably records the exact supplied evidence,
and deterministically applies ``WindowClock``.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import sqlite3
import stat
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import Field

from .policy import (
    LiveChainObservationPin,
    ScoringPolicy,
    require_live_chain_observation,
    scoring_policy_hash,
)
from .protocol import StrictProtocolModel, canonical_json_bytes
from .validator_state import ValidatorControlPlane, WindowPlan, WindowRecord
from .window import QUICKNET_GENESIS_MS, WindowClock

OBSERVATION_SCHEMA = "umi-verified-announcement-observation/1"
OBSERVATION_CACHE_SCHEMA_VERSION = 1
MAX_FINALITY_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_CHECKPOINT_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_OBSERVATION_DOCUMENT_BYTES = 64 * 1024
MAX_OBSERVATIONS = 4_096
MAX_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_CACHE_DATABASE_BYTES = 128 * 1024 * 1024
_MAX_CANONICAL_INTEGER = (1 << 53) - 1
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")


class ValidatorPlanError(RuntimeError):
    """Base class for stable deterministic-plan failures."""


class PlanPolicyError(ValidatorPlanError):
    """The policy or a chain observation does not match the configured pins."""


class PlanStateError(ValidatorPlanError):
    """Persistent validator history cannot safely produce another plan."""


class VerifiedBlockPortError(ValidatorPlanError):
    """The already-verified finalized-block port violated its contract."""


class ReadinessPortError(ValidatorPlanError):
    """The prior-window checkpoint port violated its contract."""


class ObservationCacheError(ValidatorPlanError):
    """The bounded observation cache is unsafe, corrupt, or inconsistent."""


class ObservationConflict(ObservationCacheError):
    """An already observed announcement height was supplied with different bytes."""


@dataclass(frozen=True, slots=True)
class ObservationCacheLimits:
    maximum_observations: int = MAX_OBSERVATIONS
    maximum_evidence_bytes: int = MAX_FINALITY_EVIDENCE_BYTES
    maximum_total_evidence_bytes: int = MAX_TOTAL_EVIDENCE_BYTES
    maximum_database_bytes: int = MAX_CACHE_DATABASE_BYTES

    def __post_init__(self) -> None:
        for name in (
            "maximum_observations",
            "maximum_evidence_bytes",
            "maximum_total_evidence_bytes",
            "maximum_database_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.maximum_evidence_bytes > self.maximum_total_evidence_bytes:
            raise ValueError("one evidence object cannot exceed the aggregate limit")
        if self.maximum_total_evidence_bytes > self.maximum_database_bytes:
            raise ValueError("evidence limit cannot exceed the database limit")


@dataclass(frozen=True, slots=True)
class VerifiedFinalizedBlock:
    """Exact announcement block already finalized and verified by the injected port."""

    height: int
    block_hash: str
    state_root: str
    timestamp_ms: int
    scoring_policy_hash: str
    chain_observation: LiveChainObservationPin
    finality_verifier_sha256: str
    finality_evidence: bytes
    finality_evidence_sha256: str

    def __post_init__(self) -> None:
        _uint(self.height, "finalized block height")
        _block_hash(self.block_hash, "finalized block hash")
        _block_hash(self.state_root, "finalized state root")
        _timestamp_ms(self.timestamp_ms)
        _hex32(self.scoring_policy_hash, "scoring policy hash")
        if not isinstance(self.chain_observation, LiveChainObservationPin):
            raise TypeError("chain observation must be a LiveChainObservationPin")
        _hex32(self.finality_verifier_sha256, "finality verifier digest")
        _evidence(
            self.finality_evidence,
            self.finality_evidence_sha256,
            maximum_bytes=MAX_FINALITY_EVIDENCE_BYTES,
            label="finality evidence",
        )


@dataclass(frozen=True, slots=True)
class VerifiedPriorWindowCheckpoint:
    """Already-verified proof that one terminal window revealed and advanced spent state."""

    window_id: str
    window_index: int
    reveal_round: int
    spent_root: str
    checkpoint_block_height: int
    checkpoint_block_hash: str
    checkpoint_state_root: str
    evidence: bytes
    evidence_sha256: str

    def __post_init__(self) -> None:
        _hex32(self.window_id, "checkpoint window ID")
        _uint(self.window_index, "checkpoint window index")
        _uint(self.reveal_round, "checkpoint reveal round")
        _hex32(self.spent_root, "checkpoint spent root")
        _uint(self.checkpoint_block_height, "checkpoint block height")
        _block_hash(self.checkpoint_block_hash, "checkpoint block hash")
        _block_hash(self.checkpoint_state_root, "checkpoint state root")
        _evidence(
            self.evidence,
            self.evidence_sha256,
            maximum_bytes=MAX_CHECKPOINT_EVIDENCE_BYTES,
            label="checkpoint evidence",
        )


@runtime_checkable
class VerifiedFinalizedAnnouncementPort(Protocol):
    """Boundary that returns only blocks whose finality was already verified elsewhere."""

    async def finalized_head_height(self) -> int:
        """Return the height of the independently verified finalized head."""

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None:
        """Return the already-verified exact finalized block at ``height``."""


@runtime_checkable
class PriorWindowReadinessPort(Protocol):
    """Boundary for independently verified reveal and spent-registry completion."""

    async def verified_reveal_and_spent(
        self,
        previous: WindowRecord,
    ) -> VerifiedPriorWindowCheckpoint | None:
        """Return a bound checkpoint, or ``None`` while the transition is not ready."""


class _ObservationDocument(StrictProtocolModel):
    schema_: Literal[OBSERVATION_SCHEMA] = Field(alias="schema")
    window_index: Annotated[int, Field(ge=0, le=_MAX_CANONICAL_INTEGER)]
    announcement_height: Annotated[int, Field(ge=0, le=_MAX_CANONICAL_INTEGER)]
    block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    state_root: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    timestamp_ms: Annotated[int, Field(ge=QUICKNET_GENESIS_MS, le=_MAX_CANONICAL_INTEGER)]
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    chain_observation: LiveChainObservationPin
    finality_verifier_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    finality_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    finality_evidence_size_bytes: Annotated[int, Field(gt=0, le=MAX_FINALITY_EVIDENCE_BYTES)]


@dataclass(frozen=True, slots=True)
class _CachedObservation:
    document: _ObservationDocument
    block: VerifiedFinalizedBlock


class _ObservationCache:
    """Bounded, content-addressed SQLite cache with startup invariant auditing."""

    def __init__(
        self,
        path: str | Path,
        *,
        policy_hash: str,
        limits: ObservationCacheLimits,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self.path = Path(path)
        self.policy_hash = _hex32(policy_hash, "cache policy hash")
        if not isinstance(limits, ObservationCacheLimits):
            raise TypeError("cache limits must be ObservationCacheLimits")
        self.limits = limits
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= 60_000
        ):
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        self._busy_timeout_ms = busy_timeout_ms
        self._prepare_path()
        self._initialize()
        self._bind_policy()
        self.audit()

    def observe_head(self, height: int) -> None:
        height = _uint(height, "finalized head height")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT value FROM cache_meta WHERE key = 'highest_finalized_head'"
            ).fetchone()
            if row is not None and height < int(row["value"]):
                raise ObservationConflict("verified finalized head regressed")
            connection.execute(
                """
                INSERT INTO cache_meta (key, value)
                VALUES ('highest_finalized_head', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(height),),
            )

    def observe(self, index: int, block: VerifiedFinalizedBlock) -> _CachedObservation:
        index = _uint(index, "window index")
        if not isinstance(block, VerifiedFinalizedBlock):
            raise TypeError("block must be a VerifiedFinalizedBlock")
        if len(block.finality_evidence) > self.limits.maximum_evidence_bytes:
            raise ObservationCacheError("finality evidence exceeds the configured cache limit")
        document = _observation_document(index, block)
        encoded = canonical_json_bytes(document)
        if len(encoded) > MAX_OBSERVATION_DOCUMENT_BYTES:
            raise ObservationCacheError("announcement observation document is oversized")
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM observations WHERE window_index = ?",
                (index,),
            ).fetchone()
            if existing is not None:
                cached = self._load_row(connection, existing)
                if canonical_json_bytes(cached.document) != encoded or (
                    cached.block.finality_evidence != block.finality_evidence
                ):
                    raise ObservationConflict(
                        "an observed announcement block or its evidence changed"
                    )
                return cached

            count = int(connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0])
            if count != index:
                raise ObservationCacheError("announcement observations cannot skip an index")
            if count >= self.limits.maximum_observations:
                raise ObservationCacheError("announcement observation count limit reached")
            prior = connection.execute(
                "SELECT timestamp_ms FROM observations ORDER BY window_index DESC LIMIT 1"
            ).fetchone()
            if prior is not None and block.timestamp_ms <= int(prior["timestamp_ms"]):
                raise ObservationConflict("announcement timestamps are not strictly increasing")

            object_row = connection.execute(
                "SELECT size_bytes, data FROM evidence_objects WHERE sha256 = ?",
                (block.finality_evidence_sha256,),
            ).fetchone()
            if object_row is not None:
                if (
                    int(object_row["size_bytes"]) != len(block.finality_evidence)
                    or bytes(object_row["data"]) != block.finality_evidence
                ):
                    raise ObservationConflict("content-addressed finality evidence changed")
            else:
                total = int(
                    connection.execute(
                        "SELECT COALESCE(SUM(size_bytes), 0) FROM evidence_objects"
                    ).fetchone()[0]
                )
                if total + len(block.finality_evidence) > (
                    self.limits.maximum_total_evidence_bytes
                ):
                    raise ObservationCacheError("aggregate finality-evidence limit reached")
                connection.execute(
                    "INSERT INTO evidence_objects (sha256, size_bytes, data) VALUES (?, ?, ?)",
                    (
                        block.finality_evidence_sha256,
                        len(block.finality_evidence),
                        block.finality_evidence,
                    ),
                )
            connection.execute(
                """
                INSERT INTO observations (
                    window_index, announcement_height, block_hash, timestamp_ms,
                    document_json, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    index,
                    block.height,
                    block.block_hash,
                    block.timestamp_ms,
                    encoded.decode(),
                    block.finality_evidence_sha256,
                ),
            )
            row = connection.execute(
                "SELECT * FROM observations WHERE window_index = ?",
                (index,),
            ).fetchone()
            if row is None:
                raise ObservationCacheError("announcement observation insert disappeared")
            return self._load_row(connection, row)

    def load_all(self) -> tuple[_CachedObservation, ...]:
        with self._read() as connection:
            rows = connection.execute("SELECT * FROM observations ORDER BY window_index").fetchall()
            return tuple(self._load_row(connection, row) for row in rows)

    def audit(self) -> None:
        self._require_safe_paths()
        with self._read() as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                raise ObservationCacheError("announcement observation cache failed integrity check")
            schema_rows = connection.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            ).fetchall()
            schema_objects = {(str(row["type"]), str(row["name"])) for row in schema_rows}
            expected_schema = {
                ("table", "cache_meta"),
                ("table", "evidence_objects"),
                ("table", "observations"),
            }
            if schema_objects != expected_schema:
                raise ObservationCacheError("observation cache schema objects changed")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ObservationCacheError("observation cache has a foreign-key violation")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version != OBSERVATION_CACHE_SCHEMA_VERSION:
                raise ObservationCacheError("unsupported announcement observation cache schema")
            meta_rows = connection.execute(
                "SELECT key, value FROM cache_meta ORDER BY key"
            ).fetchall()
            meta = {str(row["key"]): str(row["value"]) for row in meta_rows}
            if set(meta) - {"policy_hash", "highest_finalized_head"}:
                raise ObservationCacheError("observation cache contains an unknown metadata key")
            if meta.get("policy_hash") != self.policy_hash:
                raise ObservationCacheError("observation cache policy binding changed")
            cached_head: int | None = None
            if "highest_finalized_head" in meta:
                try:
                    cached_head = _uint(
                        int(meta["highest_finalized_head"]),
                        "cached finalized head",
                    )
                except (TypeError, ValueError) as error:
                    raise ObservationCacheError("cached finalized head is invalid") from error
                if str(cached_head) != meta["highest_finalized_head"]:
                    raise ObservationCacheError("cached finalized head is not canonical")

            rows = connection.execute("SELECT * FROM observations ORDER BY window_index").fetchall()
            if len(rows) > self.limits.maximum_observations:
                raise ObservationCacheError("cached observation count exceeds its limit")
            cached = tuple(self._load_row(connection, row) for row in rows)
            if [item.document.window_index for item in cached] != list(range(len(cached))):
                raise ObservationCacheError("cached observation indices are not a complete prefix")
            timestamps = [item.document.timestamp_ms for item in cached]
            if any(left >= right for left, right in pairwise(timestamps)):
                raise ObservationCacheError("cached announcement timestamps do not increase")
            hashes = [item.document.block_hash for item in cached]
            if len(hashes) != len(set(hashes)):
                raise ObservationCacheError("cached announcement block hashes are not unique")
            if cached and cached_head is None:
                raise ObservationCacheError("cached observations have no finalized-head bound")
            if (
                cached
                and cached_head is not None
                and (cached_head < max(item.document.announcement_height for item in cached))
            ):
                raise ObservationCacheError("cached finalized head predates an observation")

            object_rows = connection.execute(
                "SELECT sha256, size_bytes, data FROM evidence_objects ORDER BY sha256"
            ).fetchall()
            total = 0
            for row in object_rows:
                digest = _hex32(row["sha256"], "cached evidence digest")
                data = bytes(row["data"])
                size = int(row["size_bytes"])
                if size != len(data) or hashlib.sha256(data).hexdigest() != digest:
                    raise ObservationCacheError("cached content-addressed evidence is corrupt")
                if size > self.limits.maximum_evidence_bytes:
                    raise ObservationCacheError("cached evidence exceeds its object limit")
                total += size
            if total > self.limits.maximum_total_evidence_bytes:
                raise ObservationCacheError("cached evidence exceeds its aggregate limit")
            referenced = {item.document.finality_evidence_sha256 for item in cached}
            stored = {str(row["sha256"]) for row in object_rows}
            if referenced != stored:
                raise ObservationCacheError("observation cache has missing or orphan evidence")
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            if page_size * page_count > self.limits.maximum_database_bytes:
                raise ObservationCacheError("observation cache exceeds its database byte limit")

    def _load_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> _CachedObservation:
        encoded = str(row["document_json"]).encode()
        if len(encoded) > MAX_OBSERVATION_DOCUMENT_BYTES:
            raise ObservationCacheError("cached observation document is oversized")
        try:
            document = _ObservationDocument.model_validate_json(encoded)
        except ValueError as error:
            raise ObservationCacheError("cached observation document is invalid") from error
        if canonical_json_bytes(document) != encoded:
            raise ObservationCacheError("cached observation document is not canonical")
        if (
            int(row["window_index"]) != document.window_index
            or int(row["announcement_height"]) != document.announcement_height
            or str(row["block_hash"]) != document.block_hash
            or int(row["timestamp_ms"]) != document.timestamp_ms
            or str(row["evidence_sha256"]) != document.finality_evidence_sha256
        ):
            raise ObservationCacheError("cached observation columns and document disagree")
        object_row = connection.execute(
            "SELECT size_bytes, data FROM evidence_objects WHERE sha256 = ?",
            (document.finality_evidence_sha256,),
        ).fetchone()
        if object_row is None:
            raise ObservationCacheError("cached observation lost its evidence object")
        evidence = bytes(object_row["data"])
        if int(object_row["size_bytes"]) != len(evidence):
            raise ObservationCacheError("cached evidence byte length changed")
        try:
            block = VerifiedFinalizedBlock(
                height=document.announcement_height,
                block_hash=document.block_hash,
                state_root=document.state_root,
                timestamp_ms=document.timestamp_ms,
                scoring_policy_hash=document.scoring_policy_hash,
                chain_observation=document.chain_observation,
                finality_verifier_sha256=document.finality_verifier_sha256,
                finality_evidence=evidence,
                finality_evidence_sha256=document.finality_evidence_sha256,
            )
        except (TypeError, ValueError) as error:
            raise ObservationCacheError("cached verified block is invalid") from error
        if document.finality_evidence_size_bytes != len(evidence):
            raise ObservationCacheError("cached observation evidence size disagrees")
        return _CachedObservation(document=document, block=block)

    def _prepare_path(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ObservationCacheError("observation-cache parent must be a real directory")
        self._require_safe_paths(allow_missing=True)
        if not self.path.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self.path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
                _fsync_directory(self.path.parent)
        self._require_safe_paths()

    def _require_safe_paths(self, *, allow_missing: bool = False) -> None:
        for path in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
            Path(f"{self.path}-journal"),
        ):
            if not os.path.lexists(path):
                if path == self.path and not allow_missing:
                    raise ObservationCacheError("observation-cache database is missing")
                continue
            if path.is_symlink():
                raise ObservationCacheError("observation-cache paths must not be symlinks")
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ObservationCacheError("observation-cache paths must be regular files")
            if metadata.st_mode & 0o022:
                raise ObservationCacheError("observation-cache paths are group/world writable")

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA page_size = 4096")
            max_pages = max(1, self.limits.maximum_database_bytes // 4096)
            connection.execute(f"PRAGMA max_page_count = {max_pages}")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, OBSERVATION_CACHE_SCHEMA_VERSION}:
                raise ObservationCacheError(f"unsupported observation-cache schema {version}")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cache_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS evidence_objects (
                    sha256 TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
                    data BLOB NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS observations (
                    window_index INTEGER PRIMARY KEY CHECK(window_index >= 0),
                    announcement_height INTEGER NOT NULL UNIQUE CHECK(announcement_height >= 0),
                    block_hash TEXT NOT NULL UNIQUE,
                    timestamp_ms INTEGER NOT NULL CHECK(timestamp_ms >= 0),
                    document_json TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL REFERENCES evidence_objects(sha256)
                ) STRICT;
                """
            )
            connection.execute(f"PRAGMA user_version = {OBSERVATION_CACHE_SCHEMA_VERSION}")
            connection.commit()
        finally:
            connection.close()
        os.chmod(self.path, 0o600)
        _fsync_directory(self.path.parent)

    def _bind_policy(self) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT value FROM cache_meta WHERE key = 'policy_hash'"
            ).fetchone()
            if row is not None and str(row["value"]) != self.policy_hash:
                raise ObservationCacheError("observation cache belongs to another policy")
            connection.execute(
                "INSERT OR IGNORE INTO cache_meta (key, value) VALUES ('policy_hash', ?)",
                (self.policy_hash,),
            )

    @contextmanager
    def _transaction(self) -> Any:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _read(self) -> Any:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        self._require_safe_paths()
        connection = sqlite3.connect(self.path, timeout=self._busy_timeout_ms / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        return connection


class DeterministicWindowPlanSource:
    """Produce the next exact ``WindowPlan`` from verified finalized evidence."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        control_plane: ValidatorControlPlane,
        finalized_blocks: VerifiedFinalizedAnnouncementPort,
        prior_readiness: PriorWindowReadinessPort,
        observation_cache_path: str | Path,
        cache_limits: ObservationCacheLimits | None = None,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("policy must be a ScoringPolicy")
        if not isinstance(control_plane, ValidatorControlPlane):
            raise TypeError("control_plane must be a ValidatorControlPlane")
        if not callable(getattr(finalized_blocks, "finalized_head_height", None)) or not callable(
            getattr(finalized_blocks, "verified_block_at", None)
        ):
            raise TypeError("finalized_blocks must implement the verified finalized-block port")
        if not callable(getattr(prior_readiness, "verified_reveal_and_spent", None)):
            raise TypeError("prior_readiness must implement the reveal/spent checkpoint port")
        pins = policy.implementation_pins
        if (
            pins.pin_profile != "live_shadow_calibration"
            or pins.live_chain is None
            or pins.finality_verifier is None
        ):
            raise PlanPolicyError("deterministic live plans require live chain/finality pins")
        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self._control_plane = control_plane
        self._finalized_blocks = finalized_blocks
        self._prior_readiness = prior_readiness
        self._clock = _window_clock(policy)
        self._cache = _ObservationCache(
            observation_cache_path,
            policy_hash=self.policy_hash,
            limits=cache_limits or ObservationCacheLimits(),
        )
        self._lock = asyncio.Lock()
        self._audit_against_control_plane()

    async def next_plan(self) -> WindowPlan | None:
        """Return one stable next plan, or ``None`` until all prerequisites are ready."""

        async with self._lock:
            windows = self._audit_against_control_plane()
            if any(window.is_active for window in windows):
                raise PlanStateError("a plan source cannot advance while a window is active")
            expected_index = len(windows)
            history_fingerprint = _history_fingerprint(windows)

            if windows:
                previous = windows[-1]
                checkpoint = await self._prior_readiness.verified_reveal_and_spent(previous)
                if checkpoint is None:
                    return None
                _validate_checkpoint(previous, checkpoint)
                self._require_history(history_fingerprint)

            announcement_height = (
                self.policy.activation_block
                + expected_index * self.policy.clock.window_stride_blocks
            )
            head = await self._finalized_blocks.finalized_head_height()
            if isinstance(head, bool) or not isinstance(head, int):
                raise VerifiedBlockPortError("finalized head height must be an integer")
            try:
                self._cache.observe_head(head)
            except (TypeError, ValueError) as error:
                raise VerifiedBlockPortError("finalized head height is invalid") from error
            if head < announcement_height:
                self._require_history(history_fingerprint)
                return None

            block = await self._finalized_blocks.verified_block_at(announcement_height)
            if block is None:
                raise VerifiedBlockPortError(
                    "finalized head reached announcement height without its verified block"
                )
            if not isinstance(block, VerifiedFinalizedBlock):
                raise VerifiedBlockPortError("verified block port returned an invalid record")
            observations = self._cache.load_all()
            previous_timestamp = (
                observations[expected_index - 1].block.timestamp_ms if expected_index > 0 else None
            )
            self._validate_block(
                expected_index,
                announcement_height,
                block,
                previous_timestamp_ms=previous_timestamp,
            )
            self._require_history(history_fingerprint)
            cached = self._cache.observe(expected_index, block)
            plan = self._derive_plan(expected_index, cached.block)
            self._require_history(history_fingerprint)
            return plan

    def _validate_block(
        self,
        index: int,
        expected_height: int,
        block: VerifiedFinalizedBlock,
        *,
        previous_timestamp_ms: int | None,
    ) -> None:
        if block.height != expected_height:
            raise VerifiedBlockPortError("verified block is not the exact announcement height")
        if block.scoring_policy_hash != self.policy_hash:
            raise PlanPolicyError("verified block binds another scoring policy")
        try:
            require_live_chain_observation(self.policy, block.chain_observation)
        except (TypeError, RuntimeError) as error:
            raise PlanPolicyError(
                "verified block chain/runtime identity misses policy pins"
            ) from error
        finality_pin = self.policy.implementation_pins.finality_verifier
        if finality_pin is None:
            raise PlanPolicyError("policy lost its finality-verifier pin")
        if block.finality_verifier_sha256 not in set(
            finality_pin.release_sha256_by_target.values()
        ):
            raise PlanPolicyError("verified block used an unpinned finality verifier")
        if index == 0 and previous_timestamp_ms is not None:
            raise ObservationCacheError("first announcement has unexpected prior timestamp state")
        if index > 0:
            if previous_timestamp_ms is None:
                raise ObservationCacheError("prior announcement observation is unavailable")
            if block.timestamp_ms <= previous_timestamp_ms:
                raise VerifiedBlockPortError("verified announcement timestamp did not advance")

    def _derive_plan(self, index: int, block: VerifiedFinalizedBlock) -> WindowPlan:
        schedule = self._clock.derive(
            index,
            netuid=self.policy.netuid,
            announcement_block_hash=block.block_hash,
            announcement_timestamp_ms=block.timestamp_ms,
            scoring_policy_hash=self.policy_hash,
        )
        return WindowPlan.from_schedule(schedule, scoring_policy_hash=self.policy_hash)

    def _audit_against_control_plane(self) -> tuple[WindowRecord, ...]:
        self._cache.audit()
        windows = self._control_plane.list_windows()
        if [window.plan.window_index for window in windows] != list(range(len(windows))):
            raise PlanStateError("validator window history is not a zero-based complete prefix")
        if any(window.plan.scoring_policy_hash != self.policy_hash for window in windows):
            raise PlanPolicyError("validator window history belongs to another scoring policy")
        if sum(window.is_active for window in windows) > 1:
            raise PlanStateError("validator history contains multiple active windows")
        observations = self._cache.load_all()
        if len(observations) not in {len(windows), len(windows) + 1}:
            raise ObservationCacheError(
                "observation cache must match history or contain only its pending next plan"
            )
        for index, window in enumerate(windows):
            observation = observations[index]
            expected_height = (
                self.policy.activation_block + index * self.policy.clock.window_stride_blocks
            )
            self._validate_block(
                index,
                expected_height,
                observation.block,
                previous_timestamp_ms=(
                    observations[index - 1].block.timestamp_ms if index else None
                ),
            )
            if self._derive_plan(index, observation.block) != window.plan:
                raise ObservationCacheError(
                    "persisted window plan disagrees with its announcement observation"
                )
        if len(observations) == len(windows) + 1:
            pending = observations[-1]
            expected_height = (
                self.policy.activation_block + len(windows) * self.policy.clock.window_stride_blocks
            )
            self._validate_block(
                len(windows),
                expected_height,
                pending.block,
                previous_timestamp_ms=(
                    observations[-2].block.timestamp_ms if len(observations) > 1 else None
                ),
            )
        return windows

    def _require_history(self, expected_fingerprint: str) -> None:
        windows = self._audit_against_control_plane()
        if _history_fingerprint(windows) != expected_fingerprint:
            raise PlanStateError("validator history changed while deriving the next plan")


def _observation_document(
    index: int,
    block: VerifiedFinalizedBlock,
) -> _ObservationDocument:
    return _ObservationDocument(
        schema=OBSERVATION_SCHEMA,
        window_index=index,
        announcement_height=block.height,
        block_hash=block.block_hash,
        state_root=block.state_root,
        timestamp_ms=block.timestamp_ms,
        scoring_policy_hash=block.scoring_policy_hash,
        chain_observation=block.chain_observation,
        finality_verifier_sha256=block.finality_verifier_sha256,
        finality_evidence_sha256=block.finality_evidence_sha256,
        finality_evidence_size_bytes=len(block.finality_evidence),
    )


def _window_clock(policy: ScoringPolicy) -> WindowClock:
    clock = policy.clock
    return WindowClock(
        activation_block=policy.activation_block,
        window_stride_blocks=clock.window_stride_blocks,
        proposal_blocks=clock.proposal_blocks,
        anchor_blocks=clock.anchor_blocks,
        target_block_interval_seconds=clock.target_block_interval_seconds,
        selection_finality_buffer_seconds=clock.selection_finality_buffer_seconds,
        issue_allowance_seconds=clock.issue_allowance_seconds,
        response_window_seconds=clock.response_window_seconds,
        delivery_grace_seconds=clock.delivery_grace_seconds,
        reveal_margin_seconds=clock.reveal_margin_seconds,
    )


def _validate_checkpoint(
    previous: WindowRecord,
    checkpoint: object,
) -> None:
    if not isinstance(checkpoint, VerifiedPriorWindowCheckpoint):
        raise ReadinessPortError("readiness port returned an invalid checkpoint")
    if previous.is_active:
        raise PlanStateError("an active window cannot have a terminal readiness checkpoint")
    if (
        checkpoint.window_id != previous.plan.window_id
        or checkpoint.window_index != previous.plan.window_index
        or checkpoint.reveal_round != previous.plan.reveal_round
    ):
        raise ReadinessPortError("readiness checkpoint binds another window")
    if checkpoint.checkpoint_block_height < previous.plan.closing_block:
        raise ReadinessPortError("readiness checkpoint predates the previous window close")
    if (
        previous.audit_release_block is not None
        and checkpoint.checkpoint_block_height < previous.audit_release_block
    ):
        raise ReadinessPortError("readiness checkpoint predates the audit release block")


def _history_fingerprint(windows: Sequence[WindowRecord]) -> str:
    value = [
        {
            "window_id": window.plan.window_id,
            "window_index": window.plan.window_index,
            "stage": window.stage.value,
            "terminal_outcome": (
                window.terminal_outcome.value if window.terminal_outcome is not None else None
            ),
            "revision": window.revision,
        }
        for window in windows
    ]
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _evidence(
    data: object,
    digest: object,
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    if not isinstance(data, bytes) or not data:
        raise ValueError(f"{label} must be non-empty exact bytes")
    if len(data) > maximum_bytes:
        raise ValueError(f"{label} exceeds its byte ceiling")
    expected = _hex32(digest, f"{label} digest")
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"{label} digest does not reproduce")
    return data


def _timestamp_ms(value: object) -> int:
    value = _uint(value, "announcement timestamp")
    if value < QUICKNET_GENESIS_MS:
        raise ValueError("announcement timestamp predates pinned Quicknet")
    return value


def _uint(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_CANONICAL_INTEGER
    ):
        raise ValueError(f"{label} must be a non-negative canonical JSON integer")
    return value


def _hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be 32 lowercase hexadecimal bytes")
    return value


def _block_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or _BLOCK_HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a 0x-prefixed lowercase 32-byte hash")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "MAX_CACHE_DATABASE_BYTES",
    "MAX_CHECKPOINT_EVIDENCE_BYTES",
    "MAX_FINALITY_EVIDENCE_BYTES",
    "MAX_OBSERVATIONS",
    "MAX_TOTAL_EVIDENCE_BYTES",
    "OBSERVATION_CACHE_SCHEMA_VERSION",
    "OBSERVATION_SCHEMA",
    "DeterministicWindowPlanSource",
    "ObservationCacheError",
    "ObservationCacheLimits",
    "ObservationConflict",
    "PlanPolicyError",
    "PlanStateError",
    "PriorWindowReadinessPort",
    "ReadinessPortError",
    "ValidatorPlanError",
    "VerifiedBlockPortError",
    "VerifiedFinalizedAnnouncementPort",
    "VerifiedFinalizedBlock",
    "VerifiedPriorWindowCheckpoint",
]
