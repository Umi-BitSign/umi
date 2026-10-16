"""Bounded durable diagnostic forecasts, never protocol or payment authority.

Scope identities come from the consuming owner, not a process-local meter ID.
One completion per scope is retained even when its publication is repeated.
Individual attempts and immutable forecasts remain separately attributable.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
import uuid
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from pathlib import Path
from threading import RLock

from .competition_forecast_health import (
    health_for_restore,
    initialization_for_restore,
    new_health,
    read_health,
    record_gap,
    write_health,
    write_initialization,
)
from .competition_forecast_io import stream_file
from .competition_forecast_summary import ForecastSummary

_CONTEXT = ContextVar("competition_forecast_scope", default=None)
_INVOCATION = uuid.uuid4().hex
_MAXIMUM_BYTES = 32 * 1024**2
_MAXIMUM_EVENT_BYTES = 16 * 1024
_ZERO = "0" * 64


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


def _identifier(value, *, digest=False):
    pattern = r"[0-9a-f]{64}" if digest else r"[a-z][a-z0-9_]{0,79}"
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise ValueError("invalid diagnostic scope identity")
    return value


class ForecastRepairRequired(ValueError):
    """Accounting cannot be trusted; restore its exact retained snapshot explicitly."""


class ForecastCapacityRequired(ValueError):
    """Retain or expand accounting storage; never silently evict issued forecasts."""


class ForecastLedger:
    """One small separate SQLite file, with atomic immutable hash-chained records.

    FULL synchronous transactions survive interruption without altering owner
    journals. The explicit directory prevents missing records becoming a fresh
    cache. Capacity exhaustion affects diagnostics only at the consuming boundary.
    """

    def __init__(self, directory: Path, *, maximum_bytes=_MAXIMUM_BYTES):
        if type(maximum_bytes) is not int or not 64 * 1024 <= maximum_bytes <= 1024**3:
            raise ValueError("forecast accounting capacity must be 64 KiB to 1 GiB")
        self.directory = Path(directory)
        self.path = self.directory / "forecasts.sqlite3"
        self.marker = self.directory.with_name(self.directory.name + ".initialized")
        self.health_path = self.directory.with_name(self.directory.name + ".health")
        self.lock = RLock()
        self.maximum_bytes = maximum_bytes
        self.db = None
        self.owner = None
        self.capacity_required = False
        self.last_failure_token = None
        self.session_started = False
        self.owns_lock = False
        marker = None
        try:
            existing = self.directory.exists()
            if not existing and self.marker.exists():
                raise ForecastRepairRequired(
                    "previously initialized forecast accounting is missing"
                )
            if self.directory.is_symlink() or self.path.is_symlink():
                raise ForecastRepairRequired("forecast accounting path is not private")
            if existing and not self.path.is_file():
                raise ForecastRepairRequired("forecast accounting database is missing")
            if not existing:
                self.directory.mkdir(mode=0o700, parents=True)
            self.owner = os.open(
                self.directory / "owner.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
            )
            fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.owns_lock = True
            marker = None
            if self.marker.exists():
                if self.marker.is_symlink() or self.marker.stat().st_size != 26:
                    raise ForecastRepairRequired(
                        "forecast accounting initialization marker changed"
                    )
                marker = self.marker.read_bytes()
                if marker not in {b"umi-forecast-accounting/1\n", b"umi-forecast-accounting/2\n"}:
                    raise ForecastRepairRequired(
                        "forecast accounting initialization marker changed"
                    )
            if existing and marker is None and self.health_path.exists():
                raise ForecastRepairRequired("forecast accounting initialization marker is missing")
            if self.health_path.exists():
                self.health = read_health(self.health_path)
            else:
                if marker == b"umi-forecast-accounting/2\n":
                    raise ForecastRepairRequired("forecast accounting coverage marker is missing")
                self.health = new_health(legacy=existing)
                write_health(self.health_path, self.health)
            unclean = self.health.get("session_open", True)
            # Mark the session before opening or verifying SQLite: a failed
            # diagnostic startup must not silently erase a native-work gap.
            self.health = {**self.health, "session_open": True}
            write_health(self.health_path, self.health)
            self.session_started = True
            self.db = sqlite3.connect(self.path, timeout=0.05, check_same_thread=False)
            if not existing:
                os.chmod(self.path, 0o600)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
            page_bytes = self.db.execute("PRAGMA page_size").fetchone()[0]
            self.db.execute(f"PRAGMA max_page_count={maximum_bytes // page_bytes}")
            if not existing:
                with self.db:
                    self.db.execute(
                        "CREATE TABLE events (sequence INTEGER PRIMARY KEY, "
                        "identity TEXT UNIQUE NOT NULL, scope TEXT NOT NULL, "
                        "body BLOB NOT NULL, previous TEXT NOT NULL, digest TEXT NOT NULL)"
                    )
                    self.db.execute("CREATE INDEX event_scope ON events(scope,sequence)")
                    self.db.execute("CREATE TABLE head (digest TEXT, sequence INTEGER)")
                    self.db.execute("INSERT INTO head VALUES(?,0)", (_ZERO,))
                    self.db.execute("PRAGMA user_version=1")
            self._verify()
            if unclean:
                self.health = record_gap(
                    self.health, reason="unclean_accounting_session", head=self.head
                )
                write_health(self.health_path, self.health)
            blocked = self.health["blocked_capacity_bytes"]
            if blocked is not None and maximum_bytes > blocked:
                self.health = {**self.health, "blocked_capacity_bytes": None}
                write_health(self.health_path, self.health)
            self.capacity_required = self.health["blocked_capacity_bytes"] is not None
            if marker != b"umi-forecast-accounting/2\n":
                fd = os.open(self.marker, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                try:
                    os.write(fd, b"umi-forecast-accounting/2\n")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except Exception as error:
            if (
                self.owns_lock
                and not self.session_started
                and marker in {b"umi-forecast-accounting/1\n", b"umi-forecast-accounting/2\n"}
            ):
                # A failed write of the open-session marker cannot leave an old
                # clean marker silently reusable. This independent small write
                # forces explicit pinned marker repair if health selection fails.
                with suppress(Exception):
                    fd = os.open(
                        self.marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
                    )
                    try:
                        os.write(fd, b"umi-forecast-session-repair-required\n")
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            if self.db is not None:
                with suppress(Exception):
                    self.db.close()
            if self.owner is not None:
                os.close(self.owner)
            if isinstance(error, (ForecastRepairRequired, ForecastCapacityRequired)):
                raise
            raise ForecastRepairRequired("forecast accounting requires explicit repair") from error

    def status(self, scope, *, observed_unix_ms=None):
        """Pending forecasts do not vanish when no worker is currently observing them."""
        now = time.time_ns() // 1_000_000 if observed_unix_ms is None else observed_unix_ms
        with self.lock:
            result = self.summaries[scope].status(scope, now)
            return {
                **result,
                "status": "capacity_required" if self.capacity_required else "retained",
                "accounting_coverage_complete": self.health["coverage_complete"],
                "calibration_eligible": self.health["coverage_complete"]
                and not result["clock_regression"]
                and result["sample_kind"] == "prediction_outcome",
                "duration_sample_eligible": self.health["coverage_complete"]
                and not result["clock_regression"]
                and result["outcome"] == "completed",
                "accounting_gap_count": self.health["gap_count"],
                "accounting_first_gap": self.health["first_gap"],
                "accounting_last_gap": self.health["last_gap"],
            }

    def scopes(self, *, after="", limit=100):
        """Bounded keyset pages, including abandoned/overdue unfinished work."""
        if not 1 <= limit <= 1000:
            raise ValueError("forecast scope page limit is invalid")
        with self.lock:
            return [
                r[0]
                for r in self.db.execute(
                    "SELECT DISTINCT scope FROM events WHERE scope>? ORDER BY scope LIMIT ?",
                    (after, limit),
                )
            ]

    def _verify(self):
        if self.path.stat().st_size > self.maximum_bytes:
            raise ForecastCapacityRequired("forecast accounting exceeds its selected capacity")
        if self.db.execute("PRAGMA user_version").fetchone() != (1,):
            raise ForecastRepairRequired("unsupported forecast accounting schema")
        if self.db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ForecastRepairRequired("forecast accounting database is damaged")
        previous = _ZERO
        sequence = 0
        self.summaries = {}
        for row in self.db.execute(
            "SELECT sequence,identity,scope,body,previous,digest FROM events ORDER BY sequence"
        ):
            seq, identity, scope, body, parent, digest = row
            if (
                seq != sequence + 1
                or parent != previous
                or len(body) > _MAXIMUM_EVENT_BYTES
                or hashlib.sha256(parent.encode() + body).hexdigest() != digest
            ):
                raise ForecastRepairRequired("forecast accounting chain is damaged")
            event = json.loads(body)
            if (
                _encode(event) != body
                or (event["identity"], event["scope"]) != (identity, scope)
                or event["certification_authority"] is not False
            ):
                raise ForecastRepairRequired("forecast accounting identity is damaged")
            self.summaries.setdefault(scope, ForecastSummary()).accept(event)
            previous, sequence = digest, seq
        self.head = previous, sequence
        if self.db.execute("SELECT digest,sequence FROM head").fetchall() != [self.head]:
            raise ForecastRepairRequired("forecast accounting records are missing")

    def note_failure(self, reason, *, error=None, capacity_bytes=None):
        """Mark lost diagnostic coverage without replacing the native exception."""
        with self.lock:
            token = id(error) if error is not None else None
            if token is not None and token == self.last_failure_token:
                return
            self.last_failure_token = token
            self.health = record_gap(
                self.health, reason=reason, head=self.head, capacity_bytes=capacity_bytes
            )
            # The already-durable open-session marker is the fallback if this
            # write fails. In-memory coverage also stays incomplete through
            # graceful close; a failed write never resets it to healthy.
            with suppress(Exception):
                write_health(self.health_path, self.health)

    def append(self, identity, scope, kind, values):
        if self.capacity_required:
            raise ForecastCapacityRequired("forecast accounting capacity exhausted")
        with self.lock:
            try:
                event = {
                    **values,
                    "schema": "umi-forecast-event/1",
                    "identity": identity,
                    "scope": scope,
                    "kind": kind,
                    "certification_authority": False,
                }
                body = _encode(event)
                if len(body) > _MAXIMUM_EVENT_BYTES:
                    raise ForecastCapacityRequired("forecast event exceeds its selected capacity")
                self.db.execute("BEGIN IMMEDIATE")
                old = self.db.execute(
                    "SELECT body FROM events WHERE identity=?", (identity,)
                ).fetchone()
                if old is not None:
                    self.db.rollback()
                    # Stable terminal identity deduplicates later observations;
                    # the first exact completion or first-complete bracket wins.
                    retained = json.loads(old[0])
                    if (retained["scope"], retained["kind"]) != (scope, kind):
                        raise ForecastRepairRequired("forecast event identity conflicts")
                    return retained
                latest = self.db.execute(
                    "SELECT digest,sequence FROM events ORDER BY sequence DESC LIMIT 1"
                ).fetchone() or (_ZERO, 0)
                if latest != self.head:
                    raise ForecastRepairRequired("forecast accounting changed outside its owner")
                digest = hashlib.sha256(self.head[0].encode() + body).hexdigest()
                self.db.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?,?)",
                    (self.head[1] + 1, identity, scope, body, self.head[0], digest),
                )
                self.db.execute("UPDATE head SET digest=?,sequence=?", (digest, self.head[1] + 1))
                self.db.commit()
                self.head = digest, self.head[1] + 1
                self.summaries.setdefault(scope, ForecastSummary()).accept(event)
                self.last_failure_token = None
                return event
            except BaseException as error:
                with suppress(Exception):
                    self.db.rollback()
                # sqlite_errorcode was added in Python 3.11; supported 3.10
                # exposes only SQLite's exact static diagnostic text here.
                if isinstance(error, sqlite3.OperationalError) and (
                    getattr(error, "sqlite_errorcode", None) == 13
                    or error.args == ("database or disk is full",)
                ):
                    self.capacity_required = True
                    self.note_failure(
                        "capacity_exhausted", error=error, capacity_bytes=self.maximum_bytes
                    )
                    raise ForecastCapacityRequired(
                        "forecast accounting capacity exhausted"
                    ) from error
                self.note_failure(
                    "event_encoding_capacity_exhausted"
                    if isinstance(error, ForecastCapacityRequired)
                    else "unretained_observation",
                    error=error,
                )
                raise

    def records(self, scope):
        with self.lock:
            records = []
            for body, parent, digest in self.db.execute(
                "SELECT body,previous,digest FROM events WHERE scope=? ORDER BY sequence", (scope,)
            ):
                if hashlib.sha256(parent.encode() + body).hexdigest() != digest:
                    raise ForecastRepairRequired("forecast accounting record changed")
                records.append(json.loads(body))
            return records

    def snapshot(self, destination: Path):
        """Produce a bounded consistent backup for durable retention and repair."""
        if destination.exists():
            raise ValueError("forecast snapshot destination already exists")
        with self.lock:
            connection = sqlite3.connect(destination)
            try:
                self.db.backup(connection)
            finally:
                connection.close()
            os.chmod(destination, 0o600)
            checksum, total = stream_file(destination, maximum_bytes=self.maximum_bytes, sync=True)
            fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return {
                "sha256": checksum,
                "head": list(self.head),
                "bytes": total,
                "accounting_health": dict(self.health),
            }

    def close(self):
        with self.lock:
            if self.db is not None:
                try:
                    self.db.close()
                except Exception as error:
                    self.note_failure("diagnostic_close_failed", error=error)
                finally:
                    self.db = None
                self.health = {**self.health, "session_open": False}
                # A failed write leaves the durable open-session marker (or a
                # damaged marker requiring repair), never an invented clean run.
                with suppress(Exception):
                    write_health(self.health_path, self.health)
            if self.owner is not None:
                os.close(self.owner)
                self.owner = None


def restore_forecast_snapshot(
    directory: Path,
    snapshot: Path,
    receipt: dict,
    *,
    damaged_sha256: str | None,
    maximum_bytes=_MAXIMUM_BYTES,
    damaged_health_sha256: str | None = None,
    damaged_initialized_sha256: str | None = None,
):
    """Explicit offline repair; retain damaged bytes and verify the selected backup.

    The receipt must come from durable snapshot retention. Restoring an older
    backup cannot reconstruct later unarchived forecasts; that loss stays explicit.
    No protocol journal, service state, signed bytes or payload cache is touched.
    """
    if snapshot.is_symlink() or not 0 < snapshot.stat().st_size <= maximum_bytes:
        raise ForecastRepairRequired("forecast repair snapshot is not bounded")
    # Validate a separate bounded copy before changing any retained accounting.
    with tempfile.TemporaryDirectory(prefix="forecast-repair-", dir=directory.parent) as temporary:
        candidate = Path(temporary) / "candidate"
        candidate.mkdir(mode=0o700)
        checksum, total = stream_file(
            snapshot, maximum_bytes=maximum_bytes, destination=candidate / "forecasts.sqlite3"
        )
        if checksum != receipt["sha256"] or total != receipt["bytes"]:
            raise ForecastRepairRequired("forecast repair snapshot differs from retained receipt")
        checked = ForecastLedger(candidate, maximum_bytes=maximum_bytes)
        try:
            if list(checked.head) != receipt["head"]:
                raise ForecastRepairRequired("forecast repair snapshot has another retained head")
        finally:
            checked.close()
        directory.mkdir(mode=0o700, exist_ok=True)
        owner = os.open(directory / "owner.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = directory / "forecasts.sqlite3"
            if directory.is_symlink() or path.is_symlink():
                raise ForecastRepairRequired("forecast repair refuses linked state")
            if any(Path(str(path) + suffix).exists() for suffix in ("-journal", "-wal", "-shm")):
                raise ForecastRepairRequired("original SQLite recovery must finish before repair")
            prior = None
            if path.exists():
                if path.stat().st_size > maximum_bytes:
                    raise ForecastCapacityRequired("forecast repair needs a larger explicit budget")
                prior, _ = stream_file(path, maximum_bytes=maximum_bytes)
            if prior != receipt["sha256"] and prior != damaged_sha256:
                raise ForecastRepairRequired("forecast repair original identity changed")
            health_path = directory.with_name(directory.name + ".health")
            health, health_repaired = health_for_restore(
                health_path, damaged_sha256=damaged_health_sha256
            )
            marker_path = directory.with_name(directory.name + ".initialized")
            initialized_repaired = initialization_for_restore(
                marker_path, damaged_sha256=damaged_initialized_sha256
            )
            if prior == receipt["sha256"] and not health_repaired and not initialized_repaired:
                return {"status": "already_restored", "snapshot": receipt}
            preserved = None
            if prior is not None and prior != receipt["sha256"]:
                preserved = directory / ("damaged-" + prior + ".sqlite3")
                if preserved.is_symlink():
                    raise ForecastRepairRequired("forecast repair preservation path is linked")
                if preserved.exists():
                    if not preserved.is_file() or preserved.stat().st_size > maximum_bytes:
                        raise ForecastRepairRequired("forecast repair preservation is invalid")
                    saved, _ = stream_file(preserved, maximum_bytes=maximum_bytes)
                    if saved != prior:
                        raise ForecastRepairRequired(
                            "forecast repair preservation identity conflicts"
                        )
                else:
                    os.link(path, preserved)
            restored_health = record_gap(
                health,
                reason="snapshot_restoration_coverage_unknown",
                head=receipt["head"],
                snapshot=receipt,
            )
            # Persist the coverage discontinuity before changing the database.
            # Interruption can conservatively leave degraded coverage; it can
            # never install an older snapshot and silently claim full coverage.
            write_health(health_path, restored_health)
            if initialized_repaired:
                write_initialization(marker_path)
            os.replace(candidate / "forecasts.sqlite3", path)
            os.chmod(path, 0o600)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return {
                "status": "restored",
                "snapshot": receipt,
                "preserved_damaged_sha256": prior if preserved is not None else None,
                "health_repaired": health_repaired,
                "initialized_repaired": initialized_repaired,
                "unarchived_records_reconstructed": False,
                "certification_authority": False,
            }
        finally:
            os.close(owner)


@contextmanager
def forecast_scope(ledger, *, cohort, work_sha256, operation):
    """Bind meters to actual immutable owner inputs; no authorization is inferred."""
    identity = {
        "cohort_sha256": _identifier(cohort, digest=True),
        "work_sha256": _identifier(work_sha256, digest=True),
        "operation": _identifier(operation),
    }
    token = _CONTEXT.set([ledger, identity, False] if ledger is not None else None)
    try:
        yield
    finally:
        _CONTEXT.reset(token)


@contextmanager
def forecast_subscope(*, cohort, work_sha256, operation):
    """A selected consumer opts one counted child into its own exact input scope."""
    selected = _CONTEXT.get()
    if selected is None:
        yield
        return
    with forecast_scope(selected[0], cohort=cohort, work_sha256=work_sha256, operation=operation):
        yield


class ForecastAttempt:
    def __init__(self, ledger, identity, stage, unit, context):
        self.ledger = ledger
        self.identity = {
            **identity,
            "stage": _identifier(stage),
            "unit": _identifier(unit),
            # These identify semantic review/read work, not process counters.
            "review_kind": context.get("review_kind"),
            "operation_name": context.get("operation_name"),
            "read_number": context.get("read_number"),
        }
        self.scope = _digest(self.identity)
        self.attempt = uuid.uuid4().hex
        self.invocation = os.environ.get("INVOCATION_ID")
        if not self.invocation or re.fullmatch(r"[0-9a-f]{32}", self.invocation) is None:
            self.invocation = _INVOCATION
        self.revision = 0
        self.last_forecast = None

    @classmethod
    def current(cls, stage, unit, context):
        selected = _CONTEXT.get()
        if selected is None or selected[2]:
            return None
        selected[2] = True
        return cls(selected[0], selected[1], stage, unit, context)

    def observe(self, body):
        now = body["observed_unix_ms"]
        common = {
            **self.identity,
            "attempt": self.attempt,
            "invocation": self.invocation,
            "observed_unix_ms": now,
        }
        self.ledger.append(self.scope + ":start", self.scope, "scope_started", common)
        self.ledger.append(self.attempt + ":start", self.scope, "attempt_started", common)
        state, eta = body["state"], body["eta_seconds"]
        if state not in {"completed", "interrupted", "accounting_mismatch"}:
            forecast = {
                "state": state,
                "completed": body["completed"],
                "total": body["total"],
                "eta_basis": body["eta_basis"],
                "eta_seconds": eta,
                "finish_unix_ms": None if eta is None else now + round(eta * 1000),
            }
            if forecast != self.last_forecast:
                self.revision += 1
                self.ledger.append(
                    self.attempt + ":forecast:" + str(self.revision),
                    self.scope,
                    "forecast",
                    {
                        **common,
                        **forecast,
                        "revision": self.revision,
                        "finish_range_unix_ms": None,
                        "range_basis": "not_yet_calibrated",
                        "classification": "measured_substage" if eta is not None else "unknown",
                        "elapsed_seconds": body["elapsed_seconds"],
                        "raw_sample_seconds": body.get("eta_raw_sample_seconds", []),
                        "samples": body["eta_samples"],
                        "ignored_fast_samples": body["eta_ignored_fast_samples"],
                        "assumptions": [body["eta_assumption"]] if body["eta_assumption"] else [],
                        "scope_kind": "substage_only",
                        "revision_reason": (
                            "initial"
                            if self.last_forecast is None
                            else "basis_changed"
                            if forecast["eta_basis"] != self.last_forecast["eta_basis"]
                            else "new_completed_units"
                            if forecast["completed"] != self.last_forecast["completed"]
                            else "new_owner_observation"
                        ),
                        "rate_semantics": "umi-work-recent-active-duration/1",
                    },
                )
                self.last_forecast = forecast
        if state in {"completed", "interrupted", "accounting_mismatch"}:
            self.ledger.append(
                self.attempt + ":terminal",
                self.scope,
                "attempt_terminal",
                {**common, "state": state},
            )
        return {
            **self.ledger.status(self.scope, observed_unix_ms=now),
            "attempt": self.attempt,
            "invocation": self.invocation,
        }
