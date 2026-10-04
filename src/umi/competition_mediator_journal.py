"""Crash-safe at-most-once journal for external mediator diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .canonical_stream import canonical_json_matches
from .competition_mediator import (
    MediatorInvocation,
    MediatorReceipt,
    MediatorRequest,
    MediatorUnavailable,
    execute,
)
from .private_files import ensure_private_directory
from .protocol import canonical_json_bytes

_MAXIMUM_REQUEST_BYTES = 40 * 1024
_MAXIMUM_INVOCATION_BYTES = 16 * 1024
_MAXIMUM_OUTCOME_BYTES = 32 * 1024
_MAXIMUM_RESPONSE_BYTES = 1024 * 1024
_DOMAIN = b"umi-mediator-job-v1\0"

MediatorOutcome = MediatorReceipt | MediatorUnavailable


@dataclass(frozen=True, slots=True)
class JournalReservation:
    status: Literal["reserved", "retained", "outcome_unknown"]
    job_sha256: str
    outcome: MediatorOutcome | None = None
    provider_response: bytes = b""


def job_sha256(request: MediatorRequest, invocation: MediatorInvocation) -> str:
    request_digest = hashlib.sha256(canonical_json_bytes(request)).digest()
    invocation_digest = hashlib.sha256(canonical_json_bytes(invocation)).digest()
    return hashlib.sha256(_DOMAIN + request_digest + invocation_digest).hexdigest()


def _outcome(raw: bytes) -> MediatorOutcome:
    if not 1 <= len(raw) <= _MAXIMUM_OUTCOME_BYTES:
        raise ValueError("mediator journal outcome exceeds its byte bound")
    try:
        untyped = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("mediator journal outcome is invalid") from error
    if not isinstance(untyped, dict):
        raise ValueError("mediator journal outcome is invalid")
    schema = untyped.get("schema")
    if schema == "umi-mediator-receipt/1":
        value: MediatorOutcome = MediatorReceipt.model_validate_json(raw)
    elif schema == "umi-mediator-unavailable/1":
        value = MediatorUnavailable.model_validate_json(raw)
    else:
        raise ValueError("mediator journal outcome schema changed")
    if not canonical_json_matches(value, raw):
        raise ValueError("mediator journal outcome is not canonical")
    return value


class MediatorJournal:
    """Persist a terminal result or a permanent unknown outcome for each call."""

    def __init__(self, root: Path, *, maximum_records: int = 100_000) -> None:
        if type(maximum_records) is not int or not 1 <= maximum_records <= 1_000_000:
            raise ValueError("mediator journal requires a bounded record count")
        self.root, self.maximum_records = root, maximum_records
        self.path = root / "mediator.sqlite3"
        self._lock = threading.RLock()
        ensure_private_directory(root)
        self._check_files()
        descriptor = os.open(
            self.path,
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        os.close(descriptor)
        self._check_files()
        with self._transaction() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS jobs ("
                "job_sha256 TEXT PRIMARY KEY, request BLOB NOT NULL, invocation BLOB NOT NULL, "
                "phase TEXT NOT NULL CHECK(phase IN ('running','terminal')), "
                "outcome BLOB, provider_response BLOB)"
            )
            database.execute("PRAGMA user_version=1")

    def _check_files(self) -> None:
        ensure_private_directory(self.root)
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = Path(str(self.path) + suffix)
            if path.is_symlink():
                raise ValueError("mediator journal file must not be a symlink")
            if not path.exists():
                continue
            info = path.stat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise ValueError("mediator journal file must be owned and private")

    def _transaction(self):
        return _Transaction(self)

    @staticmethod
    def _validate_request(raw: bytes, expected: MediatorRequest) -> None:
        if not 1 <= len(raw) <= _MAXIMUM_REQUEST_BYTES:
            raise ValueError("mediator journal request exceeds its byte bound")
        value = MediatorRequest.model_validate_json(raw)
        if value != expected or not canonical_json_matches(value, raw):
            raise ValueError("mediator journal request changed")

    @staticmethod
    def _validate_invocation(raw: bytes, expected: MediatorInvocation) -> None:
        if not 1 <= len(raw) <= _MAXIMUM_INVOCATION_BYTES:
            raise ValueError("mediator journal invocation exceeds its byte bound")
        value = MediatorInvocation.model_validate_json(raw)
        if value != expected or not canonical_json_matches(value, raw):
            raise ValueError("mediator journal invocation changed")

    @staticmethod
    def _validate_response(outcome: MediatorOutcome, response: bytes) -> None:
        if len(response) > _MAXIMUM_RESPONSE_BYTES:
            raise ValueError("mediator journal response exceeds its byte bound")
        digest = hashlib.sha256(response).hexdigest()
        if isinstance(outcome, MediatorReceipt):
            if not response or outcome.provider_response_sha256 != digest:
                raise ValueError("mediator receipt does not bind its provider response")
        elif outcome.stdout_sha256 is None:
            if response:
                raise ValueError("mediator unavailable outcome has an unbound response")
        elif outcome.stdout_sha256 != digest:
            raise ValueError("mediator unavailable outcome does not bind its response")

    @staticmethod
    def _validate_outcome_binding(
        request: MediatorRequest,
        invocation: MediatorInvocation,
        outcome: MediatorOutcome,
    ) -> None:
        request_digest = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
        invocation_digest = hashlib.sha256(canonical_json_bytes(invocation)).hexdigest()
        if (
            outcome.request_sha256 != request_digest
            or outcome.invocation_sha256 != invocation_digest
        ):
            raise ValueError("mediator outcome identity differs from its reservation")
        if isinstance(outcome, MediatorReceipt) and (
            outcome.provider_model != invocation.model
            or outcome.output_sha256
            != hashlib.sha256(canonical_json_bytes(outcome.output)).hexdigest()
        ):
            raise ValueError("mediator receipt content binding differs")

    def reserve(
        self, request: MediatorRequest, invocation: MediatorInvocation
    ) -> JournalReservation:
        request = MediatorRequest.model_validate_json(canonical_json_bytes(request))
        invocation = MediatorInvocation.model_validate_json(canonical_json_bytes(invocation))
        key = job_sha256(request, invocation)
        request_raw = canonical_json_bytes(request)
        invocation_raw = canonical_json_bytes(invocation)
        with self._transaction() as database:
            row = database.execute(
                "SELECT request,invocation,phase,outcome,provider_response FROM jobs "
                "WHERE job_sha256=?",
                (key,),
            ).fetchone()
            if row is None:
                count = database.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
                if type(count) is not int or count >= self.maximum_records:
                    raise ValueError("mediator journal record capacity exhausted")
                database.execute(
                    "INSERT INTO jobs VALUES (?,?,?,'running',NULL,NULL)",
                    (key, request_raw, invocation_raw),
                )
                return JournalReservation("reserved", key)
            old_request, old_invocation, phase, outcome_raw, response = row
            if not isinstance(old_request, bytes) or not isinstance(old_invocation, bytes):
                raise ValueError("mediator journal record type changed")
            self._validate_request(old_request, request)
            self._validate_invocation(old_invocation, invocation)
            if phase == "running" and outcome_raw is None and response is None:
                return JournalReservation("outcome_unknown", key)
            if (
                phase != "terminal"
                or not isinstance(outcome_raw, bytes)
                or not isinstance(response, bytes)
            ):
                raise ValueError("mediator journal phase changed")
            outcome = _outcome(outcome_raw)
            self._validate_outcome_binding(request, invocation, outcome)
            self._validate_response(outcome, response)
            return JournalReservation("retained", key, outcome, response)

    def complete(
        self,
        request: MediatorRequest,
        invocation: MediatorInvocation,
        outcome: MediatorOutcome,
        provider_response: bytes,
    ) -> None:
        key = job_sha256(request, invocation)
        outcome_raw = canonical_json_bytes(outcome)
        if len(outcome_raw) > _MAXIMUM_OUTCOME_BYTES:
            raise ValueError("mediator journal outcome exceeds its byte bound")
        self._validate_outcome_binding(request, invocation, outcome)
        self._validate_response(outcome, provider_response)
        with self._transaction() as database:
            row = database.execute(
                "SELECT request,invocation,phase,outcome,provider_response FROM jobs "
                "WHERE job_sha256=?",
                (key,),
            ).fetchone()
            if row is None:
                raise ValueError("mediator journal has no reservation")
            old_request, old_invocation, phase, old_outcome, old_response = row
            if not isinstance(old_request, bytes) or not isinstance(old_invocation, bytes):
                raise ValueError("mediator journal record type changed")
            self._validate_request(old_request, request)
            self._validate_invocation(old_invocation, invocation)
            if phase == "terminal":
                if old_outcome != outcome_raw or old_response != provider_response:
                    raise ValueError("mediator journal already has a different outcome")
                return
            if phase != "running" or old_outcome is not None or old_response is not None:
                raise ValueError("mediator journal phase changed")
            database.execute(
                "UPDATE jobs SET phase='terminal',outcome=?,provider_response=? "
                "WHERE job_sha256=? AND phase='running'",
                (outcome_raw, provider_response, key),
            )

    def run_once(self, request: MediatorRequest, invocation: MediatorInvocation, **kwargs):
        reservation = self.reserve(request, invocation)
        if reservation.status == "retained":
            return reservation.outcome, reservation.provider_response
        if reservation.status == "outcome_unknown":
            return (
                MediatorUnavailable(
                    schema="umi-mediator-unavailable/1",
                    request_sha256=hashlib.sha256(canonical_json_bytes(request)).hexdigest(),
                    invocation_sha256=hashlib.sha256(canonical_json_bytes(invocation)).hexdigest(),
                    reason="prior_outcome_unknown",
                ),
                b"",
            )
        outcome, response = execute(request, invocation, **kwargs)
        self.complete(request, invocation, outcome, response)
        return outcome, response


class _Transaction:
    def __init__(self, journal: MediatorJournal) -> None:
        self.journal = journal
        self.database: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        self.journal._lock.acquire()
        try:
            self.journal._check_files()
            database = sqlite3.connect(self.journal.path, isolation_level=None, timeout=5)
            self.database = database
            database.execute("PRAGMA synchronous=FULL")
            database.execute("PRAGMA max_page_count=524288")
            database.execute("BEGIN IMMEDIATE")
            if database.execute("PRAGMA user_version").fetchone()[0] not in (0, 1):
                raise ValueError("unsupported mediator journal generation")
            return database
        except BaseException:
            if self.database is not None:
                self.database.close()
            self.journal._lock.release()
            raise

    def __exit__(self, kind, value, traceback) -> None:
        assert self.database is not None
        try:
            if kind is None:
                self.database.commit()
            else:
                self.database.rollback()
        finally:
            self.database.close()
            self.journal._lock.release()
