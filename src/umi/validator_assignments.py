"""Persistent assignment, request-attempt, and sealed-response transcripts.

This module owns no wallet, HTTP client, or chain client.  Callers inject already
prepared and already observed records.  The store makes those records durable,
enforces the protocol ordering around transmission, and derives all three roots
through :mod:`umi.anchors`.

SQLite is the authoritative state machine (WAL + FULL synchronization).  Exact
request, authentication, response, and freeze evidence lives in an immutable,
fsynced content-addressed object store referenced by SQLite rows.  Objects are
written before their referencing transaction, so a crash can create a harmless
orphan but cannot commit a dangling reference.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .anchors import (
    AssignmentAnchorRecord,
    AuthRecord,
    RequestAnchorRecord,
    ResponseAnchorRecord,
    SealedResponseRecord,
    VerifiedAuthEvidence,
    assignment_set_root,
    request_set_root,
    response_set_root,
)
from .encoding import account_id32, sha256_domain
from .protocol import (
    PROTOCOL_VERSION,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)
from .validator import PreparedRequestAttempt, validate_response_envelope

WINDOW_SCHEMA = "umi-validator-transcript-window/1"
PREPARED_ATTEMPT_SCHEMA = "umi-validator-prepared-attempt/1"
ATTEMPT_OUTCOME_SCHEMA = "umi-validator-attempt-outcome/1"
FREEZE_SCHEMA = "umi-validator-transcript-freeze/1"

MAX_ASSIGNMENTS_PER_WINDOW = 8_192
MAX_TRANSMISSIONS_PER_ASSIGNMENT = 16
MAX_REQUEST_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BODY_BYTES = 1024 * 1024
MAX_RETAINED_PREFIX_BYTES = 64 * 1024
MAX_EVIDENCE_OBJECT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 384 * 1024 * 1024
MAX_EVIDENCE_OBJECTS = 131_072
MAX_OPERATION_ID_BYTES = 160
_READ_CHUNK_BYTES = 64 * 1024

_ASSIGNMENT_ID_DOMAIN = b"umi-validator-assignment-id-v1\0"
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_OBJECT_NAME_RE = re.compile(r"^[0-9a-f]{64}$")


class AssignmentStoreError(RuntimeError):
    """Base class for a fail-closed transcript-store error."""


class AssignmentConflict(AssignmentStoreError):
    """One deterministic identity is already bound to different evidence."""


class AssignmentPhaseError(AssignmentStoreError):
    """A transcript operation was requested outside its protocol phase."""


class RequestStageLeaseBusy(AssignmentStoreError):
    """Another process owns the live request-stage lease for this window."""


class TranscriptPhase(str, Enum):
    COLLECTING_ASSIGNMENTS = "collecting_assignments"
    ASSIGNMENTS_FROZEN = "assignments_frozen"
    REQUESTS_FROZEN = "requests_frozen"
    RESPONSES_FROZEN = "responses_frozen"


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class TranscriptWindowSpec(StrictProtocolModel):
    schema_: Literal[WINDOW_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    expected_assignment_count: Annotated[
        int,
        Field(gt=0, le=MAX_ASSIGNMENTS_PER_WINDOW),
    ]
    maximum_request_transmissions_per_assignment: Annotated[
        int,
        Field(gt=0, le=MAX_TRANSMISSIONS_PER_ASSIGNMENT),
    ]
    issue_close_round: Annotated[int, Field(gt=0)]
    response_close_round: Annotated[int, Field(gt=0)]
    reveal_round: Annotated[int, Field(gt=0)]
    maximum_request_body_bytes: Annotated[int, Field(gt=0, le=MAX_REQUEST_BODY_BYTES)]
    maximum_response_body_bytes: Annotated[int, Field(gt=0, le=MAX_RESPONSE_BODY_BYTES)]
    maximum_retained_prefix_bytes: Annotated[int, Field(ge=0, le=MAX_RETAINED_PREFIX_BYTES)]

    @model_validator(mode="after")
    def validate_rounds(self) -> Self:
        if not self.issue_close_round < self.response_close_round < self.reveal_round:
            raise ValueError("transcript rounds must be strictly ordered")
        return self


class EvidenceRef(StrictProtocolModel):
    sha256: Hex32
    media_type: Literal["application/json", "application/octet-stream"]
    size_bytes: Annotated[int, Field(ge=0, le=MAX_EVIDENCE_OBJECT_BYTES)]


class AuthHeader(StrictProtocolModel):
    name: Annotated[str, Field(min_length=1, max_length=256)]
    value: Annotated[str, Field(max_length=16 * 1024)]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value != value.lower():
            raise ValueError("stored authentication header names must be lowercase")
        return value


class PreparedAttemptEvidence(StrictProtocolModel):
    schema_: Literal[PREPARED_ATTEMPT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    assignment_id: Hex32
    attempt_index: Annotated[int, Field(ge=0, lt=MAX_TRANSMISSIONS_PER_ASSIGNMENT)]
    window_id: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    request_digest: Hex32
    request_object: EvidenceRef
    auth_headers: list[AuthHeader]
    auth_record: AuthRecord

    @model_validator(mode="after")
    def validate_headers(self) -> Self:
        pairs = [(item.name, item.value) for item in self.auth_headers]
        if pairs != sorted(pairs) or len({name for name, _value in pairs}) != len(pairs):
            raise ValueError("authentication headers must be unique and canonically ordered")
        if self.auth_record.sender != self.validator_hotkey:
            raise ValueError("authentication record binds another validator")
        if self.auth_record.receiver != self.miner_hotkey:
            raise ValueError("authentication record binds another miner")
        return self


class AttemptOutcomeEvidence(StrictProtocolModel):
    schema_: Literal[ATTEMPT_OUTCOME_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    assignment_id: Hex32
    attempt_index: Annotated[int, Field(ge=0, lt=MAX_TRANSMISSIONS_PER_ASSIGNMENT)]
    recorded_at_round: Annotated[int, Field(gt=0)]
    received_block: Annotated[int, Field(ge=0)] | None
    received_round: Annotated[int, Field(gt=0)] | None
    sealed_response_record: SealedResponseRecord
    retained_body: EvidenceRef | None

    @model_validator(mode="after")
    def validate_received_pair(self) -> Self:
        if (self.received_block is None) != (self.received_round is None):
            raise ValueError("received block and round must appear together")
        if self.received_round is not None and self.received_round > self.recorded_at_round:
            raise ValueError("outcome was recorded before its claimed receipt round")
        disposition = self.sealed_response_record.disposition
        if disposition == "sealed" and self.retained_body is None:
            raise ValueError("sealed outcome must retain the exact envelope bytes")
        if disposition == "missing" and (
            self.received_block is not None or self.retained_body is not None
        ):
            raise ValueError("missing outcome cannot claim received bytes")
        return self


class FreezeEvidence(StrictProtocolModel):
    schema_: Literal[FREEZE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    kind: Literal["assignment_set", "request_set", "response_set"]
    window_id: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    observed_round: Annotated[int, Field(gt=0)]
    root: Hex32
    record_count: Annotated[int, Field(gt=0, le=MAX_ASSIGNMENTS_PER_WINDOW)]
    member_leaves: list[Hex32]

    @model_validator(mode="after")
    def validate_members(self) -> Self:
        if len(self.member_leaves) != self.record_count:
            raise ValueError("freeze member count does not reproduce")
        raw = [bytes.fromhex(item) for item in self.member_leaves]
        if raw != sorted(raw) or len(set(raw)) != len(raw):
            raise ValueError("freeze members must be unique and sorted by raw digest")
        return self


@dataclass(frozen=True, slots=True)
class AttemptOutcomeInput:
    sealed_response_record: SealedResponseRecord
    recorded_at_round: int
    received_block: int | None = None
    received_round: int | None = None
    body_or_prefix: bytes | None = None

    def __post_init__(self) -> None:
        if type(self.sealed_response_record) is not SealedResponseRecord:
            raise TypeError("sealed_response_record must be an exact SealedResponseRecord")
        _positive_int(self.recorded_at_round, "recorded-at round")
        if (self.received_block is None) != (self.received_round is None):
            raise ValueError("received block and round must appear together")
        if self.received_block is not None:
            _nonnegative_int(self.received_block, "received block")
            _positive_int(self.received_round, "received round")
        if self.body_or_prefix is not None and not isinstance(self.body_or_prefix, bytes):
            raise TypeError("body_or_prefix must be exact bytes")


@dataclass(frozen=True, slots=True)
class AttemptSnapshot:
    assignment_id: str
    attempt_index: int
    prepared_evidence_ref: EvidenceRef
    prepared: PreparedRequestAttempt
    issued: bool
    claim_operation_id: str | None
    outcome_evidence_ref: EvidenceRef | None
    outcome: AttemptOutcomeEvidence | None
    final: bool


@dataclass(frozen=True, slots=True)
class SendClaim:
    attempt: AttemptSnapshot
    should_send: bool


@dataclass(frozen=True, slots=True)
class TranscriptMaterialBinding:
    """Immutable pool-stage material identity replayed by every transcript effect."""

    material_sha256: str
    material_receipt_sha256: str
    pool_stage_evidence_sha256: str

    def __post_init__(self) -> None:
        _hex32(self.material_sha256, "window material digest")
        _hex32(self.material_receipt_sha256, "window material receipt digest")
        _hex32(self.pool_stage_evidence_sha256, "pool-stage evidence digest")


class RequestStageLease:
    """Nonblocking OS lease automatically released if its process exits.

    SQLite cannot safely hold a write transaction while miner I/O is in flight.
    ``flock`` supplies the missing cross-process exclusion without a stale timeout:
    the kernel releases the lease on descriptor close or process death.
    """

    __slots__ = ("_descriptor", "operation_id", "path", "window_id")

    def __init__(
        self,
        descriptor: int,
        path: Path,
        *,
        window_id: str,
        operation_id: str,
    ) -> None:
        self._descriptor: int | None = descriptor
        self.path = path
        self.window_id = window_id
        self.operation_id = operation_id

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> RequestStageLease:
        if self._descriptor is None:
            raise AssignmentStoreError("request-stage lease is already released")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


@dataclass(frozen=True, slots=True)
class FrozenRoot:
    kind: str
    root: str
    evidence_sha256: str
    evidence: FreezeEvidence


@dataclass(frozen=True, slots=True)
class WindowSnapshot:
    spec: TranscriptWindowSpec
    phase: TranscriptPhase
    assignment_root: str | None
    request_root: str | None
    response_root: str | None


def deterministic_assignment_id(prepared: PreparedRequestAttempt) -> str:
    """Bind assignment identity to window, validator, miner, and exact request digest."""

    if not isinstance(prepared, PreparedRequestAttempt):
        raise TypeError("prepared must be a PreparedRequestAttempt")
    return sha256_domain(
        _ASSIGNMENT_ID_DOMAIN,
        bytes.fromhex(prepared.request.window_id),
        account_id32(prepared.validator_hotkey),
        account_id32(prepared.miner_hotkey),
        bytes.fromhex(request_digest(prepared.request)),
    ).hex()


class ValidatorAssignmentStore:
    """SQLite-authoritative transcript state plus immutable exact evidence."""

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_evidence_object_bytes: int = MAX_EVIDENCE_OBJECT_BYTES,
        maximum_total_evidence_bytes: int = MAX_TOTAL_EVIDENCE_BYTES,
        maximum_evidence_objects: int = MAX_EVIDENCE_OBJECTS,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self.root = Path(root)
        _ensure_real_directory(self.root)
        self.database_path = self.root / "transcripts.sqlite3"
        if os.path.lexists(self.database_path) and self.database_path.is_symlink():
            raise AssignmentStoreError("transcript database must not be a symlink")
        self._busy_timeout_ms = _bounded_int(busy_timeout_ms, 1, 60_000, "busy timeout")
        self._objects = _TranscriptObjectStore(
            self.root / "objects",
            maximum_object_bytes=maximum_evidence_object_bytes,
            maximum_total_bytes=maximum_total_evidence_bytes,
            maximum_objects=maximum_evidence_objects,
        )
        self._lease_root = self.root / "request-stage-leases"
        _ensure_real_directory(self._lease_root)
        self._initialize()
        self._audit_persisted_state()

    def bind_window_material(
        self,
        window_id: str,
        binding: TranscriptMaterialBinding,
    ) -> TranscriptMaterialBinding:
        """Insert or exactly replay the pool-authoritative material identity."""

        window_id = _hex32(window_id, "window ID")
        if not isinstance(binding, TranscriptMaterialBinding):
            raise TypeError("binding must be TranscriptMaterialBinding")
        values = (
            window_id,
            binding.material_sha256,
            binding.material_receipt_sha256,
            binding.pool_stage_evidence_sha256,
        )
        with self._transaction() as connection:
            self._require_window(connection, window_id)
            existing = connection.execute(
                "SELECT * FROM material_bindings WHERE window_id = ?",
                (window_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO material_bindings (
                        window_id, material_sha256, material_receipt_sha256,
                        pool_stage_evidence_sha256
                    ) VALUES (?, ?, ?, ?)
                    """,
                    values,
                )
            elif tuple(existing) != values:
                raise AssignmentConflict(
                    "transcript window is bound to different pool-stage material"
                )
        return binding

    def load_window_material(self, window_id: str) -> TranscriptMaterialBinding | None:
        window_id = _hex32(window_id, "window ID")
        with self._connection() as connection:
            self._require_window(connection, window_id)
            row = connection.execute(
                "SELECT * FROM material_bindings WHERE window_id = ?",
                (window_id,),
            ).fetchone()
            if row is None:
                return None
            return self._material_binding(row)

    def acquire_request_stage_lease(
        self,
        window_id: str,
        *,
        operation_id: str,
    ) -> RequestStageLease:
        """Acquire this window's request-stage lease without blocking.

        A busy lease is pending work, not a validator fault.  The lock file is
        inert evidence only; ownership comes exclusively from the live kernel
        lease, so a crashed process cannot strand the window indefinitely.
        """

        window_id = _hex32(window_id, "window ID")
        operation_id = _operation_id(operation_id)
        with self._connection() as connection:
            self._require_window(connection, window_id)
        path = self._lease_root / f"{window_id}.lock"
        if os.path.lexists(path) and path.is_symlink():
            raise AssignmentStoreError("request-stage lease must not be a symlink")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as error:
            raise AssignmentStoreError("request-stage lease cannot be opened safely") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise AssignmentStoreError("request-stage lease is not a private regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise RequestStageLeaseBusy(
                        "another process owns the request-stage lease"
                    ) from error
                raise AssignmentStoreError("request-stage lease acquisition failed") from error
            owner = canonical_json_bytes(
                {
                    "schema": "umi-validator-request-stage-lease/1",
                    "window_id": window_id,
                    "operation_id": operation_id,
                    "pid": os.getpid(),
                }
            )
            os.ftruncate(descriptor, 0)
            offset = 0
            while offset < len(owner):
                written = os.write(descriptor, owner[offset:])
                if written <= 0:
                    raise OSError("request-stage lease write made no progress")
                offset += written
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
            return RequestStageLease(
                descriptor,
                path,
                window_id=window_id,
                operation_id=operation_id,
            )
        except BaseException:
            os.close(descriptor)
            raise

    def list_orphaned_send_claims(self, window_id: str) -> tuple[AttemptSnapshot, ...]:
        """Return issued attempts whose network outcome is unknowable after restart."""

        window_id = _hex32(window_id, "window ID")
        with self._connection() as connection:
            self._require_window(connection, window_id)
            return tuple(
                self._attempt_snapshot(connection, row)
                for row in connection.execute(
                    """
                    SELECT * FROM attempts
                    WHERE window_id = ? AND issued = 1 AND outcome_sha256 IS NULL
                    ORDER BY assignment_id, attempt_index
                    """,
                    (window_id,),
                )
            )

    def create_window(self, spec: TranscriptWindowSpec) -> WindowSnapshot:
        if not isinstance(spec, TranscriptWindowSpec):
            raise TypeError("spec must be a TranscriptWindowSpec")
        spec_ref = self._objects.add(canonical_json_bytes(spec), "application/json")
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM windows WHERE window_id = ?",
                (spec.window_id,),
            ).fetchone()
            if existing is not None:
                if existing["spec_sha256"] != spec_ref.sha256:
                    raise AssignmentConflict("window ID is already bound to another spec")
                return self._window_snapshot(connection, existing)
            connection.execute(
                """
                INSERT INTO windows (
                    window_id, spec_sha256, spec_size_bytes, validator_hotkey,
                    expected_assignment_count, maximum_transmissions,
                    issue_close_round, response_close_round, reveal_round,
                    maximum_request_body_bytes, maximum_response_body_bytes,
                    maximum_retained_prefix_bytes, phase,
                    assignment_root, assignment_freeze_sha256, assignment_freeze_size_bytes,
                    request_root, request_freeze_sha256, request_freeze_size_bytes,
                    response_root, response_freeze_sha256, response_freeze_size_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL,
                          NULL, NULL, NULL, NULL, NULL, NULL)
                """,
                (
                    spec.window_id,
                    spec_ref.sha256,
                    spec_ref.size_bytes,
                    spec.validator_hotkey,
                    spec.expected_assignment_count,
                    spec.maximum_request_transmissions_per_assignment,
                    spec.issue_close_round,
                    spec.response_close_round,
                    spec.reveal_round,
                    spec.maximum_request_body_bytes,
                    spec.maximum_response_body_bytes,
                    spec.maximum_retained_prefix_bytes,
                    TranscriptPhase.COLLECTING_ASSIGNMENTS.value,
                ),
            )
            return self._window_snapshot(
                connection,
                connection.execute(
                    "SELECT * FROM windows WHERE window_id = ?",
                    (spec.window_id,),
                ).fetchone(),
            )

    def add_assignment(
        self,
        window_id: str,
        prepared: PreparedRequestAttempt,
        *,
        observed_round: int,
    ) -> AttemptSnapshot:
        window_id = _hex32(window_id, "window ID")
        _positive_int(observed_round, "observed round")
        if not isinstance(prepared, PreparedRequestAttempt):
            raise TypeError("prepared must be a PreparedRequestAttempt")
        assignment_id = deterministic_assignment_id(prepared)
        with self._transaction() as connection:
            window = self._require_window(connection, window_id)
            spec = self._load_spec(window)
            self._validate_prepared_for_window(prepared, spec)
            evidence_ref = self._store_prepared(prepared, assignment_id, 0, spec)
            existing = connection.execute(
                "SELECT * FROM assignments WHERE assignment_id = ?",
                (assignment_id,),
            ).fetchone()
            if existing is not None:
                attempt = self._require_attempt(connection, assignment_id, 0)
                if attempt["prepared_sha256"] != evidence_ref.sha256:
                    raise AssignmentConflict(
                        "deterministic assignment is bound to another initial attempt"
                    )
                return self._attempt_snapshot(connection, attempt)
            if observed_round >= spec.issue_close_round:
                raise AssignmentPhaseError(
                    "initial assignment preparation is at or after issue close"
                )
            if TranscriptPhase(window["phase"]) is not TranscriptPhase.COLLECTING_ASSIGNMENTS:
                raise AssignmentPhaseError("assignment set is already frozen")
            count = connection.execute(
                "SELECT COUNT(*) FROM assignments WHERE window_id = ?",
                (window_id,),
            ).fetchone()[0]
            if count >= spec.expected_assignment_count:
                raise AssignmentConflict("assignment count exceeds the declared cardinality")
            nonce = prepared.auth_evidence.auth_record.nonce
            try:
                connection.execute(
                    """
                    INSERT INTO assignments (
                        assignment_id, window_id, miner_hotkey, request_digest
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        assignment_id,
                        window_id,
                        prepared.miner_hotkey,
                        request_digest(prepared.request),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO attempts (
                        assignment_id, window_id, attempt_index, prepared_sha256,
                        prepared_size_bytes, nonce_text, issued, claim_operation_id,
                        outcome_sha256, outcome_size_bytes, disposition, final
                    ) VALUES (?, ?, 0, ?, ?, ?, 0, NULL, NULL, NULL, NULL, 0)
                    """,
                    (
                        assignment_id,
                        window_id,
                        evidence_ref.sha256,
                        evidence_ref.size_bytes,
                        nonce,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise AssignmentConflict("initial authentication nonce is not unique") from error
            return self._attempt_snapshot(
                connection,
                self._require_attempt(connection, assignment_id, 0),
            )

    def add_retry(
        self,
        assignment_id: str,
        prepared: PreparedRequestAttempt,
        *,
        observed_round: int,
    ) -> AttemptSnapshot:
        assignment_id = _hex32(assignment_id, "assignment ID")
        _positive_int(observed_round, "observed round")
        if not isinstance(prepared, PreparedRequestAttempt):
            raise TypeError("prepared must be a PreparedRequestAttempt")
        with self._transaction() as connection:
            assignment = self._require_assignment(connection, assignment_id)
            window = self._require_window(connection, assignment["window_id"])
            spec = self._load_spec(window)
            self._validate_prepared_for_window(prepared, spec)
            initial = self._attempt_snapshot(
                connection,
                self._require_attempt(connection, assignment_id, 0),
            ).prepared
            if (
                prepared.request_bytes != initial.request_bytes
                or prepared.miner_hotkey != initial.miner_hotkey
                or prepared.validator_hotkey != initial.validator_hotkey
            ):
                raise AssignmentConflict("retry changes the deterministic assignment")
            rows = connection.execute(
                "SELECT * FROM attempts WHERE assignment_id = ? ORDER BY attempt_index",
                (assignment_id,),
            ).fetchall()
            for row in rows:
                row_index = int(row["attempt_index"])
                digest = self._prepared_evidence_digest(
                    prepared,
                    assignment_id,
                    row_index,
                    spec,
                )
                if row["prepared_sha256"] == digest:
                    if row_index == 0:
                        raise AssignmentConflict("retry must use fresh authentication evidence")
                    return self._attempt_snapshot(connection, row)
            if TranscriptPhase(window["phase"]) is not TranscriptPhase.ASSIGNMENTS_FROZEN:
                raise AssignmentPhaseError("retry preparation is outside the open request phase")
            if observed_round >= spec.response_close_round:
                raise AssignmentPhaseError("retry preparation is at or after response close")
            if len(rows) >= spec.maximum_request_transmissions_per_assignment:
                raise AssignmentPhaseError("request transmission ceiling is exhausted")
            previous = rows[-1]
            if not previous["issued"] or previous["outcome_sha256"] is None:
                raise AssignmentPhaseError("a retry requires the preceding attempt outcome")
            if previous["final"]:
                raise AssignmentPhaseError("a valid final response forbids retry")
            nonce = prepared.auth_evidence.auth_record.nonce
            if int(nonce) <= int(previous["nonce_text"]):
                raise AssignmentConflict("retry authentication nonce must be fresh and increasing")
            index = len(rows)
            evidence_ref = self._store_prepared(prepared, assignment_id, index, spec)
            try:
                connection.execute(
                    """
                    INSERT INTO attempts (
                        assignment_id, window_id, attempt_index, prepared_sha256,
                        prepared_size_bytes, nonce_text, issued, claim_operation_id,
                        outcome_sha256, outcome_size_bytes, disposition, final
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, NULL, 0)
                    """,
                    (
                        assignment_id,
                        assignment["window_id"],
                        index,
                        evidence_ref.sha256,
                        evidence_ref.size_bytes,
                        nonce,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise AssignmentConflict("retry authentication nonce is not unique") from error
            return self._attempt_snapshot(
                connection,
                self._require_attempt(connection, assignment_id, index),
            )

    def claim_for_send(
        self,
        assignment_id: str,
        attempt_index: int,
        *,
        operation_id: str,
        observed_round: int,
    ) -> SendClaim:
        assignment_id = _hex32(assignment_id, "assignment ID")
        _nonnegative_int(attempt_index, "attempt index")
        operation_id = _operation_id(operation_id)
        _positive_int(observed_round, "observed round")
        with self._transaction() as connection:
            row = self._require_attempt(connection, assignment_id, attempt_index)
            window = self._require_window(connection, row["window_id"])
            spec = self._load_spec(window)
            if row["issued"]:
                if row["claim_operation_id"] != operation_id:
                    raise AssignmentConflict("attempt was claimed by another operation")
                return SendClaim(self._attempt_snapshot(connection, row), False)
            if TranscriptPhase(window["phase"]) is not TranscriptPhase.ASSIGNMENTS_FROZEN:
                raise AssignmentPhaseError("attempt is not in the open issuance phase")
            deadline = spec.issue_close_round if attempt_index == 0 else spec.response_close_round
            if observed_round >= deadline:
                raise AssignmentPhaseError("attempt claim is at or after its issuance close")
            if row["outcome_sha256"] is not None:
                raise AssignmentPhaseError("attempt already has an outcome")
            connection.execute(
                """
                UPDATE attempts SET issued = 1, claim_operation_id = ?
                WHERE assignment_id = ? AND attempt_index = ?
                """,
                (operation_id, assignment_id, attempt_index),
            )
            return SendClaim(
                self._attempt_snapshot(
                    connection,
                    self._require_attempt(connection, assignment_id, attempt_index),
                ),
                True,
            )

    def record_outcome(
        self,
        assignment_id: str,
        attempt_index: int,
        outcome: AttemptOutcomeInput,
    ) -> AttemptSnapshot:
        assignment_id = _hex32(assignment_id, "assignment ID")
        _nonnegative_int(attempt_index, "attempt index")
        if not isinstance(outcome, AttemptOutcomeInput):
            raise TypeError("outcome must be AttemptOutcomeInput")
        with self._transaction() as connection:
            row = self._require_attempt(connection, assignment_id, attempt_index)
            window = self._require_window(connection, row["window_id"])
            spec = self._load_spec(window)
            if outcome.recorded_at_round >= spec.reveal_round:
                raise AssignmentPhaseError("attempt outcome is at or after reveal")
            if not row["issued"]:
                raise AssignmentPhaseError("an unissued attempt cannot have an outcome")
            prepared = self._attempt_snapshot(connection, row).prepared
            evidence_ref, evidence = self._store_outcome(
                assignment_id,
                attempt_index,
                prepared,
                outcome,
                spec,
            )
            if row["outcome_sha256"] is not None:
                if row["outcome_sha256"] != evidence_ref.sha256:
                    raise AssignmentConflict("attempt already has another outcome")
                return self._attempt_snapshot(connection, row)
            if TranscriptPhase(window["phase"]) is TranscriptPhase.RESPONSES_FROZEN:
                raise AssignmentPhaseError("response set is already frozen")
            later = connection.execute(
                """
                SELECT 1 FROM attempts
                WHERE assignment_id = ? AND attempt_index > ? LIMIT 1
                """,
                (assignment_id, attempt_index),
            ).fetchone()
            if later is not None:
                raise AssignmentConflict("outcome insertion would rewrite retry history")
            final = evidence.sealed_response_record.disposition == "sealed"
            if final:
                existing_final = connection.execute(
                    "SELECT 1 FROM attempts WHERE assignment_id = ? AND final = 1",
                    (assignment_id,),
                ).fetchone()
                if existing_final is not None:
                    raise AssignmentConflict("assignment already has a final sealed response")
            connection.execute(
                """
                UPDATE attempts
                SET outcome_sha256 = ?, outcome_size_bytes = ?, disposition = ?, final = ?
                WHERE assignment_id = ? AND attempt_index = ?
                """,
                (
                    evidence_ref.sha256,
                    evidence_ref.size_bytes,
                    evidence.sealed_response_record.disposition,
                    int(final),
                    assignment_id,
                    attempt_index,
                ),
            )
            return self._attempt_snapshot(
                connection,
                self._require_attempt(connection, assignment_id, attempt_index),
            )

    def freeze_assignments(self, window_id: str, *, observed_round: int) -> FrozenRoot:
        return self._freeze(window_id, "assignment_set", observed_round)

    def freeze_requests(self, window_id: str, *, observed_round: int) -> FrozenRoot:
        return self._freeze(window_id, "request_set", observed_round)

    def freeze_responses(self, window_id: str, *, observed_round: int) -> FrozenRoot:
        return self._freeze(window_id, "response_set", observed_round)

    def load_window(self, window_id: str) -> WindowSnapshot:
        window_id = _hex32(window_id, "window ID")
        with self._connection() as connection:
            return self._window_snapshot(connection, self._require_window(connection, window_id))

    def list_attempts(self, assignment_id: str) -> tuple[AttemptSnapshot, ...]:
        assignment_id = _hex32(assignment_id, "assignment ID")
        with self._connection() as connection:
            self._require_assignment(connection, assignment_id)
            return tuple(
                self._attempt_snapshot(connection, row)
                for row in connection.execute(
                    "SELECT * FROM attempts WHERE assignment_id = ? ORDER BY attempt_index",
                    (assignment_id,),
                )
            )

    def read_evidence(self, reference: EvidenceRef) -> bytes:
        """Read and reverify an exact content-addressed transcript object."""

        return self._objects.read(reference)

    def _freeze(self, window_id: str, kind: str, observed_round: int) -> FrozenRoot:
        window_id = _hex32(window_id, "window ID")
        _positive_int(observed_round, "observed round")
        column = {
            "assignment_set": ("assignment_root", "assignment_freeze"),
            "request_set": ("request_root", "request_freeze"),
            "response_set": ("response_root", "response_freeze"),
        }.get(kind)
        if column is None:
            raise ValueError("unsupported transcript freeze kind")
        with self._transaction() as connection:
            window = self._require_window(connection, window_id)
            spec = self._load_spec(window)
            root_column, prefix = column
            if window[root_column] is not None:
                return self._load_frozen_root(window, kind, prefix)
            phase = TranscriptPhase(window["phase"])
            expected_phase = {
                "assignment_set": TranscriptPhase.COLLECTING_ASSIGNMENTS,
                "request_set": TranscriptPhase.ASSIGNMENTS_FROZEN,
                "response_set": TranscriptPhase.REQUESTS_FROZEN,
            }[kind]
            if phase is not expected_phase:
                raise AssignmentPhaseError(f"{kind} cannot freeze from {phase.value}")
            if kind in {"assignment_set", "request_set"}:
                deadline = (
                    spec.issue_close_round
                    if kind == "assignment_set"
                    else spec.response_close_round
                )
                if observed_round >= deadline:
                    raise AssignmentPhaseError(f"{kind} freeze is at or after its close")
            elif not spec.response_close_round <= observed_round < spec.reveal_round:
                raise AssignmentPhaseError(
                    "response set must freeze after response close and before reveal"
                )
            assignments, requests, responses = self._anchor_records(connection, spec)
            if len(assignments) != spec.expected_assignment_count:
                raise AssignmentConflict("assignment cardinality is incomplete")
            if kind == "assignment_set":
                root = assignment_set_root(
                    assignments,
                    window_id=window_id,
                    validator_hotkey=spec.validator_hotkey,
                )
                leaves = [record.leaf for record in assignments]
                next_phase = TranscriptPhase.ASSIGNMENTS_FROZEN
            elif kind == "request_set":
                unissued = connection.execute(
                    """
                    SELECT 1 FROM attempts WHERE window_id = ? AND issued = 0 LIMIT 1
                    """,
                    (window_id,),
                ).fetchone()
                if unissued is not None:
                    raise AssignmentConflict("request transcript contains an unissued attempt")
                root = request_set_root(
                    requests,
                    assignments=assignments,
                    window_id=window_id,
                    validator_hotkey=spec.validator_hotkey,
                )
                leaves = [record.leaf for record in requests]
                next_phase = TranscriptPhase.REQUESTS_FROZEN
            else:
                missing = connection.execute(
                    """
                    SELECT 1 FROM attempts
                    WHERE window_id = ? AND outcome_sha256 IS NULL LIMIT 1
                    """,
                    (window_id,),
                ).fetchone()
                if missing is not None:
                    raise AssignmentConflict("response freeze requires one outcome per attempt")
                root = response_set_root(
                    responses,
                    request_records=requests,
                    window_id=window_id,
                    validator_hotkey=spec.validator_hotkey,
                )
                leaves = [record.leaf for record in responses]
                next_phase = TranscriptPhase.RESPONSES_FROZEN
            evidence = FreezeEvidence(
                schema=FREEZE_SCHEMA,
                protocol=PROTOCOL_VERSION,
                kind=kind,
                window_id=window_id,
                validator_hotkey=spec.validator_hotkey,
                observed_round=observed_round,
                root=root.hex(),
                record_count=len(leaves),
                member_leaves=sorted(item.hex() for item in leaves),
            )
            evidence_ref = self._objects.add(canonical_json_bytes(evidence), "application/json")
            connection.execute(
                f"""
                UPDATE windows
                SET phase = ?, {root_column} = ?,
                    {prefix}_sha256 = ?, {prefix}_size_bytes = ?
                WHERE window_id = ?
                """,
                (
                    next_phase.value,
                    root.hex(),
                    evidence_ref.sha256,
                    evidence_ref.size_bytes,
                    window_id,
                ),
            )
            return FrozenRoot(kind, root.hex(), evidence_ref.sha256, evidence)

    def _anchor_records(
        self,
        connection: sqlite3.Connection,
        spec: TranscriptWindowSpec,
    ) -> tuple[
        tuple[AssignmentAnchorRecord, ...],
        tuple[RequestAnchorRecord, ...],
        tuple[ResponseAnchorRecord, ...],
    ]:
        assignments: list[AssignmentAnchorRecord] = []
        requests: list[RequestAnchorRecord] = []
        responses: list[ResponseAnchorRecord] = []
        rows = connection.execute(
            "SELECT * FROM assignments WHERE window_id = ? ORDER BY assignment_id",
            (spec.window_id,),
        ).fetchall()
        for assignment in rows:
            attempts = connection.execute(
                "SELECT * FROM attempts WHERE assignment_id = ? ORDER BY attempt_index",
                (assignment["assignment_id"],),
            ).fetchall()
            prepared = [self._attempt_snapshot(connection, row) for row in attempts]
            if not prepared:
                raise AssignmentConflict("assignment has no initial attempt")
            assignment_record = AssignmentAnchorRecord(
                initial_auth_evidence=prepared[0].prepared.auth_evidence,
            )
            request_record = RequestAnchorRecord(
                auth_evidence=tuple(item.prepared.auth_evidence for item in prepared),
            )
            assignments.append(assignment_record)
            requests.append(request_record)
            outcomes = [item for item in prepared if item.outcome is not None]
            final = next((item for item in outcomes if item.final), None)
            selected = final or (outcomes[-1] if outcomes else None)
            if selected is not None:
                responses.append(
                    ResponseAnchorRecord(
                        request_leaf=request_record.leaf,
                        sealed_response_record=selected.outcome.sealed_response_record,
                    )
                )
        return tuple(assignments), tuple(requests), tuple(responses)

    def _store_prepared(
        self,
        prepared: PreparedRequestAttempt,
        assignment_id: str,
        attempt_index: int,
        spec: TranscriptWindowSpec,
    ) -> EvidenceRef:
        if len(prepared.request_bytes) > spec.maximum_request_body_bytes:
            raise AssignmentConflict("canonical request exceeds the policy body ceiling")
        request_ref = self._objects.add(prepared.request_bytes, "application/json")
        evidence = PreparedAttemptEvidence(
            schema=PREPARED_ATTEMPT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            assignment_id=assignment_id,
            attempt_index=attempt_index,
            window_id=spec.window_id,
            validator_hotkey=prepared.validator_hotkey,
            miner_hotkey=prepared.miner_hotkey,
            request_digest=request_digest(prepared.request),
            request_object=request_ref,
            auth_headers=[
                AuthHeader(name=name, value=value) for name, value in prepared.auth_headers
            ],
            auth_record=prepared.auth_evidence.auth_record,
        )
        return self._objects.add(canonical_json_bytes(evidence), "application/json")

    def _prepared_evidence_digest(
        self,
        prepared: PreparedRequestAttempt,
        assignment_id: str,
        attempt_index: int,
        spec: TranscriptWindowSpec,
    ) -> str:
        request_ref = EvidenceRef(
            sha256=hashlib.sha256(prepared.request_bytes).hexdigest(),
            media_type="application/json",
            size_bytes=len(prepared.request_bytes),
        )
        evidence = PreparedAttemptEvidence(
            schema=PREPARED_ATTEMPT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            assignment_id=assignment_id,
            attempt_index=attempt_index,
            window_id=spec.window_id,
            validator_hotkey=prepared.validator_hotkey,
            miner_hotkey=prepared.miner_hotkey,
            request_digest=request_digest(prepared.request),
            request_object=request_ref,
            auth_headers=[
                AuthHeader(name=name, value=value) for name, value in prepared.auth_headers
            ],
            auth_record=prepared.auth_evidence.auth_record,
        )
        return hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()

    def _store_outcome(
        self,
        assignment_id: str,
        attempt_index: int,
        prepared: PreparedRequestAttempt,
        outcome: AttemptOutcomeInput,
        spec: TranscriptWindowSpec,
    ) -> tuple[EvidenceRef, AttemptOutcomeEvidence]:
        record = outcome.sealed_response_record
        disposition = record.disposition
        body_ref: EvidenceRef | None = None
        body = outcome.body_or_prefix
        if (
            outcome.received_block is not None
            and outcome.received_block < prepared.request.issued_block
        ):
            raise AssignmentConflict("response receipt predates request issuance")
        if disposition == "sealed":
            if outcome.received_block is None or outcome.received_round is None or body is None:
                raise AssignmentConflict("sealed outcome requires exact receipt time and body")
            if outcome.received_block > prepared.request.deadline_block:
                raise AssignmentConflict("sealed response is later than its block deadline")
            if outcome.received_round >= spec.response_close_round:
                raise AssignmentConflict("sealed response is at or after response close")
            if len(body) > spec.maximum_response_body_bytes:
                raise AssignmentConflict("sealed response exceeds the response body ceiling")
            if hashlib.sha256(body).hexdigest() != record.wire_envelope_sha256:
                raise AssignmentConflict("sealed response body hash does not reproduce")
            try:
                envelope, _sealed = validate_response_envelope(
                    body,
                    record.signature,
                    request=prepared.request,
                    validator_hotkey=prepared.validator_hotkey,
                    miner_hotkey=prepared.miner_hotkey,
                )
            except (TypeError, ValueError) as error:
                raise AssignmentConflict("sealed response envelope is invalid") from error
            if (
                envelope.signature_scheme != record.signature_scheme
                or envelope.serving_hotkey != record.serving_hotkey
            ):
                raise AssignmentConflict("sealed response record disagrees with its envelope")
            body_ref = self._objects.add(body, "application/json")
        else:
            if disposition == "missing":
                if outcome.recorded_at_round < spec.response_close_round:
                    raise AssignmentPhaseError(
                        "missing outcome cannot be fixed before response close"
                    )
                if body is not None or record.received_bytes_sha256 is not None:
                    raise AssignmentConflict("missing outcome cannot retain response bytes")
            elif disposition == "late":
                if outcome.received_block is None or outcome.received_round is None:
                    raise AssignmentConflict("late outcome requires exact receipt time")
                if (
                    outcome.received_block <= prepared.request.deadline_block
                    and outcome.received_round < spec.response_close_round
                ):
                    raise AssignmentConflict("late marker is inside both response deadlines")
            if body is not None:
                if len(body) > spec.maximum_retained_prefix_bytes:
                    raise AssignmentConflict("failure prefix exceeds its retention ceiling")
                digest = hashlib.sha256(body).hexdigest()
                if record.received_bytes_sha256 != digest:
                    raise AssignmentConflict("failure prefix hash does not reproduce")
                body_ref = self._objects.add(body, "application/octet-stream")
            elif record.received_bytes_sha256 is not None:
                raise AssignmentConflict("failure marker references a prefix it did not retain")
        evidence = AttemptOutcomeEvidence(
            schema=ATTEMPT_OUTCOME_SCHEMA,
            protocol=PROTOCOL_VERSION,
            assignment_id=assignment_id,
            attempt_index=attempt_index,
            recorded_at_round=outcome.recorded_at_round,
            received_block=outcome.received_block,
            received_round=outcome.received_round,
            sealed_response_record=record,
            retained_body=body_ref,
        )
        encoded = canonical_json_bytes(evidence)
        if len(encoded) > MAX_EVIDENCE_OBJECT_BYTES:
            raise AssignmentConflict("attempt outcome evidence exceeds its hard ceiling")
        return self._objects.add(encoded, "application/json"), evidence

    def _validate_prepared_for_window(
        self,
        prepared: PreparedRequestAttempt,
        spec: TranscriptWindowSpec,
    ) -> None:
        if prepared.request.window_id != spec.window_id:
            raise AssignmentConflict("prepared request binds another window")
        if prepared.validator_hotkey != spec.validator_hotkey:
            raise AssignmentConflict("prepared request binds another validator")
        if prepared.request.response_close_round != spec.response_close_round:
            raise AssignmentConflict("prepared request binds another response-close round")
        if prepared.request.reveal_round != spec.reveal_round:
            raise AssignmentConflict("prepared request binds another reveal round")
        if prepared.request_bytes != canonical_json_bytes(prepared.request):
            raise AssignmentConflict("prepared request bytes are not canonical")

    def _attempt_snapshot(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AttemptSnapshot:
        assignment_id = row["assignment_id"]
        attempt_index = int(row["attempt_index"])
        prepared_ref = EvidenceRef(
            sha256=row["prepared_sha256"],
            media_type="application/json",
            size_bytes=row["prepared_size_bytes"],
        )
        prepared_evidence, prepared = self._load_prepared_ref(prepared_ref)
        if (
            prepared_evidence.assignment_id != assignment_id
            or prepared_evidence.attempt_index != attempt_index
            or prepared_evidence.window_id != row["window_id"]
        ):
            raise AssignmentStoreError("prepared-attempt evidence disagrees with its row")
        if prepared.auth_evidence.auth_record.nonce != row["nonce_text"]:
            raise AssignmentStoreError("prepared-attempt nonce disagrees with its row")
        if row["issued"] not in {0, 1} or row["final"] not in {0, 1}:
            raise AssignmentStoreError("attempt boolean columns are invalid")
        if row["claim_operation_id"] is not None:
            try:
                _operation_id(row["claim_operation_id"])
            except ValueError as error:
                raise AssignmentStoreError("persisted send operation ID is invalid") from error
        outcome = None
        outcome_ref = None
        if row["outcome_sha256"] is not None:
            outcome_ref = EvidenceRef(
                sha256=row["outcome_sha256"],
                media_type="application/json",
                size_bytes=row["outcome_size_bytes"],
            )
            outcome = self._load_outcome_ref(outcome_ref)
            if (
                outcome.assignment_id != assignment_id
                or outcome.attempt_index != attempt_index
                or outcome.sealed_response_record.disposition != row["disposition"]
            ):
                raise AssignmentStoreError("attempt-outcome evidence disagrees with its row")
            window = self._require_window(connection, row["window_id"])
            self._audit_outcome_semantics(prepared, outcome, self._load_spec(window))
        elif row["outcome_size_bytes"] is not None or row["disposition"] is not None:
            raise AssignmentStoreError("empty attempt outcome carries persisted metadata")
        return AttemptSnapshot(
            assignment_id=assignment_id,
            attempt_index=attempt_index,
            prepared_evidence_ref=prepared_ref,
            prepared=prepared,
            issued=bool(row["issued"]),
            claim_operation_id=row["claim_operation_id"],
            outcome_evidence_ref=outcome_ref,
            outcome=outcome,
            final=bool(row["final"]),
        )

    def _load_prepared_ref(
        self,
        reference: EvidenceRef,
    ) -> tuple[PreparedAttemptEvidence, PreparedRequestAttempt]:
        if reference.media_type != "application/json":
            raise AssignmentStoreError("prepared-attempt evidence has the wrong media type")
        evidence = _parse_canonical_model(
            self._objects.read(reference),
            PreparedAttemptEvidence,
            "prepared-attempt evidence",
        )
        if evidence.request_object.media_type != "application/json":
            raise AssignmentStoreError("stored translation request has the wrong media type")
        request_bytes = self._objects.read(evidence.request_object)
        try:
            request = TranslationRequest.model_validate_json(request_bytes)
        except ValueError as error:
            raise AssignmentStoreError("stored translation request is invalid") from error
        if canonical_json_bytes(request) != request_bytes:
            raise AssignmentStoreError("stored translation request is not canonical")
        if request_digest(request) != evidence.request_digest:
            raise AssignmentStoreError("stored translation request digest does not reproduce")
        headers = tuple((item.name, item.value) for item in evidence.auth_headers)
        verified = VerifiedAuthEvidence.from_headers(
            dict(headers),
            request=request,
            expected_validator_hotkey=evidence.validator_hotkey,
            expected_miner_hotkey=evidence.miner_hotkey,
        )
        if verified.auth_record != evidence.auth_record:
            raise AssignmentStoreError("stored auth record does not reproduce from headers")
        prepared = PreparedRequestAttempt(
            request=request,
            request_bytes=request_bytes,
            validator_hotkey=evidence.validator_hotkey,
            miner_hotkey=evidence.miner_hotkey,
            auth_headers=headers,
            auth_evidence=verified,
        )
        if deterministic_assignment_id(prepared) != evidence.assignment_id:
            raise AssignmentStoreError("stored deterministic assignment ID does not reproduce")
        return evidence, prepared

    def _load_outcome_ref(self, reference: EvidenceRef) -> AttemptOutcomeEvidence:
        if reference.media_type != "application/json":
            raise AssignmentStoreError("attempt-outcome evidence has the wrong media type")
        outcome = _parse_canonical_model(
            self._objects.read(reference),
            AttemptOutcomeEvidence,
            "attempt-outcome evidence",
        )
        self._load_outcome_body(outcome)
        return outcome

    def _load_outcome_body(self, outcome: AttemptOutcomeEvidence) -> bytes | None:
        reference = outcome.retained_body
        if reference is None:
            return None
        record = outcome.sealed_response_record
        expected_media_type = (
            "application/json" if record.disposition == "sealed" else "application/octet-stream"
        )
        if reference.media_type != expected_media_type:
            raise AssignmentStoreError("stored outcome body has the wrong media type")
        body = self._objects.read(reference)
        expected = (
            record.wire_envelope_sha256
            if record.disposition == "sealed"
            else record.received_bytes_sha256
        )
        if expected is None or hashlib.sha256(body).hexdigest() != expected:
            raise AssignmentStoreError("stored outcome body hash does not reproduce")
        return body

    def _audit_outcome_semantics(
        self,
        prepared: PreparedRequestAttempt,
        outcome: AttemptOutcomeEvidence,
        spec: TranscriptWindowSpec,
    ) -> None:
        if outcome.recorded_at_round >= spec.reveal_round:
            raise AssignmentStoreError("persisted attempt outcome is at or after reveal")
        if (
            outcome.received_block is not None
            and outcome.received_block < prepared.request.issued_block
        ):
            raise AssignmentStoreError("persisted response receipt predates request issuance")
        record = outcome.sealed_response_record
        body = self._load_outcome_body(outcome)
        if record.disposition == "sealed":
            if outcome.received_block is None or outcome.received_round is None or body is None:
                raise AssignmentStoreError("persisted sealed response lacks receipt evidence")
            if outcome.received_block > prepared.request.deadline_block:
                raise AssignmentStoreError("persisted sealed response misses its block deadline")
            if outcome.received_round >= spec.response_close_round:
                raise AssignmentStoreError(
                    "persisted sealed response is at or after response close"
                )
            if len(body) > spec.maximum_response_body_bytes:
                raise AssignmentStoreError("persisted sealed response exceeds its byte ceiling")
            try:
                envelope, _sealed = validate_response_envelope(
                    body,
                    record.signature,
                    request=prepared.request,
                    validator_hotkey=prepared.validator_hotkey,
                    miner_hotkey=prepared.miner_hotkey,
                )
            except (TypeError, ValueError) as error:
                raise AssignmentStoreError(
                    "persisted sealed response envelope is invalid"
                ) from error
            if (
                envelope.signature_scheme != record.signature_scheme
                or envelope.serving_hotkey != record.serving_hotkey
            ):
                raise AssignmentStoreError(
                    "persisted sealed-response record disagrees with its envelope"
                )
            return
        if record.disposition == "missing":
            if outcome.recorded_at_round < spec.response_close_round:
                raise AssignmentStoreError("persisted missing outcome predates response close")
            if (
                outcome.received_block is not None
                or body is not None
                or record.received_bytes_sha256 is not None
            ):
                raise AssignmentStoreError("persisted missing outcome claims response bytes")
            return
        if record.disposition == "late":
            if outcome.received_block is None or outcome.received_round is None:
                raise AssignmentStoreError("persisted late outcome lacks a receipt time")
            if (
                outcome.received_block <= prepared.request.deadline_block
                and outcome.received_round < spec.response_close_round
            ):
                raise AssignmentStoreError("persisted late outcome is inside both deadlines")
        if body is not None:
            if len(body) > spec.maximum_retained_prefix_bytes:
                raise AssignmentStoreError("persisted failure prefix exceeds its byte ceiling")
        elif record.received_bytes_sha256 is not None:
            raise AssignmentStoreError("persisted failure marker lacks its retained prefix")

    def _load_spec(self, window: sqlite3.Row) -> TranscriptWindowSpec:
        spec = _parse_canonical_model(
            self._objects.read(
                EvidenceRef(
                    sha256=window["spec_sha256"],
                    media_type="application/json",
                    size_bytes=window["spec_size_bytes"],
                )
            ),
            TranscriptWindowSpec,
            "window spec",
        )
        columns = (
            spec.window_id,
            spec.validator_hotkey,
            spec.expected_assignment_count,
            spec.maximum_request_transmissions_per_assignment,
            spec.issue_close_round,
            spec.response_close_round,
            spec.reveal_round,
            spec.maximum_request_body_bytes,
            spec.maximum_response_body_bytes,
            spec.maximum_retained_prefix_bytes,
        )
        stored = (
            window["window_id"],
            window["validator_hotkey"],
            window["expected_assignment_count"],
            window["maximum_transmissions"],
            window["issue_close_round"],
            window["response_close_round"],
            window["reveal_round"],
            window["maximum_request_body_bytes"],
            window["maximum_response_body_bytes"],
            window["maximum_retained_prefix_bytes"],
        )
        if columns != stored:
            raise AssignmentStoreError("window columns disagree with the canonical spec")
        return spec

    def _window_snapshot(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> WindowSnapshot:
        del connection
        return WindowSnapshot(
            spec=self._load_spec(row),
            phase=TranscriptPhase(row["phase"]),
            assignment_root=row["assignment_root"],
            request_root=row["request_root"],
            response_root=row["response_root"],
        )

    def _load_frozen_root(
        self,
        window: sqlite3.Row,
        kind: str,
        prefix: str,
    ) -> FrozenRoot:
        evidence = _parse_canonical_model(
            self._objects.read(
                EvidenceRef(
                    sha256=window[f"{prefix}_sha256"],
                    media_type="application/json",
                    size_bytes=window[f"{prefix}_size_bytes"],
                )
            ),
            FreezeEvidence,
            "freeze evidence",
        )
        root_column = prefix.removesuffix("_freeze") + "_root"
        if (
            evidence.kind != kind
            or evidence.root != window[root_column]
            or evidence.window_id != window["window_id"]
            or evidence.validator_hotkey != window["validator_hotkey"]
        ):
            raise AssignmentStoreError("freeze evidence disagrees with window state")
        if kind == "assignment_set" and evidence.observed_round >= window["issue_close_round"]:
            raise AssignmentStoreError("assignment freeze evidence is at or after issue close")
        if kind == "request_set" and evidence.observed_round >= window["response_close_round"]:
            raise AssignmentStoreError("request freeze evidence is at or after response close")
        if kind == "response_set" and not (
            window["response_close_round"] <= evidence.observed_round < window["reveal_round"]
        ):
            raise AssignmentStoreError("response freeze evidence is outside its valid interval")
        return FrozenRoot(kind, evidence.root, window[f"{prefix}_sha256"], evidence)

    def _audit_persisted_state(self) -> None:
        with self._connection() as connection:
            quick = connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick != "ok":
                raise AssignmentStoreError(f"transcript database quick_check failed: {quick}")
            version = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != "1":
                raise AssignmentStoreError("unsupported transcript database schema")
            for window in connection.execute("SELECT * FROM windows ORDER BY window_id"):
                self._audit_window(connection, window)
            dangling = connection.execute(
                """
                SELECT 1 FROM material_bindings AS binding
                LEFT JOIN windows AS window ON window.window_id = binding.window_id
                WHERE window.window_id IS NULL LIMIT 1
                """
            ).fetchone()
            if dangling is not None:
                raise AssignmentStoreError("material binding has no transcript window")

    def _audit_window(self, connection: sqlite3.Connection, window: sqlite3.Row) -> None:
        spec = self._load_spec(window)
        material = connection.execute(
            "SELECT * FROM material_bindings WHERE window_id = ?",
            (spec.window_id,),
        ).fetchone()
        if material is not None:
            self._material_binding(material)
        phase = TranscriptPhase(window["phase"])
        assignments = connection.execute(
            "SELECT * FROM assignments WHERE window_id = ? ORDER BY assignment_id",
            (spec.window_id,),
        ).fetchall()
        if len(assignments) > spec.expected_assignment_count:
            raise AssignmentStoreError("persisted assignment cardinality exceeds the spec")
        if phase is not TranscriptPhase.COLLECTING_ASSIGNMENTS and (
            len(assignments) != spec.expected_assignment_count
        ):
            raise AssignmentStoreError("frozen assignment cardinality is incomplete")
        for assignment in assignments:
            if assignment["window_id"] != spec.window_id:
                raise AssignmentStoreError("assignment row binds another window")
            rows = connection.execute(
                "SELECT * FROM attempts WHERE assignment_id = ? ORDER BY attempt_index",
                (assignment["assignment_id"],),
            ).fetchall()
            if not rows or [int(row["attempt_index"]) for row in rows] != list(range(len(rows))):
                raise AssignmentStoreError("persisted attempt indices are not contiguous")
            if len(rows) > spec.maximum_request_transmissions_per_assignment:
                raise AssignmentStoreError("persisted attempts exceed the transmission ceiling")
            snapshots = [self._attempt_snapshot(connection, row) for row in rows]
            initial = snapshots[0].prepared
            if deterministic_assignment_id(initial) != assignment["assignment_id"]:
                raise AssignmentStoreError("assignment identity does not reproduce")
            if request_digest(initial.request) != assignment["request_digest"]:
                raise AssignmentStoreError("assignment request digest does not reproduce")
            if initial.miner_hotkey != assignment["miner_hotkey"]:
                raise AssignmentStoreError("assignment miner does not reproduce")
            if any(row["window_id"] != spec.window_id for row in rows):
                raise AssignmentStoreError("attempt row binds another window")
            if phase is TranscriptPhase.COLLECTING_ASSIGNMENTS and (
                len(snapshots) != 1 or snapshots[0].issued or snapshots[0].outcome is not None
            ):
                raise AssignmentStoreError("collecting assignment state contains request activity")
            previous_nonce = -1
            final_seen = False
            for position, (snapshot, row) in enumerate(zip(snapshots, rows, strict=True)):
                prepared = snapshot.prepared
                self._validate_prepared_for_window(prepared, spec)
                if (
                    prepared.request_bytes != initial.request_bytes
                    or prepared.miner_hotkey != initial.miner_hotkey
                    or prepared.validator_hotkey != initial.validator_hotkey
                ):
                    raise AssignmentStoreError("retry changes its deterministic assignment")
                nonce = int(prepared.auth_evidence.auth_record.nonce)
                if nonce <= previous_nonce or str(nonce) != row["nonce_text"]:
                    raise AssignmentStoreError("attempt nonces are not fresh and increasing")
                previous_nonce = nonce
                if snapshot.issued != (snapshot.claim_operation_id is not None):
                    raise AssignmentStoreError("attempt claim fields disagree")
                if snapshot.outcome is not None and not snapshot.issued:
                    raise AssignmentStoreError("unissued attempt has an outcome")
                if snapshot.final != (
                    snapshot.outcome is not None
                    and snapshot.outcome.sealed_response_record.disposition == "sealed"
                ):
                    raise AssignmentStoreError("attempt final flag disagrees with its outcome")
                if final_seen:
                    raise AssignmentStoreError("valid final response has a later retry")
                final_seen = snapshot.final
                if position > 0:
                    preceding = snapshots[position - 1]
                    if not preceding.issued or preceding.outcome is None or preceding.final:
                        raise AssignmentStoreError(
                            "retry does not follow a completed nonfinal attempt"
                        )
            if phase in {
                TranscriptPhase.REQUESTS_FROZEN,
                TranscriptPhase.RESPONSES_FROZEN,
            } and any(not item.issued for item in snapshots):
                raise AssignmentStoreError("frozen request transcript has an unissued attempt")
            if phase is TranscriptPhase.RESPONSES_FROZEN and any(
                item.outcome is None for item in snapshots
            ):
                raise AssignmentStoreError("frozen response transcript lacks an outcome")
        anchor_assignments, anchor_requests, anchor_responses = self._anchor_records(
            connection,
            spec,
        )
        phase_index = list(TranscriptPhase).index(phase)
        roots = (
            (
                "assignment_set",
                "assignment_root",
                "assignment_freeze",
                anchor_assignments,
                lambda: assignment_set_root(
                    anchor_assignments,
                    window_id=spec.window_id,
                    validator_hotkey=spec.validator_hotkey,
                ),
            ),
            (
                "request_set",
                "request_root",
                "request_freeze",
                anchor_requests,
                lambda: request_set_root(
                    anchor_requests,
                    assignments=anchor_assignments,
                    window_id=spec.window_id,
                    validator_hotkey=spec.validator_hotkey,
                ),
            ),
            (
                "response_set",
                "response_root",
                "response_freeze",
                anchor_responses,
                lambda: response_set_root(
                    anchor_responses,
                    request_records=anchor_requests,
                    window_id=spec.window_id,
                    validator_hotkey=spec.validator_hotkey,
                ),
            ),
        )
        for index, (kind, root_column, prefix, records, calculate) in enumerate(roots, 1):
            frozen = phase_index >= index
            fields = (
                window[root_column],
                window[f"{prefix}_sha256"],
                window[f"{prefix}_size_bytes"],
            )
            if not frozen:
                if any(value is not None for value in fields):
                    raise AssignmentStoreError("unfrozen transcript carries a root")
                continue
            if any(value is None for value in fields):
                raise AssignmentStoreError("frozen transcript is missing root evidence")
            if len(records) != spec.expected_assignment_count:
                raise AssignmentStoreError("frozen root record cardinality is incomplete")
            calculated = calculate().hex()
            if calculated != window[root_column]:
                raise AssignmentStoreError("persisted transcript root does not reproduce")
            evidence = self._load_frozen_root(window, kind, prefix).evidence
            leaves = sorted(record.leaf.hex() for record in records)
            if evidence.member_leaves != leaves or evidence.record_count != len(records):
                raise AssignmentStoreError("freeze evidence members do not reproduce")

    def _initialize(self) -> None:
        with self._connection() as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise AssignmentStoreError("SQLite WAL mode is unavailable")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', '1');

                CREATE TABLE IF NOT EXISTS windows (
                    window_id TEXT PRIMARY KEY,
                    spec_sha256 TEXT NOT NULL,
                    spec_size_bytes INTEGER NOT NULL,
                    validator_hotkey TEXT NOT NULL,
                    expected_assignment_count INTEGER NOT NULL,
                    maximum_transmissions INTEGER NOT NULL,
                    issue_close_round INTEGER NOT NULL,
                    response_close_round INTEGER NOT NULL,
                    reveal_round INTEGER NOT NULL,
                    maximum_request_body_bytes INTEGER NOT NULL,
                    maximum_response_body_bytes INTEGER NOT NULL,
                    maximum_retained_prefix_bytes INTEGER NOT NULL,
                    phase TEXT NOT NULL,
                    assignment_root TEXT,
                    assignment_freeze_sha256 TEXT,
                    assignment_freeze_size_bytes INTEGER,
                    request_root TEXT,
                    request_freeze_sha256 TEXT,
                    request_freeze_size_bytes INTEGER,
                    response_root TEXT,
                    response_freeze_sha256 TEXT,
                    response_freeze_size_bytes INTEGER
                ) STRICT;

                CREATE TABLE IF NOT EXISTS assignments (
                    assignment_id TEXT PRIMARY KEY,
                    window_id TEXT NOT NULL REFERENCES windows(window_id),
                    miner_hotkey TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    UNIQUE(window_id, miner_hotkey, request_digest)
                ) STRICT;

                CREATE TABLE IF NOT EXISTS attempts (
                    assignment_id TEXT NOT NULL REFERENCES assignments(assignment_id),
                    window_id TEXT NOT NULL REFERENCES windows(window_id),
                    attempt_index INTEGER NOT NULL,
                    prepared_sha256 TEXT NOT NULL,
                    prepared_size_bytes INTEGER NOT NULL,
                    nonce_text TEXT NOT NULL,
                    issued INTEGER NOT NULL,
                    claim_operation_id TEXT,
                    outcome_sha256 TEXT,
                    outcome_size_bytes INTEGER,
                    disposition TEXT,
                    final INTEGER NOT NULL,
                    PRIMARY KEY (assignment_id, attempt_index),
                    UNIQUE (window_id, nonce_text)
                ) STRICT;
                CREATE INDEX IF NOT EXISTS attempts_window_idx
                    ON attempts(window_id, assignment_id, attempt_index);

                CREATE TABLE IF NOT EXISTS material_bindings (
                    window_id TEXT PRIMARY KEY REFERENCES windows(window_id),
                    material_sha256 TEXT NOT NULL,
                    material_receipt_sha256 TEXT NOT NULL,
                    pool_stage_evidence_sha256 TEXT NOT NULL
                ) STRICT;
                """
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            connection.close()
            raise AssignmentStoreError("SQLite foreign keys are unavailable")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            connection.close()
            raise AssignmentStoreError("SQLite FULL synchronization is unavailable")
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

    @staticmethod
    def _require_window(connection: sqlite3.Connection, window_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM windows WHERE window_id = ?",
            (window_id,),
        ).fetchone()
        if row is None:
            raise AssignmentStoreError("unknown transcript window")
        return row

    @staticmethod
    def _require_assignment(
        connection: sqlite3.Connection,
        assignment_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM assignments WHERE assignment_id = ?",
            (assignment_id,),
        ).fetchone()
        if row is None:
            raise AssignmentStoreError("unknown deterministic assignment")
        return row

    @staticmethod
    def _require_attempt(
        connection: sqlite3.Connection,
        assignment_id: str,
        attempt_index: int,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM attempts WHERE assignment_id = ? AND attempt_index = ?
            """,
            (assignment_id, attempt_index),
        ).fetchone()
        if row is None:
            raise AssignmentStoreError("unknown request attempt")
        return row

    @staticmethod
    def _material_binding(row: sqlite3.Row) -> TranscriptMaterialBinding:
        try:
            return TranscriptMaterialBinding(
                material_sha256=row["material_sha256"],
                material_receipt_sha256=row["material_receipt_sha256"],
                pool_stage_evidence_sha256=row["pool_stage_evidence_sha256"],
            )
        except (TypeError, ValueError) as error:
            raise AssignmentStoreError("persisted material binding is invalid") from error


class _TranscriptObjectStore:
    def __init__(
        self,
        root: Path,
        *,
        maximum_object_bytes: int,
        maximum_total_bytes: int,
        maximum_objects: int,
    ) -> None:
        self.maximum_object_bytes = _bounded_int(
            maximum_object_bytes,
            1,
            MAX_EVIDENCE_OBJECT_BYTES,
            "evidence object ceiling",
        )
        self.maximum_total_bytes = _bounded_int(
            maximum_total_bytes,
            self.maximum_object_bytes,
            MAX_TOTAL_EVIDENCE_BYTES,
            "aggregate evidence ceiling",
        )
        self.maximum_objects = _bounded_int(
            maximum_objects,
            1,
            MAX_EVIDENCE_OBJECTS,
            "evidence object-count ceiling",
        )
        self.root = root
        _ensure_real_directory(root)
        self._sizes: dict[str, int] = {}
        self._audit()

    def add(self, data: bytes, media_type: str) -> EvidenceRef:
        if not isinstance(data, bytes):
            raise TypeError("evidence object must be exact bytes")
        if media_type not in {"application/json", "application/octet-stream"}:
            raise ValueError("unsupported evidence media type")
        if len(data) > self.maximum_object_bytes:
            raise AssignmentStoreError("evidence object exceeds its byte ceiling")
        digest = hashlib.sha256(data).hexdigest()
        existing = self._sizes.get(digest)
        if existing is not None:
            if (
                existing != len(data)
                or self.read(EvidenceRef(sha256=digest, media_type=media_type, size_bytes=existing))
                != data
            ):
                raise AssignmentStoreError("content-addressed evidence collision")
            return EvidenceRef(sha256=digest, media_type=media_type, size_bytes=existing)
        if len(self._sizes) >= self.maximum_objects:
            raise AssignmentStoreError("evidence object-count ceiling reached")
        if sum(self._sizes.values()) + len(data) > self.maximum_total_bytes:
            raise AssignmentStoreError("aggregate evidence byte ceiling reached")
        path = self.root / digest
        _write_content_addressed(path, data)
        self._sizes[digest] = len(data)
        return EvidenceRef(sha256=digest, media_type=media_type, size_bytes=len(data))

    def read(self, reference: EvidenceRef) -> bytes:
        if not isinstance(reference, EvidenceRef):
            raise TypeError("reference must be EvidenceRef")
        if reference.size_bytes > self.maximum_object_bytes:
            raise AssignmentStoreError("referenced evidence exceeds its byte ceiling")
        data = _read_bounded(self.root / reference.sha256, self.maximum_object_bytes)
        if len(data) != reference.size_bytes:
            raise AssignmentStoreError("evidence object has the wrong byte length")
        if hashlib.sha256(data).hexdigest() != reference.sha256:
            raise AssignmentStoreError("evidence object failed SHA-256 verification")
        return data

    def _audit(self) -> None:
        children = tuple(self.root.iterdir())
        if len(children) > self.maximum_objects:
            raise AssignmentStoreError("evidence store exceeds its object-count ceiling")
        total = 0
        for child in children:
            if _OBJECT_NAME_RE.fullmatch(child.name) is None:
                raise AssignmentStoreError("evidence directory contains an invalid object name")
            data = _read_bounded(child, self.maximum_object_bytes)
            if hashlib.sha256(data).hexdigest() != child.name:
                raise AssignmentStoreError("evidence object name does not match its bytes")
            self._sizes[child.name] = len(data)
            total += len(data)
            if total > self.maximum_total_bytes:
                raise AssignmentStoreError("evidence store exceeds its aggregate byte ceiling")


def _parse_canonical_model(data: bytes, model: type[Any], label: str) -> Any:
    try:
        decoded = json.loads(data)
        parsed = model.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AssignmentStoreError(f"{label} is invalid") from error
    if canonical_json_bytes(parsed) != data:
        raise AssignmentStoreError(f"{label} is not exact canonical JSON")
    return parsed


def _write_content_addressed(path: Path, data: bytes) -> None:
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("evidence write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if _read_bounded(path, len(data)) != data:
                raise AssignmentStoreError("content-addressed evidence collision") from None
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AssignmentStoreError(
            f"evidence object cannot be opened safely: {path.name}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise AssignmentStoreError("evidence object is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise AssignmentStoreError("evidence object exceeds its byte ceiling")
            chunks.append(chunk)
        if total != metadata.st_size:
            raise AssignmentStoreError("evidence object changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _ensure_real_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise AssignmentStoreError(f"directory cannot be created safely: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AssignmentStoreError("transcript path must be a real directory")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hex32(value: str, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase SHA-256 hexadecimal")
    return value


def _operation_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_OPERATION_ID_BYTES
        or _OPERATION_RE.fullmatch(value) is None
    ):
        raise ValueError("operation ID is invalid")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _bounded_int(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


__all__ = [
    "ATTEMPT_OUTCOME_SCHEMA",
    "FREEZE_SCHEMA",
    "MAX_ASSIGNMENTS_PER_WINDOW",
    "MAX_EVIDENCE_OBJECT_BYTES",
    "MAX_REQUEST_BODY_BYTES",
    "MAX_RESPONSE_BODY_BYTES",
    "MAX_RETAINED_PREFIX_BYTES",
    "MAX_TRANSMISSIONS_PER_ASSIGNMENT",
    "PREPARED_ATTEMPT_SCHEMA",
    "WINDOW_SCHEMA",
    "AssignmentConflict",
    "AssignmentPhaseError",
    "AssignmentStoreError",
    "AttemptOutcomeEvidence",
    "AttemptOutcomeInput",
    "AttemptSnapshot",
    "EvidenceRef",
    "FrozenRoot",
    "RequestStageLease",
    "RequestStageLeaseBusy",
    "SendClaim",
    "TranscriptMaterialBinding",
    "TranscriptPhase",
    "TranscriptWindowSpec",
    "ValidatorAssignmentStore",
    "WindowSnapshot",
    "deterministic_assignment_id",
]
