"""Durable, fail-closed resource accounting for the UMI miner service."""

from __future__ import annotations

import errno
import hashlib
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .config import Limits
from .encoding import account_id32, raw_sha256
from .endpoint_retirement import EndpointRetirementReceipt, SignedEndpointRetirementReceipt
from .open_competition import identity, verify_signature
from .protocol import TranslationRequest, base64url_decode, canonical_json_bytes, request_digest

_SCHEMA = "umi-miner-resource-ledger/1"
_RETIREMENT_SCHEMA = "umi-miner-resource-ledger/2"
_SIGNATURE_RE = re.compile(r"^0x[0-9a-f]{128}$")


class MinerResourceError(RuntimeError):
    """A request conflicts with durable assignment state or exceeds a ceiling."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class MinerAssignmentBinding:
    assignment_id: str
    window_index: int
    validator_hotkey: str
    validator_account_hex: str
    window_id: str
    batch_id: str
    challenge_id: str
    request_digest: str
    video_sha256: str
    video_size_bytes: int
    response_close_round: int

    @classmethod
    def from_request(
        cls,
        request: TranslationRequest,
        *,
        validator_hotkey: str,
        window_index: int = 0,
    ) -> MinerAssignmentBinding:
        if not isinstance(request, TranslationRequest):
            raise TypeError("request must be a TranslationRequest")
        if isinstance(window_index, bool) or not isinstance(window_index, int) or window_index < 0:
            raise ValueError("window index must be a non-negative integer")
        validator_account = account_id32(validator_hotkey)
        assignment_id = hashlib.sha256(
            b"umi-miner-assignment-v1\0"
            + validator_account
            + bytes.fromhex(request.window_id)
            + base64url_decode(request.batch_id)
            + base64url_decode(request.challenge_id)
        ).hexdigest()
        return cls(
            assignment_id=assignment_id,
            window_index=window_index,
            validator_hotkey=validator_hotkey,
            validator_account_hex=validator_account.hex(),
            window_id=request.window_id,
            batch_id=request.batch_id,
            challenge_id=request.challenge_id,
            request_digest=request_digest(request),
            video_sha256=request.video.sha256,
            video_size_bytes=request.video.size_bytes,
            response_close_round=request.response_close_round,
        )


@dataclass(frozen=True)
class CachedMinerResponse:
    body: bytes
    signature: str


@dataclass(frozen=True)
class MinerResourceOperation:
    assignment_id: str
    kind: str
    sequence: int
    reserved_wire_bytes: int


@dataclass(frozen=True)
class MinerAssignmentResourceSnapshot:
    assignment_id: str
    request_transmissions: int
    video_fetch_attempts: int
    response_bodies: int
    accounted_wire_bytes: int
    observed_wire_bytes: int
    cached_response_sha256: str | None


class SQLiteMinerResourceLedger:
    """Persist counters and response cache across single-process restarts.

    Reservations are made before video I/O. If a process exits while an operation
    is pending, startup converts it to an abandoned attempt and retains the full
    reservation. This may reject later work conservatively, but it cannot reopen a
    policy ceiling after a crash. An advisory lock permits one protocol process for
    each on-disk ledger; concurrency belongs inside that process.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        miner_hotkey: str,
        scoring_policy_sha256: str,
        limits: Limits,
        maximum_recovery_assignments: int = 0,
    ) -> None:
        if (
            type(maximum_recovery_assignments) is not int
            or not 0 <= maximum_recovery_assignments < 2**53
        ):
            raise ValueError("recovery assignment capacity must be a non-negative safe integer")
        self._maximum_recovery_assignments = maximum_recovery_assignments
        if not isinstance(limits, Limits):
            raise TypeError("limits must be Limits")
        raw_sha256(scoring_policy_sha256, field="scoring policy hash")
        miner_account = account_id32(miner_hotkey).hex()
        self._miner_hotkey = miner_hotkey
        self._limits = limits
        self._lock = threading.RLock()
        self._process_lock_descriptor: int | None = None
        self._path = str(path)
        if self._path != ":memory:":
            database = Path(path).expanduser().absolute()
            _prepare_private_database_path(database)
            self._path = str(database)
            self._acquire_process_lock()
            database_identity = _private_file_identity(
                database,
                reason_code="resource_ledger_database_unsafe",
            )
        try:
            self._connection = sqlite3.connect(
                self._path,
                timeout=30,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            if (
                self._path != ":memory:"
                and _private_file_identity(
                    Path(self._path),
                    reason_code="resource_ledger_database_unsafe",
                )
                != database_identity
            ):
                raise MinerResourceError("resource_ledger_database_replaced")
            with self._lock:
                self._connection.execute("PRAGMA foreign_keys = ON")
                if self._path != ":memory:":
                    self._connection.execute("PRAGMA journal_mode = WAL")
                    self._connection.execute("PRAGMA synchronous = FULL")
                self._create_schema()
                self._bind_metadata(
                    miner_account=miner_account,
                    scoring_policy_sha256=scoring_policy_sha256,
                )
                self._recover_pending()
                self._audit()
            if self._path != ":memory:":
                self._secure_database_files()
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            self._release_process_lock()
            raise

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.close()
            finally:
                self._release_process_lock()

    def record_request(
        self,
        binding: MinerAssignmentBinding,
        *,
        observed_wire_bytes: int,
        current_round: int | None = None,
    ) -> CachedMinerResponse | None:
        """Count one authenticated request and return an existing exact response."""

        self._validate_observed(observed_wire_bytes)
        if current_round is not None:
            self._validate_round(current_round)
        with self._transaction() as connection:
            self._ensure_not_retiring(connection, binding)
            if current_round is not None:
                self._prune_closed_windows(connection, current_round)
                if binding.response_close_round <= current_round:
                    raise MinerResourceError("response_window_closed")
            row = self._get_or_create_assignment(connection, binding)
            self._reserve_response_recovery(connection, binding, row)
            sequence = int(row["request_transmissions"]) + 1
            if sequence > self._limits.maximum_request_transmissions_per_assignment:
                raise MinerResourceError("request_transmission_limit")
            self._charge_completed(
                connection,
                binding.assignment_id,
                kind="request",
                sequence=sequence,
                observed_wire_bytes=observed_wire_bytes,
            )
            connection.execute(
                "UPDATE assignments SET request_transmissions = ? WHERE assignment_id = ?",
                (sequence, binding.assignment_id),
            )
            refreshed = self._assignment(connection, binding.assignment_id)
            body = refreshed["cached_response_body"]
            signature = refreshed["cached_response_signature"]
            if body is None:
                if signature is not None:
                    raise MinerResourceError("resource_ledger_cache_inconsistent")
                return None
            if not isinstance(body, bytes) or not isinstance(signature, str):
                raise MinerResourceError("resource_ledger_cache_inconsistent")
            return CachedMinerResponse(body=body, signature=signature)

    def cached_response(self, binding: MinerAssignmentBinding) -> CachedMinerResponse | None:
        """Return the exact first response without charging another transmission."""

        with self._lock:
            row = self._require_binding(self._connection, binding)
            body = row["cached_response_body"]
            signature = row["cached_response_signature"]
            if body is None:
                if signature is not None:
                    raise MinerResourceError("resource_ledger_cache_inconsistent")
                return None
            if not isinstance(body, bytes) or not isinstance(signature, str):
                raise MinerResourceError("resource_ledger_cache_inconsistent")
            return CachedMinerResponse(body=body, signature=signature)

    def begin_video_fetch(
        self,
        binding: MinerAssignmentBinding,
    ) -> MinerResourceOperation:
        """Reserve one video attempt before network I/O."""

        reservation = 2 * self._limits.maximum_http_header_bytes + binding.video_size_bytes
        with self._transaction() as connection:
            retired = self._retirement(connection, binding)
            if retired is not None and retired["receipt_intent"] is not None:
                raise MinerResourceError("request_retired")
            row = self._require_binding(connection, binding)
            in_progress = connection.execute(
                "SELECT 1 FROM operations AS operation "
                "JOIN assignments AS assignment USING (assignment_id) "
                "WHERE operation.kind = 'video_fetch' AND operation.status = 'pending' "
                "AND assignment.validator_account_hex = ? "
                "AND assignment.window_id = ? AND assignment.video_sha256 = ? LIMIT 1",
                (
                    binding.validator_account_hex,
                    binding.window_id,
                    binding.video_sha256,
                ),
            ).fetchone()
            if in_progress is not None:
                raise MinerResourceError("video_fetch_in_progress")
            assignment_sequence = int(row["video_fetch_attempts"]) + 1
            validator_attempts = connection.execute(
                "SELECT COUNT(*) FROM operations AS operation "
                "JOIN assignments AS assignment USING (assignment_id) "
                "WHERE operation.kind = 'video_fetch' "
                "AND assignment.validator_account_hex = ? "
                "AND assignment.window_id = ? AND assignment.video_sha256 = ?",
                (
                    binding.validator_account_hex,
                    binding.window_id,
                    binding.video_sha256,
                ),
            ).fetchone()[0]
            if validator_attempts >= self._limits.maximum_video_fetch_attempts_per_actor:
                raise MinerResourceError("video_fetch_attempt_limit")
            self._reserve_pending(
                connection,
                binding.assignment_id,
                kind="video_fetch",
                sequence=assignment_sequence,
                reserved_wire_bytes=reservation,
            )
            connection.execute(
                "UPDATE assignments SET video_fetch_attempts = ? WHERE assignment_id = ?",
                (assignment_sequence, binding.assignment_id),
            )
        return MinerResourceOperation(
            assignment_id=binding.assignment_id,
            kind="video_fetch",
            sequence=assignment_sequence,
            reserved_wire_bytes=reservation,
        )

    def abandon_video_fetch(
        self,
        operation: MinerResourceOperation,
        *,
        error_code: str,
    ) -> None:
        """Close an interrupted fetch while retaining its full wire reservation."""

        if operation.kind != "video_fetch":
            raise TypeError("operation is not a video fetch")
        if not isinstance(error_code, str) or not error_code:
            raise ValueError("error code must be nonempty text")
        with self._transaction() as connection:
            changed = connection.execute(
                "UPDATE operations SET status = 'abandoned', error_code = ? "
                "WHERE assignment_id = ? AND kind = ? AND sequence = ? "
                "AND status = 'pending'",
                (
                    error_code,
                    operation.assignment_id,
                    operation.kind,
                    operation.sequence,
                ),
            ).rowcount
            if changed != 1:
                raise MinerResourceError("video_fetch_operation_conflict")

    def cached_video(self, binding: MinerAssignmentBinding) -> bytes | None:
        """Return a verified video already fetched for this window and digest."""

        with self._lock:
            self._require_binding(self._connection, binding)
            row = self._connection.execute(
                "SELECT body, size_bytes, response_close_round FROM videos "
                "WHERE window_id = ? AND video_sha256 = ?",
                (binding.window_id, binding.video_sha256),
            ).fetchone()
            if row is None:
                return None
            body = row["body"]
            if (
                not isinstance(body, bytes)
                or row["size_bytes"] != binding.video_size_bytes
                or row["response_close_round"] != binding.response_close_round
                or len(body) != binding.video_size_bytes
                or hashlib.sha256(body).hexdigest() != binding.video_sha256
            ):
                raise MinerResourceError("video_cache_invalid")
            return body

    def finish_video_fetch(
        self,
        operation: MinerResourceOperation,
        *,
        observed_wire_bytes: int,
        error_code: str | None,
        data: bytes | None = None,
    ) -> None:
        self._validate_observed(observed_wire_bytes)
        if operation.kind != "video_fetch":
            raise TypeError("operation is not a video fetch")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM operations WHERE assignment_id = ? AND kind = ? AND sequence = ?",
                (operation.assignment_id, operation.kind, operation.sequence),
            ).fetchone()
            if row is None or row["status"] != "pending":
                raise MinerResourceError("video_fetch_operation_conflict")
            reserved = int(row["accounted_wire_bytes"])
            status = "failed" if error_code is not None else "completed"
            assignment = self._assignment(connection, operation.assignment_id)
            resulting_total = (
                int(assignment["accounted_wire_bytes"]) - reserved + observed_wire_bytes
            )
            if resulting_total > self._limits.maximum_assignment_wire_bytes:
                raise MinerResourceError("assignment_wire_limit")
            if status == "completed":
                if (
                    not isinstance(data, bytes)
                    or len(data) != assignment["video_size_bytes"]
                    or hashlib.sha256(data).hexdigest() != assignment["video_sha256"]
                ):
                    raise MinerResourceError("video_cache_binding_invalid")
                existing = connection.execute(
                    "SELECT * FROM videos WHERE window_id = ? AND video_sha256 = ?",
                    (assignment["window_id"], assignment["video_sha256"]),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        "INSERT INTO videos (window_id, video_sha256, size_bytes, "
                        "response_close_round, body) VALUES (?, ?, ?, ?, ?)",
                        (
                            assignment["window_id"],
                            assignment["video_sha256"],
                            assignment["video_size_bytes"],
                            assignment["response_close_round"],
                            data,
                        ),
                    )
                elif (
                    existing["size_bytes"] != assignment["video_size_bytes"]
                    or existing["body"] != data
                    or existing["response_close_round"] != assignment["response_close_round"]
                ):
                    raise MinerResourceError("video_cache_conflict")
            elif data is not None:
                raise ValueError("failed video fetch cannot store data")
            connection.execute(
                "UPDATE operations SET status = ?, accounted_wire_bytes = ?, "
                "observed_wire_bytes = ?, error_code = ? "
                "WHERE assignment_id = ? AND kind = ? AND sequence = ?",
                (
                    status,
                    observed_wire_bytes,
                    observed_wire_bytes,
                    error_code,
                    operation.assignment_id,
                    operation.kind,
                    operation.sequence,
                ),
            )
            connection.execute(
                "UPDATE assignments SET accounted_wire_bytes = ?, observed_wire_bytes = "
                "observed_wire_bytes + ? WHERE assignment_id = ?",
                (
                    resulting_total,
                    observed_wire_bytes,
                    operation.assignment_id,
                ),
            )

    def prune_closed_video_cache(self, current_round: int) -> int:
        """Discard plaintext video bodies after their response window closes."""

        if isinstance(current_round, bool) or not isinstance(current_round, int):
            raise TypeError("current round must be an integer")
        if current_round < 0:
            raise ValueError("current round must be non-negative")
        with self._transaction() as connection:
            changed = connection.execute(
                "DELETE FROM videos WHERE response_close_round <= ?",
                (current_round,),
            ).rowcount
        return changed

    def prune_closed_windows(self, current_round: int) -> int:
        """Prune expired transport state, preserving reserved recovery responses."""

        self._validate_round(current_round)
        with self._transaction() as connection:
            return self._prune_closed_windows(connection, current_round)

    def record_response(
        self,
        binding: MinerAssignmentBinding,
        *,
        body: bytes,
        signature: str,
    ) -> None:
        """Cache and count a response before handing it to the ASGI server."""

        if not isinstance(body, bytes) or not body:
            raise ValueError("response body must be non-empty bytes")
        if len(body) > self._limits.maximum_response_body_bytes:
            raise MinerResourceError("response_body_limit")
        if not isinstance(signature, str) or _SIGNATURE_RE.fullmatch(signature) is None:
            raise ValueError("response signature must be canonical 64-byte hex")
        accounted_wire = self._limits.maximum_http_header_bytes + len(body)
        body_sha256 = hashlib.sha256(body).hexdigest()
        with self._transaction() as connection:
            retired = self._retirement(connection, binding)
            if retired is not None and retired["receipt_intent"] is not None:
                raise MinerResourceError("request_retired")
            row = self._require_binding(connection, binding)
            sequence = int(row["response_bodies"]) + 1
            if sequence > self._limits.maximum_response_bodies_per_assignment:
                raise MinerResourceError("response_body_attempt_limit")
            if sequence > int(row["request_transmissions"]):
                raise MinerResourceError("response_without_request")
            cached_body = row["cached_response_body"]
            cached_signature = row["cached_response_signature"]
            cached_sha256 = row["cached_response_sha256"]
            if cached_body is not None and (
                cached_body != body or cached_signature != signature or cached_sha256 != body_sha256
            ):
                raise MinerResourceError("cached_response_conflict")
            self._charge_completed(
                connection,
                binding.assignment_id,
                kind="response",
                sequence=sequence,
                observed_wire_bytes=accounted_wire,
            )
            connection.execute(
                "UPDATE assignments SET response_bodies = ?, cached_response_body = ?, "
                "cached_response_signature = ?, cached_response_sha256 = ? "
                "WHERE assignment_id = ?",
                (
                    sequence,
                    body,
                    signature,
                    body_sha256,
                    binding.assignment_id,
                ),
            )
            recovery = connection.execute(
                "SELECT * FROM response_recovery WHERE assignment_id = ?", (binding.assignment_id,)
            ).fetchone()
            if recovery is not None:
                self._validate_recovery_binding(recovery, binding)
                retained = self._recovery_response(recovery)
                if retained is not None and retained != CachedMinerResponse(body, signature):
                    raise MinerResourceError("response_recovery_conflict")
                connection.execute(
                    "UPDATE response_recovery SET body = ?, signature = ?, sha256 = ? "
                    "WHERE assignment_id = ?",
                    (body, signature, body_sha256, binding.assignment_id),
                )

    def recovered_response(
        self, request: TranslationRequest, *, validator_hotkey: str
    ) -> CachedMinerResponse | None:
        """Read original sealed bytes; absence/pending never authorizes new work.

        Callers must authenticate the original validator on the recovery route.
        This operation does not admit a request, fetch a video, advance counters
        or extend an inference window. Its returned bytes are signature-checked
        by the HTTP consumer before transmission.
        """
        binding = MinerAssignmentBinding.from_request(request, validator_hotkey=validator_hotkey)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM response_recovery WHERE assignment_id = ?", (binding.assignment_id,)
            ).fetchone()
            if row is None:
                raise MinerResourceError("response_recovery_not_retained")
            self._validate_recovery_binding(row, binding)
            return self._recovery_response(row)

    def _reserve_response_recovery(
        self,
        connection: sqlite3.Connection,
        binding: MinerAssignmentBinding,
        assignment: sqlite3.Row,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM response_recovery WHERE assignment_id = ?", (binding.assignment_id,)
        ).fetchone()
        if row is not None:
            self._validate_recovery_binding(row, binding)
            return
        if not self._maximum_recovery_assignments:
            return
        count = connection.execute("SELECT COUNT(*) FROM response_recovery").fetchone()[0]
        if count >= self._maximum_recovery_assignments:
            raise MinerResourceError("response_recovery_capacity")
        # Reservation and request admission share one transaction. Each accepted
        # row has space in the configured count for a maximum-sized response;
        # no completion, pruning or clock event evicts it. Disk headroom remains
        # an operator responsibility. Increasing capacity does not change policy.
        connection.execute(
            "INSERT INTO response_recovery "
            "(assignment_id, request_digest, validator_account_hex, body, signature, sha256) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                binding.assignment_id,
                binding.request_digest,
                binding.validator_account_hex,
                assignment["cached_response_body"],
                assignment["cached_response_signature"],
                assignment["cached_response_sha256"],
            ),
        )

    @staticmethod
    def _validate_recovery_binding(row: sqlite3.Row, binding: MinerAssignmentBinding) -> None:
        if (row["request_digest"], row["validator_account_hex"]) != (
            binding.request_digest,
            binding.validator_account_hex,
        ):
            raise MinerResourceError("response_recovery_binding_conflict")

    def _recovery_response(self, row: sqlite3.Row) -> CachedMinerResponse | None:
        body, signature, sha256 = row["body"], row["signature"], row["sha256"]
        if body is None:
            if signature is not None or sha256 is not None:
                raise MinerResourceError("response_recovery_invalid")
            return None
        if (
            not isinstance(body, bytes)
            or not 0 < len(body) <= self._limits.maximum_response_body_bytes
            or not isinstance(signature, str)
            or _SIGNATURE_RE.fullmatch(signature) is None
            or hashlib.sha256(body).hexdigest() != sha256
        ):
            raise MinerResourceError("response_recovery_invalid")
        return CachedMinerResponse(body, signature)

    def snapshot(self, binding: MinerAssignmentBinding) -> MinerAssignmentResourceSnapshot:
        with self._lock:
            row = self._require_binding(self._connection, binding)
            return MinerAssignmentResourceSnapshot(
                assignment_id=binding.assignment_id,
                request_transmissions=int(row["request_transmissions"]),
                video_fetch_attempts=int(row["video_fetch_attempts"]),
                response_bodies=int(row["response_bodies"]),
                accounted_wire_bytes=int(row["accounted_wire_bytes"]),
                observed_wire_bytes=int(row["observed_wire_bytes"]),
                cached_response_sha256=row["cached_response_sha256"],
            )

    def _retirement(self, connection, binding):
        row = connection.execute(
            "SELECT * FROM request_retirements WHERE assignment_id=?", (binding.assignment_id,)
        ).fetchone()
        if row is not None:
            self._validate_recovery_binding(row, binding)
        return row

    def _ensure_not_retiring(self, connection, binding) -> None:
        if self._retirement(connection, binding) is not None:
            raise MinerResourceError("request_retired")

    def ensure_not_retiring(self, binding: MinerAssignmentBinding) -> None:
        """Check while holding the protocol assignment lock, before new work."""
        with self._lock:
            self._ensure_not_retiring(self._connection, binding)

    def retirement_requested(self, binding: MinerAssignmentBinding, grant_sha256: str) -> bool:
        with self._lock:
            row = self._retirement(self._connection, binding)
            if row is not None and row["grant_sha256"] != grant_sha256:
                raise MinerResourceError("retirement_grant_conflict")
            return row is not None

    def request_retirement(self, binding: MinerAssignmentBinding, grant_sha256: str) -> None:
        """Fence new protocol work and reserve the response archive atomically.

        An already running protocol task can finish before finalization. The
        caller must hold its assignment lock before preparing the receipt.
        """
        raw_sha256(grant_sha256, field="grant digest")
        with self._transaction() as db:
            old = self._retirement(db, binding)
            if old is not None:
                if old["grant_sha256"] != grant_sha256:
                    raise MinerResourceError("retirement_grant_conflict")
                return
            archived = db.execute(
                "SELECT * FROM response_recovery WHERE assignment_id=?", (binding.assignment_id,)
            ).fetchone()
            if archived is None:
                if not self._maximum_recovery_assignments:
                    raise MinerResourceError("response_recovery_disabled")
                count = db.execute("SELECT COUNT(*) FROM response_recovery").fetchone()[0]
                if count >= self._maximum_recovery_assignments:
                    raise MinerResourceError("response_recovery_capacity")
                assignment = db.execute(
                    "SELECT * FROM assignments WHERE assignment_id=?", (binding.assignment_id,)
                ).fetchone()
                if assignment is not None:
                    self._validate_binding(assignment, binding)
                db.execute(
                    "INSERT INTO response_recovery VALUES (?,?,?,?,?,?)",
                    (
                        binding.assignment_id,
                        binding.request_digest,
                        binding.validator_account_hex,
                        None if assignment is None else assignment["cached_response_body"],
                        None if assignment is None else assignment["cached_response_signature"],
                        None if assignment is None else assignment["cached_response_sha256"],
                    ),
                )
            else:
                self._validate_recovery_binding(archived, binding)
                self._recovery_response(archived)
            db.execute(
                "INSERT INTO request_retirements VALUES (?,?,?,?,NULL,NULL)",
                (
                    binding.assignment_id,
                    binding.request_digest,
                    binding.validator_account_hex,
                    grant_sha256,
                ),
            )
            # Older miners must fail their schema check rather than ignore a fence.
            db.execute("UPDATE metadata SET value=? WHERE key='schema'", (_RETIREMENT_SCHEMA,))

    def prepare_retirement(
        self, binding: MinerAssignmentBinding, grant_sha256: str
    ) -> EndpointRetirementReceipt:
        """Freeze the exact response selection under the protocol assignment lock."""
        with self._transaction() as db:
            row = self._retirement(db, binding)
            if row is None or row["grant_sha256"] != grant_sha256:
                raise MinerResourceError("retirement_not_requested")
            archived = db.execute(
                "SELECT * FROM response_recovery WHERE assignment_id=?", (binding.assignment_id,)
            ).fetchone()
            if archived is None:
                raise MinerResourceError("retirement_archive_missing")
            self._validate_recovery_binding(archived, binding)
            response = self._recovery_response(archived)
            body = EndpointRetirementReceipt(
                schema="umi-endpoint-retirement/1",
                grant_sha256=grant_sha256,
                request_digest=binding.request_digest,
                miner_hotkey=self._miner_hotkey,
                evaluator_hotkey=binding.validator_hotkey,
                result="no_response_retained" if response is None else "response_retained",
                response_sha256=None
                if response is None
                else hashlib.sha256(response.body).hexdigest(),
            )
            encoded = canonical_json_bytes(body)
            if row["receipt_intent"] is not None and row["receipt_intent"] != encoded:
                raise MinerResourceError("retirement_response_conflict")
            db.execute(
                "UPDATE request_retirements SET receipt_intent=? WHERE assignment_id=?",
                (encoded, binding.assignment_id),
            )
            return body

    def retirement_receipt(
        self, binding: MinerAssignmentBinding, grant_sha256: str
    ) -> SignedEndpointRetirementReceipt | None:
        with self._lock:
            row = self._retirement(self._connection, binding)
            if row is None:
                return None
            if row["grant_sha256"] != grant_sha256:
                raise MinerResourceError("retirement_grant_conflict")
            if row["receipt"] is None:
                return None
            return self._verify_retirement(row)

    def _verify_retirement(self, row) -> SignedEndpointRetirementReceipt:
        value = SignedEndpointRetirementReceipt.model_validate_json(row["receipt"])
        if (
            canonical_json_bytes(value) != row["receipt"]
            or canonical_json_bytes(value.receipt) != row["receipt_intent"]
            or value.receipt.grant_sha256 != row["grant_sha256"]
            or value.receipt.request_digest != row["request_digest"]
            or identity(value.receipt.evaluator_hotkey) != row["validator_account_hex"]
            or identity(value.receipt.miner_hotkey) != identity(self._miner_hotkey)
            or identity(value.signature.hotkey) != identity(self._miner_hotkey)
        ):
            raise MinerResourceError("retirement_receipt_invalid")
        verify_signature(value.receipt, value.signature)
        return value

    def commit_retirement_receipt(
        self, binding: MinerAssignmentBinding, value: SignedEndpointRetirementReceipt
    ) -> None:
        encoded = canonical_json_bytes(value)
        with self._transaction() as db:
            row = self._retirement(db, binding)
            if row is None or row["receipt_intent"] is None:
                raise MinerResourceError("retirement_not_prepared")
            proposed = dict(row)
            proposed["receipt"] = encoded
            self._verify_retirement(proposed)
            if row["receipt"] is not None and row["receipt"] != encoded:
                raise MinerResourceError("retirement_receipt_conflict")
            db.execute(
                "UPDATE request_retirements SET receipt=? WHERE assignment_id=?",
                (encoded, binding.assignment_id),
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assignments (
                assignment_id TEXT PRIMARY KEY,
                window_index INTEGER NOT NULL CHECK(window_index >= 0),
                validator_hotkey TEXT NOT NULL,
                validator_account_hex TEXT NOT NULL,
                window_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                video_sha256 TEXT NOT NULL,
                video_size_bytes INTEGER NOT NULL,
                response_close_round INTEGER NOT NULL,
                request_transmissions INTEGER NOT NULL DEFAULT 0,
                video_fetch_attempts INTEGER NOT NULL DEFAULT 0,
                response_bodies INTEGER NOT NULL DEFAULT 0,
                accounted_wire_bytes INTEGER NOT NULL DEFAULT 0,
                observed_wire_bytes INTEGER NOT NULL DEFAULT 0,
                cached_response_body BLOB,
                cached_response_signature TEXT,
                cached_response_sha256 TEXT
            );
            CREATE INDEX IF NOT EXISTS assignments_by_validator_window
                ON assignments (validator_account_hex, window_id);
            CREATE INDEX IF NOT EXISTS assignments_by_window_video
                ON assignments (window_id, video_sha256);
            CREATE TABLE IF NOT EXISTS operations (
                assignment_id TEXT NOT NULL REFERENCES assignments(assignment_id),
                kind TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                status TEXT NOT NULL,
                accounted_wire_bytes INTEGER NOT NULL,
                observed_wire_bytes INTEGER NOT NULL,
                error_code TEXT,
                PRIMARY KEY (assignment_id, kind, sequence)
            );
            CREATE TABLE IF NOT EXISTS videos (
                window_id TEXT NOT NULL,
                video_sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                response_close_round INTEGER NOT NULL,
                body BLOB NOT NULL,
                PRIMARY KEY (window_id, video_sha256)
            );
            CREATE TABLE IF NOT EXISTS response_recovery (
                assignment_id TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL,
                validator_account_hex TEXT NOT NULL,
                body BLOB,
                signature TEXT,
                sha256 TEXT
            );
            CREATE TABLE IF NOT EXISTS request_retirements (
                assignment_id TEXT PRIMARY KEY REFERENCES response_recovery(assignment_id),
                request_digest TEXT NOT NULL,
                validator_account_hex TEXT NOT NULL,
                grant_sha256 TEXT NOT NULL,
                receipt_intent BLOB,
                receipt BLOB
            );
            """
        )

    def _bind_metadata(
        self,
        *,
        miner_account: str,
        scoring_policy_sha256: str,
    ) -> None:
        values = {
            "schema": _SCHEMA,
            "miner_account_hex": miner_account,
            "scoring_policy_sha256": scoring_policy_sha256,
            "maximum_request_transmissions_per_assignment": str(
                self._limits.maximum_request_transmissions_per_assignment
            ),
            "maximum_response_bodies_per_assignment": str(
                self._limits.maximum_response_bodies_per_assignment
            ),
            "maximum_video_fetch_attempts_per_actor": str(
                self._limits.maximum_video_fetch_attempts_per_actor
            ),
            "maximum_assignment_wire_bytes": str(self._limits.maximum_assignment_wire_bytes),
            "maximum_assignments_per_validator_window": str(
                self._limits.maximum_assignments_per_validator_window
            ),
            "maximum_total_assignments_per_window": str(
                self._limits.maximum_total_assignments_per_window
            ),
            "maximum_unique_videos_per_validator_window": str(
                self._limits.maximum_unique_videos_per_validator_window
            ),
            "maximum_retained_video_bytes_per_validator_window": str(
                self._limits.maximum_retained_video_bytes_per_validator_window
            ),
            "maximum_unique_videos_per_window": str(self._limits.maximum_unique_videos_per_window),
            "maximum_retained_video_bytes": str(self._limits.maximum_retained_video_bytes),
            "maximum_active_windows": str(self._limits.maximum_active_windows),
        }
        with self._transaction() as connection:
            for key, value in values.items():
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = ?",
                    (key,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO metadata (key, value) VALUES (?, ?)",
                        (key, value),
                    )
                elif key == "schema" and row["value"] in {_SCHEMA, _RETIREMENT_SCHEMA}:
                    continue
                elif row["value"] != value:
                    raise MinerResourceError("resource_ledger_identity_conflict")

    def _recover_pending(self) -> None:
        with self._transaction() as connection:
            connection.execute(
                "UPDATE operations SET status = 'abandoned', "
                "error_code = 'process_restart' WHERE status = 'pending'"
            )

    def _audit(self) -> None:
        quick = self._connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick != "ok":
            raise MinerResourceError("resource_ledger_quick_check_failed")
        retirements = self._connection.execute("SELECT * FROM request_retirements").fetchall()
        if (
            retirements
            and self._connection.execute(
                "SELECT value FROM metadata WHERE key='schema'"
            ).fetchone()[0]
            != _RETIREMENT_SCHEMA
        ):
            raise MinerResourceError("retirement_schema_invalid")
        for row in retirements:
            for key in ("assignment_id", "request_digest", "validator_account_hex", "grant_sha256"):
                if re.fullmatch(r"[0-9a-f]{64}", row[key]) is None:
                    raise MinerResourceError("retirement_binding_invalid")
            archived = self._connection.execute(
                "SELECT * FROM response_recovery WHERE assignment_id=?", (row["assignment_id"],)
            ).fetchone()
            if archived is None or any(
                archived[k] != row[k] for k in ("request_digest", "validator_account_hex")
            ):
                raise MinerResourceError("retirement_archive_missing")
            if row["receipt_intent"] is not None:
                body = EndpointRetirementReceipt.model_validate_json(row["receipt_intent"])
                response = self._recovery_response(archived)
                if (
                    canonical_json_bytes(body) != row["receipt_intent"]
                    or body.grant_sha256 != row["grant_sha256"]
                    or body.request_digest != row["request_digest"]
                    or identity(body.evaluator_hotkey) != row["validator_account_hex"]
                    or identity(body.miner_hotkey) != identity(self._miner_hotkey)
                    or body.response_sha256
                    != (None if response is None else hashlib.sha256(response.body).hexdigest())
                ):
                    raise MinerResourceError("retirement_intent_invalid")
            if row["receipt"] is not None:
                self._verify_retirement(row)
        for row in self._connection.execute("SELECT * FROM response_recovery"):
            if any(
                re.fullmatch(r"[0-9a-f]{64}", row[k]) is None
                for k in ("assignment_id", "request_digest", "validator_account_hex")
            ):
                raise MinerResourceError("response_recovery_invalid")
            self._recovery_response(row)
        rows = self._connection.execute("SELECT * FROM assignments").fetchall()
        for row in rows:
            if row["window_index"] < 0:
                raise MinerResourceError("resource_ledger_window_index_invalid")
            operations = self._connection.execute(
                "SELECT * FROM operations WHERE assignment_id = ?",
                (row["assignment_id"],),
            ).fetchall()
            counts = {
                kind: sum(operation["kind"] == kind for operation in operations)
                for kind in ("request", "video_fetch", "response")
            }
            if (
                counts["request"] != row["request_transmissions"]
                or counts["video_fetch"] != row["video_fetch_attempts"]
                or counts["response"] != row["response_bodies"]
                or row["response_bodies"] > row["request_transmissions"]
                or sum(operation["accounted_wire_bytes"] for operation in operations)
                != row["accounted_wire_bytes"]
                or sum(operation["observed_wire_bytes"] for operation in operations)
                != row["observed_wire_bytes"]
            ):
                raise MinerResourceError("resource_ledger_counter_mismatch")
            if row["accounted_wire_bytes"] > self._limits.maximum_assignment_wire_bytes:
                raise MinerResourceError("resource_ledger_assignment_wire_limit")
            body = row["cached_response_body"]
            signature = row["cached_response_signature"]
            digest = row["cached_response_sha256"]
            if body is None:
                if signature is not None or digest is not None:
                    raise MinerResourceError("resource_ledger_cache_inconsistent")
            elif (
                not isinstance(body, bytes)
                or not isinstance(signature, str)
                or _SIGNATURE_RE.fullmatch(signature) is None
                or hashlib.sha256(body).hexdigest() != digest
                or row["response_bodies"] < 1
            ):
                raise MinerResourceError("resource_ledger_cache_inconsistent")
            if any(
                operation["status"] not in {"completed", "failed", "abandoned"}
                or operation["kind"] not in {"request", "video_fetch", "response"}
                or operation["accounted_wire_bytes"] < operation["observed_wire_bytes"]
                for operation in operations
            ):
                raise MinerResourceError("resource_ledger_operation_invalid")
        grouped = self._connection.execute(
            "SELECT validator_account_hex, window_id, COUNT(*) AS count "
            "FROM assignments GROUP BY validator_account_hex, window_id"
        ).fetchall()
        if any(
            row["count"] > self._limits.maximum_assignments_per_validator_window for row in grouped
        ):
            raise MinerResourceError("resource_ledger_assignment_count_limit")
        active_windows = self._connection.execute(
            "SELECT COUNT(DISTINCT window_id) FROM assignments"
        ).fetchone()[0]
        if active_windows > self._limits.maximum_active_windows:
            raise MinerResourceError("resource_ledger_active_window_limit")
        window_bindings = self._connection.execute(
            "SELECT window_id, COUNT(DISTINCT window_index) AS indices, "
            "COUNT(DISTINCT response_close_round) AS closes FROM assignments GROUP BY window_id"
        ).fetchall()
        if any(row["indices"] != 1 or row["closes"] != 1 for row in window_bindings):
            raise MinerResourceError("resource_ledger_window_binding_conflict")
        total_by_window = self._connection.execute(
            "SELECT window_id, COUNT(*) AS count FROM assignments GROUP BY window_id"
        ).fetchall()
        if any(
            row["count"] > self._limits.maximum_total_assignments_per_window
            for row in total_by_window
        ):
            raise MinerResourceError("resource_ledger_total_assignment_limit")
        video_by_window = self._connection.execute(
            "SELECT window_id, COUNT(*) AS count, SUM(video_size_bytes) AS size_bytes FROM ("
            "SELECT validator_account_hex, window_id, video_sha256, "
            "MAX(video_size_bytes) AS video_size_bytes FROM assignments "
            "GROUP BY validator_account_hex, window_id, video_sha256) GROUP BY window_id"
        ).fetchall()
        if any(
            row["count"] > self._limits.maximum_unique_videos_per_window
            or row["size_bytes"] > self._limits.maximum_retained_video_bytes
            for row in video_by_window
        ):
            raise MinerResourceError("resource_ledger_video_declaration_limit")
        validator_videos = self._connection.execute(
            "SELECT validator_account_hex, window_id, COUNT(*) AS count, "
            "SUM(video_size_bytes) AS size_bytes FROM ("
            "SELECT validator_account_hex, window_id, video_sha256, "
            "MAX(video_size_bytes) AS video_size_bytes FROM assignments "
            "GROUP BY validator_account_hex, window_id, video_sha256) "
            "GROUP BY validator_account_hex, window_id"
        ).fetchall()
        if any(
            row["count"] > self._limits.maximum_unique_videos_per_validator_window
            or row["size_bytes"] > self._limits.maximum_retained_video_bytes_per_validator_window
            for row in validator_videos
        ):
            raise MinerResourceError("resource_ledger_validator_video_declaration_limit")
        video_attempts = self._connection.execute(
            "SELECT assignment.validator_account_hex, assignment.window_id, "
            "assignment.video_sha256, COUNT(*) AS count "
            "FROM operations AS operation JOIN assignments AS assignment "
            "USING (assignment_id) WHERE operation.kind = 'video_fetch' "
            "GROUP BY assignment.validator_account_hex, assignment.window_id, "
            "assignment.video_sha256"
        ).fetchall()
        if any(
            row["count"] > self._limits.maximum_video_fetch_attempts_per_actor
            for row in video_attempts
        ):
            raise MinerResourceError("resource_ledger_video_attempt_limit")
        videos = self._connection.execute("SELECT * FROM videos").fetchall()
        for row in videos:
            body = row["body"]
            if (
                not isinstance(body, bytes)
                or len(body) != row["size_bytes"]
                or hashlib.sha256(body).hexdigest() != row["video_sha256"]
            ):
                raise MinerResourceError("video_cache_invalid")
            bindings = self._connection.execute(
                "SELECT video_size_bytes, response_close_round FROM assignments "
                "WHERE window_id = ? AND video_sha256 = ?",
                (row["window_id"], row["video_sha256"]),
            ).fetchall()
            if not any(
                item["video_size_bytes"] == row["size_bytes"]
                and item["response_close_round"] == row["response_close_round"]
                for item in bindings
            ):
                raise MinerResourceError("video_cache_binding_invalid")

    def _get_or_create_assignment(
        self,
        connection: sqlite3.Connection,
        binding: MinerAssignmentBinding,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM assignments WHERE assignment_id = ?",
            (binding.assignment_id,),
        ).fetchone()
        if row is not None:
            self._validate_binding(row, binding)
            return row
        validator_video = connection.execute(
            "SELECT video_size_bytes, response_close_round FROM assignments "
            "WHERE validator_account_hex = ? AND window_id = ? "
            "AND video_sha256 = ? LIMIT 1",
            (
                binding.validator_account_hex,
                binding.window_id,
                binding.video_sha256,
            ),
        ).fetchone()
        if validator_video is not None and (
            validator_video["video_size_bytes"] != binding.video_size_bytes
            or validator_video["response_close_round"] != binding.response_close_round
        ):
            raise MinerResourceError("validator_video_binding_conflict")
        window = connection.execute(
            "SELECT window_index, response_close_round FROM assignments "
            "WHERE window_id = ? LIMIT 1",
            (binding.window_id,),
        ).fetchone()
        if window is not None and (
            window["window_index"] != binding.window_index
            or window["response_close_round"] != binding.response_close_round
        ):
            raise MinerResourceError("window_binding_conflict")
        active_windows = connection.execute(
            "SELECT COUNT(DISTINCT window_id) FROM assignments"
        ).fetchone()[0]
        if window is None and active_windows >= self._limits.maximum_active_windows:
            raise MinerResourceError("active_window_limit")
        count = connection.execute(
            "SELECT COUNT(*) FROM assignments WHERE validator_account_hex = ? AND window_id = ?",
            (binding.validator_account_hex, binding.window_id),
        ).fetchone()[0]
        if count >= self._limits.maximum_assignments_per_validator_window:
            raise MinerResourceError("assignment_count_limit")
        total_count = connection.execute(
            "SELECT COUNT(*) FROM assignments WHERE window_id = ?",
            (binding.window_id,),
        ).fetchone()[0]
        if total_count >= self._limits.maximum_total_assignments_per_window:
            raise MinerResourceError("total_assignment_count_limit")
        validator_declared_video = connection.execute(
            "SELECT video_size_bytes FROM assignments WHERE validator_account_hex = ? "
            "AND window_id = ? AND video_sha256 = ? LIMIT 1",
            (
                binding.validator_account_hex,
                binding.window_id,
                binding.video_sha256,
            ),
        ).fetchone()
        if validator_declared_video is None:
            validator_declarations = connection.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(video_size_bytes), 0) AS size_bytes FROM ("
                "SELECT video_sha256, MAX(video_size_bytes) AS video_size_bytes "
                "FROM assignments WHERE validator_account_hex = ? AND window_id = ? "
                "GROUP BY video_sha256)",
                (binding.validator_account_hex, binding.window_id),
            ).fetchone()
            if (
                validator_declarations["count"]
                >= self._limits.maximum_unique_videos_per_validator_window
            ):
                raise MinerResourceError("validator_unique_video_count_limit")
            if (
                validator_declarations["size_bytes"] + binding.video_size_bytes
                > self._limits.maximum_retained_video_bytes_per_validator_window
            ):
                raise MinerResourceError("validator_retained_video_byte_limit")
        if validator_declared_video is None:
            declarations = connection.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(video_size_bytes), 0) AS size_bytes FROM ("
                "SELECT validator_account_hex, video_sha256, "
                "MAX(video_size_bytes) AS video_size_bytes "
                "FROM assignments WHERE window_id = ? "
                "GROUP BY validator_account_hex, video_sha256)",
                (binding.window_id,),
            ).fetchone()
            if declarations["count"] >= self._limits.maximum_unique_videos_per_window:
                raise MinerResourceError("unique_video_count_limit")
            if (
                declarations["size_bytes"] + binding.video_size_bytes
                > self._limits.maximum_retained_video_bytes
            ):
                raise MinerResourceError("retained_video_byte_limit")
        connection.execute(
            "INSERT INTO assignments (assignment_id, window_index, validator_hotkey, "
            "validator_account_hex, window_id, batch_id, challenge_id, "
            "request_digest, video_sha256, video_size_bytes, response_close_round) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                binding.assignment_id,
                binding.window_index,
                binding.validator_hotkey,
                binding.validator_account_hex,
                binding.window_id,
                binding.batch_id,
                binding.challenge_id,
                binding.request_digest,
                binding.video_sha256,
                binding.video_size_bytes,
                binding.response_close_round,
            ),
        )
        return self._assignment(connection, binding.assignment_id)

    def _require_binding(
        self,
        connection: sqlite3.Connection,
        binding: MinerAssignmentBinding,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM assignments WHERE assignment_id = ?",
            (binding.assignment_id,),
        ).fetchone()
        if row is None:
            raise MinerResourceError("assignment_not_recorded")
        self._validate_binding(row, binding)
        return row

    @staticmethod
    def _validate_binding(row: sqlite3.Row, binding: MinerAssignmentBinding) -> None:
        expected = {
            "window_index": binding.window_index,
            "validator_hotkey": binding.validator_hotkey,
            "validator_account_hex": binding.validator_account_hex,
            "window_id": binding.window_id,
            "batch_id": binding.batch_id,
            "challenge_id": binding.challenge_id,
            "request_digest": binding.request_digest,
            "video_sha256": binding.video_sha256,
            "video_size_bytes": binding.video_size_bytes,
            "response_close_round": binding.response_close_round,
        }
        if any(row[key] != value for key, value in expected.items()):
            raise MinerResourceError("assignment_binding_conflict")

    @staticmethod
    def _assignment(connection: sqlite3.Connection, assignment_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM assignments WHERE assignment_id = ?",
            (assignment_id,),
        ).fetchone()
        if row is None:
            raise MinerResourceError("assignment_not_recorded")
        return row

    def _reserve_pending(
        self,
        connection: sqlite3.Connection,
        assignment_id: str,
        *,
        kind: str,
        sequence: int,
        reserved_wire_bytes: int,
    ) -> None:
        row = self._assignment(connection, assignment_id)
        total = int(row["accounted_wire_bytes"]) + reserved_wire_bytes
        if total > self._limits.maximum_assignment_wire_bytes:
            raise MinerResourceError("assignment_wire_limit")
        connection.execute(
            "INSERT INTO operations (assignment_id, kind, sequence, status, "
            "accounted_wire_bytes, observed_wire_bytes, error_code) "
            "VALUES (?, ?, ?, 'pending', ?, 0, NULL)",
            (assignment_id, kind, sequence, reserved_wire_bytes),
        )
        connection.execute(
            "UPDATE assignments SET accounted_wire_bytes = ? WHERE assignment_id = ?",
            (total, assignment_id),
        )

    def _charge_completed(
        self,
        connection: sqlite3.Connection,
        assignment_id: str,
        *,
        kind: str,
        sequence: int,
        observed_wire_bytes: int,
    ) -> None:
        row = self._assignment(connection, assignment_id)
        total = int(row["accounted_wire_bytes"]) + observed_wire_bytes
        if total > self._limits.maximum_assignment_wire_bytes:
            raise MinerResourceError("assignment_wire_limit")
        connection.execute(
            "INSERT INTO operations (assignment_id, kind, sequence, status, "
            "accounted_wire_bytes, observed_wire_bytes, error_code) "
            "VALUES (?, ?, ?, 'completed', ?, ?, NULL)",
            (
                assignment_id,
                kind,
                sequence,
                observed_wire_bytes,
                observed_wire_bytes,
            ),
        )
        connection.execute(
            "UPDATE assignments SET accounted_wire_bytes = ?, "
            "observed_wire_bytes = observed_wire_bytes + ? WHERE assignment_id = ?",
            (total, observed_wire_bytes, assignment_id),
        )

    @staticmethod
    def _validate_observed(value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("observed wire bytes must be a non-negative integer")

    @staticmethod
    def _validate_round(value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("current round must be a non-negative integer")

    @staticmethod
    def _prune_closed_windows(connection: sqlite3.Connection, current_round: int) -> int:
        assignment_ids = tuple(
            row[0]
            for row in connection.execute(
                "SELECT assignment_id FROM assignments WHERE response_close_round <= ?",
                (current_round,),
            ).fetchall()
        )
        connection.execute(
            "DELETE FROM videos WHERE response_close_round <= ?",
            (current_round,),
        )
        if not assignment_ids:
            return 0
        placeholders = ",".join("?" for _ in assignment_ids)
        connection.execute(
            f"DELETE FROM operations WHERE assignment_id IN ({placeholders})",
            assignment_ids,
        )
        connection.execute(
            f"DELETE FROM assignments WHERE assignment_id IN ({placeholders})",
            assignment_ids,
        )
        return len(assignment_ids)

    def _secure_database_files(self) -> None:
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(self._path + suffix)
            if os.path.lexists(candidate):
                _private_file_identity(
                    candidate,
                    reason_code="resource_ledger_database_unsafe",
                )

    def _acquire_process_lock(self) -> None:
        import fcntl

        lock_path = Path(self._path + ".lock")
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise MinerResourceError("resource_ledger_lock_unavailable") from error
            try:
                descriptor = os.open(lock_path, flags)
            except OSError as open_error:
                raise MinerResourceError("resource_ledger_lock_unavailable") from open_error
            created = False
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or (not created and stat.S_IMODE(metadata.st_mode) != 0o600)
            ):
                raise MinerResourceError("resource_ledger_lock_unsafe")
            if created:
                os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise MinerResourceError("resource_ledger_already_open") from error
        except Exception:
            os.close(descriptor)
            raise
        self._process_lock_descriptor = descriptor

    def _release_process_lock(self) -> None:
        descriptor = self._process_lock_descriptor
        if descriptor is None:
            return
        import fcntl

        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            self._process_lock_descriptor = None


def _prepare_private_database_path(database: Path) -> None:
    parent = database.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=0o700)
        os.chmod(parent, 0o700)
    _require_private_directory(parent)

    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(database, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise MinerResourceError("resource_ledger_database_unavailable") from error
        try:
            descriptor = os.open(database, flags)
        except OSError as open_error:
            raise MinerResourceError("resource_ledger_database_unavailable") from open_error
        created = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or (not created and stat.S_IMODE(metadata.st_mode) != 0o600)
        ):
            raise MinerResourceError("resource_ledger_database_unsafe")
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
    finally:
        os.close(descriptor)

    for suffix in ("-wal", "-shm", "-journal"):
        candidate = Path(f"{database}{suffix}")
        if os.path.lexists(candidate):
            _private_file_identity(
                candidate,
                reason_code="resource_ledger_database_unsafe",
            )


def _require_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MinerResourceError("resource_ledger_parent_unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise MinerResourceError("resource_ledger_parent_unsafe")


def _private_file_identity(path: Path, *, reason_code: str) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MinerResourceError(reason_code) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise MinerResourceError(reason_code)
    return metadata.st_dev, metadata.st_ino


__all__ = [
    "CachedMinerResponse",
    "MinerAssignmentBinding",
    "MinerAssignmentResourceSnapshot",
    "MinerResourceError",
    "MinerResourceOperation",
    "SQLiteMinerResourceLedger",
]
