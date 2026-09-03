"""Durable control-plane state for one UMI validator.

This module owns no wallet, network client, artifact parser, or weight builder.  It
only records which protocol stage is authoritative and exposes typed work items to
the adapters that will perform those effects.  Every mutation is one SQLite
transaction and carries an idempotency key, so a process may safely retry after an
unknown commit outcome.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .window import WindowSchedule

SCHEMA_VERSION = 1
MAX_OPERATION_ID_BYTES = 160
MAX_REASON_CODE_BYTES = 128
MAX_METADATA_BYTES = 16 * 1024
MAX_SQLITE_INTEGER = (1 << 63) - 1

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


class ControlPlaneError(RuntimeError):
    """Base class for durable validator control-plane errors."""


class TransitionError(ControlPlaneError):
    """Raised when a requested state transition is not legal."""


class IdempotencyConflict(ControlPlaneError):
    """Raised when one operation ID is reused for a different mutation."""


class PersistenceError(ControlPlaneError):
    """Raised when persisted state fails its startup invariant audit."""


class StagePending(RuntimeError):
    """A stage is healthy and durable but its protocol deadline is not ready.

    Effects raise this only for expected chain/Quicknet progress.  The engine
    converts it into a non-mutating wait result so the long-lived service can
    poll again without classifying ordinary protocol time as an adapter fault.
    """

    def __init__(self, reason_code: str) -> None:
        self.reason_code = _code(reason_code, "stage-pending reason code")
        super().__init__(self.reason_code)


class WindowStage(str, Enum):
    """The seven canonical Section 12 stages, in execution order."""

    POOL_AND_SELECTION = "pool_and_selection"
    ASSIGNMENT = "assignment"
    REQUEST_TRANSCRIPT = "request_transcript"
    SEALED_RESPONSE = "sealed_response"
    REVEAL_AND_SCORE = "reveal_and_score"
    WEIGHT_BUILD = "weight_build"
    COMMIT_AND_TERMINAL_STATE = "commit_and_terminal_state"


STAGE_ORDER = tuple(WindowStage)
_NEXT_STAGE = {stage: STAGE_ORDER[index + 1] for index, stage in enumerate(STAGE_ORDER[:-1])}


class TerminalOutcome(str, Enum):
    """Protocol-level outcomes that close the active window."""

    CALIBRATION_NO_WEIGHT = "calibration_no_weight"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"
    VOID = "void"


class PauseScope(str, Enum):
    """Independent fail-closed controls for intake and weight submission."""

    WINDOW_INTAKE = "window_intake"
    WEIGHT_SUBMISSION = "weight_submission"


class IncidentStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class WindowPlan:
    """Chain-derived identity and timing boundaries for one scheduled window."""

    window_id: str
    window_index: int
    scoring_policy_hash: str
    announcement_block: int
    proposal_close_block: int
    closing_block: int
    selection_round: int
    issue_close_round: int
    response_close_round: int
    reveal_round: int

    def __post_init__(self) -> None:
        _hex32(self.window_id, "window ID")
        _hex32(self.scoring_policy_hash, "scoring policy hash")
        _nonnegative_int(self.window_index, "window index")
        for name in (
            "announcement_block",
            "proposal_close_block",
            "closing_block",
            "selection_round",
            "issue_close_round",
            "response_close_round",
            "reveal_round",
        ):
            _nonnegative_int(getattr(self, name), name.replace("_", " "))
        if not self.announcement_block < self.proposal_close_block < self.closing_block:
            raise ValueError("window block boundaries are not strictly ordered")
        if not (
            self.selection_round
            < self.issue_close_round
            < self.response_close_round
            < self.reveal_round
        ):
            raise ValueError("window Quicknet rounds are not strictly ordered")

    @classmethod
    def from_schedule(
        cls,
        schedule: WindowSchedule,
        *,
        scoring_policy_hash: str,
    ) -> WindowPlan:
        if not isinstance(schedule, WindowSchedule):
            raise TypeError("schedule must be a WindowSchedule")
        return cls(
            window_id=schedule.window_id,
            window_index=schedule.index,
            scoring_policy_hash=scoring_policy_hash,
            announcement_block=schedule.announcement_block,
            proposal_close_block=schedule.proposal_close_block,
            closing_block=schedule.closing_block,
            selection_round=schedule.selection_round,
            issue_close_round=schedule.issue_close_round,
            response_close_round=schedule.response_close_round,
            reveal_round=schedule.reveal_round,
        )


@dataclass(frozen=True, slots=True)
class StageEvidence:
    window_id: str
    stage: WindowStage
    evidence_sha256: str
    recorded_at_unix_ns: int

    def __post_init__(self) -> None:
        _hex32(self.window_id, "window ID")
        if not isinstance(self.stage, WindowStage):
            raise TypeError("stage evidence stage must be a WindowStage")
        _hex32(self.evidence_sha256, "stage evidence digest")
        _nonnegative_int(self.recorded_at_unix_ns, "stage evidence timestamp")


@dataclass(frozen=True, slots=True)
class WindowRecord:
    plan: WindowPlan
    stage: WindowStage
    terminal_outcome: TerminalOutcome | None
    terminal_reason_code: str | None
    terminal_evidence_sha256: str | None
    audit_release_block: int | None
    created_at_unix_ns: int
    updated_at_unix_ns: int
    revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.plan, WindowPlan):
            raise TypeError("window record plan must be a WindowPlan")
        if not isinstance(self.stage, WindowStage):
            raise TypeError("window record stage must be a WindowStage")
        _nonnegative_int(self.created_at_unix_ns, "window creation timestamp")
        _nonnegative_int(self.updated_at_unix_ns, "window update timestamp")
        _nonnegative_int(self.revision, "window revision")
        if self.updated_at_unix_ns < self.created_at_unix_ns:
            raise ValueError("window update timestamp precedes its creation")
        if self.terminal_outcome is None:
            if any(
                value is not None
                for value in (
                    self.terminal_reason_code,
                    self.terminal_evidence_sha256,
                    self.audit_release_block,
                )
            ):
                raise ValueError("active window carries terminal fields")
            return
        if not isinstance(self.terminal_outcome, TerminalOutcome):
            raise TypeError("terminal outcome must be a TerminalOutcome")
        _validate_terminal_fields(
            self.terminal_outcome,
            reason_code=_optional_code(
                self.terminal_reason_code,
                "terminal reason code",
            ),
            evidence_sha256=(
                _hex32(self.terminal_evidence_sha256, "terminal evidence digest")
                if self.terminal_evidence_sha256 is not None
                else None
            ),
            audit_release_block=(
                _nonnegative_int(self.audit_release_block, "audit release block")
                if self.audit_release_block is not None
                else None
            ),
        )
        if (
            self.terminal_outcome
            in {
                TerminalOutcome.CALIBRATION_NO_WEIGHT,
                TerminalOutcome.APPLIED,
                TerminalOutcome.FAILED,
            }
            and self.stage is not WindowStage.COMMIT_AND_TERMINAL_STATE
        ):
            raise ValueError("chain terminal outcome is stored before its terminal stage")

    @property
    def is_active(self) -> bool:
        return self.terminal_outcome is None


@dataclass(frozen=True, slots=True)
class PauseHold:
    hold_id: str
    scope: PauseScope
    reason_code: str
    incident_id: str | None
    created_at_unix_ns: int
    released_at_unix_ns: int | None
    resolution_code: str | None

    @property
    def active(self) -> bool:
        return self.released_at_unix_ns is None


@dataclass(frozen=True, slots=True)
class ControlState:
    scope: PauseScope
    active_holds: tuple[PauseHold, ...]

    @property
    def paused(self) -> bool:
        return bool(self.active_holds)


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    incident_id: str
    window_id: str | None
    reason_code: str
    status: IncidentStatus
    metadata_json: str
    opened_at_unix_ns: int
    resolved_at_unix_ns: int | None
    resolution_code: str | None
    resolution_metadata_json: str | None


@dataclass(frozen=True, slots=True)
class IncidentSpec:
    incident_id: str
    reason_code: str
    metadata: Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True)
class StageCompletion:
    operation_id: str
    window_id: str
    completed_stage: WindowStage
    evidence_sha256: str
    metadata: Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True)
class TerminalDecision:
    operation_id: str
    window_id: str
    stage: WindowStage
    outcome: TerminalOutcome
    reason_code: str | None = None
    evidence_sha256: str | None = None
    audit_release_block: int | None = None
    incident: IncidentSpec | None = None
    pause_scopes: tuple[PauseScope, ...] = ()
    metadata: Mapping[str, object] | None = None


StageResult = StageCompletion | TerminalDecision


@dataclass(frozen=True, slots=True)
class StageWorkItem:
    window: WindowRecord
    completed_evidence: tuple[StageEvidence, ...]
    controls: tuple[ControlState, ...]

    @property
    def stage(self) -> WindowStage:
        return self.window.stage

    @property
    def weight_submission_allowed(self) -> bool:
        return not next(
            state.paused for state in self.controls if state.scope is PauseScope.WEIGHT_SUBMISSION
        )


@dataclass(frozen=True, slots=True)
class RecoveryState:
    active_window: WindowRecord | None
    pending_work: StageWorkItem | None
    controls: tuple[ControlState, ...]
    open_incidents: tuple[IncidentRecord, ...]


@dataclass(frozen=True, slots=True)
class OperationRecord:
    operation_id: str
    operation_type: str
    request_sha256: str
    request_json: str
    result_json: str
    committed_at_unix_ns: int


@runtime_checkable
class StageAdapter(Protocol):
    """Boundary implemented later by chain, HTTP, reveal, and scoring adapters."""

    async def execute(self, work: StageWorkItem) -> StageResult:
        """Perform one external stage and return a persistable, idempotent decision."""


class ValidatorControlPlane:
    """SQLite-backed authority for validator lifecycle transitions.

    Connections are short lived so a restarted process observes only committed
    state.  ``BEGIN IMMEDIATE`` serializes writers, while WAL keeps read-only
    observer access independent of a stage transaction.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock_ns: Callable[[], int] = time.time_ns,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self.path = Path(path)
        if self.path.exists() and self.path.is_dir():
            raise ValueError("control-plane database path is a directory")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int):
            raise TypeError("busy_timeout_ms must be an integer")
        if busy_timeout_ms <= 0 or busy_timeout_ms > 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        self._clock_ns = clock_ns
        self._busy_timeout_ms = busy_timeout_ms
        self._initialize()
        self._audit_persisted_state()

    def start_window(
        self,
        plan: WindowPlan,
        *,
        operation_id: str,
        metadata: Mapping[str, object] | None = None,
    ) -> WindowRecord:
        if not isinstance(plan, WindowPlan):
            raise TypeError("plan must be a WindowPlan")
        request = {"plan": _plan_dict(plan), "metadata": _metadata_value(metadata)}

        def mutate(connection: sqlite3.Connection, now: int) -> WindowRecord:
            if self._control_state(connection, PauseScope.WINDOW_INTAKE).paused:
                raise TransitionError("window intake is paused")
            active = connection.execute(
                "SELECT window_id FROM windows WHERE terminal_outcome IS NULL"
            ).fetchone()
            if active is not None:
                raise TransitionError(f"window {active['window_id']} is already active")
            previous = connection.execute(
                "SELECT * FROM windows ORDER BY window_index DESC LIMIT 1"
            ).fetchone()
            if previous is not None:
                expected_index = int(previous["window_index"]) + 1
                if plan.window_index != expected_index:
                    raise TransitionError(
                        f"next window index must be {expected_index}, got {plan.window_index}"
                    )
                if plan.selection_round <= int(previous["reveal_round"]):
                    raise TransitionError("window Quicknet round intervals overlap")
                if plan.announcement_block <= int(previous["closing_block"]):
                    raise TransitionError("window block intervals overlap")
            connection.execute(
                """
                INSERT INTO windows (
                    window_id, window_index, scoring_policy_hash,
                    announcement_block, proposal_close_block, closing_block,
                    selection_round, issue_close_round, response_close_round, reveal_round,
                    stage, terminal_outcome, terminal_reason_code,
                    terminal_evidence_sha256, audit_release_block,
                    created_at_unix_ns, updated_at_unix_ns, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?, 0)
                """,
                (
                    plan.window_id,
                    plan.window_index,
                    plan.scoring_policy_hash,
                    plan.announcement_block,
                    plan.proposal_close_block,
                    plan.closing_block,
                    plan.selection_round,
                    plan.issue_close_round,
                    plan.response_close_round,
                    plan.reveal_round,
                    WindowStage.POOL_AND_SELECTION.value,
                    now,
                    now,
                ),
            )
            return self._require_window(connection, plan.window_id)

        return self._mutate(operation_id, "start_window", request, mutate, _window_from_dict)

    def advance_window(
        self,
        window_id: str,
        *,
        completed_stage: WindowStage,
        evidence_sha256: str,
        operation_id: str,
        metadata: Mapping[str, object] | None = None,
    ) -> WindowRecord:
        window_id = _hex32(window_id, "window ID")
        completed_stage = _enum_value(completed_stage, WindowStage, "completed stage")
        evidence_sha256 = _hex32(evidence_sha256, "stage evidence digest")
        request = {
            "window_id": window_id,
            "completed_stage": completed_stage.value,
            "evidence_sha256": evidence_sha256,
            "metadata": _metadata_value(metadata),
        }

        def mutate(connection: sqlite3.Connection, now: int) -> WindowRecord:
            current = self._require_window(connection, window_id)
            if not current.is_active:
                raise TransitionError("a terminal window cannot advance")
            if current.stage is not completed_stage:
                raise TransitionError(
                    f"window is at {current.stage.value}, not {completed_stage.value}"
                )
            next_stage = _NEXT_STAGE.get(completed_stage)
            if next_stage is None:
                raise TransitionError("terminal-state stage must close with terminate_window")
            connection.execute(
                """
                INSERT INTO stage_evidence (
                    window_id, stage, evidence_sha256, recorded_at_unix_ns
                ) VALUES (?, ?, ?, ?)
                """,
                (window_id, completed_stage.value, evidence_sha256, now),
            )
            connection.execute(
                """
                UPDATE windows
                SET stage = ?, updated_at_unix_ns = ?, revision = revision + 1
                WHERE window_id = ?
                """,
                (next_stage.value, now, window_id),
            )
            return self._require_window(connection, window_id)

        return self._mutate(operation_id, "advance_window", request, mutate, _window_from_dict)

    def apply_completion(self, completion: StageCompletion) -> WindowRecord:
        if not isinstance(completion, StageCompletion):
            raise TypeError("completion must be a StageCompletion")
        return self.advance_window(
            completion.window_id,
            completed_stage=completion.completed_stage,
            evidence_sha256=completion.evidence_sha256,
            operation_id=completion.operation_id,
            metadata=completion.metadata,
        )

    def apply_terminal_decision(self, decision: TerminalDecision) -> WindowRecord:
        if not isinstance(decision, TerminalDecision):
            raise TypeError("decision must be a TerminalDecision")
        return self.terminate_window(
            decision.window_id,
            outcome=decision.outcome,
            operation_id=decision.operation_id,
            expected_stage=decision.stage,
            reason_code=decision.reason_code,
            evidence_sha256=decision.evidence_sha256,
            audit_release_block=decision.audit_release_block,
            incident=decision.incident,
            pause_scopes=decision.pause_scopes,
            metadata=decision.metadata,
        )

    def apply_result(self, result: StageResult) -> WindowRecord:
        if isinstance(result, StageCompletion):
            return self.apply_completion(result)
        if isinstance(result, TerminalDecision):
            return self.apply_terminal_decision(result)
        raise TypeError("result must be a StageCompletion or TerminalDecision")

    def terminate_window(
        self,
        window_id: str,
        *,
        outcome: TerminalOutcome,
        operation_id: str,
        expected_stage: WindowStage | None = None,
        reason_code: str | None = None,
        evidence_sha256: str | None = None,
        audit_release_block: int | None = None,
        incident: IncidentSpec | None = None,
        pause_scopes: Sequence[PauseScope] = (),
        metadata: Mapping[str, object] | None = None,
    ) -> WindowRecord:
        window_id = _hex32(window_id, "window ID")
        outcome = _enum_value(outcome, TerminalOutcome, "terminal outcome")
        if expected_stage is not None:
            expected_stage = _enum_value(expected_stage, WindowStage, "expected stage")
        reason_code = _optional_code(reason_code, "terminal reason code")
        evidence_sha256 = (
            _hex32(evidence_sha256, "terminal evidence digest")
            if evidence_sha256 is not None
            else None
        )
        if audit_release_block is not None:
            _nonnegative_int(audit_release_block, "audit release block")
        scopes = _canonical_scopes(pause_scopes)
        incident_value = _validate_incident_spec(incident) if incident is not None else None
        metadata_value = _metadata_value(metadata)
        _validate_terminal_fields(
            outcome,
            reason_code=reason_code,
            evidence_sha256=evidence_sha256,
            audit_release_block=audit_release_block,
        )
        if scopes and incident_value is None:
            raise ValueError("terminal pause scopes require an incident")
        request = {
            "window_id": window_id,
            "outcome": outcome.value,
            "expected_stage": expected_stage.value if expected_stage is not None else None,
            "reason_code": reason_code,
            "evidence_sha256": evidence_sha256,
            "audit_release_block": audit_release_block,
            "incident": _incident_spec_dict(incident_value),
            "pause_scopes": [scope.value for scope in scopes],
            "metadata": metadata_value,
        }

        def mutate(connection: sqlite3.Connection, now: int) -> WindowRecord:
            current = self._require_window(connection, window_id)
            if not current.is_active:
                raise TransitionError("window is already terminal")
            if expected_stage is not None and current.stage is not expected_stage:
                raise TransitionError(
                    f"window is at {current.stage.value}, not {expected_stage.value}"
                )
            if (
                outcome
                in {
                    TerminalOutcome.CALIBRATION_NO_WEIGHT,
                    TerminalOutcome.APPLIED,
                    TerminalOutcome.FAILED,
                }
                and current.stage is not WindowStage.COMMIT_AND_TERMINAL_STATE
            ):
                raise TransitionError(
                    f"{outcome.value} requires the commit-and-terminal-state stage"
                )
            if incident_value is not None:
                self._insert_incident(
                    connection,
                    incident_value,
                    window_id=window_id,
                    pause_scopes=scopes,
                    now=now,
                )
            connection.execute(
                """
                UPDATE windows
                SET terminal_outcome = ?, terminal_reason_code = ?,
                    terminal_evidence_sha256 = ?, audit_release_block = ?,
                    updated_at_unix_ns = ?, revision = revision + 1
                WHERE window_id = ?
                """,
                (
                    outcome.value,
                    reason_code,
                    evidence_sha256,
                    audit_release_block,
                    now,
                    window_id,
                ),
            )
            return self._require_window(connection, window_id)

        return self._mutate(operation_id, "terminate_window", request, mutate, _window_from_dict)

    def record_incident(
        self,
        incident: IncidentSpec,
        *,
        operation_id: str,
        window_id: str | None = None,
        pause_scopes: Sequence[PauseScope] = (),
    ) -> IncidentRecord:
        incident = _validate_incident_spec(incident)
        if window_id is not None:
            window_id = _hex32(window_id, "window ID")
        scopes = _canonical_scopes(pause_scopes)
        request = {
            "incident": _incident_spec_dict(incident),
            "window_id": window_id,
            "pause_scopes": [scope.value for scope in scopes],
        }

        def mutate(connection: sqlite3.Connection, now: int) -> IncidentRecord:
            if window_id is not None:
                self._require_window(connection, window_id)
            self._insert_incident(
                connection,
                incident,
                window_id=window_id,
                pause_scopes=scopes,
                now=now,
            )
            return self._require_incident(connection, incident.incident_id)

        return self._mutate(
            operation_id,
            "record_incident",
            request,
            mutate,
            _incident_from_dict,
        )

    def resolve_incident(
        self,
        incident_id: str,
        *,
        resolution_code: str,
        operation_id: str,
        metadata: Mapping[str, object] | None = None,
    ) -> IncidentRecord:
        incident_id = _identifier(incident_id, "incident ID")
        resolution_code = _code(resolution_code, "resolution code")
        metadata_value = _metadata_value(metadata)
        request = {
            "incident_id": incident_id,
            "resolution_code": resolution_code,
            "metadata": metadata_value,
        }

        def mutate(connection: sqlite3.Connection, now: int) -> IncidentRecord:
            incident = self._require_incident(connection, incident_id)
            if incident.status is IncidentStatus.RESOLVED:
                raise TransitionError("incident is already resolved")
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, resolved_at_unix_ns = ?, resolution_code = ?,
                    resolution_metadata_json = ?
                WHERE incident_id = ?
                """,
                (
                    IncidentStatus.RESOLVED.value,
                    now,
                    resolution_code,
                    _canonical_json(metadata_value),
                    incident_id,
                ),
            )
            return self._require_incident(connection, incident_id)

        return self._mutate(
            operation_id,
            "resolve_incident",
            request,
            mutate,
            _incident_from_dict,
        )

    def pause(
        self,
        scope: PauseScope,
        *,
        reason_code: str,
        operation_id: str,
        incident_id: str | None = None,
    ) -> ControlState:
        scope = _enum_value(scope, PauseScope, "pause scope")
        reason_code = _code(reason_code, "pause reason code")
        incident_id = _identifier(incident_id, "incident ID") if incident_id is not None else None
        operation_id = _identifier(operation_id, "operation ID")
        request = {
            "scope": scope.value,
            "reason_code": reason_code,
            "incident_id": incident_id,
        }

        def mutate(connection: sqlite3.Connection, now: int) -> ControlState:
            if incident_id is not None:
                incident = self._require_incident(connection, incident_id)
                if incident.status is not IncidentStatus.OPEN:
                    raise TransitionError("a resolved incident cannot create a pause hold")
            self._insert_pause_hold(
                connection,
                hold_id=operation_id,
                scope=scope,
                reason_code=reason_code,
                incident_id=incident_id,
                now=now,
            )
            return self._control_state(connection, scope)

        return self._mutate(operation_id, "pause", request, mutate, _control_from_dict)

    def resume(
        self,
        scope: PauseScope,
        *,
        hold_id: str,
        resolution_code: str,
        operation_id: str,
    ) -> ControlState:
        scope = _enum_value(scope, PauseScope, "pause scope")
        hold_id = _identifier(hold_id, "pause hold ID")
        resolution_code = _code(resolution_code, "resolution code")
        request = {
            "scope": scope.value,
            "hold_id": hold_id,
            "resolution_code": resolution_code,
        }

        def mutate(connection: sqlite3.Connection, now: int) -> ControlState:
            row = connection.execute(
                "SELECT * FROM pause_holds WHERE hold_id = ?",
                (hold_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown pause hold: {hold_id}")
            hold = _pause_hold_from_row(row)
            if hold.scope is not scope:
                raise TransitionError("pause hold belongs to a different scope")
            if not hold.active:
                raise TransitionError("pause hold is already released")
            if hold.incident_id is not None:
                incident = self._require_incident(connection, hold.incident_id)
                if incident.status is IncidentStatus.OPEN:
                    raise TransitionError("incident must be resolved before its pause is released")
            connection.execute(
                """
                UPDATE pause_holds
                SET released_at_unix_ns = ?, resolution_code = ?
                WHERE hold_id = ?
                """,
                (now, resolution_code, hold_id),
            )
            return self._control_state(connection, scope)

        return self._mutate(operation_id, "resume", request, mutate, _control_from_dict)

    def get_window(self, window_id: str) -> WindowRecord:
        window_id = _hex32(window_id, "window ID")
        with self._read() as connection:
            return self._require_window(connection, window_id)

    def active_window(self) -> WindowRecord | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM windows WHERE terminal_outcome IS NULL"
            ).fetchone()
            return _window_from_row(row) if row is not None else None

    def list_windows(self) -> tuple[WindowRecord, ...]:
        with self._read() as connection:
            rows = connection.execute("SELECT * FROM windows ORDER BY window_index").fetchall()
            return tuple(_window_from_row(row) for row in rows)

    def list_operations(self) -> tuple[OperationRecord, ...]:
        """Return the append-only mutation log used for audit and crash diagnosis."""

        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM operations ORDER BY committed_at_unix_ns, operation_id"
            ).fetchall()
            return tuple(_operation_from_row(row) for row in rows)

    def get_incident(self, incident_id: str) -> IncidentRecord:
        incident_id = _identifier(incident_id, "incident ID")
        with self._read() as connection:
            return self._require_incident(connection, incident_id)

    def control_state(self, scope: PauseScope) -> ControlState:
        scope = _enum_value(scope, PauseScope, "pause scope")
        with self._read() as connection:
            return self._control_state(connection, scope)

    def pending_work(self) -> StageWorkItem | None:
        with self._read() as connection:
            active = connection.execute(
                "SELECT * FROM windows WHERE terminal_outcome IS NULL"
            ).fetchone()
            if active is None:
                return None
            return self._work_item(connection, _window_from_row(active))

    def require_submission_allowed(self) -> None:
        state = self.control_state(PauseScope.WEIGHT_SUBMISSION)
        if state.paused:
            hold_ids = ", ".join(hold.hold_id for hold in state.active_holds)
            raise TransitionError(f"weight submission is paused by: {hold_ids}")

    def recovery_state(self) -> RecoveryState:
        """Return the exact committed restart point after auditing its invariants."""

        self._audit_persisted_state()
        with self._read() as connection:
            active_row = connection.execute(
                "SELECT * FROM windows WHERE terminal_outcome IS NULL"
            ).fetchone()
            active = _window_from_row(active_row) if active_row is not None else None
            controls = tuple(self._control_state(connection, scope) for scope in PauseScope)
            incident_rows = connection.execute(
                "SELECT * FROM incidents WHERE status = ? ORDER BY opened_at_unix_ns, incident_id",
                (IncidentStatus.OPEN.value,),
            ).fetchall()
            incidents = tuple(_incident_from_row(row) for row in incident_rows)
            pending = self._work_item(connection, active) if active is not None else None
            return RecoveryState(
                active_window=active,
                pending_work=pending,
                controls=controls,
                open_incidents=incidents,
            )

    def _work_item(
        self,
        connection: sqlite3.Connection,
        window: WindowRecord,
    ) -> StageWorkItem:
        evidence_rows = connection.execute(
            """
            SELECT * FROM stage_evidence
            WHERE window_id = ?
            """,
            (window.plan.window_id,),
        ).fetchall()
        evidence = tuple(
            sorted(
                (_stage_evidence_from_row(row) for row in evidence_rows),
                key=lambda item: STAGE_ORDER.index(item.stage),
            )
        )
        controls = tuple(self._control_state(connection, scope) for scope in PauseScope)
        return StageWorkItem(
            window=window,
            completed_evidence=evidence,
            controls=controls,
        )

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, SCHEMA_VERSION}:
                raise PersistenceError(
                    f"unsupported validator state schema {version}; expected {SCHEMA_VERSION}"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS windows (
                    window_id TEXT PRIMARY KEY,
                    window_index INTEGER NOT NULL UNIQUE,
                    scoring_policy_hash TEXT NOT NULL,
                    announcement_block INTEGER NOT NULL,
                    proposal_close_block INTEGER NOT NULL,
                    closing_block INTEGER NOT NULL,
                    selection_round INTEGER NOT NULL,
                    issue_close_round INTEGER NOT NULL,
                    response_close_round INTEGER NOT NULL,
                    reveal_round INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    terminal_outcome TEXT,
                    terminal_reason_code TEXT,
                    terminal_evidence_sha256 TEXT,
                    audit_release_block INTEGER,
                    created_at_unix_ns INTEGER NOT NULL,
                    updated_at_unix_ns INTEGER NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 0),
                    CHECK (stage IN (
                        'pool_and_selection', 'assignment', 'request_transcript',
                        'sealed_response', 'reveal_and_score', 'weight_build',
                        'commit_and_terminal_state'
                    )),
                    CHECK (terminal_outcome IS NOT NULL OR (
                        terminal_reason_code IS NULL
                        AND terminal_evidence_sha256 IS NULL
                        AND audit_release_block IS NULL
                    )),
                    CHECK (terminal_outcome IS NULL OR terminal_outcome IN
                        ('calibration_no_weight', 'applied', 'failed', 'skipped', 'void'))
                );

                CREATE UNIQUE INDEX IF NOT EXISTS one_active_window
                    ON windows ((1)) WHERE terminal_outcome IS NULL;

                CREATE TABLE IF NOT EXISTS stage_evidence (
                    window_id TEXT NOT NULL REFERENCES windows(window_id),
                    stage TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    recorded_at_unix_ns INTEGER NOT NULL,
                    PRIMARY KEY (window_id, stage),
                    CHECK (stage IN (
                        'pool_and_selection', 'assignment', 'request_transcript',
                        'sealed_response', 'reveal_and_score', 'weight_build'
                    ))
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    window_id TEXT REFERENCES windows(window_id),
                    reason_code TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
                    metadata_json TEXT NOT NULL,
                    opened_at_unix_ns INTEGER NOT NULL,
                    resolved_at_unix_ns INTEGER,
                    resolution_code TEXT,
                    resolution_metadata_json TEXT,
                    CHECK (
                        (status = 'open' AND resolved_at_unix_ns IS NULL
                            AND resolution_code IS NULL
                            AND resolution_metadata_json IS NULL)
                        OR
                        (status = 'resolved' AND resolved_at_unix_ns IS NOT NULL
                            AND resolution_code IS NOT NULL)
                    )
                );

                CREATE TABLE IF NOT EXISTS pause_holds (
                    hold_id TEXT PRIMARY KEY,
                    scope TEXT NOT NULL CHECK (scope IN ('window_intake', 'weight_submission')),
                    reason_code TEXT NOT NULL,
                    incident_id TEXT REFERENCES incidents(incident_id),
                    created_at_unix_ns INTEGER NOT NULL,
                    released_at_unix_ns INTEGER,
                    resolution_code TEXT,
                    CHECK ((released_at_unix_ns IS NULL) = (resolution_code IS NULL))
                );

                CREATE INDEX IF NOT EXISTS active_pause_holds
                    ON pause_holds (scope, created_at_unix_ns)
                    WHERE released_at_unix_ns IS NULL;

                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    committed_at_unix_ns INTEGER NOT NULL
                );
                """
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.commit()
        finally:
            connection.close()

    def _audit_persisted_state(self) -> None:
        try:
            self._audit_persisted_state_unchecked()
        except PersistenceError:
            raise
        except (KeyError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            raise PersistenceError("persisted validator control-plane state is invalid") from error

    def _audit_persisted_state_unchecked(self) -> None:
        with self._read() as connection:
            result = connection.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise PersistenceError("SQLite quick_check failed")
            rows = connection.execute("SELECT * FROM windows ORDER BY window_index").fetchall()
            windows = tuple(_window_from_row(row) for row in rows)
            if sum(window.is_active for window in windows) > 1:
                raise PersistenceError("more than one active window is persisted")
            if windows:
                initial_index = windows[0].plan.window_index
                for offset, window in enumerate(windows):
                    if window.plan.window_index != initial_index + offset:
                        raise PersistenceError("persisted window indices are not consecutive")
                    evidence_rows = connection.execute(
                        "SELECT * FROM stage_evidence WHERE window_id = ?",
                        (window.plan.window_id,),
                    ).fetchall()
                    evidence = tuple(_stage_evidence_from_row(row) for row in evidence_rows)
                    expected = set(STAGE_ORDER[: STAGE_ORDER.index(window.stage)])
                    if {item.stage for item in evidence} != expected:
                        raise PersistenceError("persisted stage evidence is not a complete prefix")
                for previous, current in pairwise(windows):
                    if current.plan.selection_round <= previous.plan.reveal_round:
                        raise PersistenceError("persisted window Quicknet intervals overlap")
                    if current.plan.announcement_block <= previous.plan.closing_block:
                        raise PersistenceError("persisted window block intervals overlap")
                    if previous.is_active:
                        raise PersistenceError("a persisted window follows an active window")
            for row in connection.execute("SELECT * FROM incidents").fetchall():
                _incident_from_row(row)
            for row in connection.execute("SELECT * FROM pause_holds").fetchall():
                _pause_hold_from_row(row)
            for row in connection.execute("SELECT * FROM operations").fetchall():
                _operation_from_row(row)

    def _insert_incident(
        self,
        connection: sqlite3.Connection,
        incident: IncidentSpec,
        *,
        window_id: str | None,
        pause_scopes: tuple[PauseScope, ...],
        now: int,
    ) -> None:
        existing = connection.execute(
            "SELECT incident_id FROM incidents WHERE incident_id = ?",
            (incident.incident_id,),
        ).fetchone()
        if existing is not None:
            raise TransitionError(f"incident {incident.incident_id!r} is already recorded")
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id, window_id, reason_code, status, metadata_json,
                opened_at_unix_ns, resolved_at_unix_ns, resolution_code,
                resolution_metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
            """,
            (
                incident.incident_id,
                window_id,
                incident.reason_code,
                IncidentStatus.OPEN.value,
                _canonical_json(_metadata_value(incident.metadata)),
                now,
            ),
        )
        for scope in pause_scopes:
            self._insert_pause_hold(
                connection,
                hold_id=_incident_hold_id(incident.incident_id, scope),
                scope=scope,
                reason_code=incident.reason_code,
                incident_id=incident.incident_id,
                now=now,
            )

    @staticmethod
    def _insert_pause_hold(
        connection: sqlite3.Connection,
        *,
        hold_id: str,
        scope: PauseScope,
        reason_code: str,
        incident_id: str | None,
        now: int,
    ) -> None:
        _identifier(hold_id, "pause hold ID")
        existing = connection.execute(
            "SELECT hold_id FROM pause_holds WHERE hold_id = ?",
            (hold_id,),
        ).fetchone()
        if existing is not None:
            raise TransitionError(f"pause hold {hold_id!r} is already recorded")
        connection.execute(
            """
            INSERT INTO pause_holds (
                hold_id, scope, reason_code, incident_id,
                created_at_unix_ns, released_at_unix_ns, resolution_code
            ) VALUES (?, ?, ?, ?, ?, NULL, NULL)
            """,
            (hold_id, scope.value, reason_code, incident_id, now),
        )

    def _control_state(
        self,
        connection: sqlite3.Connection,
        scope: PauseScope,
    ) -> ControlState:
        rows = connection.execute(
            """
            SELECT * FROM pause_holds
            WHERE scope = ? AND released_at_unix_ns IS NULL
            ORDER BY created_at_unix_ns, hold_id
            """,
            (scope.value,),
        ).fetchall()
        return ControlState(
            scope=scope,
            active_holds=tuple(_pause_hold_from_row(row) for row in rows),
        )

    def _require_window(
        self,
        connection: sqlite3.Connection,
        window_id: str,
    ) -> WindowRecord:
        row = connection.execute(
            "SELECT * FROM windows WHERE window_id = ?",
            (window_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown window: {window_id}")
        return _window_from_row(row)

    def _require_incident(
        self,
        connection: sqlite3.Connection,
        incident_id: str,
    ) -> IncidentRecord:
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown incident: {incident_id}")
        return _incident_from_row(row)

    def _mutate(
        self,
        operation_id: str,
        operation_type: str,
        request: Mapping[str, object],
        mutate: Callable[[sqlite3.Connection, int], Any],
        restore: Callable[[Mapping[str, object]], Any],
    ) -> Any:
        operation_id = _identifier(operation_id, "operation ID")
        request_json = _canonical_json(request)
        request_sha256 = hashlib.sha256(request_json.encode()).hexdigest()
        with self._transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if previous is not None:
                if (
                    previous["operation_type"] != operation_type
                    or previous["request_sha256"] != request_sha256
                ):
                    raise IdempotencyConflict(
                        f"operation ID {operation_id!r} was already used for another mutation"
                    )
                return restore(json.loads(previous["result_json"]))
            now = self._now()
            result = mutate(connection, now)
            connection.execute(
                """
                INSERT INTO operations (
                    operation_id, operation_type, request_sha256, request_json,
                    result_json, committed_at_unix_ns
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    operation_type,
                    request_sha256,
                    request_json,
                    _canonical_json(_result_dict(result)),
                    now,
                ),
            )
            return result

    def _now(self) -> int:
        value = self._clock_ns()
        _nonnegative_int(value, "clock nanoseconds")
        return value

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
        connection = sqlite3.connect(self.path, timeout=self._busy_timeout_ms / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        return connection


def _window_from_row(row: sqlite3.Row) -> WindowRecord:
    return WindowRecord(
        plan=WindowPlan(
            window_id=row["window_id"],
            window_index=row["window_index"],
            scoring_policy_hash=row["scoring_policy_hash"],
            announcement_block=row["announcement_block"],
            proposal_close_block=row["proposal_close_block"],
            closing_block=row["closing_block"],
            selection_round=row["selection_round"],
            issue_close_round=row["issue_close_round"],
            response_close_round=row["response_close_round"],
            reveal_round=row["reveal_round"],
        ),
        stage=WindowStage(row["stage"]),
        terminal_outcome=(
            TerminalOutcome(row["terminal_outcome"])
            if row["terminal_outcome"] is not None
            else None
        ),
        terminal_reason_code=row["terminal_reason_code"],
        terminal_evidence_sha256=row["terminal_evidence_sha256"],
        audit_release_block=row["audit_release_block"],
        created_at_unix_ns=row["created_at_unix_ns"],
        updated_at_unix_ns=row["updated_at_unix_ns"],
        revision=row["revision"],
    )


def _window_dict(value: WindowRecord) -> dict[str, object]:
    return {
        "plan": _plan_dict(value.plan),
        "stage": value.stage.value,
        "terminal_outcome": (
            value.terminal_outcome.value if value.terminal_outcome is not None else None
        ),
        "terminal_reason_code": value.terminal_reason_code,
        "terminal_evidence_sha256": value.terminal_evidence_sha256,
        "audit_release_block": value.audit_release_block,
        "created_at_unix_ns": value.created_at_unix_ns,
        "updated_at_unix_ns": value.updated_at_unix_ns,
        "revision": value.revision,
    }


def _window_from_dict(value: Mapping[str, object]) -> WindowRecord:
    raw_plan = value["plan"]
    if not isinstance(raw_plan, dict):
        raise PersistenceError("idempotent window result has an invalid plan")
    plan = WindowPlan(**raw_plan)
    terminal = value["terminal_outcome"]
    return WindowRecord(
        plan=plan,
        stage=WindowStage(str(value["stage"])),
        terminal_outcome=TerminalOutcome(str(terminal)) if terminal is not None else None,
        terminal_reason_code=_optional_str(value["terminal_reason_code"]),
        terminal_evidence_sha256=_optional_str(value["terminal_evidence_sha256"]),
        audit_release_block=_optional_int(value["audit_release_block"]),
        created_at_unix_ns=int(value["created_at_unix_ns"]),
        updated_at_unix_ns=int(value["updated_at_unix_ns"]),
        revision=int(value["revision"]),
    )


def _stage_evidence_from_row(row: sqlite3.Row) -> StageEvidence:
    return StageEvidence(
        window_id=row["window_id"],
        stage=WindowStage(row["stage"]),
        evidence_sha256=row["evidence_sha256"],
        recorded_at_unix_ns=row["recorded_at_unix_ns"],
    )


def _pause_hold_from_row(row: sqlite3.Row) -> PauseHold:
    hold = PauseHold(
        hold_id=_identifier(row["hold_id"], "pause hold ID"),
        scope=PauseScope(row["scope"]),
        reason_code=_code(row["reason_code"], "pause reason code"),
        incident_id=(
            _identifier(row["incident_id"], "incident ID")
            if row["incident_id"] is not None
            else None
        ),
        created_at_unix_ns=row["created_at_unix_ns"],
        released_at_unix_ns=row["released_at_unix_ns"],
        resolution_code=(
            _code(row["resolution_code"], "resolution code")
            if row["resolution_code"] is not None
            else None
        ),
    )
    if hold.active != (hold.resolution_code is None):
        raise PersistenceError("pause hold release fields disagree")
    return hold


def _pause_hold_dict(value: PauseHold) -> dict[str, object]:
    return {
        "hold_id": value.hold_id,
        "scope": value.scope.value,
        "reason_code": value.reason_code,
        "incident_id": value.incident_id,
        "created_at_unix_ns": value.created_at_unix_ns,
        "released_at_unix_ns": value.released_at_unix_ns,
        "resolution_code": value.resolution_code,
    }


def _control_dict(value: ControlState) -> dict[str, object]:
    return {
        "scope": value.scope.value,
        "active_holds": [_pause_hold_dict(hold) for hold in value.active_holds],
    }


def _control_from_dict(value: Mapping[str, object]) -> ControlState:
    raw_holds = value["active_holds"]
    if not isinstance(raw_holds, list):
        raise PersistenceError("idempotent control result has invalid holds")
    holds = tuple(
        PauseHold(
            hold_id=str(item["hold_id"]),
            scope=PauseScope(str(item["scope"])),
            reason_code=str(item["reason_code"]),
            incident_id=_optional_str(item["incident_id"]),
            created_at_unix_ns=int(item["created_at_unix_ns"]),
            released_at_unix_ns=_optional_int(item["released_at_unix_ns"]),
            resolution_code=_optional_str(item["resolution_code"]),
        )
        for item in raw_holds
        if isinstance(item, dict)
    )
    if len(holds) != len(raw_holds):
        raise PersistenceError("idempotent control result has a malformed hold")
    return ControlState(scope=PauseScope(str(value["scope"])), active_holds=holds)


def _incident_from_row(row: sqlite3.Row) -> IncidentRecord:
    incident = IncidentRecord(
        incident_id=_identifier(row["incident_id"], "incident ID"),
        window_id=(_hex32(row["window_id"], "window ID") if row["window_id"] is not None else None),
        reason_code=_code(row["reason_code"], "incident reason code"),
        status=IncidentStatus(row["status"]),
        metadata_json=row["metadata_json"],
        opened_at_unix_ns=row["opened_at_unix_ns"],
        resolved_at_unix_ns=row["resolved_at_unix_ns"],
        resolution_code=(
            _code(row["resolution_code"], "resolution code")
            if row["resolution_code"] is not None
            else None
        ),
        resolution_metadata_json=row["resolution_metadata_json"],
    )
    for name, encoded in (
        ("incident metadata", incident.metadata_json),
        ("incident resolution metadata", incident.resolution_metadata_json),
    ):
        if encoded is None:
            continue
        try:
            decoded = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise PersistenceError(f"{name} is invalid JSON") from error
        if _canonical_json(decoded) != encoded or len(encoded.encode()) > MAX_METADATA_BYTES:
            raise PersistenceError(f"{name} is noncanonical or exceeds its byte ceiling")
    if (incident.status is IncidentStatus.RESOLVED) != (
        incident.resolved_at_unix_ns is not None
        and incident.resolution_code is not None
        and incident.resolution_metadata_json is not None
    ):
        raise PersistenceError("incident status and resolution fields disagree")
    if incident.status is IncidentStatus.OPEN and incident.resolution_metadata_json is not None:
        raise PersistenceError("open incident carries resolution metadata")
    return incident


def _incident_dict(value: IncidentRecord) -> dict[str, object]:
    return {
        "incident_id": value.incident_id,
        "window_id": value.window_id,
        "reason_code": value.reason_code,
        "status": value.status.value,
        "metadata_json": value.metadata_json,
        "opened_at_unix_ns": value.opened_at_unix_ns,
        "resolved_at_unix_ns": value.resolved_at_unix_ns,
        "resolution_code": value.resolution_code,
        "resolution_metadata_json": value.resolution_metadata_json,
    }


def _incident_from_dict(value: Mapping[str, object]) -> IncidentRecord:
    return IncidentRecord(
        incident_id=str(value["incident_id"]),
        window_id=_optional_str(value["window_id"]),
        reason_code=str(value["reason_code"]),
        status=IncidentStatus(str(value["status"])),
        metadata_json=str(value["metadata_json"]),
        opened_at_unix_ns=int(value["opened_at_unix_ns"]),
        resolved_at_unix_ns=_optional_int(value["resolved_at_unix_ns"]),
        resolution_code=_optional_str(value["resolution_code"]),
        resolution_metadata_json=_optional_str(value["resolution_metadata_json"]),
    )


def _operation_from_row(row: sqlite3.Row) -> OperationRecord:
    operation = OperationRecord(
        operation_id=_identifier(row["operation_id"], "operation ID"),
        operation_type=_identifier(row["operation_type"], "operation type"),
        request_sha256=_hex32(row["request_sha256"], "operation request digest"),
        request_json=row["request_json"],
        result_json=row["result_json"],
        committed_at_unix_ns=_nonnegative_int(
            row["committed_at_unix_ns"], "operation commit timestamp"
        ),
    )
    try:
        request_value = json.loads(operation.request_json)
        result_value = json.loads(operation.result_json)
    except json.JSONDecodeError as error:
        raise PersistenceError("operation log contains invalid JSON") from error
    if _canonical_json(request_value) != operation.request_json:
        raise PersistenceError("operation request JSON is not canonical")
    if _canonical_json(result_value) != operation.result_json:
        raise PersistenceError("operation result JSON is not canonical")
    if hashlib.sha256(operation.request_json.encode()).hexdigest() != operation.request_sha256:
        raise PersistenceError("operation request digest does not reproduce")
    return operation


def _result_dict(value: object) -> dict[str, object]:
    if isinstance(value, WindowRecord):
        return _window_dict(value)
    if isinstance(value, IncidentRecord):
        return _incident_dict(value)
    if isinstance(value, ControlState):
        return _control_dict(value)
    raise TypeError(f"unsupported idempotent result type: {type(value).__name__}")


def _plan_dict(plan: WindowPlan) -> dict[str, object]:
    return {
        "window_id": plan.window_id,
        "window_index": plan.window_index,
        "scoring_policy_hash": plan.scoring_policy_hash,
        "announcement_block": plan.announcement_block,
        "proposal_close_block": plan.proposal_close_block,
        "closing_block": plan.closing_block,
        "selection_round": plan.selection_round,
        "issue_close_round": plan.issue_close_round,
        "response_close_round": plan.response_close_round,
        "reveal_round": plan.reveal_round,
    }


def _incident_spec_dict(value: IncidentSpec | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "incident_id": value.incident_id,
        "reason_code": value.reason_code,
        "metadata": _metadata_value(value.metadata),
    }


def _incident_hold_id(incident_id: str, scope: PauseScope) -> str:
    digest = hashlib.sha256(incident_id.encode()).hexdigest()
    return f"incident.{digest}.{scope.value}"


def _validate_incident_spec(value: IncidentSpec) -> IncidentSpec:
    if not isinstance(value, IncidentSpec):
        raise TypeError("incident must be an IncidentSpec")
    _identifier(value.incident_id, "incident ID")
    _code(value.reason_code, "incident reason code")
    _metadata_value(value.metadata)
    return value


def _validate_terminal_fields(
    outcome: TerminalOutcome,
    *,
    reason_code: str | None,
    evidence_sha256: str | None,
    audit_release_block: int | None,
) -> None:
    successful = {
        TerminalOutcome.APPLIED,
        TerminalOutcome.CALIBRATION_NO_WEIGHT,
    }
    failed = {
        TerminalOutcome.FAILED,
        TerminalOutcome.SKIPPED,
        TerminalOutcome.VOID,
    }
    if outcome in successful and reason_code is not None:
        raise ValueError(f"{outcome.value} cannot carry a failure reason")
    if outcome in failed and reason_code is None:
        raise ValueError(f"{outcome.value} requires a reason code")
    if (evidence_sha256 is None) != (audit_release_block is None):
        raise ValueError("terminal evidence and audit release block must be recorded together")
    if outcome in {
        TerminalOutcome.APPLIED,
        TerminalOutcome.FAILED,
        TerminalOutcome.CALIBRATION_NO_WEIGHT,
    } and (evidence_sha256 is None or audit_release_block is None):
        raise ValueError(f"{outcome.value} requires terminal evidence and release block")


def _canonical_scopes(scopes: Sequence[PauseScope]) -> tuple[PauseScope, ...]:
    values = tuple(_enum_value(scope, PauseScope, "pause scope") for scope in scopes)
    canonical = tuple(sorted(set(values), key=lambda item: item.value))
    if len(values) != len(canonical):
        raise ValueError("pause scopes must be unique")
    return canonical


def _metadata_value(value: Mapping[str, object] | None) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping")
    result = dict(value)
    if any(not isinstance(key, str) or not key for key in result):
        raise ValueError("metadata keys must be non-empty strings")
    encoded = _canonical_json(result)
    if len(encoded.encode()) > MAX_METADATA_BYTES:
        raise ValueError("metadata exceeds its byte ceiling")
    return json.loads(encoded)


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("control-plane metadata is not canonical JSON data") from error


def _hex32(value: object, name: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be 32 lowercase hexadecimal bytes")
    return value


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a non-empty canonical string")
    if "\x00" in value or len(value.encode()) > MAX_OPERATION_ID_BYTES:
        raise ValueError(f"{name} exceeds its byte ceiling or contains NUL")
    return value


def _code(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or _CODE_RE.fullmatch(value) is None
        or len(value.encode()) > MAX_REASON_CODE_BYTES
    ):
        raise ValueError(f"{name} is not a canonical reason code")
    return value


def _optional_code(value: object, name: str) -> str | None:
    return _code(value, name) if value is not None else None


def _nonnegative_int(value: object, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_SQLITE_INTEGER
    ):
        raise ValueError(f"{name} must be a non-negative SQLite integer")
    return value


def _enum_value(value: object, enum_type: type[Enum], name: str) -> Any:
    if not isinstance(value, enum_type):
        raise TypeError(f"{name} must be {enum_type.__name__}")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PersistenceError("persisted optional string is malformed")
    return value


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise PersistenceError("persisted optional integer is malformed")
    return value


__all__ = [
    "MAX_METADATA_BYTES",
    "SCHEMA_VERSION",
    "STAGE_ORDER",
    "ControlPlaneError",
    "ControlState",
    "IdempotencyConflict",
    "IncidentRecord",
    "IncidentSpec",
    "IncidentStatus",
    "OperationRecord",
    "PauseHold",
    "PauseScope",
    "PersistenceError",
    "RecoveryState",
    "StageAdapter",
    "StageCompletion",
    "StageEvidence",
    "StagePending",
    "StageResult",
    "StageWorkItem",
    "TerminalDecision",
    "TerminalOutcome",
    "TransitionError",
    "ValidatorControlPlane",
    "WindowPlan",
    "WindowRecord",
    "WindowStage",
]
