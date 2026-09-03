"""Receipt-first adapters between validator effects and durable state transitions.

This module deliberately contains no network, wallet, signing, or broadcast code.
Concrete effects perform one bounded stage and return exact evidence bytes plus a
typed decision.  The adapter persists those bytes and that decision in
``ValidatorStageJournal`` before it returns a ``StageResult`` to
``ValidatorEngine``.

If the journal receipt exists after an unknown control-plane outcome, the adapter
reconstructs the same ``StageResult`` from the receipt and does not invoke the
effect again.  A crash before a receipt exists cannot in general prove whether a
remote side effect happened; concrete effects must therefore also use the supplied
deterministic operation ID for their own idempotency boundary.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Literal, Protocol, TypeAlias, runtime_checkable

from pydantic import Field, JsonValue, model_validator
from typing_extensions import Self

from .protocol import StrictProtocolModel, canonical_json_bytes
from .validator_journal import StageJournalRecord, StageObjectInput, ValidatorStageJournal
from .validator_state import (
    MAX_METADATA_BYTES,
    MAX_OPERATION_ID_BYTES,
    STAGE_ORDER,
    IncidentSpec,
    PauseScope,
    StageCompletion,
    StageResult,
    StageWorkItem,
    TerminalDecision,
    TerminalOutcome,
    WindowStage,
)

ADAPTER_RESULT_SCHEMA = "umi-validator-adapter-result/1"
_OPERATION_PREFIX = "umi-stage-v1"
_MAX_REASON_CODE_BYTES = 128
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_REASON_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


class JournalStageAdapterError(RuntimeError):
    """Base class for a stable journal-adapter failure."""


class StageEffectBindingError(JournalStageAdapterError):
    """An effect returned a value not bound to its assigned operation."""


class StageReceiptBindingError(JournalStageAdapterError):
    """Persisted journal evidence disagrees with recovered control-plane state."""


@dataclass(frozen=True, slots=True)
class CompleteStageEffect:
    """Decision marker for a stage that should advance to its successor."""


@dataclass(frozen=True, slots=True)
class TerminalStageEffect:
    """Exact terminal fields to preserve in the stage receipt."""

    outcome: TerminalOutcome
    audit_release_block: int
    reason_code: str | None = None
    incident: IncidentSpec | None = None
    pause_scopes: tuple[PauseScope, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, TerminalOutcome):
            raise TypeError("terminal outcome must be a TerminalOutcome")
        _nonnegative_sqlite_int(self.audit_release_block, "audit release block")
        _validate_terminal_reason(self.outcome, self.reason_code)
        scopes = _canonical_pause_scopes(self.pause_scopes)
        object.__setattr__(self, "pause_scopes", scopes)
        if self.incident is not None:
            _validate_incident(self.incident)
        if scopes and self.incident is None:
            raise ValueError("terminal pause scopes require an incident")


StageEffectDecision: TypeAlias = CompleteStageEffect | TerminalStageEffect


@dataclass(frozen=True, slots=True)
class StageEffectResult:
    """One effect's exact bindings, evidence objects, metadata, and decision."""

    operation_id: str
    window_id: str
    stage: WindowStage
    objects: tuple[StageObjectInput, ...]
    metadata: Mapping[str, JsonValue]
    decision: StageEffectDecision
    _effect_metadata_bytes: bytes = field(init=False, repr=False, compare=False)
    _receipt_metadata_bytes: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _operation_id(self.operation_id)
        _window_id(self.window_id)
        if not isinstance(self.stage, WindowStage):
            raise TypeError("stage must be a WindowStage")
        if isinstance(self.objects, (str, bytes, bytearray)) or not isinstance(
            self.objects, Sequence
        ):
            raise TypeError("stage objects must be a sequence")
        objects = tuple(self.objects)
        if not objects:
            raise ValueError("a stage effect must return at least one evidence object")
        if any(not isinstance(item, StageObjectInput) for item in objects):
            raise TypeError("stage objects must contain StageObjectInput values")
        digests = [hashlib.sha256(item.data).digest() for item in objects]
        if len(digests) != len(set(digests)):
            raise ValueError("stage evidence objects must have unique SHA-256 digests")
        object.__setattr__(self, "objects", objects)

        metadata, encoded = _canonical_metadata(self.metadata, "effect metadata")
        object.__setattr__(self, "metadata", MappingProxyType(metadata))
        object.__setattr__(self, "_effect_metadata_bytes", encoded)
        if not isinstance(self.decision, (CompleteStageEffect, TerminalStageEffect)):
            raise TypeError("stage decision must be CompleteStageEffect or TerminalStageEffect")
        _validate_decision_for_stage(self.stage, self.decision)
        receipt_metadata = _effect_receipt_metadata(self)
        object.__setattr__(
            self,
            "_receipt_metadata_bytes",
            canonical_json_bytes(receipt_metadata),
        )

    def receipt_metadata(self) -> dict[str, JsonValue]:
        """Return an isolated copy of the authoritative journal metadata."""

        value = json.loads(self._receipt_metadata_bytes)
        if not isinstance(value, dict):
            raise RuntimeError("adapter receipt metadata lost its JSON object shape")
        return value


@runtime_checkable
class StageEffect(Protocol):
    """Bounded external work invoked only when no authoritative receipt exists."""

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        """Return exact evidence and a decision for ``operation_id`` and ``work``."""


@runtime_checkable
class AfterReceiptEffect(Protocol):
    """Optional recovery-safe hook run only after a stage receipt is durable.

    Implementations must be idempotent: the hook is also run when an existing
    journal receipt is recovered after a crash.  This lets an effect bind a
    secondary durable store to the authoritative receipt without repeating its
    external stage work.
    """

    async def after_receipt(
        self,
        *,
        record: StageJournalRecord,
        work: StageWorkItem,
    ) -> None:
        """Bind ``record`` to effect-owned durable state before control advances."""


@runtime_checkable
class StageReceiptObserver(Protocol):
    """Generic receipt-first hook shared across otherwise unrelated effects."""

    async def after_receipt(
        self,
        *,
        record: StageJournalRecord,
        work: StageWorkItem,
    ) -> None:
        """Observe one durable receipt before its control-plane transition."""


class _ReceiptIncident(StrictProtocolModel):
    incident_id: Annotated[str, Field(min_length=1, max_length=MAX_OPERATION_ID_BYTES)]
    reason_code: Annotated[str, Field(min_length=1, max_length=_MAX_REASON_CODE_BYTES)]
    metadata: dict[str, JsonValue]


class _ReceiptTerminal(StrictProtocolModel):
    outcome: Literal[
        "calibration_no_weight",
        "applied",
        "failed",
        "skipped",
        "void",
    ]
    reason_code: str | None
    audit_release_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    incident: _ReceiptIncident | None
    pause_scopes: list[Literal["window_intake", "weight_submission"]]

    @model_validator(mode="after")
    def validate_terminal(self) -> Self:
        outcome = TerminalOutcome(self.outcome)
        _validate_terminal_reason(outcome, self.reason_code)
        scopes = tuple(PauseScope(value) for value in self.pause_scopes)
        if scopes != _canonical_pause_scopes(scopes):
            raise ValueError("receipt pause scopes are not unique and canonically ordered")
        if self.incident is not None:
            _validate_incident(
                IncidentSpec(
                    incident_id=self.incident.incident_id,
                    reason_code=self.incident.reason_code,
                    metadata=self.incident.metadata,
                )
            )
        if scopes and self.incident is None:
            raise ValueError("receipt pause scopes require an incident")
        return self


class _ReceiptResult(StrictProtocolModel):
    schema_: Literal[ADAPTER_RESULT_SCHEMA] = Field(alias="schema")
    kind: Literal["completion", "terminal"]
    metadata: dict[str, JsonValue]
    terminal: _ReceiptTerminal | None

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        if (self.kind == "terminal") != (self.terminal is not None):
            raise ValueError("receipt result kind and terminal fields disagree")
        _canonical_metadata(self.metadata, "receipt effect metadata")
        return self


class JournalStageAdapter:
    """Implement ``StageAdapter`` with receipt-first crash recovery.

    The in-process lock prevents two callers of this adapter instance from running
    the effect concurrently.  Cross-process effects still need their own
    idempotency keyed by the supplied deterministic operation ID.
    """

    def __init__(
        self,
        *,
        stage: WindowStage,
        journal: ValidatorStageJournal,
        effect: StageEffect,
        receipt_observer: StageReceiptObserver | None = None,
    ) -> None:
        if not isinstance(stage, WindowStage):
            raise TypeError("stage must be a WindowStage")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be a ValidatorStageJournal")
        if not callable(getattr(effect, "perform", None)):
            raise TypeError("effect must define perform(operation_id=..., work=...)")
        after_receipt = getattr(effect, "after_receipt", None)
        if after_receipt is not None and (
            not callable(after_receipt) or not inspect.iscoroutinefunction(after_receipt)
        ):
            raise TypeError("effect after_receipt must be async when provided")
        observer_hook = (
            getattr(receipt_observer, "after_receipt", None)
            if receipt_observer is not None
            else None
        )
        if observer_hook is not None and (
            not callable(observer_hook) or not inspect.iscoroutinefunction(observer_hook)
        ):
            raise TypeError("receipt observer after_receipt must be async")
        if receipt_observer is not None and observer_hook is None:
            raise TypeError("receipt_observer must define async after_receipt")
        self.stage = stage
        self._journal = journal
        self._effect = effect
        self._after_receipt_hook = after_receipt
        self._receipt_observer_hook = observer_hook
        self._lock = asyncio.Lock()

    async def execute(self, work: StageWorkItem) -> StageResult:
        """Recover or perform one stage, durably receipt it, and return its decision."""

        if not isinstance(work, StageWorkItem):
            raise TypeError("work must be a StageWorkItem")
        if work.stage is not self.stage:
            raise StageEffectBindingError(
                f"adapter for {self.stage.value} received {work.stage.value} work"
            )
        async with self._lock:
            operation_id = stage_operation_id(work.window.plan.window_id, work.stage)
            existing = self._current_receipt(work)
            if existing is not None:
                await self._after_receipt(existing, work)
                return _stage_result_from_receipt(existing, work)

            effect_result = await self._effect.perform(
                operation_id=operation_id,
                work=work,
            )
            _validate_effect_binding(effect_result, work, operation_id)
            record = self._journal.record(
                window_id=work.window.plan.window_id,
                stage=work.stage,
                operation_id=operation_id,
                objects=effect_result.objects,
                metadata=effect_result.receipt_metadata(),
            )
            await self._after_receipt(record, work)
            return _stage_result_from_receipt(record, work)

    async def _after_receipt(
        self,
        record: StageJournalRecord,
        work: StageWorkItem,
    ) -> None:
        hook = self._after_receipt_hook
        if hook is not None:
            await hook(record=record, work=work)
        observer = self._receipt_observer_hook
        if observer is not None:
            await observer(record=record, work=work)

    def _current_receipt(self, work: StageWorkItem) -> StageJournalRecord | None:
        records = self._journal.load_window(work.window.plan.window_id)
        stage_index = STAGE_ORDER.index(work.stage)
        if len(work.completed_evidence) != stage_index:
            raise StageReceiptBindingError(
                "control-plane evidence is not the complete prefix before the pending stage"
            )
        if len(records) not in {stage_index, stage_index + 1}:
            raise StageReceiptBindingError(
                "journal receipts do not end at the control-plane stage boundary"
            )
        for index, evidence in enumerate(work.completed_evidence):
            expected_stage = STAGE_ORDER[index]
            record = records[index]
            if evidence.window_id != work.window.plan.window_id:
                raise StageReceiptBindingError("completed evidence binds another window")
            if evidence.stage is not expected_stage:
                raise StageReceiptBindingError("completed evidence is not canonically ordered")
            if record.receipt.stage != expected_stage.value:
                raise StageReceiptBindingError("journal receipt stage prefix is not canonical")
            if record.receipt.operation_id != stage_operation_id(
                work.window.plan.window_id,
                expected_stage,
            ):
                raise StageReceiptBindingError("prior receipt has a noncanonical operation ID")
            prior_result = _stage_result_from_receipt(record, work=None)
            if not isinstance(prior_result, StageCompletion):
                raise StageReceiptBindingError("an active window follows a terminal receipt")
            if evidence.evidence_sha256 != record.evidence_sha256:
                raise StageReceiptBindingError(
                    "control-plane evidence digest disagrees with its journal receipt"
                )
        return records[-1] if len(records) == stage_index + 1 else None


def stage_operation_id(window_id: str, stage: WindowStage) -> str:
    """Return the deterministic control-plane and effect idempotency key."""

    _window_id(window_id)
    if not isinstance(stage, WindowStage):
        raise TypeError("stage must be a WindowStage")
    value = f"{_OPERATION_PREFIX}/{window_id}/{stage.value}"
    _operation_id(value)
    return value


def _validate_effect_binding(
    result: object,
    work: StageWorkItem,
    operation_id: str,
) -> None:
    if not isinstance(result, StageEffectResult):
        raise StageEffectBindingError("effect did not return StageEffectResult")
    if result.operation_id != operation_id:
        raise StageEffectBindingError("effect result binds another operation ID")
    if result.window_id != work.window.plan.window_id:
        raise StageEffectBindingError("effect result binds another window")
    if result.stage is not work.stage:
        raise StageEffectBindingError("effect result binds another stage")


def _stage_result_from_receipt(
    record: StageJournalRecord,
    work: StageWorkItem | None,
) -> StageResult:
    if not isinstance(record, StageJournalRecord):
        raise TypeError("record must be a StageJournalRecord")
    try:
        metadata = _ReceiptResult.model_validate(record.receipt.metadata)
    except ValueError as error:
        raise StageReceiptBindingError("receipt has invalid adapter-result metadata") from error
    stage = WindowStage(record.receipt.stage)
    expected_operation_id = stage_operation_id(record.receipt.window_id, stage)
    if record.receipt.operation_id != expected_operation_id:
        raise StageReceiptBindingError("receipt has a noncanonical operation ID")
    if work is not None:
        if record.receipt.window_id != work.window.plan.window_id:
            raise StageReceiptBindingError("receipt binds another window")
        if stage is not work.stage:
            raise StageReceiptBindingError("receipt binds another stage")
    effect_metadata, _encoded = _canonical_metadata(
        metadata.metadata,
        "receipt effect metadata",
    )
    if metadata.kind == "completion":
        if stage is WindowStage.COMMIT_AND_TERMINAL_STATE:
            raise StageReceiptBindingError("terminal stage receipt contains a completion")
        return StageCompletion(
            operation_id=record.receipt.operation_id,
            window_id=record.receipt.window_id,
            completed_stage=stage,
            evidence_sha256=record.evidence_sha256,
            metadata=effect_metadata,
        )

    terminal = metadata.terminal
    if terminal is None:
        raise StageReceiptBindingError("terminal receipt lost its terminal fields")
    outcome = TerminalOutcome(terminal.outcome)
    if (
        outcome
        in {
            TerminalOutcome.CALIBRATION_NO_WEIGHT,
            TerminalOutcome.APPLIED,
            TerminalOutcome.FAILED,
        }
        and stage is not WindowStage.COMMIT_AND_TERMINAL_STATE
    ):
        raise StageReceiptBindingError(
            f"{outcome.value} receipt is stored before the terminal stage"
        )
    incident = (
        IncidentSpec(
            incident_id=terminal.incident.incident_id,
            reason_code=terminal.incident.reason_code,
            metadata=dict(terminal.incident.metadata),
        )
        if terminal.incident is not None
        else None
    )
    return TerminalDecision(
        operation_id=record.receipt.operation_id,
        window_id=record.receipt.window_id,
        stage=stage,
        outcome=outcome,
        reason_code=terminal.reason_code,
        evidence_sha256=record.evidence_sha256,
        audit_release_block=terminal.audit_release_block,
        incident=incident,
        pause_scopes=tuple(PauseScope(value) for value in terminal.pause_scopes),
        metadata=effect_metadata,
    )


def stage_result_from_receipt(
    record: StageJournalRecord,
    *,
    work: StageWorkItem | None = None,
) -> StageResult:
    """Public strict replay of one journal receipt into its state decision."""

    return _stage_result_from_receipt(record, work)


def _effect_receipt_metadata(result: StageEffectResult) -> dict[str, JsonValue]:
    terminal: dict[str, JsonValue] | None = None
    kind = "completion"
    if isinstance(result.decision, TerminalStageEffect):
        kind = "terminal"
        incident: dict[str, JsonValue] | None = None
        if result.decision.incident is not None:
            incident_metadata, _encoded = _canonical_metadata(
                result.decision.incident.metadata,
                "incident metadata",
            )
            incident = {
                "incident_id": result.decision.incident.incident_id,
                "reason_code": result.decision.incident.reason_code,
                "metadata": incident_metadata,
            }
        terminal = {
            "outcome": result.decision.outcome.value,
            "reason_code": result.decision.reason_code,
            "audit_release_block": result.decision.audit_release_block,
            "incident": incident,
            "pause_scopes": [scope.value for scope in result.decision.pause_scopes],
        }
    return {
        "schema": ADAPTER_RESULT_SCHEMA,
        "kind": kind,
        "metadata": json.loads(result._effect_metadata_bytes),
        "terminal": terminal,
    }


def _validate_decision_for_stage(
    stage: WindowStage,
    decision: StageEffectDecision,
) -> None:
    if isinstance(decision, CompleteStageEffect):
        if stage is WindowStage.COMMIT_AND_TERMINAL_STATE:
            raise ValueError("terminal stage requires a TerminalStageEffect")
        return
    if (
        decision.outcome
        in {
            TerminalOutcome.CALIBRATION_NO_WEIGHT,
            TerminalOutcome.APPLIED,
            TerminalOutcome.FAILED,
        }
        and stage is not WindowStage.COMMIT_AND_TERMINAL_STATE
    ):
        raise ValueError(f"{decision.outcome.value} is only valid at the terminal stage")


def _canonical_metadata(
    value: Mapping[str, JsonValue] | None,
    label: str,
) -> tuple[dict[str, JsonValue], bytes]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    material = dict(value)
    if any(not isinstance(key, str) or not key for key in material):
        raise ValueError(f"{label} keys must be non-empty strings")
    try:
        encoded = canonical_json_bytes(material)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} must contain RFC 8785 JSON data") from error
    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError(f"{label} exceeds its byte ceiling")
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise ValueError(f"{label} must encode a JSON object")
    return decoded, encoded


def _validate_incident(incident: IncidentSpec) -> None:
    if not isinstance(incident, IncidentSpec):
        raise TypeError("incident must be an IncidentSpec")
    _identifier(incident.incident_id, "incident ID")
    _reason_code(incident.reason_code, "incident reason code")
    _canonical_metadata(incident.metadata, "incident metadata")


def _validate_terminal_reason(outcome: TerminalOutcome, reason_code: str | None) -> None:
    if reason_code is not None:
        _reason_code(reason_code, "terminal reason code")
    if outcome in {TerminalOutcome.APPLIED, TerminalOutcome.CALIBRATION_NO_WEIGHT}:
        if reason_code is not None:
            raise ValueError(f"{outcome.value} cannot carry a failure reason")
    elif reason_code is None:
        raise ValueError(f"{outcome.value} requires a reason code")


def _canonical_pause_scopes(scopes: Sequence[PauseScope]) -> tuple[PauseScope, ...]:
    if isinstance(scopes, (str, bytes, bytearray)) or not isinstance(scopes, Sequence):
        raise TypeError("pause scopes must be a sequence")
    values = tuple(scopes)
    if any(not isinstance(scope, PauseScope) for scope in values):
        raise TypeError("pause scopes must contain PauseScope values")
    canonical = tuple(sorted(set(values), key=lambda scope: scope.value))
    if len(values) != len(canonical):
        raise ValueError("pause scopes must be unique")
    return canonical


def _window_id(value: object) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError("window ID must be 32 lowercase hexadecimal bytes")
    return value


def _operation_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or _OPERATION_RE.fullmatch(value) is None
        or len(value.encode()) > MAX_OPERATION_ID_BYTES
    ):
        raise ValueError("operation ID is not canonical or exceeds its byte ceiling")
    return value


def _identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value.encode()) > MAX_OPERATION_ID_BYTES
    ):
        raise ValueError(f"{label} is not canonical or exceeds its byte ceiling")
    return value


def _reason_code(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or _REASON_RE.fullmatch(value) is None
        or len(value.encode()) > _MAX_REASON_CODE_BYTES
    ):
        raise ValueError(f"{label} is not canonical or exceeds its byte ceiling")
    return value


def _nonnegative_sqlite_int(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SQLITE_INTEGER
    ):
        raise ValueError(f"{label} must be a non-negative SQLite integer")
    return value


__all__ = [
    "ADAPTER_RESULT_SCHEMA",
    "AfterReceiptEffect",
    "CompleteStageEffect",
    "JournalStageAdapter",
    "JournalStageAdapterError",
    "StageEffect",
    "StageEffectBindingError",
    "StageEffectDecision",
    "StageEffectResult",
    "StageReceiptBindingError",
    "StageReceiptObserver",
    "TerminalStageEffect",
    "stage_operation_id",
    "stage_result_from_receipt",
]
