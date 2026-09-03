"""Concrete live-shadow effects for UMI's three pre-reveal transcripts.

The transcript store supplies durable assignment/request/response state and the
extrinsic journal supplies restart-safe signing and submission.  This module
connects them to ``JournalStageAdapter`` without owning a wallet, chain client,
clock, or generic transaction capability.  Its only chain intents are the three
``Commitments.set_commitment(Data::Sha256(root))`` anchors.

Facts that cannot be proven locally remain narrow injected ports: deterministic
assignment preparation, miner endpoints, finalized/Quicknet observations,
anchor reconciliation proofs, and the schedule-derived audit release block.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
import re
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol, TypeVar

from bittensor import UnsignedExtrinsic
from pydantic import Field, JsonValue, model_validator
from typing_extensions import Self

from .anchors import (
    AssignmentAnchorRecord,
    RequestAnchorRecord,
    ResponseAnchorRecord,
    SealedResponseRecord,
    VerifiedAuthEvidence,
    assignment_set_root,
    request_set_root,
    response_set_root,
)
from .protocol import (
    PROTOCOL_VERSION,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)
from .validator import (
    PreparedRequestAttempt,
    QueryOutcome,
    validate_response_envelope,
)
from .validator_adapters import (
    CompleteStageEffect,
    StageEffectResult,
    stage_operation_id,
)
from .validator_assignments import (
    MAX_ASSIGNMENTS_PER_WINDOW,
    MAX_TRANSMISSIONS_PER_ASSIGNMENT,
    AssignmentPhaseError,
    AssignmentStoreError,
    AttemptOutcomeEvidence,
    AttemptOutcomeInput,
    AttemptSnapshot,
    EvidenceRef,
    FreezeEvidence,
    FrozenRoot,
    PreparedAttemptEvidence,
    RequestStageLeaseBusy,
    TranscriptMaterialBinding,
    TranscriptPhase,
    TranscriptWindowSpec,
    ValidatorAssignmentStore,
    deterministic_assignment_id,
)
from .validator_extrinsics import (
    ANCHOR_INTENT_SCHEMA,
    ExtrinsicJournalError,
    ExtrinsicOperation,
    ExtrinsicPorts,
    ExtrinsicPortTimeout,
    ExtrinsicState,
    JournalEntry,
    SubmissionEvidence,
    ValidatorExtrinsicJournal,
)
from .validator_journal import (
    StageJournalRecord,
    StageObjectInput,
    StageReceipt,
    ValidatorStageJournal,
)
from .validator_pool_no_score import (
    POOL_NO_SCORE_SCHEMA,
    POOL_NO_SCORE_STAGE_SCHEMA,
    PoolNoScoreEvidence,
    PoolNoScoreReplay,
    PoolNoScoreStageEvidence,
    parse_pool_no_score_evidence,
    pool_no_score_metadata,
)
from .validator_state import (
    STAGE_ORDER,
    StagePending,
    StageWorkItem,
    WindowStage,
)
from .validator_transcript_abort import (
    DurableTranscriptAbortRegistry,
    TranscriptAbortRegistryError,
    read_receipt_objects,
)

TRANSCRIPT_STAGE_MANIFEST_SCHEMA = "umi-validator-transcript-stage/1"
TRANSCRIPT_TERMINAL_SCHEMA = "umi-validator-transcript-terminal/1"
TRANSCRIPT_ABORT_ORIGIN_SCHEMA = "umi-validator-transcript-abort-origin/1"
TRANSCRIPT_ABORT_STAGE_SCHEMA = "umi-validator-transcript-abort-stage/1"

MAX_FACT_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_ANCHOR_ADVANCES_PER_EFFECT = 3
_CHAIN_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_ANCHOR_KINDS = ("assignment_set", "request_set", "response_set")

AnchorKind = Literal["assignment_set", "request_set", "response_set"]
TranscriptStageName = Literal["assignment", "request_transcript", "sealed_response"]
T = TypeVar("T")


class TranscriptEffectError(RuntimeError):
    """Stable error at the concrete transcript-effect boundary."""


class TranscriptEffectPending(StagePending, TranscriptEffectError):
    """The effect is durable but cannot yet produce a terminal stage receipt."""


class TranscriptEffectBindingError(TranscriptEffectError):
    """An injected plan or verified fact is bound to another protocol object."""


class TranscriptReplayError(TranscriptEffectError):
    """A transcript receipt cannot reproduce solely from its listed payloads."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class TranscriptAbortOrigin(StrictProtocolModel):
    """The first transcript failure, preserved unchanged through reveal."""

    schema_: Literal[TRANSCRIPT_ABORT_ORIGIN_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    pool_stage_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    window_material_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    window_material_receipt_sha256: Annotated[
        str,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ]
    origin_stage: TranscriptStageName
    origin_operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    reason_code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$", max_length=128)]
    audit_release_block: Annotated[int, Field(ge=0)]
    details: dict[str, JsonValue]
    source_objects: list[EvidenceRef]

    @model_validator(mode="after")
    def validate_sources(self) -> Self:
        digests = [bytes.fromhex(item.sha256) for item in self.source_objects]
        if digests != sorted(digests) or len(digests) != len(set(digests)):
            raise ValueError("abort source objects must be unique and digest-sorted")
        return self


class TranscriptAbortStageEvidence(StrictProtocolModel):
    """One receipt-local link in the abort propagation chain."""

    schema_: Literal[TRANSCRIPT_ABORT_STAGE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    stage: TranscriptStageName
    operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    origin: EvidenceRef
    origin_stage_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None
    previous_stage_evidence_sha256: Annotated[
        str,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ]


class _ManifestAttempt(StrictProtocolModel):
    attempt_index: Annotated[int, Field(ge=0, lt=MAX_TRANSMISSIONS_PER_ASSIGNMENT)]
    prepared_evidence: EvidenceRef
    issued: bool
    claim_operation_id: Annotated[str, Field(min_length=1, max_length=160)] | None
    outcome_evidence: EvidenceRef | None
    disposition: (
        Literal[
            "sealed",
            "missing",
            "late",
            "outer_invalid",
            "resource_limit",
        ]
        | None
    )
    final: bool

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.issued != (self.claim_operation_id is not None):
            raise ValueError("manifest attempt claim fields disagree")
        if (self.outcome_evidence is None) != (self.disposition is None):
            raise ValueError("manifest attempt outcome fields disagree")
        if self.final != (self.disposition == "sealed"):
            raise ValueError("manifest final flag disagrees with disposition")
        return self


class _ManifestAssignment(StrictProtocolModel):
    assignment_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    miner_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    attempts: Annotated[
        list[_ManifestAttempt],
        Field(min_length=1, max_length=MAX_TRANSMISSIONS_PER_ASSIGNMENT),
    ]

    @model_validator(mode="after")
    def validate_attempt_order(self) -> Self:
        if [item.attempt_index for item in self.attempts] != list(range(len(self.attempts))):
            raise ValueError("manifest attempt indices are not contiguous")
        if any(item.final for item in self.attempts[:-1]):
            raise ValueError("manifest has a retry after a final response")
        return self


class _TranscriptStageManifest(StrictProtocolModel):
    schema_: Literal[TRANSCRIPT_STAGE_MANIFEST_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    stage: Literal["assignment", "request_transcript", "sealed_response"]
    freeze_kind: Literal["assignment_set", "request_set", "response_set"]
    root: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    freeze_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    transcript_spec: EvidenceRef
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    window_material_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    window_material_receipt_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    pool_stage_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    assignments: Annotated[
        list[_ManifestAssignment],
        Field(min_length=1, max_length=MAX_ASSIGNMENTS_PER_WINDOW),
    ]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        expected_kind = {
            "assignment": "assignment_set",
            "request_transcript": "request_set",
            "sealed_response": "response_set",
        }[self.stage]
        if self.freeze_kind != expected_kind:
            raise ValueError("manifest stage and freeze kind disagree")
        identifiers = [item.assignment_id for item in self.assignments]
        if identifiers != sorted(set(identifiers)):
            raise ValueError("manifest assignments must be unique and sorted")
        return self


@dataclass(frozen=True, slots=True)
class TranscriptStageReplay:
    """Root and immutable bindings reproduced from one stage receipt."""

    window_id: str
    stage: WindowStage
    freeze_kind: AnchorKind
    root: str
    assignment_count: int
    attempt_count: int
    material_binding: TranscriptMaterialBinding
    scoring_policy_hash: str
    miner_origins: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class TranscriptAbortReplay:
    """Abort origin and receipt-chain bindings reproduced without mutable state."""

    window_id: str
    stage: WindowStage
    operation_id: str
    origin: TranscriptAbortOrigin
    origin_sha256: str
    origin_stage_evidence_sha256: str | None
    previous_stage_evidence_sha256: str


@dataclass(frozen=True, slots=True)
class TranscriptAssignment:
    """One deterministic initial attempt and its snapshotted serving origin."""

    initial_attempt: PreparedRequestAttempt
    miner_url: str

    def __post_init__(self) -> None:
        if not isinstance(self.initial_attempt, PreparedRequestAttempt):
            raise TypeError("initial_attempt must be PreparedRequestAttempt")
        if not isinstance(self.miner_url, str) or not self.miner_url:
            raise ValueError("miner_url must be a nonempty serving origin")

    @property
    def assignment_id(self) -> str:
        return deterministic_assignment_id(self.initial_attempt)


@dataclass(frozen=True, slots=True)
class TranscriptExecutionPlan:
    """Complete deterministic assignment material for one selected window."""

    spec: TranscriptWindowSpec
    assignments: tuple[TranscriptAssignment, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.spec, TranscriptWindowSpec):
            raise TypeError("spec must be TranscriptWindowSpec")
        if not isinstance(self.assignments, tuple) or any(
            not isinstance(value, TranscriptAssignment) for value in self.assignments
        ):
            raise TypeError("assignments must be a tuple of TranscriptAssignment values")
        if len(self.assignments) != self.spec.expected_assignment_count:
            raise ValueError("execution plan assignment cardinality disagrees with its spec")
        identifiers = tuple(value.assignment_id for value in self.assignments)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("execution plan assignments must be unique and sorted by ID")
        for assignment in self.assignments:
            prepared = assignment.initial_attempt
            if prepared.request.window_id != self.spec.window_id:
                raise ValueError("execution plan attempt binds another window")
            if prepared.validator_hotkey != self.spec.validator_hotkey:
                raise ValueError("execution plan attempt binds another validator")
            if prepared.request.response_close_round != self.spec.response_close_round:
                raise ValueError("execution plan attempt has another response-close round")
            if prepared.request.reveal_round != self.spec.reveal_round:
                raise ValueError("execution plan attempt has another reveal round")


@dataclass(frozen=True, slots=True)
class TranscriptExecutionMaterial:
    """One pool-authoritative plan and the digests that make it immutable."""

    plan: TranscriptExecutionPlan
    material_sha256: str
    material_receipt_sha256: str
    pool_stage_evidence_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.plan, TranscriptExecutionPlan):
            raise TypeError("material plan must be TranscriptExecutionPlan")
        _hex32(self.material_sha256, "window material digest")
        _hex32(self.material_receipt_sha256, "window material receipt digest")
        _hex32(self.pool_stage_evidence_sha256, "pool-stage evidence digest")

    @property
    def spec(self) -> TranscriptWindowSpec:
        return self.plan.spec

    @property
    def assignments(self) -> tuple[TranscriptAssignment, ...]:
        return self.plan.assignments

    @property
    def binding(self) -> TranscriptMaterialBinding:
        return TranscriptMaterialBinding(
            material_sha256=self.material_sha256,
            material_receipt_sha256=self.material_receipt_sha256,
            pool_stage_evidence_sha256=self.pool_stage_evidence_sha256,
        )


@dataclass(frozen=True, slots=True)
class VerifiedProtocolObservation:
    """A finalized-head/Quicknet observation from the owned verifier boundary."""

    finalized_block: int
    finalized_block_hash: str
    quicknet_round: int
    evidence_bytes: bytes

    def __post_init__(self) -> None:
        _nonnegative_int(self.finalized_block, "finalized block")
        _chain_hash(self.finalized_block_hash, "finalized block hash")
        _positive_int(self.quicknet_round, "Quicknet round")
        _fact_bytes(self.evidence_bytes, "protocol observation")


@dataclass(frozen=True, slots=True)
class VerifiedAnchorFinality:
    """Verified inclusion and finalization timing for one exact anchor root."""

    anchor_kind: AnchorKind
    root: str
    operation_id: str
    inclusion_block: int
    inclusion_block_hash: str
    inclusion_round: int
    finalized_head_block: int
    finalized_head_hash: str
    finalized_round: int
    evidence_bytes: bytes

    def __post_init__(self) -> None:
        if self.anchor_kind not in _ANCHOR_KINDS:
            raise ValueError("anchor finality has an unsupported kind")
        _hex32(self.root, "anchor root")
        _hex32(self.operation_id, "anchor operation ID")
        _nonnegative_int(self.inclusion_block, "anchor inclusion block")
        _chain_hash(self.inclusion_block_hash, "anchor inclusion block hash")
        _positive_int(self.inclusion_round, "anchor inclusion round")
        _nonnegative_int(self.finalized_head_block, "anchor finalized head")
        _chain_hash(self.finalized_head_hash, "anchor finalized head hash")
        _positive_int(self.finalized_round, "anchor finalized round")
        if self.inclusion_block > self.finalized_head_block:
            raise ValueError("anchor inclusion is above its finalized head")
        if self.inclusion_round > self.finalized_round:
            raise ValueError("anchor finalization precedes inclusion")
        _fact_bytes(self.evidence_bytes, "anchor finality")


class TranscriptPlanPort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
    ) -> object | Awaitable[object]: ...


class ObservationPort(Protocol):
    def __call__(
        self,
        boundary: str,
        work: StageWorkItem,
    ) -> VerifiedProtocolObservation | Awaitable[VerifiedProtocolObservation]: ...


class AnchorPortsPort(Protocol):
    def __call__(
        self,
        operation: ExtrinsicOperation,
        work: StageWorkItem,
    ) -> ExtrinsicPorts | Awaitable[ExtrinsicPorts]: ...


class AnchorFinalityPort(Protocol):
    def __call__(
        self,
        operation: ExtrinsicOperation,
        frozen: FrozenRoot,
        entry: JournalEntry,
        work: StageWorkItem,
    ) -> VerifiedAnchorFinality | Awaitable[VerifiedAnchorFinality]: ...


class AuditReleasePort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
        reason_code: str,
    ) -> int | Awaitable[int]: ...


class TransportPort(Protocol):
    async def __call__(
        self,
        prepared: PreparedRequestAttempt,
        assignment_id: str,
        miner_url: str,
        work: StageWorkItem,
    ) -> QueryOutcome: ...


class RetryPreparationPort(Protocol):
    def __call__(
        self,
        assignment: TranscriptAssignment,
        previous: AttemptSnapshot,
        next_attempt_index: int,
        work: StageWorkItem,
    ) -> PreparedRequestAttempt | Awaitable[PreparedRequestAttempt | None] | None: ...


@dataclass(frozen=True, slots=True)
class TranscriptEffectPorts:
    """All external authority used by the three concrete effects."""

    plan: TranscriptPlanPort
    observe: ObservationPort
    anchor_ports: AnchorPortsPort
    verify_anchor: AnchorFinalityPort
    audit_release_block: AuditReleasePort
    transport: TransportPort | None = None
    prepare_retry: RetryPreparationPort | None = None

    def __post_init__(self) -> None:
        for name in (
            "plan",
            "observe",
            "anchor_ports",
            "verify_anchor",
            "audit_release_block",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} port must be callable")
        for name in ("transport", "prepare_retry"):
            value = getattr(self, name)
            if value is not None and not callable(value):
                raise TypeError(f"{name} port must be callable or None")
        if self.transport is not None and not _is_async_callable(self.transport):
            raise TypeError("transport port must be an async callable")


class _AnchorRejected(TranscriptEffectError):
    def __init__(self, reason_code: str, entry: JournalEntry) -> None:
        self.reason_code = reason_code
        self.entry = entry
        super().__init__(reason_code)


class _AnchorSubmissionClosed(ExtrinsicJournalError):
    """A final boundary observation forbids this exact network submission."""

    def __init__(self, observation: VerifiedProtocolObservation) -> None:
        self.observation = observation
        super().__init__("anchor submission is outside its protocol interval")


@dataclass(frozen=True, slots=True)
class _RequestIssueDeadline:
    assignment_id: str
    attempt_index: int
    observation: VerifiedProtocolObservation


class _TranscriptEffectBase:
    def __init__(
        self,
        *,
        assignments: ValidatorAssignmentStore,
        extrinsics: ValidatorExtrinsicJournal,
        ports: TranscriptEffectPorts,
        abort_registry: DurableTranscriptAbortRegistry | None = None,
        maximum_anchor_advances: int = MAX_ANCHOR_ADVANCES_PER_EFFECT,
        maximum_transport_concurrency: int = 32,
        transport_timeout_seconds: float = 60.0,
    ) -> None:
        if not isinstance(assignments, ValidatorAssignmentStore):
            raise TypeError("assignments must be ValidatorAssignmentStore")
        if not isinstance(extrinsics, ValidatorExtrinsicJournal):
            raise TypeError("extrinsics must be ValidatorExtrinsicJournal")
        if not isinstance(ports, TranscriptEffectPorts):
            raise TypeError("ports must be TranscriptEffectPorts")
        if (
            isinstance(maximum_anchor_advances, bool)
            or not isinstance(maximum_anchor_advances, int)
            or maximum_anchor_advances <= 0
            or maximum_anchor_advances > 16
        ):
            raise ValueError("maximum_anchor_advances must be in [1, 16]")
        if (
            isinstance(maximum_transport_concurrency, bool)
            or not isinstance(maximum_transport_concurrency, int)
            or not 1 <= maximum_transport_concurrency <= 1_024
        ):
            raise ValueError("maximum_transport_concurrency must be in [1, 1024]")
        if (
            isinstance(transport_timeout_seconds, bool)
            or not isinstance(transport_timeout_seconds, (int, float))
            or not math.isfinite(transport_timeout_seconds)
            or transport_timeout_seconds <= 0
        ):
            raise ValueError("transport_timeout_seconds must be positive and finite")
        self._assignments = assignments
        self._extrinsics = extrinsics
        self._ports = ports
        self._abort_registry = abort_registry or DurableTranscriptAbortRegistry(
            assignments.root / "abort-registry"
        )
        self._maximum_anchor_advances = maximum_anchor_advances
        self._maximum_transport_concurrency = maximum_transport_concurrency
        self._transport_timeout_seconds = float(transport_timeout_seconds)

    async def after_receipt(
        self,
        *,
        record: StageJournalRecord,
        work: StageWorkItem,
    ) -> None:
        """Bind an origin marker only after its stage receipt is durable."""

        if record.receipt.window_id != work.window.plan.window_id:
            raise TranscriptEffectBindingError("abort receipt binds another window")
        try:
            replay = _replay_abort_stage_receipt(
                record.receipt,
                read_receipt_objects(record),
            )
        except (TranscriptAbortRegistryError, TranscriptReplayError) as error:
            raise TranscriptEffectBindingError("abort receipt cannot be replayed") from error
        if replay is None:
            return
        if isinstance(replay, PoolNoScoreReplay):
            existing = self._abort_registry.load(replay.window_id)
            origin_bytes = canonical_json_bytes(replay.origin)
            if (
                existing is None
                or existing.origin_stage != WindowStage.POOL_AND_SELECTION.value
                or existing.origin_receipt_evidence_sha256 != replay.pool_stage_evidence_sha256
                or existing.origin_sha256 != replay.origin_sha256
                or existing.origin_bytes != origin_bytes
            ):
                raise TranscriptEffectBindingError(
                    "pool no-score propagation differs from its durable origin"
                )
            return
        origin_bytes = canonical_json_bytes(replay.origin)
        existing = self._abort_registry.load(replay.window_id)
        if replay.stage is WindowStage(replay.origin.origin_stage):
            self._abort_registry.record(
                window_id=replay.window_id,
                origin_stage=replay.origin.origin_stage,
                origin_receipt_evidence_sha256=record.evidence_sha256,
                origin_bytes=origin_bytes,
            )
            return
        if (
            existing is None
            or existing.origin_stage != replay.origin.origin_stage
            or existing.origin_receipt_evidence_sha256 != replay.origin_stage_evidence_sha256
            or existing.origin_sha256 != replay.origin_sha256
            or existing.origin_bytes != origin_bytes
        ):
            raise TranscriptEffectBindingError("propagated abort differs from its durable origin")

    def _propagate_abort(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult | None:
        entry = self._abort_registry.load(work.window.plan.window_id)
        if entry is None:
            return None
        try:
            decoded = json.loads(entry.origin_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TranscriptEffectBindingError("durable no-score origin is invalid") from error
        if isinstance(decoded, dict) and decoded.get("schema") == POOL_NO_SCORE_SCHEMA:
            try:
                origin = parse_pool_no_score_evidence(entry.origin_bytes)
            except ValueError as error:
                raise TranscriptEffectBindingError(
                    "durable pool no-score origin is invalid"
                ) from error
            if (
                entry.origin_stage != WindowStage.POOL_AND_SELECTION.value
                or origin.window_id != work.window.plan.window_id
                or origin.scoring_policy_hash != work.window.plan.scoring_policy_hash
                or origin.window.to_plan() != work.window.plan
                or origin.operation_id
                != stage_operation_id(origin.window_id, WindowStage.POOL_AND_SELECTION)
            ):
                raise TranscriptEffectBindingError(
                    "durable pool no-score origin changes its window binding"
                )
            previous = _previous_stage_digest(work)
            origin_ref = _evidence_ref(entry.origin_bytes, "application/json")
            link = PoolNoScoreStageEvidence(
                schema=POOL_NO_SCORE_STAGE_SCHEMA,
                protocol=PROTOCOL_VERSION,
                window_id=origin.window_id,
                stage=work.stage.value,
                operation_id=operation_id,
                origin=origin_ref,
                pool_stage_evidence_sha256=entry.origin_receipt_evidence_sha256,
                previous_stage_evidence_sha256=previous,
            )
            link_bytes = canonical_json_bytes(link)
            return StageEffectResult(
                operation_id=operation_id,
                window_id=origin.window_id,
                stage=work.stage,
                objects=_unique_objects(
                    (
                        StageObjectInput(entry.origin_bytes, "application/json"),
                        StageObjectInput(link_bytes, "application/json"),
                    )
                ),
                metadata=pool_no_score_metadata(
                    origin,
                    origin_sha256=entry.origin_sha256,
                    pool_stage_evidence_sha256=entry.origin_receipt_evidence_sha256,
                    previous_stage_evidence_sha256=previous,
                ),
                decision=CompleteStageEffect(),
            )
        origin = _parse_canonical_model(
            entry.origin_bytes,
            TranscriptAbortOrigin,
            "transcript abort origin",
        )
        current_index = _transcript_stage_index(work.stage)
        origin_index = _transcript_stage_index(WindowStage(origin.origin_stage))
        if current_index <= origin_index:
            raise TranscriptEffectBindingError("durable abort is not before the pending stage")
        prior = _previous_stage_digest(work)
        origin_ref = _evidence_ref(entry.origin_bytes, "application/json")
        link = TranscriptAbortStageEvidence(
            schema=TRANSCRIPT_ABORT_STAGE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=origin.window_id,
            stage=work.stage.value,
            operation_id=operation_id,
            origin=origin_ref,
            origin_stage_evidence_sha256=entry.origin_receipt_evidence_sha256,
            previous_stage_evidence_sha256=prior,
        )
        link_bytes = canonical_json_bytes(link)
        return StageEffectResult(
            operation_id=operation_id,
            window_id=origin.window_id,
            stage=work.stage,
            objects=_unique_objects(
                (
                    StageObjectInput(entry.origin_bytes, "application/json"),
                    StageObjectInput(link_bytes, "application/json"),
                )
            ),
            metadata=_abort_metadata(origin, link, origin_ref.sha256),
            decision=CompleteStageEffect(),
        )

    async def _plan(self, work: StageWorkItem) -> TranscriptExecutionMaterial:
        value = await _await_port(self._ports.plan(work))
        material = _execution_material(value)
        value = material.plan
        expected = work.window.plan
        if value.spec.window_id != expected.window_id:
            raise TranscriptEffectBindingError("transcript plan binds another window")
        if value.spec.issue_close_round != expected.issue_close_round:
            raise TranscriptEffectBindingError("transcript plan changes issue close")
        if value.spec.response_close_round != expected.response_close_round:
            raise TranscriptEffectBindingError("transcript plan changes response close")
        if value.spec.reveal_round != expected.reveal_round:
            raise TranscriptEffectBindingError("transcript plan changes reveal round")
        for assignment in value.assignments:
            if assignment.initial_attempt.request.scoring_policy_hash != (
                expected.scoring_policy_hash
            ):
                raise TranscriptEffectBindingError(
                    "transcript request binds another scoring policy"
                )
        return material

    async def _observe(
        self,
        boundary: str,
        work: StageWorkItem,
    ) -> VerifiedProtocolObservation:
        value = await _await_port(self._ports.observe(boundary, work))
        if not isinstance(value, VerifiedProtocolObservation):
            raise TranscriptEffectBindingError(
                "observation port did not return VerifiedProtocolObservation"
            )
        return value

    async def _anchor(
        self,
        *,
        kind: AnchorKind,
        frozen: FrozenRoot,
        plan: TranscriptExecutionMaterial,
        work: StageWorkItem,
        progress_observation: VerifiedProtocolObservation,
        submission_open_round: int | None,
        submission_close_round: int,
    ) -> tuple[ExtrinsicOperation, JournalEntry, VerifiedAnchorFinality]:
        operation = _anchor_operation(kind, frozen, plan.spec)
        _positive_int(submission_close_round, "anchor submission close round")
        if submission_open_round is not None:
            _positive_int(submission_open_round, "anchor submission open round")
            if submission_open_round >= submission_close_round:
                raise ValueError("anchor submission interval is empty")
        entry = self._extrinsics.load(operation)
        can_reconcile_only = entry is not None and entry.state in {
            ExtrinsicState.SIGNED,
            ExtrinsicState.SUBMITTED,
            ExtrinsicState.UNKNOWN,
            ExtrinsicState.FINALIZED_SUCCESS,
            ExtrinsicState.FINALIZED_FAILURE,
            ExtrinsicState.EXPIRED,
        }
        outside_interval = progress_observation.quicknet_round >= submission_close_round or (
            submission_open_round is not None
            and progress_observation.quicknet_round < submission_open_round
        )
        if outside_interval and not can_reconcile_only:
            raise _AnchorSubmissionClosed(progress_observation)

        base_ports = await _await_port(self._ports.anchor_ports(operation, work))
        if not isinstance(base_ports, ExtrinsicPorts):
            raise TranscriptEffectBindingError("anchor-ports port did not return ExtrinsicPorts")
        if not _is_async_callable(base_ports.submit):
            raise TranscriptEffectBindingError("anchor submit port must be an async callable")

        async def guarded_submit(
            unsigned: UnsignedExtrinsic,
            signature: bytes,
        ) -> SubmissionEvidence:
            submission_observation = await self._observe(
                f"{kind}_anchor_submit",
                work,
            )
            if submission_observation.quicknet_round >= submission_close_round or (
                submission_open_round is not None
                and submission_observation.quicknet_round < submission_open_round
            ):
                raise _AnchorSubmissionClosed(submission_observation)
            value = await _await_port(base_ports.submit(unsigned, signature))
            if not isinstance(value, SubmissionEvidence):
                raise TranscriptEffectBindingError(
                    "anchor submit port did not return SubmissionEvidence"
                )
            return value

        ports = ExtrinsicPorts(
            prepare=base_ports.prepare,
            verify_prepared_call=base_ports.verify_prepared_call,
            sign=base_ports.sign,
            submit=guarded_submit,
            reconcile=base_ports.reconcile,
            derive_signed_hash=base_ports.derive_signed_hash,
        )
        for _index in range(self._maximum_anchor_advances):
            if entry is not None and entry.state in {
                ExtrinsicState.FINALIZED_SUCCESS,
                ExtrinsicState.FINALIZED_FAILURE,
                ExtrinsicState.EXPIRED,
            }:
                break
            try:
                if entry is not None and entry.state in {
                    ExtrinsicState.SUBMITTED,
                    ExtrinsicState.UNKNOWN,
                }:
                    # Reconcile once per effect invocation.  A nonterminal result
                    # remains durable and is retried by the outer service later.
                    entry = await self._extrinsics.advance(operation, ports)
                    break
                entry = await self._extrinsics.advance(operation, ports)
            except ExtrinsicPortTimeout as error:
                raise TranscriptEffectPending(f"{kind}_anchor_port_pending") from error
        if entry is None:
            raise TranscriptEffectError("anchor journal produced no entry")
        if entry.state is ExtrinsicState.FINALIZED_FAILURE:
            raise _AnchorRejected("anchor_finalized_failure", entry)
        if entry.state is ExtrinsicState.EXPIRED:
            raise _AnchorRejected("anchor_mortal_era_expired", entry)
        if entry.state is not ExtrinsicState.FINALIZED_SUCCESS:
            raise TranscriptEffectPending(f"{kind}_anchor_pending")
        finality = await _await_port(self._ports.verify_anchor(operation, frozen, entry, work))
        if not isinstance(finality, VerifiedAnchorFinality):
            raise TranscriptEffectBindingError(
                "anchor verifier did not return VerifiedAnchorFinality"
            )
        _validate_anchor_finality(finality, operation, frozen, entry)
        return operation, entry, finality

    async def _terminal(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        reason_code: str,
        details: Mapping[str, JsonValue] | None = None,
        extra_objects: Sequence[StageObjectInput] = (),
    ) -> StageEffectResult:
        release = await _await_port(self._ports.audit_release_block(work, reason_code))
        _nonnegative_int(release, "audit release block")
        detail_object = dict(details or {})
        evidence = canonical_json_bytes(
            {
                "schema": TRANSCRIPT_TERMINAL_SCHEMA,
                "protocol": PROTOCOL_VERSION,
                "window_id": work.window.plan.window_id,
                "stage": work.stage.value,
                "operation_id": operation_id,
                "reason_code": reason_code,
                "details": detail_object,
            }
        )
        source_objects = _unique_objects(extra_objects) if extra_objects else ()
        source_refs = sorted(
            (_evidence_ref(item.data, item.media_type) for item in source_objects),
            key=lambda item: bytes.fromhex(item.sha256),
        )
        material_binding = self._assignments.load_window_material(work.window.plan.window_id)
        if material_binding is None:
            raise TranscriptEffectBindingError(
                "transcript abort lacks its durable window-material binding"
            )
        origin = TranscriptAbortOrigin(
            schema=TRANSCRIPT_ABORT_ORIGIN_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=work.window.plan.window_id,
            scoring_policy_hash=work.window.plan.scoring_policy_hash,
            pool_stage_evidence_sha256=_pool_stage_digest(work),
            window_material_sha256=material_binding.material_sha256,
            window_material_receipt_sha256=(material_binding.material_receipt_sha256),
            origin_stage=work.stage.value,
            origin_operation_id=operation_id,
            reason_code=reason_code,
            audit_release_block=release,
            details=detail_object,
            source_objects=source_refs,
        )
        origin_bytes = canonical_json_bytes(origin)
        origin_ref = _evidence_ref(origin_bytes, "application/json")
        link = TranscriptAbortStageEvidence(
            schema=TRANSCRIPT_ABORT_STAGE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=work.window.plan.window_id,
            stage=work.stage.value,
            operation_id=operation_id,
            origin=origin_ref,
            origin_stage_evidence_sha256=None,
            previous_stage_evidence_sha256=_previous_stage_digest(work),
        )
        link_bytes = canonical_json_bytes(link)
        return StageEffectResult(
            operation_id=operation_id,
            window_id=work.window.plan.window_id,
            stage=work.stage,
            objects=_unique_objects(
                (
                    StageObjectInput(evidence, "application/json"),
                    StageObjectInput(origin_bytes, "application/json"),
                    StageObjectInput(link_bytes, "application/json"),
                    *source_objects,
                )
            ),
            metadata=_abort_metadata(origin, link, origin_ref.sha256),
            decision=CompleteStageEffect(),
        )

    def _complete(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        plan: TranscriptExecutionMaterial,
        frozen: FrozenRoot,
        anchor_operation: ExtrinsicOperation,
        entry: JournalEntry,
        finality: VerifiedAnchorFinality,
        observation: VerifiedProtocolObservation,
    ) -> StageEffectResult:
        manifest = _stage_manifest(self._assignments, plan, work.stage, frozen)
        objects = _unique_objects(
            (
                StageObjectInput(manifest, "application/json"),
                *_transcript_object_graph(self._assignments, plan),
                StageObjectInput(canonical_json_bytes(frozen.evidence), "application/json"),
                StageObjectInput(canonical_json_bytes(entry.receipt), "application/json"),
                StageObjectInput(observation.evidence_bytes, "application/octet-stream"),
                StageObjectInput(finality.evidence_bytes, "application/octet-stream"),
            )
        )
        return StageEffectResult(
            operation_id=operation_id,
            window_id=work.window.plan.window_id,
            stage=work.stage,
            objects=objects,
            metadata={
                "anchor_kind": finality.anchor_kind,
                "anchor_root": frozen.root,
                "anchor_operation_id": anchor_operation.operation_id,
                "inclusion_block": finality.inclusion_block,
                "inclusion_block_hash": finality.inclusion_block_hash,
                "inclusion_round": finality.inclusion_round,
                "finalized_head_block": finality.finalized_head_block,
                "finalized_head_hash": finality.finalized_head_hash,
                "finalized_round": finality.finalized_round,
                "transcript_phase": self._assignments.load_window(plan.spec.window_id).phase.value,
                "window_material_sha256": plan.material_sha256,
                "window_material_receipt_sha256": plan.material_receipt_sha256,
                "pool_stage_evidence_sha256": plan.pool_stage_evidence_sha256,
            },
            decision=CompleteStageEffect(),
        )


class AssignmentTranscriptEffect(_TranscriptEffectBase):
    """Freeze and finalize the assignment anchor before any send claim exists."""

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        _require_stage(work, WindowStage.ASSIGNMENT)
        propagated = self._propagate_abort(operation_id=operation_id, work=work)
        if propagated is not None:
            return propagated
        plan = await self._plan(work)
        observation = await self._observe("assignment_freeze", work)
        try:
            snapshot = self._assignments.create_window(plan.spec)
            self._assignments.bind_window_material(plan.spec.window_id, plan.binding)
            if (
                snapshot.phase is TranscriptPhase.COLLECTING_ASSIGNMENTS
                and observation.quicknet_round >= plan.spec.issue_close_round
            ):
                return await self._terminal(
                    operation_id=operation_id,
                    work=work,
                    reason_code="assignment_freeze_deadline_missed",
                    details={"observed_round": observation.quicknet_round},
                    extra_objects=(
                        StageObjectInput(
                            observation.evidence_bytes,
                            "application/octet-stream",
                        ),
                    ),
                )
            for assignment in plan.assignments:
                self._assignments.add_assignment(
                    plan.spec.window_id,
                    assignment.initial_attempt,
                    observed_round=observation.quicknet_round,
                )
            frozen = self._assignments.freeze_assignments(
                plan.spec.window_id,
                observed_round=observation.quicknet_round,
            )
            anchor_operation, entry, finality = await self._anchor(
                kind="assignment_set",
                frozen=frozen,
                plan=plan,
                work=work,
                progress_observation=observation,
                submission_open_round=None,
                submission_close_round=plan.spec.issue_close_round,
            )
        except _AnchorSubmissionClosed as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="assignment_anchor_submission_deadline_missed",
                details={"observed_round": error.observation.quicknet_round},
                extra_objects=(
                    StageObjectInput(
                        error.observation.evidence_bytes,
                        "application/octet-stream",
                    ),
                ),
            )
        except _AnchorRejected as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code=error.reason_code,
                details={"anchor_state": error.entry.state.value},
                extra_objects=(
                    StageObjectInput(canonical_json_bytes(error.entry.receipt), "application/json"),
                ),
            )
        except (AssignmentStoreError, ExtrinsicJournalError) as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="assignment_transcript_fault",
                details={"error_type": type(error).__name__},
            )
        if (
            finality.inclusion_round >= plan.spec.issue_close_round
            or finality.finalized_round >= plan.spec.issue_close_round
        ):
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="assignment_anchor_deadline_missed",
                details={
                    "inclusion_round": finality.inclusion_round,
                    "finalized_round": finality.finalized_round,
                },
                extra_objects=(
                    StageObjectInput(finality.evidence_bytes, "application/octet-stream"),
                ),
            )
        return self._complete(
            operation_id=operation_id,
            work=work,
            plan=plan,
            frozen=frozen,
            anchor_operation=anchor_operation,
            entry=entry,
            finality=finality,
            observation=observation,
        )


class RequestTranscriptEffect(_TranscriptEffectBase):
    """Issue bounded requests/retries, freeze them, and finalize their anchor."""

    def __init__(
        self,
        *,
        assignments: ValidatorAssignmentStore,
        extrinsics: ValidatorExtrinsicJournal,
        ports: TranscriptEffectPorts,
        maximum_transport_concurrency: int,
        transport_timeout_seconds: float,
        maximum_anchor_advances: int = MAX_ANCHOR_ADVANCES_PER_EFFECT,
        abort_registry: DurableTranscriptAbortRegistry | None = None,
    ) -> None:
        # Both values are deliberately mandatory: live wiring must source them
        # from the active policy/capacity preflight rather than silently using a
        # process-local default that cannot issue the complete launch panel.
        super().__init__(
            assignments=assignments,
            extrinsics=extrinsics,
            ports=ports,
            abort_registry=abort_registry,
            maximum_anchor_advances=maximum_anchor_advances,
            maximum_transport_concurrency=maximum_transport_concurrency,
            transport_timeout_seconds=transport_timeout_seconds,
        )

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        _require_stage(work, WindowStage.REQUEST_TRANSCRIPT)
        propagated = self._propagate_abort(operation_id=operation_id, work=work)
        if propagated is not None:
            return propagated
        plan = await self._plan(work)
        try:
            self._assignments.bind_window_material(plan.spec.window_id, plan.binding)
            lease = self._assignments.acquire_request_stage_lease(
                plan.spec.window_id,
                operation_id=operation_id,
            )
        except RequestStageLeaseBusy as error:
            raise TranscriptEffectPending("request_stage_lease_pending") from error
        except AssignmentStoreError as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="request_transcript_fault",
                details={"error_type": type(error).__name__},
            )
        try:
            return await self._perform_with_lease(
                operation_id=operation_id,
                work=work,
                plan=plan,
            )
        finally:
            lease.release()

    async def _perform_with_lease(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        plan: TranscriptExecutionMaterial,
    ) -> StageEffectResult:
        observation = await self._observe("request_stage", work)
        try:
            snapshot = self._assignments.load_window(plan.spec.window_id)
            if snapshot.phase is TranscriptPhase.ASSIGNMENTS_FROZEN:
                orphaned = self._assignments.list_orphaned_send_claims(plan.spec.window_id)
                if orphaned:
                    return await self._terminal(
                        operation_id=operation_id,
                        work=work,
                        reason_code="issuance_outcome_unknown",
                        details={
                            "orphaned_claims": [
                                {
                                    "assignment_id": attempt.assignment_id,
                                    "attempt_index": attempt.attempt_index,
                                    "claim_operation_id": attempt.claim_operation_id,
                                }
                                for attempt in orphaned
                            ]
                        },
                    )
                terminal = await self._issue_requests(
                    operation_id=operation_id,
                    work=work,
                    plan=plan,
                )
                if terminal is not None:
                    return terminal
            elif snapshot.phase not in {
                TranscriptPhase.REQUESTS_FROZEN,
                TranscriptPhase.RESPONSES_FROZEN,
            }:
                raise AssignmentPhaseError(f"request effect cannot run from {snapshot.phase.value}")
            snapshot = self._assignments.load_window(plan.spec.window_id)
            if snapshot.phase is TranscriptPhase.ASSIGNMENTS_FROZEN:
                freeze_observation = await self._observe("request_freeze", work)
                if freeze_observation.quicknet_round >= plan.spec.response_close_round:
                    return await self._terminal(
                        operation_id=operation_id,
                        work=work,
                        reason_code="request_freeze_deadline_missed",
                        details={"observed_round": freeze_observation.quicknet_round},
                        extra_objects=(
                            StageObjectInput(
                                freeze_observation.evidence_bytes,
                                "application/octet-stream",
                            ),
                        ),
                    )
            else:
                freeze_observation = observation
            frozen = self._assignments.freeze_requests(
                plan.spec.window_id,
                observed_round=freeze_observation.quicknet_round,
            )
            anchor_operation, entry, finality = await self._anchor(
                kind="request_set",
                frozen=frozen,
                plan=plan,
                work=work,
                progress_observation=freeze_observation,
                submission_open_round=None,
                submission_close_round=plan.spec.response_close_round,
            )
        except _AnchorSubmissionClosed as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="request_anchor_submission_deadline_missed",
                details={"observed_round": error.observation.quicknet_round},
                extra_objects=(
                    StageObjectInput(
                        error.observation.evidence_bytes,
                        "application/octet-stream",
                    ),
                ),
            )
        except _AnchorRejected as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code=error.reason_code,
                details={"anchor_state": error.entry.state.value},
                extra_objects=(
                    StageObjectInput(canonical_json_bytes(error.entry.receipt), "application/json"),
                ),
            )
        except (AssignmentStoreError, ExtrinsicJournalError) as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="request_transcript_fault",
                details={"error_type": type(error).__name__},
            )
        if (
            finality.inclusion_round >= plan.spec.response_close_round
            or finality.finalized_round >= plan.spec.reveal_round
        ):
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="request_anchor_deadline_missed",
                details={
                    "inclusion_round": finality.inclusion_round,
                    "finalized_round": finality.finalized_round,
                },
                extra_objects=(
                    StageObjectInput(finality.evidence_bytes, "application/octet-stream"),
                ),
            )
        return self._complete(
            operation_id=operation_id,
            work=work,
            plan=plan,
            frozen=frozen,
            anchor_operation=anchor_operation,
            entry=entry,
            finality=finality,
            observation=observation,
        )

    async def _issue_requests(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        plan: TranscriptExecutionMaterial,
    ) -> StageEffectResult | None:
        if self._ports.transport is None:
            raise TranscriptEffectBindingError("request effect requires a transport port")
        semaphore = asyncio.Semaphore(self._maximum_transport_concurrency)
        results = await asyncio.gather(
            *(
                self._issue_assignment(
                    operation_id=operation_id,
                    work=work,
                    plan=plan,
                    assignment=assignment,
                    semaphore=semaphore,
                )
                for assignment in plan.assignments
            ),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                raise result
            if result is not None:
                return await self._terminal(
                    operation_id=operation_id,
                    work=work,
                    reason_code="request_issue_deadline_missed",
                    details={
                        "assignment_id": result.assignment_id,
                        "attempt_index": result.attempt_index,
                        "observed_round": result.observation.quicknet_round,
                    },
                    extra_objects=(
                        StageObjectInput(
                            result.observation.evidence_bytes,
                            "application/octet-stream",
                        ),
                    ),
                )
        return None

    async def _issue_assignment(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        plan: TranscriptExecutionMaterial,
        assignment: TranscriptAssignment,
        semaphore: asyncio.Semaphore,
    ) -> _RequestIssueDeadline | None:
        if self._ports.transport is None:  # Narrowed by _issue_requests.
            raise TranscriptEffectBindingError("request effect requires a transport port")
        while True:
            attempts = self._assignments.list_attempts(assignment.assignment_id)
            if any(attempt.final for attempt in attempts):
                return None
            latest = attempts[-1]
            if not latest.issued:
                # The semaphore is acquired before the one-way durable claim.
                # Waiting work therefore cannot become claimed and then start
                # transport after its protocol deadline.
                async with semaphore:
                    claim_observation = await self._observe("request_claim", work)
                    deadline = (
                        plan.spec.issue_close_round
                        if latest.attempt_index == 0
                        else plan.spec.response_close_round
                    )
                    if claim_observation.quicknet_round >= deadline:
                        return _RequestIssueDeadline(
                            assignment.assignment_id,
                            latest.attempt_index,
                            claim_observation,
                        )
                    claim = self._assignments.claim_for_send(
                        assignment.assignment_id,
                        latest.attempt_index,
                        operation_id=_send_operation_id(
                            operation_id,
                            assignment.assignment_id,
                            latest.attempt_index,
                        ),
                        observed_round=claim_observation.quicknet_round,
                    )
                    if claim.should_send:
                        try:
                            outcome = await asyncio.wait_for(
                                _await_port(
                                    self._ports.transport(
                                        claim.attempt.prepared,
                                        assignment.assignment_id,
                                        assignment.miner_url,
                                        work,
                                    )
                                ),
                                timeout=self._transport_timeout_seconds,
                            )
                        except (asyncio.TimeoutError, TimeoutError):
                            # A coroutine timeout is an observed in-process
                            # outcome, unlike a process crash.  Persist it now so
                            # restart cannot mistake the durable claim for an
                            # unknowable send boundary.
                            timeout_observation = await self._observe(
                                "transport_timeout",
                                work,
                            )
                            self._assignments.record_outcome(
                                assignment.assignment_id,
                                latest.attempt_index,
                                _no_response_outcome(
                                    "transport_timeout",
                                    timeout_observation,
                                    plan.spec,
                                ),
                            )
                        else:
                            if not isinstance(outcome, QueryOutcome):
                                raise TranscriptEffectBindingError(
                                    "transport port did not return QueryOutcome"
                                )
                            receipt_observation = await self._observe(
                                "response_receipt",
                                work,
                            )
                            converted = _attempt_outcome(
                                outcome,
                                prepared=claim.attempt.prepared,
                                spec=plan.spec,
                                observation=receipt_observation,
                            )
                            self._assignments.record_outcome(
                                assignment.assignment_id,
                                latest.attempt_index,
                                converted,
                            )
                attempts = self._assignments.list_attempts(assignment.assignment_id)
                latest = attempts[-1]
            if latest.outcome is None:
                # A prior process may have crashed after its durable claim.
                # Reissuing would make the transcript ambiguous, so the response
                # stage later turns it into one explicit missing marker.
                return None
            if latest.final or len(attempts) >= (
                plan.spec.maximum_request_transmissions_per_assignment
            ):
                return None
            if self._ports.prepare_retry is None:
                return None
            retry_observation = await self._observe("retry_prepare", work)
            if retry_observation.quicknet_round >= plan.spec.response_close_round:
                return None
            prepared = await _await_port(
                self._ports.prepare_retry(
                    assignment,
                    latest,
                    len(attempts),
                    work,
                )
            )
            if prepared is None:
                return None
            if not isinstance(prepared, PreparedRequestAttempt):
                raise TranscriptEffectBindingError("retry port returned another value type")
            self._assignments.add_retry(
                assignment.assignment_id,
                prepared,
                observed_round=retry_observation.quicknet_round,
            )


class SealedResponseTranscriptEffect(_TranscriptEffectBase):
    """Materialize missing outcomes, freeze responses, and anchor before reveal."""

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        _require_stage(work, WindowStage.SEALED_RESPONSE)
        propagated = self._propagate_abort(operation_id=operation_id, work=work)
        if propagated is not None:
            return propagated
        plan = await self._plan(work)
        observation = await self._observe("response_freeze", work)
        try:
            self._assignments.bind_window_material(plan.spec.window_id, plan.binding)
            snapshot = self._assignments.load_window(plan.spec.window_id)
            if snapshot.phase is TranscriptPhase.REQUESTS_FROZEN:
                if observation.quicknet_round < plan.spec.response_close_round:
                    raise TranscriptEffectPending("response_close_pending")
                if observation.quicknet_round >= plan.spec.reveal_round:
                    return await self._terminal(
                        operation_id=operation_id,
                        work=work,
                        reason_code="response_freeze_deadline_missed",
                        details={"observed_round": observation.quicknet_round},
                        extra_objects=(
                            StageObjectInput(
                                observation.evidence_bytes,
                                "application/octet-stream",
                            ),
                        ),
                    )
                for assignment in plan.assignments:
                    for attempt in self._assignments.list_attempts(assignment.assignment_id):
                        if not attempt.issued:
                            raise AssignmentPhaseError(
                                "request freeze retained an unissued attempt"
                            )
                        if attempt.outcome is None:
                            self._assignments.record_outcome(
                                assignment.assignment_id,
                                attempt.attempt_index,
                                _missing_outcome(observation),
                            )
            elif snapshot.phase is not TranscriptPhase.RESPONSES_FROZEN:
                raise AssignmentPhaseError(
                    f"response effect cannot run from {snapshot.phase.value}"
                )
            frozen = self._assignments.freeze_responses(
                plan.spec.window_id,
                observed_round=observation.quicknet_round,
            )
            anchor_operation, entry, finality = await self._anchor(
                kind="response_set",
                frozen=frozen,
                plan=plan,
                work=work,
                progress_observation=observation,
                submission_open_round=plan.spec.response_close_round,
                submission_close_round=plan.spec.reveal_round,
            )
        except _AnchorSubmissionClosed as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="response_anchor_submission_deadline_missed",
                details={"observed_round": error.observation.quicknet_round},
                extra_objects=(
                    StageObjectInput(
                        error.observation.evidence_bytes,
                        "application/octet-stream",
                    ),
                ),
            )
        except _AnchorRejected as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code=error.reason_code,
                details={"anchor_state": error.entry.state.value},
                extra_objects=(
                    StageObjectInput(canonical_json_bytes(error.entry.receipt), "application/json"),
                ),
            )
        except (AssignmentStoreError, ExtrinsicJournalError) as error:
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="response_transcript_fault",
                details={"error_type": type(error).__name__},
            )
        if (
            finality.inclusion_round < plan.spec.response_close_round
            or finality.inclusion_round >= plan.spec.reveal_round
            or finality.finalized_round >= plan.spec.reveal_round
        ):
            return await self._terminal(
                operation_id=operation_id,
                work=work,
                reason_code="response_anchor_deadline_missed",
                details={
                    "inclusion_round": finality.inclusion_round,
                    "finalized_round": finality.finalized_round,
                },
                extra_objects=(
                    StageObjectInput(finality.evidence_bytes, "application/octet-stream"),
                ),
            )
        return self._complete(
            operation_id=operation_id,
            work=work,
            plan=plan,
            frozen=frozen,
            anchor_operation=anchor_operation,
            entry=entry,
            finality=finality,
            observation=observation,
        )


def _anchor_operation(
    kind: AnchorKind,
    frozen: FrozenRoot,
    spec: TranscriptWindowSpec,
) -> ExtrinsicOperation:
    if frozen.kind != kind:
        raise TranscriptEffectBindingError("frozen root has another anchor kind")
    return ExtrinsicOperation(
        schema="umi-validator-extrinsic-operation/1",
        protocol=PROTOCOL_VERSION,
        operation={
            "assignment_set": "assignment_anchor",
            "request_set": "request_anchor",
            "response_set": "response_anchor",
        }[kind],
        window_id=spec.window_id,
        validator_hotkey=spec.validator_hotkey,
        request={
            "schema": ANCHOR_INTENT_SCHEMA,
            "call": "Commitments.set_commitment",
            "netuid": 78,
            "anchor_kind": kind,
            "field": {"type": "Data::Sha256", "sha256": frozen.root},
        },
    )


def _validate_anchor_finality(
    finality: VerifiedAnchorFinality,
    operation: ExtrinsicOperation,
    frozen: FrozenRoot,
    entry: JournalEntry,
) -> None:
    if finality.anchor_kind != frozen.kind:
        raise TranscriptEffectBindingError("anchor finality binds another kind")
    if finality.root != frozen.root:
        raise TranscriptEffectBindingError("anchor finality binds another root")
    if finality.operation_id != operation.operation_id:
        raise TranscriptEffectBindingError("anchor finality binds another operation")
    reconciliation = entry.receipt.reconciliation
    if reconciliation is None or entry.state is not ExtrinsicState.FINALIZED_SUCCESS:
        raise TranscriptEffectBindingError("anchor finality lacks a successful journal proof")
    if (
        reconciliation.inclusion_block != finality.inclusion_block
        or reconciliation.inclusion_block_hash != finality.inclusion_block_hash
        or reconciliation.finalized_head_block != finality.finalized_head_block
        or reconciliation.finalized_head_hash != finality.finalized_head_hash
    ):
        raise TranscriptEffectBindingError(
            "anchor finality disagrees with extrinsic reconciliation"
        )


def _attempt_outcome(
    outcome: QueryOutcome,
    *,
    prepared: PreparedRequestAttempt,
    spec: TranscriptWindowSpec,
    observation: VerifiedProtocolObservation,
) -> AttemptOutcomeInput:
    if outcome.request != prepared.request:
        raise TranscriptEffectBindingError("transport outcome binds another request")
    if tuple(sorted(outcome.auth_headers.items())) != prepared.auth_headers:
        raise TranscriptEffectBindingError(
            "transport outcome binds different authentication headers"
        )
    body = outcome.envelope_bytes
    received_evidence = body if body is not None else outcome.received_body_prefix
    if outcome.received_bytes_sha256 is not None:
        if received_evidence is None or hashlib.sha256(received_evidence).hexdigest() != (
            outcome.received_bytes_sha256
        ):
            raise TranscriptEffectBindingError(
                "transport byte digest lacks its exact bounded response evidence"
            )
    elif received_evidence is not None:
        raise TranscriptEffectBindingError(
            "transport response evidence lacks its received-byte digest"
        )
    prefix = (
        received_evidence[: spec.maximum_retained_prefix_bytes]
        if received_evidence is not None
        else None
    )
    within_deadline = (
        observation.quicknet_round < spec.response_close_round
        and observation.finalized_block <= prepared.request.deadline_block
    )
    if (
        within_deadline
        and outcome.failure_code is None
        and outcome.envelope is not None
        and outcome.sealed_response is not None
        and outcome.response_signature is not None
        and body is not None
    ):
        record = SealedResponseRecord.model_validate(
            {
                "disposition": "sealed",
                "receipt_metadata": {
                    "received_at_unix_ns": outcome.received_at_unix_ns,
                    "observed_block": observation.finalized_block,
                    "observed_round": observation.quicknet_round,
                },
                "wire_envelope_sha256": hashlib.sha256(body).hexdigest(),
                "signature_scheme": outcome.envelope.signature_scheme,
                "serving_hotkey": outcome.envelope.serving_hotkey,
                "signature": outcome.response_signature,
            }
        )
        return AttemptOutcomeInput(
            sealed_response_record=record,
            recorded_at_round=observation.quicknet_round,
            received_block=observation.finalized_block,
            received_round=observation.quicknet_round,
            body_or_prefix=body,
        )

    received = received_evidence is not None or outcome.received_at_unix_ns is not None
    if not within_deadline and received:
        disposition = "late"
    elif observation.quicknet_round >= spec.response_close_round and not received:
        return _missing_outcome(observation)
    elif outcome.failure_code == "resource_limit":
        disposition = "resource_limit"
    else:
        disposition = "outer_invalid"
    record = SealedResponseRecord.model_validate(
        {
            "disposition": disposition,
            "receipt_metadata": {
                "failure_code": outcome.failure_code or "deadline_exceeded",
                "received_at_unix_ns": outcome.received_at_unix_ns,
                "observed_block": observation.finalized_block,
                "observed_round": observation.quicknet_round,
            },
            "received_bytes_sha256": (
                hashlib.sha256(prefix).hexdigest() if prefix is not None else None
            ),
        }
    )
    return AttemptOutcomeInput(
        sealed_response_record=record,
        recorded_at_round=observation.quicknet_round,
        received_block=observation.finalized_block if received else None,
        received_round=observation.quicknet_round if received else None,
        body_or_prefix=prefix,
    )


def _missing_outcome(observation: VerifiedProtocolObservation) -> AttemptOutcomeInput:
    return AttemptOutcomeInput(
        sealed_response_record=SealedResponseRecord.model_validate(
            {
                "disposition": "missing",
                "receipt_metadata": {
                    "boundary": "response_close",
                    "observed_block": observation.finalized_block,
                    "observed_round": observation.quicknet_round,
                },
            }
        ),
        recorded_at_round=observation.quicknet_round,
    )


def _no_response_outcome(
    failure_code: str,
    observation: VerifiedProtocolObservation,
    spec: TranscriptWindowSpec,
) -> AttemptOutcomeInput:
    if observation.quicknet_round >= spec.response_close_round:
        return _missing_outcome(observation)
    return AttemptOutcomeInput(
        sealed_response_record=SealedResponseRecord.model_validate(
            {
                "disposition": "outer_invalid",
                "receipt_metadata": {
                    "failure_code": failure_code,
                    "observed_block": observation.finalized_block,
                    "observed_round": observation.quicknet_round,
                    "response_bytes_received": False,
                },
            }
        ),
        recorded_at_round=observation.quicknet_round,
    )


def _stage_manifest(
    store: ValidatorAssignmentStore,
    plan: TranscriptExecutionMaterial,
    stage: WindowStage,
    frozen: FrozenRoot,
) -> bytes:
    spec_bytes = canonical_json_bytes(plan.spec)
    spec_ref = EvidenceRef(
        sha256=hashlib.sha256(spec_bytes).hexdigest(),
        media_type="application/json",
        size_bytes=len(spec_bytes),
    )
    scoring_policy_hashes = {
        assignment.initial_attempt.request.scoring_policy_hash for assignment in plan.assignments
    }
    if len(scoring_policy_hashes) != 1:
        raise TranscriptEffectBindingError(
            "transcript plan requests do not share one scoring policy"
        )
    assignments: list[dict[str, JsonValue]] = []
    for assignment in plan.assignments:
        attempts: list[dict[str, JsonValue]] = []
        for attempt in store.list_attempts(assignment.assignment_id):
            attempts.append(
                {
                    "attempt_index": attempt.attempt_index,
                    "prepared_evidence": attempt.prepared_evidence_ref.model_dump(
                        mode="json", by_alias=True
                    ),
                    "issued": attempt.issued,
                    "claim_operation_id": attempt.claim_operation_id,
                    "outcome_evidence": (
                        attempt.outcome_evidence_ref.model_dump(mode="json", by_alias=True)
                        if attempt.outcome_evidence_ref is not None
                        else None
                    ),
                    "disposition": (
                        attempt.outcome.sealed_response_record.disposition
                        if attempt.outcome is not None
                        else None
                    ),
                    "final": attempt.final,
                }
            )
        assignments.append(
            {
                "assignment_id": assignment.assignment_id,
                "miner_hotkey": assignment.initial_attempt.miner_hotkey,
                "miner_url": assignment.miner_url,
                "attempts": attempts,
            }
        )
    return canonical_json_bytes(
        {
            "schema": TRANSCRIPT_STAGE_MANIFEST_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window_id": plan.spec.window_id,
            "stage": stage.value,
            "freeze_kind": frozen.kind,
            "root": frozen.root,
            "freeze_evidence_sha256": frozen.evidence_sha256,
            "transcript_spec": spec_ref.model_dump(mode="json", by_alias=True),
            "scoring_policy_hash": next(iter(scoring_policy_hashes)),
            "window_material_sha256": plan.material_sha256,
            "window_material_receipt_sha256": plan.material_receipt_sha256,
            "pool_stage_evidence_sha256": plan.pool_stage_evidence_sha256,
            "assignments": assignments,
        }
    )


def _transcript_object_graph(
    store: ValidatorAssignmentStore,
    plan: TranscriptExecutionMaterial,
) -> tuple[StageObjectInput, ...]:
    """Return every exact object recursively referenced by the stage manifest."""

    values: list[StageObjectInput] = [
        StageObjectInput(canonical_json_bytes(plan.spec), "application/json")
    ]
    for assignment in plan.assignments:
        for attempt in store.list_attempts(assignment.assignment_id):
            prepared_bytes = store.read_evidence(attempt.prepared_evidence_ref)
            values.append(
                StageObjectInput(prepared_bytes, attempt.prepared_evidence_ref.media_type)
            )
            prepared_evidence = _parse_canonical_model(
                prepared_bytes,
                PreparedAttemptEvidence,
                "prepared-attempt evidence",
            )
            request_bytes = store.read_evidence(prepared_evidence.request_object)
            values.append(
                StageObjectInput(request_bytes, prepared_evidence.request_object.media_type)
            )
            if attempt.outcome_evidence_ref is None:
                continue
            outcome_bytes = store.read_evidence(attempt.outcome_evidence_ref)
            values.append(StageObjectInput(outcome_bytes, attempt.outcome_evidence_ref.media_type))
            outcome_evidence = _parse_canonical_model(
                outcome_bytes,
                AttemptOutcomeEvidence,
                "attempt-outcome evidence",
            )
            if outcome_evidence.retained_body is not None:
                body = store.read_evidence(outcome_evidence.retained_body)
                values.append(StageObjectInput(body, outcome_evidence.retained_body.media_type))
    return _unique_objects(values)


class _ReceiptPayloads:
    def __init__(self, receipt: StageReceipt, payloads: Mapping[str, bytes]) -> None:
        if not isinstance(receipt, StageReceipt):
            raise TypeError("receipt must be a StageReceipt")
        if not isinstance(payloads, Mapping):
            raise TypeError("payloads must be a mapping")
        references = {item.sha256: item for item in receipt.objects}
        if set(payloads) != set(references):
            missing = set(references).difference(payloads)
            reason = "receipt_object_payload_missing" if missing else "unlisted_object_payload"
            raise TranscriptReplayError(reason)
        checked: dict[str, bytes] = {}
        for digest, reference in references.items():
            payload = payloads[digest]
            if not isinstance(payload, bytes):
                raise TranscriptReplayError("receipt_object_payload_not_bytes")
            if len(payload) != reference.size_bytes:
                raise TranscriptReplayError("receipt_object_size_mismatch")
            if hashlib.sha256(payload).hexdigest() != digest:
                raise TranscriptReplayError("receipt_object_digest_mismatch")
            checked[digest] = payload
        self.receipt = receipt
        self.references = references
        self.payloads = checked

    def resolve(self, reference: EvidenceRef) -> bytes:
        listed = self.references.get(reference.sha256)
        if listed is None:
            raise TranscriptReplayError("referenced_object_missing")
        if listed.media_type != reference.media_type or listed.size_bytes != reference.size_bytes:
            raise TranscriptReplayError("referenced_object_metadata_mismatch")
        return self.payloads[reference.sha256]

    def resolve_digest(self, digest: str, *, media_type: str) -> bytes:
        listed = self.references.get(digest)
        if listed is None:
            raise TranscriptReplayError("referenced_object_missing")
        if listed.media_type != media_type:
            raise TranscriptReplayError("referenced_object_metadata_mismatch")
        return self.payloads[digest]


def _replay_abort_stage_receipt(
    receipt: StageReceipt,
    payloads: Mapping[str, bytes],
) -> TranscriptAbortReplay | PoolNoScoreReplay | None:
    objects = _ReceiptPayloads(receipt, payloads)
    links: list[TranscriptAbortStageEvidence] = []
    origins: list[tuple[TranscriptAbortOrigin, bytes]] = []
    pool_links: list[PoolNoScoreStageEvidence] = []
    pool_origins: list[tuple[PoolNoScoreEvidence, bytes]] = []
    for reference in receipt.objects:
        if reference.media_type != "application/json":
            continue
        payload = objects.payloads[reference.sha256]
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(decoded, Mapping):
            continue
        if decoded.get("schema") == TRANSCRIPT_ABORT_STAGE_SCHEMA:
            links.append(
                _parse_canonical_model(
                    payload,
                    TranscriptAbortStageEvidence,
                    "transcript abort stage evidence",
                )
            )
        elif decoded.get("schema") == TRANSCRIPT_ABORT_ORIGIN_SCHEMA:
            origins.append(
                (
                    _parse_canonical_model(
                        payload,
                        TranscriptAbortOrigin,
                        "transcript abort origin",
                    ),
                    payload,
                )
            )
        elif decoded.get("schema") == POOL_NO_SCORE_STAGE_SCHEMA:
            pool_links.append(
                _parse_canonical_model(
                    payload,
                    PoolNoScoreStageEvidence,
                    "pool no-score stage evidence",
                )
            )
        elif decoded.get("schema") == POOL_NO_SCORE_SCHEMA:
            pool_origins.append(
                (
                    _parse_canonical_model(
                        payload,
                        PoolNoScoreEvidence,
                        "pool no-score origin",
                    ),
                    payload,
                )
            )
    if pool_links or pool_origins:
        if links or origins or len(pool_links) != 1 or len(pool_origins) != 1:
            raise TranscriptReplayError("pool_no_score_object_cardinality")
        link = pool_links[0]
        origin, origin_bytes = pool_origins[0]
        try:
            stage = WindowStage(link.stage)
        except ValueError as error:
            raise TranscriptReplayError("pool_no_score_stage_invalid") from error
        origin_sha256 = hashlib.sha256(origin_bytes).hexdigest()
        if (
            objects.resolve(link.origin) != origin_bytes
            or link.origin.sha256 != origin_sha256
            or receipt.window_id != link.window_id
            or receipt.window_id != origin.window_id
            or receipt.stage != link.stage
            or receipt.operation_id != link.operation_id
            or origin.operation_id
            != stage_operation_id(origin.window_id, WindowStage.POOL_AND_SELECTION)
        ):
            raise TranscriptReplayError("pool_no_score_receipt_binding_mismatch")
        metadata = _effect_metadata(receipt.metadata)
        expected_metadata = pool_no_score_metadata(
            origin,
            origin_sha256=origin_sha256,
            pool_stage_evidence_sha256=link.pool_stage_evidence_sha256,
            previous_stage_evidence_sha256=link.previous_stage_evidence_sha256,
        )
        if metadata != expected_metadata:
            raise TranscriptReplayError("pool_no_score_metadata_mismatch")
        return PoolNoScoreReplay(
            window_id=origin.window_id,
            stage=stage,
            operation_id=link.operation_id,
            origin=origin,
            origin_sha256=origin_sha256,
            pool_stage_evidence_sha256=link.pool_stage_evidence_sha256,
            previous_stage_evidence_sha256=link.previous_stage_evidence_sha256,
        )
    if not links and not origins:
        return None
    if len(links) != 1 or len(origins) != 1:
        raise TranscriptReplayError("transcript_abort_object_cardinality")
    link = links[0]
    origin, origin_bytes = origins[0]
    try:
        stage = WindowStage(link.stage)
        origin_stage = WindowStage(origin.origin_stage)
    except ValueError as error:
        raise TranscriptReplayError("transcript_abort_stage_invalid") from error
    origin_sha256 = hashlib.sha256(origin_bytes).hexdigest()
    resolved_origin = objects.resolve(link.origin)
    if (
        resolved_origin != origin_bytes
        or link.origin.sha256 != origin_sha256
        or receipt.window_id != link.window_id
        or receipt.window_id != origin.window_id
        or receipt.stage != link.stage
        or receipt.operation_id != link.operation_id
        or _transcript_stage_index(stage) < _transcript_stage_index(origin_stage)
    ):
        raise TranscriptReplayError("transcript_abort_receipt_binding_mismatch")
    is_origin = stage is origin_stage
    if (
        is_origin
        and (
            link.origin_stage_evidence_sha256 is not None
            or link.operation_id != origin.origin_operation_id
        )
    ) or (
        not is_origin
        and (
            link.origin_stage_evidence_sha256 is None
            or link.operation_id == origin.origin_operation_id
        )
    ):
        raise TranscriptReplayError("transcript_abort_origin_binding_mismatch")
    if is_origin:
        for reference in origin.source_objects:
            objects.resolve(reference)

    metadata = _effect_metadata(receipt.metadata)
    if metadata != _abort_metadata(origin, link, origin_sha256):
        raise TranscriptReplayError("transcript_abort_metadata_mismatch")
    return TranscriptAbortReplay(
        window_id=origin.window_id,
        stage=stage,
        operation_id=link.operation_id,
        origin=origin,
        origin_sha256=origin_sha256,
        origin_stage_evidence_sha256=link.origin_stage_evidence_sha256,
        previous_stage_evidence_sha256=link.previous_stage_evidence_sha256,
    )


def replay_transcript_stage_journal(
    journal: ValidatorStageJournal,
    window_id: str,
    stage: WindowStage,
) -> TranscriptStageReplay | TranscriptAbortReplay | PoolNoScoreReplay:
    """Load one journal receipt and replay it using only its listed payloads."""

    if not isinstance(journal, ValidatorStageJournal):
        raise TypeError("journal must be a ValidatorStageJournal")
    record = journal.load(window_id, stage)
    payloads = {
        reference.sha256: journal.read_object(reference) for reference in record.receipt.objects
    }
    return replay_transcript_stage_receipt(record.receipt, payloads)


def replay_transcript_stage_record(
    record: StageJournalRecord,
    journal: ValidatorStageJournal,
) -> TranscriptStageReplay | TranscriptAbortReplay | PoolNoScoreReplay:
    """Replay an already loaded record without consulting transcript state."""

    if not isinstance(record, StageJournalRecord):
        raise TypeError("record must be a StageJournalRecord")
    if not isinstance(journal, ValidatorStageJournal):
        raise TypeError("journal must be a ValidatorStageJournal")
    payloads = {
        reference.sha256: journal.read_object(reference) for reference in record.receipt.objects
    }
    return replay_transcript_stage_receipt(record.receipt, payloads)


def replay_transcript_stage_receipt(
    receipt: StageReceipt,
    payloads: Mapping[str, bytes],
) -> TranscriptStageReplay | TranscriptAbortReplay | PoolNoScoreReplay:
    """Recompute a transcript root and all manifest bindings from receipt payloads.

    The mapping must contain exactly the objects named by ``receipt``.  Every
    prepared-attempt reference is followed to its exact canonical request, and
    every outcome reference is followed to its retained envelope or bounded
    failure prefix.  No assignment database, plan provider, or network port is
    consulted.
    """

    abort = _replay_abort_stage_receipt(receipt, payloads)
    if abort is not None:
        return abort
    objects = _ReceiptPayloads(receipt, payloads)
    manifests: list[_TranscriptStageManifest] = []
    for reference in receipt.objects:
        if reference.media_type != "application/json":
            continue
        payload = objects.payloads[reference.sha256]
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(decoded, Mapping) and decoded.get("schema") == (
            TRANSCRIPT_STAGE_MANIFEST_SCHEMA
        ):
            manifests.append(
                _parse_canonical_model(
                    payload,
                    _TranscriptStageManifest,
                    "transcript stage manifest",
                )
            )
    if len(manifests) != 1:
        raise TranscriptReplayError("transcript_stage_manifest_cardinality")
    manifest = manifests[0]
    try:
        stage = WindowStage(manifest.stage)
    except ValueError as error:  # Pydantic constrains this, retained for fail-closed clarity.
        raise TranscriptReplayError("transcript_stage_invalid") from error
    if receipt.window_id != manifest.window_id or receipt.stage != manifest.stage:
        raise TranscriptReplayError("transcript_receipt_manifest_binding_mismatch")

    spec = _parse_canonical_model(
        objects.resolve(manifest.transcript_spec),
        TranscriptWindowSpec,
        "transcript window spec",
    )
    if spec.window_id != manifest.window_id:
        raise TranscriptReplayError("transcript_spec_window_mismatch")
    if spec.expected_assignment_count != len(manifest.assignments):
        raise TranscriptReplayError("transcript_assignment_count_mismatch")

    assignments: list[AssignmentAnchorRecord] = []
    requests: list[RequestAnchorRecord] = []
    responses: list[ResponseAnchorRecord] = []
    validator_hotkey: str | None = None
    attempt_count = 0
    origins: list[tuple[str, str]] = []
    for assignment in manifest.assignments:
        if len(assignment.attempts) > spec.maximum_request_transmissions_per_assignment:
            raise TranscriptReplayError("transcript_attempt_limit_exceeded")
        attempts: list[tuple[PreparedRequestAttempt, AttemptOutcomeEvidence | None]] = []
        prior_nonce = -1
        for attempt in assignment.attempts:
            prepared_evidence = _parse_canonical_model(
                objects.resolve(attempt.prepared_evidence),
                PreparedAttemptEvidence,
                "prepared-attempt evidence",
            )
            prepared = _replay_prepared_attempt(
                objects,
                prepared_evidence,
                manifest=manifest,
                spec=spec,
                assignment=assignment,
                attempt=attempt,
            )
            nonce = prepared.auth_evidence.auth_record.nonce_int
            if nonce <= prior_nonce:
                raise TranscriptReplayError("transcript_attempt_nonce_order_invalid")
            prior_nonce = nonce
            if validator_hotkey is None:
                validator_hotkey = prepared.validator_hotkey
            elif prepared.validator_hotkey != validator_hotkey:
                raise TranscriptReplayError("transcript_validator_binding_mismatch")

            outcome: AttemptOutcomeEvidence | None = None
            if attempt.outcome_evidence is not None:
                outcome = _parse_canonical_model(
                    objects.resolve(attempt.outcome_evidence),
                    AttemptOutcomeEvidence,
                    "attempt-outcome evidence",
                )
                body = (
                    None
                    if outcome.retained_body is None
                    else objects.resolve(outcome.retained_body)
                )
                _validate_replayed_outcome(
                    prepared,
                    outcome,
                    body,
                    spec=spec,
                    assignment_id=assignment.assignment_id,
                    attempt_index=attempt.attempt_index,
                )
                if outcome.sealed_response_record.disposition != attempt.disposition:
                    raise TranscriptReplayError("manifest_outcome_disposition_mismatch")
            attempts.append((prepared, outcome))
            attempt_count += 1

        if stage is WindowStage.ASSIGNMENT:
            if len(attempts) != 1 or any(
                item.issued or item.outcome_evidence is not None for item in assignment.attempts
            ):
                raise TranscriptReplayError("assignment_stage_attempt_state_invalid")
        elif any(not item.issued for item in assignment.attempts):
            raise TranscriptReplayError("frozen_request_contains_unissued_attempt")
        if stage is WindowStage.SEALED_RESPONSE and any(
            outcome is None for _prepared, outcome in attempts
        ):
            raise TranscriptReplayError("response_stage_outcome_missing")

        initial = attempts[0][0]
        assignment_record = AssignmentAnchorRecord(initial.auth_evidence)
        request_record = RequestAnchorRecord(
            tuple(prepared.auth_evidence for prepared, _outcome in attempts)
        )
        assignments.append(assignment_record)
        requests.append(request_record)
        available = [outcome for _prepared, outcome in attempts if outcome is not None]
        final = next(
            (
                outcome
                for outcome in available
                if outcome.sealed_response_record.disposition == "sealed"
            ),
            None,
        )
        selected = final or (available[-1] if available else None)
        if selected is not None:
            responses.append(
                ResponseAnchorRecord(
                    request_leaf=request_record.leaf,
                    sealed_response_record=selected.sealed_response_record,
                )
            )
        origins.append((assignment.assignment_id, assignment.miner_url))

    if validator_hotkey is None:
        raise TranscriptReplayError("transcript_validator_missing")
    try:
        if stage is WindowStage.ASSIGNMENT:
            records = assignments
            calculated = assignment_set_root(
                assignments,
                window_id=manifest.window_id,
                validator_hotkey=validator_hotkey,
            )
        elif stage is WindowStage.REQUEST_TRANSCRIPT:
            records = requests
            calculated = request_set_root(
                requests,
                assignments=assignments,
                window_id=manifest.window_id,
                validator_hotkey=validator_hotkey,
            )
        else:
            records = responses
            calculated = response_set_root(
                responses,
                request_records=requests,
                window_id=manifest.window_id,
                validator_hotkey=validator_hotkey,
            )
    except (TypeError, ValueError) as error:
        raise TranscriptReplayError("transcript_root_reconstruction_failed") from error
    root = calculated.hex()
    if root != manifest.root:
        raise TranscriptReplayError("transcript_root_mismatch")

    freeze = _parse_canonical_model(
        objects.resolve_digest(
            manifest.freeze_evidence_sha256,
            media_type="application/json",
        ),
        FreezeEvidence,
        "transcript freeze evidence",
    )
    expected_leaves = sorted(record.leaf.hex() for record in records)
    if (
        freeze.kind != manifest.freeze_kind
        or freeze.window_id != manifest.window_id
        or freeze.validator_hotkey != validator_hotkey
        or freeze.root != root
        or freeze.record_count != len(records)
        or freeze.member_leaves != expected_leaves
    ):
        raise TranscriptReplayError("transcript_freeze_evidence_mismatch")
    _validate_replay_metadata(receipt, manifest, freeze, spec)
    return TranscriptStageReplay(
        window_id=manifest.window_id,
        stage=stage,
        freeze_kind=manifest.freeze_kind,
        root=root,
        assignment_count=len(assignments),
        attempt_count=attempt_count,
        material_binding=TranscriptMaterialBinding(
            material_sha256=manifest.window_material_sha256,
            material_receipt_sha256=manifest.window_material_receipt_sha256,
            pool_stage_evidence_sha256=manifest.pool_stage_evidence_sha256,
        ),
        scoring_policy_hash=manifest.scoring_policy_hash,
        miner_origins=tuple(origins),
    )


def _replay_prepared_attempt(
    objects: _ReceiptPayloads,
    evidence: PreparedAttemptEvidence,
    *,
    manifest: _TranscriptStageManifest,
    spec: TranscriptWindowSpec,
    assignment: _ManifestAssignment,
    attempt: _ManifestAttempt,
) -> PreparedRequestAttempt:
    if (
        evidence.assignment_id != assignment.assignment_id
        or evidence.attempt_index != attempt.attempt_index
        or evidence.window_id != manifest.window_id
        or evidence.validator_hotkey != spec.validator_hotkey
        or evidence.miner_hotkey != assignment.miner_hotkey
    ):
        raise TranscriptReplayError("prepared_attempt_manifest_binding_mismatch")
    request_bytes = objects.resolve(evidence.request_object)
    request = _parse_canonical_model(
        request_bytes,
        TranslationRequest,
        "translation request",
    )
    if (
        request_digest(request) != evidence.request_digest
        or request.window_id != manifest.window_id
        or request.scoring_policy_hash != manifest.scoring_policy_hash
        or request.response_close_round != spec.response_close_round
        or request.reveal_round != spec.reveal_round
        or len(request_bytes) > spec.maximum_request_body_bytes
    ):
        raise TranscriptReplayError("prepared_request_binding_mismatch")
    headers = tuple((item.name, item.value) for item in evidence.auth_headers)
    try:
        verified = VerifiedAuthEvidence.from_headers(
            dict(headers),
            request=request,
            expected_validator_hotkey=evidence.validator_hotkey,
            expected_miner_hotkey=evidence.miner_hotkey,
        )
    except (TypeError, ValueError) as error:
        raise TranscriptReplayError("prepared_authentication_invalid") from error
    if verified.auth_record != evidence.auth_record:
        raise TranscriptReplayError("prepared_authentication_record_mismatch")
    prepared = PreparedRequestAttempt(
        request=request,
        request_bytes=request_bytes,
        validator_hotkey=evidence.validator_hotkey,
        miner_hotkey=evidence.miner_hotkey,
        auth_headers=headers,
        auth_evidence=verified,
    )
    if deterministic_assignment_id(prepared) != assignment.assignment_id:
        raise TranscriptReplayError("prepared_assignment_id_mismatch")
    return prepared


def _validate_replayed_outcome(
    prepared: PreparedRequestAttempt,
    outcome: AttemptOutcomeEvidence,
    body: bytes | None,
    *,
    spec: TranscriptWindowSpec,
    assignment_id: str,
    attempt_index: int,
) -> None:
    if outcome.assignment_id != assignment_id or outcome.attempt_index != attempt_index:
        raise TranscriptReplayError("outcome_attempt_binding_mismatch")
    if outcome.recorded_at_round >= spec.reveal_round:
        raise TranscriptReplayError("outcome_recorded_after_reveal")
    if outcome.received_block is not None and outcome.received_block < (
        prepared.request.issued_block
    ):
        raise TranscriptReplayError("outcome_receipt_predates_request")
    record = outcome.sealed_response_record
    if record.disposition == "sealed":
        if outcome.received_block is None or outcome.received_round is None or body is None:
            raise TranscriptReplayError("sealed_outcome_evidence_missing")
        if (
            outcome.retained_body is None
            or outcome.retained_body.media_type != "application/json"
            or len(body) > spec.maximum_response_body_bytes
            or hashlib.sha256(body).hexdigest() != record.wire_envelope_sha256
            or outcome.received_block > prepared.request.deadline_block
            or outcome.received_round >= spec.response_close_round
        ):
            raise TranscriptReplayError("sealed_outcome_binding_mismatch")
        try:
            envelope, _sealed = validate_response_envelope(
                body,
                record.signature,
                request=prepared.request,
                validator_hotkey=prepared.validator_hotkey,
                miner_hotkey=prepared.miner_hotkey,
            )
        except (TypeError, ValueError) as error:
            raise TranscriptReplayError("sealed_outcome_envelope_invalid") from error
        if (
            envelope.signature_scheme != record.signature_scheme
            or envelope.serving_hotkey != record.serving_hotkey
        ):
            raise TranscriptReplayError("sealed_outcome_envelope_mismatch")
        return
    if record.disposition == "missing":
        if (
            outcome.recorded_at_round < spec.response_close_round
            or outcome.received_block is not None
            or body is not None
            or record.received_bytes_sha256 is not None
        ):
            raise TranscriptReplayError("missing_outcome_binding_mismatch")
        return
    if record.disposition == "late":
        if outcome.received_block is None or outcome.received_round is None:
            raise TranscriptReplayError("late_outcome_receipt_missing")
        if (
            outcome.received_block <= prepared.request.deadline_block
            and outcome.received_round < spec.response_close_round
        ):
            raise TranscriptReplayError("late_outcome_inside_deadline")
    if body is not None:
        if (
            outcome.retained_body is None
            or outcome.retained_body.media_type != "application/octet-stream"
            or len(body) > spec.maximum_retained_prefix_bytes
            or hashlib.sha256(body).hexdigest() != record.received_bytes_sha256
        ):
            raise TranscriptReplayError("failure_prefix_binding_mismatch")
    elif record.received_bytes_sha256 is not None:
        raise TranscriptReplayError("failure_prefix_missing")


def _validate_replay_metadata(
    receipt: StageReceipt,
    manifest: _TranscriptStageManifest,
    freeze: FreezeEvidence,
    spec: TranscriptWindowSpec,
) -> None:
    # Production receipts are written through ``JournalStageAdapter``, which
    # wraps the effect-local metadata alongside the typed completion decision.
    # Direct effect fixtures historically stored the local mapping itself.  The
    # replay boundary accepts both encodings, but always validates the same
    # effect-local fields.
    metadata = _effect_metadata(receipt.metadata)
    expected_phase = {
        "assignment": TranscriptPhase.ASSIGNMENTS_FROZEN.value,
        "request_transcript": TranscriptPhase.REQUESTS_FROZEN.value,
        "sealed_response": TranscriptPhase.RESPONSES_FROZEN.value,
    }[manifest.stage]
    expected: dict[str, JsonValue] = {
        "anchor_kind": manifest.freeze_kind,
        "anchor_root": manifest.root,
        "transcript_phase": expected_phase,
        "window_material_sha256": manifest.window_material_sha256,
        "window_material_receipt_sha256": manifest.window_material_receipt_sha256,
        "pool_stage_evidence_sha256": manifest.pool_stage_evidence_sha256,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise TranscriptReplayError("transcript_receipt_metadata_mismatch")
    if manifest.stage == WindowStage.ASSIGNMENT.value:
        valid_round = freeze.observed_round < spec.issue_close_round
    elif manifest.stage == WindowStage.REQUEST_TRANSCRIPT.value:
        valid_round = freeze.observed_round < spec.response_close_round
    else:
        valid_round = spec.response_close_round <= freeze.observed_round < spec.reveal_round
    if not valid_round:
        raise TranscriptReplayError("transcript_freeze_round_invalid")


def _parse_canonical_model(data: bytes, model: type[T], label: str) -> T:
    try:
        decoded = json.loads(data)
        value = model.model_validate(decoded)  # type: ignore[attr-defined]
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise TranscriptReplayError(f"{label.replace(' ', '_')}_invalid") from error
    if canonical_json_bytes(value) != data:
        raise TranscriptReplayError(f"{label.replace(' ', '_')}_noncanonical")
    return value


def _evidence_ref(data: bytes, media_type: str) -> EvidenceRef:
    return EvidenceRef(
        sha256=hashlib.sha256(data).hexdigest(),
        media_type=media_type,
        size_bytes=len(data),
    )


def _abort_metadata(
    origin: TranscriptAbortOrigin,
    link: TranscriptAbortStageEvidence,
    origin_sha256: str,
) -> dict[str, JsonValue]:
    return {
        "transcript_abort": True,
        "transcript_abort_origin_stage": origin.origin_stage,
        "transcript_abort_origin_sha256": origin_sha256,
        "transcript_abort_origin_stage_evidence_sha256": (link.origin_stage_evidence_sha256),
        "transcript_abort_previous_stage_evidence_sha256": (link.previous_stage_evidence_sha256),
        "transcript_abort_reason_code": origin.reason_code,
        "transcript_abort_audit_release_block": origin.audit_release_block,
    }


def _effect_metadata(metadata: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    if metadata.get("schema") != "umi-validator-adapter-result/1":
        return dict(metadata)
    if (
        metadata.get("kind") != "completion"
        or metadata.get("terminal") is not None
        or not isinstance(metadata.get("metadata"), dict)
    ):
        raise TranscriptReplayError("transcript_abort_adapter_metadata_invalid")
    return dict(metadata["metadata"])


def _previous_stage_digest(work: StageWorkItem) -> str:
    expected = STAGE_ORDER.index(work.stage)
    if len(work.completed_evidence) != expected or expected == 0:
        raise TranscriptEffectBindingError("transcript abort lacks its complete prior prefix")
    previous = work.completed_evidence[-1]
    if previous.stage is not STAGE_ORDER[expected - 1]:
        raise TranscriptEffectBindingError("transcript abort prior stage is not adjacent")
    return previous.evidence_sha256


def _pool_stage_digest(work: StageWorkItem) -> str:
    if not work.completed_evidence:
        raise TranscriptEffectBindingError("transcript abort lacks pool-stage evidence")
    pool = work.completed_evidence[0]
    if pool.stage is not WindowStage.POOL_AND_SELECTION:
        raise TranscriptEffectBindingError("transcript abort pool prefix is not canonical")
    return pool.evidence_sha256


def _transcript_stage_index(stage: WindowStage) -> int:
    stages = (
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
        WindowStage.SEALED_RESPONSE,
    )
    try:
        return stages.index(stage)
    except ValueError as error:
        raise TranscriptEffectBindingError("abort stage is not a transcript stage") from error


def _send_operation_id(
    stage_operation_id: str,
    assignment_id: str,
    attempt_index: int,
) -> str:
    digest = hashlib.sha256(
        b"umi-transcript-send-v1\0"
        + stage_operation_id.encode()
        + bytes.fromhex(assignment_id)
        + attempt_index.to_bytes(4, "big")
    ).hexdigest()
    return f"send.{digest}"


def _unique_objects(values: Sequence[StageObjectInput]) -> tuple[StageObjectInput, ...]:
    result: dict[bytes, StageObjectInput] = {}
    for value in values:
        if not isinstance(value, StageObjectInput):
            raise TypeError("effect objects must be StageObjectInput values")
        digest = hashlib.sha256(value.data).digest()
        existing = result.setdefault(digest, value)
        if existing.media_type != value.media_type:
            raise TranscriptEffectBindingError(
                "one transcript evidence object has conflicting media types"
            )
    if not result:
        raise ValueError("effect evidence cannot be empty")
    return tuple(result[digest] for digest in sorted(result))


def _require_stage(work: StageWorkItem, expected: WindowStage) -> None:
    if not isinstance(work, StageWorkItem):
        raise TypeError("work must be StageWorkItem")
    if work.stage is not expected:
        raise TranscriptEffectBindingError(
            f"{expected.value} effect received {work.stage.value} work"
        )


async def _await_port(value: T | Awaitable[T]) -> T:
    return await value if inspect.isawaitable(value) else value


def _is_async_callable(value: object) -> bool:
    if not callable(value):
        return False
    call_method = type(value).__call__
    return inspect.iscoroutinefunction(value) or inspect.iscoroutinefunction(call_method)


def _execution_material(value: object) -> TranscriptExecutionMaterial:
    """Coerce the durable store result without importing its circular module.

    ``ValidatorWindowMaterialStore.load_for_work`` returns a
    ``StoredWindowMaterial`` whose receipt owns the authoritative material hash.
    This structural conversion keeps the transcript module independent while
    rejecting the old, unbound ``TranscriptExecutionPlan`` return shape.
    """

    if isinstance(value, TranscriptExecutionMaterial):
        return value
    plan = getattr(value, "plan", None)
    receipt = getattr(value, "receipt", None)
    material_sha256 = getattr(receipt, "material_sha256", None)
    material_receipt_sha256 = getattr(value, "receipt_sha256", None)
    pool_stage_evidence_sha256 = getattr(value, "pool_stage_evidence_sha256", None)
    try:
        return TranscriptExecutionMaterial(
            plan=plan,
            material_sha256=material_sha256,
            material_receipt_sha256=material_receipt_sha256,
            pool_stage_evidence_sha256=pool_stage_evidence_sha256,
        )
    except (TypeError, ValueError) as error:
        raise TranscriptEffectBindingError(
            "plan port did not return pool-bound execution material"
        ) from error


def _fact_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise ValueError(f"{label} evidence must be nonempty exact bytes")
    if len(value) > MAX_FACT_EVIDENCE_BYTES:
        raise ValueError(f"{label} evidence exceeds its byte ceiling")
    return value


def _hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be 32 lowercase hexadecimal bytes")
    return value


def _chain_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or _CHAIN_HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a 0x-prefixed chain hash")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


__all__ = [
    "ANCHOR_INTENT_SCHEMA",
    "MAX_ANCHOR_ADVANCES_PER_EFFECT",
    "MAX_FACT_EVIDENCE_BYTES",
    "TRANSCRIPT_ABORT_ORIGIN_SCHEMA",
    "TRANSCRIPT_ABORT_STAGE_SCHEMA",
    "TRANSCRIPT_STAGE_MANIFEST_SCHEMA",
    "TRANSCRIPT_TERMINAL_SCHEMA",
    "AnchorFinalityPort",
    "AnchorPortsPort",
    "AssignmentTranscriptEffect",
    "AuditReleasePort",
    "ObservationPort",
    "RequestTranscriptEffect",
    "RetryPreparationPort",
    "SealedResponseTranscriptEffect",
    "TranscriptAbortOrigin",
    "TranscriptAbortReplay",
    "TranscriptAbortStageEvidence",
    "TranscriptAssignment",
    "TranscriptEffectBindingError",
    "TranscriptEffectError",
    "TranscriptEffectPending",
    "TranscriptEffectPorts",
    "TranscriptExecutionMaterial",
    "TranscriptExecutionPlan",
    "TranscriptPlanPort",
    "TranscriptReplayError",
    "TranscriptStageReplay",
    "TransportPort",
    "VerifiedAnchorFinality",
    "VerifiedProtocolObservation",
    "replay_transcript_stage_journal",
    "replay_transcript_stage_receipt",
    "replay_transcript_stage_record",
]
