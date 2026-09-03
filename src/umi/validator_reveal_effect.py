"""Receipt-bound reveal, exact scoring, and durable protocol-state transition.

The reveal stage deliberately has no wallet, HTTP, generic chain, or peer-score
capability.  It consumes the immutable pool receipt and pre-reveal response-set
receipt, verifies one Quicknet reveal pulse, opens only the timelocks committed by
those receipts, and derives all live scoring and registry inputs locally.

The protocol and source-monitoring databases are independent SQLite stores.  A
small FULL-synchronous coordinator records the canonical transition intent before
either store is touched, invokes both stores with the same 32-byte operation ID,
and records their exact canonical requests/results only after both reproduce.  A
crash between the two commits therefore leaves a recoverable pending operation;
replaying the stage completes it idempotently and cannot substitute different
material for the same window.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

from pydantic import Field, JsonValue, ValidationError, model_validator
from typing_extensions import Self

from .anchors import RequestAnchorRecord, SealedResponseRecord, VerifiedAuthEvidence
from .artifacts import (
    PublicBatchManifest,
    validate_public_batch_manifest,
    validate_revealed_batch_shape,
)
from .calibration_bundle import (
    CalibrationStageEvidence,
    calibration_stage_replay_hook_id,
)
from .canary import evaluate_canary
from .crypto import (
    SealedResponse,
    TimelockDecryptionError,
    decrypt_response,
    parse_sealed_response,
)
from .drand import DrandPulse, DrandVerificationError
from .encoding import account_id32, raw_sha256, sha256_domain
from .monitoring import SourceObservation
from .policy import SCORING_POLICY_MEDIA_TYPE, ScoringPolicy, scoring_policy_hash
from .pool import (
    CandidateBatch,
    MinerCandidate,
    PoolBatchEntry,
    batch_rank,
    candidate_pool_root,
    miner_rank,
    parse_pool_manifest_bytes,
    select_batches,
    select_miner_panel,
    selection_seed,
)
from .protocol import (
    PROTOCOL_VERSION,
    GroundTruthPayload,
    ResponsePlaintext,
    StrictProtocolModel,
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
    normalized_grapheme_count,
    normalized_token_count,
)
from .registries import (
    PublisherFaultFinding,
    PublisherRevealEvidence,
    PublisherRevealOutcome,
    SpentCohortBatch,
    classify_publisher_reveal,
    spent_script_leaf,
)
from .rolling import AssignmentScore, ScoredBatch
from .scoring import score_cer_with_trace, score_wer_with_trace, scoring_environment
from .validator import (
    ComponentResponseError,
    PreparedRequestAttempt,
    validate_response_envelope,
    validate_response_plaintext,
)
from .validator_adapters import (
    CompleteStageEffect,
    StageEffectResult,
    TerminalStageEffect,
    stage_operation_id,
)
from .validator_assignments import (
    AttemptOutcomeEvidence,
    EvidenceRef,
    PreparedAttemptEvidence,
    TranscriptMaterialBinding,
    TranscriptWindowSpec,
    deterministic_assignment_id,
)
from .validator_journal import (
    MAX_JOURNAL_OBJECT_BYTES,
    MAX_STAGE_OBJECT_BYTES,
    STAGE_RECEIPT_MEDIA_TYPE,
    StageJournalRecord,
    StageObject,
    StageObjectInput,
    StageReceipt,
    ValidatorStageJournal,
)
from .validator_monitoring_state import (
    MonitoringBatchSource,
    MonitoringSignerCluster,
    ValidatorMonitoringStateStore,
    source_observations_from_scored_batches,
)
from .validator_pool_effect import (
    POOL_SELECTION_EVIDENCE_SCHEMA,
    ClosingSnapshot,
    PoolEvidenceObjectRef,
    PoolSelectionEvidence,
    SelectedCandidateEvidence,
)
from .validator_pool_no_score import (
    POOL_EMPTY_SOURCE_SCHEMA,
    POOL_NO_SCORE_SCHEMA,
    PoolEmptySourceEvidence,
    PoolNoScoreCandidate,
    PoolNoScoreEvidence,
    PoolNoScoreReplay,
)
from .validator_protocol_state import (
    AppliedProtocolWindow,
    ProtocolStateCorruption,
    ProtocolStatePolicyLimits,
    ProtocolStateSnapshot,
    ValidatorProtocolStateStore,
    decode_protocol_state_snapshot,
    encode_protocol_state_snapshot,
)
from .validator_state import (
    STAGE_ORDER,
    IncidentSpec,
    PauseScope,
    StageWorkItem,
    TerminalOutcome,
    WindowPlan,
    WindowStage,
)
from .validator_transcript_effects import (
    TRANSCRIPT_STAGE_MANIFEST_SCHEMA,
    TranscriptAbortOrigin,
    TranscriptAbortReplay,
    TranscriptAssignment,
    TranscriptExecutionPlan,
    TranscriptReplayError,
    TranscriptStageReplay,
    replay_transcript_stage_receipt,
)
from .validator_window_material import StoredWindowMaterial, ValidatorWindowMaterialStore

REVEAL_STAGE_SCHEMA = "umi-validator-reveal-stage/1"
REVEAL_RESULT_SCHEMA = "umi-validator-reveal-result/1"
REVEAL_ABORT_RESULT_SCHEMA = "umi-validator-transcript-abort-reveal/1"
POOL_NO_SCORE_REVEAL_RESULT_SCHEMA = "umi-validator-pool-no-score-reveal/1"
REVEAL_TRANSITION_SCHEMA = "umi-validator-reveal-transition/1"
REVEAL_DECRYPTION_SCHEMA = "umi-validator-reveal-decryption/1"
REVEAL_AUDIT_RELEASE_SCHEMA = "umi-validator-reveal-audit-release/1"

MAX_REVEAL_PULSE_BYTES = 64 * 1024
MAX_REVEAL_PLAINTEXT_BYTES = 4 * 1024 * 1024
MAX_REVEAL_ASSIGNMENTS = 262_144
MAX_REVEAL_CANDIDATES = 4_096
MAX_REVEAL_COORDINATOR_BYTES = 128 * 1024 * 1024
MAX_REVEAL_OBJECTS = 131_072
_ADAPTER_RESULT_SCHEMA = "umi-validator-adapter-result/1"
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_COORDINATOR_APPLICATION_ID = 0x554D4952  # "UMIR"
_COORDINATOR_SCHEMA_VERSION = 1
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


class RevealEffectError(RuntimeError):
    """A reveal receipt cannot safely produce a protocol transition."""


class RevealBindingError(RevealEffectError):
    """Exact source material is valid in isolation but bound elsewhere."""


class RevealLimitError(RevealEffectError):
    """Reveal evidence exceeds a policy or journal resource ceiling."""


class RevealTransitionConflict(RevealEffectError):
    """A coordinator operation is already bound to different material."""


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class RevealObjectRef(StrictProtocolModel):
    sha256: Hex32
    media_type: Literal[
        "application/json",
        "application/octet-stream",
        "application/vnd.umi.scoring-policy+json",
        "application/vnd.umi.validator-stage-receipt+json",
    ]
    size_bytes: Annotated[int, Field(ge=0, le=MAX_JOURNAL_OBJECT_BYTES)]


class RevealAuditRelease(StrictProtocolModel):
    """Finalized audit-release fact supplied only for a reveal-time void."""

    schema_: Literal[REVEAL_AUDIT_RELEASE_SCHEMA] = Field(alias="schema")
    window_id: Hex32
    reason_code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")]
    audit_release_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    evidence_sha256: Hex32


@dataclass(frozen=True, slots=True)
class VerifiedRevealAuditRelease:
    fact: RevealAuditRelease
    evidence_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.fact, RevealAuditRelease):
            raise TypeError("audit release fact must be RevealAuditRelease")
        if not isinstance(self.evidence_bytes, bytes) or not self.evidence_bytes:
            raise TypeError("audit release evidence must be nonempty exact bytes")
        if len(self.evidence_bytes) > MAX_STAGE_OBJECT_BYTES:
            raise RevealLimitError("audit release evidence exceeds the journal object ceiling")
        if hashlib.sha256(self.evidence_bytes).hexdigest() != self.fact.evidence_sha256:
            raise RevealBindingError("audit release evidence digest does not reproduce")


class RevealPulsePort(Protocol):
    def __call__(self, work: StageWorkItem) -> bytes | Awaitable[bytes]: ...


class RevealDecryptPort(Protocol):
    def __call__(
        self,
        sealed: SealedResponse,
        pulse: DrandPulse,
    ) -> bytes | Awaitable[bytes]: ...


class RevealAuditReleasePort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
        reason_code: str,
    ) -> VerifiedRevealAuditRelease | Awaitable[VerifiedRevealAuditRelease]: ...


@dataclass(frozen=True, slots=True)
class RevealEffectPorts:
    reveal_pulse: RevealPulsePort
    decrypt: RevealDecryptPort
    audit_release: RevealAuditReleasePort

    def __post_init__(self) -> None:
        for name in ("reveal_pulse", "decrypt", "audit_release"):
            if not callable(getattr(self, name)):
                raise TypeError(f"reveal effect {name} port must be callable")


class _ManifestAttempt(StrictProtocolModel):
    attempt_index: Annotated[int, Field(ge=0, lt=16)]
    prepared_evidence: EvidenceRef
    issued: Literal[True]
    claim_operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    outcome_evidence: EvidenceRef
    disposition: Literal["sealed", "missing", "late", "outer_invalid", "resource_limit"]
    final: bool

    @model_validator(mode="after")
    def validate_final(self) -> Self:
        if self.final != (self.disposition == "sealed"):
            raise ValueError("response manifest final flag disagrees with disposition")
        return self


class _ManifestAssignment(StrictProtocolModel):
    assignment_id: Hex32
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    miner_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    attempts: Annotated[list[_ManifestAttempt], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def validate_attempts(self) -> Self:
        account_id32(self.miner_hotkey)
        if [item.attempt_index for item in self.attempts] != list(range(len(self.attempts))):
            raise ValueError("response manifest attempt indices are not contiguous")
        if any(item.final for item in self.attempts[:-1]):
            raise ValueError("response manifest retries after a final envelope")
        return self


class _ResponseStageManifest(StrictProtocolModel):
    schema_: Literal[TRANSCRIPT_STAGE_MANIFEST_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    stage: Literal["sealed_response"]
    freeze_kind: Literal["response_set"]
    root: Hex32
    freeze_evidence_sha256: Hex32
    transcript_spec: EvidenceRef
    scoring_policy_hash: Hex32
    window_material_sha256: Hex32
    window_material_receipt_sha256: Hex32
    pool_stage_evidence_sha256: Hex32
    assignments: Annotated[list[_ManifestAssignment], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_assignments(self) -> Self:
        identifiers = [item.assignment_id for item in self.assignments]
        if identifiers != sorted(set(identifiers)):
            raise ValueError("response manifest assignments are not canonical")
        return self


class RevealStageManifest(StrictProtocolModel):
    """Index for a self-contained reveal-stage journal object graph."""

    schema_: Literal[REVEAL_STAGE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    transition_operation_id: Hex32
    transition_evidence_sha256: Hex32
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    pool_stage_receipt: RevealObjectRef
    response_stage_receipt: RevealObjectRef
    pool_selection_evidence: RevealObjectRef
    reveal_pulse: RevealObjectRef
    policy_object: RevealObjectRef
    prior_protocol_state: RevealObjectRef
    reveal_result: RevealObjectRef
    protocol_transition_request: RevealObjectRef
    protocol_transition_result: RevealObjectRef
    monitoring_transition_request: RevealObjectRef | None
    monitoring_report: RevealObjectRef | None
    audit_release_fact: RevealObjectRef | None
    audit_release_evidence: RevealObjectRef | None
    decryption_records: list[RevealObjectRef]
    plaintext_objects: list[RevealObjectRef]
    source_objects: Annotated[list[RevealObjectRef], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_refs(self) -> Self:
        if (self.monitoring_transition_request is None) != (self.monitoring_report is None):
            raise ValueError("monitoring transition and report references must appear together")
        if (self.audit_release_fact is None) != (self.audit_release_evidence is None):
            raise ValueError("audit release fact and evidence references must appear together")
        for name in ("decryption_records", "plaintext_objects", "source_objects"):
            values = getattr(self, name)
            digests = [bytes.fromhex(item.sha256) for item in values]
            if digests != sorted(digests) or len(set(digests)) != len(digests):
                raise ValueError(f"{name} must be unique and sorted by digest")
        return self


class RevealResult(StrictProtocolModel):
    """Canonical deterministic result consumed by downstream weight build."""

    schema_: Literal[REVEAL_RESULT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    reveal_pulse_evidence_digest: Hex32
    pool_stage_evidence_sha256: Hex32
    response_stage_evidence_sha256: Hex32
    response_set_root: Hex32
    prior_protocol_state_digest: Hex32
    scoring_environment: dict[str, JsonValue]
    candidate_reveals: list[dict[str, JsonValue]]
    responses: list[dict[str, JsonValue]]
    void_reason_codes: list[str]
    canary_hit: bool
    objective_fault_findings: list[dict[str, JsonValue]]
    spent_transition_preview: dict[str, JsonValue]
    scored_batches: list[dict[str, JsonValue]]
    issued_request_count: Annotated[int, Field(ge=0, le=MAX_REVEAL_ASSIGNMENTS)]
    monitoring_observations: list[dict[str, JsonValue]]

    @model_validator(mode="after")
    def validate_canonical_collections(self) -> Self:
        if self.void_reason_codes != sorted(set(self.void_reason_codes)):
            raise ValueError("reveal void reasons must be unique and sorted")
        if self.canary_hit != ("canary_hit" in self.void_reason_codes):
            raise ValueError("reveal canary flag disagrees with its void reasons")
        assignment_ids = [item.get("assignment_id") for item in self.responses]
        if assignment_ids != sorted(assignment_ids):
            raise ValueError("reveal responses must be sorted by assignment ID")
        return self


class TranscriptAbortRevealResult(StrictProtocolModel):
    """No-score reveal result that closes one receipt-bound transcript abort."""

    schema_: Literal[REVEAL_ABORT_RESULT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    reveal_pulse_evidence_digest: Hex32
    pool_stage_evidence_sha256: Hex32
    response_stage_evidence_sha256: Hex32
    prior_protocol_state_digest: Hex32
    scoring_environment: dict[str, JsonValue]
    abort_origin: TranscriptAbortOrigin
    abort_origin_sha256: Hex32
    abort_origin_stage_evidence_sha256: Hex32
    candidate_reveals: list[dict[str, JsonValue]]
    void_reason_codes: list[str]
    canary_hit: Literal[False]
    objective_fault_findings: list[dict[str, JsonValue]]
    spent_transition_preview: dict[str, JsonValue]
    scored_batches: list[dict[str, JsonValue]]
    issued_request_count: Annotated[int, Field(ge=0, le=MAX_REVEAL_ASSIGNMENTS)]
    monitoring_observations: list[dict[str, JsonValue]]

    @model_validator(mode="after")
    def validate_abort_result(self) -> Self:
        if self.void_reason_codes != ["transcript_abort"]:
            raise ValueError("abort reveal has an invalid no-score reason")
        if self.scored_batches or self.monitoring_observations:
            raise ValueError("abort reveal cannot contain scoring output")
        origin_bytes = canonical_json_bytes(self.abort_origin)
        if hashlib.sha256(origin_bytes).hexdigest() != self.abort_origin_sha256:
            raise ValueError("abort reveal origin digest does not reproduce")
        if (
            self.abort_origin.window_id != self.window_id
            or self.abort_origin.scoring_policy_hash != self.scoring_policy_hash
            or self.abort_origin.pool_stage_evidence_sha256 != self.pool_stage_evidence_sha256
        ):
            raise ValueError("abort reveal origin changes its window binding")
        return self


class PoolNoScoreRevealResult(StrictProtocolModel):
    """No-score reveal result for a fully evidenced pool-stage decision."""

    schema_: Literal[POOL_NO_SCORE_REVEAL_RESULT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    reveal_pulse_evidence_digest: Hex32
    pool_stage_evidence_sha256: Hex32
    response_stage_evidence_sha256: Hex32
    prior_protocol_state_digest: Hex32
    scoring_environment: dict[str, JsonValue]
    pool_no_score: PoolNoScoreEvidence
    pool_no_score_sha256: Hex32
    candidate_reveals: list[dict[str, JsonValue]]
    void_reason_codes: list[str]
    canary_hit: Literal[False]
    objective_fault_findings: list[dict[str, JsonValue]]
    spent_transition_preview: dict[str, JsonValue]
    scored_batches: list[dict[str, JsonValue]]
    issued_request_count: Literal[0]
    monitoring_observations: list[dict[str, JsonValue]]

    @model_validator(mode="after")
    def validate_no_score_result(self) -> Self:
        if self.void_reason_codes != ["pool_no_score"]:
            raise ValueError("pool no-score reveal has an invalid reason set")
        if self.scored_batches or self.monitoring_observations:
            raise ValueError("pool no-score reveal cannot contain scoring output")
        origin_bytes = canonical_json_bytes(self.pool_no_score)
        if hashlib.sha256(origin_bytes).hexdigest() != self.pool_no_score_sha256:
            raise ValueError("pool no-score reveal origin digest does not reproduce")
        if (
            self.pool_no_score.window_id != self.window_id
            or self.pool_no_score.window_index != self.window_index
            or self.pool_no_score.scoring_policy_hash != self.scoring_policy_hash
        ):
            raise ValueError("pool no-score reveal origin changes its window binding")
        expected_candidates = [
            (
                item.batch_id,
                item.publisher_hotkey,
                item.control_group_id,
                item.batch_commitment,
                item.pool_leaf,
                item.batch_rank,
                item.selection_ordinal,
            )
            for item in self.pool_no_score.candidates
        ]
        actual_candidates = [
            (
                item.get("batch_id"),
                item.get("publisher_hotkey"),
                item.get("control_group_id"),
                item.get("batch_commitment"),
                item.get("pool_leaf"),
                item.get("batch_rank"),
                item.get("selection_ordinal"),
            )
            for item in self.candidate_reveals
        ]
        if actual_candidates != expected_candidates:
            raise ValueError("pool no-score reveal changes its candidate set")
        return self


@dataclass(frozen=True, slots=True)
class _ResponseMaterial:
    assignment_id: str
    prepared: PreparedRequestAttempt
    request_leaf: bytes
    disposition: str
    sealed_record: SealedResponseRecord
    envelope_bytes: bytes | None


@dataclass(frozen=True, slots=True)
class _CandidateMaterial:
    evidence: SelectedCandidateEvidence | PoolNoScoreCandidate
    pool_entry: PoolBatchEntry
    public_manifest: PublicBatchManifest
    sealed_ground_truth: SealedResponse


@dataclass(frozen=True, slots=True)
class _TranscriptReceiptSource:
    receipt: StageReceipt
    receipt_bytes: bytes
    evidence_sha256: str
    payloads: Mapping[str, bytes]


@dataclass(frozen=True, slots=True)
class _TranscriptAbortChain:
    origin: TranscriptAbortOrigin
    origin_sha256: str
    origin_stage_evidence_sha256: str
    sources: tuple[_TranscriptReceiptSource, ...]
    replays: tuple[TranscriptStageReplay | TranscriptAbortReplay, ...]


@dataclass(frozen=True, slots=True)
class _PoolNoScoreChain:
    origin: PoolNoScoreEvidence
    origin_sha256: str
    pool_stage_evidence_sha256: str
    sources: tuple[_TranscriptReceiptSource, ...]
    replays: tuple[PoolNoScoreReplay, ...]


@dataclass(frozen=True, slots=True)
class RevealComputation:
    """Typed output of the receipt-only deterministic reveal computation."""

    result_bytes: bytes
    spent_batches: tuple[SpentCohortBatch, ...]
    fault_findings: tuple[PublisherFaultFinding, ...]
    scored_batches: tuple[ScoredBatch, ...]
    issued_miner_roots: tuple[bytes, ...]
    monitoring_observations: tuple[SourceObservation, ...]
    void_reason_codes: tuple[str, ...]
    objects: tuple[StageObjectInput, ...]

    @property
    def valid_scoring_window(self) -> bool:
        return not self.void_reason_codes


@dataclass(frozen=True, slots=True)
class AppliedRevealTransition:
    transition_operation_id: bytes
    request_bytes: bytes
    protocol: AppliedProtocolWindow
    monitoring_request_bytes: bytes | None
    monitoring_report_bytes: bytes | None
    idempotent: bool


@dataclass(frozen=True, slots=True)
class ResolvedRevealStage:
    """Independently resolved authoritative receipt for downstream stages."""

    manifest: RevealStageManifest
    result: RevealResult | TranscriptAbortRevealResult | PoolNoScoreRevealResult
    policy: ScoringPolicy
    protocol_transition_request: Mapping[str, JsonValue]
    protocol_transition_result: Mapping[str, JsonValue]
    monitoring_report_bytes: bytes | None

    @property
    def resulting_protocol_state_digest(self) -> str:
        state = self.protocol_transition_result.get("state")
        if not isinstance(state, dict):
            raise RevealBindingError("protocol transition result lacks state")
        digest = state.get("state_digest")
        if not isinstance(digest, str) or _HEX32_RE.fullmatch(digest) is None:
            raise RevealBindingError("protocol transition result has an invalid state digest")
        return digest


def _default_decrypt(sealed: SealedResponse, _pulse: DrandPulse) -> Awaitable[bytes]:
    return asyncio.to_thread(
        decrypt_response,
        sealed,
        reveal_round=sealed.reveal_round,
        sha256_hex=sealed.sha256_hex,
        wait=False,
    )


async def _await_value(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _fraction(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def _object_ref(data: bytes, media_type: str) -> RevealObjectRef:
    if not isinstance(data, bytes):
        raise TypeError("reveal object must be exact bytes")
    if media_type not in {
        "application/json",
        "application/octet-stream",
        SCORING_POLICY_MEDIA_TYPE,
        STAGE_RECEIPT_MEDIA_TYPE,
    }:
        raise ValueError("reveal object has an unsupported media type")
    return RevealObjectRef(
        sha256=hashlib.sha256(data).hexdigest(),
        media_type=media_type,
        size_bytes=len(data),
    )


def _stage_ref(reference: StageObject) -> RevealObjectRef:
    return RevealObjectRef.model_validate(reference.model_dump(mode="json"))


def _parse_canonical(data: bytes, model: type[Any], label: str) -> Any:
    if not isinstance(data, bytes):
        raise TypeError(f"{label} must be exact bytes")
    try:
        value = model.model_validate_json(data)
    except (ValidationError, ValueError) as error:
        raise RevealBindingError(f"{label} is invalid") from error
    if canonical_json_bytes(value) != data:
        raise RevealBindingError(f"{label} is not canonical JSON")
    return value


def _parse_reveal_result(
    data: bytes,
) -> RevealResult | TranscriptAbortRevealResult | PoolNoScoreRevealResult:
    value = _strict_json(data, "reveal result")
    if not isinstance(value, dict):
        raise RevealBindingError("reveal result is not a JSON object")
    schema = value.get("schema")
    if schema == REVEAL_RESULT_SCHEMA:
        model: type[Any] = RevealResult
    elif schema == REVEAL_ABORT_RESULT_SCHEMA:
        model = TranscriptAbortRevealResult
    elif schema == POOL_NO_SCORE_REVEAL_RESULT_SCHEMA:
        model = PoolNoScoreRevealResult
    else:
        raise RevealBindingError("reveal result has another schema")
    return _parse_canonical(data, model, "reveal result")


def _strict_json(data: bytes, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise RevealBindingError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevealBindingError(f"{label} is invalid JSON") from error


def _parse_pulse(data: bytes, *, expected_round: int) -> DrandPulse:
    value = _strict_json(data, "reveal pulse")
    if not isinstance(value, dict) or set(value) != {"round", "randomness", "signature"}:
        raise RevealBindingError("reveal pulse has unexpected fields")
    if canonical_json_bytes(value) != data:
        raise RevealBindingError("reveal pulse is not canonical JSON")
    if isinstance(value["round"], bool) or not isinstance(value["round"], int):
        raise RevealBindingError("reveal pulse round is not an exact integer")
    try:
        pulse = DrandPulse.from_json(value, expected_round=expected_round)
        pulse.verify()
    except (TypeError, ValueError, DrandVerificationError) as error:
        raise RevealBindingError("reveal pulse verification failed") from error
    return pulse


def _completed_digest(work: StageWorkItem, stage: WindowStage) -> str:
    matches = [item for item in work.completed_evidence if item.stage is stage]
    if len(matches) != 1:
        raise RevealBindingError(f"work lacks one authoritative {stage.value} digest")
    evidence = matches[0]
    if evidence.window_id != work.window.plan.window_id:
        raise RevealBindingError(f"{stage.value} evidence binds another window")
    return evidence.evidence_sha256


def _receipt_payloads(
    journal: ValidatorStageJournal,
    record: StageJournalRecord,
) -> dict[str, bytes]:
    payloads = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
    if set(payloads) != {item.sha256 for item in record.receipt.objects}:
        raise RevealBindingError("stage receipt object graph is incomplete")
    return payloads


def _transcript_receipt_sources(
    journal: ValidatorStageJournal,
    records: Sequence[StageJournalRecord],
) -> tuple[_TranscriptReceiptSource, ...]:
    return tuple(
        _TranscriptReceiptSource(
            receipt=record.receipt,
            receipt_bytes=record.receipt_bytes,
            evidence_sha256=record.evidence_sha256,
            payloads=_receipt_payloads(journal, record),
        )
        for record in records
    )


def _embedded_transcript_sources(
    payloads: Mapping[str, bytes],
    *,
    window_id: str,
) -> tuple[_TranscriptReceiptSource, ...]:
    expected = (
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
        WindowStage.SEALED_RESPONSE,
    )
    found: dict[WindowStage, list[tuple[StageReceipt, bytes]]] = {stage: [] for stage in expected}
    for data in payloads.values():
        try:
            decoded = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(decoded, dict) or decoded.get("schema") != (
            "umi-validator-stage-receipt/1"
        ):
            continue
        receipt = _parse_canonical(data, StageReceipt, "embedded stage receipt")
        try:
            stage = WindowStage(receipt.stage)
        except ValueError:
            continue
        if receipt.window_id == window_id and stage in found:
            found[stage].append((receipt, data))
    if any(len(found[stage]) != 1 for stage in expected):
        raise RevealBindingError("abort reveal transcript receipt cardinality is not exact")
    sources: list[_TranscriptReceiptSource] = []
    for stage in expected:
        receipt, receipt_bytes = found[stage][0]
        if not {item.sha256 for item in receipt.objects}.issubset(payloads):
            raise RevealBindingError("abort reveal omits a transcript receipt object")
        sources.append(
            _TranscriptReceiptSource(
                receipt=receipt,
                receipt_bytes=receipt_bytes,
                evidence_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
                payloads={item.sha256: payloads[item.sha256] for item in receipt.objects},
            )
        )
    return tuple(sources)


def _resolve_transcript_abort_chain(
    sources: Sequence[_TranscriptReceiptSource],
    *,
    pool_stage_evidence_sha256: str,
    material_binding: TranscriptMaterialBinding | None,
    scoring_policy_hash: str,
) -> _TranscriptAbortChain | None:
    expected_stages = (
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
        WindowStage.SEALED_RESPONSE,
    )
    if len(sources) != len(expected_stages):
        raise RevealBindingError("transcript abort source prefix is incomplete")
    pool_digest = raw_sha256(
        pool_stage_evidence_sha256,
        field="pool stage evidence",
    ).hex()
    replays: list[TranscriptStageReplay | TranscriptAbortReplay] = []
    origin: TranscriptAbortOrigin | None = None
    origin_sha256: str | None = None
    origin_stage_digest: str | None = None
    prior_digest = pool_digest
    window_id: str | None = None
    canonical_sources: list[_TranscriptReceiptSource] = []
    for stage, source in zip(expected_stages, sources, strict=True):
        if not isinstance(source, _TranscriptReceiptSource):
            raise TypeError("transcript source must be _TranscriptReceiptSource")
        if (
            canonical_json_bytes(source.receipt) != source.receipt_bytes
            or hashlib.sha256(source.receipt_bytes).hexdigest() != source.evidence_sha256
            or source.receipt.stage != stage.value
            or source.receipt.operation_id != stage_operation_id(source.receipt.window_id, stage)
        ):
            raise RevealBindingError("transcript abort source receipt changed")
        if window_id is None:
            window_id = source.receipt.window_id
        elif source.receipt.window_id != window_id:
            raise RevealBindingError("transcript abort source binds another window")
        try:
            replay = replay_transcript_stage_receipt(
                _transcript_receipt_for_replay(source.receipt),
                source.payloads,
            )
        except TranscriptReplayError as error:
            raise RevealBindingError("transcript abort source does not replay") from error
        if replay.stage is not stage or replay.window_id != source.receipt.window_id:
            raise RevealBindingError("transcript abort replay changes its stage binding")
        if isinstance(replay, TranscriptStageReplay):
            if origin is not None:
                raise RevealBindingError("normal transcript receipt follows an abort")
            if material_binding is not None and (
                replay.material_binding != material_binding
                or replay.scoring_policy_hash != scoring_policy_hash
            ):
                raise RevealBindingError("normal transcript prefix changes window material")
        else:
            if replay.previous_stage_evidence_sha256 != prior_digest:
                raise RevealBindingError("transcript abort chain skips its prior receipt")
            if origin is None:
                if (
                    replay.origin.origin_stage != stage.value
                    or replay.origin_stage_evidence_sha256 is not None
                ):
                    raise RevealBindingError("transcript abort origin is not receipt-local")
                origin = replay.origin
                origin_sha256 = replay.origin_sha256
                origin_stage_digest = source.evidence_sha256
            elif (
                replay.origin != origin
                or replay.origin_sha256 != origin_sha256
                or replay.origin_stage_evidence_sha256 != origin_stage_digest
            ):
                raise RevealBindingError("transcript abort propagation changes its origin")
        replays.append(replay)
        canonical_sources.append(source)
        prior_digest = source.evidence_sha256
    if origin is None:
        return None
    if not isinstance(replays[-1], TranscriptAbortReplay):
        raise RevealBindingError("transcript abort does not reach sealed response")
    effective_binding = material_binding or TranscriptMaterialBinding(
        material_sha256=origin.window_material_sha256,
        material_receipt_sha256=origin.window_material_receipt_sha256,
        pool_stage_evidence_sha256=origin.pool_stage_evidence_sha256,
    )
    if any(
        isinstance(replay, TranscriptStageReplay)
        and (
            replay.material_binding != effective_binding
            or replay.scoring_policy_hash != scoring_policy_hash
        )
        for replay in replays
    ):
        raise RevealBindingError("normal transcript prefix changes window material")
    if (
        window_id is None
        or origin.window_id != window_id
        or origin.scoring_policy_hash != scoring_policy_hash
        or origin.pool_stage_evidence_sha256 != pool_digest
        or origin.window_material_sha256 != effective_binding.material_sha256
        or origin.window_material_receipt_sha256 != effective_binding.material_receipt_sha256
        or origin.origin_operation_id
        != stage_operation_id(window_id, WindowStage(origin.origin_stage))
        or origin_sha256 is None
        or origin_stage_digest is None
    ):
        raise RevealBindingError("transcript abort origin changes its window binding")
    return _TranscriptAbortChain(
        origin=origin,
        origin_sha256=origin_sha256,
        origin_stage_evidence_sha256=origin_stage_digest,
        sources=tuple(canonical_sources),
        replays=tuple(replays),
    )


def _resolve_pool_no_score_chain(
    sources: Sequence[_TranscriptReceiptSource],
    *,
    pool_stage_evidence_sha256: str,
    expected_origin: PoolNoScoreEvidence,
    scoring_policy_hash: str,
) -> _PoolNoScoreChain:
    expected_stages = (
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
        WindowStage.SEALED_RESPONSE,
    )
    if len(sources) != len(expected_stages):
        raise RevealBindingError("pool no-score transcript prefix is incomplete")
    pool_digest = raw_sha256(
        pool_stage_evidence_sha256,
        field="pool stage evidence",
    ).hex()
    origin_bytes = canonical_json_bytes(expected_origin)
    origin_sha256 = hashlib.sha256(origin_bytes).hexdigest()
    prior_digest = pool_digest
    replays: list[PoolNoScoreReplay] = []
    canonical_sources: list[_TranscriptReceiptSource] = []
    for stage, source in zip(expected_stages, sources, strict=True):
        if (
            canonical_json_bytes(source.receipt) != source.receipt_bytes
            or hashlib.sha256(source.receipt_bytes).hexdigest() != source.evidence_sha256
            or source.receipt.stage != stage.value
            or source.receipt.operation_id != stage_operation_id(source.receipt.window_id, stage)
        ):
            raise RevealBindingError("pool no-score transcript receipt changed")
        try:
            replay = replay_transcript_stage_receipt(
                _transcript_receipt_for_replay(source.receipt),
                source.payloads,
            )
        except TranscriptReplayError as error:
            raise RevealBindingError("pool no-score transcript receipt does not replay") from error
        if (
            not isinstance(replay, PoolNoScoreReplay)
            or replay.stage is not stage
            or replay.window_id != expected_origin.window_id
            or replay.operation_id != source.receipt.operation_id
            or replay.origin != expected_origin
            or replay.origin_sha256 != origin_sha256
            or replay.pool_stage_evidence_sha256 != pool_digest
            or replay.previous_stage_evidence_sha256 != prior_digest
        ):
            raise RevealBindingError("pool no-score transcript chain changes its origin")
        replays.append(replay)
        canonical_sources.append(source)
        prior_digest = source.evidence_sha256
    if (
        expected_origin.scoring_policy_hash != scoring_policy_hash
        or expected_origin.operation_id
        != stage_operation_id(expected_origin.window_id, WindowStage.POOL_AND_SELECTION)
    ):
        raise RevealBindingError("pool no-score origin changes its policy binding")
    return _PoolNoScoreChain(
        origin=expected_origin,
        origin_sha256=origin_sha256,
        pool_stage_evidence_sha256=pool_digest,
        sources=tuple(canonical_sources),
        replays=tuple(replays),
    )


def _abort_issued_miner_roots(
    abort: _TranscriptAbortChain,
    *,
    selection: PoolSelectionEvidence,
    stored: StoredWindowMaterial,
) -> tuple[bytes, ...]:
    if abort.origin.origin_stage != WindowStage.SEALED_RESPONSE.value:
        return ()
    request_replay = abort.replays[1]
    if not isinstance(request_replay, TranscriptStageReplay):
        raise RevealBindingError("response abort lacks a valid request-set anchor")
    expected_origins = tuple(
        (assignment.assignment_id, assignment.miner_url) for assignment in stored.plan.assignments
    )
    if (
        request_replay.stage is not WindowStage.REQUEST_TRANSCRIPT
        or request_replay.assignment_count != len(stored.plan.assignments)
        or request_replay.miner_origins != expected_origins
    ):
        raise RevealBindingError("response abort request-set anchor changes assignments")
    roots_by_hotkey = {
        account_id32(item.hotkey): account_id32(item.root) for item in selection.selected_panel
    }
    roots: list[bytes] = []
    for assignment in stored.plan.assignments:
        root = roots_by_hotkey.get(account_id32(assignment.initial_attempt.miner_hotkey))
        if root is None:
            raise RevealBindingError("response abort assignment is absent from selected panel")
        roots.append(root)
    return tuple(sorted(roots))


def _resolve(
    payloads: Mapping[str, bytes],
    reference: PoolEvidenceObjectRef | EvidenceRef | RevealObjectRef,
    *,
    label: str,
) -> bytes:
    try:
        data = payloads[reference.sha256]
    except KeyError as error:
        raise RevealBindingError(f"{label} object is absent from its source receipt") from error
    if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != reference.sha256:
        raise RevealBindingError(f"{label} object metadata does not reproduce")
    return data


def _policy_state_object(snapshot: ProtocolStateSnapshot) -> bytes:
    """Canonical complete pre-state required to replay reveal transitions."""
    return encode_protocol_state_snapshot(snapshot)


def _exact_fraction(value: Any, *, label: str) -> Fraction:
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise RevealBindingError(f"{label} is not an exact fraction")
    numerator = value["numerator"]
    denominator = value["denominator"]
    if (
        isinstance(numerator, bool)
        or not isinstance(numerator, int)
        or isinstance(denominator, bool)
        or not isinstance(denominator, int)
        or denominator <= 0
    ):
        raise RevealBindingError(f"{label} is not an exact fraction")
    result = Fraction(numerator, denominator)
    if result.numerator != numerator or result.denominator != denominator:
        raise RevealBindingError(f"{label} fraction is not reduced")
    return result


def _decode_scored_batch_object(value: Any) -> ScoredBatch:
    if not isinstance(value, dict) or set(value) != {
        "window_index",
        "batch_rank",
        "pool_leaf",
        "challenge_ids",
        "miner_roots",
        "assignments",
    }:
        raise RevealBindingError("prior rolling batch is invalid")
    assignments_value = value["assignments"]
    if not isinstance(assignments_value, list):
        raise RevealBindingError("prior rolling assignments are invalid")
    assignments: list[AssignmentScore] = []
    for item in assignments_value:
        if not isinstance(item, dict) or set(item) != {
            "miner_root",
            "challenge_id",
            "request_leaf",
            "stratum",
            "canary",
            "score",
        }:
            raise RevealBindingError("prior rolling assignment is invalid")
        score = item["score"]
        assignments.append(
            AssignmentScore(
                miner_root=raw_sha256(item["miner_root"], field="prior miner root"),
                challenge_id=item["challenge_id"],
                request_leaf=raw_sha256(item["request_leaf"], field="prior request leaf"),
                stratum=item["stratum"],
                canary=item["canary"],
                score=(None if score is None else _exact_fraction(score, label="prior score")),
            )
        )
    try:
        return ScoredBatch(
            window_index=value["window_index"],
            batch_rank=raw_sha256(value["batch_rank"], field="prior batch rank"),
            pool_leaf=raw_sha256(value["pool_leaf"], field="prior pool leaf"),
            challenge_ids=tuple(value["challenge_ids"]),
            miner_roots=tuple(
                raw_sha256(item, field="prior miner root") for item in value["miner_roots"]
            ),
            assignments=tuple(assignments),
        )
    except (ProtocolStateCorruption, TypeError, ValueError) as error:
        raise RevealBindingError("prior rolling batch does not reproduce") from error


def _policy_state_from_object(data: bytes) -> ProtocolStateSnapshot:
    try:
        return decode_protocol_state_snapshot(data)
    except (TypeError, ValueError) as error:
        raise RevealBindingError("prior protocol state does not reproduce") from error


def _assignment_score_object(value: AssignmentScore) -> dict[str, Any]:
    return {
        "miner_root": value.root.hex(),
        "challenge_id": value.challenge_id,
        "request_leaf": value.leaf.hex(),
        "stratum": value.stratum,
        "canary": value.canary,
        "score": None if value.score is None else _fraction(value.score),
    }


def _scored_batch_object(value: ScoredBatch) -> dict[str, Any]:
    return {
        "window_index": value.window_index,
        "batch_rank": raw_sha256(value.batch_rank, field="batch rank").hex(),
        "pool_leaf": raw_sha256(value.pool_leaf, field="pool leaf").hex(),
        "challenge_ids": list(value.challenge_ids),
        "miner_roots": [account_id32(item).hex() for item in value.miner_roots],
        "assignments": [_assignment_score_object(item) for item in value.assignments],
    }


class RevealTransitionCoordinator:
    """Recoverably atomic coordinator for protocol and monitoring stores.

    SQLite cannot atomically commit two unrelated database files.  This journal
    therefore records one immutable intent first, requires every reveal to pass
    through the journal in window order, and uses the same operation/evidence
    digests at both idempotent stores.  A partial commit remains the sole pending
    operation and is completed on retry before another window can start.
    """

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        busy_timeout_seconds: float = 10.0,
    ) -> None:
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("coordinator busy timeout must be positive and finite")
        self._path = Path(database_path)
        self._prepare_path()
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(
                os.fspath(self._path),
                timeout=float(busy_timeout_seconds),
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_seconds * 1_000)}")
            self._initialize()
            self.audit()
            self._assert_safe_files()
        except RevealEffectError:
            with suppress(Exception):
                self._connection.close()
            raise
        except (OSError, sqlite3.Error) as error:
            with suppress(Exception):
                self._connection.close()
            raise RevealEffectError("reveal transition coordinator cannot open") from error

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> RevealTransitionCoordinator:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def apply(
        self,
        *,
        stage_operation_id_value: str,
        transition_operation_id: bytes,
        evidence_digest: bytes,
        window_index: int,
        window_id: bytes,
        reveal_round: int,
        prior_state_digest: bytes,
        prior_state_bytes: bytes,
        computation: RevealComputation,
        protocol_state: ValidatorProtocolStateStore,
        monitoring_state: ValidatorMonitoringStateStore,
        policy_limits: ProtocolStatePolicyLimits,
    ) -> AppliedRevealTransition:
        if not isinstance(computation, RevealComputation):
            raise TypeError("computation must be RevealComputation")
        if not isinstance(protocol_state, ValidatorProtocolStateStore):
            raise TypeError("protocol_state must be ValidatorProtocolStateStore")
        if not isinstance(monitoring_state, ValidatorMonitoringStateStore):
            raise TypeError("monitoring_state must be ValidatorMonitoringStateStore")
        operation = raw_sha256(transition_operation_id, field="transition operation ID")
        evidence = raw_sha256(evidence_digest, field="reveal evidence digest")
        identifier = raw_sha256(window_id, field="window ID")
        prior = raw_sha256(prior_state_digest, field="prior protocol state digest")
        if _policy_state_from_object(prior_state_bytes).state_digest != prior:
            raise RevealBindingError("coordinator prior-state bytes bind another digest")
        request_bytes = canonical_json_bytes(
            {
                "schema": REVEAL_TRANSITION_SCHEMA,
                "stage_operation_id": stage_operation_id_value,
                "transition_operation_id": operation.hex(),
                "window_index": window_index,
                "window_id": identifier.hex(),
                "reveal_round": reveal_round,
                "evidence_digest": evidence.hex(),
                "prior_protocol_state_digest": prior.hex(),
                "valid_scoring_window": computation.valid_scoring_window,
                "void_reason_codes": list(computation.void_reason_codes),
                "reveal_result_sha256": hashlib.sha256(computation.result_bytes).hexdigest(),
                "scored_batches_sha256": hashlib.sha256(
                    canonical_json_bytes(
                        [_scored_batch_object(item) for item in computation.scored_batches]
                    )
                ).hexdigest(),
                "monitoring_observations_sha256": hashlib.sha256(
                    canonical_json_bytes(
                        [
                            _source_observation_object(item)
                            for item in computation.monitoring_observations
                        ]
                    )
                ).hexdigest(),
            }
        )
        if len(request_bytes) > MAX_REVEAL_COORDINATOR_BYTES:
            raise RevealLimitError("coordinator request exceeds its byte ceiling")
        existed_complete = self._record_intent(
            operation=operation,
            window_index=window_index,
            window_id=identifier,
            request_bytes=request_bytes,
            prior_state_bytes=prior_state_bytes,
        )

        protocol = protocol_state.apply_window(
            operation_id=operation,
            window_index=window_index,
            window_id=identifier,
            reveal_round=reveal_round,
            evidence_digest=evidence,
            spent_cohort_batches=computation.spent_batches,
            objective_fault_findings=computation.fault_findings,
            scored_batches=computation.scored_batches,
            issued_miner_roots=computation.issued_miner_roots,
            policy_limits=policy_limits,
        )
        monitoring_request: bytes | None = None
        monitoring_report: bytes | None = None
        if computation.valid_scoring_window:
            applied_monitoring = monitoring_state.apply_window(
                operation_id=operation,
                window_index=window_index,
                window_id=identifier,
                evidence_digest=evidence,
                valid_window=True,
                observations=computation.monitoring_observations,
            )
            monitoring_request = applied_monitoring.request_bytes
            monitoring_report = monitoring_state.computation_input().compute().report_bytes

        self._record_completion(
            operation=operation,
            request_bytes=request_bytes,
            protocol_request=protocol.request_bytes,
            protocol_result=protocol.result_bytes,
            monitoring_request=monitoring_request,
            monitoring_report=monitoring_report,
        )
        return AppliedRevealTransition(
            transition_operation_id=operation,
            request_bytes=request_bytes,
            protocol=protocol,
            monitoring_request_bytes=monitoring_request,
            monitoring_report_bytes=monitoring_report,
            idempotent=existed_complete and protocol.idempotent,
        )

    def recover_prior_state(
        self,
        *,
        transition_operation_id: bytes,
        window_index: int,
        window_id: bytes,
    ) -> ProtocolStateSnapshot | None:
        """Return the immutable pre-state for a partial/complete stage retry."""

        operation = raw_sha256(transition_operation_id, field="transition operation ID")
        identifier = raw_sha256(window_id, field="window ID")
        with self._lock, self._transaction() as connection:
            row = connection.execute(
                "SELECT window_index, window_id, prior_state_bytes, prior_state_sha256 "
                "FROM operations WHERE operation_id = ?",
                (operation,),
            ).fetchone()
            if row is None:
                return None
            if int(row["window_index"]) != window_index or bytes(row["window_id"]) != identifier:
                raise RevealTransitionConflict("coordinator recovery binds another window")
            data = bytes(row["prior_state_bytes"])
            if hashlib.sha256(data).digest() != bytes(row["prior_state_sha256"]):
                raise RevealEffectError("coordinator prior-state digest does not reproduce")
            return _policy_state_from_object(data)

    def audit(self) -> None:
        with self._lock, self._transaction() as connection:
            rows = connection.execute("SELECT * FROM operations ORDER BY window_index").fetchall()
            pending = 0
            prior_index = -1
            for row in rows:
                request = bytes(row["request_bytes"])
                if len(request) > MAX_REVEAL_COORDINATOR_BYTES:
                    raise RevealEffectError("coordinator request exceeds its byte ceiling")
                if hashlib.sha256(request).digest() != bytes(row["request_sha256"]):
                    raise RevealEffectError("coordinator request digest does not reproduce")
                prior_state_bytes = bytes(row["prior_state_bytes"])
                if hashlib.sha256(prior_state_bytes).digest() != bytes(row["prior_state_sha256"]):
                    raise RevealEffectError("coordinator prior-state digest does not reproduce")
                prior_state = _policy_state_from_object(prior_state_bytes)
                value = _strict_json(request, "coordinator request")
                if not isinstance(value, dict) or value.get("schema") != REVEAL_TRANSITION_SCHEMA:
                    raise RevealEffectError("coordinator request schema is invalid")
                if value.get("transition_operation_id") != bytes(row["operation_id"]).hex():
                    raise RevealEffectError("coordinator operation binding does not reproduce")
                if value.get("prior_protocol_state_digest") != prior_state.state_digest.hex():
                    raise RevealEffectError("coordinator prior-state binding does not reproduce")
                index = int(row["window_index"])
                if index <= prior_index:
                    raise RevealEffectError("coordinator window ordering is invalid")
                prior_index = index
                if value.get("window_id") != bytes(row["window_id"]).hex():
                    raise RevealEffectError("coordinator window binding does not reproduce")
                complete = int(row["complete"])
                if complete not in {0, 1}:
                    raise RevealEffectError("coordinator completion flag is invalid")
                outputs = (
                    row["protocol_request"],
                    row["protocol_result"],
                    row["monitoring_request"],
                    row["monitoring_report"],
                )
                if complete:
                    if outputs[0] is None or outputs[1] is None:
                        raise RevealEffectError("complete coordinator row lacks protocol output")
                    if (outputs[2] is None) != (outputs[3] is None):
                        raise RevealEffectError("coordinator monitoring output is partial")
                    self._verify_output_digests(row)
                else:
                    pending += 1
                    if any(value is not None for value in outputs):
                        raise RevealEffectError("pending coordinator row carries output")
            if pending > 1:
                raise RevealEffectError("coordinator contains more than one pending operation")

    def _record_intent(
        self,
        *,
        operation: bytes,
        window_index: int,
        window_id: bytes,
        request_bytes: bytes,
        prior_state_bytes: bytes,
    ) -> bool:
        with self._lock, self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation,)
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["request_bytes"]) != request_bytes
                    or bytes(existing["prior_state_bytes"]) != prior_state_bytes
                ):
                    raise RevealTransitionConflict("transition operation ID conflict")
                return bool(existing["complete"])
            pending = connection.execute(
                "SELECT operation_id FROM operations WHERE complete = 0 LIMIT 1"
            ).fetchone()
            if pending is not None:
                raise RevealTransitionConflict("another reveal transition is pending recovery")
            collision = connection.execute(
                "SELECT operation_id FROM operations WHERE window_index = ? OR window_id = ?",
                (window_index, window_id),
            ).fetchone()
            if collision is not None:
                raise RevealTransitionConflict("reveal window already has another operation")
            connection.execute(
                "INSERT INTO operations (operation_id, window_index, window_id, request_bytes, "
                "request_sha256, prior_state_bytes, prior_state_sha256, complete) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    operation,
                    window_index,
                    window_id,
                    request_bytes,
                    hashlib.sha256(request_bytes).digest(),
                    prior_state_bytes,
                    hashlib.sha256(prior_state_bytes).digest(),
                ),
            )
            return False

    def _record_completion(
        self,
        *,
        operation: bytes,
        request_bytes: bytes,
        protocol_request: bytes,
        protocol_result: bytes,
        monitoring_request: bytes | None,
        monitoring_report: bytes | None,
    ) -> None:
        values = (protocol_request, protocol_result, monitoring_request, monitoring_report)
        if any(value is not None and not isinstance(value, bytes) for value in values):
            raise TypeError("coordinator outputs must be exact bytes")
        if (monitoring_request is None) != (monitoring_report is None):
            raise ValueError("coordinator monitoring outputs must appear together")
        if sum(len(value) for value in values if value is not None) > (
            MAX_REVEAL_COORDINATOR_BYTES
        ):
            raise RevealLimitError("coordinator outputs exceed their byte ceiling")
        with self._lock, self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation,)
            ).fetchone()
            if row is None or bytes(row["request_bytes"]) != request_bytes:
                raise RevealTransitionConflict("coordinator intent disappeared or changed")
            if row["complete"]:
                expected = tuple(
                    None if value is None else bytes(value)
                    for value in (
                        row["protocol_request"],
                        row["protocol_result"],
                        row["monitoring_request"],
                        row["monitoring_report"],
                    )
                )
                if expected != values:
                    raise RevealTransitionConflict("coordinator completion output conflict")
                return
            connection.execute(
                "UPDATE operations SET protocol_request = ?, protocol_request_sha256 = ?, "
                "protocol_result = ?, protocol_result_sha256 = ?, monitoring_request = ?, "
                "monitoring_request_sha256 = ?, monitoring_report = ?, "
                "monitoring_report_sha256 = ?, complete = 1 WHERE operation_id = ?",
                (
                    protocol_request,
                    hashlib.sha256(protocol_request).digest(),
                    protocol_result,
                    hashlib.sha256(protocol_result).digest(),
                    monitoring_request,
                    (
                        None
                        if monitoring_request is None
                        else hashlib.sha256(monitoring_request).digest()
                    ),
                    monitoring_report,
                    (
                        None
                        if monitoring_report is None
                        else hashlib.sha256(monitoring_report).digest()
                    ),
                    operation,
                ),
            )

    def _verify_output_digests(self, row: sqlite3.Row) -> None:
        for name in (
            "protocol_request",
            "protocol_result",
            "monitoring_request",
            "monitoring_report",
        ):
            value = row[name]
            digest = row[f"{name}_sha256"]
            if value is None:
                if digest is not None:
                    raise RevealEffectError("empty coordinator output carries a digest")
                continue
            if digest is None or hashlib.sha256(bytes(value)).digest() != bytes(digest):
                raise RevealEffectError("coordinator output digest does not reproduce")

    def _prepare_path(self) -> None:
        parent = self._path.parent
        if not self._path.is_absolute():
            raise RevealEffectError("coordinator database path must be absolute")
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            unresolved = parent.lstat()
            if stat.S_ISLNK(unresolved.st_mode):
                raise RevealEffectError("coordinator parent must be a private real directory")
            resolved_parent = parent.resolve(strict=True)
            parent_metadata = resolved_parent.stat()
        except RevealEffectError:
            raise
        except OSError as error:
            raise RevealEffectError("coordinator parent is unavailable") from error
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_mode & 0o077
            or (hasattr(os, "getuid") and parent_metadata.st_uid != os.getuid())
        ):
            raise RevealEffectError("coordinator parent must be a private real directory")
        self._path = resolved_parent / self._path.name
        for suffix in ("", "-wal", "-shm", "-journal"):
            self._assert_safe_path(
                Path(os.fspath(self._path) + suffix),
                allow_missing=True,
            )
        if not self._path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self._path, flags, 0o600)
                os.close(descriptor)
            except OSError as error:
                raise RevealEffectError("coordinator database cannot be created safely") from error
        self._assert_safe_path(self._path, allow_missing=False)

    def _initialize(self) -> None:
        with self._lock, self._transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS store_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) "
                "WITHOUT ROWID"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS operations ("
                "operation_id BLOB PRIMARY KEY CHECK(typeof(operation_id)='blob' AND "
                "length(operation_id)=32), window_index INTEGER NOT NULL UNIQUE "
                "CHECK(window_index>=0), window_id BLOB NOT NULL UNIQUE "
                "CHECK(typeof(window_id)='blob' AND length(window_id)=32), "
                "request_bytes BLOB NOT NULL, request_sha256 BLOB NOT NULL "
                "CHECK(length(request_sha256)=32), "
                "prior_state_bytes BLOB NOT NULL, prior_state_sha256 BLOB NOT NULL "
                "CHECK(length(prior_state_sha256)=32), "
                "protocol_request BLOB, protocol_request_sha256 BLOB, protocol_result BLOB, "
                "protocol_result_sha256 BLOB, monitoring_request BLOB, "
                "monitoring_request_sha256 BLOB, "
                "monitoring_report BLOB, monitoring_report_sha256 BLOB, complete INTEGER NOT NULL "
                "CHECK(complete IN (0,1))) WITHOUT ROWID"
            )
            app_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if app_id not in {0, _COORDINATOR_APPLICATION_ID}:
                raise RevealEffectError("coordinator application ID is foreign")
            if user_version not in {0, _COORDINATOR_SCHEMA_VERSION}:
                raise RevealEffectError("coordinator schema version is unsupported")
            connection.execute(f"PRAGMA application_id = {_COORDINATOR_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {_COORDINATOR_SCHEMA_VERSION}")
        self._assert_safe_files()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            yield self._connection
            self._assert_safe_files()
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def _assert_safe_files(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = Path(os.fspath(self._path) + suffix)
            self._assert_safe_path(path, allow_missing=suffix != "")

    @staticmethod
    def _assert_safe_path(path: Path, *, allow_missing: bool) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if allow_missing:
                return
            raise RevealEffectError("coordinator SQLite path is missing") from None
        except OSError as error:
            raise RevealEffectError("coordinator SQLite path is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RevealEffectError("coordinator SQLite path is a symlink")
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
            or metadata.st_nlink != 1
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise RevealEffectError("coordinator SQLite path is not a private regular file")


def _source_observation_object(value: SourceObservation) -> dict[str, Any]:
    return {
        "request_leaf": value.request_leaf.hex(),
        "pool_leaf": value.pool_leaf.hex(),
        "miner_root": value.miner_root.hex(),
        "publisher_hotkey": value.publisher_hotkey.hex(),
        "control_group_id": value.control_group_id.hex(),
        "signer_cluster_id": value.signer_cluster_id.hex(),
        "stratum": value.stratum,
        "score": _fraction(value.score),
    }


def _find_one_schema(
    payloads: Mapping[str, bytes],
    schema: str,
    model: type[Any],
    *,
    label: str,
) -> tuple[Any, bytes]:
    matches: list[tuple[Any, bytes]] = []
    for data in payloads.values():
        if not data.startswith(b"{"):
            continue
        try:
            value = _strict_json(data, label)
        except RevealBindingError:
            continue
        if isinstance(value, dict) and value.get("schema") == schema:
            matches.append((_parse_canonical(data, model, label), data))
    if len(matches) != 1:
        raise RevealBindingError(f"{label} cardinality is not exactly one")
    return matches[0]


def _find_pool_stage_decision(
    payloads: Mapping[str, bytes],
) -> tuple[PoolSelectionEvidence | PoolNoScoreEvidence, bytes]:
    matches: list[tuple[PoolSelectionEvidence | PoolNoScoreEvidence, bytes]] = []
    models: dict[str, type[PoolSelectionEvidence | PoolNoScoreEvidence]] = {
        POOL_SELECTION_EVIDENCE_SCHEMA: PoolSelectionEvidence,
        POOL_NO_SCORE_SCHEMA: PoolNoScoreEvidence,
    }
    for data in payloads.values():
        if not data.startswith(b"{"):
            continue
        try:
            value = _strict_json(data, "pool stage decision")
        except RevealBindingError:
            continue
        if not isinstance(value, dict):
            continue
        schema = value.get("schema")
        model = models.get(schema) if isinstance(schema, str) else None
        if model is not None:
            matches.append((_parse_canonical(data, model, "pool stage decision"), data))
    if len(matches) != 1:
        raise RevealBindingError("pool stage decision cardinality is not exactly one")
    return matches[0]


def _validate_source_index(
    evidence: PoolSelectionEvidence,
    payloads: Mapping[str, bytes],
) -> None:
    refs = {item.sha256: item for item in evidence.source_objects}
    for digest, reference in refs.items():
        _resolve(payloads, reference, label=f"pool source {digest}")
    required = {
        evidence.closing_snapshot.sha256,
        evidence.closing_proof_evidence.sha256,
        evidence.artifact_retrieval_evidence.sha256,
        evidence.selection_pulse.sha256,
        evidence.policy_object.sha256,
        evidence.issuance_finality_evidence.sha256,
    }
    required.update(item.final_pool_manifest.sha256 for item in evidence.candidates)
    required.update(item.public_manifest.sha256 for item in evidence.candidates)
    required.update(item.ground_truth_envelope.sha256 for item in evidence.candidates)
    if not required.issubset(refs):
        raise RevealBindingError("pool selection source index omits required material")


def _validate_no_score_source_index(
    evidence: PoolNoScoreEvidence,
    payloads: Mapping[str, bytes],
) -> None:
    refs = {item.sha256: item for item in evidence.source_objects}
    evidence_sha256 = hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
    if set(payloads) != set(refs) | {evidence_sha256} or evidence_sha256 in refs:
        raise RevealBindingError("pool no-score source graph is not exact")
    for digest, reference in refs.items():
        _resolve(payloads, reference, label=f"pool source {digest}")
    required = {
        evidence.announcement_validator_snapshot.sha256,
        evidence.announcement_validator_proof_evidence.sha256,
        evidence.closing_snapshot.sha256,
        evidence.closing_proof_evidence.sha256,
        evidence.selection_pulse.sha256,
        evidence.policy_object.sha256,
        evidence.prior_protocol_state.sha256,
    }
    if evidence.artifact_retrieval_evidence is not None:
        required.add(evidence.artifact_retrieval_evidence.sha256)
    if evidence.empty_source_evidence is not None:
        required.add(evidence.empty_source_evidence.sha256)
    required.update(item.final_pool_manifest.sha256 for item in evidence.candidates)
    required.update(item.public_manifest.sha256 for item in evidence.candidates)
    required.update(item.ground_truth_envelope.sha256 for item in evidence.candidates)
    if not required.issubset(refs):
        raise RevealBindingError("pool no-score source index omits required material")


def _validate_pool_empty_source(
    *,
    no_score: PoolNoScoreEvidence,
    payloads: Mapping[str, bytes],
    policy: ScoringPolicy,
    window: WindowPlan,
) -> None:
    reference = no_score.empty_source_evidence
    if reference is None:
        raise RevealBindingError("empty-source validation lacks its evidence reference")
    evidence = _parse_canonical(
        _resolve(payloads, reference, label="empty pool source evidence"),
        PoolEmptySourceEvidence,
        "empty pool source evidence",
    )
    closing_bytes = _resolve(payloads, no_score.closing_snapshot, label="closing snapshot")
    proof_bytes = _resolve(
        payloads,
        no_score.closing_proof_evidence,
        label="closing proof evidence",
    )
    closing = _parse_canonical(closing_bytes, ClosingSnapshot, "closing snapshot")
    if (
        evidence.schema_ != POOL_EMPTY_SOURCE_SCHEMA
        or evidence.window_id != window.window_id
        or evidence.window_index != window.window_index
        or evidence.scoring_policy_hash != scoring_policy_hash(policy)
        or evidence.closing_block != window.closing_block
        or evidence.closing_block_hash != closing.closing_block_hash
        or evidence.closing_snapshot_sha256 != hashlib.sha256(closing_bytes).hexdigest()
        or evidence.closing_proof_evidence_sha256 != hashlib.sha256(proof_bytes).hexdigest()
        or not closing.complete_publisher_registry
        or evidence.publisher_registry_count != len(closing.publishers)
        or len(closing.publishers) != len(policy.publisher_registry)
    ):
        raise RevealBindingError("empty-source evidence changes its closing snapshot binding")
    if any(
        row.pool_manifest_sha256 is not None
        and row.anchor_inclusion_block is not None
        and row.anchor_inclusion_block <= window.closing_block
        for row in closing.publishers
    ):
        raise RevealBindingError("empty-source evidence conflicts with a timely pool anchor")


def _load_pool_candidates(
    *,
    selection: PoolSelectionEvidence,
    payloads: Mapping[str, bytes],
    policy: ScoringPolicy,
    prior_state: ProtocolStateSnapshot,
    plan: TranscriptExecutionPlan,
    selection_round: int,
) -> tuple[tuple[_CandidateMaterial, ...], DrandPulse]:
    policy_hash = scoring_policy_hash(policy)
    if (
        selection.window_id != plan.spec.window_id
        or selection.scoring_policy_hash != policy_hash
        or selection.validator_hotkey != plan.spec.validator_hotkey
        or selection.assignment_ids != [item.assignment_id for item in plan.assignments]
    ):
        raise RevealBindingError("pool selection evidence disagrees with window material")
    if (
        selection.protocol_state_digest != prior_state.state_digest.hex()
        or selection.prior_spent_root != prior_state.spent_registry.root.hex()
        or selection.prior_publisher_fault_root != prior_state.publisher_faults.root.hex()
    ):
        raise RevealBindingError("protocol state changed after pool selection")
    policy_bytes = _resolve(payloads, selection.policy_object, label="pool policy")
    if policy_bytes != canonical_json_bytes(policy):
        raise RevealBindingError("pool policy object differs from the active policy")
    _validate_source_index(selection, payloads)

    selection_pulse_bytes = _resolve(
        payloads,
        selection.selection_pulse,
        label="selection pulse",
    )
    selection_pulse = _parse_pulse(
        selection_pulse_bytes,
        expected_round=selection_round,
    )
    if selection.selection_pulse_evidence_digest != selection_pulse.evidence_digest:
        raise RevealBindingError("selection pulse evidence digest changed")

    publisher_groups = {
        account_id32(item.publisher_hotkey): item.control_group_id
        for item in policy.publisher_registry
    }
    materials: list[_CandidateMaterial] = []
    candidates: list[CandidateBatch] = []
    for item in selection.candidates:
        final_bytes = _resolve(
            payloads,
            item.final_pool_manifest,
            label="final pool manifest",
        )
        try:
            final = parse_pool_manifest_bytes(final_bytes, policy=policy)
        except (TypeError, ValueError) as error:
            raise RevealBindingError("final pool manifest no longer verifies") from error
        if account_id32(final.publisher_hotkey) != account_id32(item.publisher_hotkey):
            raise RevealBindingError("candidate publisher differs from its final pool manifest")
        entries = [entry for entry in final.batches if entry.batch_id == item.batch_id]
        if len(entries) != 1:
            raise RevealBindingError("candidate pool entry cardinality is not one")
        entry = entries[0]
        public_bytes = _resolve(payloads, item.public_manifest, label="public batch manifest")
        public = _parse_canonical(
            public_bytes,
            PublicBatchManifest,
            "public batch manifest",
        )
        try:
            validate_public_batch_manifest(public, policy)
        except (TypeError, ValueError) as error:
            raise RevealBindingError("public batch manifest no longer verifies") from error
        envelope_bytes = _resolve(
            payloads,
            item.ground_truth_envelope,
            label="ground-truth envelope",
        )
        if len(envelope_bytes) > policy.limits.maximum_ground_truth_envelope_bytes:
            raise RevealLimitError("ground-truth envelope exceeds the active policy ceiling")
        try:
            sealed = parse_sealed_response(
                base64url_encode(envelope_bytes),
                reveal_round=public.reveal_round,
                sha256_hex=public.ciphertext_sha256,
            )
        except (TypeError, ValueError) as error:
            raise RevealBindingError("ground-truth envelope no longer strictly parses") from error
        group = publisher_groups.get(account_id32(final.publisher_hotkey))
        if group is None:
            raise RevealBindingError("candidate publisher is absent from active policy")
        candidate = CandidateBatch(
            publisher_hotkey=final.publisher_hotkey,
            control_group_id=group,
            batch_id=entry.batch_id,
            batch_commitment=entry.batch_commitment,
        )
        if (
            public.window_id != selection.window_id
            or public.publisher_hotkey != final.publisher_hotkey
            or public.batch_id != entry.batch_id
            or public.scoring_policy_hash != selection.scoring_policy_hash
            or public.response_close_round != plan.spec.response_close_round
            or public.reveal_round != plan.spec.reveal_round
            or entry.public_manifest_sha256 != hashlib.sha256(public_bytes).hexdigest()
            or entry.ciphertext_sha256 != hashlib.sha256(envelope_bytes).hexdigest()
            or entry.reveal_round != public.reveal_round
            or item.control_group_id != group
            or item.batch_commitment != entry.batch_commitment
            or item.pool_leaf != candidate.pool_leaf.hex()
        ):
            raise RevealBindingError("candidate source material changes a committed binding")
        candidates.append(candidate)
        materials.append(
            _CandidateMaterial(
                evidence=item,
                pool_entry=entry,
                public_manifest=public,
                sealed_ground_truth=sealed,
            )
        )
    if len(candidates) > MAX_REVEAL_CANDIDATES:
        raise RevealLimitError("candidate count exceeds the reveal ceiling")
    pool_root = candidate_pool_root(tuple(candidates))
    seed = selection_seed(selection_pulse.signature_bytes, pool_root)
    if selection.candidate_pool_root != pool_root.hex() or selection.selection_seed != seed.hex():
        raise RevealBindingError("selection root or seed no longer reproduces")
    selected = select_batches(
        tuple(candidates),
        seed,
        count=policy.limits.batches_selected_per_window,
    )
    ordinal_by_leaf = {value.pool_leaf: index for index, value in enumerate(selected)}
    for material, candidate in zip(materials, candidates, strict=True):
        evidence = material.evidence
        if evidence.batch_rank != batch_rank(
            seed, candidate
        ).hex() or evidence.selection_ordinal != ordinal_by_leaf.get(candidate.pool_leaf):
            raise RevealBindingError("candidate rank or selection ordinal changed")

    closing_bytes = _resolve(payloads, selection.closing_snapshot, label="closing snapshot")
    closing = _parse_canonical(closing_bytes, ClosingSnapshot, "closing snapshot")
    if (
        closing.window_id != selection.window_id
        or closing.window_index != selection.window_index
        or closing.scoring_policy_hash != selection.scoring_policy_hash
    ):
        raise RevealBindingError("closing snapshot binds another pool selection")
    publisher_accounts = {account_id32(item.publisher_hotkey) for item in policy.publisher_registry}
    miner_candidates: list[MinerCandidate] = []
    neuron_by_hotkey: dict[bytes, Any] = {}
    seen_roots: set[bytes] = set()
    for neuron in closing.neurons:
        hotkey = account_id32(neuron.hotkey)
        if neuron.validator_permit or hotkey in publisher_accounts or neuron.serving_url is None:
            continue
        root = account_id32(neuron.root)
        if root in seen_roots:
            raise RevealBindingError("closing miner snapshot contains duplicate roots")
        seen_roots.add(root)
        miner_candidates.append(
            MinerCandidate(
                hotkey=neuron.hotkey,
                root=neuron.root,
                assigned_observation_count=prior_state.assigned_observation_count(root),
            )
        )
        neuron_by_hotkey[hotkey] = neuron
    panel = select_miner_panel(
        tuple(miner_candidates),
        seed,
        validator_hotkey=selection.validator_hotkey,
        panel_size=policy.limits.miner_panel_size,
    )
    if len(panel) != len(selection.selected_panel):
        raise RevealBindingError("selected miner panel size no longer reproduces")
    for index, (miner, evidence) in enumerate(zip(panel, selection.selected_panel, strict=True)):
        neuron = neuron_by_hotkey[account_id32(miner.hotkey)]
        if (
            evidence.panel_ordinal != index
            or account_id32(evidence.hotkey) != account_id32(miner.hotkey)
            or account_id32(evidence.root) != account_id32(miner.root)
            or evidence.uid != neuron.uid
            or evidence.serving_url != neuron.serving_url
            or evidence.assigned_observation_count != miner.assigned_observation_count
            or evidence.miner_rank
            != miner_rank(seed, selection.validator_hotkey, miner.hotkey).hex()
        ):
            raise RevealBindingError("selected miner panel no longer reproduces")

    selected_batch_ids = {item.batch_id for item in selected}
    public_by_batch = {
        material.public_manifest.batch_id: material.public_manifest for material in materials
    }
    panel_accounts = {account_id32(item.hotkey): item for item in selection.selected_panel}
    expected = {
        (batch_id, public_item.challenge_id, miner)
        for batch_id in selected_batch_ids
        for public_item in public_by_batch[batch_id].items
        for miner in panel_accounts
    }
    actual: set[tuple[str, str, bytes]] = set()
    for assignment in plan.assignments:
        request = assignment.initial_attempt.request
        key = (
            request.batch_id,
            request.challenge_id,
            account_id32(assignment.initial_attempt.miner_hotkey),
        )
        if key not in expected or key in actual:
            raise RevealBindingError("window material is not the selected Cartesian assignment set")
        actual.add(key)
        public_item = next(
            item
            for item in public_by_batch[request.batch_id].items
            if item.challenge_id == request.challenge_id
        )
        miner = panel_accounts[key[2]]
        if (
            assignment.miner_url != miner.serving_url
            or request.window_id != selection.window_id
            or request.scoring_policy_hash != selection.scoring_policy_hash
            or request.batch_id not in selected_batch_ids
            or request.video.sha256 != public_item.media.sha256
            or request.video.size_bytes != public_item.media.size_bytes
            or request.video.media_type != public_item.media.media_type
            or request.task.stratum != public_item.stratum
        ):
            raise RevealBindingError("window material changes selected request bindings")
    if actual != expected:
        raise RevealBindingError("window material omits selected assignments")
    return tuple(materials), selection_pulse


def _load_pool_no_score_candidates(
    *,
    no_score: PoolNoScoreEvidence,
    payloads: Mapping[str, bytes],
    policy: ScoringPolicy,
    prior_state: ProtocolStateSnapshot,
    window: WindowPlan,
) -> tuple[tuple[_CandidateMaterial, ...], DrandPulse]:
    policy_hash = scoring_policy_hash(policy)
    if (
        no_score.window_id != window.window_id
        or no_score.window_index != window.window_index
        or no_score.scoring_policy_hash != policy_hash
        or no_score.window.to_plan() != window
        or no_score.operation_id
        != stage_operation_id(window.window_id, WindowStage.POOL_AND_SELECTION)
        or no_score.protocol_state_digest != prior_state.state_digest.hex()
        or no_score.prior_spent_root != prior_state.spent_registry.root.hex()
        or no_score.prior_publisher_fault_root != prior_state.publisher_faults.root.hex()
    ):
        raise RevealBindingError("pool no-score evidence changes its window or state")
    policy_bytes = _resolve(payloads, no_score.policy_object, label="pool policy")
    if policy_bytes != canonical_json_bytes(policy):
        raise RevealBindingError("pool no-score policy differs from the active policy")
    prior_bytes = _resolve(
        payloads,
        no_score.prior_protocol_state,
        label="pool prior protocol state",
    )
    if prior_bytes != encode_protocol_state_snapshot(prior_state):
        raise RevealBindingError("pool no-score prior state differs from active state")
    _validate_no_score_source_index(no_score, payloads)

    if no_score.empty_source_evidence is not None:
        _validate_pool_empty_source(
            no_score=no_score,
            payloads=payloads,
            policy=policy,
            window=window,
        )

    pulse_bytes = _resolve(payloads, no_score.selection_pulse, label="selection pulse")
    pulse = _parse_pulse(pulse_bytes, expected_round=window.selection_round)
    if no_score.selection_pulse_evidence_digest != pulse.evidence_digest:
        raise RevealBindingError("pool no-score selection pulse digest changed")

    publisher_groups = {
        account_id32(item.publisher_hotkey): item.control_group_id
        for item in policy.publisher_registry
    }
    materials: list[_CandidateMaterial] = []
    candidates: list[CandidateBatch] = []
    for item in no_score.candidates:
        final_bytes = _resolve(
            payloads,
            item.final_pool_manifest,
            label="final pool manifest",
        )
        try:
            final = parse_pool_manifest_bytes(final_bytes, policy=policy)
        except (TypeError, ValueError) as error:
            raise RevealBindingError("final pool manifest no longer verifies") from error
        if account_id32(final.publisher_hotkey) != account_id32(item.publisher_hotkey):
            raise RevealBindingError("no-score publisher differs from its pool manifest")
        entries = [entry for entry in final.batches if entry.batch_id == item.batch_id]
        if len(entries) != 1:
            raise RevealBindingError("no-score pool entry cardinality is not one")
        entry = entries[0]
        public_bytes = _resolve(payloads, item.public_manifest, label="public batch manifest")
        public = _parse_canonical(
            public_bytes,
            PublicBatchManifest,
            "public batch manifest",
        )
        try:
            validate_public_batch_manifest(public, policy)
        except (TypeError, ValueError) as error:
            raise RevealBindingError("public batch manifest no longer verifies") from error
        envelope_bytes = _resolve(
            payloads,
            item.ground_truth_envelope,
            label="ground-truth envelope",
        )
        if len(envelope_bytes) > policy.limits.maximum_ground_truth_envelope_bytes:
            raise RevealLimitError("ground-truth envelope exceeds the active policy ceiling")
        try:
            sealed = parse_sealed_response(
                base64url_encode(envelope_bytes),
                reveal_round=public.reveal_round,
                sha256_hex=public.ciphertext_sha256,
            )
        except (TypeError, ValueError) as error:
            raise RevealBindingError("ground-truth envelope no longer strictly parses") from error
        group = publisher_groups.get(account_id32(final.publisher_hotkey))
        if group is None:
            raise RevealBindingError("no-score publisher is absent from active policy")
        candidate = CandidateBatch(
            publisher_hotkey=final.publisher_hotkey,
            control_group_id=group,
            batch_id=entry.batch_id,
            batch_commitment=entry.batch_commitment,
        )
        if (
            public.window_id != no_score.window_id
            or public.publisher_hotkey != final.publisher_hotkey
            or public.batch_id != entry.batch_id
            or public.scoring_policy_hash != no_score.scoring_policy_hash
            or public.response_close_round != window.response_close_round
            or public.reveal_round != window.reveal_round
            or entry.public_manifest_sha256 != hashlib.sha256(public_bytes).hexdigest()
            or entry.ciphertext_sha256 != hashlib.sha256(envelope_bytes).hexdigest()
            or entry.reveal_round != public.reveal_round
            or item.control_group_id != group
            or item.batch_commitment != entry.batch_commitment
            or item.pool_leaf != candidate.pool_leaf.hex()
        ):
            raise RevealBindingError("pool no-score candidate binding changed")
        candidates.append(candidate)
        materials.append(
            _CandidateMaterial(
                evidence=item,
                pool_entry=entry,
                public_manifest=public,
                sealed_ground_truth=sealed,
            )
        )
    if len(candidates) > MAX_REVEAL_CANDIDATES:
        raise RevealLimitError("candidate count exceeds the reveal ceiling")

    if no_score.reason_code == "candidate_pool_empty":
        if (
            candidates
            or no_score.candidate_pool_root is not None
            or no_score.selection_seed is not None
        ):
            raise RevealBindingError("empty candidate pool no longer reproduces")
        return (), pulse

    pool_root = candidate_pool_root(tuple(candidates))
    seed = selection_seed(pulse.signature_bytes, pool_root)
    if no_score.candidate_pool_root != pool_root.hex() or no_score.selection_seed != seed.hex():
        raise RevealBindingError("pool no-score root or seed no longer reproduces")
    if no_score.reason_code == "candidate_control_group_count_insufficient":
        try:
            select_batches(
                tuple(candidates),
                seed,
                count=policy.limits.batches_selected_per_window,
            )
        except ValueError:
            selected: tuple[CandidateBatch, ...] = ()
        else:
            raise RevealBindingError("pool no-score group insufficiency no longer reproduces")
    else:
        selected = select_batches(
            tuple(candidates),
            seed,
            count=policy.limits.batches_selected_per_window,
        )
        closing_bytes = _resolve(payloads, no_score.closing_snapshot, label="closing snapshot")
        closing = _parse_canonical(closing_bytes, ClosingSnapshot, "closing snapshot")
        publisher_accounts = {
            account_id32(item.publisher_hotkey) for item in policy.publisher_registry
        }
        miners: list[MinerCandidate] = []
        seen_roots: set[bytes] = set()
        for neuron in closing.neurons:
            account = account_id32(neuron.hotkey)
            if (
                neuron.validator_permit
                or account in publisher_accounts
                or neuron.serving_url is None
            ):
                continue
            root = account_id32(neuron.root)
            if root in seen_roots:
                raise RevealBindingError("closing miner snapshot contains duplicate roots")
            seen_roots.add(root)
            miners.append(
                MinerCandidate(
                    hotkey=neuron.hotkey,
                    root=neuron.root,
                    assigned_observation_count=prior_state.assigned_observation_count(root),
                )
            )
        panel = select_miner_panel(
            tuple(miners),
            seed,
            validator_hotkey=no_score.validator_hotkey,
            panel_size=policy.limits.miner_panel_size,
        )
        if panel:
            raise RevealBindingError("pool no-score empty miner panel no longer reproduces")

    ordinal_by_leaf = {value.pool_leaf: index for index, value in enumerate(selected)}
    for material, candidate in zip(materials, candidates, strict=True):
        evidence = material.evidence
        if evidence.batch_rank != batch_rank(
            seed, candidate
        ).hex() or evidence.selection_ordinal != ordinal_by_leaf.get(candidate.pool_leaf):
            raise RevealBindingError("pool no-score candidate rank or selection changed")
    return tuple(materials), pulse


def _load_response_material(
    *,
    record: StageJournalRecord,
    payloads: Mapping[str, bytes],
    stored: StoredWindowMaterial | None,
    expected_binding: TranscriptMaterialBinding | None = None,
    policy_hash: str,
) -> tuple[tuple[_ResponseMaterial, ...], str, TranscriptExecutionPlan]:
    try:
        replay = replay_transcript_stage_receipt(
            _transcript_receipt_for_replay(record.receipt),
            payloads,
        )
    except TranscriptReplayError as error:
        raise RevealBindingError(f"sealed response receipt replay failed: {error}") from error
    if stored is not None:
        stored_binding = TranscriptMaterialBinding(
            material_sha256=stored.receipt.material_sha256,
            material_receipt_sha256=stored.receipt_sha256,
            pool_stage_evidence_sha256=stored.pool_stage_evidence_sha256 or "",
        )
        if expected_binding is not None and expected_binding != stored_binding:
            raise RevealBindingError("response replay expected binding conflicts with store")
        expected_binding = stored_binding
    if expected_binding is None:
        raise RevealBindingError("response replay lacks an immutable material binding")
    if (
        replay.stage is not WindowStage.SEALED_RESPONSE
        or replay.material_binding != expected_binding
        or replay.scoring_policy_hash != policy_hash
    ):
        raise RevealBindingError("sealed response replay has different immutable bindings")
    manifest, _manifest_bytes = _find_one_schema(
        payloads,
        TRANSCRIPT_STAGE_MANIFEST_SCHEMA,
        _ResponseStageManifest,
        label="sealed-response transcript manifest",
    )
    if replay.window_id != manifest.window_id:
        raise RevealBindingError("sealed response replay binds another manifest window")
    spec_bytes = _resolve(payloads, manifest.transcript_spec, label="transcript window spec")
    spec = _parse_canonical(spec_bytes, TranscriptWindowSpec, "transcript window spec")
    plan_by_id = (
        {} if stored is None else {item.assignment_id: item for item in stored.plan.assignments}
    )
    if stored is not None and set(plan_by_id) != {
        item.assignment_id for item in manifest.assignments
    }:
        raise RevealBindingError("response receipt is not a bijection with window material")

    results: list[_ResponseMaterial] = []
    initial_assignments: list[TranscriptAssignment] = []
    for assignment in manifest.assignments:
        initial_plan = plan_by_id.get(assignment.assignment_id)
        prepared_values: list[PreparedRequestAttempt] = []
        outcomes: list[tuple[_ManifestAttempt, AttemptOutcomeEvidence, bytes | None]] = []
        for attempt in assignment.attempts:
            prepared_bytes = _resolve(
                payloads,
                attempt.prepared_evidence,
                label="prepared-attempt evidence",
            )
            prepared_evidence = _parse_canonical(
                prepared_bytes,
                PreparedAttemptEvidence,
                "prepared-attempt evidence",
            )
            request_bytes = _resolve(
                payloads,
                prepared_evidence.request_object,
                label="translation request",
            )
            request = _parse_canonical(request_bytes, TranslationRequest, "translation request")
            try:
                auth = VerifiedAuthEvidence.from_headers(
                    {item.name: item.value for item in prepared_evidence.auth_headers},
                    request=request,
                    expected_validator_hotkey=prepared_evidence.validator_hotkey,
                    expected_miner_hotkey=prepared_evidence.miner_hotkey,
                )
                prepared = PreparedRequestAttempt(
                    request=request,
                    request_bytes=request_bytes,
                    validator_hotkey=prepared_evidence.validator_hotkey,
                    miner_hotkey=prepared_evidence.miner_hotkey,
                    auth_headers=tuple(
                        (item.name, item.value) for item in prepared_evidence.auth_headers
                    ),
                    auth_evidence=auth,
                )
            except (TypeError, ValueError) as error:
                raise RevealBindingError("prepared response request does not replay") from error
            if (
                prepared_evidence.assignment_id != assignment.assignment_id
                or prepared_evidence.attempt_index != attempt.attempt_index
                or prepared_evidence.auth_record != auth.auth_record
                or deterministic_assignment_id(prepared) != assignment.assignment_id
            ):
                raise RevealBindingError("prepared response request changes its assignment")
            if (
                attempt.attempt_index == 0
                and initial_plan is not None
                and prepared != initial_plan.initial_attempt
            ):
                raise RevealBindingError(
                    "response receipt changes the pool-selected initial request"
                )
            prepared_values.append(prepared)

            outcome_bytes = _resolve(
                payloads,
                attempt.outcome_evidence,
                label="attempt-outcome evidence",
            )
            outcome = _parse_canonical(
                outcome_bytes,
                AttemptOutcomeEvidence,
                "attempt-outcome evidence",
            )
            body = (
                None
                if outcome.retained_body is None
                else _resolve(payloads, outcome.retained_body, label="retained response body")
            )
            if (
                outcome.assignment_id != assignment.assignment_id
                or outcome.attempt_index != attempt.attempt_index
                or outcome.sealed_response_record.disposition != attempt.disposition
            ):
                raise RevealBindingError("attempt outcome changes its manifest binding")
            outcomes.append((attempt, outcome, body))
        request_anchor = RequestAnchorRecord(tuple(item.auth_evidence for item in prepared_values))
        initial_assignments.append(
            TranscriptAssignment(
                initial_attempt=prepared_values[0],
                miner_url=assignment.miner_url,
            )
        )
        selected = next((item for item in outcomes if item[0].final), outcomes[-1])
        selected_attempt, selected_outcome, selected_body = selected
        prepared_for_response = prepared_values[selected_attempt.attempt_index]
        results.append(
            _ResponseMaterial(
                assignment_id=assignment.assignment_id,
                prepared=prepared_for_response,
                request_leaf=request_anchor.leaf,
                disposition=selected_outcome.sealed_response_record.disposition,
                sealed_record=selected_outcome.sealed_response_record,
                envelope_bytes=selected_body,
            )
        )
    try:
        replayed_plan = TranscriptExecutionPlan(
            spec=spec,
            assignments=tuple(initial_assignments),
        )
    except (TypeError, ValueError) as error:
        raise RevealBindingError("response receipt execution plan does not reproduce") from error
    if stored is not None and replayed_plan != stored.plan:
        raise RevealBindingError("response receipt changes immutable window material")
    return tuple(results), replay.root, replayed_plan


def _transcript_receipt_for_replay(receipt: StageReceipt) -> StageReceipt:
    """Expose effect metadata from an authoritative adapter receipt.

    Transcript replay predates the generic adapter envelope and therefore expects
    the effect-owned metadata at the receipt root.  The envelope is retained in
    the authoritative receipt; this isolated model copy only supplies the exact
    nested object to the pure transcript replay function.
    """

    metadata = receipt.metadata
    if metadata.get("schema") != _ADAPTER_RESULT_SCHEMA:
        return receipt
    if metadata.get("kind") != "completion" or metadata.get("terminal") is not None:
        raise RevealBindingError("sealed-response adapter receipt is not a completion")
    effect_metadata = metadata.get("metadata")
    if not isinstance(effect_metadata, Mapping):
        raise RevealBindingError("sealed-response adapter metadata is malformed")
    return receipt.model_copy(update={"metadata": dict(effect_metadata)})


async def _open_timelock(
    *,
    sealed: SealedResponse,
    pulse: DrandPulse,
    decrypt: RevealDecryptPort,
    kind: Literal["ground_truth", "miner_response"],
    identity: Mapping[str, JsonValue],
) -> tuple[
    bytes | None,
    TimelockDecryptionError | None,
    tuple[StageObjectInput, ...],
    dict[str, Any],
]:
    if pulse.round != sealed.reveal_round:
        raise RevealBindingError("decrypt request and verified reveal pulse rounds disagree")
    plaintext: bytes | None = None
    failure: TimelockDecryptionError | None = None
    try:
        value = await _await_value(decrypt(sealed, pulse))
        if not isinstance(value, bytes):
            raise RevealBindingError("reveal decryptor returned non-bytes plaintext")
        if len(value) > MAX_REVEAL_PLAINTEXT_BYTES:
            raise RevealLimitError("revealed plaintext exceeds its byte ceiling")
        plaintext = value
    except TimelockDecryptionError as error:
        failure = error
    plaintext_ref = (
        None if plaintext is None else _object_ref(plaintext, "application/octet-stream")
    )
    record = {
        "schema": REVEAL_DECRYPTION_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "kind": kind,
        "identity": dict(identity),
        "ciphertext_sha256": sealed.sha256_hex,
        "reveal_round": sealed.reveal_round,
        "reveal_pulse_evidence_digest": pulse.evidence_digest,
        "outcome": "timelock_decryption_failed" if failure is not None else "decrypted",
        "plaintext": (
            None if plaintext_ref is None else plaintext_ref.model_dump(mode="json", by_alias=True)
        ),
        "error_type": None if failure is None else type(failure).__name__,
        "error_message_sha256": (
            None if failure is None else hashlib.sha256(b"timelock_decryption_failed").hexdigest()
        ),
    }
    record_bytes = canonical_json_bytes(record)
    objects = [StageObjectInput(record_bytes, "application/json")]
    if plaintext is not None:
        objects.append(StageObjectInput(plaintext, "application/octet-stream"))
    return plaintext, failure, tuple(objects), record


def _try_ground_truth(data: bytes) -> GroundTruthPayload | None:
    try:
        value = GroundTruthPayload.model_validate_json(data)
    except (ValidationError, ValueError):
        return None
    return value if canonical_json_bytes(value) == data else None


def _response_hypothesis(
    plaintext: ResponsePlaintext,
    *,
    request: TranslationRequest,
    policy: ScoringPolicy,
) -> tuple[str | None, str | None]:
    if plaintext.status == "error":
        if plaintext.error_code not in policy.implementation_pins.rules.miner_error_codes:
            return None, "miner_error_code_unpinned"
        if plaintext.received_video_sha256 not in {None, request.video.sha256}:
            return None, "received_video_digest_mismatch"
        return None, plaintext.error_code
    hypothesis = plaintext.hypothesis
    if hypothesis is None:
        return None, "plaintext_invalid"
    if plaintext.received_video_sha256 != request.video.sha256:
        return None, "received_video_digest_mismatch"
    try:
        size = len(hypothesis.encode("utf-8"))
    except UnicodeEncodeError:
        return None, "hypothesis_utf8_invalid"
    if size > policy.limits.maximum_hypothesis_utf8_bytes:
        return None, "hypothesis_utf8_limit"
    if normalized_token_count(hypothesis) > policy.limits.maximum_hypothesis_tokens:
        return None, "hypothesis_token_limit"
    if normalized_grapheme_count(hypothesis) > policy.limits.maximum_hypothesis_graphemes:
        return None, "hypothesis_grapheme_limit"
    return hypothesis, None


async def _compute_reveal(
    *,
    policy: ScoringPolicy,
    selection: PoolSelectionEvidence | PoolNoScoreEvidence,
    candidates: tuple[_CandidateMaterial, ...],
    responses: tuple[_ResponseMaterial, ...],
    prior_state: ProtocolStateSnapshot,
    reveal_pulse: DrandPulse,
    decrypt: RevealDecryptPort,
    pool_stage_digest: str,
    response_stage_digest: str,
    response_set_root: str | None,
    transcript_abort: _TranscriptAbortChain | None = None,
    pool_no_score: _PoolNoScoreChain | None = None,
    issued_miner_roots: tuple[bytes, ...] | None = None,
) -> RevealComputation:
    if transcript_abort is not None and pool_no_score is not None:
        raise RevealBindingError("reveal cannot carry two no-score origins")
    if len(responses) > MAX_REVEAL_ASSIGNMENTS:
        raise RevealLimitError("response assignment count exceeds the reveal ceiling")
    selected_candidates = tuple(
        sorted(
            (item for item in candidates if item.evidence.selection_ordinal is not None),
            key=lambda item: item.evidence.selection_ordinal or 0,
        )
    )
    expected_selected = (
        0
        if pool_no_score is not None
        and pool_no_score.origin.reason_code
        in {"candidate_pool_empty", "candidate_control_group_count_insufficient"}
        else policy.limits.batches_selected_per_window
    )
    if len(selected_candidates) != expected_selected:
        raise RevealBindingError("reveal source does not contain the expected batch count")

    objects: list[StageObjectInput] = []
    candidate_records: list[dict[str, Any]] = []
    ground_truth_by_batch: dict[str, GroundTruthPayload] = {}
    spent_batches: list[SpentCohortBatch] = []
    findings: list[PublisherFaultFinding] = []
    invalid_selected: set[str] = set()
    for candidate in candidates:
        plaintext, failure, decrypt_objects, decryption_record = await _open_timelock(
            sealed=candidate.sealed_ground_truth,
            pulse=reveal_pulse,
            decrypt=decrypt,
            kind="ground_truth",
            identity={"batch_id": candidate.evidence.batch_id},
        )
        objects.extend(decrypt_objects)
        outcome = (
            PublisherRevealOutcome.TIMELOCK_DECRYPTION_FAILED
            if failure is not None
            else PublisherRevealOutcome.DECRYPTED
        )
        reveal_evidence = PublisherRevealEvidence(
            control_group_id=candidate.evidence.control_group_id,
            pool_entry=candidate.pool_entry,
            public_manifest=candidate.public_manifest,
            sealed_ground_truth=candidate.sealed_ground_truth,
            reveal_pulse=reveal_pulse,
            anchored_eligibility_evidence_sha256=pool_stage_digest,
            outcome=outcome,
            decrypted_bytes=plaintext,
            decryption_error=failure,
            prior_spent_leaves=prior_state.spent_registry.leaves,
        )
        candidate_findings = classify_publisher_reveal(reveal_evidence, policy=policy)
        findings.extend(candidate_findings)
        ground_truth = None if plaintext is None else _try_ground_truth(plaintext)
        shape_valid = False
        shape_failure: str | None = None
        if ground_truth is not None:
            try:
                validate_revealed_batch_shape(candidate.public_manifest, ground_truth, policy)
            except (TypeError, ValueError) as error:
                shape_failure = type(error).__name__
            else:
                shape_valid = True
                ground_truth_by_batch[candidate.evidence.batch_id] = ground_truth
        elif plaintext is not None:
            shape_failure = "ground_truth_schema_invalid"
        scripts = (
            ()
            if ground_truth is None
            else tuple(
                script for item in ground_truth.items for script in item.retirement_script_sha256s
            )
        )
        spent_batches.append(
            SpentCohortBatch(
                batch_commitment=candidate.evidence.batch_commitment,
                video_hashes=tuple(item.media.sha256 for item in candidate.public_manifest.items),
                frame_digests=tuple(
                    item.media.frame_digest for item in candidate.public_manifest.items
                ),
                revealed_script_hashes=scripts,
            )
        )
        if candidate.evidence.selection_ordinal is not None and not shape_valid:
            invalid_selected.add(candidate.evidence.batch_id)
        plaintext_ref = (
            None if plaintext is None else _object_ref(plaintext, "application/octet-stream")
        )
        candidate_records.append(
            {
                "batch_id": candidate.evidence.batch_id,
                "publisher_hotkey": candidate.evidence.publisher_hotkey,
                "control_group_id": candidate.evidence.control_group_id,
                "batch_commitment": candidate.evidence.batch_commitment,
                "pool_leaf": candidate.evidence.pool_leaf,
                "batch_rank": candidate.evidence.batch_rank,
                "selection_ordinal": candidate.evidence.selection_ordinal,
                "decryption": decryption_record,
                "plaintext": (
                    None
                    if plaintext_ref is None
                    else plaintext_ref.model_dump(mode="json", by_alias=True)
                ),
                "ground_truth_shape_valid": shape_valid,
                "shape_failure": shape_failure,
                "retirement_script_sha256s": sorted(set(scripts)),
                "objective_faults": [
                    {"reason": item.reason.value, "reason_code": item.reason_code}
                    for item in candidate_findings
                ],
            }
        )

    spent_tuple = tuple(
        sorted(spent_batches, key=lambda value: raw_sha256(value.batch_commitment, field="batch"))
    )
    try:
        _next_spent, spent_transition = prior_state.spent_registry.apply(
            reveal_pulse.round,
            spent_tuple,
        )
    except (TypeError, ValueError) as error:
        raise RevealBindingError(
            "spent transition does not reproduce from pool evidence"
        ) from error
    if spent_transition.duplicate_video_hashes or spent_transition.duplicate_frame_digests:
        raise RevealBindingError("revealed cohort changed prequalified public uniqueness")

    void_reasons: set[str] = set()
    if invalid_selected and transcript_abort is None and pool_no_score is None:
        void_reasons.add("selected_ground_truth_invalid")
    selected_script_hashes: list[str] = []
    for candidate in selected_candidates:
        ground_truth = ground_truth_by_batch.get(candidate.evidence.batch_id)
        if ground_truth is not None:
            selected_script_hashes.extend(
                script for item in ground_truth.items for script in item.retirement_script_sha256s
            )
    if (
        transcript_abort is None
        and pool_no_score is None
        and len(selected_script_hashes) != len(set(selected_script_hashes))
    ):
        void_reasons.add("selected_script_duplicate")
    if (
        transcript_abort is None
        and pool_no_score is None
        and any(
            spent_script_leaf(script) in prior_state.spent_registry.leaves
            for script in selected_script_hashes
        )
    ):
        void_reasons.add("selected_script_duplicate")
    if transcript_abort is not None:
        void_reasons.add("transcript_abort")
    if pool_no_score is not None:
        void_reasons.add("pool_no_score")

    panel_root_by_hotkey = (
        {account_id32(item.hotkey): account_id32(item.root) for item in selection.selected_panel}
        if isinstance(selection, PoolSelectionEvidence)
        else {}
    )
    public_by_batch = {item.public_manifest.batch_id: item.public_manifest for item in candidates}
    response_records: list[dict[str, Any]] = []
    scores_by_batch: dict[str, list[AssignmentScore]] = {
        item.evidence.batch_id: [] for item in selected_candidates
    }
    signer_by_request: dict[bytes, bytes] = {}
    canary_hit = False
    for response in responses:
        request = response.prepared.request
        root = panel_root_by_hotkey.get(account_id32(response.prepared.miner_hotkey))
        if root is None:
            raise RevealBindingError("response assignment miner is absent from selected panel")
        public = public_by_batch.get(request.batch_id)
        if public is None:
            raise RevealBindingError("response assignment references an unselected batch")
        public_item = next(
            (item for item in public.items if item.challenge_id == request.challenge_id),
            None,
        )
        if public_item is None:
            raise RevealBindingError("response assignment challenge is absent from public batch")

        hypothesis: str | None = None
        zero_reason: str | None = None
        response_plaintext: bytes | None = None
        response_decryption: dict[str, Any]
        if response.disposition != "sealed":
            zero_reason = response.disposition
            response_decryption = {
                "schema": REVEAL_DECRYPTION_SCHEMA,
                "protocol": PROTOCOL_VERSION,
                "kind": "miner_response",
                "identity": {"assignment_id": response.assignment_id},
                "outcome": "not_sealed",
                "disposition": response.disposition,
            }
            objects.append(
                StageObjectInput(canonical_json_bytes(response_decryption), "application/json")
            )
        else:
            if response.envelope_bytes is None or response.sealed_record.signature is None:
                raise RevealBindingError("sealed response lacks exact envelope/signature evidence")
            try:
                envelope, sealed = validate_response_envelope(
                    response.envelope_bytes,
                    response.sealed_record.signature,
                    request=request,
                    validator_hotkey=response.prepared.validator_hotkey,
                    miner_hotkey=response.prepared.miner_hotkey,
                )
            except (TypeError, ValueError) as error:
                raise RevealBindingError("anchored sealed response no longer verifies") from error
            plaintext, decrypt_failure, decrypt_objects, response_decryption = await _open_timelock(
                sealed=sealed,
                pulse=reveal_pulse,
                decrypt=decrypt,
                kind="miner_response",
                identity={"assignment_id": response.assignment_id},
            )
            objects.extend(decrypt_objects)
            response_plaintext = plaintext
            if decrypt_failure is not None:
                zero_reason = "undecryptable"
            elif plaintext is None:
                raise RuntimeError("successful response decryption lost plaintext")
            else:
                try:
                    parsed_plaintext = validate_response_plaintext(
                        plaintext,
                        envelope=envelope,
                        request=request,
                    )
                except ComponentResponseError as error:
                    zero_reason = error.code
                else:
                    hypothesis, zero_reason = _response_hypothesis(
                        parsed_plaintext,
                        request=request,
                        policy=policy,
                    )

        ground_truth = ground_truth_by_batch.get(request.batch_id)
        ground_item = (
            None
            if ground_truth is None
            else next(
                (item for item in ground_truth.items if item.challenge_id == request.challenge_id),
                None,
            )
        )
        score: Fraction | None = None
        trace_record: dict[str, Any] | None = None
        canary = False
        canary_record: dict[str, Any] | None = None
        if ground_item is not None:
            canary = ground_item.canary
            if canary:
                result = evaluate_canary(
                    ground_item,
                    hypothesis,
                    cer_threshold=policy.thresholds.canary_cer_hit_threshold.fraction,
                    wer_threshold=policy.thresholds.canary_wer_hit_threshold.fraction,
                )
                canary_hit = canary_hit or result.hit
                canary_record = {
                    "metric": result.metric,
                    "score": _fraction(result.score),
                    "threshold": _fraction(result.threshold),
                    "hit": result.hit,
                    "trace": None if result.trace is None else result.trace.to_record(),
                }
            else:
                if hypothesis is None:
                    score = Fraction(0, 1)
                else:
                    trace = (
                        score_cer_with_trace(hypothesis, ground_item.references)
                        if ground_item.metric == "cer"
                        else score_wer_with_trace(hypothesis, ground_item.references)
                    )
                    score = trace.score
                    trace_record = trace.to_record()
            assignment_score = AssignmentScore(
                miner_root=root,
                challenge_id=request.challenge_id,
                request_leaf=response.request_leaf,
                stratum=public_item.stratum,
                canary=canary,
                score=None if canary else score,
            )
            scores_by_batch[request.batch_id].append(assignment_score)
            if not canary:
                signer_by_request[response.request_leaf] = bytes.fromhex(
                    public_item.signer_id_sha256
                )
        response_records.append(
            {
                "assignment_id": response.assignment_id,
                "request_leaf": response.request_leaf.hex(),
                "batch_id": request.batch_id,
                "challenge_id": request.challenge_id,
                "miner_hotkey": response.prepared.miner_hotkey,
                "miner_root": root.hex(),
                "outer_disposition": response.disposition,
                "decryption": response_decryption,
                "plaintext": (
                    None
                    if response_plaintext is None
                    else _object_ref(
                        response_plaintext,
                        "application/octet-stream",
                    ).model_dump(mode="json", by_alias=True)
                ),
                "zero_score_reason": zero_reason,
                "canary": canary if ground_item is not None else None,
                "score": None if score is None else _fraction(score),
                "score_trace": trace_record,
                "canary_result": canary_record,
            }
        )
    if canary_hit and transcript_abort is None and pool_no_score is None:
        void_reasons.add("canary_hit")

    scored_batches: tuple[ScoredBatch, ...] = ()
    monitoring_observations: tuple[SourceObservation, ...] = ()
    if not void_reasons:
        built: list[ScoredBatch] = []
        roots = tuple(sorted(set(panel_root_by_hotkey.values())))
        for candidate in selected_candidates:
            batch_id = candidate.evidence.batch_id
            public = candidate.public_manifest
            built.append(
                ScoredBatch(
                    window_index=selection.window_index,
                    batch_rank=candidate.evidence.batch_rank,
                    pool_leaf=candidate.evidence.pool_leaf,
                    challenge_ids=tuple(item.challenge_id for item in public.items),
                    miner_roots=roots,
                    assignments=tuple(sorted(scores_by_batch[batch_id], key=lambda item: item.key)),
                )
            )
        scored_batches = tuple(sorted(built, key=lambda item: item.order_key))
        sources = tuple(
            sorted(
                (
                    MonitoringBatchSource(
                        pool_leaf=item.evidence.pool_leaf,
                        publisher_hotkey=item.evidence.publisher_hotkey,
                        control_group_id=item.evidence.control_group_id,
                    )
                    for item in selected_candidates
                ),
                key=lambda item: item.pool,
            )
        )
        clusters = tuple(
            sorted(
                (
                    MonitoringSignerCluster(
                        request_leaf=request_leaf,
                        signer_cluster_id=cluster,
                    )
                    for request_leaf, cluster in signer_by_request.items()
                ),
                key=lambda item: item.leaf,
            )
        )
        monitoring_observations = source_observations_from_scored_batches(
            scored_batches,  # type: ignore[arg-type]
            batch_sources=sources,  # type: ignore[arg-type]
            signer_clusters=clusters,
        )

    if issued_miner_roots is None:
        issued_roots = tuple(
            sorted(
                panel_root_by_hotkey[account_id32(item.prepared.miner_hotkey)] for item in responses
            )
        )
    else:
        if issued_miner_roots != tuple(sorted(issued_miner_roots)) or any(
            len(item) != 32 for item in issued_miner_roots
        ):
            raise RevealBindingError("abort issued-miner roots are not canonical")
        issued_roots = issued_miner_roots
    finding_tuple = tuple(
        sorted(
            {item.leaf: item for item in findings}.values(),
            key=lambda item: item.leaf,
        )
    )
    void_tuple = tuple(sorted(void_reasons))
    common_result: dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "window_id": selection.window_id,
        "window_index": selection.window_index,
        "scoring_policy_hash": selection.scoring_policy_hash,
        "reveal_round": reveal_pulse.round,
        "reveal_pulse_evidence_digest": reveal_pulse.evidence_digest,
        "pool_stage_evidence_sha256": pool_stage_digest,
        "response_stage_evidence_sha256": response_stage_digest,
        "prior_protocol_state_digest": prior_state.state_digest.hex(),
        "scoring_environment": scoring_environment(),
        "candidate_reveals": candidate_records,
        "void_reason_codes": list(void_tuple),
        "canary_hit": "canary_hit" in void_reasons,
        "objective_fault_findings": [
            {
                "leaf": item.leaf.hex(),
                "control_group_id": item.control_group_id.hex(),
                "publisher_hotkey": item.publisher_hotkey.hex(),
                "batch_commitment": item.batch_commitment.hex(),
                "reason": item.reason.value,
                "reason_code": item.reason_code,
            }
            for item in finding_tuple
        ],
        "spent_transition_preview": {
            "previous_root": spent_transition.previous_root.hex(),
            "delta_root": spent_transition.delta_root.hex(),
            "resulting_root": spent_transition.resulting_root.hex(),
            "delta_leaves": [item.hex() for item in spent_transition.delta_leaves],
            "prior_collisions": [item.hex() for item in spent_transition.prior_collisions],
        },
        "scored_batches": [_scored_batch_object(item) for item in scored_batches],
        "issued_request_count": len(issued_roots),
        "monitoring_observations": [
            _source_observation_object(item) for item in monitoring_observations
        ],
    }
    if transcript_abort is None and pool_no_score is None:
        if response_set_root is None:
            raise RevealBindingError("normal reveal lacks a response-set root")
        result = {
            "schema": REVEAL_RESULT_SCHEMA,
            **common_result,
            "response_set_root": response_set_root,
            "responses": response_records,
        }
        result_model: type[RevealResult | TranscriptAbortRevealResult | PoolNoScoreRevealResult] = (
            RevealResult
        )
    elif transcript_abort is not None:
        if response_set_root is not None or responses or response_records:
            raise RevealBindingError("abort reveal contains response-set material")
        result = {
            "schema": REVEAL_ABORT_RESULT_SCHEMA,
            **common_result,
            "abort_origin": transcript_abort.origin.model_dump(
                mode="json",
                by_alias=True,
            ),
            "abort_origin_sha256": transcript_abort.origin_sha256,
            "abort_origin_stage_evidence_sha256": (transcript_abort.origin_stage_evidence_sha256),
        }
        result_model = TranscriptAbortRevealResult
    else:
        if pool_no_score is None:
            raise RuntimeError("pool no-score branch lost its origin")
        if response_set_root is not None or responses or response_records or issued_roots:
            raise RevealBindingError("pool no-score reveal contains transcript material")
        result = {
            "schema": POOL_NO_SCORE_REVEAL_RESULT_SCHEMA,
            **common_result,
            "pool_no_score": pool_no_score.origin.model_dump(
                mode="json",
                by_alias=True,
            ),
            "pool_no_score_sha256": pool_no_score.origin_sha256,
        }
        result_model = PoolNoScoreRevealResult
    result_bytes = canonical_json_bytes(result)
    _parse_canonical(result_bytes, result_model, "reveal result")
    objects.append(StageObjectInput(result_bytes, "application/json"))
    return RevealComputation(
        result_bytes=result_bytes,
        spent_batches=spent_tuple,
        fault_findings=finding_tuple,
        scored_batches=scored_batches,
        issued_miner_roots=issued_roots,
        monitoring_observations=monitoring_observations,
        void_reason_codes=void_tuple,
        objects=_unique_stage_objects(objects),
    )


def _unique_stage_objects(values: Sequence[StageObjectInput]) -> tuple[StageObjectInput, ...]:
    unique: dict[str, StageObjectInput] = {}
    for value in values:
        digest = hashlib.sha256(value.data).hexdigest()
        prior = unique.setdefault(digest, value)
        if prior.media_type != value.media_type:
            # Invalid JSON plaintext is intentionally stored as octet-stream.
            # Decryption records remain JSON and cannot collide with arbitrary
            # plaintext under the same digest except by breaking SHA-256.
            raise RevealBindingError("one reveal object digest has conflicting media metadata")
    return tuple(unique[key] for key in sorted(unique, key=bytes.fromhex))


def reveal_transition_operation_id(window_id: str) -> bytes:
    """Return the deterministic raw operation ID shared by both state stores."""

    identifier = raw_sha256(window_id, field="window ID")
    operation = stage_operation_id(window_id, WindowStage.REVEAL_AND_SCORE)
    return sha256_domain(
        b"umi-validator-reveal-transition-operation-v1\0",
        identifier,
        operation.encode("ascii"),
    )


def _stage_inputs(
    journal: ValidatorStageJournal,
    record: StageJournalRecord,
) -> tuple[StageObjectInput, ...]:
    return tuple(
        StageObjectInput(
            data=journal.read_object(reference),
            media_type=reference.media_type,
        )
        for reference in record.receipt.objects
    )


def _json_object(data: bytes, *, label: str) -> dict[str, JsonValue]:
    value = _strict_json(data, label)
    if not isinstance(value, dict) or canonical_json_bytes(value) != data:
        raise RevealBindingError(f"{label} is not a canonical JSON object")
    return value


class ValidatorRevealEffect:
    """Perform the bounded authoritative reveal-and-score stage."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        validator_hotkey: str,
        journal: ValidatorStageJournal,
        material_store: ValidatorWindowMaterialStore,
        protocol_state: ValidatorProtocolStateStore,
        monitoring_state: ValidatorMonitoringStateStore,
        coordinator: RevealTransitionCoordinator,
        ports: RevealEffectPorts,
        port_timeout_seconds: float = 30.0,
        maximum_stage_object_bytes: int = MAX_STAGE_OBJECT_BYTES,
        maximum_stage_total_bytes: int = MAX_JOURNAL_OBJECT_BYTES,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("policy must be ScoringPolicy")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be ValidatorStageJournal")
        if not isinstance(material_store, ValidatorWindowMaterialStore):
            raise TypeError("material_store must be ValidatorWindowMaterialStore")
        if not isinstance(protocol_state, ValidatorProtocolStateStore):
            raise TypeError("protocol_state must be ValidatorProtocolStateStore")
        if not isinstance(monitoring_state, ValidatorMonitoringStateStore):
            raise TypeError("monitoring_state must be ValidatorMonitoringStateStore")
        if not isinstance(coordinator, RevealTransitionCoordinator):
            raise TypeError("coordinator must be RevealTransitionCoordinator")
        if not isinstance(ports, RevealEffectPorts):
            raise TypeError("ports must be RevealEffectPorts")
        account = account_id32(validator_hotkey)
        if account not in {
            account_id32(item.validator_hotkey) for item in policy.validator_registry
        }:
            raise ValueError("reveal validator is absent from the active policy")
        if (
            isinstance(port_timeout_seconds, bool)
            or not isinstance(port_timeout_seconds, (int, float))
            or not math.isfinite(port_timeout_seconds)
            or port_timeout_seconds <= 0
        ):
            raise ValueError("reveal port timeout must be positive and finite")
        for value, ceiling, label in (
            (maximum_stage_object_bytes, MAX_STAGE_OBJECT_BYTES, "stage object"),
            (maximum_stage_total_bytes, MAX_JOURNAL_OBJECT_BYTES, "stage aggregate"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= ceiling:
                raise ValueError(f"reveal {label} byte ceiling is invalid")
        if maximum_stage_object_bytes > maximum_stage_total_bytes:
            raise ValueError("reveal object ceiling exceeds its aggregate ceiling")

        self.policy = policy
        self.validator_hotkey = validator_hotkey
        self._validator_account = account
        self._policy_hash = scoring_policy_hash(policy)
        self.journal = journal
        self.material_store = material_store
        self.protocol_state = protocol_state
        self.monitoring_state = monitoring_state
        self.coordinator = coordinator
        self.ports = ports
        self.port_timeout_seconds = float(port_timeout_seconds)
        self.maximum_stage_object_bytes = maximum_stage_object_bytes
        self.maximum_stage_total_bytes = maximum_stage_total_bytes
        self._validate_monitoring_policy()

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        self._validate_work(operation_id, work)
        window = work.window.plan
        records = self.journal.load_window(window.window_id)
        stage_index = STAGE_ORDER.index(WindowStage.REVEAL_AND_SCORE)
        if len(records) != stage_index:
            raise RevealBindingError("reveal journal is not the complete pre-reveal prefix")
        for evidence, record, stage in zip(
            work.completed_evidence,
            records,
            STAGE_ORDER[:stage_index],
            strict=True,
        ):
            if (
                evidence.stage is not stage
                or evidence.evidence_sha256 != record.evidence_sha256
                or record.receipt.operation_id != stage_operation_id(window.window_id, stage)
            ):
                raise RevealBindingError("reveal source receipt prefix changed")

        pool_record = records[0]
        response_record = records[-1]
        pool_digest = _completed_digest(work, WindowStage.POOL_AND_SELECTION)
        response_digest = _completed_digest(work, WindowStage.SEALED_RESPONSE)
        if (
            pool_record.evidence_sha256 != pool_digest
            or response_record.evidence_sha256 != response_digest
        ):
            raise RevealBindingError("reveal source digest differs from its journal receipt")

        pool_payloads = _receipt_payloads(self.journal, pool_record)
        response_payloads = _receipt_payloads(self.journal, response_record)
        selection, selection_bytes = _find_pool_stage_decision(pool_payloads)
        transition_operation = reveal_transition_operation_id(window.window_id)
        prior_state = self.coordinator.recover_prior_state(
            transition_operation_id=transition_operation,
            window_index=window.window_index,
            window_id=bytes.fromhex(window.window_id),
        )
        if prior_state is None:
            prior_state = self.protocol_state.snapshot
        if prior_state.last_window_index != window.window_index - 1:
            raise RevealBindingError("reveal pre-state is not the preceding scheduled window")
        prior_state_bytes = _policy_state_object(prior_state)

        transcript_sources = _transcript_receipt_sources(self.journal, records[1:])
        pool_no_score: _PoolNoScoreChain | None = None
        if isinstance(selection, PoolSelectionEvidence):
            stored = self.material_store.load(window.window_id)
            if stored.window != window or stored.pool_stage_evidence_sha256 != pool_digest:
                raise RevealBindingError("window material is not bound to the reveal pool receipt")
            candidates, _selection_pulse = _load_pool_candidates(
                selection=selection,
                payloads=pool_payloads,
                policy=self.policy,
                prior_state=prior_state,
                plan=stored.plan,
                selection_round=window.selection_round,
            )
            material_binding = TranscriptMaterialBinding(
                material_sha256=stored.receipt.material_sha256,
                material_receipt_sha256=stored.receipt_sha256,
                pool_stage_evidence_sha256=stored.pool_stage_evidence_sha256 or "",
            )
            transcript_abort = _resolve_transcript_abort_chain(
                transcript_sources,
                pool_stage_evidence_sha256=pool_digest,
                material_binding=material_binding,
                scoring_policy_hash=self._policy_hash,
            )
            if transcript_abort is None:
                responses, response_root, _response_plan = _load_response_material(
                    record=response_record,
                    payloads=response_payloads,
                    stored=stored,
                    policy_hash=self._policy_hash,
                )
                issued_miner_roots = None
            else:
                responses = ()
                response_root = None
                issued_miner_roots = _abort_issued_miner_roots(
                    transcript_abort,
                    selection=selection,
                    stored=stored,
                )
        else:
            if account_id32(selection.validator_hotkey) != self._validator_account:
                raise RevealBindingError("pool no-score evidence binds another validator")
            candidates, _selection_pulse = _load_pool_no_score_candidates(
                no_score=selection,
                payloads=pool_payloads,
                policy=self.policy,
                prior_state=prior_state,
                window=window,
            )
            pool_no_score = _resolve_pool_no_score_chain(
                transcript_sources,
                pool_stage_evidence_sha256=pool_digest,
                expected_origin=selection,
                scoring_policy_hash=self._policy_hash,
            )
            transcript_abort = None
            responses = ()
            response_root = None
            issued_miner_roots = ()
        pulse_bytes = await self._invoke(
            self.ports.reveal_pulse,
            work,
            label="reveal pulse",
        )
        if not isinstance(pulse_bytes, bytes):
            raise RevealBindingError("reveal pulse port returned non-bytes evidence")
        if not pulse_bytes or len(pulse_bytes) > MAX_REVEAL_PULSE_BYTES:
            raise RevealLimitError("reveal pulse exceeds its byte ceiling")
        reveal_pulse = _parse_pulse(pulse_bytes, expected_round=window.reveal_round)

        async def bounded_decrypt(sealed: SealedResponse, pulse: DrandPulse) -> bytes:
            value = await self._invoke(
                self.ports.decrypt,
                sealed,
                pulse,
                label="timelock decryption",
            )
            if not isinstance(value, bytes):
                raise RevealBindingError("timelock decrypt port returned non-bytes plaintext")
            return value

        computation = await _compute_reveal(
            policy=self.policy,
            selection=selection,
            candidates=candidates,
            responses=responses,
            prior_state=prior_state,
            reveal_pulse=reveal_pulse,
            decrypt=bounded_decrypt,
            pool_stage_digest=pool_digest,
            response_stage_digest=response_digest,
            response_set_root=response_root,
            transcript_abort=transcript_abort,
            pool_no_score=pool_no_score,
            issued_miner_roots=issued_miner_roots,
        )
        transition_evidence = sha256_domain(
            b"umi-validator-reveal-evidence-v1\0",
            bytes.fromhex(pool_digest),
            bytes.fromhex(response_digest),
            raw_sha256(reveal_pulse.evidence_digest, field="reveal pulse evidence"),
            hashlib.sha256(computation.result_bytes).digest(),
            prior_state.state_digest,
        )
        applied = self.coordinator.apply(
            stage_operation_id_value=operation_id,
            transition_operation_id=transition_operation,
            evidence_digest=transition_evidence,
            window_index=window.window_index,
            window_id=bytes.fromhex(window.window_id),
            reveal_round=window.reveal_round,
            prior_state_digest=prior_state.state_digest,
            prior_state_bytes=prior_state_bytes,
            computation=computation,
            protocol_state=self.protocol_state,
            monitoring_state=self.monitoring_state,
            policy_limits=ProtocolStatePolicyLimits(
                rolling_batch_count=self.policy.limits.rolling_batch_count,
                score_max_age_windows=self.policy.limits.score_max_age_windows,
                publisher_fault_cooldown_windows=(
                    self.policy.limits.publisher_fault_cooldown_windows
                ),
            ),
        )
        if (
            applied.protocol.snapshot.last_window_index != window.window_index
            or applied.protocol.snapshot.last_window_id != bytes.fromhex(window.window_id)
        ):
            raise RevealBindingError("protocol transition returned another state head")

        reason = None
        if pool_no_score is not None:
            reason = pool_no_score.origin.reason_code
        elif transcript_abort is None:
            reason = (
                "canary_hit"
                if "canary_hit" in computation.void_reason_codes
                else (computation.void_reason_codes[0] if computation.void_reason_codes else None)
            )
        audit_release: VerifiedRevealAuditRelease | None = None
        if reason is not None:
            value = await self._invoke(
                self.ports.audit_release,
                work,
                reason,
                label="reveal audit release",
            )
            if not isinstance(value, VerifiedRevealAuditRelease):
                raise RevealBindingError("audit-release port returned another type")
            if value.fact.window_id != window.window_id or value.fact.reason_code != reason:
                raise RevealBindingError("audit-release fact binds another reveal outcome")
            audit_release = value

        return self._effect_result(
            operation_id=operation_id,
            work=work,
            pool_record=pool_record,
            response_record=response_record,
            pool_inputs=_stage_inputs(self.journal, pool_record),
            response_inputs=_stage_inputs(self.journal, response_record),
            selection_bytes=selection_bytes,
            pulse_bytes=pulse_bytes,
            prior_state_bytes=prior_state_bytes,
            transition_operation=transition_operation,
            transition_evidence=transition_evidence,
            computation=computation,
            applied=applied,
            audit_release=audit_release,
            transcript_abort=transcript_abort,
            pool_no_score=pool_no_score,
        )

    def _effect_result(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        pool_record: StageJournalRecord,
        response_record: StageJournalRecord,
        pool_inputs: tuple[StageObjectInput, ...],
        response_inputs: tuple[StageObjectInput, ...],
        selection_bytes: bytes,
        pulse_bytes: bytes,
        prior_state_bytes: bytes,
        transition_operation: bytes,
        transition_evidence: bytes,
        computation: RevealComputation,
        applied: AppliedRevealTransition,
        audit_release: VerifiedRevealAuditRelease | None,
        transcript_abort: _TranscriptAbortChain | None,
        pool_no_score: _PoolNoScoreChain | None,
    ) -> StageEffectResult:
        policy_bytes = canonical_json_bytes(self.policy)
        inputs = [
            *pool_inputs,
            *response_inputs,
            StageObjectInput(pool_record.receipt_bytes, STAGE_RECEIPT_MEDIA_TYPE),
            StageObjectInput(response_record.receipt_bytes, STAGE_RECEIPT_MEDIA_TYPE),
            StageObjectInput(policy_bytes, SCORING_POLICY_MEDIA_TYPE),
            StageObjectInput(pulse_bytes, "application/json"),
            StageObjectInput(prior_state_bytes, "application/json"),
            *computation.objects,
            StageObjectInput(applied.request_bytes, "application/json"),
            StageObjectInput(applied.protocol.request_bytes, "application/json"),
            StageObjectInput(applied.protocol.result_bytes, "application/json"),
        ]
        no_score_sources = (
            transcript_abort.sources
            if transcript_abort is not None
            else (() if pool_no_score is None else pool_no_score.sources)
        )
        for source in no_score_sources:
            inputs.extend(
                StageObjectInput(data, reference.media_type)
                for reference, data in (
                    (reference, source.payloads[reference.sha256])
                    for reference in source.receipt.objects
                )
            )
            inputs.append(StageObjectInput(source.receipt_bytes, STAGE_RECEIPT_MEDIA_TYPE))
        if applied.monitoring_request_bytes is not None:
            if applied.monitoring_report_bytes is None:
                raise RevealBindingError("monitoring transition lacks its deterministic report")
            inputs.extend(
                (
                    StageObjectInput(applied.monitoring_request_bytes, "application/json"),
                    StageObjectInput(applied.monitoring_report_bytes, "application/json"),
                )
            )
        audit_fact_bytes: bytes | None = None
        if audit_release is not None:
            audit_fact_bytes = canonical_json_bytes(audit_release.fact)
            inputs.extend(
                (
                    StageObjectInput(audit_fact_bytes, "application/json"),
                    StageObjectInput(audit_release.evidence_bytes, "application/octet-stream"),
                )
            )
        source_inputs = _unique_stage_objects(inputs)
        decrypt_refs: dict[str, RevealObjectRef] = {}
        plaintext_refs: dict[str, RevealObjectRef] = {}
        for item in computation.objects:
            reference = _object_ref(item.data, item.media_type)
            if item.media_type == "application/octet-stream":
                plaintext_refs.setdefault(reference.sha256, reference)
                continue
            value = _strict_json(item.data, "reveal computation object")
            if isinstance(value, dict) and value.get("schema") == REVEAL_DECRYPTION_SCHEMA:
                decrypt_refs.setdefault(reference.sha256, reference)
        if not decrypt_refs and not (
            pool_no_score is not None and not pool_no_score.origin.candidates
        ):
            raise RevealBindingError("reveal computation omitted decryption evidence")
        manifest = RevealStageManifest(
            schema=REVEAL_STAGE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            operation_id=operation_id,
            transition_operation_id=transition_operation.hex(),
            transition_evidence_sha256=transition_evidence.hex(),
            window_id=work.window.plan.window_id,
            window_index=work.window.plan.window_index,
            scoring_policy_hash=self._policy_hash,
            pool_stage_receipt=_object_ref(
                pool_record.receipt_bytes,
                STAGE_RECEIPT_MEDIA_TYPE,
            ),
            response_stage_receipt=_object_ref(
                response_record.receipt_bytes,
                STAGE_RECEIPT_MEDIA_TYPE,
            ),
            pool_selection_evidence=_object_ref(selection_bytes, "application/json"),
            reveal_pulse=_object_ref(pulse_bytes, "application/json"),
            policy_object=_object_ref(policy_bytes, SCORING_POLICY_MEDIA_TYPE),
            prior_protocol_state=_object_ref(prior_state_bytes, "application/json"),
            reveal_result=_object_ref(computation.result_bytes, "application/json"),
            protocol_transition_request=_object_ref(
                applied.protocol.request_bytes, "application/json"
            ),
            protocol_transition_result=_object_ref(
                applied.protocol.result_bytes, "application/json"
            ),
            monitoring_transition_request=(
                None
                if applied.monitoring_request_bytes is None
                else _object_ref(applied.monitoring_request_bytes, "application/json")
            ),
            monitoring_report=(
                None
                if applied.monitoring_report_bytes is None
                else _object_ref(applied.monitoring_report_bytes, "application/json")
            ),
            audit_release_fact=(
                None
                if audit_fact_bytes is None
                else _object_ref(audit_fact_bytes, "application/json")
            ),
            audit_release_evidence=(
                None
                if audit_release is None
                else _object_ref(audit_release.evidence_bytes, "application/octet-stream")
            ),
            decryption_records=[
                decrypt_refs[key] for key in sorted(decrypt_refs, key=bytes.fromhex)
            ],
            plaintext_objects=sorted(
                plaintext_refs.values(),
                key=lambda item: bytes.fromhex(item.sha256),
            ),
            source_objects=[_object_ref(item.data, item.media_type) for item in source_inputs],
        )
        manifest_bytes = canonical_json_bytes(manifest)
        objects = _unique_stage_objects(
            (*source_inputs, StageObjectInput(manifest_bytes, "application/json"))
        )
        self._preflight_objects(objects)
        protocol_result = _json_object(
            applied.protocol.result_bytes,
            label="protocol transition result",
        )
        state = protocol_result.get("state")
        if not isinstance(state, dict) or not isinstance(state.get("state_digest"), str):
            raise RevealBindingError("protocol transition result lacks a state digest")
        parsed_result = _parse_reveal_result(computation.result_bytes)
        metadata: dict[str, JsonValue] = {
            "reveal_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "reveal_result_sha256": hashlib.sha256(computation.result_bytes).hexdigest(),
            "transition_operation_id": transition_operation.hex(),
            "transition_evidence_sha256": transition_evidence.hex(),
            "resulting_protocol_state_digest": state["state_digest"],
            "void_reason_codes": list(computation.void_reason_codes),
            "objective_fault_count": len(computation.fault_findings),
            "scored_batch_count": len(computation.scored_batches),
            "issued_request_count": len(computation.issued_miner_roots),
        }
        if isinstance(parsed_result, RevealResult):
            metadata["response_set_root"] = parsed_result.response_set_root
        elif isinstance(parsed_result, TranscriptAbortRevealResult):
            metadata.update(
                {
                    "transcript_abort": True,
                    "transcript_abort_origin_stage": (parsed_result.abort_origin.origin_stage),
                    "transcript_abort_origin_sha256": (parsed_result.abort_origin_sha256),
                    "transcript_abort_origin_stage_evidence_sha256": (
                        parsed_result.abort_origin_stage_evidence_sha256
                    ),
                    "transcript_abort_reason_code": (parsed_result.abort_origin.reason_code),
                }
            )
        else:
            metadata.update(
                {
                    "pool_no_score": True,
                    "pool_no_score_origin_sha256": (parsed_result.pool_no_score_sha256),
                    "pool_no_score_reason_code": (parsed_result.pool_no_score.reason_code),
                    "pool_no_score_terminal_outcome": (
                        parsed_result.pool_no_score.terminal_outcome
                    ),
                }
            )
        if pool_no_score is not None:
            if audit_release is None or not isinstance(
                parsed_result,
                PoolNoScoreRevealResult,
            ):
                raise RevealBindingError("pool no-score reveal decision inputs disagree")
            origin = pool_no_score.origin
            incident = IncidentSpec(
                incident_id=f"{origin.operation_id}/incident",
                reason_code=origin.reason_code,
                metadata={
                    "pool_no_score_origin_sha256": pool_no_score.origin_sha256,
                    "pool_no_score_pool_stage_evidence_sha256": (
                        pool_no_score.pool_stage_evidence_sha256
                    ),
                    "reveal_result_sha256": hashlib.sha256(computation.result_bytes).hexdigest(),
                    "transition_operation_id": transition_operation.hex(),
                    "resulting_protocol_state_digest": state["state_digest"],
                    "audit_release_evidence_sha256": (audit_release.fact.evidence_sha256),
                },
            )
            decision = TerminalStageEffect(
                outcome=origin.outcome,
                audit_release_block=audit_release.fact.audit_release_block,
                reason_code=origin.reason_code,
                incident=incident,
            )
        elif transcript_abort is not None:
            if audit_release is not None or not isinstance(
                parsed_result,
                TranscriptAbortRevealResult,
            ):
                raise RevealBindingError("abort reveal decision inputs disagree")
            origin = transcript_abort.origin
            incident = IncidentSpec(
                incident_id=f"{origin.origin_operation_id}/incident",
                reason_code=origin.reason_code,
                metadata={
                    "transcript_abort_origin_stage": origin.origin_stage,
                    "transcript_abort_origin_sha256": transcript_abort.origin_sha256,
                    "transcript_abort_origin_stage_evidence_sha256": (
                        transcript_abort.origin_stage_evidence_sha256
                    ),
                    "reveal_result_sha256": hashlib.sha256(computation.result_bytes).hexdigest(),
                    "transition_operation_id": transition_operation.hex(),
                    "resulting_protocol_state_digest": state["state_digest"],
                },
            )
            decision = TerminalStageEffect(
                outcome=TerminalOutcome.SKIPPED,
                audit_release_block=origin.audit_release_block,
                reason_code=origin.reason_code,
                incident=incident,
            )
        elif audit_release is None:
            decision = CompleteStageEffect()
        else:
            reason = audit_release.fact.reason_code
            incident = IncidentSpec(
                incident_id=f"umi-reveal-incident/{work.window.plan.window_id}/{reason}",
                reason_code=reason,
                metadata={
                    "reveal_result_sha256": hashlib.sha256(computation.result_bytes).hexdigest(),
                    "transition_operation_id": transition_operation.hex(),
                    "audit_release_evidence_sha256": audit_release.fact.evidence_sha256,
                },
            )
            pause_scopes = (
                (PauseScope.WEIGHT_SUBMISSION, PauseScope.WINDOW_INTAKE)
                if reason == "canary_hit"
                else ()
            )
            decision = TerminalStageEffect(
                outcome=TerminalOutcome.VOID,
                audit_release_block=audit_release.fact.audit_release_block,
                reason_code=reason,
                incident=incident,
                pause_scopes=pause_scopes,
            )
        return StageEffectResult(
            operation_id=operation_id,
            window_id=work.window.plan.window_id,
            stage=WindowStage.REVEAL_AND_SCORE,
            objects=objects,
            metadata=metadata,
            decision=decision,
        )

    def _validate_work(self, operation_id: str, work: StageWorkItem) -> None:
        if not isinstance(work, StageWorkItem):
            raise TypeError("reveal work must be StageWorkItem")
        if work.stage is not WindowStage.REVEAL_AND_SCORE:
            raise RevealBindingError("reveal effect received another stage")
        if operation_id != stage_operation_id(work.window.plan.window_id, work.stage):
            raise RevealBindingError("reveal operation ID is not deterministic")
        if work.window.plan.scoring_policy_hash != self._policy_hash:
            raise RevealBindingError("reveal window names another scoring policy")
        expected = STAGE_ORDER.index(WindowStage.REVEAL_AND_SCORE)
        if len(work.completed_evidence) != expected:
            raise RevealBindingError("reveal work lacks the complete stage prefix")

    def _validate_monitoring_policy(self) -> None:
        monitoring = self.monitoring_state.policy
        publishers = tuple(
            sorted(account_id32(item.publisher_hotkey) for item in self.policy.publisher_registry)
        )
        groups = tuple(
            sorted(
                raw_sha256(item.control_group_id, field="control group ID")
                for item in self.policy.control_group_registry
            )
        )
        mappings = tuple(
            sorted(
                (
                    account_id32(item.publisher_hotkey),
                    raw_sha256(item.control_group_id, field="control group ID"),
                )
                for item in self.policy.publisher_registry
            )
        )
        expected = (
            self._validator_account,
            bytes.fromhex(self._policy_hash),
            self.policy.limits.publisher_monitoring_batches,
            self.policy.limits.divergence_minimum_clips_per_side_and_stratum,
            self.policy.thresholds.source_divergence_alert_threshold.fraction,
            publishers,
            groups,
            mappings,
        )
        actual = (
            monitoring.validator_account_id32,
            monitoring.scoring_policy_hash,
            monitoring.maximum_batches,
            monitoring.minimum_clips_per_side_and_stratum,
            monitoring.alert_threshold,
            monitoring.publisher_sources,
            monitoring.control_group_sources,
            monitoring.publisher_control_groups,
        )
        if actual != expected:
            raise RevealBindingError("monitoring state policy differs from scoring policy")

    def _preflight_objects(self, objects: Sequence[StageObjectInput]) -> None:
        if len(objects) > MAX_REVEAL_OBJECTS:
            raise RevealLimitError("reveal stage object-count ceiling exceeded")
        total = 0
        aggregate_ceiling = min(
            self.maximum_stage_total_bytes,
            self.policy.limits.maximum_audit_bundle_bytes,
            self.journal.maximum_total_object_bytes,
        )
        for item in objects:
            if len(item.data) > self.maximum_stage_object_bytes:
                raise RevealLimitError("reveal object exceeds the stage-journal ceiling")
            total += len(item.data)
            if total > aggregate_ceiling:
                raise RevealLimitError("reveal evidence exceeds its aggregate byte ceiling")

    async def _invoke(
        self,
        function: Callable[..., Any],
        *args: Any,
        label: str,
    ) -> Any:
        try:
            if inspect.iscoroutinefunction(function):
                return await asyncio.wait_for(
                    function(*args),
                    timeout=self.port_timeout_seconds,
                )
            result = await asyncio.wait_for(
                asyncio.to_thread(function, *args),
                timeout=self.port_timeout_seconds,
            )
            if inspect.isawaitable(result):
                return await asyncio.wait_for(result, timeout=self.port_timeout_seconds)
            return result
        except (asyncio.TimeoutError, TimeoutError) as error:
            raise RevealEffectError(f"{label} port timed out") from error


def _resolve_reveal_stage_payloads(
    policy: ScoringPolicy,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
) -> ResolvedRevealStage:
    """Resolve a reveal stage from only its policy, receipt, and exact objects."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be ScoringPolicy")
    if not isinstance(receipt, StageReceipt):
        raise TypeError("receipt must be StageReceipt")
    if not isinstance(objects, Mapping):
        raise TypeError("objects must be a digest-to-bytes mapping")
    if receipt.stage != WindowStage.REVEAL_AND_SCORE.value:
        raise RevealBindingError("receipt is not a reveal stage")
    expected_operation = stage_operation_id(
        receipt.window_id,
        WindowStage.REVEAL_AND_SCORE,
    )
    if receipt.operation_id != expected_operation:
        raise RevealBindingError("reveal receipt operation ID is not deterministic")
    expected_objects = {item.sha256: item for item in receipt.objects}
    if set(objects) != set(expected_objects):
        raise RevealBindingError("reveal receipt object graph is not exact")
    payloads: dict[str, bytes] = {}
    for digest, reference in expected_objects.items():
        data = objects[digest]
        if not isinstance(data, bytes):
            raise TypeError("reveal receipt object values must be exact bytes")
        if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != digest:
            raise RevealBindingError("reveal receipt object metadata does not reproduce")
        payloads[digest] = data
    manifest, manifest_bytes = _find_one_schema(
        payloads,
        REVEAL_STAGE_SCHEMA,
        RevealStageManifest,
        label="reveal stage manifest",
    )
    if (
        manifest.operation_id != expected_operation
        or manifest.window_id != receipt.window_id
        or manifest.transition_operation_id
        != reveal_transition_operation_id(receipt.window_id).hex()
    ):
        raise RevealBindingError("reveal manifest changes its receipt binding")
    expected_sources = set(payloads) - {hashlib.sha256(manifest_bytes).hexdigest()}
    if {item.sha256 for item in manifest.source_objects} != expected_sources:
        raise RevealBindingError("reveal manifest source graph is incomplete")
    for reference in manifest.source_objects:
        _resolve(payloads, reference, label="reveal source")

    pool_receipt_bytes = _resolve(
        payloads,
        manifest.pool_stage_receipt,
        label="pool stage receipt",
    )
    response_receipt_bytes = _resolve(
        payloads,
        manifest.response_stage_receipt,
        label="response stage receipt",
    )
    pool_receipt = _parse_canonical(pool_receipt_bytes, StageReceipt, "pool stage receipt")
    response_receipt = _parse_canonical(
        response_receipt_bytes,
        StageReceipt,
        "response stage receipt",
    )
    if (
        pool_receipt.stage != WindowStage.POOL_AND_SELECTION.value
        or response_receipt.stage != WindowStage.SEALED_RESPONSE.value
        or pool_receipt.window_id != manifest.window_id
        or response_receipt.window_id != manifest.window_id
    ):
        raise RevealBindingError("reveal source receipts bind another window or stage")
    if not {item.sha256 for item in pool_receipt.objects}.issubset(payloads):
        raise RevealBindingError("reveal graph omits a pool receipt object")
    if not {item.sha256 for item in response_receipt.objects}.issubset(payloads):
        raise RevealBindingError("reveal graph omits a response receipt object")

    policy_bytes = _resolve(payloads, manifest.policy_object, label="reveal policy")
    embedded_policy = _parse_canonical(policy_bytes, ScoringPolicy, "reveal policy")
    if (
        canonical_json_bytes(embedded_policy) != canonical_json_bytes(policy)
        or scoring_policy_hash(policy) != manifest.scoring_policy_hash
    ):
        raise RevealBindingError("reveal policy hash does not reproduce")
    result_bytes = _resolve(payloads, manifest.reveal_result, label="reveal result")
    result = _parse_reveal_result(result_bytes)
    if not manifest.decryption_records and not (
        isinstance(result, PoolNoScoreRevealResult) and not result.candidate_reveals
    ):
        raise RevealBindingError("reveal manifest omits required decryption records")
    pulse_bytes = _resolve(payloads, manifest.reveal_pulse, label="reveal pulse")
    pulse = _parse_pulse(pulse_bytes, expected_round=result.reveal_round)
    if (
        result.window_id != manifest.window_id
        or result.window_index != manifest.window_index
        or result.scoring_policy_hash != manifest.scoring_policy_hash
        or result.reveal_pulse_evidence_digest != pulse.evidence_digest
        or result.pool_stage_evidence_sha256 != hashlib.sha256(pool_receipt_bytes).hexdigest()
        or result.response_stage_evidence_sha256
        != hashlib.sha256(response_receipt_bytes).hexdigest()
    ):
        raise RevealBindingError("reveal result changes a source binding")

    prior_bytes = _resolve(
        payloads,
        manifest.prior_protocol_state,
        label="prior protocol state",
    )
    prior = _policy_state_from_object(prior_bytes)
    if prior.state_digest.hex() != result.prior_protocol_state_digest:
        raise RevealBindingError("reveal result changes its prior state")
    expected_transition_evidence = sha256_domain(
        b"umi-validator-reveal-evidence-v1\0",
        hashlib.sha256(pool_receipt_bytes).digest(),
        hashlib.sha256(response_receipt_bytes).digest(),
        raw_sha256(pulse.evidence_digest, field="reveal pulse evidence"),
        hashlib.sha256(result_bytes).digest(),
        prior.state_digest,
    )
    if expected_transition_evidence.hex() != manifest.transition_evidence_sha256:
        raise RevealBindingError("reveal transition evidence does not reproduce")

    if isinstance(result, RevealResult):
        try:
            response_replay = replay_transcript_stage_receipt(
                _transcript_receipt_for_replay(response_receipt),
                {
                    reference.sha256: payloads[reference.sha256]
                    for reference in response_receipt.objects
                },
            )
        except TranscriptReplayError as error:
            raise RevealBindingError("embedded response receipt does not replay") from error
        if (
            not isinstance(response_replay, TranscriptStageReplay)
            or response_replay.root != result.response_set_root
        ):
            raise RevealBindingError("reveal result changes the response-set root")
    elif isinstance(result, TranscriptAbortRevealResult):
        transcript_sources = _embedded_transcript_sources(
            payloads,
            window_id=manifest.window_id,
        )
        abort = _resolve_transcript_abort_chain(
            transcript_sources,
            pool_stage_evidence_sha256=result.pool_stage_evidence_sha256,
            material_binding=None,
            scoring_policy_hash=result.scoring_policy_hash,
        )
        if (
            abort is None
            or transcript_sources[-1].receipt_bytes != response_receipt_bytes
            or abort.origin != result.abort_origin
            or abort.origin_sha256 != result.abort_origin_sha256
            or abort.origin_stage_evidence_sha256 != result.abort_origin_stage_evidence_sha256
            or manifest.audit_release_fact is not None
            or manifest.audit_release_evidence is not None
            or manifest.monitoring_transition_request is not None
            or manifest.monitoring_report is not None
        ):
            raise RevealBindingError("abort reveal changes its transcript chain")
    else:
        origin_bytes = _resolve(
            payloads,
            manifest.pool_selection_evidence,
            label="pool no-score origin",
        )
        origin = _parse_canonical(
            origin_bytes,
            PoolNoScoreEvidence,
            "pool no-score origin",
        )
        transcript_sources = _embedded_transcript_sources(
            payloads,
            window_id=manifest.window_id,
        )
        chain = _resolve_pool_no_score_chain(
            transcript_sources,
            pool_stage_evidence_sha256=result.pool_stage_evidence_sha256,
            expected_origin=origin,
            scoring_policy_hash=result.scoring_policy_hash,
        )
        if (
            transcript_sources[-1].receipt_bytes != response_receipt_bytes
            or chain.origin != result.pool_no_score
            or chain.origin_sha256 != result.pool_no_score_sha256
            or manifest.audit_release_fact is None
            or manifest.audit_release_evidence is None
            or manifest.monitoring_transition_request is not None
            or manifest.monitoring_report is not None
        ):
            raise RevealBindingError("pool no-score reveal changes its settlement chain")
        audit_fact_bytes = _resolve(
            payloads,
            manifest.audit_release_fact,
            label="pool no-score audit release fact",
        )
        audit_fact = _parse_canonical(
            audit_fact_bytes,
            RevealAuditRelease,
            "pool no-score audit release fact",
        )
        audit_evidence = _resolve(
            payloads,
            manifest.audit_release_evidence,
            label="pool no-score audit release evidence",
        )
        if (
            audit_fact.window_id != result.window_id
            or audit_fact.reason_code != result.pool_no_score.reason_code
            or audit_fact.evidence_sha256 != hashlib.sha256(audit_evidence).hexdigest()
        ):
            raise RevealBindingError("pool no-score audit release does not reproduce")
    transition_request_bytes = _resolve(
        payloads,
        manifest.protocol_transition_request,
        label="protocol transition request",
    )
    transition_result_bytes = _resolve(
        payloads,
        manifest.protocol_transition_result,
        label="protocol transition result",
    )
    transition_request = _json_object(
        transition_request_bytes,
        label="protocol transition request",
    )
    transition_result = _json_object(
        transition_result_bytes,
        label="protocol transition result",
    )
    if (
        transition_request.get("operation_id") != manifest.transition_operation_id
        or transition_request.get("window_id") != manifest.window_id
        or transition_request.get("evidence_digest") != manifest.transition_evidence_sha256
        or transition_result.get("operation_id") != manifest.transition_operation_id
        or transition_result.get("window_id") != manifest.window_id
        or transition_result.get("request_sha256")
        != hashlib.sha256(transition_request_bytes).hexdigest()
    ):
        raise RevealBindingError("protocol transition receipt does not reproduce")

    for reference in manifest.decryption_records:
        value = _json_object(
            _resolve(payloads, reference, label="decryption record"),
            label="decryption record",
        )
        if value.get("schema") != REVEAL_DECRYPTION_SCHEMA:
            raise RevealBindingError("decryption record has another schema")
        plaintext = value.get("plaintext")
        if plaintext is not None:
            plaintext_ref = RevealObjectRef.model_validate(plaintext)
            _resolve(payloads, plaintext_ref, label="revealed plaintext")
    for reference in manifest.plaintext_objects:
        _resolve(payloads, reference, label="revealed plaintext")

    monitoring_report = (
        None
        if manifest.monitoring_report is None
        else _resolve(payloads, manifest.monitoring_report, label="monitoring report")
    )
    resolved = ResolvedRevealStage(
        manifest=manifest,
        result=result,
        policy=policy,
        protocol_transition_request=transition_request,
        protocol_transition_result=transition_result,
        monitoring_report_bytes=monitoring_report,
    )
    _ = resolved.resulting_protocol_state_digest
    return resolved


def resolve_reveal_stage(
    policy: ScoringPolicy,
    evidence: CalibrationStageEvidence,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
) -> ResolvedRevealStage:
    """Resolve one calibration-stage receipt through its complete evidence binding."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be ScoringPolicy")
    if not isinstance(evidence, CalibrationStageEvidence):
        raise TypeError("evidence must be CalibrationStageEvidence")
    if not isinstance(receipt, StageReceipt):
        raise TypeError("receipt must be StageReceipt")
    if policy.translation_weights_active:
        raise RevealBindingError("calibration replay requires a shadow policy")
    policy_hash = scoring_policy_hash(policy)
    receipt_bytes = canonical_json_bytes(receipt)
    if (
        evidence.stage_id != WindowStage.REVEAL_AND_SCORE.value
        or evidence.window_id != receipt.window_id
        or evidence.scoring_policy_hash != policy_hash
        or evidence.replay_hook_id
        != calibration_stage_replay_hook_id(policy, WindowStage.REVEAL_AND_SCORE.value)
        or evidence.receipt_object.sha256 != hashlib.sha256(receipt_bytes).hexdigest()
        or evidence.receipt_object.size_bytes != len(receipt_bytes)
    ):
        raise RevealBindingError("calibration evidence does not bind the reveal receipt")
    expected_payloads = {
        item.sha256: (item.media_type, item.size_bytes) for item in receipt.objects
    }
    supplied_payloads = {
        item.sha256: (item.media_type, item.size_bytes) for item in evidence.payload_objects
    }
    if supplied_payloads != expected_payloads:
        raise RevealBindingError("calibration payload references differ from the receipt")
    return _resolve_reveal_stage_payloads(policy, receipt, objects)


def resolve_reveal_receipt(
    policy: ScoringPolicy,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
) -> ResolvedRevealStage:
    """Resolve exact receipt payloads for a downstream local stage."""

    return _resolve_reveal_stage_payloads(policy, receipt, objects)


def replay_reveal_stage(
    *,
    policy: ScoringPolicy,
    evidence: CalibrationStageEvidence,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
) -> bool:
    """Pinned calibration hook with no store, cache, peer, or network dependency."""

    resolve_reveal_stage(policy, evidence, receipt, objects)
    return True


def resolve_reveal_stage_record(
    record: StageJournalRecord,
    journal: ValidatorStageJournal,
) -> ResolvedRevealStage:
    """Resolve an authoritative journal record through the pure replay boundary."""

    if not isinstance(record, StageJournalRecord):
        raise TypeError("record must be StageJournalRecord")
    if not isinstance(journal, ValidatorStageJournal):
        raise TypeError("journal must be ValidatorStageJournal")
    payloads = _receipt_payloads(journal, record)
    policy_payloads = []
    for reference in record.receipt.objects:
        if reference.media_type not in {"application/json", SCORING_POLICY_MEDIA_TYPE}:
            continue
        data = payloads[reference.sha256]
        try:
            decoded = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(decoded, Mapping) and decoded.get("schema") == "umi-scoring-policy/1":
            policy_payloads.append(data)
    if len(policy_payloads) != 1:
        raise RevealBindingError("reveal receipt policy object cardinality is not one")
    policy = _parse_canonical(policy_payloads[0], ScoringPolicy, "reveal policy")
    if record.evidence_sha256 != hashlib.sha256(record.receipt_bytes).hexdigest():
        raise RevealBindingError("journal evidence does not bind the reveal receipt")
    return _resolve_reveal_stage_payloads(policy, record.receipt, payloads)
