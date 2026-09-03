"""Canonical evidence for deterministic pool-stage no-score windows.

The pool stage may know, from complete and otherwise valid source evidence, that
the window cannot issue work.  That is different from a malformed or unavailable
pool: every anchored-eligible candidate is still known and must retire at reveal.
These models preserve that distinction while the empty transcript is carried to
the reveal stage.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .encoding import account_id32
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, base64url_decode, canonical_json_bytes
from .validator_assignments import EvidenceRef
from .validator_journal import MAX_JOURNAL_OBJECT_BYTES
from .validator_state import TerminalOutcome, WindowPlan, WindowStage

POOL_NO_SCORE_SCHEMA = "umi-validator-pool-no-score/1"
POOL_NO_SCORE_STAGE_SCHEMA = "umi-validator-pool-no-score-stage/1"
POOL_EMPTY_SOURCE_SCHEMA = "umi-validator-pool-empty-source/1"

PoolNoScoreReason = Literal[
    "candidate_pool_empty",
    "candidate_control_group_count_insufficient",
    "eligible_miner_set_empty",
]

Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class PoolNoScoreObjectRef(StrictProtocolModel):
    sha256: Hex32
    media_type: Literal[
        "application/json",
        "application/octet-stream",
        "application/vnd.umi.scoring-policy+json",
    ]
    size_bytes: Annotated[int, Field(ge=0, le=MAX_JOURNAL_OBJECT_BYTES)]


class PoolEmptySourceEvidence(StrictProtocolModel):
    """Proof binding for a window with no timely closing-block pool anchor.

    The complete closing snapshot and its retained storage proof are the
    authority. No mirror index exists in this case and no mirror assertion is
    consulted.
    """

    schema_: Literal[POOL_EMPTY_SOURCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    closing_block: Annotated[int, Field(ge=0)]
    closing_block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    closing_snapshot_sha256: Hex32
    closing_proof_evidence_sha256: Hex32
    complete_publisher_registry: Literal[True]
    publisher_registry_count: Annotated[int, Field(ge=1, le=65_535)]
    timely_anchor_count: Literal[0]
    determination: Literal["complete_closing_snapshot_has_zero_timely_pool_anchors"]


class PoolNoScoreWindow(StrictProtocolModel):
    """Canonical window schedule retained when no transcript plan is created."""

    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    announcement_block: Annotated[int, Field(ge=0)]
    proposal_close_block: Annotated[int, Field(ge=0)]
    closing_block: Annotated[int, Field(ge=0)]
    selection_round: Annotated[int, Field(ge=0)]
    issue_close_round: Annotated[int, Field(ge=0)]
    response_close_round: Annotated[int, Field(ge=0)]
    reveal_round: Annotated[int, Field(ge=0)]

    @classmethod
    def from_plan(cls, plan: WindowPlan) -> PoolNoScoreWindow:
        if not isinstance(plan, WindowPlan):
            raise TypeError("window must be a WindowPlan")
        return cls.model_validate(
            {
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
        )

    def to_plan(self) -> WindowPlan:
        return WindowPlan(**self.model_dump())


class PoolNoScoreCandidate(StrictProtocolModel):
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    control_group_id: Hex32
    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    batch_commitment: Hex32
    pool_leaf: Hex32
    batch_rank: Hex32
    selection_ordinal: Annotated[int, Field(ge=0, le=65_535)] | None
    final_pool_manifest: PoolNoScoreObjectRef
    public_manifest: PoolNoScoreObjectRef
    ground_truth_envelope: PoolNoScoreObjectRef

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        account_id32(self.publisher_hotkey)
        if len(base64url_decode(self.batch_id)) != 16:
            raise ValueError("no-score candidate batch ID must encode 16 bytes")
        return self


class PoolNoScoreEvidence(StrictProtocolModel):
    """Receipt-bound proof that a complete pool cannot issue assignments."""

    schema_: Literal[POOL_NO_SCORE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    window: PoolNoScoreWindow
    reason_code: PoolNoScoreReason
    terminal_outcome: Literal["skipped", "void"]
    announcement_validator_snapshot: PoolNoScoreObjectRef
    announcement_validator_proof_evidence: PoolNoScoreObjectRef
    closing_snapshot: PoolNoScoreObjectRef
    closing_proof_evidence: PoolNoScoreObjectRef
    artifact_retrieval_evidence: PoolNoScoreObjectRef | None
    mirror_discovery_rule: PoolNoScoreObjectRef | None
    mirror_readiness_set: PoolNoScoreObjectRef | None
    empty_source_evidence: PoolNoScoreObjectRef | None
    selection_pulse: PoolNoScoreObjectRef
    selection_pulse_evidence_digest: Hex32
    policy_object: PoolNoScoreObjectRef
    prior_protocol_state: PoolNoScoreObjectRef
    protocol_state_digest: Hex32
    prior_spent_root: Hex32
    prior_publisher_fault_root: Hex32
    candidate_pool_root: Hex32 | None
    selection_seed: Hex32 | None
    candidates: list[PoolNoScoreCandidate]
    source_objects: Annotated[list[PoolNoScoreObjectRef], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_canonical_bindings(self) -> Self:
        account_id32(self.validator_hotkey)
        self.window.to_plan()
        if (
            self.window.window_id != self.window_id
            or self.window.window_index != self.window_index
            or self.window.scoring_policy_hash != self.scoring_policy_hash
        ):
            raise ValueError("pool no-score window schedule changes its identity")
        expected_outcome = (
            TerminalOutcome.VOID.value
            if self.reason_code == "candidate_control_group_count_insufficient"
            else TerminalOutcome.SKIPPED.value
        )
        if self.terminal_outcome != expected_outcome:
            raise ValueError("pool no-score outcome disagrees with its reason")
        if (self.artifact_retrieval_evidence is None) == (self.empty_source_evidence is None):
            raise ValueError(
                "pool no-score evidence must name one mirror retrieval or empty-source proof"
            )
        if self.artifact_retrieval_evidence is None:
            if self.mirror_discovery_rule is not None or self.mirror_readiness_set is not None:
                raise ValueError("empty-source evidence cannot carry mirror readiness")
        elif self.mirror_discovery_rule is None or self.mirror_readiness_set is None:
            raise ValueError("anchor-backed no-score evidence lacks mirror readiness")
        if self.empty_source_evidence is not None and (
            self.reason_code != "candidate_pool_empty" or self.candidates
        ):
            raise ValueError("empty-source proof is valid only for an empty candidate pool")
        has_seed = self.candidate_pool_root is not None and self.selection_seed is not None
        if (self.candidate_pool_root is None) != (self.selection_seed is None):
            raise ValueError("pool no-score root and seed must appear together")
        if self.reason_code == "candidate_pool_empty":
            if self.candidates or has_seed:
                raise ValueError("empty candidate pool carries ranked candidates")
        elif not self.candidates or not has_seed:
            raise ValueError("nonempty pool no-score evidence lacks ranked candidates")

        candidate_keys = [
            (bytes.fromhex(item.batch_rank), bytes.fromhex(item.pool_leaf))
            for item in self.candidates
        ]
        if candidate_keys != sorted(candidate_keys):
            raise ValueError("pool no-score candidates are not canonically ranked")
        ordinals = [
            item.selection_ordinal for item in self.candidates if item.selection_ordinal is not None
        ]
        if ordinals != list(range(len(ordinals))):
            raise ValueError("pool no-score selected ordinals are not contiguous")
        if self.reason_code == "candidate_control_group_count_insufficient" and ordinals:
            raise ValueError("insufficient-group evidence cannot select a batch cohort")
        if self.reason_code == "eligible_miner_set_empty" and not ordinals:
            raise ValueError("no-miner evidence must preserve the selected batch cohort")

        refs = [bytes.fromhex(item.sha256) for item in self.source_objects]
        if refs != sorted(refs) or len(refs) != len(set(refs)):
            raise ValueError("pool no-score sources must be unique and digest-sorted")
        available = {item.sha256 for item in self.source_objects}
        required = {
            self.announcement_validator_snapshot.sha256,
            self.announcement_validator_proof_evidence.sha256,
            self.closing_snapshot.sha256,
            self.closing_proof_evidence.sha256,
            self.selection_pulse.sha256,
            self.policy_object.sha256,
            self.prior_protocol_state.sha256,
        }
        if self.artifact_retrieval_evidence is not None:
            required.add(self.artifact_retrieval_evidence.sha256)
            required.add(self.mirror_discovery_rule.sha256)
            required.add(self.mirror_readiness_set.sha256)
        if self.empty_source_evidence is not None:
            required.add(self.empty_source_evidence.sha256)
        required.update(item.final_pool_manifest.sha256 for item in self.candidates)
        required.update(item.public_manifest.sha256 for item in self.candidates)
        required.update(item.ground_truth_envelope.sha256 for item in self.candidates)
        if not required.issubset(available):
            raise ValueError("pool no-score source index omits required evidence")
        return self

    @property
    def outcome(self) -> TerminalOutcome:
        return TerminalOutcome(self.terminal_outcome)


class PoolNoScoreStageEvidence(StrictProtocolModel):
    """One empty-transcript receipt linked to the pool no-score decision."""

    schema_: Literal[POOL_NO_SCORE_STAGE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    stage: Literal["assignment", "request_transcript", "sealed_response"]
    operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    origin: EvidenceRef
    pool_stage_evidence_sha256: Hex32
    previous_stage_evidence_sha256: Hex32


@dataclass(frozen=True, slots=True)
class PoolNoScoreReplay:
    window_id: str
    stage: WindowStage
    operation_id: str
    origin: PoolNoScoreEvidence
    origin_sha256: str
    pool_stage_evidence_sha256: str
    previous_stage_evidence_sha256: str


def parse_pool_no_score_evidence(data: bytes) -> PoolNoScoreEvidence:
    if not isinstance(data, bytes):
        raise TypeError("pool no-score evidence must be exact bytes")
    try:
        value = PoolNoScoreEvidence.model_validate_json(data)
    except Exception as error:
        raise ValueError("pool no-score evidence is invalid") from error
    if canonical_json_bytes(value) != data:
        raise ValueError("pool no-score evidence is not canonical JSON")
    return value


def pool_no_score_metadata(
    origin: PoolNoScoreEvidence,
    *,
    origin_sha256: str,
    pool_stage_evidence_sha256: str | None = None,
    previous_stage_evidence_sha256: str | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "pool_no_score": True,
        "pool_no_score_origin_sha256": origin_sha256,
        "pool_no_score_reason_code": origin.reason_code,
        "pool_no_score_terminal_outcome": origin.terminal_outcome,
        "candidate_count": len(origin.candidates),
    }
    if pool_stage_evidence_sha256 is not None:
        metadata["pool_no_score_pool_stage_evidence_sha256"] = pool_stage_evidence_sha256
    if previous_stage_evidence_sha256 is not None:
        metadata["pool_no_score_previous_stage_evidence_sha256"] = previous_stage_evidence_sha256
    return metadata


def pool_no_score_digest(value: PoolNoScoreEvidence) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "POOL_EMPTY_SOURCE_SCHEMA",
    "POOL_NO_SCORE_SCHEMA",
    "POOL_NO_SCORE_STAGE_SCHEMA",
    "PoolEmptySourceEvidence",
    "PoolNoScoreCandidate",
    "PoolNoScoreEvidence",
    "PoolNoScoreObjectRef",
    "PoolNoScoreReplay",
    "PoolNoScoreStageEvidence",
    "PoolNoScoreWindow",
    "parse_pool_no_score_evidence",
    "pool_no_score_digest",
    "pool_no_score_metadata",
]
