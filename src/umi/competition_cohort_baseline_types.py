"""Portable winner-selection evidence; no replay, storage or weight authority."""

from typing import Annotated, Literal

from pydantic import Field

from .competition_exact_quality import ExactQuality
from .open_competition import Hotkey
from .protocol import Hex32, StrictProtocolModel


class CohortBaselineCandidate(StrictProtocolModel):
    schema_: Literal["umi-cohort-baseline-candidate/1"] = Field(alias="schema")
    policy_sha256: Hex32
    authority_sha256: Hex32
    round_sha256: Hex32
    model_award_sha256: Hex32
    quality_manifest_sha256: Hex32
    original_baseline_model_sha256: Hex32
    submission_sha256: Hex32
    model_sha256: Hex32
    content_sha256: Hex32
    contributor_hotkey: Hotkey
    acceptance_sha256: Hex32
    accepted_ordinal: Annotated[int, Field(ge=1, le=2**53 - 1)]
    quality_sha256: Hex32
    aggregate: ExactQuality
    baseline_aggregate: ExactQuality
    rights_evidence_sha256: Hex32
    reconstruction_evidence_sha256: Hex32
    rule: Literal["best_exact_aggregate_first_complete/1"] = "best_exact_aggregate_first_complete/1"
    reference_promotion_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False
