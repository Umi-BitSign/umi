"""Portable review of a native-replayed cohort winner as a successor baseline.

This decision does not replace a retained preparation or grant weight authority.
Its consumer must authenticate the local native preparation and promotion parent
before appending history. Certificate validity alone is not a current-head proof.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_baseline import CohortBaselineCandidate
from .competition_cohort_recovery import Block, verify_recovery_quorum
from .competition_settlement import PromotionHeadBinding
from .open_competition import (
    CompetitionPolicy,
    ModelBundle,
    Signature,
    digest,
    model_content_digest,
    validate_bundle_policy,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortBaselineReview(StrictProtocolModel):
    schema_: Literal["umi-cohort-baseline-review/1"] = Field(alias="schema")
    policy_sha256: Hex32
    series_sha256: Hex32
    source_cohort_sha256: Hex32
    source_sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    activation_sha256: Hex32
    package_sha256: Hex32
    allocation_sha256: Hex32
    target_cohort_sha256: Hex32
    target_sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    previous: PromotionHeadBinding
    candidate: CohortBaselineCandidate
    model: ModelBundle
    not_before_block: Block
    valid_through_block: Block
    eligibility_rule: Literal["paired_successor_baseline_or_better/1"] = (
        "paired_successor_baseline_or_better/1"
    )
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def exact_reference(self):
        c = self.candidate
        # The original accepted parent is provenance, independent of which
        # incumbent supplied the paired quality measurement. Preserve it.
        score = Fraction(int(c.aggregate.numerator), int(c.aggregate.denominator))
        reference = Fraction(
            int(c.baseline_aggregate.numerator), int(c.baseline_aggregate.denominator)
        )
        if (
            c.policy_sha256 != self.policy_sha256
            or self.source_cohort_sha256 == self.target_cohort_sha256
            or self.target_sequence <= self.source_sequence
            or self.not_before_block > self.valid_through_block
            or self.previous.model_sha256 != c.original_baseline_model_sha256
            or digest(self.model) != c.model_sha256
            or model_content_digest(self.model) != c.content_sha256
            or not 0 <= reference <= score <= 1
            or self.previous.sequence == 2**53 - 1
        ):
            raise ValueError("cohort baseline review changes its paired winner or successor")
        if c.model_sha256 == self.previous.model_sha256:
            raise ValueError("winning model is already the baseline; no append is needed")
        return self


class CertifiedCohortBaselineReview(StrictProtocolModel):
    review: CohortBaselineReview
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def validate_baseline_review(
    review: CohortBaselineReview, policy: CompetitionPolicy
) -> CohortBaselineReview:
    raw = canonical_json_bytes(review)
    if len(raw) > 4 * 1024**2:
        raise ValueError("cohort baseline review exceeds its metadata bound")
    review = CohortBaselineReview.model_validate_json(raw)
    if (
        review.policy_sha256 != digest(policy)
        or not policy.valid_from_block
        <= review.not_before_block
        <= review.valid_through_block
        <= policy.valid_through_block
        or "0" * 64
        in {
            review.series_sha256,
            review.source_cohort_sha256,
            review.activation_sha256,
            review.package_sha256,
            review.allocation_sha256,
            review.target_cohort_sha256,
            review.candidate.rights_evidence_sha256,
            review.candidate.reconstruction_evidence_sha256,
        }
    ):
        raise ValueError("cohort baseline review lacks its policy window or source bindings")
    validate_bundle_policy(review.model, policy)
    return review


def verify_baseline_review(
    certificate: CertifiedCohortBaselineReview, policy: CompetitionPolicy
) -> CertifiedCohortBaselineReview:
    raw = canonical_json_bytes(certificate)
    if len(raw) > 4 * 1024**2:
        raise ValueError("cohort baseline certificate exceeds its metadata bound")
    certificate = CertifiedCohortBaselineReview.model_validate_json(raw)
    review = validate_baseline_review(certificate.review, policy)
    verify_recovery_quorum(review, certificate.signatures, policy)
    return certificate


def cohort_baseline_record(review: CohortBaselineReview) -> dict:
    """Shared history identity excludes signature ordering and local arrival time.

    Calling this pure function confers no authority to store the record. A new
    history reader, original-head fence and retained-intake migration must ship
    together with its applying consumer before this format can be selected.
    """
    review = CohortBaselineReview.model_validate_json(canonical_json_bytes(review))
    return {
        "schema": "umi-model-baseline/4",
        "sequence": review.previous.sequence + 1,
        "policy_sha256": review.policy_sha256,
        "model_sha256": review.candidate.model_sha256,
        "contributor_hotkey": review.candidate.contributor_hotkey,
        "previous_promotion_sha256": review.previous.promotion_sha256,
        "submission_sha256": review.candidate.submission_sha256,
        "kind": "verified_cohort_model_promotion_no_weight",
        "review": review.model_dump(mode="json", by_alias=True),
    }
