"""Exact, separately authenticated model score corrections.

An already certified reward package remains immutable. A correction binds a
new score evidence manifest to that package and derives model credits with the
existing geometric rule. These pure operations do not review model executions,
select a standing reward activation, or authorize a transaction. Independent
reviewers must verify the retained case evidence before signing a statement;
reward consumers must explicitly select that signed statement after native
review of the original package and finalized history.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_model_award import (
    GeometricModelAward,
    ModelAwardCandidate,
    ModelAwardEvidence,
    derive_geometric_model_award,
)
from .competition_cohort_quality import ExactQuality
from .competition_cohort_recovery import Block, verify_recovery_quorum
from .competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    _combine_model_credits,
    _geometric_credit_maps,
)
from .competition_cohort_service_certification import CertifiedServiceAllocation
from .competition_geometric_rewards import GeometricRewardParameters
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


def _score(value: ExactQuality) -> Fraction:
    score = Fraction(int(value.numerator), int(value.denominator))
    if not 0 <= score <= 1:
        raise ValueError("corrected model quality must be normalized")
    return score


class CorrectedModelScore(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    submission_sha256: Hex32
    model_sha256: Hex32
    content_sha256: Hex32
    accepted_ordinal: Annotated[int, Field(ge=1)]
    source_evidence_sha256: Hex32
    aggregate: ExactQuality


class ModelScoreCorrectionEvidence(StrictProtocolModel):
    """Private reviewed metadata; source case receipts live in durable R2."""

    schema_: Literal["umi-model-score-correction-evidence/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    original_package_bytes_sha256: Hex32
    original_package_sha256: Hex32
    original_allocation_sha256: Hex32
    original_quality_manifest_sha256: Hex32
    score_source_manifest_sha256: Hex32
    selected_suite_sha256: Hex32
    selected_execution_profile_sha256: Hex32
    baseline_aggregate: ExactQuality
    parameters: GeometricRewardParameters
    rows: Annotated[tuple[CorrectedModelScore, ...], Field(min_length=1, max_length=512)]
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def identities(self):
        keys = [row.submission_sha256 for row in self.rows]
        uids = [row.uid for row in self.rows]
        ordinals = [row.accepted_ordinal for row in self.rows]
        if (
            len(keys) != len(set(keys))
            or len(uids) != len(set(uids))
            or len(ordinals) != len(set(ordinals))
            or tuple(ordinals) != tuple(sorted(ordinals))
        ):
            raise ValueError("correction evidence must retain unique acceptance order")
        _score(self.baseline_aggregate)
        for row in self.rows:
            _score(row.aggregate)
        return self


class ModelScoreCorrectionStatement(StrictProtocolModel):
    """Quorum review result, still subject to explicit reward activation."""

    schema_: Literal["umi-model-score-correction-statement/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    authority_sha256: Hex32
    original_package_bytes_sha256: Hex32
    original_package_sha256: Hex32
    original_allocation_sha256: Hex32
    evidence_sha256: Hex32
    corrected_model_award_sha256: Hex32
    corrected_allocation_sha256: Hex32
    issued_at_block: Block
    original_signed_inputs_unchanged: Literal[True] = True
    chain_submission_authorized: Literal[False] = False


class SignedModelScoreCorrection(StrictProtocolModel):
    statement: ModelScoreCorrectionStatement
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def propose_score_correction(
    *,
    evidence: ModelScoreCorrectionEvidence,
    original: CohortRewardAllocation,
    service: CertifiedServiceAllocation,
    policy: CompetitionPolicy,
    authority_sha256: str,
    original_package_sha256: str,
    original_package_bytes_sha256: str,
    issued_at_block: int,
) -> ModelScoreCorrectionStatement:
    """Build exact unsigned bytes after independent source and finality review."""
    evidence = ModelScoreCorrectionEvidence.model_validate_json(canonical_json_bytes(evidence))
    original = CohortRewardAllocation.model_validate_json(canonical_json_bytes(original))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if (
        type(issued_at_block) is not int
        or original.policy_sha256 != digest(policy)
        or original.model_award is None
        or original.model_award.authority_sha256 != authority_sha256
        or evidence.original_package_sha256 != original_package_sha256
        or evidence.original_package_bytes_sha256 != original_package_bytes_sha256
    ):
        raise ValueError("score correction proposal differs from original authority")
    corrected = derive_corrected_allocation(original, service, evidence)
    return ModelScoreCorrectionStatement(
        schema="umi-model-score-correction-statement/1",
        cohort_sha256=evidence.cohort_sha256,
        policy_sha256=digest(policy),
        authority_sha256=authority_sha256,
        original_package_bytes_sha256=original_package_bytes_sha256,
        original_package_sha256=original_package_sha256,
        original_allocation_sha256=digest(original),
        evidence_sha256=digest(evidence),
        corrected_model_award_sha256=digest(corrected.model_award),
        corrected_allocation_sha256=digest(corrected),
        issued_at_block=issued_at_block,
    )


def derive_corrected_model_award(
    original: ModelAwardEvidence,
    evidence: ModelScoreCorrectionEvidence,
) -> GeometricModelAward:
    """Rebind only score evidence; preserve all certified acceptance identities."""
    original = ModelAwardEvidence.model_validate_json(
        canonical_json_bytes(
            original.model_dump(
                mode="json", by_alias=True, include=set(ModelAwardEvidence.model_fields)
            )
        )
    )
    evidence = ModelScoreCorrectionEvidence.model_validate_json(canonical_json_bytes(evidence))
    candidates = {item.submission_sha256: item for item in original.candidates}
    receipts = {item.acceptance.submission_sha256: item for item in original.acceptances}
    rows = {item.submission_sha256: item for item in evidence.rows}
    if len(candidates) != len(original.candidates) or len(receipts) != len(original.acceptances):
        raise ValueError("correction roster differs from original certified acceptances")
    if set(candidates) != set(receipts) or set(candidates) != set(rows):
        raise ValueError("correction roster omits or adds an original model")
    if original.quality_manifest_sha256 != evidence.original_quality_manifest_sha256:
        raise ValueError("correction changed the original quality manifest")
    changed = []
    for candidate in original.candidates:
        key = candidate.submission_sha256
        row = rows[key]
        acceptance = receipts[key].acceptance
        if (
            (row.model_sha256, row.content_sha256, row.accepted_ordinal)
            != (
                candidate.model_sha256,
                candidate.content_sha256,
                acceptance.accepted_ordinal,
            )
            or candidate.acceptance_sha256 != digest(receipts[key])
            or candidate.recipient_hotkey != acceptance.recipient_hotkey
            or acceptance.cohort_sha256 != evidence.cohort_sha256
            or acceptance.policy_sha256 != original.policy_sha256
            or acceptance.authority_sha256 != original.authority_sha256
        ):
            raise ValueError("corrected score changed a certified model identity")
        changed.append(
            ModelAwardCandidate(
                submission_sha256=key,
                model_sha256=candidate.model_sha256,
                content_sha256=candidate.content_sha256,
                recipient_hotkey=candidate.recipient_hotkey,
                acceptance_sha256=candidate.acceptance_sha256,
                quality_sha256=digest(row),
                aggregate=row.aggregate,
                baseline_aggregate=evidence.baseline_aggregate,
                eligible=_score(row.aggregate) >= _score(evidence.baseline_aggregate),
            )
        )
    fields = ModelAwardEvidence.model_fields
    body = {key: getattr(original, key) for key in fields if key != "candidates"}
    body.update(
        candidates=tuple(changed),
        quality_manifest_sha256=digest(evidence),
        suite_sha256=evidence.selected_suite_sha256,
        runtime_sha256=evidence.selected_execution_profile_sha256,
    )
    return derive_geometric_model_award(
        ModelAwardEvidence.model_validate(body), evidence.parameters
    )


def derive_corrected_allocation(
    original: CohortRewardAllocation,
    service: CertifiedServiceAllocation,
    evidence: ModelScoreCorrectionEvidence,
) -> CohortRewardAllocation:
    """Reuse the certified service split and existing geometric apportionment."""
    original = CohortRewardAllocation.model_validate_json(canonical_json_bytes(original))
    service = CertifiedServiceAllocation.model_validate_json(canonical_json_bytes(service))
    evidence = ModelScoreCorrectionEvidence.model_validate_json(canonical_json_bytes(evidence))
    amounts = service.statement.allocation
    if (
        original.model_award is None
        or digest(original) != evidence.original_allocation_sha256
        or original.service_certificate_sha256 != digest(service)
        or service.statement.policy_sha256 != original.policy_sha256
        or service.statement.round_sha256 != original.round_sha256
        or original.quality_manifest_sha256 != evidence.original_quality_manifest_sha256
        or original.model_award.round_sha256 != original.round_sha256
        or original.model_award.policy_sha256 != original.policy_sha256
        or amounts.service_budget + amounts.model_budget != 65535
        or sum(row.raw_weight for row in amounts.recipients) + amounts.burn_weight
        != amounts.service_budget
    ):
        raise ValueError("correction changed certified reward or service input bindings")
    award = derive_corrected_model_award(original.model_award, evidence)
    recipients, burn = _combine_model_credits(amounts, *_geometric_credit_maps(award))
    return CohortRewardAllocation(
        schema="umi-cohort-reward-allocation/5",
        policy_sha256=original.policy_sha256,
        round_sha256=original.round_sha256,
        service_certificate_sha256=original.service_certificate_sha256,
        quality_manifest_sha256=digest(evidence),
        model_award=award,
        recipients=recipients,
        burn_weight=burn,
    )


def verify_signed_score_correction(
    signed: SignedModelScoreCorrection,
    *,
    evidence: ModelScoreCorrectionEvidence,
    original: CohortRewardAllocation,
    service: CertifiedServiceAllocation,
    original_package_bytes_sha256: str,
    original_package_sha256: str,
    authority_sha256: str,
    policy: CompetitionPolicy,
    current_block: int,
) -> CohortRewardAllocation:
    """Verify signed math and bindings after the caller's native case review.

    The caller must independently authenticate the original package, source
    manifest and case receipts. This result is not selected for rewards until
    the standing control history explicitly names the signed statement.
    """
    signed = SignedModelScoreCorrection.model_validate_json(canonical_json_bytes(signed))
    evidence = ModelScoreCorrectionEvidence.model_validate_json(canonical_json_bytes(evidence))
    original = CohortRewardAllocation.model_validate_json(canonical_json_bytes(original))
    service = CertifiedServiceAllocation.model_validate_json(canonical_json_bytes(service))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    body = signed.statement
    if (
        body.policy_sha256 != digest(policy)
        or original.policy_sha256 != body.policy_sha256
        or original.model_award is None
        or original.model_award.authority_sha256 != body.authority_sha256
        or body.cohort_sha256 != evidence.cohort_sha256
        or body.authority_sha256 != authority_sha256
        or body.original_package_bytes_sha256 != original_package_bytes_sha256
        or body.original_package_bytes_sha256 != evidence.original_package_bytes_sha256
        or body.original_package_sha256 != original_package_sha256
        or body.original_package_sha256 != evidence.original_package_sha256
        or body.original_allocation_sha256 != evidence.original_allocation_sha256
        or body.evidence_sha256 != digest(evidence)
        or body.issued_at_block > current_block
    ):
        raise ValueError("score correction differs from selected original evidence")
    verify_recovery_quorum(body, signed.signatures, policy)
    corrected = derive_corrected_allocation(original, service, evidence)
    if (
        digest(corrected.model_award) != body.corrected_model_award_sha256
        or digest(corrected) != body.corrected_allocation_sha256
    ):
        raise ValueError("signed score correction differs from exact model allocation")
    return corrected
