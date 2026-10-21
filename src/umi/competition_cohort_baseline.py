"""Select the public reference candidate from a native-replayed cohort award.

Reward bands and their pool sizes do not choose the next reference model. This
selection uses exact measured quality and original complete-acceptance order.
It is preparation evidence only: promotion still needs its separately reviewed
history append, native source binding and preserving deployment.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_model_award import MODEL_AWARD_ADAPTER, ModelAward
from .competition_cohort_quality import ExactQuality
from .open_competition import Hotkey, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


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


def _fraction(value: ExactQuality) -> Fraction:
    result = Fraction(int(value.numerator), int(value.denominator))
    if not 0 <= result <= 1:
        raise ValueError("baseline selection requires normalized exact quality")
    return result


def select_cohort_baseline_candidate(award: ModelAward) -> CohortBaselineCandidate | None:
    """Derive a candidate without conferring review, rights or weight authority.

    The caller must obtain the complete award through native package/quality
    replay. Parsing this metadata or observing a public ranking cannot establish
    that provenance. No model bytes, history proofs or databases are read here.
    All supported original/effective award versions keep their signed bytes.
    """
    award = MODEL_AWARD_ADAPTER.validate_json(canonical_json_bytes(award))
    candidates = {c.submission_sha256: c for c in award.candidates}
    certificates = {c.acceptance.submission_sha256: c for c in award.acceptances}
    if (
        len(candidates) != len(award.candidates)
        or len(certificates) != len(award.acceptances)
        or candidates.keys() != certificates.keys()
    ):
        raise ValueError("baseline selection requires complete unique model acceptances")
    ordinals = [c.acceptance.accepted_ordinal for c in award.acceptances]
    if len(ordinals) != len(set(ordinals)):
        raise ValueError("baseline selection has ambiguous complete-acceptance order")
    baselines = {_fraction(c.baseline_aggregate) for c in award.candidates}
    if len(baselines) > 1:
        raise ValueError("baseline selection has inconsistent paired reference scores")
    eligible = []
    for key, candidate in candidates.items():
        certificate = certificates[key]
        accepted = certificate.acceptance
        score, reference = _fraction(candidate.aggregate), _fraction(candidate.baseline_aggregate)
        if (
            candidate.eligible != (score >= reference)
            or candidate.acceptance_sha256 != digest(certificate)
            or accepted.policy_sha256 != award.policy_sha256
            or accepted.authority_sha256 != award.authority_sha256
            or (candidate.model_sha256, candidate.content_sha256, candidate.recipient_hotkey)
            != (accepted.model_sha256, accepted.content_sha256, accepted.recipient_hotkey)
        ):
            raise ValueError("baseline candidate differs from its paired quality or acceptance")
        if candidate.eligible:
            eligible.append((-score, accepted.accepted_ordinal, key))
    if not eligible:
        return None
    _, ordinal, key = min(eligible)
    selected, acceptance = candidates[key], certificates[key].acceptance
    return CohortBaselineCandidate(
        schema="umi-cohort-baseline-candidate/1",
        policy_sha256=award.policy_sha256,
        authority_sha256=award.authority_sha256,
        round_sha256=award.round_sha256,
        model_award_sha256=digest(award),
        quality_manifest_sha256=award.quality_manifest_sha256,
        original_baseline_model_sha256=award.baseline_model_sha256,
        submission_sha256=key,
        model_sha256=selected.model_sha256,
        content_sha256=selected.content_sha256,
        contributor_hotkey=selected.recipient_hotkey,
        acceptance_sha256=selected.acceptance_sha256,
        accepted_ordinal=ordinal,
        quality_sha256=selected.quality_sha256,
        aggregate=selected.aggregate,
        baseline_aggregate=selected.baseline_aggregate,
        rights_evidence_sha256=acceptance.rights_evidence_sha256,
        reconstruction_evidence_sha256=acceptance.reconstruction_evidence_sha256,
    )
