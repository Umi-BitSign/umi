"""A correction changes exact scores while preserving certified model identity."""

from fractions import Fraction

import pytest

from umi.competition_cohort_recovery import ModelRewardCohortAuthority
from umi.competition_cohort_score_correction import (
    CorrectedModelScore,
    ModelScoreCorrectionEvidence,
    SignedModelScoreCorrection,
    derive_corrected_allocation,
    propose_score_correction,
    verify_signed_score_correction,
)
from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import (
    RewardModelAdoption,
    derive_adopted_reward_allocation,
)
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_geometric_rewards import exact, package_boundary
from .test_open_competition import policy as policy
from .test_open_competition import wallet


def case(policy):
    authority = ModelRewardCohortAuthority(
        schema="umi-cohort-recovery-authority/3",
        policy_sha256=digest(policy),
        cohort_sha256s=("22" * 32,),
        issued_at_block=10,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
        model_reward_rule="baseline_or_better_best_score_first_complete/1",
    )
    package = package_boundary(
        ["0.9", "0.7", "0.2"],
        authority=authority,
        model_budget=65535,
        service_credit=0,
    )
    original = package.allocation
    candidates = {row.submission_sha256: row for row in original.model_award.candidates}
    rows = []
    for certificate in sorted(
        original.model_award.acceptances,
        key=lambda item: item.acceptance.accepted_ordinal,
    ):
        a = certificate.acceptance
        c = candidates[a.submission_sha256]
        rows.append(
            CorrectedModelScore(
                uid=10 + a.accepted_ordinal,
                submission_sha256=a.submission_sha256,
                model_sha256=c.model_sha256,
                content_sha256=c.content_sha256,
                accepted_ordinal=a.accepted_ordinal,
                source_evidence_sha256=digest(["retained-case-result", a.accepted_ordinal]),
                aggregate=exact(["0.46", "0.44", "0.10"][a.accepted_ordinal - 1]),
            )
        )
    evidence = ModelScoreCorrectionEvidence(
        schema="umi-model-score-correction-evidence/1",
        cohort_sha256=authority.cohort_sha256s[0],
        original_package_bytes_sha256="bc" * 32,
        original_package_sha256="ab" * 32,
        original_allocation_sha256=digest(original),
        original_quality_manifest_sha256=original.quality_manifest_sha256,
        score_source_manifest_sha256="cd" * 32,
        selected_suite_sha256="ef" * 32,
        selected_execution_profile_sha256="fa" * 32,
        baseline_aggregate=exact(Fraction(121, 360)),
        parameters=GeometricRewardParameters(
            band_width_bps=250,
            band_decay_bps=7500,
            within_band_decay_bps=7500,
            score_duplicate_tolerance_bps=1,
        ),
        rows=tuple(rows),
    )
    return package, evidence, authority


def signed(package, evidence, authority, policy):
    corrected = derive_corrected_allocation(
        package.allocation, package.service, evidence
    )
    body = propose_score_correction(
        evidence=evidence,
        original=package.allocation,
        service=package.service,
        policy=policy,
        authority_sha256=digest(authority),
        original_package_bytes_sha256=evidence.original_package_bytes_sha256,
        original_package_sha256=evidence.original_package_sha256,
        issued_at_block=200,
    )
    assert body.corrected_allocation_sha256 == digest(corrected)
    signatures = tuple(
        sorted(
            (sign_object(body, wallet(name)) for name in ("Charlie", "Dave")),
            key=lambda item: identity(item.hotkey),
        )
    )
    return SignedModelScoreCorrection(statement=body, signatures=signatures), corrected


def test_correction_reuses_geometric_math_and_preserves_original_package(policy):
    package, evidence, authority = case(policy)
    saved = canonical_json_bytes(package.allocation)
    signed_result, expected = signed(package, evidence, authority, policy)
    actual = verify_signed_score_correction(
        signed_result,
        evidence=evidence,
        original=package.allocation,
        service=package.service,
        original_package_bytes_sha256=evidence.original_package_bytes_sha256,
        original_package_sha256=evidence.original_package_sha256,
        authority_sha256=digest(authority),
        policy=policy,
        current_block=200,
    )
    assert actual == expected
    assert canonical_json_bytes(package.allocation) == saved
    assert len(actual.model_award.credits) == 2
    assert sum(item.raw_weight for item in actual.recipients) == 65535
    assert not signed_result.statement.chain_submission_authorized


def test_correction_rejects_changed_identity_and_wrong_quorum(policy):
    package, evidence, authority = case(policy)
    body, _ = signed(package, evidence, authority, policy)
    wrong = evidence.model_copy(
        update={
            "rows": (
                evidence.rows[0].model_copy(update={"model_sha256": "ff" * 32}),
                *evidence.rows[1:],
            )
        }
    )
    with pytest.raises(ValueError, match="certified model identity"):
        derive_corrected_allocation(
            package.allocation, package.service, wrong
        )
    with pytest.raises(ValueError, match="original evidence"):
        verify_signed_score_correction(
            body,
            evidence=evidence,
            original=package.allocation,
            service=package.service,
            original_package_bytes_sha256=evidence.original_package_bytes_sha256,
            original_package_sha256="ff" * 32,
            authority_sha256=digest(authority),
            policy=policy,
            current_block=200,
        )
    forged = body.model_copy(update={"signatures": body.signatures[:1]})
    with pytest.raises(ValueError, match="quorum"):
        verify_signed_score_correction(
            forged,
            evidence=evidence,
            original=package.allocation,
            service=package.service,
            original_package_bytes_sha256=evidence.original_package_bytes_sha256,
            original_package_sha256=evidence.original_package_sha256,
            authority_sha256=digest(authority),
            policy=policy,
            current_block=200,
        )


def test_corrected_adoption_derives_only_signed_selected_scores(policy, monkeypatch):
    package, evidence, authority = case(policy)
    # package_boundary supplies a lightweight package namespace; production
    # supplies a native verified package snapshot with this retained identity.
    monkeypatch.setattr(
        "umi.competition_reward_adoption.verified_package_digest",
        lambda value: evidence.original_package_sha256,
    )
    signed_result, corrected = signed(package, evidence, authority, policy)
    adopted = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/4",
        series_sha256="ab" * 32,
        policy_sha256=digest(policy),
        cohort_sha256=evidence.cohort_sha256,
        authority_sha256=digest(authority),
        package_sha256=evidence.original_package_sha256,
        allocation_sha256=digest(package.allocation),
        service_certificate_sha256=digest(package.service),
        quality_manifest_sha256=package.allocation.quality_manifest_sha256,
        effective_allocation_sha256=digest(corrected),
        parameters=evidence.parameters,
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=200,
        lifetime="until_first_verified_live_reward_then_locked",
        score_correction_evidence=evidence,
        signed_score_correction=signed_result,
    )
    assert derive_adopted_reward_allocation(package, adopted, policy) == corrected
    assert RewardModelAdoption.model_validate_json(canonical_json_bytes(adopted)) == adopted
    with pytest.raises(ValueError, match="complete versioned evidence"):
        RewardModelAdoption.model_validate_json(
            canonical_json_bytes(adopted.model_copy(update={"signed_score_correction": None}))
        )
