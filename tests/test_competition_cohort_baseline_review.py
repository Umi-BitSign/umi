"""Native award-derived review metadata; no promotion or deployment is claimed."""

import pytest

from umi.competition_cohort_baseline import select_cohort_baseline_candidate
from umi.competition_cohort_baseline_review import (
    CertifiedCohortBaselineReview,
    CohortBaselineReview,
    cohort_baseline_record,
    validate_baseline_review,
    verify_baseline_review,
)
from umi.competition_cohort_quality import ExactQuality
from umi.competition_settlement import PromotionHeadBinding
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_award import award
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import model_case as model_case
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("model_case", [("best", 2)], indirect=True),
]


@pytest.fixture
async def review_case(model_case):
    b, _, _, _, _ = model_case
    candidate = select_cohort_baseline_candidate(award(model_case))
    sub = next(
        p.record.request.signed_submission.submission
        for p in b["roster"].participants
        if digest(p.record.request.signed_submission.submission) == candidate.submission_sha256
    )
    body = CohortBaselineReview(
        schema="umi-cohort-baseline-review/1",
        policy_sha256=digest(b["policy"]),
        series_sha256="11" * 32,
        source_cohort_sha256=digest(b["history"].plan),
        source_sequence=5,
        activation_sha256="12" * 32,
        package_sha256="13" * 32,
        allocation_sha256="14" * 32,
        target_cohort_sha256="15" * 32,
        target_sequence=6,
        previous=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="16" * 32,
            model_sha256=candidate.original_baseline_model_sha256,
            contributor_hotkey=None,
        ),
        candidate=candidate,
        model=sub.model_bundle,
        not_before_block=220,
        valid_through_block=250,
    )
    return b["policy"], body


def certify(body, names=("Charlie", "Dave")):
    return CertifiedCohortBaselineReview(
        review=body,
        signatures=tuple(
            sorted((sign_object(body, wallet(n)) for n in names), key=lambda s: identity(s.hotkey))
        ),
    )


async def test_native_winner_review_preserves_bundle_rights_and_paired_successor_rule(review_case):
    policy, body = review_case
    original = canonical_json_bytes(body)
    checked = verify_baseline_review(certify(body), policy)
    record = cohort_baseline_record(checked.review)
    assert record["contributor_hotkey"] == body.candidate.contributor_hotkey
    assert record["previous_promotion_sha256"] == body.previous.promotion_sha256
    assert body.model.license_id == checked.review.model.license_id
    assert body.candidate.rights_evidence_sha256 != "0" * 64
    assert checked.review.eligibility_rule == "paired_successor_baseline_or_better/1"
    assert not checked.review.chain_submission_authorized
    assert canonical_json_bytes(body) == original
    assert cohort_baseline_record(certify(body, ("Dave", "Charlie")).review) == record


async def test_review_refuses_stale_parent_different_model_and_non_successor(review_case):
    _, body = review_case
    for change in (
        {"previous": body.previous.model_copy(update={"model_sha256": "ab" * 32})},
        {"model": body.model.model_copy(update={"license_id": "Apache-2.0"})},
        {"target_sequence": body.source_sequence},
        {"target_cohort_sha256": body.source_cohort_sha256},
        {"valid_through_block": body.not_before_block - 1},
        {"previous": body.previous.model_copy(update={"sequence": 2**53 - 1})},
    ):
        with pytest.raises(ValueError):
            CohortBaselineReview.model_validate_json(
                canonical_json_bytes(body.model_copy(update=change))
            )


async def test_review_refuses_weaker_candidate_and_incomplete_source_bindings(review_case):
    policy, body = review_case
    weaker = body.candidate.model_copy(
        update={
            "aggregate": ExactQuality(numerator="0", denominator="1"),
            "baseline_aggregate": ExactQuality(numerator="1", denominator="1"),
        }
    )
    with pytest.raises(ValueError):
        validate_baseline_review(body.model_copy(update={"candidate": weaker}), policy)
    for field in ("package_sha256", "activation_sha256", "allocation_sha256"):
        with pytest.raises(ValueError, match="source bindings"):
            validate_baseline_review(body.model_copy(update={field: "0" * 64}), policy)


async def test_review_requires_policy_quorum_and_original_signed_body(review_case):
    policy, body = review_case
    with pytest.raises(ValueError, match="quorum"):
        verify_baseline_review(certify(body, ("Charlie",)), policy)
    with pytest.raises(ValueError):
        verify_baseline_review(certify(body, ("Alice", "Charlie")), policy)
    certificate = certify(body)
    changed = certificate.model_copy(
        update={"review": body.model_copy(update={"target_cohort_sha256": "17" * 32})}
    )
    with pytest.raises(ValueError):
        verify_baseline_review(changed, policy)
    with pytest.raises(ValueError, match="policy window"):
        verify_baseline_review(
            certify(
                body.model_copy(update={"valid_through_block": policy.valid_through_block + 1})
            ),
            policy,
        )
