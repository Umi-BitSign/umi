"""Fixed pre-intake quality buckets prevent model-entry multiplication."""

import shutil
from fractions import Fraction

import pytest
from pydantic import ValidationError

from umi.competition_cohort_model_award import QualityBucketModelAward, quality_bucket_index
from umi.competition_cohort_recovery import ModelRewardCohortAuthority
from umi.competition_cohort_reward_allocation import (
    build_reward_allocation,
    retain_reward_allocation,
)
from umi.competition_cohort_reward_certification import replay_reward_allocation
from umi.competition_cohort_service_allocation import apportion_work_budget
from umi.competition_round_journal import RoundJournal
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_award import award, service_boundary
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import model_case as model_case
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_standing_phases import standing


def _allocate(case, decision):
    review, service = service_boundary(case, 5000)
    return build_reward_allocation(
        service,
        review,
        case[2],
        case[1],
        None,
        model_award=decision,
    )


@pytest.mark.parametrize("model_case", [("sybil-variants", 20)], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["quality-bucket-model-awards"], indirect=True)
def test_twenty_distinct_artifacts_at_one_quality_create_one_model_credit(model_case):
    decision = award(model_case)
    assert isinstance(decision, QualityBucketModelAward)
    assert decision.bucket_width_bps == 500
    assert len(decision.candidates) == 20
    assert len({candidate.content_sha256 for candidate in decision.candidates}) == 20
    assert len(decision.credits) == 1
    credit = decision.credits[0]
    assert len(credit.member_submission_sha256s) == 20
    expected = min(
        decision.acceptances,
        key=lambda certificate: certificate.acceptance.accepted_ordinal,
    ).acceptance
    assert credit.submission_sha256 == expected.submission_sha256
    assert credit.recipient_hotkey == expected.recipient_hotkey
    allocation = _allocate(model_case, decision)
    assert allocation.schema_ == "umi-cohort-reward-allocation/4"
    assert len(allocation.recipients) == 1
    assert allocation.recipients[0].raw_weight == 32768
    assert allocation.burn_weight == 32767

    baseline = decision.candidates[0].baseline_aggregate.model_copy(
        update={"numerator": "250", "denominator": "1000"}
    )
    varied = tuple(
        candidate.model_copy(
            update={
                "aggregate": candidate.aggregate.model_copy(
                    update={"numerator": str(300 + index), "denominator": "1000"}
                ),
                "baseline_aggregate": baseline,
                "eligible": True,
            }
        )
        for index, candidate in enumerate(decision.candidates)
    )
    winner = varied[-1]
    varied_decision = QualityBucketModelAward.model_validate(
        {
            **decision.model_dump(by_alias=True),
            "candidates": varied,
            "credits": (
                credit.model_copy(
                    update={
                        "bucket_index": 6,
                        "lower_bound_bps": 3000,
                        "upper_bound_bps": 3500,
                        "content_sha256": winner.content_sha256,
                        "submission_sha256": winner.submission_sha256,
                        "recipient_hotkey": winner.recipient_hotkey,
                        "score": winner.aggregate,
                    }
                ),
            ),
        }
    )
    assert len(varied_decision.credits) == 1
    assert varied_decision.credits[0].bucket_index == 6
    assert varied_decision.credits[0].score.numerator == "319"
    with pytest.raises(ValidationError, match="candidate is not canonical"):
        QualityBucketModelAward.model_validate(
            {
                **varied_decision.model_dump(by_alias=True),
                "candidates": (
                    varied[0].model_copy(update={"eligible": False}),
                    *varied[1:],
                ),
            }
        )


@pytest.mark.parametrize("model_case", [("duplicate-disagree", 2)], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["quality-bucket-model-awards"], indirect=True)
def test_exact_content_aliases_are_visible_but_create_one_credit(model_case):
    decision = award(model_case)
    assert isinstance(decision, QualityBucketModelAward)
    assert len(decision.candidates) == 2
    assert len({candidate.content_sha256 for candidate in decision.candidates}) == 1
    assert len(decision.credits) == 1
    assert len(decision.credits[0].member_submission_sha256s) == 2
    expected = min(
        decision.acceptances,
        key=lambda certificate: certificate.acceptance.accepted_ordinal,
    ).acceptance
    assert decision.credits[0].submission_sha256 == expected.submission_sha256
    canonical = next(
        candidate
        for candidate in decision.candidates
        if candidate.submission_sha256 == expected.submission_sha256
    )
    assert len({candidate.aggregate for candidate in decision.candidates}) == 2
    assert decision.credits[0].score == canonical.aggregate
    assert decision.credits[0].member_submission_sha256s == tuple(
        sorted(candidate.submission_sha256 for candidate in decision.candidates)
    )


@pytest.mark.parametrize("model_case", [("duplicate-first-ineligible", 2)], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["quality-bucket-model-awards"], indirect=True)
def test_later_eligible_exact_alias_cannot_retry_ineligible_content(model_case):
    decision = award(model_case)
    assert isinstance(decision, QualityBucketModelAward)
    assert len(decision.candidates) == 2
    assert len({candidate.content_sha256 for candidate in decision.candidates}) == 1
    ordered = sorted(
        decision.acceptances,
        key=lambda certificate: certificate.acceptance.accepted_ordinal,
    )
    candidates = {candidate.submission_sha256: candidate for candidate in decision.candidates}
    assert not candidates[ordered[0].acceptance.submission_sha256].eligible
    assert candidates[ordered[1].acceptance.submission_sha256].eligible
    assert decision.credits == ()


@pytest.mark.parametrize("model_case", [("proportional", 2)], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["quality-bucket-model-awards"], indirect=True)
def test_distinct_quality_bands_receive_score_proportional_credits(model_case):
    decision = award(model_case)
    assert isinstance(decision, QualityBucketModelAward)
    assert len(decision.credits) == 2
    assert [credit.bucket_index for credit in decision.credits] == sorted(
        {credit.bucket_index for credit in decision.credits}
    )
    scores = {
        credit.recipient_hotkey: Fraction(
            int(credit.score.numerator), int(credit.score.denominator)
        )
        for credit in decision.credits
    }
    allocation = _allocate(model_case, decision)
    for recipient in allocation.recipients:
        ideal = 32768 * scores[recipient.hotkey] / sum(scores.values())
        assert abs(recipient.raw_weight - ideal) < 1


@pytest.mark.parametrize("model_case", [("proportional", 2)], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["quality-bucket-model-awards"], indirect=True)
def test_bucket_award_restarts_exactly_and_rejects_tampering(model_case, tmp_path, monkeypatch):
    batch, benchmark_review, benchmark, acceptances, archive = model_case
    service_review, service = service_boundary(model_case, 5000)
    store = CompetitionStore(tmp_path / "native-model-store", batch["policy"])
    shutil.copytree(archive, store.directory / "model-reward-artifacts")
    for receipt in acceptances:
        path = (
            store.directory
            / "model-reward-acceptances"
            / digest(batch["history"].plan)
            / (receipt.acceptance.submission_sha256 + ".json")
        )
        publish_private_model(path, receipt)
    root, binding = tmp_path / "owner", {"scope": "quality-bucket-model-test"}
    owner = RoundJournal(root, binding)
    put = owner.put

    def retain(journal):
        return retain_reward_allocation(
            journal,
            store,
            service,
            service_review,
            benchmark,
            benchmark_review,
            maximum_promotion_bytes=1_000_000,
        )

    def lose_reply(kind, key, value):
        put(kind, key, value)
        if kind == "cohort_reward_allocation":
            raise OSError("lost allocation reply")

    with monkeypatch.context() as patch:
        patch.setattr(owner, "put", lose_reply)
        with pytest.raises(OSError, match="lost allocation reply"):
            retain(owner)
    saved = owner.get("cohort_reward_allocation", service_review.slot)
    result = retain(RoundJournal(root, binding))
    assert canonical_json_bytes(result) == canonical_json_bytes(saved)
    assert result.schema_ == "umi-cohort-reward-allocation/4"

    def replay(value):
        return replay_reward_allocation(
            value,
            store,
            service,
            service_review,
            benchmark,
            benchmark_review,
            maximum_promotion_bytes=1_000_000,
        )

    assert replay(result) == result
    first = result.model_award.credits[0]
    changed_award = result.model_award.model_copy(
        update={
            "credits": (
                first.model_copy(
                    update={"recipient_hotkey": result.model_award.credits[-1].recipient_hotkey}
                ),
                *result.model_award.credits[1:],
            )
        }
    )
    with pytest.raises(ValueError, match=r"canonical|independently replayed"):
        replay(result.model_copy(update={"model_award": changed_award}))
    with pytest.raises(ValueError, match="version differs"):
        replay(result.model_copy(update={"schema_": "umi-cohort-reward-allocation/3"}))


def test_bucket_parameters_must_be_signed_before_intake(recovery, policy):
    plan = recovery[0]
    with pytest.raises(ValidationError, match="bucket width"):
        standing(
            plan,
            policy,
            model_rewards=True,
            model_rule="baseline_or_better_quality_bucket_best_score_first_complete/1",
        )
    with pytest.raises(ValidationError, match="bucket width"):
        ModelRewardCohortAuthority.model_validate(
            {
                **standing(
                    plan,
                    policy,
                    model_rewards=True,
                    model_rule="baseline_or_better_quality_bucket_best_score_first_complete/1",
                    model_quality_bucket_width_bps=500,
                )[0].authority.model_dump(by_alias=True),
                "model_reward_rule": "baseline_or_better_proportional_score_first_complete/1",
            }
        )


def test_legacy_model_authority_bytes_do_not_gain_null_bucket_parameters(recovery, policy):
    authority = standing(
        recovery[0],
        policy,
        model_rewards=True,
        model_rule="baseline_or_better_proportional_score_first_complete/1",
    )[0].authority
    assert b"model_quality_bucket_width_bps" not in canonical_json_bytes(authority)


def test_exact_fraction_bucket_boundaries_are_deterministic():
    width = 500
    assert quality_bucket_index(Fraction(0), width) == 0
    assert quality_bucket_index(Fraction(499, 10000), width) == 0
    assert quality_bucket_index(Fraction(1, 20), width) == 1
    assert quality_bucket_index(Fraction(3, 10), width) == quality_bucket_index(
        Fraction(304, 1000), width
    )
    assert {quality_bucket_index(Fraction(300 + offset, 1000), width) for offset in range(20)} == {
        6
    }
    assert quality_bucket_index(Fraction(9999, 10000), width) == 19
    assert quality_bucket_index(Fraction(1), width) == 19
    assert apportion_work_budget(
        1,
        {"bucket:0010": Fraction(1), "bucket:0002": Fraction(1)},
    ) == {"bucket:0010": 0, "bucket:0002": 1}
