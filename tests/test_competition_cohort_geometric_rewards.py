"""Native geometric authority, roster, award, allocation and certification replay."""

import shutil
from fractions import Fraction

import pytest

from umi.competition_cohort_model_award import GeometricModelAward
from umi.competition_cohort_recovery import (
    GeometricModelRewardCohortAuthority,
    SignedCohortRecoveryAuthority,
    verify_recovery_authority,
)
from umi.competition_cohort_reward_allocation import (
    build_reward_allocation,
    retain_reward_allocation,
)
from umi.competition_cohort_reward_certification import (
    replay_reward_allocation,
    verify_certified_reward_allocation,
)
from umi.competition_geometric_rewards import GEOMETRIC_MODEL_REWARD_RULE, GeometricRewardParameters
from umi.competition_round_journal import RoundJournal
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import tip
from .test_competition_cohort_model_award import award, service_boundary
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import model_case as model_case
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_roster import close
from .test_competition_cohort_standing_phases import standing


@pytest.mark.parametrize("receipt_scenario", ["geometric-model-awards"], indirect=True)
@pytest.mark.parametrize(
    "model_case,expected",
    [
        (("best", 2), 2),
        (("duplicate-disagree", 2), 1),
        (("duplicate-first-ineligible", 2), 0),
        (("distinct-zero", 2), 1),
    ],
    indirect=["model_case"],
)
def test_native_award_uses_signed_parameters_and_first_canonical_content(model_case, expected):
    batch, review, benchmark, _, _ = model_case
    original_authority = canonical_json_bytes(batch["history"].authority)
    decision = award(model_case)
    assert isinstance(decision, GeometricModelAward)
    assert decision.parameters == GeometricRewardParameters()
    assert len(decision.credits) == expected
    assert sum(
        Fraction(int(c.weight.numerator), int(c.weight.denominator)) for c in decision.credits
    ) == int(bool(expected))
    service_review, service = service_boundary(model_case, 5000)
    allocation = build_reward_allocation(
        service, service_review, benchmark, review, None, model_award=decision
    )
    assert allocation.schema_ == "umi-cohort-reward-allocation/5"
    assert sum(r.raw_weight for r in allocation.recipients) == (32768 if expected else 0)
    assert allocation.burn_weight == (32767 if expected else 65535)
    assert canonical_json_bytes(batch["history"].authority) == original_authority
    changed = decision.model_copy(
        update={"parameters": decision.parameters.model_copy(update={"band_decay_bps": 5000})}
    )
    with pytest.raises(ValueError, match=r"canonical|parameters differ"):
        build_reward_allocation(
            service, service_review, benchmark, review, None, model_award=changed
        )


@pytest.mark.parametrize("model_case", [("proportional", 2)], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["geometric-model-awards"], indirect=True)
def test_native_geometric_allocation_recovers_lost_reply_and_certifies(
    model_case, tmp_path, monkeypatch
):
    batch, review, benchmark, acceptances, archive = model_case
    service_review, service = service_boundary(model_case, 5000)
    store = CompetitionStore(tmp_path / "model-store", batch["policy"])
    shutil.copytree(archive, store.directory / "model-reward-artifacts")
    for receipt in acceptances:
        publish_private_model(
            store.directory
            / "model-reward-acceptances"
            / digest(batch["history"].plan)
            / (receipt.acceptance.submission_sha256 + ".json"),
            receipt,
        )
    root, binding = tmp_path / "allocation-owner", {"scope": "geometric-model-test"}
    owner = RoundJournal(root, binding)
    put = owner.put

    def retain(journal):
        return retain_reward_allocation(
            journal,
            store,
            service,
            service_review,
            benchmark,
            review,
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
    assert (
        replay_reward_allocation(
            result,
            store,
            service,
            service_review,
            benchmark,
            review,
            maximum_promotion_bytes=1_000_000,
        )
        == result
    )
    history = batch["quality_history"]
    for block, evidence in (
        (2000, digest(benchmark)),
        (2100, digest(service)),
        (2200, digest(result)),
    ):
        history = close(history, batch["policy"], batch["decisions"], block, evidence)
    assert (
        verify_certified_reward_allocation(
            result,
            store,
            service,
            service_review,
            benchmark,
            review,
            history,
            batch["decisions"].__getitem__,
            expected_tip_sha256=tip(history),
            current_block=2**53 - 1,
            maximum_promotion_bytes=1_000_000,
        )
        == result
    )
    assert result.schema_ == "umi-cohort-reward-allocation/5"


def test_native_authority_signs_each_parameter_and_preserves_legacy_bytes(recovery, policy):
    parameters = GeometricRewardParameters(
        band_width_bps=10000, band_decay_bps=0, within_band_decay_bps=10000
    )
    signed, _, _ = standing(
        recovery[0],
        policy,
        model_rewards=True,
        model_rule=GEOMETRIC_MODEL_REWARD_RULE,
        model_reward_parameters=parameters,
    )
    assert isinstance(
        verify_recovery_authority(signed, policy), GeometricModelRewardCohortAuthority
    )
    for field, value in (
        ("band_width_bps", 500),
        ("band_decay_bps", 7500),
        ("within_band_decay_bps", 7500),
        ("score_duplicate_tolerance_bps", 2),
    ):
        body = signed.authority.model_copy(
            update={"model_reward_parameters": parameters.model_copy(update={field: value})}
        )
        with pytest.raises(ValueError):
            verify_recovery_authority(signed.model_copy(update={"authority": body}), policy)
    for old in (
        recovery[1],
        standing(recovery[0], policy)[0],
        standing(recovery[0], policy, model_rewards=True)[0],
    ):
        raw = canonical_json_bytes(old)
        assert canonical_json_bytes(SignedCohortRecoveryAuthority.model_validate_json(raw)) == raw
        assert b"model_reward_parameters" not in raw
    assert canonical_json_bytes(
        SignedCohortRecoveryAuthority.model_validate_json(canonical_json_bytes(signed))
    ) == canonical_json_bytes(signed)
