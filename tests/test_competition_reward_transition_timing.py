"""Operator release and finalized 24-hour timeout share the same native consumers."""

import pytest

from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardAutomaticRelease,
    RewardEarlyRelease,
    RewardModelAdoption,
    SignedRewardModelAdoption,
)
from umi.competition_reward_decisions import RewardControlDecision
from umi.competition_reward_opportunity import (
    prepare_early_release_revision,
    select_signed_early_release_revision,
    verify_signed_early_release,
)
from umi.competition_reward_transition_timing import (
    REWARD_TRANSITION_WAIT_MS,
    RewardPredecessorLiveAge,
)
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import signatures
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case


def predecessor(c):
    return RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(c.series),
        sequence=1,
        predecessor_sha256=digest(c.admission),
        kind="activate",
        observed_at_block=200,
        activation=c.activation,
    )


def age(c, *, elapsed=REWARD_TRANSITION_WAIT_MS):
    return RewardPredecessorLiveAge(
        schema="umi-reward-predecessor-live-age/1",
        series_sha256=digest(c.series),
        chain_config_sha256="11" * 32,
        predecessor_activation_sha256=digest(c.activation),
        validator_account_id=identity(c.series.validators[0]),
        live_at_block=201,
        live_block_hash="12" * 32,
        live_timestamp_ms=1000,
        live_endpoint_sha256="13" * 32,
        observed_at_block=202,
        observed_block_hash="14" * 32,
        observed_timestamp_ms=1000 + elapsed,
        observation_evidence_sha256="15" * 32,
    )


def initial(c):
    body = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(c.series),
        policy_sha256=digest(c.policy),
        cohort_sha256=digest(c.series.cohorts[1]),
        authority_sha256=digest(c.series.recovery.authority),
        package_sha256="ab" * 32,
        allocation_sha256="01" * 32,
        service_certificate_sha256="02" * 32,
        quality_manifest_sha256="03" * 32,
        effective_allocation_sha256="04" * 32,
        parameters=GeometricRewardParameters(),
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=200,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    return RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=(SignedRewardModelAdoption(adoption=body, signatures=signatures(body)),),
    )


@pytest.mark.parametrize(
    "elapsed,ready,remaining",
    [
        (0, False, REWARD_TRANSITION_WAIT_MS),
        (REWARD_TRANSITION_WAIT_MS - 1, False, 1),
        (REWARD_TRANSITION_WAIT_MS, True, 0),
        (REWARD_TRANSITION_WAIT_MS + 1, True, 0),
    ],
)
def test_exact_elapsed_boundary_is_not_block_count_or_coverage(
    opportunity_case, elapsed, ready, remaining
):
    facts = age(opportunity_case, elapsed=elapsed)
    assert facts.ready is ready
    assert facts.remaining_ms == remaining


@pytest.mark.parametrize("automatic", [False, True])
def test_release_reaches_shared_consumers_and_repeats_immutably(opportunity_case, automatic):
    c = opportunity_case
    selected = initial(c)
    original_bytes = canonical_json_bytes(selected.adoptions[0])
    args = dict(series=c.series, policy=c.policy, manifest=c.manifest, predecessor=predecessor(c))
    body = prepare_early_release_revision(
        selected,
        **args,
        successor_cohort_sha256=digest(c.series.cohorts[1]),
        issued_at_block=202,
        reason="Configured successor release policy",
        live_age=age(c) if automatic else None,
    )
    assert body.schema_.endswith("/6" if automatic else "/5")
    assert type(body.early_release) is (RewardAutomaticRelease if automatic else RewardEarlyRelease)
    signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    updated = select_signed_early_release_revision(selected, signed, **args)
    assert canonical_json_bytes(updated.adoptions[0]) == original_bytes
    assert select_signed_early_release_revision(updated, signed, **args) == updated
    successor = c.activation.model_copy(
        update={
            "cohort_sha256": body.cohort_sha256,
            "package_sha256": body.package_sha256,
            "reward_adoption_sha256": digest(body),
            "effective_allocation_sha256": body.effective_allocation_sha256,
            "prior_opportunity_sha256": digest(body.early_release),
        }
    )
    assert verify_signed_early_release(updated, **args, successor=successor, current_block=202)
    with pytest.raises(ValueError, match="predecessor or successor"):
        verify_signed_early_release(updated, **args, successor=successor, current_block=201)
    roundtrip = RewardModelAdoption.model_validate_json(canonical_json_bytes(body))
    assert roundtrip == body


@pytest.mark.parametrize(
    "change",
    [
        {"observed_timestamp_ms": REWARD_TRANSITION_WAIT_MS + 999},
        {"observed_at_block": 203},
        {"series_sha256": "aa" * 32},
        {"predecessor_activation_sha256": "bb" * 32},
        {"validator_account_id": "cc" * 32},
        {"live_at_block": 199},
    ],
)
def test_automatic_release_refuses_short_or_unbound_time(opportunity_case, change):
    c = opportunity_case
    with pytest.raises(ValueError):
        prepare_early_release_revision(
            initial(c),
            series=c.series,
            policy=c.policy,
            manifest=c.manifest,
            predecessor=predecessor(c),
            successor_cohort_sha256=digest(c.series.cohorts[1]),
            issued_at_block=202,
            reason="Configured successor release policy",
            live_age=age(c).model_copy(update=change),
        )


@pytest.mark.parametrize(
    "change",
    [
        {"observed_at_block": 200},
        {"observed_timestamp_ms": 999},
        {"observed_at_block": 201, "observed_timestamp_ms": 1000},
        {"observed_at_block": 201, "observed_block_hash": "12" * 32},
    ],
)
def test_finalized_time_cannot_reverse_or_conflict_at_one_height(opportunity_case, change):
    facts = age(opportunity_case).model_dump(by_alias=True)
    with pytest.raises(ValueError, match="finalized observation order"):
        RewardPredecessorLiveAge.model_validate(facts | change)


def test_one_identical_finalized_observation_has_zero_elapsed_time(opportunity_case):
    facts = age(opportunity_case).model_dump(by_alias=True)
    facts.update(observed_at_block=201, observed_block_hash="12" * 32, observed_timestamp_ms=1000)
    actual = RewardPredecessorLiveAge.model_validate(facts)
    assert not actual.ready
    assert actual.remaining_ms == REWARD_TRANSITION_WAIT_MS


@pytest.mark.parametrize("automatic", [False, True])
def test_release_does_not_accept_a_different_signed_authority(opportunity_case, automatic):
    c = opportunity_case
    current = initial(c)
    wrong = current.adoptions[0].adoption.model_copy(update={"authority_sha256": "fa" * 32})
    forged_selection = current.model_copy(
        update={
            "adoptions": (SignedRewardModelAdoption(adoption=wrong, signatures=signatures(wrong)),)
        }
    )
    with pytest.raises(ValueError, match="selected standing authority"):
        prepare_early_release_revision(
            forged_selection,
            series=c.series,
            policy=c.policy,
            manifest=c.manifest,
            predecessor=predecessor(c),
            successor_cohort_sha256=digest(c.series.cohorts[1]),
            issued_at_block=202,
            reason="Explicit early release request",
            live_age=age(c) if automatic else None,
        )


def test_historical_operator_release_replays_without_automatic_age_fields(opportunity_case):
    c = opportunity_case
    selected = initial(c)
    args = dict(series=c.series, policy=c.policy, manifest=c.manifest, predecessor=predecessor(c))
    body = prepare_early_release_revision(
        selected,
        **args,
        successor_cohort_sha256=digest(c.series.cohorts[1]),
        issued_at_block=200,
        reason="Operator releases immediately at predecessor activation",
    )
    original = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    wire = canonical_json_bytes(original)
    restored = SignedRewardModelAdoption.model_validate_json(wire)
    assert canonical_json_bytes(restored) == wire
    assert restored.adoption.schema_ == "umi-standing-model-reward-adoption/5"
    assert type(restored.adoption.early_release) is RewardEarlyRelease
    assert b'"live_age"' not in wire and b'"trigger"' not in wire
    adopted = select_signed_early_release_revision(selected, restored, **args)
    successor = c.activation.model_copy(
        update={
            "cohort_sha256": body.cohort_sha256,
            "package_sha256": body.package_sha256,
            "reward_adoption_sha256": digest(body),
            "effective_allocation_sha256": body.effective_allocation_sha256,
            "prior_opportunity_sha256": digest(body.early_release),
        }
    )
    assert verify_signed_early_release(adopted, **args, successor=successor, current_block=200)
    assert verify_signed_early_release(adopted, **args, successor=successor, current_block=10000)
    assert select_signed_early_release_revision(adopted, restored, **args) == adopted
    assert canonical_json_bytes(adopted.adoptions[-1]) == wire
