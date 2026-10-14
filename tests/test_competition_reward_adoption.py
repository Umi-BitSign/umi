"""Forward authority and revision sequencing; no synthetic chain-live claims."""

import json

import pytest

from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    verify_adoption_selection,
    verify_reward_adoption,
)
from umi.competition_reward_decisions import (
    RewardActivation,
    RewardControlDecision,
    effective_activation_decision,
    original_activation_decision,
    verify_reward_decisions,
)
from umi.competition_reward_revision import validate_revision_clearance
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import (
    chain as chain,
)
from .test_competition_reward_decisions import (
    chain_config as chain_config,
)
from .test_competition_reward_decisions import (
    control as control,
)
from .test_competition_reward_decisions import (
    policy as policy,
)
from .test_competition_reward_decisions import (
    series_case as series_case,
)
from .test_competition_reward_decisions import (
    signatures,
    signed,
)


def adoption_case(c, *, revisions=2):
    original = c.decision(c.genesis, 5, observed=200)
    activation = original.decision.activation
    values = []
    for revision in range(1, revisions + 1):
        body = RewardModelAdoption(
            schema="umi-standing-model-reward-adoption/1",
            series_sha256=digest(c.series),
            policy_sha256=c.series.policy_sha256,
            cohort_sha256=activation.cohort_sha256,
            authority_sha256=digest(c.series.recovery.authority),
            package_sha256=activation.package_sha256,
            allocation_sha256=activation.allocation_sha256,
            service_certificate_sha256="a1" * 32,
            quality_manifest_sha256="a2" * 32,
            effective_allocation_sha256=f"{revision:064x}",
            parameters=GeometricRewardParameters(band_decay_bps=7500 + revision),
            revision=revision,
            predecessor_adoption_sha256=None if revision == 1 else digest(values[-1].adoption),
            issued_at_block=180 + revision,
            lifetime="until_first_verified_live_reward_then_locked",
        )
        values.append(SignedRewardModelAdoption(adoption=body, signatures=signatures(body)))
    selection = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1", adoptions=tuple(values)
    )
    return original, selection


def transition(c, prefix, kind, activation, *, clearance=None, observed=500):
    return signed(
        RewardControlDecision(
            schema="umi-reward-control-decision/3",
            series_sha256=digest(c.series),
            sequence=len(prefix),
            predecessor_sha256=digest(prefix[-1].decision),
            kind=kind,
            observed_at_block=observed,
            activation=activation,
            revision_clearance_sha256=clearance,
        )
    )


def revised(original, adoption):
    return original.model_copy(
        update={
            "reward_adoption_sha256": digest(adoption.adoption),
            "effective_allocation_sha256": adoption.adoption.effective_allocation_sha256,
        }
    )


def test_legacy_signed_serialization_is_unchanged(series_case):
    c = series_case
    old, _ = adoption_case(c)
    raw = json.loads(canonical_json_bytes(old.decision))
    assert set(raw["activation"]) == {
        "cohort_sha256",
        "allocation_sha256",
        "package_sha256",
        "recovery_tip_sha256",
        "prior_opportunity_sha256",
    }
    assert "revision_clearance_sha256" not in raw
    assert canonical_json_bytes(RewardControlDecision.model_validate(raw)) == canonical_json_bytes(
        old.decision
    )


def test_independent_parameters_are_authenticated_and_original_evidence_is_fixed(series_case):
    c = series_case
    original, selection = adoption_case(c)
    assert verify_adoption_selection(selection, c.series, c.control.policy) == selection
    value = selection.adoptions[0]
    active = revised(original.decision.activation, value)
    assert (
        verify_reward_adoption(
            selection,
            digest(value.adoption),
            series=c.series,
            policy=c.control.policy,
            activation=active,
            current_block=200,
        )
        == value.adoption
    )
    changed = value.adoption.model_copy(
        update={"parameters": GeometricRewardParameters(within_band_decay_bps=8000)}
    )
    bad = selection.model_copy(
        update={"adoptions": (value.model_copy(update={"adoption": changed}),)}
    )
    with pytest.raises(ValueError):
        verify_adoption_selection(bad, c.series, c.control.policy)
    with pytest.raises(ValueError, match="ahead"):
        verify_reward_adoption(
            selection,
            digest(value.adoption),
            series=c.series,
            policy=c.control.policy,
            current_block=180,
        )


def test_lineage_cannot_drop_or_rewrite_a_signed_predecessor(series_case):
    _, selection = adoption_case(series_case)
    with pytest.raises(ValueError, match="original revision"):
        RewardAdoptionSelection(schema=selection.schema_, adoptions=selection.adoptions[1:])
    changed = selection.adoptions[1].adoption.model_copy(update={"allocation_sha256": "ff" * 32})
    with pytest.raises(ValueError, match="original evidence"):
        RewardAdoptionSelection(
            schema=selection.schema_,
            adoptions=(
                selection.adoptions[0],
                selection.adoptions[1].model_copy(update={"adoption": changed}),
            ),
        )


def test_revision_appends_after_suspension_without_replacing_prior_decisions(series_case):
    c = series_case
    original, selection = adoption_case(c)
    prefix = (c.genesis, original)
    saved = tuple(canonical_json_bytes(v) for v in prefix)
    suspended = transition(c, prefix, "suspend_activation", original.decision.activation)
    prefix += (suspended,)
    target = revised(original.decision.activation, selection.adoptions[-1])
    revision = transition(c, prefix, "revise_activation", target, clearance="c1" * 32)
    prefix += (revision,)
    assert (
        verify_reward_decisions(c.series, c.control.policy, prefix, reward_adoptions=selection)
        == prefix
    )
    assert tuple(canonical_json_bytes(v) for v in prefix[:2]) == saved
    assert original_activation_decision(prefix, target.cohort_sha256) == original.decision
    assert effective_activation_decision(prefix) == revision.decision
    with pytest.raises(ValueError, match=r"authority|order"):
        verify_reward_decisions(c.series, c.control.policy, prefix)
    with pytest.raises(ValueError, match="native finalized clearance"):
        validate_revision_clearance(
            object(), decision=revision.decision, prefix=prefix[:-1], series=c.series
        )


def test_unsigned_or_direct_revision_and_false_resume_are_refused(series_case):
    c = series_case
    original, selection = adoption_case(c)
    prefix = (c.genesis, original)
    target = revised(original.decision.activation, selection.adoptions[0])
    direct = transition(c, prefix, "revise_activation", target, clearance="c1" * 32)
    with pytest.raises(ValueError, match="suspension"):
        verify_reward_decisions(
            c.series, c.control.policy, (*prefix, direct), reward_adoptions=selection
        )
    suspended = transition(c, prefix, "suspend_activation", original.decision.activation)
    prefix += (suspended,)
    false_resume = transition(c, prefix, "resume_activation", target)
    with pytest.raises(ValueError, match="resume"):
        verify_reward_decisions(
            c.series, c.control.policy, (*prefix, false_resume), reward_adoptions=selection
        )
    resumed = transition(c, prefix, "resume_activation", original.decision.activation)
    assert verify_reward_decisions(
        c.series, c.control.policy, (*prefix, resumed), reward_adoptions=selection
    )


def test_revision_slots_do_not_consume_or_reorder_cohorts(series_case):
    c = series_case
    original, selection = adoption_case(c, revisions=5)
    prefix = (c.genesis, original)
    for adoption in selection.adoptions:
        old = effective_activation_decision(prefix).activation
        prefix += (transition(c, prefix, "suspend_activation", old),)
        prefix += (
            transition(c, prefix, "revise_activation", revised(old, adoption), clearance="c1" * 32),
        )
    assert len(prefix) > len(c.series.cohorts) + 2
    assert verify_reward_decisions(c.series, c.control.policy, prefix, reward_adoptions=selection)
    next_cohort = c.decision(prefix[-1], 6, observed=600)
    assert verify_reward_decisions(
        c.series, c.control.policy, (*prefix, next_cohort), reward_adoptions=selection
    )


def test_incomplete_effective_activation_pair_refused(series_case):
    original, _ = adoption_case(series_case)
    with pytest.raises(ValueError, match="authenticated adoption"):
        RewardActivation.model_validate(
            {**original.decision.activation.model_dump(), "reward_adoption_sha256": "ff" * 32}
        )
