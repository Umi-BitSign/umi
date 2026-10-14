"""Signed timing, exact age boundary and native reader restart behavior."""

import json

import pytest

from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    verify_adoption_selection,
)
from umi.competition_reward_timing import (
    THREE_DAYS_MS,
    RewardActivationAge,
    activation_effective_block,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_adoption import adoption_case, revised, transition
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_competition_reward_decisions import (
    signatures,
)


def aged(c, *, delta=1, cohort=5):
    original, selection = adoption_case(c, revisions=1)
    if cohort != 5:
        original = c.decision(c.genesis, cohort, observed=200)
    old = selection.adoptions[0].adoption
    head = c.control.finality.ref.block_number
    age = RewardActivationAge(
        schema="umi-reward-activation-age/1",
        rule="skip_activation_delay_if_older_than_three_days",
        cohort_start_block=200,
        cohort_start_hash="a1" * 32,
        cohort_start_timestamp_ms=1000,
        start_evidence_sha256="a2" * 32,
        observed_at_block=head,
        observed_block_hash="b1" * 32,
        observed_timestamp_ms=1000 + THREE_DAYS_MS + delta,
        observation_evidence_sha256="b2" * 32,
    )
    body = RewardModelAdoption.model_validate(
        {
            **old.model_dump(by_alias=True),
            "schema": "umi-standing-model-reward-adoption/2",
            "cohort_sha256": original.decision.activation.cohort_sha256,
            "package_sha256": original.decision.activation.package_sha256,
            "allocation_sha256": original.decision.activation.allocation_sha256,
            "activation_age": age,
            "issued_at_block": head,
        }
    )
    adopted = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    selection = RewardAdoptionSelection(schema=selection.schema_, adoptions=(adopted,))
    return original, adopted, selection


@pytest.mark.parametrize("delta,skip", [(-1, False), (0, False), (1, True)])
async def test_age_boundary_current_native_selection_and_restart(series_case, delta, skip):
    c = series_case
    original, adoption, selection = aged(c, delta=delta)
    head = c.control.finality.ref.block_number
    active = transition(
        c, (c.genesis,), "activate", revised(original.decision.activation, adoption), observed=head
    )
    c.objects[digest(active.decision)] = canonical_json_bytes(active)
    c.reader = c.reopen(reward_adoptions=selection)
    selected = c.reader.select(await c.observe(active, block=head), c.source)
    assert selected.state == ("selected" if skip else "draining")
    assert selected.effective_at_block == head + (0 if skip else 160)
    assert selected.chain_submission_authorized is False
    c.reader = c.reopen(reward_adoptions=selection)
    after_restart = c.reader.select(await c.observe(active, block=head), lambda _: None)
    assert after_restart == selected


def test_original_serialization_and_old_timing_preserved(series_case):
    c = series_case
    original, old = adoption_case(c, revisions=1)
    raw = canonical_json_bytes(old.adoptions[0].adoption)
    assert "activation_age" not in json.loads(raw)
    assert canonical_json_bytes(RewardModelAdoption.model_validate_json(raw)) == raw
    _, _, new = aged(c)
    assert activation_effective_block(c.series, original.decision, 300, new) == 460


@pytest.mark.parametrize("cohort", [5, 6, 7, 10])
def test_same_rule_supports_every_selected_cohort(series_case, cohort):
    c = series_case
    original, adopted, selection = aged(c, cohort=cohort)
    head = c.control.finality.ref.block_number
    selected = verify_adoption_selection(selection, c.series, c.control.policy)
    decision = transition(
        c, (c.genesis,), "activate", revised(original.decision.activation, adopted), observed=head
    ).decision
    assert activation_effective_block(c.series, decision, head, selected) == head


def test_unsigned_age_change_is_rejected(series_case):
    c = series_case
    _, signed, selection = aged(c)
    changed = signed.adoption.model_copy(
        update={
            "activation_age": signed.adoption.activation_age.model_copy(
                update={"cohort_start_timestamp_ms": 999}
            )
        }
    )
    bad = selection.model_copy(
        update={"adoptions": (signed.model_copy(update={"adoption": changed}),)}
    )
    with pytest.raises(ValueError):
        verify_adoption_selection(bad, c.series, c.control.policy)


def test_wrong_start_or_future_observation_rejected(series_case):
    c = series_case
    _, signed, selection = aged(c)
    age = signed.adoption.activation_age.model_copy(update={"cohort_start_block": 199})
    body = signed.adoption.model_copy(update={"activation_age": age})
    bad = selection.model_copy(
        update={
            "adoptions": (SignedRewardModelAdoption(adoption=body, signatures=signatures(body)),)
        }
    )
    with pytest.raises(ValueError, match="signed cohort start"):
        verify_adoption_selection(bad, c.series, c.control.policy)
    age = signed.adoption.activation_age.model_copy(
        update={"observed_at_block": signed.adoption.issued_at_block + 1}
    )
    with pytest.raises(ValueError, match="ahead"):
        RewardModelAdoption.model_validate(
            {**signed.adoption.model_dump(by_alias=True), "activation_age": age}
        )


def test_legacy_schema_cannot_silently_gain_timing(series_case):
    _, signed, _ = aged(series_case)
    with pytest.raises(ValueError, match="versioned"):
        RewardModelAdoption.model_validate(
            {
                **signed.adoption.model_dump(by_alias=True),
                "schema": "umi-standing-model-reward-adoption/1",
            }
        )
