"""Authenticated optional reward economics at unchanged native owner boundaries."""

from types import SimpleNamespace

import pytest

from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
)
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_reward_boot as writer
from . import test_competition_reward_coordinator_boot as coordinator
from .test_competition_reward_boot import chain as chain
from .test_competition_reward_boot import chain_config as chain_config
from .test_competition_reward_boot import control as control
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_boot import policy as policy
from .test_competition_reward_boot import series_case as series_case
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_open_competition import wallet


def selected_adoption(config, *, series=None, timing=False):
    series = series or config.series
    body = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(series),
        policy_sha256=digest(config.policy),
        cohort_sha256=digest(series.cohorts[0]),
        authority_sha256=digest(series.recovery.authority),
        package_sha256="a1" * 32,
        allocation_sha256="a2" * 32,
        service_certificate_sha256="a3" * 32,
        quality_manifest_sha256="a4" * 32,
        effective_allocation_sha256="a5" * 32,
        parameters=GeometricRewardParameters(),
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=series.recovery.authority.issued_at_block,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    if timing:
        from umi.competition_reward_timing import THREE_DAYS_MS, RewardActivationAge

        start = series.cohorts[0].not_before_block
        body = RewardModelAdoption.model_validate(
            {
                **body.model_dump(by_alias=True),
                "schema": "umi-standing-model-reward-adoption/2",
                "issued_at_block": start + 1,
                "activation_age": RewardActivationAge(
                    schema="umi-reward-activation-age/1",
                    rule="skip_activation_delay_if_older_than_three_days",
                    cohort_start_block=start,
                    cohort_start_hash="c1" * 32,
                    cohort_start_timestamp_ms=1,
                    start_evidence_sha256="c2" * 32,
                    observed_at_block=start + 1,
                    observed_block_hash="d1" * 32,
                    observed_timestamp_ms=THREE_DAYS_MS + 2,
                    observation_evidence_sha256="d2" * 32,
                ),
            }
        )
    signed = SignedRewardModelAdoption(
        adoption=body,
        signatures=tuple(
            sorted(
                (sign_object(body, wallet(name)) for name in ("Charlie", "Dave")),
                key=lambda value: identity(value.hotkey),
            )
        ),
    )
    return RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1", adoptions=(signed,)
    )


@pytest.mark.parametrize("role", ["writer", "coordinator"])
@pytest.mark.parametrize("timing", [False, True])
def test_optional_adoption_preserves_old_bytes_and_original_state(
    inputs, config_case, role, timing
):
    original = inputs.value if role == "writer" else config_case.config
    raw = canonical_json_bytes(original)
    assert b'"reward_adoptions"' not in raw
    assert b'"predecessor_reward_adoptions"' not in raw
    selected = original.model_copy(
        update={"reward_adoptions": selected_adoption(original, timing=timing)}
    )
    checked = type(original).model_validate_json(canonical_json_bytes(selected))
    assert checked.reward_adoptions == selected.reward_adoptions
    assert canonical_json_bytes(checked.model_copy(update={"reward_adoptions": None})) == raw
    assert digest(checked.series) == digest(original.series)
    assert checked.chain.state_directory == original.chain.state_directory
    if role == "writer":
        # Original immutable host approval and execution binding are retained;
        # the root-owned boot explicitly selects this separately signed overlay.
        inputs.save(inputs.path, canonical_json_bytes(checked))
        assert writer.boot.load_standing_boot(inputs.path, inputs.anchor) == checked
    else:
        assert checked.state_directory == original.state_directory
        config_case.save(config_case.path, canonical_json_bytes(checked))
        assert coordinator.boot.load_reward_coordinator_config(config_case.path) == checked


@pytest.mark.parametrize("role", ["writer", "coordinator"])
@pytest.mark.parametrize("change", ["signature", "series", "orphan_predecessor"])
def test_bad_adoption_fails_before_owner_construction(inputs, config_case, role, change):
    original = inputs.value if role == "writer" else config_case.config
    value = selected_adoption(original)
    if change == "signature":
        signed = value.adoptions[0]
        value = value.model_copy(
            update={"adoptions": (signed.model_copy(update={"signatures": signed.signatures[:1]}),)}
        )
    elif change == "series":
        signed = value.adoptions[0]
        value = value.model_copy(
            update={
                "adoptions": (
                    signed.model_copy(
                        update={
                            "adoption": signed.adoption.model_copy(
                                update={"series_sha256": "ff" * 32}
                            )
                        }
                    ),
                )
            }
        )
    name = "predecessor_reward_adoptions" if change == "orphan_predecessor" else "reward_adoptions"
    with pytest.raises(ValueError):
        type(original).model_validate_json(
            canonical_json_bytes(original.model_copy(update={name: value}))
        )


@pytest.mark.parametrize("role", ["coordinator", "reviewer"])
async def test_native_coordinator_assembly_keeps_selected_adoption(config_case, monkeypatch, role):
    original = config_case.config
    selected = original.model_copy(update={"reward_adoptions": selected_adoption(original)})
    observed = []
    native_reader = coordinator.boot.StandingRewardControlReader
    native_signer = coordinator.boot.RewardDecisionJournal
    native_offers = coordinator.boot.StandingRewardOffers

    def reader(*args, **kwargs):
        result = native_reader(*args, **kwargs)
        observed.append(("reader", result.reward_adoptions))
        return result

    def signer(*args, **kwargs):
        result = native_signer(*args, **kwargs)
        observed.append(("signer", result.reward_adoptions))
        return result

    def offers(*args, **kwargs):
        result = native_offers(*args, **kwargs)
        observed.append(("offers", result.reward_adoptions))
        return result

    monkeypatch.setattr(coordinator.boot, "StandingRewardControlReader", reader)
    monkeypatch.setattr(coordinator.boot, "RewardDecisionJournal", signer)
    monkeypatch.setattr(coordinator.boot, "StandingRewardOffers", offers)
    case = SimpleNamespace(**(vars(config_case) | {"config": selected}))
    await coordinator.test_boot_loads_only_role_keys_and_closes_provider_on_every_exit(
        case, monkeypatch, role, None, False
    )
    assert {name for name, _ in observed} == (
        {"reader", "signer", "offers"} if role == "coordinator" else {"reader", "signer"}
    )
    assert all(value == selected.reward_adoptions for _, value in observed)


async def test_native_writer_assembly_keeps_selected_adoption(inputs, monkeypatch):
    selected = inputs.value.model_copy(update={"reward_adoptions": selected_adoption(inputs.value)})
    observed = []
    native_reader = writer.boot.StandingRewardControlReader

    def reader(*args, **kwargs):
        result = native_reader(*args, **kwargs)
        observed.append(result.reward_adoptions)
        return result

    monkeypatch.setattr(writer.boot, "StandingRewardControlReader", reader)
    case = SimpleNamespace(**(vars(inputs) | {"value": selected}))
    await writer.test_native_assembly_preserves_configuration_and_closes_owned_providers(
        case, monkeypatch, None, False
    )
    assert observed == [selected.reward_adoptions]


def test_predecessor_adoption_binds_its_own_series(inputs):
    candidate, _ = writer.successor_boot(inputs)
    current = selected_adoption(candidate)
    previous = selected_adoption(candidate, series=candidate.predecessor_series)
    selected = candidate.model_copy(
        update={
            "reward_adoptions": current,
            "predecessor_reward_adoptions": previous,
        }
    )
    assert type(candidate).model_validate_json(canonical_json_bytes(selected)) == selected
    for change in (
        {"reward_adoptions": previous},
        {"predecessor_reward_adoptions": current},
    ):
        with pytest.raises(ValueError):
            type(candidate).model_validate_json(
                canonical_json_bytes(selected.model_copy(update=change))
            )


async def test_successor_writer_assembly_retains_both_economic_lineages(inputs, monkeypatch):
    candidate, approval = writer.successor_boot(inputs)
    current = selected_adoption(candidate)
    previous = selected_adoption(candidate, series=candidate.predecessor_series)
    candidate = candidate.model_copy(
        update={
            "reward_adoptions": current,
            "predecessor_reward_adoptions": previous,
        }
    )
    monkeypatch.setattr(writer, "successor_boot", lambda _: (candidate, approval))
    native_reader = writer.boot.StandingRewardControlReader
    observed = []

    def reader(*args, **kwargs):
        result = native_reader(*args, **kwargs)
        observed.append((digest(result.series), result.reward_adoptions))
        return result

    monkeypatch.setattr(writer.boot, "StandingRewardControlReader", reader)
    await writer.test_successor_native_assembly_reconstructs_predecessor_owners(inputs, monkeypatch)
    assert observed == [
        (digest(candidate.series), current),
        (digest(candidate.predecessor_series), previous),
    ]
