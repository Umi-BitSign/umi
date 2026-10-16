"""Exact authenticated runtime scopes preserve original authority and old bytes."""

import json
from dataclasses import replace

import pytest

from umi.competition_reward_boot import StandingRewardBootConfig
from umi.competition_reward_coverage_intervals import CoveragePoint
from umi.competition_reward_eligibility import RewardEligibilityRuntime
from umi.competition_reward_runtime_adoption import (
    RewardRuntimeAdoption,
    RewardRuntimeAdoptionSelection,
    SelectedRewardRuntime,
    SignedRewardRuntimeAdoption,
    extend_boot_runtime_adoptions,
    select_boot_runtime,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import chain as chain
from .test_competition_reward_boot import chain_config as chain_config
from .test_competition_reward_boot import control as control
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_boot import policy as policy
from .test_competition_reward_boot import series_case as series_case
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_coverage_intervals import point
from .test_competition_reward_decisions import signatures


@pytest.fixture
def adopted(inputs, monkeypatch):
    config = inputs.value
    profile = RewardEligibilityRuntime(
        schema="umi-reward-eligibility-runtime/2",
        genesis_hash=config.eligibility.genesis_hash,
        netuid=78,
        runtime_code_sha256="a9" * 32,
        epoch_source_revision="f4786f9087cac84cfab37cbdf1e01c399042653a",
    )
    monkeypatch.setattr(
        "umi.competition_reward_eligibility._QUALIFIED_YUMA_RUNTIMES",
        frozenset({(profile.runtime_code_sha256, profile.epoch_source_revision)}),
    )
    first = config.series.recovery.authority.issued_at_block + 10
    body = RewardRuntimeAdoption(
        schema="umi-standing-reward-runtime-adoption/1",
        series_sha256=digest(config.series),
        manifest_sha256=digest(config.manifest),
        policy_sha256=digest(config.policy),
        authority_sha256=digest(config.series.recovery.authority),
        original_runtime_profile_sha256=digest(config.eligibility),
        effective_profile=profile,
        first_block=first,
        last_block=first + 100,
        issued_at_block=first + 20,
        revision=1,
        predecessor_adoption_sha256=None,
        original_signed_inputs_unchanged=True,
    )
    selection = RewardRuntimeAdoptionSelection(
        schema="umi-standing-reward-runtime-adoption-selection/1",
        adoptions=(SignedRewardRuntimeAdoption(adoption=body, signatures=signatures(body)),),
    )
    return config.model_copy(update={"runtime_adoptions": selection})


def test_original_boot_and_point_bytes_are_unchanged(inputs):
    original = canonical_json_bytes(inputs.value)
    parsed = StandingRewardBootConfig.model_validate_json(original)
    assert canonical_json_bytes(parsed) == original
    assert "runtime_adoptions" not in json.loads(original)
    assert "predecessor_runtime_adoptions" not in json.loads(original)
    assert select_boot_runtime(parsed) is None
    old = point()
    raw = canonical_json_bytes(old)
    assert "runtime_adoption_sha256" not in json.loads(raw)
    assert "effective_runtime_profile_sha256" not in json.loads(raw)
    assert canonical_json_bytes(CoveragePoint.model_validate_json(raw)) == raw


def test_adoption_preserves_signed_series_and_selects_only_exact_scoped_profile(inputs, adopted):
    parsed = StandingRewardBootConfig.model_validate_json(canonical_json_bytes(adopted))
    for name in ("series", "policy", "manifest", "handoff", "eligibility"):
        assert canonical_json_bytes(getattr(parsed, name)) == canonical_json_bytes(
            getattr(inputs.value, name)
        )
    context = select_boot_runtime(parsed)
    body = parsed.runtime_adoptions.adoptions[0].adoption
    assert context.selected(body.first_block - 1) == (inputs.value.eligibility, None)
    assert context.selected(body.first_block) == (body.effective_profile, digest(body))
    assert context.selected(body.last_block) == (body.effective_profile, digest(body))
    assert context.selected(body.last_block + 1) == (inputs.value.eligibility, None)
    # A native completed original is never silently relabelled under a later adoption.
    assert (
        context.check(
            block=body.first_block,
            profile_sha256=digest(inputs.value.eligibility),
            adoption_sha256=None,
        )
        == inputs.value.eligibility
    )


@pytest.mark.parametrize(
    "field",
    [
        "series_sha256",
        "manifest_sha256",
        "policy_sha256",
        "authority_sha256",
        "original_runtime_profile_sha256",
    ],
)
def test_even_signed_foreign_authority_is_refused(adopted, field):
    body = adopted.runtime_adoptions.adoptions[0].adoption.model_copy(update={field: "fe" * 32})
    selection = adopted.runtime_adoptions.model_copy(
        update={
            "adoptions": (SignedRewardRuntimeAdoption(adoption=body, signatures=signatures(body)),)
        }
    )
    with pytest.raises(ValueError, match="standing authority"):
        select_boot_runtime(adopted.model_copy(update={"runtime_adoptions": selection}))


def test_unsigned_replacement_and_unqualified_runtime_are_refused(adopted, monkeypatch):
    signed = adopted.runtime_adoptions.adoptions[0]
    changed = signed.model_copy(
        update={"adoption": signed.adoption.model_copy(update={"last_block": 9999})}
    )
    with pytest.raises(ValueError):
        select_boot_runtime(
            adopted.model_copy(
                update={
                    "runtime_adoptions": adopted.runtime_adoptions.model_copy(
                        update={"adoptions": (changed,)}
                    )
                }
            )
        )
    monkeypatch.setattr("umi.competition_reward_eligibility._QUALIFIED_YUMA_RUNTIMES", frozenset())
    with pytest.raises(ValueError, match="qualified runtime"):
        select_boot_runtime(adopted)


def test_adoption_lineage_cannot_change_earlier_scope_or_omit_parent(adopted):
    original = adopted.runtime_adoptions.adoptions[0]
    body = original.adoption
    second = body.model_copy(
        update={
            "revision": 2,
            "first_block": body.last_block + 1,
            "last_block": body.last_block + 100,
            "predecessor_adoption_sha256": digest(body),
        }
    )
    for delta in (
        {},
        {"first_block": body.last_block},
        {"revision": 3},
        {"predecessor_adoption_sha256": "f1" * 32},
        {"manifest_sha256": "f2" * 32},
    ):
        changed = second.model_copy(update=delta)
        raw = canonical_json_bytes(
            adopted.runtime_adoptions.model_copy(
                update={
                    "adoptions": (
                        original,
                        SignedRewardRuntimeAdoption(
                            adoption=changed, signatures=signatures(changed)
                        ),
                    )
                }
            )
        )
        if delta:
            with pytest.raises(ValueError):
                RewardRuntimeAdoptionSelection.model_validate_json(raw)
        else:
            assert RewardRuntimeAdoptionSelection.model_validate_json(raw).adoptions[0] == original


def test_selection_cannot_be_forged_or_rebound(adopted):
    context = select_boot_runtime(adopted)
    for changed in (
        replace(context, policy_sha256="f3" * 32),
        SelectedRewardRuntime(
            context.original_profile,
            context.selection,
            context.series_sha256,
            context.manifest_sha256,
            context.policy_sha256,
        ),
    ):
        with pytest.raises(ValueError, match="provenance"):
            changed.selected(1)
    body = adopted.runtime_adoptions.adoptions[0].adoption
    for delta in (
        {"profile_sha256": "fe" * 32},
        {"adoption_sha256": "fd" * 32},
        {"block": body.last_block + 1},
    ):
        values = {
            "block": body.first_block,
            "profile_sha256": digest(body.effective_profile),
            "adoption_sha256": digest(body),
            **delta,
        }
        with pytest.raises(ValueError, match="block selection"):
            context.check(**values)


def test_upgrade_preparation_is_additive_repeatable_and_reports_progress(inputs, adopted, caplog):
    with caplog.at_level("INFO", logger="umi.competition.progress"):
        first = extend_boot_runtime_adoptions(inputs.value, adopted.runtime_adoptions)
        second = extend_boot_runtime_adoptions(first, adopted.runtime_adoptions)
    assert (
        canonical_json_bytes(first) == canonical_json_bytes(second) == canonical_json_bytes(adopted)
    )
    assert "reward_runtime_adoption_prepare" in caplog.text
    body = adopted.runtime_adoptions.adoptions[0].adoption.model_copy(update={"last_block": 9999})
    replaced = adopted.runtime_adoptions.model_copy(
        update={
            "adoptions": (SignedRewardRuntimeAdoption(adoption=body, signatures=signatures(body)),)
        }
    )
    with pytest.raises(ValueError, match="retained signed adoption lineage"):
        extend_boot_runtime_adoptions(first, replaced)
    with pytest.raises(ValueError, match="original series"):
        extend_boot_runtime_adoptions(inputs.value, adopted.runtime_adoptions, predecessor=True)


def test_successor_boot_preserves_original_runtime_adoption_for_predecessor(inputs, adopted):
    from .test_competition_reward_boot import successor_boot

    successor, _ = successor_boot(inputs)
    candidate = extend_boot_runtime_adoptions(
        successor, adopted.runtime_adoptions, predecessor=True
    )
    assert select_boot_runtime(candidate) is None
    assert select_boot_runtime(candidate, predecessor=True) == select_boot_runtime(adopted)
    assert canonical_json_bytes(candidate.series) == canonical_json_bytes(successor.series)
    assert canonical_json_bytes(candidate.predecessor_series) == canonical_json_bytes(
        inputs.value.series
    )


async def test_writer_native_assembly_receives_authenticated_runtime_selection(
    inputs, adopted, monkeypatch
):
    from .test_competition_reward_boot import (
        test_native_assembly_preserves_configuration_and_closes_owned_providers,
    )

    inputs.value = adopted
    await test_native_assembly_preserves_configuration_and_closes_owned_providers(
        inputs, monkeypatch, None, False
    )


@pytest.mark.parametrize("role", ["coordinator", "reviewer"])
async def test_coordinator_and_reviewer_assembly_receive_runtime_selection(
    config_case, adopted, monkeypatch, role
):
    from .test_competition_reward_coordinator_boot import (
        test_boot_loads_only_role_keys_and_closes_provider_on_every_exit,
    )

    config_case.config = extend_boot_runtime_adoptions(
        config_case.config, adopted.runtime_adoptions
    )
    await test_boot_loads_only_role_keys_and_closes_provider_on_every_exit(
        config_case, monkeypatch, role, None, False, successor=False
    )
