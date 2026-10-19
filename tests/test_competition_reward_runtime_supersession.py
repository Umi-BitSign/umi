"""Explicit code supersession retains every signed scope and completed identity."""

import json

import pytest

from umi.competition_reward_boot import StandingRewardBootConfig
from umi.competition_reward_eligibility import RewardEligibilityRuntime
from umi.competition_reward_runtime_adoption import (
    RewardRuntimeAdoption,
    RewardRuntimeAdoptionSelection,
    SignedRewardRuntimeAdoption,
    extend_boot_runtime_adoptions,
    select_boot_runtime,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import signatures
from .test_competition_reward_runtime_adoption import chain as chain
from .test_competition_reward_runtime_adoption import chain_config as chain_config
from .test_competition_reward_runtime_adoption import control as control
from .test_competition_reward_runtime_adoption import inputs as inputs
from .test_competition_reward_runtime_adoption import policy as policy
from .test_competition_reward_runtime_adoption import series_case as series_case


def profile(config, version):
    code, source = {
        479: (
            "d0ea4955e6b4366d8561038307d5e47572c1ad67664638402c8253cde26a84be",
            "f4786f9087cac84cfab37cbdf1e01c399042653a",
        ),
        481: (
            "48225f3199bf317966d0214588bc45fb49c28c3e7bd510293bb4da7d6aea224b",
            "6a972693ae9580541225bd37696ac2fee26b8ae9",
        ),
    }[version]
    return RewardEligibilityRuntime(
        schema="umi-reward-eligibility-runtime/2",
        genesis_hash=config.eligibility.genesis_hash,
        netuid=78,
        runtime_code_sha256=code,
        epoch_source_revision=source,
    )


def signed(body):
    return SignedRewardRuntimeAdoption(adoption=body, signatures=signatures(body))


@pytest.fixture
def superseded(inputs):
    config = inputs.value
    first = config.series.recovery.authority.issued_at_block + 10
    old = RewardRuntimeAdoption(
        schema="umi-standing-reward-runtime-adoption/1",
        series_sha256=digest(config.series),
        manifest_sha256=digest(config.manifest),
        policy_sha256=digest(config.policy),
        authority_sha256=digest(config.series.recovery.authority),
        original_runtime_profile_sha256=digest(config.eligibility),
        effective_profile=profile(config, 479),
        first_block=first,
        last_block=first + 1000,
        issued_at_block=first,
        revision=1,
        predecessor_adoption_sha256=None,
        original_signed_inputs_unchanged=True,
    )
    new = RewardRuntimeAdoption.model_validate_json(
        canonical_json_bytes(
            old.model_copy(
                update={
                    "schema_": "umi-standing-reward-runtime-adoption/2",
                    "effective_profile": profile(config, 481),
                    "first_block": first + 100,
                    "issued_at_block": first + 200,
                    "revision": 2,
                    "predecessor_adoption_sha256": digest(old),
                    "supersedes_adoption_sha256": digest(old),
                }
            )
        )
    )
    selection = RewardRuntimeAdoptionSelection(
        schema="umi-standing-reward-runtime-adoption-selection/3",
        adoptions=(signed(old), signed(new)),
    )
    return config, old, new, selection


def selected_config(config, selection):
    return config.model_copy(update={"runtime_adoptions": selection})


def test_explicit_supersession_selects_exact_new_window_without_changing_old_bytes(superseded):
    config, old, new, selection = superseded
    raw = canonical_json_bytes(selection)
    parsed = RewardRuntimeAdoptionSelection.model_validate_json(raw)
    assert canonical_json_bytes(parsed) == raw
    old_raw = canonical_json_bytes(old)
    assert "supersedes_adoption_sha256" not in json.loads(old_raw)
    assert canonical_json_bytes(parsed.adoptions[0].adoption) == old_raw
    native = select_boot_runtime(selected_config(config, parsed))
    for block in [old.first_block, new.first_block - 1]:
        assert native.selected(block) == (old.effective_profile, digest(old))
    for block in [new.first_block, new.last_block]:
        assert native.selected(block) == (new.effective_profile, digest(new))
    assert native.selected(new.last_block + 1) == (config.eligibility, None)


@pytest.mark.parametrize("schema", ["/1", "/2"])
def test_legacy_selection_formats_preserve_exact_bytes_and_refuse_supersession(superseded, schema):
    _config, old, new, _selection = superseded
    value = {
        "schema": "umi-standing-reward-runtime-adoption-selection" + schema,
        "adoptions": [signed(old).model_dump(mode="json", by_alias=True)],
    }
    raw = canonical_json_bytes(value)
    assert canonical_json_bytes(RewardRuntimeAdoptionSelection.model_validate_json(raw)) == raw
    value["adoptions"].append(signed(new).model_dump(mode="json", by_alias=True))
    with pytest.raises(ValueError):
        RewardRuntimeAdoptionSelection.model_validate_json(canonical_json_bytes(value))


def test_actual_native_upgrade_retains_prefix_clocks_and_repeatability(superseded):
    config, _old, new, selection = superseded
    prior = RewardRuntimeAdoptionSelection(
        schema="umi-standing-reward-runtime-adoption-selection/2",
        adoptions=(selection.adoptions[0],),
    )
    original = selected_config(config, prior)
    raw = canonical_json_bytes(original)
    candidate = extend_boot_runtime_adoptions(original, selection)
    assert canonical_json_bytes(
        extend_boot_runtime_adoptions(candidate, selection)
    ) == canonical_json_bytes(candidate)
    assert canonical_json_bytes(candidate.model_copy(update={"runtime_adoptions": prior})) == raw
    parsed = StandingRewardBootConfig.model_validate_json(canonical_json_bytes(candidate))
    assert select_boot_runtime(parsed).selected(new.first_block) == (
        new.effective_profile,
        digest(new),
    )


@pytest.mark.parametrize(
    "change",
    [
        "unknown_target",
        "earlier_start",
        "later_end",
        "same_code",
        "no_explicit_version",
        "no_explicit_target",
    ],
)
def test_supersession_cannot_extend_clocks_or_infer_a_target(superseded, change):
    _config, old, new, selection = superseded
    update = {
        "unknown_target": {"supersedes_adoption_sha256": "ff" * 32},
        "earlier_start": {"first_block": old.first_block - 1},
        "later_end": {"last_block": old.last_block + 1},
        "same_code": {"effective_profile": old.effective_profile},
        "no_explicit_version": {"schema_": "umi-standing-reward-runtime-adoption/1"},
        "no_explicit_target": {"supersedes_adoption_sha256": None},
    }[change]
    body = new.model_copy(update=update)
    with pytest.raises(ValueError):
        value = selection.model_copy(update={"adoptions": (selection.adoptions[0], signed(body))})
        RewardRuntimeAdoptionSelection.model_validate_json(canonical_json_bytes(value))


def test_current_selection_and_retained_proofs_keep_distinct_profile_identities(superseded):
    config, old, new, selection = superseded
    native = select_boot_runtime(selected_config(config, selection))
    block = new.first_block + 1
    assert native.selected(block) == (new.effective_profile, digest(new))
    assert (
        native.check(
            block=block, profile_sha256=digest(old.effective_profile), adoption_sha256=digest(old)
        )
        == old.effective_profile
    )
    assert (
        native.check(
            block=block, profile_sha256=digest(new.effective_profile), adoption_sha256=digest(new)
        )
        == new.effective_profile
    )
    for kwargs in [
        dict(
            block=old.last_block + 1,
            profile_sha256=digest(old.effective_profile),
            adoption_sha256=digest(old),
        ),
        dict(
            block=block, profile_sha256=digest(new.effective_profile), adoption_sha256=digest(old)
        ),
    ]:
        with pytest.raises(ValueError):
            native.check(**kwargs)


def test_signature_covers_new_scope_even_when_structural_target_still_valid(superseded):
    config, _old, new, selection = superseded
    changed = new.model_copy(update={"first_block": new.first_block + 1})
    stale = selection.adoptions[1].model_copy(update={"adoption": changed})
    value = selection.model_copy(update={"adoptions": (selection.adoptions[0], stale)})
    with pytest.raises(ValueError):
        select_boot_runtime(selected_config(config, value))


def test_nested_code_upgrade_retains_ancestors_and_refuses_branching_overlap(superseded):
    config, old, new, selection = superseded
    reverted = new.model_copy(
        update={
            "effective_profile": old.effective_profile,
            "first_block": new.first_block + 1,
            "revision": 3,
            "issued_at_block": new.issued_at_block + 1,
            "predecessor_adoption_sha256": digest(new),
            "supersedes_adoption_sha256": digest(new),
        }
    )
    value = selection.model_copy(update={"adoptions": (*selection.adoptions, signed(reverted))})
    native = select_boot_runtime(selected_config(config, value))
    assert native.selected(reverted.first_block) == (old.effective_profile, digest(reverted))
    wrong = reverted.model_copy(
        update={
            "effective_profile": new.effective_profile,
            "supersedes_adoption_sha256": digest(old),
        }
    )
    with pytest.raises(ValueError, match="unrelated"):
        RewardRuntimeAdoptionSelection.model_validate_json(
            canonical_json_bytes(
                selection.model_copy(update={"adoptions": (*selection.adoptions, signed(wrong))})
            )
        )


def test_unversioned_overlap_is_never_accepted_in_new_wrapper(superseded):
    _config, _old, new, selection = superseded
    body = new.model_copy(
        update={
            "schema_": "umi-standing-reward-runtime-adoption/1",
            "supersedes_adoption_sha256": None,
        }
    )
    with pytest.raises(ValueError, match="explicit"):
        RewardRuntimeAdoptionSelection.model_validate_json(
            canonical_json_bytes(
                selection.model_copy(update={"adoptions": (selection.adoptions[0], signed(body))})
            )
        )


def test_successor_predecessor_upgrade_preserves_each_signed_series_and_clocks(inputs, superseded):
    from .test_competition_reward_boot import successor_boot

    _original, _old, new, selection = superseded
    successor, _ = successor_boot(inputs)
    candidate = extend_boot_runtime_adoptions(successor, selection, predecessor=True)
    assert select_boot_runtime(candidate) is None
    assert select_boot_runtime(candidate, predecessor=True).selected(new.first_block) == (
        new.effective_profile,
        digest(new),
    )
    restored = candidate.model_copy(
        update={"predecessor_runtime_adoptions": successor.predecessor_runtime_adoptions}
    )
    assert canonical_json_bytes(restored) == canonical_json_bytes(successor)
