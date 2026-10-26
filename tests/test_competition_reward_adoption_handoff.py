"""A signed reward revision must reach coordinator and writer with one lineage."""

import json

import pytest

from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import RewardModelAdoption, SignedRewardModelAdoption
from umi.competition_reward_adoption_handoff import (
    WRITER_SUPPLEMENTAL_MODE,
    prepare_reward_adoption_boot_candidates,
)
from umi.competition_reward_boot import StandingRewardBootConfig
from umi.competition_reward_coordinator_boot import RewardCoordinatorConfig
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_competition_reward_decisions import signatures
from .test_open_competition import wallet


@pytest.fixture
def handoff(config_case, inputs):
    coordinator = config_case.config
    writer = inputs.value
    assert coordinator.series == writer.series
    body = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(coordinator.series),
        policy_sha256=digest(coordinator.policy),
        cohort_sha256=digest(coordinator.series.cohorts[1]),
        authority_sha256=digest(coordinator.series.recovery.authority),
        package_sha256="a1" * 32,
        allocation_sha256="a2" * 32,
        service_certificate_sha256="a3" * 32,
        quality_manifest_sha256="a4" * 32,
        effective_allocation_sha256="a5" * 32,
        parameters=GeometricRewardParameters(
            band_width_bps=250,
            band_decay_bps=7500,
            within_band_decay_bps=7500,
            score_duplicate_tolerance_bps=1,
        ),
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=coordinator.series.recovery.authority.issued_at_block,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    return canonical_json_bytes(coordinator), canonical_json_bytes(writer), signed


def test_candidate_handoff_changes_only_reward_selection_and_repeats_exactly(handoff):
    coordinator, writer, signed = handoff
    staged = prepare_reward_adoption_boot_candidates(coordinator, writer, signed)
    assert WRITER_SUPPLEMENTAL_MODE == 0o444
    assert staged.writer_supplemental == canonical_json_bytes(staged.selection)
    assert staged.selection.latest(signed.adoption.cohort_sha256) == signed
    for original, candidate, kind in (
        (coordinator, staged.coordinator, RewardCoordinatorConfig),
        (writer, staged.writer, StandingRewardBootConfig),
    ):
        old, new = json.loads(original), json.loads(candidate)
        assert {k for k in old.keys() | new.keys() if old.get(k) != new.get(k)} == {
            "reward_adoptions"
        }
        assert kind.model_validate_json(candidate).reward_adoptions == staged.selection
    repeated = prepare_reward_adoption_boot_candidates(staged.coordinator, staged.writer, signed)
    assert repeated == staged


def test_candidate_handoff_rejects_split_lineage_and_changed_signature(handoff):
    coordinator, writer, signed = handoff
    staged = prepare_reward_adoption_boot_candidates(coordinator, writer, signed)
    with pytest.raises(ValueError, match="disagree on signed reward lineage"):
        prepare_reward_adoption_boot_candidates(coordinator, staged.writer, signed)
    changed = signed.model_copy(
        update={
            "adoption": signed.adoption.model_copy(
                update={"effective_allocation_sha256": "ff" * 32}
            )
        }
    )
    with pytest.raises(ValueError):
        prepare_reward_adoption_boot_candidates(coordinator, writer, changed)


def test_candidate_handoff_refuses_noncanonical_input(handoff):
    coordinator, writer, signed = handoff
    with pytest.raises(ValueError, match="canonical installed boot"):
        prepare_reward_adoption_boot_candidates(b" " + coordinator, writer, signed)


def test_candidate_handoff_selects_matching_reviewer_and_refuses_split_lineage(handoff):
    coordinator, writer, signed = handoff
    original = json.loads(coordinator)
    reviewer = RewardCoordinatorConfig.model_validate_json(
        canonical_json_bytes(
            original
            | {
                "role": "reviewer",
                "signer_hotkey": wallet("Dave").hotkey.ss58_address,
                "signer_key_file": original["signer_key_file"] + "-reviewer",
                "control_key_file": None,
                "readback_directory": None,
                "settlement_directory": None,
                "state_directory": original["state_directory"] + "-reviewer",
                "exchange_inbox": original["exchange_inbox"] + "-reviewer",
                "exchange_outbox": original["exchange_outbox"] + "-reviewer",
            }
        )
    )
    reviewer_raw = canonical_json_bytes(reviewer)
    staged = prepare_reward_adoption_boot_candidates(
        coordinator, writer, signed, reviewer_raws=(reviewer_raw,)
    )
    assert len(staged.reviewers) == 1
    assert (
        RewardCoordinatorConfig.model_validate_json(staged.reviewers[0]).reward_adoptions
        == staged.selection
    )
    assert (
        prepare_reward_adoption_boot_candidates(
            staged.coordinator,
            staged.writer,
            signed,
            reviewer_raws=staged.reviewers,
        )
        == staged
    )
    with pytest.raises(ValueError, match="reviewer disagrees"):
        prepare_reward_adoption_boot_candidates(
            coordinator, writer, signed, reviewer_raws=staged.reviewers
        )
    with pytest.raises(ValueError, match="canonical installed boot"):
        prepare_reward_adoption_boot_candidates(
            coordinator, writer, signed, reviewer_raws=(b" " + reviewer_raw,)
        )
