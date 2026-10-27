"""A signed reward revision must reach coordinator and writer with one lineage."""

import json

import pytest

from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import (
    RewardEarlyRelease,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    prepare_activation_age_revision,
)
from umi.competition_reward_adoption_handoff import (
    REFERENCE_PUBLISHER_CONFIG_MODE,
    WRITER_SUPPLEMENTAL_MODE,
    prepare_reward_adoption_boot_candidates,
)
from umi.competition_reward_boot import StandingRewardBootConfig
from umi.competition_reward_coordinator_boot import RewardCoordinatorConfig
from umi.competition_reward_decisions import RewardActivation, RewardControlDecision
from umi.competition_reward_opportunity import prepare_early_release_revision
from umi.competition_reward_timing import RewardActivationAge, activation_effective_block
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.translation_reference_config import ReferencePublisherConfig

from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_competition_reward_decisions import signatures
from .test_open_competition import wallet
from .test_translation_reference_channel import channel_case as channel_case
from .test_translation_reference_channel import publication_case as publication_case
from .test_translation_reference_config import installed as installed


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


def test_early_release_revision_uses_same_consumer_handoff(handoff):
    coordinator, writer, initial = handoff
    staged = prepare_reward_adoption_boot_candidates(coordinator, writer, initial)
    config = RewardCoordinatorConfig.model_validate_json(staged.coordinator)
    predecessor = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(config.series),
        sequence=1,
        predecessor_sha256="10" * 32,
        kind="activate",
        observed_at_block=config.series.recovery.authority.issued_at_block,
        activation=RewardActivation(
            cohort_sha256=digest(config.series.cohorts[0]),
            allocation_sha256="11" * 32,
            package_sha256="12" * 32,
            recovery_tip_sha256="13" * 32,
            prior_opportunity_sha256="14" * 32,
        ),
    )
    proposal = prepare_early_release_revision(
        staged.selection,
        series=config.series,
        policy=config.policy,
        manifest=config.manifest,
        predecessor=predecessor,
        successor_cohort_sha256=initial.adoption.cohort_sha256,
        issued_at_block=initial.adoption.issued_at_block + 1,
        reason="Operator authorizes release of the certified successor package",
    )
    signed = SignedRewardModelAdoption(adoption=proposal, signatures=signatures(proposal))
    result = prepare_reward_adoption_boot_candidates(
        staged.coordinator,
        staged.writer,
        signed,
        early_release_predecessor=predecessor,
    )
    assert result.selection.latest(initial.adoption.cohort_sha256) == signed
    assert (
        prepare_reward_adoption_boot_candidates(
            result.coordinator,
            result.writer,
            signed,
            early_release_predecessor=predecessor,
        )
        == result
    )
    with pytest.raises(ValueError, match="signed predecessor"):
        prepare_reward_adoption_boot_candidates(staged.coordinator, staged.writer, signed)


def test_age_revision_preserves_early_release_and_changes_only_signed_timing(handoff):
    coordinator, writer, initial = handoff
    staged = prepare_reward_adoption_boot_candidates(coordinator, writer, initial)
    config = RewardCoordinatorConfig.model_validate_json(staged.coordinator)
    predecessor = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(config.series),
        sequence=1,
        predecessor_sha256="10" * 32,
        kind="activate",
        observed_at_block=config.series.recovery.authority.issued_at_block,
        activation=RewardActivation(
            cohort_sha256=digest(config.series.cohorts[0]),
            allocation_sha256="11" * 32,
            package_sha256="12" * 32,
            recovery_tip_sha256="13" * 32,
            prior_opportunity_sha256="14" * 32,
        ),
    )
    release = prepare_early_release_revision(
        staged.selection,
        series=config.series,
        policy=config.policy,
        manifest=config.manifest,
        predecessor=predecessor,
        successor_cohort_sha256=initial.adoption.cohort_sha256,
        issued_at_block=initial.adoption.issued_at_block + 1,
        reason="Operator authorizes release of the certified successor package",
    )
    signed_release = SignedRewardModelAdoption(
        adoption=release, signatures=signatures(release)
    )
    selected = prepare_reward_adoption_boot_candidates(
        staged.coordinator, staged.writer, signed_release,
        early_release_predecessor=predecessor,
    )
    plan = config.series.cohorts[1]
    observed = max(plan.not_before_block + 1, release.issued_at_block + 1)
    age = RewardActivationAge(
        schema="umi-reward-activation-age/1",
        rule="skip_activation_delay_if_older_than_three_days",
        cohort_start_block=plan.not_before_block,
        cohort_start_hash="21" * 32,
        cohort_start_timestamp_ms=1_000_000,
        start_evidence_sha256="22" * 32,
        observed_at_block=observed,
        observed_block_hash="23" * 32,
        observed_timestamp_ms=1_000_000 + 3 * 24 * 60 * 60 * 1000 + 1,
        observation_evidence_sha256="24" * 32,
    )
    proposal = prepare_activation_age_revision(
        selected.selection,
        series=config.series,
        policy=config.policy,
        cohort_sha256=initial.adoption.cohort_sha256,
        activation_age=age,
        issued_at_block=observed,
    )
    assert proposal.revision == 3
    assert proposal.early_release == release.early_release
    assert proposal.activation_age == age
    signed_age = SignedRewardModelAdoption(
        adoption=proposal, signatures=signatures(proposal)
    )
    result = prepare_reward_adoption_boot_candidates(
        selected.coordinator, selected.writer, signed_age,
        early_release_predecessor=predecessor,
    )
    assert result.selection.latest(initial.adoption.cohort_sha256) == signed_age
    assert prepare_reward_adoption_boot_candidates(
        result.coordinator, result.writer, signed_age,
        early_release_predecessor=predecessor,
    ) == result
    old_activation = RewardActivation(
        cohort_sha256=initial.adoption.cohort_sha256,
        allocation_sha256=release.allocation_sha256,
        package_sha256=release.package_sha256,
        recovery_tip_sha256="31" * 32,
        prior_opportunity_sha256=digest(release.early_release),
        reward_adoption_sha256=digest(release),
        effective_allocation_sha256=release.effective_allocation_sha256,
    )
    old_decision = RewardControlDecision(
        schema="umi-reward-control-decision/3",
        series_sha256=digest(config.series),
        sequence=2,
        predecessor_sha256="32" * 32,
        kind="activate",
        observed_at_block=observed,
        activation=old_activation,
    )
    revised = RewardControlDecision(
        schema="umi-reward-control-decision/3",
        series_sha256=digest(config.series),
        sequence=3,
        predecessor_sha256=digest(old_decision),
        kind="revise_activation",
        observed_at_block=observed,
        activation=old_activation.model_copy(
            update={"reward_adoption_sha256": digest(proposal)}
        ),
        revision_clearance_sha256="33" * 32,
    )
    committed = observed + 1
    assert activation_effective_block(
        config.series, old_decision, committed, result.selection
    ) == (
        committed
        + config.series.maximum_proof_lag_blocks
        + config.series.maximum_transaction_lifetime_blocks
    )
    assert activation_effective_block(
        config.series, revised, committed, result.selection
    ) == committed
    with pytest.raises(ValueError, match="signed predecessor"):
        prepare_reward_adoption_boot_candidates(
            selected.coordinator, selected.writer, signed_age
        )
    with pytest.raises(ValueError, match="eligible signed predecessor"):
        prepare_activation_age_revision(
            selected.selection,
            series=config.series,
            policy=config.policy,
            cohort_sha256=initial.adoption.cohort_sha256,
            activation_age=age.model_copy(update={"observed_timestamp_ms": 1_000_001}),
            issued_at_block=observed,
        )


def test_initial_early_release_uses_one_signed_adoption(handoff):
    coordinator, writer, original = handoff
    config = RewardCoordinatorConfig.model_validate_json(coordinator)
    prior = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(config.series),
        sequence=1,
        predecessor_sha256="10" * 32,
        kind="activate",
        observed_at_block=config.series.recovery.authority.issued_at_block,
        activation=RewardActivation(
            cohort_sha256=digest(config.series.cohorts[0]),
            allocation_sha256="11" * 32,
            package_sha256="12" * 32,
            recovery_tip_sha256="13" * 32,
            prior_opportunity_sha256="14" * 32,
        ),
    )
    release = RewardEarlyRelease(
        schema="umi-reward-early-release/1",
        predecessor_decision_sha256=digest(prior),
        predecessor_activation_sha256=digest(prior.activation),
        successor_cohort_sha256=original.adoption.cohort_sha256,
        successor_package_sha256=original.adoption.package_sha256,
        manifest_sha256=digest(config.manifest),
        reason="Operator authorizes first adoption of this certified package",
    )
    body = RewardModelAdoption.model_validate_json(
        canonical_json_bytes(
            original.adoption.model_copy(
                update={
                    "schema_": "umi-standing-model-reward-adoption/5",
                    "early_release": release,
                }
            )
        )
    )
    signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    result = prepare_reward_adoption_boot_candidates(
        coordinator, writer, signed, early_release_predecessor=prior
    )
    assert result.selection.latest(body.cohort_sha256) == signed
    with pytest.raises(ValueError, match="signed predecessor"):
        prepare_reward_adoption_boot_candidates(
            coordinator,
            writer,
            signed,
            early_release_predecessor=prior.model_copy(
                update={"observed_at_block": prior.observed_at_block + 1}
            ),
        )


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


def test_reference_publisher_candidate_follows_the_same_signed_selection(handoff, installed):
    coordinator, writer, signed = handoff
    reference = canonical_json_bytes(installed.config)
    target = "/var/lib/umi-reward-handoff/coordinator.json"
    staged = prepare_reward_adoption_boot_candidates(
        coordinator,
        writer,
        signed,
        reference_publisher_config_raw=reference,
        reference_current_boot_raw=coordinator,
        reference_current_boot_path=installed.config.coordinator_config,
        coordinator_candidate_path=target,
    )
    assert REFERENCE_PUBLISHER_CONFIG_MODE == 0o600
    candidate = ReferencePublisherConfig.model_validate_json(staged.reference_publisher_config)
    assert candidate.coordinator_config == target
    assert {
        k
        for k, old in json.loads(reference).items()
        if old != json.loads(staged.reference_publisher_config)[k]
    } == {"coordinator_config"}
    assert (
        prepare_reward_adoption_boot_candidates(
            staged.coordinator,
            staged.writer,
            signed,
            reference_publisher_config_raw=staged.reference_publisher_config,
            reference_current_boot_raw=staged.coordinator,
            reference_current_boot_path=target,
            coordinator_candidate_path=target,
        )
        == staged
    )


def test_reference_publisher_candidate_refuses_split_lineage(handoff, installed):
    coordinator, writer, signed = handoff
    reference = canonical_json_bytes(installed.config)
    target = "/var/lib/umi-reward-handoff/coordinator.json"
    staged = prepare_reward_adoption_boot_candidates(coordinator, writer, signed)
    with pytest.raises(ValueError, match="disagrees on signed reward lineage"):
        prepare_reward_adoption_boot_candidates(
            coordinator,
            writer,
            signed,
            reference_publisher_config_raw=reference,
            reference_current_boot_raw=staged.coordinator,
            reference_current_boot_path=installed.config.coordinator_config,
            coordinator_candidate_path=target,
        )
    with pytest.raises(ValueError, match="absolute boot path"):
        prepare_reward_adoption_boot_candidates(
            coordinator,
            writer,
            signed,
            reference_publisher_config_raw=reference,
            reference_current_boot_raw=coordinator,
            reference_current_boot_path=installed.config.coordinator_config,
            coordinator_candidate_path="relative.json",
        )
    with pytest.raises(ValueError, match="current boot path differs"):
        prepare_reward_adoption_boot_candidates(
            coordinator,
            writer,
            signed,
            reference_publisher_config_raw=reference,
            reference_current_boot_raw=coordinator,
            reference_current_boot_path="/var/lib/unrelated.json",
            coordinator_candidate_path=target,
        )


def test_package_delivery_candidate_follows_signed_selection_and_repeats(handoff):
    coordinator, writer, signed = handoff
    current = "/var/lib/umi-reward-handoff/current-coordinator.json"
    target = "/var/lib/umi-reward-handoff/selected-coordinator.json"
    delivery = canonical_json_bytes(
        {
            "schema": "umi-native-reward-package-delivery/1",
            "native_source": "/opt/umi-native",
            "producer_config": "/etc/umi/producer.json",
            "coordinator_config": current,
            "state_directory": "/var/lib/umi-delivery",
        }
    )
    staged = prepare_reward_adoption_boot_candidates(
        coordinator,
        writer,
        signed,
        package_delivery_config_raw=delivery,
        package_delivery_current_boot_raw=coordinator,
        package_delivery_current_boot_path=current,
        coordinator_candidate_path=target,
    )
    assert {
        key
        for key, old in json.loads(delivery).items()
        if old != json.loads(staged.package_delivery_config)[key]
    } == {"coordinator_config"}
    assert json.loads(staged.package_delivery_config)["coordinator_config"] == target
    assert (
        prepare_reward_adoption_boot_candidates(
            staged.coordinator,
            staged.writer,
            signed,
            package_delivery_config_raw=staged.package_delivery_config,
            package_delivery_current_boot_raw=staged.coordinator,
            package_delivery_current_boot_path=target,
            coordinator_candidate_path=target,
        )
        == staged
    )


def test_package_delivery_candidate_refuses_split_lineage_and_wrong_path(handoff):
    coordinator, writer, signed = handoff
    current = "/var/lib/umi-reward-handoff/current-coordinator.json"
    target = "/var/lib/umi-reward-handoff/selected-coordinator.json"
    delivery = canonical_json_bytes(
        {
            "schema": "umi-native-reward-package-delivery/1",
            "native_source": "/opt/umi-native",
            "producer_config": "/etc/umi/producer.json",
            "coordinator_config": current,
            "state_directory": "/var/lib/umi-delivery",
        }
    )
    staged = prepare_reward_adoption_boot_candidates(coordinator, writer, signed)
    with pytest.raises(ValueError, match="disagrees on signed reward lineage"):
        prepare_reward_adoption_boot_candidates(
            coordinator,
            writer,
            signed,
            package_delivery_config_raw=delivery,
            package_delivery_current_boot_raw=staged.coordinator,
            package_delivery_current_boot_path=current,
            coordinator_candidate_path=target,
        )
    with pytest.raises(ValueError, match="current or target boot path differs"):
        prepare_reward_adoption_boot_candidates(
            coordinator,
            writer,
            signed,
            package_delivery_config_raw=delivery,
            package_delivery_current_boot_raw=coordinator,
            package_delivery_current_boot_path="/var/lib/unrelated.json",
            coordinator_candidate_path=target,
        )
