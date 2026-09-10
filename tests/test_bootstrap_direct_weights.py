from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from bittensor.intents import Batch

from tests.factories import dev_wallet
from umi.bootstrap_direct_weights import (
    DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
    DIRECT_OPERATIONAL_PREFLIGHT_SCHEMA,
    DIRECT_TRANSITION_PROFILE,
    DirectBootstrapOperationalPreflight,
    DirectBootstrapSubmissionJournal,
    OwnerFenceJournal,
    OwnerFencePreflight,
    attest_owner_fence,
    build_direct_bootstrap_call_material,
    build_owner_fence_call,
    classify_direct_bootstrap_application,
    sign_direct_transition_authorization,
    submit_direct_bootstrap_weights,
    submit_owner_fence,
    validate_direct_bootstrap_preflight,
    verify_direct_transition_authorization,
)
from umi.bootstrap_weight_operator import (
    BOOTSTRAP_HEALTH_SET_SCHEMA,
    BOOTSTRAP_PILOT_REPLAY_SET_SCHEMA,
    BootstrapChainParticipant,
    BootstrapChainSnapshot,
    BootstrapExtrinsicReference,
    BootstrapHealthReceipt,
    BootstrapHealthReceiptSet,
    BootstrapManifestAnchorObservation,
    BootstrapOperatorError,
    BootstrapPilotReplayReceipt,
    BootstrapPilotReplaySet,
)
from umi.bootstrap_weights import (
    BOOTSTRAP_WEIGHT_POLICY_SCHEMA,
    U16_MAX,
    BootstrapEligibilityEntry,
    BootstrapWeightPolicy,
    build_bootstrap_eligibility_manifest,
    sign_bootstrap_eligibility_manifest,
    sign_bootstrap_opt_in,
)
from umi.encoding import account_id32
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.protocol import canonical_json_bytes

NOW = datetime(2026, 9, 9, 15, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1_000)
BLOCK_HASH = "0x" + "12" * 32
POST_BLOCK_HASH = "0x" + "13" * 32
DIRECT_REVISION = "ab" * 20
DIRECT_WVK = 1 << 32


def _case():
    coordinator = dev_wallet("//DirectBootstrapCoordinator")
    owner = dev_wallet("//DirectBootstrapOwner")
    policy = BootstrapWeightPolicy(
        schema=BOOTSTRAP_WEIGHT_POLICY_SCHEMA,
        network="finney",
        netuid=78,
        mechanism_id=0,
        translation_weights_active=False,
        service_weights_active=True,
        campaign_id="11" * 32,
        public_evidence_origin="https://api.umi.vision",
        coordinator_hotkey=coordinator.hotkey.ss58_address,
        umi_git_revision="cd" * 20,
        weights_version_key=1,
        published_at_block=100,
        activation_block=120,
        commit_stop_block=49_080,
        hard_sunset_block=50_520,
        health_ttl_blocks=20,
        manifest_ttl_blocks=30,
    )
    miners = [dev_wallet(f"//DirectBootstrapMiner{index}") for index in range(2)]
    entries = []
    for index, miner in enumerate(miners, start=1):
        pilot_id = f"{index:02x}" * 32
        opt_in = sign_bootstrap_opt_in(
            policy,
            pilot_id=pilot_id,
            wallet=miner,
            signed_at_block=122,
        )
        entries.append(
            BootstrapEligibilityEntry(
                pilot_id=pilot_id,
                miner_hotkey=miner.hotkey.ss58_address,
                uid=index,
                origin=f"https://8.8.8.{index}:443",
                pilot_block=110,
                health_block=124,
                utility=1,
                opt_in=opt_in,
            )
        )
    signed = sign_bootstrap_eligibility_manifest(
        build_bootstrap_eligibility_manifest(
            policy,
            entries,
            frozen_at_block=125,
            frozen_at_block_hash=BLOCK_HASH,
        ),
        wallet=coordinator,
    )
    authorization = sign_direct_transition_authorization(
        signed,
        weights_version_key=DIRECT_WVK,
        submission_id="44" * 32,
        umi_git_revision=DIRECT_REVISION,
        signed_at_block=125,
        valid_from_block=125,
        expires_at_block=155,
        validator_hotkey=owner.hotkey.ss58_address,
        validator_uid=0,
        wallet=coordinator,
    )
    participants = [
        BootstrapChainParticipant(
            hotkey=owner.hotkey.ss58_address,
            uid=0,
            validator_permit=True,
            origin=None,
            last_update=100,
        )
    ]
    participants.extend(
        BootstrapChainParticipant(
            hotkey=entry.miner_hotkey,
            uid=entry.uid,
            validator_permit=False,
            origin=entry.origin,
            last_update=100,
        )
        for entry in entries
    )
    participants.extend(
        BootstrapChainParticipant(
            hotkey=dev_wallet(f"//DirectBootstrapFiller{uid}").hotkey.ss58_address,
            uid=uid,
            validator_permit=False,
            origin=None,
            last_update=100,
        )
        for uid in range(3, 256)
    )
    return signed, authorization, owner, participants


def _permitted_case():
    signed, _authorization, owner, participants = _case()
    validator = dev_wallet("//DirectBootstrapPermittedValidator")
    updated = list(participants)
    updated[0] = updated[0].model_copy(update={"validator_permit": False})
    updated[200] = updated[200].model_copy(
        update={
            "hotkey": validator.hotkey.ss58_address,
            "validator_permit": True,
            "last_update": 100,
        }
    )
    authorization = sign_direct_transition_authorization(
        signed,
        weights_version_key=DIRECT_WVK,
        submission_id="66" * 32,
        umi_git_revision=DIRECT_REVISION,
        signed_at_block=125,
        valid_from_block=125,
        expires_at_block=155,
        validator_hotkey=validator.hotkey.ss58_address,
        validator_uid=200,
        wallet=dev_wallet("//DirectBootstrapCoordinator"),
    )
    preflight = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(updated),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=validator.hotkey.ss58_address,
        now=NOW,
    )
    return signed, authorization, owner, validator, updated, preflight


def _snapshot(participants, **changes):
    values = {
        "network": "finney",
        "genesis_block_hash": f"0x{FINNEY_GENESIS_HASH}",
        "block_number": 125,
        "block_hash": BLOCK_HASH,
        "block_timestamp_ms": NOW_MS,
        "manifest_frozen_block_hash": BLOCK_HASH,
        "mechanism_count": 1,
        "commit_reveal_enabled": False,
        "commit_reveal_version": 4,
        "reveal_period_epochs": 1,
        "weights_version_key": DIRECT_WVK,
        "min_allowed_weights": 256,
        "max_weights_limit": 32_768,
        "max_allowed_uids": 256,
        "weights_set_rate_limit": 0,
        "activity_cutoff_blocks": 360,
        "validator_mechid0_row": [],
        "validator_has_pending_commit": False,
        "total_pending_commit_count": 0,
        "active_mechid0_row_hotkeys": [],
        "storage_proofs_verified": False,
        "tempo": 360,
        "last_epoch_block": 100,
        "pending_epoch_at": 0,
        "subnet_epoch_index": 5,
        "blocks_since_last_step": 25,
        "block_time_seconds": 12.0,
        "participants": participants,
    }
    values.update(changes)
    return BootstrapChainSnapshot.model_validate(values)


def _operational(signed, preflight):
    replay = BootstrapPilotReplaySet(
        schema=BOOTSTRAP_PILOT_REPLAY_SET_SCHEMA,
        manifest_sha256=signed.manifest_sha256,
        public_evidence_origin=signed.manifest.policy.public_evidence_origin,
        receipts=[
            BootstrapPilotReplayReceipt(
                pilot_id=entry.pilot_id,
                manifest_sha256=entry.pilot_id,
                bundle_bytes=100,
                miner_hotkey=entry.miner_hotkey,
                uid=entry.uid,
                origin=entry.origin,
                coordinator_hotkey=signed.manifest.policy.coordinator_hotkey,
                campaign_id=signed.manifest.policy.campaign_id,
                outcome_classification="ok",
                deterministic_replay_verified=True,
                coordinator_signature_verified=True,
                storage_proofs_verified=False,
            )
            for entry in signed.manifest.entries
        ],
    )
    health = BootstrapHealthReceiptSet(
        schema=BOOTSTRAP_HEALTH_SET_SCHEMA,
        manifest_sha256=signed.manifest_sha256,
        checked_at_block=preflight.snapshot.block_number,
        checked_at_block_hash=preflight.snapshot.block_hash,
        receipts=[
            BootstrapHealthReceipt(
                miner_hotkey=entry.miner_hotkey,
                uid=entry.uid,
                origin=entry.origin,
                endpoint=entry.origin + "/healthz",
                checked_at_block=preflight.snapshot.block_number,
                checked_at_block_hash=preflight.snapshot.block_hash,
                status_code=200,
                body_sha256="22" * 32,
                body_size_bytes=2,
                tls_certificate_sha256="33" * 32,
                redirect_policy="disabled",
                tls_server_authentication="system_trust_store/1",
                checked_at=NOW,
            )
            for entry in signed.manifest.entries
        ],
    )
    return DirectBootstrapOperationalPreflight(
        schema=DIRECT_OPERATIONAL_PREFLIGHT_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        signed_manifest=signed,
        chain=preflight,
        pilot_replay=replay,
        health=health,
    )


def _preflight():
    signed, authorization, owner, participants = _case()
    preflight = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(participants),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=owner.hotkey.ss58_address,
        now=NOW,
    )
    return signed, authorization, owner, participants, preflight


class _ClientContext:
    def __init__(self, client):
        self.client = client

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, *_args):
        return None


def _owner_fence_preflight(owner, *, applied: bool = False) -> OwnerFencePreflight:
    return OwnerFencePreflight(
        schema="umi-bootstrap-owner-fence-preflight/1",
        network="finney",
        netuid=78,
        block_number=126 if applied else 125,
        block_hash=POST_BLOCK_HASH if applied else BLOCK_HASH,
        subnet_owner_coldkey_account_id32="0x" + account_id32(owner.coldkeypub.ss58_address).hex(),
        subnet_owner_hotkey_account_id32="0x" + account_id32(owner.hotkey.ss58_address).hex(),
        mechanism_count=1,
        max_allowed_uids=256,
        subnetwork_n=256,
        pending_commit_count=3,
        tempo=360,
        last_epoch_block=100,
        pending_epoch_at=0,
        admin_freeze_window=10,
        blocks_until_next_auto_epoch=334 if applied else 335,
        admin_submission_window_has_era_headroom=True,
        weights_version_key_rate_limit_tempos=5,
        weights_version_key_rate_limit_blocks=1_800,
        weights_version_key_last_update_block=0,
        weights_version_key_rate_limit_ready=True,
        owner_hyperparam_rate_limit_tempos=2,
        owner_hyperparam_rate_limit_blocks=720,
        min_allowed_weights_last_update_block=0,
        commit_reveal_enabled_last_update_block=0,
        owner_hyperparam_rate_limits_ready=True,
        current_weights_version_key=DIRECT_WVK if applied else 1,
        current_min_allowed_weights=256 if applied else 1,
        current_commit_reveal_enabled=not applied,
        target_weights_version_key=DIRECT_WVK,
        target_min_allowed_weights=256,
        target_commit_reveal_enabled=False,
        target_state_classification="already_applied" if applied else "requires_submission",
        sdk_finalized_reads_verified=True,
        storage_proofs_verified=False,
    )


def test_direct_authorization_binds_original_consent_and_new_release() -> None:
    signed, authorization, _owner, _participants = _case()

    assert authorization.manifest_sha256 == signed.manifest_sha256
    assert authorization.original_policy_sha256 == signed.manifest.policy_sha256
    assert authorization.weights_version_key == DIRECT_WVK
    assert authorization.umi_git_revision == DIRECT_REVISION
    assert (
        verify_direct_transition_authorization(
            signed,
            authorization,
            current_block=130,
        )
        == authorization
    )

    changed = authorization.model_copy(update={"umi_git_revision": "ef" * 20})
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_direct_transition_authorization(signed, changed, current_block=130)


def test_direct_preflight_accepts_the_exact_authorized_permitted_nonowner() -> None:
    signed, authorization, owner, validator, updated, preflight = _permitted_case()

    assert preflight.validator_uid == 200
    assert preflight.validator_hotkey == validator.hotkey.ss58_address
    assert preflight.transition_authorization.validator_uid == 200
    assert preflight.full_row_weights[200] == 0

    with pytest.raises(BootstrapOperatorError, match="authorized_validator_hotkey_mismatch"):
        validate_direct_bootstrap_preflight(
            signed,
            _snapshot(updated),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=owner.hotkey.ss58_address,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"commit_reveal_enabled": True}, "direct_requires_commit_reveal_disabled"),
        ({"commit_reveal_version": 3}, "direct_commit_reveal_version_mismatch"),
        ({"reveal_period_epochs": 2}, "direct_reveal_period_mismatch"),
        ({"tempo": 361}, "direct_tempo_mismatch"),
        ({"activity_cutoff_blocks": 359}, "direct_activity_cutoff_mismatch"),
        ({"block_time_seconds": 11.9}, "direct_block_time_mismatch"),
        ({"min_allowed_weights": 255}, "direct_requires_min_allowed_weights_256"),
        ({"max_allowed_uids": 255}, "direct_requires_max_allowed_uids_256"),
        ({"weights_version_key": 1}, "direct_weights_version_key_mismatch"),
        ({"mechanism_count": 2}, "mechanism_count_mismatch"),
        ({"max_weights_limit": 32_767}, "row_exceeds_max_weight_ratio"),
    ],
)
def test_direct_preflight_fails_closed_on_runtime_gate(changes, reason) -> None:
    signed, authorization, owner, participants = _case()
    with pytest.raises(BootstrapOperatorError, match=reason):
        validate_direct_bootstrap_preflight(
            signed,
            _snapshot(participants, **changes),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=owner.hotkey.ss58_address,
            now=NOW,
        )


def test_direct_preflight_requires_the_entire_pending_queue_to_be_empty() -> None:
    signed, authorization, owner, participants = _case()
    with pytest.raises(BootstrapOperatorError, match="direct_pending_commits_not_drained"):
        validate_direct_bootstrap_preflight(
            signed,
            _snapshot(participants, total_pending_commit_count=1),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=owner.hotkey.ss58_address,
            now=NOW,
        )


def test_direct_authorization_explicitly_bridges_expired_manifest_ttl() -> None:
    signed, _authorization, owner, participants = _case()
    authorization = sign_direct_transition_authorization(
        signed,
        weights_version_key=DIRECT_WVK,
        submission_id="55" * 32,
        umi_git_revision=DIRECT_REVISION,
        signed_at_block=49_070,
        valid_from_block=49_080,
        expires_at_block=50_500,
        validator_hotkey=owner.hotkey.ss58_address,
        validator_uid=0,
        wallet=dev_wallet("//DirectBootstrapCoordinator"),
    )
    preflight = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(
            participants,
            block_number=49_100,
            blocks_since_last_step=100,
        ),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=owner.hotkey.ss58_address,
        now=NOW,
    )

    assert preflight.snapshot.block_number - signed.manifest.frozen_at_block > (
        signed.manifest.policy.manifest_ttl_blocks
    )
    assert preflight.snapshot.block_number > signed.manifest.policy.commit_stop_block


def test_owner_fence_is_one_atomic_ordered_call_and_allows_pending_commits() -> None:
    _signed, _authorization, owner, _participants = _case()
    preflight = OwnerFencePreflight(
        schema="umi-bootstrap-owner-fence-preflight/1",
        network="finney",
        netuid=78,
        block_number=125,
        block_hash=BLOCK_HASH,
        subnet_owner_coldkey_account_id32=(
            "0x" + account_id32(owner.coldkeypub.ss58_address).hex()
        ),
        subnet_owner_hotkey_account_id32="0x" + account_id32(owner.hotkey.ss58_address).hex(),
        mechanism_count=1,
        max_allowed_uids=256,
        subnetwork_n=256,
        pending_commit_count=3,
        tempo=360,
        last_epoch_block=100,
        pending_epoch_at=0,
        admin_freeze_window=10,
        blocks_until_next_auto_epoch=335,
        admin_submission_window_has_era_headroom=True,
        weights_version_key_rate_limit_tempos=5,
        weights_version_key_rate_limit_blocks=1_800,
        weights_version_key_last_update_block=0,
        weights_version_key_rate_limit_ready=True,
        owner_hyperparam_rate_limit_tempos=2,
        owner_hyperparam_rate_limit_blocks=720,
        min_allowed_weights_last_update_block=0,
        commit_reveal_enabled_last_update_block=0,
        owner_hyperparam_rate_limits_ready=True,
        current_weights_version_key=1,
        current_min_allowed_weights=1,
        current_commit_reveal_enabled=True,
        target_weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
        target_min_allowed_weights=256,
        target_commit_reveal_enabled=False,
        target_state_classification="requires_submission",
        sdk_finalized_reads_verified=True,
        storage_proofs_verified=False,
    )
    material, raw = build_owner_fence_call(preflight)

    assert raw.module == "Utility"
    assert raw.function == "batch_all"
    calls = raw.params["calls"]
    assert [(call.module, call.function) for call in calls] == [
        ("AdminUtils", "sudo_set_weights_version_key"),
        ("AdminUtils", "sudo_set_min_allowed_weights"),
        ("AdminUtils", "sudo_set_commit_reveal_weights_enabled"),
    ]
    assert calls[0].params["weights_version_key"] == 1 << 32
    assert calls[1].params["min_allowed_weights"] == 256
    assert calls[2].params["enabled"] is False
    assert material.preflight.pending_commit_count == 3

    for failed_gate in (
        "admin_submission_window_has_era_headroom",
        "weights_version_key_rate_limit_ready",
        "owner_hyperparam_rate_limits_ready",
    ):
        values = preflight.model_dump(by_alias=True)
        values[failed_gate] = False
        with pytest.raises(ValueError, match="rate-limit-ready submission window"):
            OwnerFencePreflight.model_validate(values)


@pytest.mark.asyncio
async def test_stock_btcli_owner_fence_intents_build_one_coldkey_batch() -> None:
    batch = Batch(
        intents=[
            {
                "op": "set_hyperparameter",
                "netuid": 78,
                "name": "weights_version",
                "value": DIRECT_WVK,
            },
            {
                "op": "set_hyperparameter",
                "netuid": 78,
                "name": "min_allowed_weights",
                "value": 256,
            },
            {
                "op": "set_hyperparameter",
                "netuid": 78,
                "name": "commit_reveal_weights_enabled",
                "value": False,
            },
        ]
    )

    assert batch.op == "batch"
    assert batch.signer == "coldkey"
    assert batch.intents == [
        {
            "op": "set_hyperparameter",
            "netuid": 78,
            "name": "weights_version",
            "value": DIRECT_WVK,
        },
        {
            "op": "set_hyperparameter",
            "netuid": 78,
            "name": "min_allowed_weights",
            "value": 256,
        },
        {
            "op": "set_hyperparameter",
            "netuid": 78,
            "name": "commit_reveal_weights_enabled",
            "value": 0,
        },
    ]

    class Substrate:
        async def compose(self, call):
            return call

    raw = await batch.build(Substrate(), None)
    assert raw.module == "Utility"
    assert raw.function == "batch_all"
    assert [(call.module, call.function, call.params) for call in raw.params["calls"]] == [
        (
            "AdminUtils",
            "sudo_set_weights_version_key",
            {"netuid": 78, "weights_version_key": DIRECT_WVK},
        ),
        (
            "AdminUtils",
            "sudo_set_min_allowed_weights",
            {"netuid": 78, "min_allowed_weights": 256},
        ),
        (
            "AdminUtils",
            "sudo_set_commit_reveal_weights_enabled",
            {"netuid": 78, "enabled": False},
        ),
    ]


def test_direct_raw_call_retains_all_256_destinations_and_zero_weights() -> None:
    signed, _authorization, _owner, _participants, preflight = _preflight()
    material, raw = build_direct_bootstrap_call_material(_operational(signed, preflight))

    assert raw.module == "SubtensorModule"
    assert raw.function == "set_mechanism_weights"
    assert raw.params["dests"] == list(range(256))
    assert len(raw.params["weights"]) == 256
    assert raw.params["weights"][1:3] == [U16_MAX, U16_MAX]
    assert raw.params["weights"][0] == 0
    assert raw.params["weights"][3:] == [0] * 253
    assert raw.params["version_key"] == DIRECT_WVK
    assert material.expected_applied_row == [
        [uid, raw.params["weights"][uid]] for uid in range(256)
    ]


def test_first_direct_row_requires_every_legacy_row_to_be_inactive() -> None:
    signed, authorization, owner, participants = _case()

    with pytest.raises(BootstrapOperatorError, match="pre_direct_active_rows_not_drained"):
        validate_direct_bootstrap_preflight(
            signed,
            _snapshot(
                participants,
                active_mechid0_row_hotkeys=[participants[110].hotkey],
            ),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=owner.hotkey.ss58_address,
            now=NOW,
        )


def test_direct_preflight_requires_owner_hotkey_at_uid_zero_with_permit() -> None:
    signed, authorization, owner, participants = _case()
    owner_at_three = list(participants)
    owner_at_three[0] = participants[3].model_copy(update={"uid": 0})
    owner_at_three[3] = participants[0].model_copy(update={"uid": 3})

    with pytest.raises(BootstrapOperatorError, match="subnet_owner_hotkey_is_not_uid_0"):
        validate_direct_bootstrap_preflight(
            signed,
            _snapshot(owner_at_three),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=owner.hotkey.ss58_address,
            now=NOW,
        )

    no_permit = list(participants)
    no_permit[0] = participants[0].model_copy(update={"validator_permit": False})
    with pytest.raises(BootstrapOperatorError, match="lacks_validator_permit"):
        validate_direct_bootstrap_preflight(
            signed,
            _snapshot(no_permit),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=owner.hotkey.ss58_address,
            now=NOW,
        )


def test_direct_drain_includes_fresh_permitted_validator_with_empty_row() -> None:
    signed, authorization, owner, participants = _case()
    fresh_nonowner = list(participants)
    fresh_nonowner[110] = participants[110].model_copy(
        update={"validator_permit": True, "last_update": 125}
    )

    with pytest.raises(
        BootstrapOperatorError,
        match="pre_direct_other_active_permitted_validators_not_drained",
    ):
        validate_direct_bootstrap_preflight(
            signed,
            _snapshot(fresh_nonowner, active_mechid0_row_hotkeys=[]),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=owner.hotkey.ss58_address,
            now=NOW,
        )


def test_direct_builder_rejects_a_zero_filtering_wrapper() -> None:
    signed, _authorization, _owner, _participants, preflight = _preflight()

    def filtering_builder(**values):
        pairs = [
            (uid, weight)
            for uid, weight in zip(values["dests"], values["weights"], strict=True)
            if weight
        ]
        return SimpleNamespace(
            module="SubtensorModule",
            function="set_mechanism_weights",
            params={
                "netuid": values["netuid"],
                "mecid": values["mecid"],
                "dests": [uid for uid, _ in pairs],
                "weights": [weight for _, weight in pairs],
                "version_key": values["version_key"],
            },
        )

    with pytest.raises(BootstrapOperatorError, match="direct_raw_weight_call_parameter_mismatch"):
        build_direct_bootstrap_call_material(
            _operational(signed, preflight),
            call_builder=filtering_builder,
        )


def test_finalized_direct_chain_result_requires_exact_full_row_and_last_update() -> None:
    signed, authorization, owner, participants, _preflight_before_anchor = _preflight()
    anchor = BootstrapExtrinsicReference(
        extrinsic_id="126-0001",
        block_number=126,
        extrinsic_index=1,
        block_hash="0x" + "14" * 32,
    )
    anchor_observation = BootstrapManifestAnchorObservation(
        manifest_sha256=signed.manifest_sha256,
        anchor=anchor,
        observation_block=127,
        observation_block_hash="0x" + "15" * 32,
        stored_commitment_block=126,
        field_count=1,
        field_type="Data::Sha256",
        field_sha256=signed.manifest_sha256,
        sdk_finalized_read_verified=True,
        storage_proofs_verified=False,
    )
    preflight = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(
            participants,
            block_number=127,
            block_hash="0x" + "15" * 32,
            blocks_since_last_step=27,
        ),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=owner.hotkey.ss58_address,
        now=NOW,
    )
    material, _ = build_direct_bootstrap_call_material(
        _operational(signed, preflight),
        manifest_anchor=anchor_observation,
    )
    call = BootstrapExtrinsicReference(
        extrinsic_id="130-0002",
        block_number=130,
        extrinsic_index=2,
        block_hash="0x" + "16" * 32,
    )
    updated_participants = [
        item.model_copy(update={"last_update": 130}) if item.uid == 0 else item
        for item in participants
    ]
    observed = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(
            updated_participants,
            block_number=130,
            block_hash=POST_BLOCK_HASH,
            validator_mechid0_row=material.expected_applied_row,
            active_mechid0_row_hotkeys=[owner.hotkey.ss58_address],
            blocks_since_last_step=30,
        ),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=owner.hotkey.ss58_address,
        now=NOW,
    )
    receipt = classify_direct_bootstrap_application(
        material,
        anchor=anchor,
        weight_call=call,
        observation=observed,
        created_at=NOW,
    )

    assert receipt.classification == "applied"
    assert receipt.reason_codes == []
    assert receipt.finalized_inclusion_verified
    assert receipt.applied_row_verified
    assert receipt.last_update_verified

    wrong_snapshot = observed.snapshot.model_copy(
        update={"validator_mechid0_row": material.expected_applied_row[:-1]}
    )
    failed = classify_direct_bootstrap_application(
        material,
        anchor=anchor,
        weight_call=call,
        observation=observed.model_copy(update={"snapshot": wrong_snapshot}),
        created_at=NOW,
    )
    assert failed.classification == "failed"
    assert failed.reason_codes == ["applied_row_mismatch"]
    assert not failed.applied_row_verified


def test_direct_raw_call_is_generated_without_sdk_set_weights() -> None:
    source = __import__("inspect").getsource(build_direct_bootstrap_call_material)
    assert "bt.calls.SubtensorModule.set_mechanism_weights" in source
    assert ".set_weights(" not in source


@pytest.mark.asyncio
async def test_owner_fence_submit_uses_coldkey_and_verifies_finalized_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed, _authorization, owner, _participants = _case()
    observations = iter(
        [_owner_fence_preflight(owner), _owner_fence_preflight(owner, applied=True)]
    )

    async def collect(_client, **_kwargs):
        return next(observations)

    class Client:
        def __init__(self):
            self.calls = []

        async def submit_call(self, call, wallet, **kwargs):
            self.calls.append((call, wallet, kwargs))
            return SimpleNamespace(
                success=True,
                extrinsic_id="126-0001",
                block_hash=POST_BLOCK_HASH,
            )

    client = Client()
    monkeypatch.setattr(
        "umi.bootstrap_direct_weights.collect_owner_fence_preflight_with_client", collect
    )
    receipt = await submit_owner_fence(
        wallet=owner,
        receipt_output=tmp_path / "receipt.json",
        call_material_output=tmp_path / "material.json",
        state_dir=tmp_path / "state",
        live_submit=True,
        acknowledgement="APPLY SN78 DIRECT BOOTSTRAP OWNER FENCE",
        client_factory=lambda _network: _ClientContext(client),
        clock=lambda: NOW,
    )

    assert receipt.classification == "applied"
    assert len(client.calls) == 1
    assert client.calls[0][0].function == "batch_all"
    assert client.calls[0][2]["signer"] == "coldkey"
    assert client.calls[0][2]["wait_for_finalization"] is True
    journal_path = next((tmp_path / "state").glob("owner-fence-*.json"))
    assert OwnerFenceJournal.model_validate_json(journal_path.read_bytes()).phase == "applied"


@pytest.mark.asyncio
async def test_owner_fence_submit_rejects_a_call_output_at_its_journal_path(
    tmp_path: Path,
) -> None:
    _signed, _authorization, owner, _participants = _case()
    owner_account = account_id32(owner.coldkeypub.ss58_address).hex()
    state_dir = tmp_path / "state"
    journal_path = state_dir / f"owner-fence-78-{DIRECT_WVK}-{owner_account}.json"

    with pytest.raises(BootstrapOperatorError, match="output_state_paths_overlap"):
        await submit_owner_fence(
            wallet=owner,
            receipt_output=tmp_path / "receipt.json",
            call_material_output=journal_path,
            state_dir=state_dir,
            live_submit=True,
            acknowledgement="APPLY SN78 DIRECT BOOTSTRAP OWNER FENCE",
            client_factory=lambda _network: (_ for _ in ()).throw(
                AssertionError("path rejection must precede network access")
            ),
            clock=lambda: NOW,
        )

    assert not state_dir.exists()


@pytest.mark.asyncio
async def test_owner_fence_ambiguous_submit_is_claimed_and_cannot_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed, _authorization, owner, _participants = _case()

    async def collect(_client, **_kwargs):
        return _owner_fence_preflight(owner)

    class Client:
        def __init__(self):
            self.calls = 0

        async def submit_call(self, *_args, **_kwargs):
            self.calls += 1
            raise ConnectionError("ambiguous")

    client = Client()
    monkeypatch.setattr(
        "umi.bootstrap_direct_weights.collect_owner_fence_preflight_with_client", collect
    )
    values = dict(
        wallet=owner,
        receipt_output=tmp_path / "receipt.json",
        call_material_output=tmp_path / "material.json",
        state_dir=tmp_path / "state",
        live_submit=True,
        acknowledgement="APPLY SN78 DIRECT BOOTSTRAP OWNER FENCE",
        client_factory=lambda _network: _ClientContext(client),
        clock=lambda: NOW,
    )
    with pytest.raises(ConnectionError, match="ambiguous"):
        await submit_owner_fence(**values)
    journal_path = next((tmp_path / "state").glob("owner-fence-*.json"))
    assert (
        OwnerFenceJournal.model_validate_json(journal_path.read_bytes()).phase == "material_written"
    )

    values["receipt_output"] = tmp_path / "receipt-2.json"
    values["call_material_output"] = tmp_path / "material-2.json"
    with pytest.raises(BootstrapOperatorError, match="claim_exists_reconcile_required"):
        await submit_owner_fence(**values)
    assert client.calls == 1


@pytest.mark.asyncio
async def test_owner_fence_preflight_failure_leaves_no_claim_and_can_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed, _authorization, owner, _participants = _case()
    attempts = 0

    async def collect(_client, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise BootstrapOperatorError("owner_fence_admin_freeze_window_or_headroom")
        return _owner_fence_preflight(owner, applied=True)

    client = _DirectSubmitClient()
    monkeypatch.setattr(
        "umi.bootstrap_direct_weights.collect_owner_fence_preflight_with_client", collect
    )
    values = dict(
        wallet=owner,
        receipt_output=tmp_path / "receipt.json",
        call_material_output=tmp_path / "material.json",
        state_dir=tmp_path / "state",
        live_submit=True,
        acknowledgement="APPLY SN78 DIRECT BOOTSTRAP OWNER FENCE",
        client_factory=lambda _network: _ClientContext(client),
        clock=lambda: NOW,
    )
    with pytest.raises(BootstrapOperatorError, match="admin_freeze"):
        await submit_owner_fence(**values)
    assert not list((tmp_path / "state").glob("owner-fence-*.json"))

    receipt = await submit_owner_fence(**values)
    assert receipt.classification == "already_applied"
    assert client.calls == []


@pytest.mark.asyncio
async def test_owner_fence_attestation_is_read_only_and_records_no_extrinsic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed, _authorization, owner, _participants = _case()
    expected_owner = owner.coldkeypub.ss58_address
    seen_expected_owners: list[str] = []

    async def collect(_client, **kwargs):
        seen_expected_owners.append(kwargs["expected_owner_coldkey"])
        return _owner_fence_preflight(owner, applied=True)

    class ReadOnlyClient:
        async def submit_call(self, *_args, **_kwargs):
            raise AssertionError("read-only attestation must not submit a call")

    monkeypatch.setattr(
        "umi.bootstrap_direct_weights.collect_owner_fence_preflight_with_client", collect
    )
    monkeypatch.setattr(
        "umi.bootstrap_direct_weights.bt.Wallet",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("wallet must not be loaded")),
    )
    receipt_path = tmp_path / "receipt.json"
    material_path = tmp_path / "material.json"
    receipt = await attest_owner_fence(
        expected_owner_coldkey=expected_owner,
        receipt_output=receipt_path,
        call_material_output=material_path,
        state_dir=tmp_path / "state",
        client_factory=lambda _network: _ClientContext(ReadOnlyClient()),
        clock=lambda: NOW,
    )

    assert seen_expected_owners == [expected_owner]
    assert receipt.classification == "already_applied"
    assert receipt.extrinsic is None
    assert receipt.batch_all_finalized_success is False
    assert receipt.all_storage_targets_verified is True
    assert (
        receipt.source_snapshot_pending_commit_count == receipt.observed_pending_commit_count == 3
    )
    assert receipt_path.read_bytes() == canonical_json_bytes(receipt)
    assert material_path.read_bytes() == canonical_json_bytes(receipt.call_material)
    journal_path = next((tmp_path / "state").glob("owner-fence-*.json"))
    journal = OwnerFenceJournal.model_validate_json(journal_path.read_bytes())
    assert journal.phase == "already_applied"
    assert journal.extrinsic is None
    assert journal.receipt_sha256 == hashlib.sha256(receipt_path.read_bytes()).hexdigest()


@pytest.mark.asyncio
async def test_owner_fence_attestation_receipt_cross_binds_its_finalized_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed, _authorization, owner, _participants = _case()

    async def collect(_client, **_kwargs):
        return _owner_fence_preflight(owner, applied=True)

    monkeypatch.setattr(
        "umi.bootstrap_direct_weights.collect_owner_fence_preflight_with_client", collect
    )
    receipt = await attest_owner_fence(
        expected_owner_coldkey=owner.coldkeypub.ss58_address,
        receipt_output=tmp_path / "receipt.json",
        call_material_output=tmp_path / "material.json",
        state_dir=tmp_path / "state",
        client_factory=lambda _network: _ClientContext(object()),
        clock=lambda: NOW,
    )

    cases = (
        ({"observation_block": receipt.observation_block + 1}, "observation is not its preflight"),
        ({"observation_block_hash": BLOCK_HASH}, "observation is not its preflight"),
        (
            {
                "source_snapshot_pending_commit_count": receipt.source_snapshot_pending_commit_count
                + 1
            },
            "source pending count",
        ),
        (
            {"observed_pending_commit_count": receipt.observed_pending_commit_count + 1},
            "pending count",
        ),
    )
    for updates, reason in cases:
        values = receipt.model_dump(by_alias=True)
        values.update(updates)
        with pytest.raises(ValueError, match=reason):
            type(receipt).model_validate(values)

    legacy_material, _ = build_owner_fence_call(_owner_fence_preflight(owner))
    values = receipt.model_dump(by_alias=True)
    values["call_material"] = legacy_material.model_dump(by_alias=True)
    values["call_material_sha256"] = hashlib.sha256(
        canonical_json_bytes(legacy_material)
    ).hexdigest()
    with pytest.raises(ValueError, match="lacks a fenced-state preflight"):
        type(receipt).model_validate(values)


@pytest.mark.asyncio
@pytest.mark.parametrize("collision", ("journal", "lock", "state", "nested_outputs"))
async def test_owner_fence_attestation_rejects_output_state_path_collisions(
    tmp_path: Path,
    collision: str,
) -> None:
    _signed, _authorization, owner, _participants = _case()
    owner_account = account_id32(owner.coldkeypub.ss58_address).hex()
    state_dir = tmp_path / "state"
    stem = f"owner-fence-78-{DIRECT_WVK}-{owner_account}"
    receipt_output = tmp_path / "receipt.json"
    call_material_output = tmp_path / "material.json"
    if collision == "journal":
        call_material_output = state_dir / f"{stem}.json"
    elif collision == "lock":
        receipt_output = state_dir / f".{stem}.lock" / "receipt.json"
    elif collision == "state":
        receipt_output = state_dir
    else:
        call_material_output = receipt_output / "material.json"

    with pytest.raises(BootstrapOperatorError, match="output_state_paths_overlap"):
        await attest_owner_fence(
            expected_owner_coldkey=owner.coldkeypub.ss58_address,
            receipt_output=receipt_output,
            call_material_output=call_material_output,
            state_dir=state_dir,
            client_factory=lambda _network: (_ for _ in ()).throw(
                AssertionError("path rejection must precede network access")
            ),
            clock=lambda: NOW,
        )

    assert not state_dir.exists()


@pytest.mark.asyncio
async def test_owner_fence_attestation_rejects_unfenced_state_without_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed, _authorization, owner, _participants = _case()

    async def collect(_client, **_kwargs):
        return _owner_fence_preflight(owner)

    monkeypatch.setattr(
        "umi.bootstrap_direct_weights.collect_owner_fence_preflight_with_client", collect
    )
    with pytest.raises(BootstrapOperatorError, match="external_batch_not_applied"):
        await attest_owner_fence(
            expected_owner_coldkey=owner.coldkeypub.ss58_address,
            receipt_output=tmp_path / "receipt.json",
            call_material_output=tmp_path / "material.json",
            state_dir=tmp_path / "state",
            client_factory=lambda _network: _ClientContext(object()),
            clock=lambda: NOW,
        )

    assert not (tmp_path / "receipt.json").exists()
    assert not (tmp_path / "material.json").exists()
    assert not list((tmp_path / "state").glob("owner-fence-*.json"))


class _DirectSubmitClient:
    def __init__(self, *, fail_weight: bool = False):
        self.calls = []
        self.fail_weight = fail_weight

    async def submit_call(self, call, wallet, **kwargs):
        self.calls.append((call, wallet, kwargs))
        if len(self.calls) == 2 and self.fail_weight:
            raise ConnectionError("ambiguous weight call")
        block = 126 if len(self.calls) == 1 else 130
        index = len(self.calls)
        return SimpleNamespace(
            success=True,
            extrinsic_id=f"{block}-{index:04d}",
            block_hash="0x" + f"{20 + index:02x}" * 32,
        )


class _DirectSubmitChain:
    def __init__(
        self,
        client,
        signed,
        authorization,
        owner,
        participants,
        *,
        owner_after_anchor=None,
    ):
        self.client_factory = lambda _network: _ClientContext(client)
        self.clock = lambda: NOW
        validator_hotkey = authorization.validator_hotkey
        self.before = validate_direct_bootstrap_preflight(
            signed,
            _snapshot(participants),
            authorization=authorization,
            subnet_owner_hotkey=owner.hotkey.ss58_address,
            validator_hotkey=validator_hotkey,
            now=NOW,
        )
        after_anchor_participants = list(participants)
        observed_owner = owner_after_anchor or owner
        if owner_after_anchor is not None:
            after_anchor_participants[0] = after_anchor_participants[0].model_copy(
                update={"hotkey": owner_after_anchor.hotkey.ss58_address}
            )
        self.after_anchor = validate_direct_bootstrap_preflight(
            signed,
            _snapshot(
                after_anchor_participants,
                block_number=127,
                block_hash="0x" + "15" * 32,
                blocks_since_last_step=27,
            ),
            authorization=authorization,
            subnet_owner_hotkey=observed_owner.hotkey.ss58_address,
            validator_hotkey=validator_hotkey,
            now=NOW,
        )
        updated = [
            item.model_copy(update={"last_update": 130})
            if item.uid == authorization.validator_uid
            else item
            for item in after_anchor_participants
        ]
        self.after_weight = validate_direct_bootstrap_preflight(
            signed,
            _snapshot(
                updated,
                block_number=130,
                block_hash=POST_BLOCK_HASH,
                validator_mechid0_row=self.before.expected_applied_row,
                active_mechid0_row_hotkeys=[validator_hotkey],
                blocks_since_last_step=30,
            ),
            authorization=authorization,
            subnet_owner_hotkey=observed_owner.hotkey.ss58_address,
            validator_hotkey=validator_hotkey,
            now=NOW,
            require_submission_ready=False,
        )

    async def direct_operational_preflight_with_client(self, *_args, **_kwargs):
        return _operational(_args[1], self.before)

    async def direct_preflight_with_client(self, *_args, **kwargs):
        return (
            self.after_weight
            if kwargs.get("require_submission_ready") is False
            else self.after_anchor
        )

    async def verify_manifest_anchor_with_client(
        self, _client, signed, *, validator_hotkey, anchor, post_anchor
    ):
        assert validator_hotkey == self.before.validator_hotkey
        return BootstrapManifestAnchorObservation(
            manifest_sha256=signed.manifest_sha256,
            anchor=anchor,
            observation_block=post_anchor.snapshot.block_number,
            observation_block_hash=post_anchor.snapshot.block_hash,
            stored_commitment_block=anchor.block_number,
            field_count=1,
            field_type="Data::Sha256",
            field_sha256=signed.manifest_sha256,
            sdk_finalized_read_verified=True,
            storage_proofs_verified=False,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("ambiguous", [False, True])
async def test_direct_submit_hotkey_readback_and_ambiguous_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ambiguous: bool,
) -> None:
    signed, authorization, owner, participants = _case()
    client = _DirectSubmitClient(fail_weight=ambiguous)
    chain = _DirectSubmitChain(client, signed, authorization, owner, participants)

    async def health(_signed, preflight, **_kwargs):
        return _operational(_signed, preflight).health

    monkeypatch.setattr("umi.bootstrap_direct_weights.probe_bootstrap_health", health)
    callback_events: list[tuple[object, ...]] = []

    def before_first_effect() -> None:
        assert client.calls == []
        callback_events.append(("intent",))

    async def finalized_snapshot_guard(
        block_number: int,
        block_hash: str,
        headroom: int,
    ) -> None:
        callback_events.append(("snapshot", block_number, block_hash, headroom))

    values = dict(
        authorization=authorization,
        wallet=owner,
        chain=chain,
        receipt_output=tmp_path / "receipt.json",
        call_material_output=tmp_path / "material.json",
        state_dir=tmp_path / "state",
        live_submit=True,
        acknowledgement="SUBMIT SN78 DIRECT FULL BOOTSTRAP ROW",
        before_first_effect=before_first_effect,
        finalized_snapshot_guard=finalized_snapshot_guard,
    )
    if ambiguous:
        with pytest.raises(ConnectionError, match="ambiguous weight call"):
            await submit_direct_bootstrap_weights(signed, **values)
        journal_path = next((tmp_path / "state").glob("direct-*.json"))
        journal = DirectBootstrapSubmissionJournal.model_validate_json(journal_path.read_bytes())
        assert journal.phase == "material_written"
        values["receipt_output"] = tmp_path / "receipt-2.json"
        values["call_material_output"] = tmp_path / "material-2.json"
        with pytest.raises(BootstrapOperatorError, match="claim_exists_reconcile_required"):
            await submit_direct_bootstrap_weights(signed, **values)
        assert len(client.calls) == 2
        assert callback_events[:3] == [
            ("snapshot", 125, BLOCK_HASH, 16),
            ("intent",),
            ("snapshot", 127, "0x" + "15" * 32, 8),
        ]
        return

    receipt = await submit_direct_bootstrap_weights(signed, **values)
    assert receipt.classification == "applied"
    assert [item[0].function for item in client.calls] == [
        "set_commitment",
        "set_mechanism_weights",
    ]
    assert all(item[2]["signer"] == "hotkey" for item in client.calls)
    assert all(item[2]["wait_for_finalization"] is True for item in client.calls)
    assert callback_events == [
        ("snapshot", 125, BLOCK_HASH, 16),
        ("intent",),
        ("snapshot", 127, "0x" + "15" * 32, 8),
        ("snapshot", 130, POST_BLOCK_HASH, 0),
    ]
    journal_path = next((tmp_path / "state").glob("direct-*.json"))
    assert DirectBootstrapSubmissionJournal.model_validate_json(
        journal_path.read_bytes()
    ).phase == ("applied")


@pytest.mark.asyncio
async def test_direct_submit_orchestrates_the_authorized_uid_200_hotkey(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed, authorization, owner, validator, participants, _preflight = _permitted_case()
    client = _DirectSubmitClient()
    chain = _DirectSubmitChain(client, signed, authorization, owner, participants)

    async def health(_signed, preflight, **_kwargs):
        return _operational(_signed, preflight).health

    monkeypatch.setattr("umi.bootstrap_direct_weights.probe_bootstrap_health", health)
    receipt = await submit_direct_bootstrap_weights(
        signed,
        authorization=authorization,
        wallet=validator,
        chain=chain,
        receipt_output=tmp_path / "receipt.json",
        call_material_output=tmp_path / "material.json",
        state_dir=tmp_path / "state",
        live_submit=True,
        acknowledgement="SUBMIT SN78 DIRECT FULL BOOTSTRAP ROW",
    )

    assert receipt.classification == "applied"
    assert receipt.validator_uid == 200
    assert receipt.validator_hotkey == validator.hotkey.ss58_address
    assert receipt.observed_last_update == 130
    assert all(call[1] is validator for call in client.calls)
    assert all(call[2]["signer"] == "hotkey" for call in client.calls)
    assert client.calls[1][0].params["dests"] == list(range(256))
    assert client.calls[1][0].params["weights"][200] == 0


@pytest.mark.asyncio
async def test_direct_submit_rejects_owner_rotation_after_anchor_before_weight_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed, authorization, owner, validator, participants, _preflight = _permitted_case()
    client = _DirectSubmitClient()
    rotated_owner = dev_wallet("//DirectBootstrapRotatedOwner")
    chain = _DirectSubmitChain(
        client,
        signed,
        authorization,
        owner,
        participants,
        owner_after_anchor=rotated_owner,
    )

    async def health(_signed, preflight, **_kwargs):
        return _operational(_signed, preflight).health

    monkeypatch.setattr("umi.bootstrap_direct_weights.probe_bootstrap_health", health)
    with pytest.raises(BootstrapOperatorError, match="direct_subnet_owner_changed_after_anchor"):
        await submit_direct_bootstrap_weights(
            signed,
            authorization=authorization,
            wallet=validator,
            chain=chain,
            receipt_output=tmp_path / "receipt.json",
            call_material_output=tmp_path / "material.json",
            state_dir=tmp_path / "state",
            live_submit=True,
            acknowledgement="SUBMIT SN78 DIRECT FULL BOOTSTRAP ROW",
        )

    assert [call[0].function for call in client.calls] == ["set_commitment"]
    assert not (tmp_path / "material.json").exists()
    assert not (tmp_path / "receipt.json").exists()
    journal_path = next((tmp_path / "state").glob("direct-*.json"))
    assert (
        DirectBootstrapSubmissionJournal.model_validate_json(journal_path.read_bytes()).phase
        == "anchor_finalized"
    )
