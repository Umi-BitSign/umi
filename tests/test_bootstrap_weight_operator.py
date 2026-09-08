from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import bittensor as bt
import pytest

from tests.factories import dev_wallet
from umi.bootstrap_weight_operator import (
    BOOTSTRAP_CUTOVER_CHECKPOINT_SCHEMA,
    BOOTSTRAP_HEALTH_SET_SCHEMA,
    BOOTSTRAP_OPERATIONAL_PREFLIGHT_SCHEMA,
    BOOTSTRAP_PILOT_REPLAY_SET_SCHEMA,
    BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA,
    LIVE_SUBMIT_ACKNOWLEDGEMENT,
    BittensorBootstrapChain,
    BootstrapChainParticipant,
    BootstrapChainSnapshot,
    BootstrapCutoverCheckpoint,
    BootstrapExtrinsicReference,
    BootstrapHealthHTTPResult,
    BootstrapHealthReceipt,
    BootstrapHealthReceiptSet,
    BootstrapManifestAnchorObservation,
    BootstrapOperationalPreflight,
    BootstrapOperatorError,
    BootstrapPilotReplayReceipt,
    BootstrapPilotReplaySet,
    BootstrapRevealPeriodObservation,
    BootstrapTerminalEvent,
    BootstrapTerminalObservation,
    BootstrapWeightCallMaterial,
    BootstrapWeightScheduleEvidence,
    BootstrapWeightSubmissionReceipt,
    build_bootstrap_weight_call_material,
    observe_bootstrap_sunset,
    observe_bootstrap_terminal,
    probe_bootstrap_health,
    sign_bootstrap_terminal_observation,
    submit_bootstrap_weights,
    validate_bootstrap_preflight,
    verify_runtime_checkout,
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
from umi.chain import _header_hash
from umi.chain_evidence import BuiltCRv4WeightCommit, WeightScheduleSnapshot
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.protocol import canonical_json_bytes

NOW = datetime(2026, 9, 8, 16, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1_000)
BLOCK_HASH = "0x" + "12" * 32


def test_bootstrap_container_validates_revision_length_and_charset() -> None:
    dockerfile = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "bootstrap-validator"
        / "Dockerfile"
    ).read_text(encoding="utf-8")

    assert 'test "${#UMI_GIT_REVISION}" -eq 40' in dockerfile
    assert "*[!0-9a-f]*)" in dockerfile


def _signed_manifest(*, count: int = 2):
    coordinator = dev_wallet("//BootstrapOperatorCoordinator")
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
        umi_git_revision="ab" * 20,
        weights_version_key=1,
        published_at_block=100,
        activation_block=120,
        commit_stop_block=49_080,
        hard_sunset_block=50_520,
        health_ttl_blocks=10,
        manifest_ttl_blocks=30,
    )
    entries: list[BootstrapEligibilityEntry] = []
    miners = []
    for index in range(count):
        miner = dev_wallet(f"//BootstrapOperatorMiner{index}")
        miners.append(miner)
        pilot_id = f"{index + 1:02x}" * 32
        opt_in = sign_bootstrap_opt_in(
            policy,
            pilot_id=pilot_id,
            wallet=miner,
            signed_at_block=121,
        )
        entries.append(
            BootstrapEligibilityEntry(
                pilot_id=pilot_id,
                miner_hotkey=miner.hotkey.ss58_address,
                uid=1 + index,
                origin=f"https://8.8.8.{index + 1}:443",
                pilot_block=90,
                health_block=124,
                utility=1,
                opt_in=opt_in,
            )
        )
    manifest = build_bootstrap_eligibility_manifest(
        policy,
        entries,
        frozen_at_block=125,
        frozen_at_block_hash=BLOCK_HASH,
    )
    return sign_bootstrap_eligibility_manifest(manifest, wallet=coordinator), miners


def _snapshot(signed, miners, *, validator=None, **changes) -> BootstrapChainSnapshot:
    validator = validator or dev_wallet("//BootstrapOperatorValidator")
    participants = [
        BootstrapChainParticipant(
            hotkey=validator.hotkey.ss58_address,
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
        for entry in signed.manifest.entries
    )
    values = {
        "network": "finney",
        "genesis_block_hash": f"0x{FINNEY_GENESIS_HASH}",
        "block_number": 125,
        "block_hash": BLOCK_HASH,
        "block_timestamp_ms": NOW_MS,
        "manifest_frozen_block_hash": BLOCK_HASH,
        "mechanism_count": 1,
        "commit_reveal_enabled": True,
        "commit_reveal_version": 4,
        "reveal_period_epochs": 1,
        "weights_version_key": 1,
        "min_allowed_weights": 1,
        "max_weights_limit": U16_MAX,
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


def _cutover(signed) -> BootstrapCutoverCheckpoint:
    return BootstrapCutoverCheckpoint(
        schema=BOOTSTRAP_CUTOVER_CHECKPOINT_SCHEMA,
        policy_sha256=signed.manifest.policy_sha256,
        published_at_block=100,
        published_at_block_hash="0x" + "10" * 32,
        published_weights_version_key=0,
        checkpoint_block=120,
        checkpoint_block_hash="0x" + "11" * 32,
        checkpoint_weights_version_key=1,
        mechanism_count=1,
        commit_reveal_enabled=True,
        commit_reveal_version=4,
        reveal_period_epochs=1,
        tempo=360,
        activity_cutoff_blocks=360,
        total_pending_commit_count=0,
        active_mechid0_row_hotkeys=[],
        storage_proofs_verified=False,
    )


def _operational(signed, preflight) -> BootstrapOperationalPreflight:
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
    return BootstrapOperationalPreflight(
        schema=BOOTSTRAP_OPERATIONAL_PREFLIGHT_SCHEMA,
        signed_manifest=signed,
        cutover=_cutover(signed),
        chain=preflight,
        pilot_replay=replay,
        health=health,
    )


def _applied_terminal(signed, validator_hotkey: str, row: list[list[int]]):
    commit = BootstrapExtrinsicReference(
        extrinsic_id="120-0001",
        block_number=120,
        extrinsic_index=1,
        block_hash="0x" + "44" * 32,
    )
    commit_event = BootstrapTerminalEvent(
        block_number=120,
        block_hash=commit.block_hash,
        event_index=2,
        extrinsic_index=1,
        event="TimelockedWeightsCommitted",
        commitment_blake2b256="aa" * 32,
        reveal_round=200,
        payload_sha256="55" * 32,
    )
    reveal_event = BootstrapTerminalEvent(
        block_number=124,
        block_hash="0x" + "66" * 32,
        event_index=0,
        extrinsic_index=None,
        event="TimelockedWeightsRevealed",
        payload_sha256="77" * 32,
    )
    return BootstrapTerminalObservation(
        schema="umi-bootstrap-terminal-observation/1",
        classification="applied",
        reason_codes=[],
        policy_sha256=signed.manifest.policy_sha256,
        manifest_sha256=signed.manifest_sha256,
        call_material_sha256="88" * 32,
        validator_hotkey=validator_hotkey,
        commit=commit,
        commit_epoch_index=4,
        reveal_round=200,
        ciphertext_sha256="99" * 32,
        observation_block=124,
        observation_block_hash=reveal_event.block_hash,
        expected_row=row,
        observed_row=row,
        mapping_checks_passed=True,
        validator_pending_commit=False,
        exact_epoch_entry_present=False,
        exact_epoch_queue_removal_observed=True,
        commit_event_unique_and_bound=True,
        duplicate_commit_absent=True,
        reveal_event_unique_and_bound=True,
        reveal_period_history_stable=True,
        row_matches_expected=True,
        sdk_finalized_reads_verified=True,
        commit_events=[commit_event],
        reveal_events=[reveal_event],
        reveal_period_history=[
            BootstrapRevealPeriodObservation(
                block_number=120,
                block_hash=commit.block_hash,
                reveal_period_epochs=1,
            ),
            BootstrapRevealPeriodObservation(
                block_number=124,
                block_hash=reveal_event.block_hash,
                reveal_period_epochs=1,
            ),
        ],
        event_interval_start=120,
        event_interval_end=124,
        event_storage_proofs_verified=False,
        exact_queue_removal_sdk_observed=True,
        row_storage_proof_verified=False,
        protocol_terminal_classification_verified=True,
    )


def _terminal_block_hash(block_number: int) -> str:
    return "0x" + block_number.to_bytes(32, "big").hex()


def _terminal_inputs(signed, miners, validator):
    preflight = validate_bootstrap_preflight(
        signed,
        _snapshot(signed, miners, validator=validator),
        validator_hotkey=validator.hotkey.ss58_address,
        now=NOW,
    )
    anchor = BootstrapExtrinsicReference(
        extrinsic_id="124-0000",
        block_number=124,
        extrinsic_index=0,
        block_hash=_terminal_block_hash(124),
    )
    anchor_observation = BootstrapManifestAnchorObservation(
        manifest_sha256=signed.manifest_sha256,
        anchor=anchor,
        observation_block=125,
        observation_block_hash=BLOCK_HASH,
        stored_commitment_block=124,
        field_count=1,
        field_type="Data::Sha256",
        field_sha256=signed.manifest_sha256,
        sdk_finalized_read_verified=True,
        storage_proofs_verified=False,
    )

    def fake_builder(**kwargs):
        raw_call = bt.calls.SubtensorModule.commit_timelocked_mechanism_weights(
            netuid=78,
            mecid=0,
            commit=b"ciphertext",
            reveal_round=900,
            commit_reveal_version=4,
        )
        return BuiltCRv4WeightCommit(
            schedule=kwargs["schedule"],
            netuid=78,
            uids=tuple(kwargs["uids"]),
            weights=tuple(kwargs["weights"]),
            weights_version_key=kwargs["weights_version_key"],
            hotkey_public_key=kwargs["hotkey_public_key"],
            ciphertext=b"ciphertext",
            reveal_round=900,
            raw_call=raw_call,
        )

    material, _built = build_bootstrap_weight_call_material(
        _operational(signed, preflight),
        manifest_anchor=anchor_observation,
        call_builder=fake_builder,
    )
    commit = BootstrapExtrinsicReference(
        extrinsic_id="126-0001",
        block_number=126,
        extrinsic_index=1,
        block_hash=_terminal_block_hash(126),
    )
    receipt = BootstrapWeightSubmissionReceipt(
        schema=BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA,
        status="commit_finalized_pending_terminal_verification",
        reason_code=None,
        manifest_sha256=signed.manifest_sha256,
        validator_hotkey=validator.hotkey.ss58_address,
        anchor=anchor,
        commit=commit,
        call_material_sha256=hashlib.sha256(canonical_json_bytes(material)).hexdigest(),
        commit_epoch_index=6,
        reveal_round=900,
        ciphertext_sha256=hashlib.sha256(b"ciphertext").hexdigest(),
        exact_commit_entry_observed=True,
        submission_era_period=8,
        storage_proofs_verified=False,
        terminal_verification_complete=False,
        created_at=NOW,
    )
    return material, receipt


def test_preflight_accepts_exact_equal_row_and_inactive_translation_policy() -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")

    result = validate_bootstrap_preflight(
        signed,
        _snapshot(signed, miners, validator=validator),
        validator_hotkey=validator.hotkey.ss58_address,
        now=NOW,
    )

    assert result.quantized_uids == [1, 2]
    assert result.quantized_weights == [U16_MAX, U16_MAX]
    assert sum(result.quantized_weights) == 2 * U16_MAX
    assert result.prior_row_classification == "empty"
    assert result.snapshot.weights_version_key == signed.manifest.policy.weights_version_key


def test_runtime_checkout_accepts_only_immutable_exact_image_marker(tmp_path: Path) -> None:
    signed, _miners = _signed_manifest()
    marker = tmp_path / "image-revision"
    marker.write_text(signed.manifest.policy.umi_git_revision + "\n", encoding="ascii")
    marker.chmod(0o444)

    verify_runtime_checkout(
        signed.manifest.policy,
        repository=tmp_path,
        image_revision_path=marker,
    )

    marker.chmod(0o644)
    with pytest.raises(BootstrapOperatorError, match="image_revision_marker_invalid"):
        verify_runtime_checkout(
            signed.manifest.policy,
            repository=tmp_path,
            image_revision_path=marker,
        )


@pytest.mark.asyncio
async def test_health_probe_accepts_httpx_default_port_canonicalization() -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    preflight = validate_bootstrap_preflight(
        signed,
        _snapshot(signed, miners, validator=validator),
        validator_hotkey=validator.hotkey.ss58_address,
        now=NOW,
    )

    async def request(url: str):
        return BootstrapHealthHTTPResult(
            requested_url=url,
            final_url=url.replace(":443/", "/"),
            status_code=200,
            body=b"{}",
            tls_certificate_sha256="33" * 32,
        )

    result = await probe_bootstrap_health(signed, preflight, request=request)
    assert len(result.receipts) == 2


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"mechanism_count": 2}, "mechanism_count_mismatch"),
        ({"commit_reveal_enabled": False}, "commit_reveal_disabled"),
        ({"commit_reveal_version": 3}, "commit_reveal_version_mismatch"),
        ({"reveal_period_epochs": 2}, "reveal_period_mismatch"),
        ({"weights_version_key": 2}, "weights_version_key_mismatch"),
        ({"validator_has_pending_commit": True}, "validator_pending_commit_exists"),
        ({"min_allowed_weights": 3}, "row_below_min_allowed_weights"),
        ({"max_weights_limit": 32_767}, "row_exceeds_max_weight_ratio"),
        ({"max_allowed_uids": 2}, "row_exceeds_uid_limit"),
        ({"weights_set_rate_limit": 30}, "weights_rate_limit_not_elapsed"),
    ],
)
def test_preflight_fails_closed_on_live_chain_mismatch(changes, reason: str) -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")

    with pytest.raises(BootstrapOperatorError, match=reason):
        validate_bootstrap_preflight(
            signed,
            _snapshot(signed, miners, validator=validator, **changes),
            validator_hotkey=validator.hotkey.ss58_address,
            now=NOW,
        )


def test_preflight_rechecks_miner_mapping_permit_origin_and_validator_row() -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    base = _snapshot(signed, miners, validator=validator)

    changed = base.model_dump(mode="json")
    changed["participants"][1]["uid"] = 30
    with pytest.raises(BootstrapOperatorError, match="eligible_miner_uid_mismatch"):
        validate_bootstrap_preflight(
            signed,
            BootstrapChainSnapshot.model_validate(changed),
            validator_hotkey=validator.hotkey.ss58_address,
            now=NOW,
        )


def test_preflight_allows_only_named_applied_bootstrap_row_refresh() -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    base = _snapshot(signed, miners, validator=validator)
    row = [[1, U16_MAX]]
    snapshot = _snapshot(
        signed,
        miners,
        validator=validator,
        validator_mechid0_row=row,
    )
    terminal = _applied_terminal(signed, validator.hotkey.ss58_address, row)

    result = validate_bootstrap_preflight(
        signed,
        snapshot,
        validator_hotkey=validator.hotkey.ss58_address,
        prior_terminal=terminal,
        now=NOW,
    )

    assert result.prior_row_classification == "active_prior_bootstrap"
    assert (
        result.prior_terminal_sha256 == hashlib.sha256(canonical_json_bytes(terminal)).hexdigest()
    )

    changed = base.model_dump(mode="json")
    changed["participants"][1]["origin"] = "https://8.8.4.4:443"
    with pytest.raises(BootstrapOperatorError, match="eligible_miner_origin_mismatch"):
        validate_bootstrap_preflight(
            signed,
            BootstrapChainSnapshot.model_validate(changed),
            validator_hotkey=validator.hotkey.ss58_address,
            now=NOW,
        )

    changed = base.model_dump(mode="json")
    changed["participants"][1]["validator_permit"] = True
    with pytest.raises(BootstrapOperatorError, match="eligible_miner_has_validator_permit"):
        validate_bootstrap_preflight(
            signed,
            BootstrapChainSnapshot.model_validate(changed),
            validator_hotkey=validator.hotkey.ss58_address,
            now=NOW,
        )

    changed = base.model_dump(mode="json")
    changed["validator_mechid0_row"] = [[1, U16_MAX]]
    changed["participants"][0]["last_update"] = 120
    with pytest.raises(BootstrapOperatorError, match="previous_validator_row_active"):
        validate_bootstrap_preflight(
            signed,
            BootstrapChainSnapshot.model_validate(changed),
            validator_hotkey=validator.hotkey.ss58_address,
            now=NOW,
        )


def test_call_builder_uses_one_explicit_schedule_and_max_upscaled_values() -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    preflight = validate_bootstrap_preflight(
        signed,
        _snapshot(signed, miners, validator=validator),
        validator_hotkey=validator.hotkey.ss58_address,
        now=NOW,
    )
    operational = _operational(signed, preflight)
    captured: dict[str, Any] = {}

    def fake_builder(**kwargs):
        captured.update(kwargs)
        raw_call = bt.calls.SubtensorModule.commit_timelocked_mechanism_weights(
            netuid=78,
            mecid=0,
            commit=b"ciphertext",
            reveal_round=900,
            commit_reveal_version=4,
        )
        return BuiltCRv4WeightCommit(
            schedule=kwargs["schedule"],
            netuid=78,
            uids=tuple(kwargs["uids"]),
            weights=tuple(kwargs["weights"]),
            weights_version_key=kwargs["weights_version_key"],
            hotkey_public_key=kwargs["hotkey_public_key"],
            ciphertext=b"ciphertext",
            reveal_round=900,
            raw_call=raw_call,
        )

    material, built = build_bootstrap_weight_call_material(
        operational,
        call_builder=fake_builder,
    )

    assert isinstance(captured["schedule"], WeightScheduleSnapshot)
    assert captured["schedule"].block_number == 125
    assert captured["uids"] == [1, 2]
    assert captured["weights"] == [U16_MAX, U16_MAX]
    assert material.ciphertext == "0x" + b"ciphertext".hex()
    assert material.schedule.block_number == 125
    assert built.raw_call.params["mecid"] == 0
    assert built.raw_call.params["commit_reveal_version"] == 4

    tampered = material.model_dump(mode="json", by_alias=True)
    tampered["uids"] = [1, 3]
    with pytest.raises(ValueError, match="core inputs"):
        BootstrapWeightCallMaterial.model_validate_json(canonical_json_bytes(tampered), strict=True)


class _ClientContext:
    def __init__(self, client):
        self.client = client

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, *_args):
        return None


class _SubmittingClient:
    def __init__(self, validator_hotkey: str):
        self.calls = []
        self.validator_hotkey = validator_hotkey

    async def submit_call(self, call, wallet, **kwargs):
        self.calls.append((call, wallet, kwargs))
        index = len(self.calls)
        return SimpleNamespace(
            success=True,
            extrinsic_id=f"{125 + index}-{index:04d}",
            block_hash="0x" + f"{index + 20:02x}" * 32,
        )

    async def at(self, block):
        assert block == 127
        validator_hotkey = self.validator_hotkey

        class CommitSnapshot:
            async def block_info(self):
                return SimpleNamespace(number=127, hash="0x" + "16" * 32)

            async def read(self, name, **params):
                assert name == "timelocked_weight_commits"
                assert params == {"netuid": 78, "mechid": 0}
                return {
                    6: [
                        {
                            "hotkey": validator_hotkey,
                            "commit_block": 127,
                            "reveal_round": 900,
                            "ciphertext": b"ciphertext",
                        }
                    ]
                }

        return CommitSnapshot()


class _SubmissionChain:
    def __init__(self, client, signed, preflight):
        self.client = client
        self.signed = signed
        self.preflight_value = preflight
        post = preflight.model_dump(mode="json", by_alias=True)
        post["snapshot"]["block_number"] = 126
        post["snapshot"]["block_hash"] = "0x" + "15" * 32
        post["snapshot"]["blocks_since_last_step"] = 26
        self.post_preflight_value = type(preflight).model_validate(post)
        self.preflight_calls = 0
        self.clock = lambda: NOW
        self.client_factory = lambda _network: _ClientContext(client)

    async def operational_preflight_with_client(self, client, signed, **kwargs):
        assert client is self.client
        assert signed.manifest_sha256 == self.preflight_value.manifest_sha256
        assert kwargs["validator_hotkey"] == self.preflight_value.validator_hotkey
        self.preflight_calls += 1
        return _operational(signed, self.preflight_value)

    async def preflight_with_client(self, client, signed, **kwargs):
        assert client is self.client
        assert kwargs["validator_hotkey"] == self.preflight_value.validator_hotkey
        self.preflight_calls += 1
        return self.post_preflight_value

    async def verify_manifest_anchor_with_client(
        self, client, signed, *, validator_hotkey, anchor, post_anchor
    ):
        assert client is self.client
        assert validator_hotkey == self.preflight_value.validator_hotkey
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

    async def current_schedule_with_client(self, client, policy):
        assert client is self.client
        assert policy == self.signed.manifest.policy
        snapshot = self.post_preflight_value.snapshot
        return BootstrapWeightScheduleEvidence(
            block_number=126,
            block_hash=snapshot.block_hash,
            tempo=360,
            last_epoch_block=100,
            pending_epoch_at=0,
            subnet_epoch_index=5,
            blocks_since_last_step=26,
            reveal_period_epochs=1,
            block_time=12.0,
            weights_version_key=1,
            commit_reveal_enabled=True,
            commit_reveal_version=4,
            mechanism_count=1,
        )


@pytest.mark.asyncio
async def test_submit_requires_ack_and_anchors_before_raw_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    preflight = validate_bootstrap_preflight(
        signed,
        _snapshot(signed, miners, validator=validator),
        validator_hotkey=validator.hotkey.ss58_address,
        now=NOW,
    )
    client = _SubmittingClient(validator.hotkey.ss58_address)
    chain = _SubmissionChain(client, signed, preflight)
    output = tmp_path / "receipt.json"
    material_output = tmp_path / "material.json"
    state_dir = tmp_path / "state"

    with pytest.raises(BootstrapOperatorError, match="acknowledgement"):
        await submit_bootstrap_weights(
            signed,
            cutover=_cutover(signed),
            wallet=validator,
            chain=chain,  # type: ignore[arg-type]
            receipt_output=output,
            call_material_output=material_output,
            state_dir=state_dir,
            live_submit=False,
            acknowledgement=LIVE_SUBMIT_ACKNOWLEDGEMENT,
        )
    assert client.calls == []

    raw_call = bt.calls.SubtensorModule.commit_timelocked_mechanism_weights(
        netuid=78,
        mecid=0,
        commit=b"ciphertext",
        reveal_round=900,
        commit_reveal_version=4,
    )
    built = BuiltCRv4WeightCommit(
        schedule=WeightScheduleSnapshot(
            block_number=126,
            block_hash="0x" + "15" * 32,
            tempo=360,
            last_epoch_block=100,
            pending_epoch_at=0,
            subnet_epoch_index=5,
            blocks_since_last_step=26,
            reveal_period_epochs=1,
            block_time=12.0,
        ),
        netuid=78,
        uids=(1, 2),
        weights=(U16_MAX, U16_MAX),
        weights_version_key=1,
        hotkey_public_key=bytes(validator.hotkey.public_key),
        ciphertext=b"ciphertext",
        reveal_round=900,
        raw_call=raw_call,
    )

    def fake_builder(**_kwargs):
        return built

    async def healthy(url):
        return BootstrapHealthHTTPResult(
            requested_url=url,
            final_url=url,
            status_code=200,
            body=b"{}",
            tls_certificate_sha256="33" * 32,
        )

    receipt = await submit_bootstrap_weights(
        signed,
        cutover=_cutover(signed),
        wallet=validator,
        chain=chain,  # type: ignore[arg-type]
        receipt_output=output,
        call_material_output=material_output,
        state_dir=state_dir,
        live_submit=True,
        acknowledgement=LIVE_SUBMIT_ACKNOWLEDGEMENT,
        health_request=healthy,
        call_builder=fake_builder,
    )

    assert chain.preflight_calls == 2
    assert len(client.calls) == 2
    assert client.calls[0][0].module == "Commitments"
    assert client.calls[0][0].params["info"]["fields"] == [
        {"Sha256": bytes.fromhex(signed.manifest_sha256)}
    ]
    assert client.calls[1][0] == raw_call
    assert all(call[2]["signer"] == "hotkey" for call in client.calls)
    assert all(call[2]["wait_for_finalization"] is True for call in client.calls)
    assert receipt.status == "commit_finalized_pending_terminal_verification"
    assert output.read_bytes() == canonical_json_bytes(receipt)
    assert BootstrapWeightCallMaterial.model_validate_json(material_output.read_bytes())
    assert os.stat(output).st_mode & 0o777 == 0o600


class _Headers:
    def __init__(self, header):
        self.header = header
        self.used = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.used:
            raise StopAsyncIteration
        self.used = True
        return self.header

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_live_collector_pins_all_reads_to_one_finalized_snapshot() -> None:
    signed, _miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    header_body = {
        "number": 125,
        "parentHash": "0x" + "21" * 32,
        "stateRoot": "0x" + "22" * 32,
        "extrinsicsRoot": "0x" + "23" * 32,
        "digest": {"logs": []},
    }
    finalized_hash = _header_hash(header_body, "test header")
    neurons = [
        SimpleNamespace(
            uid=0,
            hotkey=validator.hotkey.ss58_address,
            validator_permit=True,
            last_update=100,
            axon=None,
        )
    ] + [
        SimpleNamespace(
            uid=entry.uid,
            hotkey=entry.miner_hotkey,
            validator_permit=False,
            last_update=100,
            axon=entry.origin.removeprefix("https://"),
        )
        for entry in signed.manifest.entries
    ]
    maximum_uid = max(neuron.uid for neuron in neurons)
    permit_column = [False] * (maximum_uid + 1)
    update_column = [0] * (maximum_uid + 1)
    for neuron in neurons:
        permit_column[neuron.uid] = neuron.validator_permit
        update_column[neuron.uid] = neuron.last_update

    class Subnets:
        async def metagraph(self, *, netuid, commitments):
            assert (netuid, commitments) == (78, False)
            return SimpleNamespace(netuid=78, mechid=0, block=125, neurons=neurons)

    class Pinned:
        block = 125
        subnets = Subnets()

        async def block_info(self):
            return SimpleNamespace(
                number=125,
                hash=finalized_hash,
                timestamp=NOW,
                header=header_body,
            )

        async def query(self, descriptor, params=None):
            if descriptor.name == "Weights":
                assert params is not None and len(params) == 2 and params[0] == 78
            values = {
                "MechanismCountCurrent": 1,
                "CommitRevealWeightsEnabled": True,
                "CommitRevealWeightsVersion": 4,
                "RevealPeriodEpochs": 1,
                "WeightsVersionKey": 1,
                "MinAllowedWeights": 1,
                "MaxWeightsLimit": U16_MAX,
                "MaxAllowedUids": 256,
                "WeightsSetRateLimit": 0,
                "ActivityCutoff": 360,
                "ActivityCutoffFactorMilli": 1_000,
                "Tempo": 360,
                "LastEpochBlock": 100,
                "PendingEpochAt": 0,
                "SubnetEpochIndex": 5,
                "BlocksSinceLastStep": 25,
                "ValidatorPermit": permit_column,
                "LastUpdate": update_column,
                "Weights": [],
            }
            return values[descriptor.name]

        async def read(self, name, **params):
            assert name == "timelocked_weight_commits"
            assert params == {"netuid": 78, "mechid": 0}
            return {}

    class Substrate:
        async def block_hash(self, block):
            if block == 0:
                return f"0x{FINNEY_GENESIS_HASH}"
            assert block == 125
            return BLOCK_HASH

        async def block_time(self):
            return 12.0

    class Client:
        _substrate = Substrate()

        def blocks(self, *, finalized):
            assert finalized is True
            return _Headers(
                SimpleNamespace(number=125, parent_hash=header_body["parentHash"], raw=header_body)
            )

        async def at(self, block):
            assert block == 125
            return Pinned()

    chain = BittensorBootstrapChain(clock=lambda: NOW)
    result = await chain.preflight_with_client(
        Client(),
        signed,
        validator_hotkey=validator.hotkey.ss58_address,
    )

    assert result.snapshot.block_hash == finalized_hash
    assert result.snapshot.manifest_frozen_block_hash == BLOCK_HASH
    assert result.validator_uid == 0
    assert result.quantized_weights == [U16_MAX, U16_MAX]


class _TerminalPinned:
    def __init__(self, client: _TerminalClient, block_number: int):
        self.client = client
        self.block_number = block_number

    async def block_info(self):
        return SimpleNamespace(
            number=self.block_number,
            hash=_terminal_block_hash(self.block_number),
        )

    async def query(self, descriptor, params=None):
        assert descriptor.name == "RevealPeriodEpochs"
        assert params == [78]
        return self.client.reveal_periods.get(self.block_number, 1)

    async def read(self, name, **params):
        assert self.block_number == self.client.observation_block
        assert name == "timelocked_weight_commits"
        assert params == {"netuid": 78, "mechid": 0}
        return self.client.pending


class _TerminalSubstrate:
    def __init__(self, client: _TerminalClient):
        self.client = client

    async def block_hash(self, block_number: int):
        return _terminal_block_hash(block_number)

    async def events(self, block_hash: str):
        return self.client.events.get(block_hash, [])


class _TerminalClient:
    def __init__(
        self,
        *,
        observation_block: int,
        pending: dict[int, list[dict[str, Any]]],
        events: dict[str, list[dict[str, Any]]],
        reveal_periods: dict[int, int] | None = None,
        subnet_emission_enabled: int | bool = 0,
    ):
        self.observation_block = observation_block
        self.pending = pending
        self.events = events
        self.reveal_periods = reveal_periods or {}
        self.subnet_emission_enabled = subnet_emission_enabled
        self._substrate = _TerminalSubstrate(self)

    async def at(self, block_number: int):
        if block_number == self.observation_block and not self.events:
            client = self

            class SunsetPinned:
                async def read(self, name, **params):
                    assert name == "subnet_emission_enabled"
                    assert params == {"netuid": 78}
                    return client.subnet_emission_enabled

            return SunsetPinned()
        return _TerminalPinned(self, block_number)


class _ObservationChain:
    def __init__(self, snapshot: BootstrapChainSnapshot, client: _TerminalClient):
        self.snapshot = snapshot
        self.client = client
        self.checkout_verified = False
        self.client_factory = lambda _network: _ClientContext(client)

    def checkout_verifier(self, policy):
        assert policy.weights_version_key == 1
        self.checkout_verified = True

    async def _snapshot(self, client, signed, *, validator_hotkey, allow_missing_validator):
        assert client is self.client
        assert signed.manifest.policy.weights_version_key == 1
        assert validator_hotkey
        assert allow_missing_validator is True
        return self.snapshot


def _terminal_events(
    validator_hotkey: str,
    *,
    commitment_hash: str,
    reveal_round: int,
    duplicate: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    commit = {
        "event": {
            "module_id": "SubtensorModule",
            "event_id": "TimelockedWeightsCommitted",
            "attributes": [validator_hotkey, 78, commitment_hash, reveal_round],
        },
        "extrinsic_idx": 1,
    }
    return {
        _terminal_block_hash(126): [commit, commit] if duplicate else [commit],
        _terminal_block_hash(129): [
            {
                "event": {
                    "module_id": "SubtensorModule",
                    "event_id": "TimelockedWeightsRevealed",
                    "attributes": [78, validator_hotkey],
                },
                "extrinsic_idx": None,
            }
        ],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "hash_override",
        "round_override",
        "duplicate",
        "receipt_block_hash_override",
        "classification",
    ),
    [
        (None, None, False, None, "applied"),
        ("ff" * 32, None, False, None, "failed"),
        (None, 901, False, None, "failed"),
        (None, None, True, None, "failed"),
        (None, None, False, "0x" + "ff" * 32, "failed"),
    ],
)
async def test_terminal_binds_live_commit_event_hash_round_and_uniqueness(
    hash_override: str | None,
    round_override: int | None,
    duplicate: bool,
    receipt_block_hash_override: str | None,
    classification: str,
) -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    material, receipt = _terminal_inputs(signed, miners, validator)
    if receipt_block_hash_override is not None:
        receipt = receipt.model_copy(
            update={
                "commit": receipt.commit.model_copy(
                    update={"block_hash": receipt_block_hash_override}
                )
            }
        )
    expected_hash = hashlib.blake2b(b"ciphertext", digest_size=32).hexdigest()
    events = _terminal_events(
        validator.hotkey.ss58_address,
        commitment_hash=hash_override or expected_hash,
        reveal_round=round_override or 900,
        duplicate=duplicate,
    )
    row = [[uid, weight] for uid, weight in zip(material.uids, material.weights, strict=True)]
    snapshot = _snapshot(
        signed,
        miners,
        validator=validator,
        block_number=130,
        block_hash=_terminal_block_hash(130),
        validator_mechid0_row=row,
        validator_has_pending_commit=False,
        total_pending_commit_count=0,
        active_mechid0_row_hotkeys=[validator.hotkey.ss58_address],
    )
    client = _TerminalClient(observation_block=130, pending={}, events=events)
    chain = _ObservationChain(snapshot, client)

    result = await observe_bootstrap_terminal(
        signed,
        receipt,
        material,
        chain=chain,  # type: ignore[arg-type]
    )

    assert result.classification == classification
    assert result.commit_event_unique_and_bound is (classification == "applied")
    assert result.duplicate_commit_absent is (not duplicate)
    assert chain.checkout_verified is True


@pytest.mark.asyncio
async def test_terminal_reports_exact_entry_as_pending() -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    material, receipt = _terminal_inputs(signed, miners, validator)
    expected_hash = hashlib.blake2b(b"ciphertext", digest_size=32).hexdigest()
    events = _terminal_events(
        validator.hotkey.ss58_address,
        commitment_hash=expected_hash,
        reveal_round=900,
    )
    events.pop(_terminal_block_hash(129))
    pending = {
        6: [
            {
                "hotkey": validator.hotkey.ss58_address,
                "commit_block": 126,
                "reveal_round": 900,
                "ciphertext": b"ciphertext",
            }
        ]
    }
    snapshot = _snapshot(
        signed,
        miners,
        validator=validator,
        block_number=127,
        block_hash=_terminal_block_hash(127),
        validator_has_pending_commit=True,
        total_pending_commit_count=1,
    )
    chain = _ObservationChain(
        snapshot,
        _TerminalClient(observation_block=127, pending=pending, events=events),
    )

    result = await observe_bootstrap_terminal(
        signed,
        receipt,
        material,
        chain=chain,  # type: ignore[arg-type]
    )

    assert result.classification == "pending"
    assert result.exact_epoch_entry_present is True
    assert result.protocol_terminal_classification_verified is False


@pytest.mark.asyncio
@pytest.mark.parametrize("validator_change", ["missing", "uid", "permit"])
async def test_terminal_signs_failure_when_validator_mapping_changes(
    validator_change: str,
) -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    material, receipt = _terminal_inputs(signed, miners, validator)
    expected_hash = hashlib.blake2b(b"ciphertext", digest_size=32).hexdigest()
    events = _terminal_events(
        validator.hotkey.ss58_address,
        commitment_hash=expected_hash,
        reveal_round=900,
    )
    row = [[uid, weight] for uid, weight in zip(material.uids, material.weights, strict=True)]
    baseline = _snapshot(
        signed,
        miners,
        validator=validator,
        block_number=130,
        block_hash=_terminal_block_hash(130),
        validator_mechid0_row=row,
    ).model_dump(mode="json")
    if validator_change == "missing":
        baseline["participants"] = baseline["participants"][1:]
        baseline["validator_mechid0_row"] = []
    elif validator_change == "uid":
        baseline["participants"][0]["uid"] = 10
    else:
        baseline["participants"][0]["validator_permit"] = False
    snapshot = BootstrapChainSnapshot.model_validate(baseline)
    chain = _ObservationChain(
        snapshot,
        _TerminalClient(observation_block=130, pending={}, events=events),
    )

    observation = await observe_bootstrap_terminal(
        signed,
        receipt,
        material,
        chain=chain,  # type: ignore[arg-type]
    )
    result = sign_bootstrap_terminal_observation(observation, wallet=validator)

    assert result.observation.classification == "failed"
    assert "validator_mapping_changed" in result.observation.reason_codes
    assert result.observation.protocol_terminal_classification_verified is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("block_number", "emission", "expected_status"),
    [
        (119, 1, "pre_activation"),
        (120, 1, "commit_interval_open"),
        (49_080, 1, "commits_closed_awaiting_sunset"),
        (50_520, 0, "sunset_clean_sdk_observation"),
        (50_520, 1, "sunset_incident_sdk_observation"),
    ],
)
async def test_sunset_status_handles_live_integer_flag_without_claiming_activation(
    block_number: int,
    emission: int,
    expected_status: str,
) -> None:
    signed, miners = _signed_manifest()
    validator = dev_wallet("//BootstrapOperatorValidator")
    snapshot = _snapshot(
        signed,
        miners,
        validator=validator,
        block_number=block_number,
        block_hash=_terminal_block_hash(block_number),
        last_epoch_block=min(100, block_number),
        blocks_since_last_step=min(25, block_number),
        total_pending_commit_count=0,
        active_mechid0_row_hotkeys=[],
    )
    client = _TerminalClient(
        observation_block=block_number,
        pending={},
        events={},
        subnet_emission_enabled=emission,
    )
    chain = _ObservationChain(snapshot, client)

    result = await observe_bootstrap_sunset(
        signed,
        validator_hotkey=validator.hotkey.ss58_address,
        chain=chain,  # type: ignore[arg-type]
    )

    assert result.status == expected_status
    assert result.service_weights_active is False
