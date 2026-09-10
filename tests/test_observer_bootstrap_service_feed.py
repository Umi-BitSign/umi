from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tests.factories import dev_wallet
from umi import observer_bootstrap_service_feed as bootstrap_feed_module
from umi.bootstrap_direct_weights import (
    DIRECT_SUBMISSION_JOURNAL_SCHEMA,
    DIRECT_TRANSITION_PROFILE,
    DirectBootstrapSubmissionJournal,
    OwnerFenceReceipt,
    build_direct_bootstrap_call_material,
    build_owner_fence_call,
    classify_direct_bootstrap_application,
    sign_direct_transition_authorization,
    validate_direct_bootstrap_preflight,
)
from umi.bootstrap_weight_operator import (
    BootstrapExtrinsicReference,
    BootstrapManifestAnchorObservation,
)
from umi.bootstrap_weights import SignedBootstrapEligibilityManifest
from umi.encoding import account_id32
from umi.observer import create_observer_app
from umi.observer_bootstrap_service_feed import (
    ObserverBootstrapServiceFeed,
    build_bootstrap_service_publication,
    build_observer_bootstrap_service_feed,
)
from umi.observer_models import ChainValidatorWeightRow, ObserverSnapshot
from umi.observer_pilot_feed import ObserverPilotFeed, VerifiedComponentPilot
from umi.protocol import canonical_json_bytes
from umi.simple_bootstrap_validator import (
    SIMPLE_BOOTSTRAP_LEASE_SCHEMA,
    SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION,
    SignedSimpleBootstrapLease,
    build_simple_bootstrap_lease_body,
)

from .test_bootstrap_direct_weights import (
    NOW,
    _operational,
    _owner_fence_preflight,
    _permitted_case,
    _preflight,
)
from .test_bootstrap_direct_weights import _snapshot as _bootstrap_snapshot
from .test_observer import SequenceCollector, _cache, _participant, _snapshot


def _fake_pilot_feed(signed) -> ObserverPilotFeed:
    pilots = []
    for entry in signed.manifest.entries:
        attestation = SimpleNamespace(
            outcome_classification="ok",
            expected_miner_uid=entry.uid,
            announced_origin=entry.origin,
            contacted_origin=entry.origin,
            chain_observation=SimpleNamespace(block_number=entry.pilot_block),
        )
        pilots.append(
            VerifiedComponentPilot(
                pilot_id=entry.pilot_id,
                public_origin="https://api.umi.vision",
                manifest_bytes=b"{}",
                objects=MappingProxyType({}),
                bundle_bytes=2,
                validator_hotkey=signed.manifest.policy.coordinator_hotkey,
                miner_hotkey=entry.miner_hotkey,
                missing_stages=("publisher_pool",),
                solutions=(),
                public_endpoint=SimpleNamespace(attestation=attestation),
            )
        )
    return ObserverPilotFeed(pilots=tuple(pilots))


def _terminal_records(
    *,
    permitted: bool = False,
    block_offset: int = 0,
    authorization_variant: bool = False,
    base_case=None,
):
    if base_case is not None:
        signed, authorization, owner, participants = base_case
    elif permitted:
        signed, authorization, owner, _validator, participants, _ = _permitted_case()
    else:
        signed, authorization, owner, participants, _ = _preflight()
    if authorization_variant:
        authorization = sign_direct_transition_authorization(
            signed,
            weights_version_key=authorization.weights_version_key,
            submission_id=authorization.submission_id,
            umi_git_revision=authorization.umi_git_revision,
            signed_at_block=authorization.signed_at_block,
            valid_from_block=authorization.valid_from_block + 1,
            expires_at_block=authorization.expires_at_block,
            validator_hotkey=authorization.validator_hotkey,
            validator_uid=authorization.validator_uid,
            wallet=dev_wallet("//DirectBootstrapCoordinator"),
        )
    anchor_block = 126 + block_offset
    preflight_block = 127 + block_offset
    weight_block = 130 + block_offset
    anchor = BootstrapExtrinsicReference(
        extrinsic_id=f"{anchor_block}-0001",
        block_number=anchor_block,
        extrinsic_index=1,
        block_hash="0x" + f"{0x14 + block_offset:02x}" * 32,
    )
    anchor_observation = BootstrapManifestAnchorObservation(
        manifest_sha256=signed.manifest_sha256,
        anchor=anchor,
        observation_block=preflight_block,
        observation_block_hash="0x" + f"{0x15 + block_offset:02x}" * 32,
        stored_commitment_block=anchor_block,
        field_count=1,
        field_type="Data::Sha256",
        field_sha256=signed.manifest_sha256,
        sdk_finalized_read_verified=True,
        storage_proofs_verified=False,
    )
    preflight = validate_direct_bootstrap_preflight(
        signed,
        _bootstrap_snapshot(
            participants,
            block_number=preflight_block,
            block_hash="0x" + f"{0x15 + block_offset:02x}" * 32,
            blocks_since_last_step=27 + block_offset,
        ),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=authorization.validator_hotkey,
        now=NOW,
    )
    material, _ = build_direct_bootstrap_call_material(
        _operational(signed, preflight),
        manifest_anchor=anchor_observation,
    )
    weight_call = BootstrapExtrinsicReference(
        extrinsic_id=f"{weight_block}-0002",
        block_number=weight_block,
        extrinsic_index=2,
        block_hash="0x" + f"{0x16 + block_offset:02x}" * 32,
    )
    updated = [
        item.model_copy(update={"last_update": weight_block})
        if item.uid == authorization.validator_uid
        else item
        for item in participants
    ]
    observation = validate_direct_bootstrap_preflight(
        signed,
        _bootstrap_snapshot(
            updated,
            block_number=weight_block,
            block_hash="0x" + f"{0x17 + block_offset:02x}" * 32,
            validator_mechid0_row=material.expected_applied_row,
            active_mechid0_row_hotkeys=[authorization.validator_hotkey],
            blocks_since_last_step=30 + block_offset,
        ),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=authorization.validator_hotkey,
        now=NOW,
    )
    receipt = classify_direct_bootstrap_application(
        material,
        anchor=anchor,
        weight_call=weight_call,
        observation=observation,
        created_at=NOW,
    )
    material_sha256 = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    authorization_sha256 = hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
    journal = DirectBootstrapSubmissionJournal(
        schema=DIRECT_SUBMISSION_JOURNAL_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        submission_id=authorization.submission_id,
        phase="applied",
        manifest_sha256=signed.manifest_sha256,
        transition_authorization_sha256=authorization_sha256,
        validator_hotkey=authorization.validator_hotkey,
        anchor=anchor,
        call_material_sha256=material_sha256,
        weight_call=weight_call,
        receipt_sha256=receipt_sha256,
        updated_at=NOW,
    )
    owner_material, _ = build_owner_fence_call(_owner_fence_preflight(owner, applied=True))
    owner_receipt = OwnerFenceReceipt(
        schema="umi-bootstrap-owner-fence-receipt/1",
        classification="already_applied",
        call_material_sha256=hashlib.sha256(canonical_json_bytes(owner_material)).hexdigest(),
        call_material=owner_material,
        extrinsic=None,
        observation_block=126,
        observation_block_hash="0x" + "13" * 32,
        observed_weights_version_key=1 << 32,
        observed_min_allowed_weights=256,
        observed_commit_reveal_enabled=False,
        source_snapshot_pending_commit_count=3,
        observed_pending_commit_count=3,
        batch_all_finalized_success=False,
        all_storage_targets_verified=True,
        sdk_finalized_reads_verified=True,
        storage_proofs_verified=False,
        created_at=NOW,
    )
    return owner_receipt, signed, authorization, material, receipt, journal, owner, participants


def _write_feed(tmp_path: Path, *, permitted: bool = False):
    owner_fence, signed, authorization, material, receipt, journal, owner, participants = (
        _terminal_records(permitted=permitted)
    )
    root = tmp_path / "publication"
    build_bootstrap_service_publication(
        owner_fence_receipt=owner_fence,
        signed_manifest=signed,
        authorization=authorization,
        call_material=material,
        submission_receipt=receipt,
        submission_journal=journal,
        output_root=root,
    )
    config = tmp_path / "feed.json"
    config.write_bytes(
        canonical_json_bytes(
            {
                "schema": "umi-observer-bootstrap-service-feed-config/1",
                "protocol": "umi-asl/0.1",
                "mode": "bootstrap_service_binary",
                "public_origin": "https://api.umi.vision",
                "bundle_roots": [str(root)],
            }
        )
    )
    feed = build_observer_bootstrap_service_feed(
        config,
        pilot_feed=_fake_pilot_feed(signed),
    )
    return feed, owner, participants


def _active_snapshot(feed, owner, participants, *, block_number: int = 130) -> ObserverSnapshot:
    publication = feed.publications[0]
    validator_uid = publication.receipt.validator_uid
    activity_cutoff_blocks = (
        publication.call_material.operational_preflight.chain.snapshot.activity_cutoff_blocks
    )
    rows = tuple(
        _participant(item.uid, validator=item.validator_permit).model_copy(
            update={
                "hotkey": item.hotkey,
                "last_update_block": (
                    "130" if item.uid == validator_uid else str(item.last_update)
                ),
                "last_update_age_blocks": str(
                    block_number - (130 if item.uid == validator_uid else item.last_update)
                ),
                "serving_announced": item.origin is not None,
                "serving_origin": item.origin,
            }
        )
        for item in participants
    )
    base = _snapshot(block_number=block_number, participants=rows)
    active_rows = tuple(
        item.model_copy(
            update={
                "chain_active": not item.validator_permit or item.uid == validator_uid,
            }
        )
        for item in rows
    )
    expected_row = tuple(tuple(item) for item in publication.receipt.expected_applied_row)
    network = base.network.model_copy(
        update={
            "runtime_spec_version": str(SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION),
            "commit_reveal_enabled": False,
            "pending_weight_commit_count": 0,
            "subnet_owner_hotkey_account_id32": (
                publication.call_material.operational_preflight.chain.subnet_owner_hotkey_account_id32
            ),
            "uid_zero_mechid0_row": expected_row if validator_uid == 0 else (),
            "validator_mechid0_rows": (
                ChainValidatorWeightRow(
                    validator_uid=validator_uid,
                    weights=expected_row,
                ),
            ),
            "counts": base.network.counts.model_copy(
                update={
                    "chain_active": sum(item.chain_active for item in active_rows),
                    "maximum_uids": 256,
                }
            ),
            "hyperparameters": base.network.hyperparameters.model_copy(
                update={
                    "min_allowed_weights": 256,
                    "weights_version_key": str(1 << 32),
                    "activity_cutoff_blocks": str(activity_cutoff_blocks),
                }
            ),
        }
    )
    return base.model_copy(update={"network": network, "participants": active_rows})


def _write_simple_feed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ObserverBootstrapServiceFeed:
    manifest_path = (
        Path(__file__).parents[1]
        / "deploy"
        / "linux-validator-supervisor"
        / "bootstrap-manifest.json"
    )
    signed = SignedBootstrapEligibilityManifest.model_validate_json(manifest_path.read_bytes())
    body = build_simple_bootstrap_lease_body(
        signed,
        umi_git_revision="ab" * 20,
        valid_from_block=9_039_000,
    )
    lease = SignedSimpleBootstrapLease(
        schema=SIMPLE_BOOTSTRAP_LEASE_SCHEMA,
        body=body,
        signature_scheme="sr25519",
        signature="0x" + "11" * 64,
    )
    local_manifest = tmp_path / "bootstrap-manifest.json"
    local_lease = tmp_path / "bootstrap-lease.json"
    local_manifest.write_bytes(canonical_json_bytes(signed))
    local_lease.write_bytes(canonical_json_bytes(lease))
    config = tmp_path / "simple-feed.json"
    config.write_bytes(
        canonical_json_bytes(
            {
                "schema": "umi-observer-simple-bootstrap-feed-config/1",
                "protocol": "umi-asl/0.1",
                "mode": "bootstrap_service_binary",
                "public_origin": "https://api.umi.vision",
                "bundle_roots": [],
                "simple_bootstrap_signed_manifest_path": str(local_manifest),
                "simple_bootstrap_lease_path": str(local_lease),
            }
        )
    )
    monkeypatch.setattr(
        bootstrap_feed_module,
        "verify_simple_bootstrap_lease",
        lambda *args, **kwargs: lease,
    )
    return build_observer_bootstrap_service_feed(
        config,
        pilot_feed=_fake_pilot_feed(signed),
    )


def _simple_active_snapshot(
    feed: ObserverBootstrapServiceFeed,
    *,
    exact_validator_uids: tuple[int, ...] = (200,),
    mismatched_validator_uids: tuple[int, ...] = (),
    subnet_emission_enabled: bool = False,
) -> ObserverSnapshot:
    configuration = feed.simple_bootstrap
    assert configuration is not None
    block_number = 9_040_000
    validator_uids = set(exact_validator_uids) | set(mismatched_validator_uids)
    entries = {entry.uid: entry for entry in configuration.signed_manifest.manifest.entries}
    owner_hotkey = dev_wallet("//SimpleObserverOwner").hotkey.ss58_address
    participants = []
    for uid in range(256):
        participant = _participant(uid, validator=uid in validator_uids)
        updates: dict[str, object] = {
            "last_update_block": str(block_number - 10 if uid in validator_uids else 90),
            "last_update_age_blocks": str(10 if uid in validator_uids else block_number - 90),
        }
        if uid == 0:
            updates["hotkey"] = owner_hotkey
        if uid in entries:
            entry = entries[uid]
            updates.update(
                {
                    "hotkey": entry.miner_hotkey,
                    "serving_announced": True,
                    "serving_origin": entry.origin,
                }
            )
        participants.append(participant.model_copy(update=updates))
    base = _snapshot(block_number=block_number, participants=participants)
    expected_row = configuration.expected_row
    rows = [
        ChainValidatorWeightRow(validator_uid=uid, weights=expected_row)
        for uid in exact_validator_uids
    ]
    rows.extend(
        ChainValidatorWeightRow(validator_uid=uid, weights=((0, 1),))
        for uid in mismatched_validator_uids
    )
    network = base.network.model_copy(
        update={
            "runtime_spec_version": "455",
            "commit_reveal_enabled": False,
            "commit_reveal_version": "4",
            "reveal_period_epochs": "1",
            "pending_weight_commit_count": 0,
            "subnet_emission_enabled": subnet_emission_enabled,
            "subnet_owner_hotkey_account_id32": "0x" + account_id32(owner_hotkey).hex(),
            "uid_zero_mechid0_row": (expected_row if 0 in exact_validator_uids else ()),
            "validator_mechid0_rows": tuple(sorted(rows, key=lambda item: item.validator_uid)),
            "hyperparameters": base.network.hyperparameters.model_copy(
                update={
                    "min_allowed_weights": 256,
                    "weights_version_key": str(1 << 32),
                    "activity_cutoff_blocks": "360",
                }
            ),
        }
    )
    return base.model_copy(update={"network": network})


def test_applied_direct_bundle_is_replayed_and_served_immutably(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    publication = feed.publications[0]
    snapshot = _active_snapshot(feed, owner, participants)
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(publication.signed_manifest),
        bootstrap_service_feed=feed,
    )
    with TestClient(app) as client:
        status = client.get("/api/v1/status")
        service = client.get("/api/v1/bootstrap-service")
        leaderboard = client.get("/api/v1/leaderboard")
        manifest = client.get(
            f"/api/v1/bootstrap-service/{publication.publication_id}/bundle/manifest.json"
        )
        first_object = next(iter(publication.objects.values()))
        evidence_object = client.get(
            f"/api/v1/bootstrap-service/{publication.publication_id}"
            f"/bundle/objects/{first_object.sha256}"
        )

    assert status.status_code == 200
    assert status.json()["protocol_state"]["service_weights_active"] is True
    assert status.json()["protocol_state"]["translation_weights_active"] is False
    assert "umi_weight_cutover_unverified" not in status.json()["outstanding_gap_codes"]
    body = service.json()
    assert body["availability"] == "active"
    assert body["current"]["evidence"]["publication_id"] == publication.publication_id
    assert body["current"]["validator_uid"] == 0
    assert len(body["current"]["eligible_miners"]) == 2
    assert body["current"]["section_14_gate_credit"] is False
    assert [
        source["verification_status"]
        for source in body["sources"]
        if source["source_kind"] == "bootstrap_service_bundle"
    ] == ["bootstrap_current_state_verified"]
    assert leaderboard.json()["umi_translation"]["availability"] == "not_started"
    assert manifest.content == publication.manifest_bytes
    assert manifest.headers["x-umi-bootstrap-bundle"] == publication.publication_id
    assert manifest.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert evidence_object.content == first_object.data
    assert evidence_object.headers["etag"] == f'"{first_object.sha256}"'


def test_permitted_nonowner_bundle_is_verified_against_its_own_chain_row(
    tmp_path: Path,
) -> None:
    feed, owner, participants = _write_feed(tmp_path, permitted=True)
    publication = feed.publications[0]
    snapshot = _active_snapshot(feed, owner, participants)
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(publication.signed_manifest),
        bootstrap_service_feed=feed,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")

    authorization_hotkey = publication.authorization.validator_hotkey
    assert response.status_code == 200
    assert response.json()["availability"] == "active"
    assert response.json()["current"]["validator_uid"] == 200
    assert response.json()["current"]["validator_hotkey"] == authorization_hotkey
    assert authorization_hotkey == publication.receipt.validator_hotkey


def test_common_lease_uses_finalized_exact_row_as_the_public_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = _write_simple_feed(tmp_path, monkeypatch)
    configuration = feed.simple_bootstrap
    assert configuration is not None
    snapshot = _simple_active_snapshot(feed, subnet_emission_enabled=False)
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(configuration.signed_manifest),
        bootstrap_service_feed=feed,
    )

    with TestClient(app) as client:
        service = client.get("/api/v1/bootstrap-service")
        status = client.get("/api/v1/status")
        manifest = client.get(
            f"/api/v1/bootstrap-service/{configuration.publication_id}/bundle/manifest.json"
        )
        lease_ref = configuration.manifest.signed_lease
        lease = client.get(
            f"/api/v1/bootstrap-service/{configuration.publication_id}"
            f"/bundle/objects/{lease_ref.sha256}"
        )

    body = service.json()
    assert body["availability"] == "active"
    assert body["warning_codes"] == []
    assert body["current"]["evidence_class"] == "finalized_chain_state"
    assert body["current"]["subnet_emission_enabled"] is False
    assert body["current"]["translation_weights_active"] is False
    assert [item["uid"] for item in body["current"]["exact_validator_rows"]] == [200]
    assert [item["uid"] for item in body["current"]["eligible_miners"]] == [6, 247]
    assert body["current"]["observation_block"] == "9040000"
    assert status.json()["protocol_state"]["service_weights_active"] is True
    assert status.json()["protocol_state"]["translation_weights_active"] is False
    assert snapshot.network.subnet_emission_enabled is False
    assert manifest.content == configuration.manifest_bytes
    assert lease.content == configuration.objects[lease_ref.sha256].data


def test_common_lease_accepts_multiple_exact_rows_and_warns_on_foreign_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = _write_simple_feed(tmp_path, monkeypatch)
    configuration = feed.simple_bootstrap
    assert configuration is not None
    snapshot = _simple_active_snapshot(
        feed,
        exact_validator_uids=(110, 200),
        mismatched_validator_uids=(198,),
        subnet_emission_enabled=True,
    )
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(configuration.signed_manifest),
        bootstrap_service_feed=feed,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")

    body = response.json()
    assert body["availability"] == "active"
    assert [item["uid"] for item in body["current"]["exact_validator_rows"]] == [110, 200]
    assert body["current"]["subnet_emission_enabled"] is True
    assert body["warning_codes"] == ["bootstrap_service_mismatched_active_row_uid_198"]


def test_common_lease_remains_inactive_without_an_exact_active_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = _write_simple_feed(tmp_path, monkeypatch)
    configuration = feed.simple_bootstrap
    assert configuration is not None
    snapshot = _simple_active_snapshot(
        feed,
        exact_validator_uids=(),
        mismatched_validator_uids=(198,),
    )
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(configuration.signed_manifest),
        bootstrap_service_feed=feed,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")

    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == "bootstrap_service_exact_active_row_unavailable"
    assert response.json()["current"] is None


def test_common_lease_fails_closed_when_the_weight_rate_limit_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = _write_simple_feed(tmp_path, monkeypatch)
    active = _simple_active_snapshot(feed)
    snapshot = active.model_copy(
        update={
            "network": active.network.model_copy(
                update={
                    "hyperparameters": active.network.hyperparameters.model_copy(
                        update={"weights_rate_limit_blocks": "241"}
                    )
                }
            )
        }
    )
    configuration = feed.simple_bootstrap
    assert configuration is not None
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(configuration.signed_manifest),
        bootstrap_service_feed=feed,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")

    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == "bootstrap_service_weights_rate_limit_changed"


def test_common_lease_fails_closed_on_runtime_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = _write_simple_feed(tmp_path, monkeypatch)
    active = _simple_active_snapshot(feed)
    snapshot = active.model_copy(
        update={
            "network": active.network.model_copy(
                update={"runtime_spec_version": str(SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION + 1)}
            )
        }
    )
    configuration = feed.simple_bootstrap
    assert configuration is not None
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(configuration.signed_manifest),
        bootstrap_service_feed=feed,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")
        status = client.get("/api/v1/status")

    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == "bootstrap_service_runtime_spec_mismatch"
    assert status.json()["protocol_state"]["service_weights_active"] is False


def test_bootstrap_service_requires_the_verified_pilot_feed(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    snapshot = _active_snapshot(feed, owner, participants)
    with pytest.raises(ValueError, match="requires the verified pilot feed"):
        create_observer_app(
            _cache(SequenceCollector([snapshot])),
            bootstrap_service_feed=feed,
        )


def test_bootstrap_service_response_sorts_account_order_by_uid(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    publication = feed.publications[0]
    reversed_manifest = publication.signed_manifest.manifest.model_copy(
        update={"entries": list(reversed(publication.signed_manifest.manifest.entries))}
    )
    reversed_signed = publication.signed_manifest.model_copy(update={"manifest": reversed_manifest})
    reversed_publication = replace(publication, signed_manifest=reversed_signed)
    rendering_feed = ObserverBootstrapServiceFeed(publications=(reversed_publication,))
    snapshot = _active_snapshot(feed, owner, participants)
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(publication.signed_manifest),
        bootstrap_service_feed=rendering_feed,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")
    assert [item["uid"] for item in response.json()["current"]["eligible_miners"]] == [1, 2]


@pytest.mark.parametrize(
    ("change", "reason"),
    (
        ({"runtime_spec_version": "456"}, "bootstrap_service_runtime_spec_mismatch"),
        ({"pending_weight_commit_count": 1}, "bootstrap_service_pending_commit_queue_not_empty"),
        ({"validator_mechid0_rows": ()}, "bootstrap_service_applied_row_mismatch"),
    ),
)
def test_bootstrap_service_state_fails_closed_on_chain_drift(
    tmp_path: Path,
    change: dict[str, object],
    reason: str,
) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    active = _active_snapshot(feed, owner, participants)
    snapshot = active.model_copy(update={"network": active.network.model_copy(update=change)})
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(feed.publications[0].signed_manifest),
        bootstrap_service_feed=feed,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")
        status = client.get("/api/v1/status")
    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == reason
    assert response.json()["current"] is None
    assert response.json()["verified_publications"]
    assert not any(
        source["source_kind"] == "bootstrap_service_bundle" for source in response.json()["sources"]
    )
    assert status.json()["protocol_state"]["service_weights_active"] is False


def test_bootstrap_service_warns_about_other_active_validator(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    active = _active_snapshot(feed, owner, participants)
    competing = active.participants[3].model_copy(
        update={
            "chain_active": True,
            "validator_permit": True,
            "role": "validator",
            "last_update_block": "129",
            "last_update_age_blocks": "1",
        }
    )
    snapshot = active.model_copy(
        update={
            "participants": (*active.participants[:3], competing, *active.participants[4:]),
            "network": active.network.model_copy(
                update={
                    "counts": active.network.counts.model_copy(
                        update={
                            "miners": active.network.counts.miners - 1,
                            "validators": active.network.counts.validators + 1,
                        }
                    )
                }
            ),
        }
    )
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(feed.publications[0].signed_manifest),
        bootstrap_service_feed=feed,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")
    assert response.json()["availability"] == "active"
    assert response.json()["reason_code"] is None
    assert response.json()["warning_codes"] == ["bootstrap_service_other_active_validator_uid_3"]


def test_bootstrap_service_rejects_eligible_uid_reassignment(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    active = _active_snapshot(feed, owner, participants)
    replacement = active.participants[1].model_copy(
        update={"hotkey": active.participants[2].hotkey}
    )
    snapshot = active.model_copy(
        update={"participants": (active.participants[0], replacement, *active.participants[2:])}
    )
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(feed.publications[0].signed_manifest),
        bootstrap_service_feed=feed,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")
    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == "bootstrap_service_eligible_miner_mapping_changed"


def test_bootstrap_service_rejects_subnet_owner_rotation(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    active = _active_snapshot(feed, owner, participants)
    snapshot = active.model_copy(
        update={
            "network": active.network.model_copy(
                update={"subnet_owner_hotkey_account_id32": "0x" + "99" * 32}
            )
        }
    )
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(feed.publications[0].signed_manifest),
        bootstrap_service_feed=feed,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")

    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == "bootstrap_service_subnet_owner_mapping_changed"


def test_bootstrap_service_rejects_eligible_miner_origin_change(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    active = _active_snapshot(feed, owner, participants)
    changed = active.participants[1].model_copy(update={"serving_origin": "https://9.9.9.9:443"})
    snapshot = active.model_copy(
        update={"participants": (active.participants[0], changed, *active.participants[2:])}
    )
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(feed.publications[0].signed_manifest),
        bootstrap_service_feed=feed,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")

    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == "bootstrap_service_eligible_miner_origin_changed"


def test_builder_refuses_to_replace_an_existing_publication(tmp_path: Path) -> None:
    records = _terminal_records()
    root = tmp_path / "publication"
    build_bootstrap_service_publication(
        owner_fence_receipt=records[0],
        signed_manifest=records[1],
        authorization=records[2],
        call_material=records[3],
        submission_receipt=records[4],
        submission_journal=records[5],
        output_root=root,
    )
    with pytest.raises(FileExistsError, match="already exists"):
        build_bootstrap_service_publication(
            owner_fence_receipt=records[0],
            signed_manifest=records[1],
            authorization=records[2],
            call_material=records[3],
            submission_receipt=records[4],
            submission_journal=records[5],
            output_root=root,
        )


def test_builder_rejects_inconsistent_terminal_records_before_writing(tmp_path: Path) -> None:
    records = _terminal_records()
    bad_journal = records[5].model_copy(update={"receipt_sha256": "00" * 32})
    root = tmp_path / "publication"
    with pytest.raises(ValueError, match="not consistently cross-bound"):
        build_bootstrap_service_publication(
            owner_fence_receipt=records[0],
            signed_manifest=records[1],
            authorization=records[2],
            call_material=records[3],
            submission_receipt=records[4],
            submission_journal=bad_journal,
            output_root=root,
        )
    assert not root.exists()


def test_feed_rejects_terminal_object_tampering(tmp_path: Path) -> None:
    feed, _owner, _participants = _write_feed(tmp_path)
    publication = feed.publications[0]
    root = tmp_path / "publication"
    target = root / "objects" / publication.manifest.submission_journal.sha256
    target.write_bytes(target.read_bytes() + b" ")
    config = tmp_path / "feed.json"
    with pytest.raises(ValueError, match=r"wrong byte length|SHA-256"):
        build_observer_bootstrap_service_feed(
            config,
            pilot_feed=_fake_pilot_feed(publication.signed_manifest),
        )


def test_feed_rejects_aggregate_limit_before_loading_another_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed, _owner, _participants = _write_feed(tmp_path)
    publication = feed.publications[0]
    first = tmp_path / "publication"
    second = tmp_path / "publication-copy"
    shutil.copytree(first, second)
    publication_bytes = len(publication.manifest_bytes) + sum(
        item.size_bytes for item in publication.objects.values()
    )
    monkeypatch.setattr(
        bootstrap_feed_module,
        "MAX_BOOTSTRAP_FEED_BYTES",
        publication_bytes,
    )
    config = tmp_path / "two-roots.json"
    config.write_bytes(
        canonical_json_bytes(
            {
                "schema": "umi-observer-bootstrap-service-feed-config/1",
                "protocol": "umi-asl/0.1",
                "mode": "bootstrap_service_binary",
                "public_origin": "https://api.umi.vision",
                "bundle_roots": [str(first), str(second)],
            }
        )
    )
    with pytest.raises(ValueError, match="aggregate byte ceiling"):
        build_observer_bootstrap_service_feed(
            config,
            pilot_feed=_fake_pilot_feed(publication.signed_manifest),
        )


@pytest.mark.parametrize(
    ("authorization_variant", "reason"),
    (
        (False, "reuses a direct transition authorization"),
        (True, "reuses a direct transition submission ID"),
    ),
)
def test_feed_rejects_reused_single_use_authority_across_distinct_weight_calls(
    tmp_path: Path,
    authorization_variant: bool,
    reason: str,
) -> None:
    first = _terminal_records()
    second = _terminal_records(
        block_offset=4,
        authorization_variant=authorization_variant,
        base_case=(first[1], first[2], first[6], first[7]),
    )
    roots = (tmp_path / "first", tmp_path / "second")
    for root, records in zip(roots, (first, second), strict=True):
        build_bootstrap_service_publication(
            owner_fence_receipt=records[0],
            signed_manifest=records[1],
            authorization=records[2],
            call_material=records[3],
            submission_receipt=records[4],
            submission_journal=records[5],
            output_root=root,
        )
    config = tmp_path / "reused-authority-feed.json"
    config.write_bytes(
        canonical_json_bytes(
            {
                "schema": "umi-observer-bootstrap-service-feed-config/1",
                "protocol": "umi-asl/0.1",
                "mode": "bootstrap_service_binary",
                "public_origin": "https://api.umi.vision",
                "bundle_roots": [str(root) for root in roots],
            }
        )
    )

    with pytest.raises(ValueError, match=reason):
        build_observer_bootstrap_service_feed(
            config,
            pilot_feed=_fake_pilot_feed(first[1]),
        )
