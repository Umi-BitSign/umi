from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from umi import observer_bootstrap_service_feed as bootstrap_feed_module
from umi.bootstrap_direct_weights import (
    DIRECT_TRANSITION_PROFILE,
    DirectBootstrapSubmissionJournal,
    OwnerFenceReceipt,
    build_direct_bootstrap_call_material,
    build_owner_fence_call,
    classify_direct_bootstrap_application,
    validate_direct_bootstrap_preflight,
)
from umi.bootstrap_weight_operator import (
    BootstrapExtrinsicReference,
    BootstrapManifestAnchorObservation,
)
from umi.observer import create_observer_app
from umi.observer_bootstrap_service_feed import (
    ObserverBootstrapServiceFeed,
    build_bootstrap_service_publication,
    build_observer_bootstrap_service_feed,
)
from umi.observer_models import ObserverSnapshot
from umi.observer_pilot_feed import ObserverPilotFeed, VerifiedComponentPilot
from umi.protocol import canonical_json_bytes

from .test_bootstrap_direct_weights import NOW, _operational, _owner_fence_preflight, _preflight
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


def _terminal_records():
    signed, authorization, owner, participants, _ = _preflight()
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
        _bootstrap_snapshot(
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
    weight_call = BootstrapExtrinsicReference(
        extrinsic_id="130-0002",
        block_number=130,
        extrinsic_index=2,
        block_hash="0x" + "16" * 32,
    )
    updated = [
        item.model_copy(update={"last_update": 130}) if item.uid == 0 else item
        for item in participants
    ]
    observation = validate_direct_bootstrap_preflight(
        signed,
        _bootstrap_snapshot(
            updated,
            block_number=130,
            block_hash="0x" + "13" * 32,
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
        weight_call=weight_call,
        observation=observation,
        created_at=NOW,
    )
    material_sha256 = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    authorization_sha256 = hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
    journal = DirectBootstrapSubmissionJournal(
        schema="umi-bootstrap-direct-submission-journal/1",
        transition_profile=DIRECT_TRANSITION_PROFILE,
        submission_id=authorization.submission_id,
        phase="applied",
        manifest_sha256=signed.manifest_sha256,
        transition_authorization_sha256=authorization_sha256,
        validator_hotkey=owner.hotkey.ss58_address,
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
        pre_submit_pending_commit_count=3,
        observed_pending_commit_count=3,
        batch_all_finalized_success=False,
        all_storage_targets_verified=True,
        sdk_finalized_reads_verified=True,
        storage_proofs_verified=False,
        created_at=NOW,
    )
    return owner_receipt, signed, authorization, material, receipt, journal, owner, participants


def _write_feed(tmp_path: Path):
    owner_fence, signed, authorization, material, receipt, journal, owner, participants = (
        _terminal_records()
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
    rows = tuple(
        _participant(item.uid, validator=item.validator_permit).model_copy(
            update={
                "hotkey": item.hotkey,
                "last_update_block": "130" if item.uid == 0 else str(item.last_update),
                "last_update_age_blocks": str(
                    block_number - (130 if item.uid == 0 else item.last_update)
                ),
            }
        )
        for item in participants
    )
    base = _snapshot(block_number=block_number, participants=rows)
    publication = feed.publications[0]
    network = base.network.model_copy(
        update={
            "runtime_spec_version": "455",
            "commit_reveal_enabled": False,
            "pending_weight_commit_count": 0,
            "uid_zero_mechid0_row": tuple(
                tuple(item) for item in publication.receipt.expected_applied_row
            ),
            "counts": base.network.counts.model_copy(update={"maximum_uids": 256}),
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
        ({"uid_zero_mechid0_row": ()}, "bootstrap_service_applied_row_mismatch"),
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


def test_bootstrap_service_rejects_active_non_owner_validator(tmp_path: Path) -> None:
    feed, owner, participants = _write_feed(tmp_path)
    active = _active_snapshot(feed, owner, participants)
    competing = active.participants[1].model_copy(
        update={
            "chain_active": False,
            "validator_permit": True,
            "role": "validator",
            "last_update_block": "129",
            "last_update_age_blocks": "1",
        }
    )
    snapshot = active.model_copy(
        update={"participants": (active.participants[0], competing, *active.participants[2:])}
    )
    app = create_observer_app(
        _cache(SequenceCollector([snapshot])),
        pilot_feed=_fake_pilot_feed(feed.publications[0].signed_manifest),
        bootstrap_service_feed=feed,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/bootstrap-service")
    assert response.json()["availability"] == "inactive"
    assert response.json()["reason_code"] == "bootstrap_service_non_owner_validator_active"


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
