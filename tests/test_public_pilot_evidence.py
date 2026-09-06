from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import bittensor as bt
import pytest
from fastapi.testclient import TestClient

from umi.audit import EvidenceStore
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.observer import create_observer_app
from umi.observer_pilot_feed import build_observer_pilot_feed
from umi.protocol import (
    GroundTruthPayload,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)
from umi.public_pilot_campaign import CAMPAIGN_ID, build_public_pilot_inputs
from umi.public_pilot_evidence import (
    PUBLIC_ENDPOINT_PILOT_SCHEMA,
    _validated_https_origin,
    attach_public_endpoint_pilot,
)

from .factories import dev_wallet, three_requests
from .test_component_run import build_completed_bundle, install_replay_decryptor
from .test_observer import SequenceCollector, _cache, _snapshot

MINER_ORIGIN = "https://8.8.8.8:443"
FINALIZED_BLOCK_HASH = "0x" + "92" * 32
PILOT_VIDEO_BYTES = (
    Path(__file__).resolve().parents[1] / "docs" / "pilot-media" / "asl-book.mp4"
).read_bytes()


def _campaign_inputs() -> tuple[tuple[TranslationRequest, ...], GroundTruthPayload]:
    request, truth = build_public_pilot_inputs(
        current_round=bt.timelock.current_round(),
        setup_allowance_seconds=300,
        response_window_seconds=300,
        reveal_margin_seconds=30,
        entropy=lambda size: bytes([size]) * size,
    )
    return (request,), truth


def _set_miner_origin(bundle_root: Path) -> None:
    store = EvidenceStore(bundle_root)
    manifest = store.load_manifest()
    manifest["miner_origin"] = MINER_ORIGIN
    store.write_manifest(manifest)


def _attach(
    bundle_root: Path,
    *,
    block_number: int = 12_345,
    campaign_id: str = CAMPAIGN_ID,
) -> Path:
    return attach_public_endpoint_pilot(
        bundle_root,
        wallet=dev_wallet("//Alice"),
        campaign_id=campaign_id,
        network="finney",
        genesis_block_hash="0x" + FINNEY_GENESIS_HASH,
        finalized_block_number=block_number,
        finalized_block_hash=FINALIZED_BLOCK_HASH,
        finalized_block_timestamp_ms=1_725_555_555_000,
        expected_miner_uid=236,
        announced_origin=MINER_ORIGIN,
        contacted_origin=MINER_ORIGIN,
    )


def _write_feed_config(path: Path, *bundle_roots: Path) -> Path:
    path.write_bytes(
        canonical_json_bytes(
            {
                "schema": "umi-observer-pilot-feed-config/1",
                "protocol": "umi-asl/0.1",
                "mode": "component_test_no_weight",
                "translation_weights_active": False,
                "protocol_conformance": False,
                "activation_evidence": False,
                "public_origin": "https://api.umi.vision",
                "bundle_roots": [str(root) for root in bundle_roots],
            }
        )
    )
    return path


@pytest.mark.parametrize(
    "origin",
    (
        "https://miner.example:443",
        "https://127.0.0.1:443",
        "https://8.8.8.8",
        "https://8.8.8.8:443/",
    ),
)
def test_public_endpoint_evidence_requires_a_normalized_public_ip_origin(
    origin: str,
) -> None:
    with pytest.raises(ValueError, match="public endpoint origin"):
        _validated_https_origin(origin)


@pytest.mark.asyncio
async def test_signed_public_endpoint_evidence_is_derived_and_projected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_requests, campaign_truth = _campaign_inputs()
    bundle_root, requests = await build_completed_bundle(
        tmp_path,
        monkeypatch,
        requests=campaign_requests,
        truth_override=campaign_truth,
        video_bytes=PILOT_VIDEO_BYTES,
    )
    _set_miner_origin(bundle_root)
    install_replay_decryptor(bundle_root, monkeypatch)
    manifest_path = _attach(bundle_root)

    manifest = json.loads(manifest_path.read_bytes())
    store = EvidenceStore(bundle_root)
    attachment = manifest["public_endpoint_pilot"]
    attestation = json.loads(store.read(attachment["attestation"]))
    signature = json.loads(store.read(attachment["signature"]))
    assert attestation["schema"] == PUBLIC_ENDPOINT_PILOT_SCHEMA
    assert attestation["campaign_id"] == CAMPAIGN_ID
    assert attestation["chain_observation"]["network"] == "finney"
    assert attestation["chain_observation"]["genesis_block_hash"] == ("0x" + FINNEY_GENESIS_HASH)
    assert attestation["request_digest"] == request_digest(requests[0])
    assert attestation["expected_miner_uid"] == 236
    assert attestation["announced_origin"] == MINER_ORIGIN
    assert attestation["contacted_origin"] == MINER_ORIGIN
    assert attestation["attempt_count"] == 1
    assert attestation["outcome_classification"] == "ok"
    assert attestation["miner_signed_envelope_verified"] is True
    assert attestation["miner_signed_plaintext_verified"] is True
    assert attestation["translation_weights_active"] is False
    assert attestation["protocol_conformance"] is False
    assert attestation["activation_evidence"] is False
    assert attestation["validator_input_eligible"] is False
    assert signature["attestation_sha256"] == attachment["attestation"]["sha256"]

    feed = build_observer_pilot_feed(_write_feed_config(tmp_path / "pilot-feed.json", bundle_root))
    pilot = feed.pilots[0]
    assert pilot.public_endpoint is not None
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])), pilot_feed=feed)
    with TestClient(app) as client:
        response = client.get(f"/api/v1/pilots/{pilot.pilot_id}")
        windows = client.get("/api/v1/windows")
        leaderboard = client.get("/api/v1/leaderboard")

    assert response.status_code == 200
    assert response.json()["schema"] == "umi-observer-pilot/2"
    record = response.json()["pilot"]
    assert record["pilot_profile"] == "public_endpoint"
    assert record["evidence"]["replay_command"] == ("umi-public-pilot replay --bundle ./bundle")
    evidence = record["public_endpoint_evidence"]
    assert evidence["campaign_id"] == CAMPAIGN_ID
    assert evidence["coordinator_signature_verified"] is True
    assert evidence["chain"]["network"] == "finney"
    assert evidence["chain"]["genesis_block_hash"] == (
        "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
    )
    assert evidence["chain"]["expected_miner_uid"] == 236
    assert evidence["chain"]["block_number"] == "12345"
    assert evidence["chain"]["storage_proofs_verified"] is False
    assert evidence["transport"]["coordinator_attested_origin_match"] is True
    assert evidence["transport"]["attempt_count"] == 1
    assert evidence["transport"]["outcome_classification"] == "ok"
    assert evidence["attestation"]["sha256"] == attachment["attestation"]["sha256"]
    assert evidence["signature"]["sha256"] == attachment["signature"]["sha256"]
    assert windows.json()["availability"] == "not_started"
    assert leaderboard.json()["umi_translation"]["entries"] == []


@pytest.mark.asyncio
async def test_public_endpoint_evidence_rejects_tampering_and_multiple_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unrelated_root = tmp_path / "unrelated"
    unrelated_root.mkdir()
    unrelated_bundle, _ = await build_completed_bundle(
        unrelated_root,
        monkeypatch,
        requests=(three_requests()[0],),
    )
    _set_miner_origin(unrelated_bundle)
    install_replay_decryptor(unrelated_bundle, monkeypatch)
    with pytest.raises(ValueError, match="public-pilot request"):
        _attach(unrelated_bundle)

    campaign_requests, campaign_truth = _campaign_inputs()
    bundle_root, _requests = await build_completed_bundle(
        tmp_path,
        monkeypatch,
        requests=campaign_requests,
        truth_override=campaign_truth,
        video_bytes=PILOT_VIDEO_BYTES,
    )
    _set_miner_origin(bundle_root)
    install_replay_decryptor(bundle_root, monkeypatch)
    with pytest.raises(ValueError, match="postdate the signed attestation"):
        attach_public_endpoint_pilot(
            bundle_root,
            wallet=dev_wallet("//Alice"),
            campaign_id=CAMPAIGN_ID,
            network="finney",
            genesis_block_hash="0x" + FINNEY_GENESIS_HASH,
            finalized_block_number=12_345,
            finalized_block_hash=FINALIZED_BLOCK_HASH,
            finalized_block_timestamp_ms=time.time_ns() // 1_000_000 + 60_000,
            expected_miner_uid=236,
            announced_origin=MINER_ORIGIN,
            contacted_origin=MINER_ORIGIN,
        )
    with pytest.raises(ValueError, match="campaign_id"):
        _attach(bundle_root, campaign_id="91" * 32)
    _attach(bundle_root)

    store = EvidenceStore(bundle_root)
    manifest = store.load_manifest()
    attestation = json.loads(store.read(manifest["public_endpoint_pilot"]["attestation"]))
    attestation["expected_miner_uid"] = 237
    manifest["public_endpoint_pilot"]["attestation"] = store.add_json(attestation).as_dict()
    store.write_manifest(manifest)
    with pytest.raises(ValueError, match="attestation signature is invalid"):
        build_observer_pilot_feed(_write_feed_config(tmp_path / "feed.json", bundle_root))

    multi_root = tmp_path / "multiple"
    multi_root.mkdir()
    multi_bundle, _requests = await build_completed_bundle(multi_root, monkeypatch)
    _set_miner_origin(multi_bundle)
    install_replay_decryptor(multi_bundle, monkeypatch)
    with pytest.raises(ValueError, match="exactly one component outcome"):
        _attach(multi_bundle)


@pytest.mark.asyncio
async def test_feed_rejects_second_public_pilot_for_same_miner_and_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_requests, campaign_truth = _campaign_inputs()
    bundle_root, _requests = await build_completed_bundle(
        tmp_path,
        monkeypatch,
        requests=campaign_requests,
        truth_override=campaign_truth,
        video_bytes=PILOT_VIDEO_BYTES,
    )
    _set_miner_origin(bundle_root)
    install_replay_decryptor(bundle_root, monkeypatch)
    second_root = tmp_path / "second-bundle"
    shutil.copytree(bundle_root, second_root)
    _attach(bundle_root, block_number=12_345)
    _attach(second_root, block_number=12_346)

    with pytest.raises(ValueError, match="more than one public endpoint pilot"):
        build_observer_pilot_feed(
            _write_feed_config(tmp_path / "feed.json", bundle_root, second_root)
        )
