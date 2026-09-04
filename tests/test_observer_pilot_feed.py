from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import bittensor as bt
import pytest
from fastapi.testclient import TestClient

import umi.component_pilot as pilot_module
import umi.observer_pilot_feed as pilot_feed_module
import umi.validator as validator_module
from umi.audit import EvidenceStore
from umi.component import NOT_REACHED
from umi.component_pilot import run_local_component_pilot
from umi.encoding import account_id32
from umi.observer import create_observer_app
from umi.observer_pilot_feed import build_observer_pilot_feed
from umi.protocol import canonical_json_bytes

from .factories import dev_wallet
from .test_component_run import (
    FixtureFetcher,
    FixtureTranslator,
    build_completed_bundle,
    install_replay_decryptor,
    write_case_inputs,
)
from .test_observer import SequenceCollector, _cache, _snapshot


def _write_feed_config(path: Path, bundle_root: Path) -> Path:
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
                "bundle_roots": [str(bundle_root)],
            }
        )
    )
    return path


@pytest.mark.asyncio
async def test_component_pilot_is_replayed_and_stays_out_of_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_root, _requests = await build_completed_bundle(tmp_path, monkeypatch)
    install_replay_decryptor(bundle_root, monkeypatch)
    feed = build_observer_pilot_feed(_write_feed_config(tmp_path / "feed.json", bundle_root))
    pilot = feed.pilots[0]
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        pilot_feed=feed,
    )

    with TestClient(app) as client:
        listing = client.get("/api/v1/pilots")
        solutions = client.get(f"/api/v1/pilots/{pilot.pilot_id}/solutions")
        windows = client.get("/api/v1/windows")
        false_window = client.get(f"/api/v1/windows/{pilot.pilot_id}")
        manifest = client.get(f"/api/v1/pilots/{pilot.pilot_id}/bundle/manifest.json")
        first_object = next(iter(pilot.objects.values()))
        evidence_object = client.get(
            f"/api/v1/pilots/{pilot.pilot_id}/bundle/objects/{first_object.sha256}"
        )

    assert listing.status_code == 200
    listed = listing.json()
    assert listed["protocol_state"]["phase"] == "pre_public_calibration"
    assert listed["protocol_state"]["conformance_evidence_available"] is False
    assert listed["protocol_state"]["activation_evidence_available"] is False
    record = listed["pilots"][0]
    assert record["pilot_id"] == pilot.pilot_id
    assert record["evidence_class"] == "component_test_no_weight"
    assert record["translation_weights_active"] is False
    assert record["protocol_conformance"] is False
    assert record["activation_evidence"] is False
    assert record["deterministic_replay_verified"] is True
    assert record["missing_canonical_stages"] == list(NOT_REACHED)

    assert solutions.status_code == 200
    solution_body = solutions.json()
    assert solution_body["pilot"]["bundle_manifest_sha256"] == pilot.pilot_id
    assert len(solution_body["solutions"]) == 3
    assert all(item["response_plaintext_valid"] for item in solution_body["solutions"])
    assert {item["hypothesis"] for item in solution_body["solutions"]} == {
        "hello",
        "hello world",
    }
    assert all(len(item["references"]) >= 3 for item in solution_body["solutions"])
    assert all(
        item["score"] == {"numerator": "1", "denominator": "1"}
        for item in solution_body["solutions"]
    )

    assert windows.json()["availability"] == "not_started"
    assert false_window.status_code == 404
    assert manifest.content == pilot.manifest_bytes
    assert manifest.headers["x-umi-pilot-bundle"] == pilot.pilot_id
    assert manifest.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert evidence_object.content == first_object.data
    assert evidence_object.headers["etag"] == f'"{first_object.sha256}"'
    assert evidence_object.headers["x-umi-pilot-bundle"] == pilot.pilot_id


@pytest.mark.asyncio
async def test_pilot_feed_rejects_missing_stage_and_unsafe_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_root, _requests = await build_completed_bundle(tmp_path, monkeypatch)
    install_replay_decryptor(bundle_root, monkeypatch)
    store = EvidenceStore(bundle_root)
    manifest = store.load_manifest()
    manifest["not_reached"] = manifest["not_reached"][:-1]
    store.write_manifest(manifest)
    config = _write_feed_config(tmp_path / "feed.json", bundle_root)

    with pytest.raises(ValueError, match="missing canonical stage"):
        build_observer_pilot_feed(config)

    config.write_text(json.dumps(json.loads(config.read_bytes()), indent=2))
    with pytest.raises(ValueError, match="canonical JSON"):
        build_observer_pilot_feed(config)


@pytest.mark.asyncio
async def test_pilot_feed_rejects_unverifiable_response_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_root, _requests = await build_completed_bundle(tmp_path, monkeypatch)
    install_replay_decryptor(bundle_root, monkeypatch)
    store = EvidenceStore(bundle_root)
    manifest = store.load_manifest()
    manifest["outcomes"][0]["received_bytes_sha256"] = "0" * 64
    store.write_manifest(manifest)

    with pytest.raises(ValueError, match="digest does not match retained bytes"):
        build_observer_pilot_feed(_write_feed_config(tmp_path / "feed.json", bundle_root))


@pytest.mark.asyncio
async def test_pilot_feed_requires_distinct_signed_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_root, _requests = await build_completed_bundle(tmp_path, monkeypatch)
    install_replay_decryptor(bundle_root, monkeypatch)
    original_replay = pilot_feed_module.replay_bundle_detailed

    def same_identity(root: Path):
        replay = original_replay(root)
        return replace(replay, validator_hotkey=replay.miner_hotkey)

    monkeypatch.setattr(pilot_feed_module, "replay_bundle_detailed", same_identity)
    with pytest.raises(ValueError, match="hotkeys must be distinct"):
        build_observer_pilot_feed(_write_feed_config(tmp_path / "feed.json", bundle_root))


@pytest.mark.asyncio
async def test_pilot_feed_compares_identity_account_bytes_not_ss58_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_root, _requests = await build_completed_bundle(tmp_path, monkeypatch)
    install_replay_decryptor(bundle_root, monkeypatch)
    original_replay = pilot_feed_module.replay_bundle_detailed

    def same_key_with_another_prefix(root: Path):
        replay = original_replay(root)
        alternate = bt.sp_core.encode_ss58(account_id32(replay.miner_hotkey), 0)
        assert alternate != replay.miner_hotkey
        return replace(replay, validator_hotkey=alternate)

    monkeypatch.setattr(
        pilot_feed_module,
        "replay_bundle_detailed",
        same_key_with_another_prefix,
    )
    with pytest.raises(ValueError, match="hotkeys must be distinct"):
        build_observer_pilot_feed(_write_feed_config(tmp_path / "feed.json", bundle_root))


@pytest.mark.asyncio
async def test_public_pilot_rejects_video_urls_with_query_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from .factories import three_requests

    requests = tuple(
        request.model_copy(
            update={
                "video": request.video.model_copy(
                    update={"url": "https://media.example/video.mp4?X-Amz-Signature=secret"}
                )
            }
        )
        for request in three_requests()
    )
    bundle_root, _requests = await build_completed_bundle(
        tmp_path,
        monkeypatch,
        requests=requests,
    )
    install_replay_decryptor(bundle_root, monkeypatch)

    with pytest.raises(ValueError, match="query or fragment"):
        build_observer_pilot_feed(_write_feed_config(tmp_path / "feed.json", bundle_root))


def test_empty_pilot_namespace_is_explicit() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))
    with TestClient(app) as client:
        response = client.get("/api/v1/pilots")
        invalid = client.get("/api/v1/pilots/not-a-digest")

    assert response.status_code == 200
    assert response.json()["availability"] == "not_started"
    assert response.json()["reason_code"] == "public_component_pilot_not_started"
    assert invalid.status_code == 422
    assert invalid.json()["error"]["reason_code"] == "invalid_pilot_id"


@pytest.mark.asyncio
async def test_local_pilot_runner_uses_distinct_signed_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests, truth, request_path, truth_path = write_case_inputs(tmp_path)
    revealed = [canonical_json_bytes(truth)]
    validator_wallet = dev_wallet("//Alice")
    miner_wallet = dev_wallet("//Bob")
    from .test_component_run import response_plaintext

    revealed.extend(
        canonical_json_bytes(
            response_plaintext(
                request,
                validator_hotkey=validator_wallet.hotkey.ss58_address,
                miner_hotkey=miner_wallet.hotkey.ss58_address,
            )
        )
        for request in requests
    )

    async def fake_decrypt(_sealed, *, timeout):
        return revealed.pop(0)

    monkeypatch.setattr(validator_module, "_decrypt", fake_decrypt)

    def stored_scoring(root: Path):
        store = EvidenceStore(root)
        manifest = store.load_manifest()
        return json.loads(store.read(manifest["scoring"]))

    monkeypatch.setattr(pilot_module, "replay_bundle", stored_scoring)
    bundle_root = tmp_path / "pilot-bundle"
    manifest_path, scoring = await run_local_component_pilot(
        requests_path=request_path,
        ground_truth_path=truth_path,
        output=bundle_root,
        validator_wallet=validator_wallet,
        miner_wallet=miner_wallet,
        translator=FixtureTranslator(),
        video_fetcher=FixtureFetcher(),
        model_revision=None,
        request_timeout_seconds=5,
        reveal_timeout_seconds=5,
        inference_timeout_seconds=5,
        backend_lifecycle_timeout_seconds=5,
    )

    assert revealed == []
    assert manifest_path == bundle_root / "manifest.json"
    assert scoring["assigned_clip_count"] == 3
    manifest = EvidenceStore(bundle_root).load_manifest()
    assert manifest["terminal_code"] == "component_test_no_weight"
    assert manifest["translation_weights_active"] is False
    assert manifest["protocol_conformance"] is False
    assert manifest["activation_evidence"] is False
