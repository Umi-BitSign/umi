from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

import umi.validator as validator_module
from umi.audit import EvidenceStore
from umi.auth import RequestAuthenticator
from umi.backends import Translator
from umi.component import load_case, prepare_case, score_component_responses
from umi.config import Limits
from umi.miner import MinerRuntime, _identity, create_app
from umi.protocol import (
    RESPONSE_PLAINTEXT_SCHEMA,
    ResponseEnvelope,
    ResponsePlaintext,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)
from umi.validator import replay_bundle, run_component_case
from umi.video import VideoFetcher

from .factories import VIDEO_BYTES, dev_wallet, ground_truth, three_requests


@dataclass(frozen=True)
class FixtureFetcher(VideoFetcher):
    async def fetch(self, descriptor) -> bytes:
        return VIDEO_BYTES


@dataclass(frozen=True)
class FixtureTranslator(Translator):
    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        return "hello" if request.task.stratum == "fingerspelling" else "hello world"


def write_case_inputs(
    root: Path,
    requests: tuple[TranslationRequest, ...] | None = None,
):
    requests = requests or three_requests()
    truth = ground_truth(requests)
    request_path = root / "requests.json"
    truth_path = root / "ground-truth.json"
    request_path.write_bytes(
        canonical_json_bytes(
            [request.model_dump(mode="json", by_alias=True) for request in requests]
        )
    )
    truth_path.write_bytes(canonical_json_bytes(truth))
    return requests, truth, request_path, truth_path


def response_plaintext(
    request: TranslationRequest,
    *,
    validator_hotkey: str,
    miner_hotkey: str,
) -> ResponsePlaintext:
    hypothesis = "hello" if request.task.stratum == "fingerspelling" else "hello world"
    return ResponsePlaintext.model_validate(
        {
            "schema": RESPONSE_PLAINTEXT_SCHEMA,
            "protocol": request.protocol,
            "window_id": request.window_id,
            "batch_id": request.batch_id,
            "challenge_id": request.challenge_id,
            "request_digest": request_digest(request),
            "issued_block_hash": request.issued_block_hash,
            "validator_hotkey": validator_hotkey,
            "serving_hotkey": miner_hotkey,
            "status": "ok",
            "received_video_sha256": request.video.sha256,
            "hypothesis": hypothesis,
            "model_revision": None,
            "error_code": None,
        }
    )


def install_replay_decryptor(
    bundle_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = json.loads((bundle_root / "manifest.json").read_bytes())
    objects = bundle_root / "objects"
    revealed_by_ciphertext_hash = {
        manifest["ground_truth_envelope"]["sha256"]: (
            objects / manifest["ground_truth_plaintext"]["sha256"]
        ).read_bytes()
    }
    for outcome in manifest["outcomes"]:
        if outcome["response_plaintext"] is None:
            continue
        envelope = ResponseEnvelope.model_validate_json(
            (objects / outcome["response_envelope"]["sha256"]).read_bytes()
        )
        revealed_by_ciphertext_hash[envelope.encrypted_response_sha256] = (
            objects / outcome["response_plaintext"]["sha256"]
        ).read_bytes()

    def fake_sync_decrypt(sealed, **_kwargs):
        return revealed_by_ciphertext_hash[sealed.sha256_hex]

    monkeypatch.setattr(validator_module, "decrypt_response", fake_sync_decrypt)


async def build_completed_bundle(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    response_bytes: list[bytes] | None = None,
    requests: tuple[TranslationRequest, ...] | None = None,
) -> tuple[Path, tuple[TranslationRequest, ...]]:
    requests, truth, request_path, truth_path = write_case_inputs(root, requests)
    case_root = root / "case"
    prepare_case(request_path, truth_path, case_root)
    validator_wallet = dev_wallet("//Alice")
    miner_wallet = dev_wallet("//Bob")
    miner_hotkey, scheme = _identity(miner_wallet)
    runtime = MinerRuntime(
        wallet=miner_wallet,
        hotkey_ss58=miner_hotkey,
        signature_scheme=scheme,
        translator=FixtureTranslator(),
        video_fetcher=FixtureFetcher(),
        allowed_validator_hotkeys=frozenset({validator_wallet.hotkey.ss58_address}),
        authenticator=RequestAuthenticator.in_memory(miner_hotkey),
        limits=Limits(),
    )
    revealed = [canonical_json_bytes(truth)]
    revealed.extend(
        response_bytes
        or [
            canonical_json_bytes(
                response_plaintext(
                    request,
                    validator_hotkey=validator_wallet.hotkey.ss58_address,
                    miner_hotkey=miner_hotkey,
                )
            )
            for request in requests
        ]
    )

    async def fake_decrypt(_sealed, *, timeout):
        return revealed.pop(0)

    monkeypatch.setattr(validator_module, "_decrypt", fake_decrypt)
    bundle_root = root / "bundle"
    await run_component_case(
        case_root,
        bundle_root,
        wallet=validator_wallet,
        miner_url="http://miner.test",
        miner_hotkey=miner_hotkey,
        transport=httpx.ASGITransport(app=create_app(runtime)),
    )
    assert revealed == []
    return bundle_root, requests


def test_prepare_case_contains_no_reference_plaintext(tmp_path: Path) -> None:
    requests, _truth, request_path, truth_path = write_case_inputs(tmp_path)
    case_root = tmp_path / "case"
    manifest_path = prepare_case(request_path, truth_path, case_root)

    prepared = load_case(case_root)
    assert prepared.requests == requests
    assert manifest_path == case_root / "manifest.json"
    all_public_bytes = b"".join(
        path.read_bytes() for path in case_root.rglob("*") if path.is_file()
    )
    assert b"hello world" not in all_public_bytes
    assert b"hi world" not in all_public_bytes


def test_component_scoring_keeps_missing_assignment_as_zero(tmp_path: Path) -> None:
    requests, truth, _request_path, _truth_path = write_case_inputs(tmp_path)
    responses = {request.challenge_id: None for request in requests}
    scores = score_component_responses(requests, truth, responses)
    assert scores["assigned_clip_count"] == 3
    assert all(clip["score"] == {"numerator": 0, "denominator": 1} for clip in scores["per_clip"])
    assert scores["diagnostic_accuracy"]["score"] == {"numerator": 0, "denominator": 1}
    assert scores["weight_eligible"] is False


@pytest.mark.asyncio
async def test_run_and_offline_replay_reproduce_exact_scores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests, truth, request_path, truth_path = write_case_inputs(tmp_path)
    case_root = tmp_path / "case"
    prepare_case(request_path, truth_path, case_root)

    validator_wallet = dev_wallet("//Alice")
    miner_wallet = dev_wallet("//Bob")
    miner_hotkey, scheme = _identity(miner_wallet)
    runtime = MinerRuntime(
        wallet=miner_wallet,
        hotkey_ss58=miner_hotkey,
        signature_scheme=scheme,
        translator=FixtureTranslator(),
        video_fetcher=FixtureFetcher(),
        allowed_validator_hotkeys=frozenset({validator_wallet.hotkey.ss58_address}),
        authenticator=RequestAuthenticator.in_memory(miner_hotkey),
        limits=Limits(),
    )

    revealed = [canonical_json_bytes(truth)]
    revealed.extend(
        canonical_json_bytes(
            response_plaintext(
                request,
                validator_hotkey=validator_wallet.hotkey.ss58_address,
                miner_hotkey=miner_hotkey,
            )
        )
        for request in requests
    )

    async def fake_decrypt(_sealed, *, timeout):
        assert timeout == 5
        return revealed.pop(0)

    monkeypatch.setattr(validator_module, "_decrypt", fake_decrypt)
    bundle_root = tmp_path / "bundle"
    manifest_path = await run_component_case(
        case_root,
        bundle_root,
        wallet=validator_wallet,
        miner_url="http://miner.test",
        miner_hotkey=miner_hotkey,
        reveal_timeout_seconds=5,
        transport=httpx.ASGITransport(app=create_app(runtime)),
    )
    assert revealed == []
    assert manifest_path == bundle_root / "manifest.json"

    manifest = json.loads(manifest_path.read_bytes())
    assert manifest["translation_weights_active"] is False
    assert manifest["protocol_conformance"] is False
    assert manifest["activation_evidence"] is False
    assert manifest["terminal_code"] == "component_test_no_weight"
    assert "weight_submission" in manifest["not_reached"]

    install_replay_decryptor(bundle_root, monkeypatch)
    replayed = replay_bundle(bundle_root)
    assert replayed["weight_eligible"] is False
    assert replayed["diagnostic_accuracy"]["score"] == {
        "numerator": 1,
        "denominator": 1,
    }
    assert all(clip["failure_code"] is None for clip in replayed["per_clip"])


@pytest.mark.asyncio
async def test_replay_detects_content_object_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests, truth, request_path, truth_path = write_case_inputs(tmp_path)
    case_root = tmp_path / "case"
    prepare_case(request_path, truth_path, case_root)
    validator_wallet = dev_wallet("//Alice")
    miner_wallet = dev_wallet("//Bob")
    miner_hotkey, scheme = _identity(miner_wallet)
    runtime = MinerRuntime(
        wallet=miner_wallet,
        hotkey_ss58=miner_hotkey,
        signature_scheme=scheme,
        translator=FixtureTranslator(),
        video_fetcher=FixtureFetcher(),
        allowed_validator_hotkeys=frozenset({validator_wallet.hotkey.ss58_address}),
        authenticator=RequestAuthenticator.in_memory(miner_hotkey),
        limits=Limits(),
    )
    revealed = [canonical_json_bytes(truth)] + [
        canonical_json_bytes(
            response_plaintext(
                request,
                validator_hotkey=validator_wallet.hotkey.ss58_address,
                miner_hotkey=miner_hotkey,
            )
        )
        for request in requests
    ]

    async def fake_decrypt(_sealed, *, timeout):
        return revealed.pop(0)

    monkeypatch.setattr(validator_module, "_decrypt", fake_decrypt)
    bundle_root = tmp_path / "bundle"
    await run_component_case(
        case_root,
        bundle_root,
        wallet=validator_wallet,
        miner_url="http://miner.test",
        miner_hotkey=miner_hotkey,
        transport=httpx.ASGITransport(app=create_app(runtime)),
    )
    manifest = json.loads((bundle_root / "manifest.json").read_bytes())
    scoring_digest = manifest["scoring"]["sha256"]
    (bundle_root / "objects" / scoring_digest).write_bytes(b"{}")
    install_replay_decryptor(bundle_root, monkeypatch)
    with pytest.raises(ValueError, match=r"byte length|SHA-256"):
        replay_bundle(bundle_root)


def test_load_case_rejects_ground_truth_that_opens_before_request_round(
    tmp_path: Path,
) -> None:
    requests, _truth, request_path, truth_path = write_case_inputs(tmp_path)
    case_root = tmp_path / "case"
    prepare_case(request_path, truth_path, case_root)
    store = EvidenceStore(case_root)
    manifest = store.load_manifest()
    later_requests = tuple(
        request.model_copy(
            update={
                "response_close_round": request.response_close_round + 1,
                "reveal_round": request.reveal_round + 1,
            }
        )
        for request in requests
    )
    manifest["request_objects"] = [store.add_json(request).as_dict() for request in later_requests]
    store.write_manifest(manifest)

    with pytest.raises(ValueError, match="envelope round"):
        load_case(case_root)


def test_load_case_rejects_duplicate_request_objects(tmp_path: Path) -> None:
    _requests, _truth, request_path, truth_path = write_case_inputs(tmp_path)
    case_root = tmp_path / "case"
    prepare_case(request_path, truth_path, case_root)
    store = EvidenceStore(case_root)
    manifest = store.load_manifest()
    manifest["request_objects"] = [manifest["request_objects"][0]] * 2
    store.write_manifest(manifest)

    with pytest.raises(ValueError, match="duplicate challenge ID"):
        load_case(case_root)


@pytest.mark.asyncio
async def test_invalid_revealed_plaintext_is_retained_and_replayed_as_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response_bytes = [b"{}"] * 3
    bundle_root, _ = await build_completed_bundle(
        tmp_path,
        monkeypatch,
        response_bytes=response_bytes,
    )
    manifest = EvidenceStore(bundle_root).load_manifest()
    first = manifest["outcomes"][0]
    assert first["failure_code"] == "plaintext_invalid"
    assert first["response_plaintext"] is not None

    install_replay_decryptor(bundle_root, monkeypatch)
    replayed = replay_bundle(bundle_root)
    assert replayed["per_clip"][0]["failure_code"] == "plaintext_invalid"
    assert replayed["per_clip"][0]["score"] == {"numerator": 0, "denominator": 1}


@pytest.mark.asyncio
async def test_replay_rejects_duplicate_outcomes_before_decryption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_root, _requests = await build_completed_bundle(tmp_path, monkeypatch)
    store = EvidenceStore(bundle_root)
    manifest = store.load_manifest()
    manifest["outcomes"].append(manifest["outcomes"][0])
    store.write_manifest(manifest)

    with pytest.raises(ValueError, match="duplicate challenge ID"):
        replay_bundle(bundle_root)


@pytest.mark.asyncio
async def test_replay_rejects_a_different_scoring_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_root, _requests = await build_completed_bundle(tmp_path, monkeypatch)
    store = EvidenceStore(bundle_root)
    manifest = store.load_manifest()
    manifest["scoring_environment"]["unicode_data_version"] = "different"
    store.write_manifest(manifest)

    with pytest.raises(ValueError, match="scoring environment"):
        replay_bundle(bundle_root)


@pytest.mark.asyncio
async def test_late_valid_envelopes_remain_replayable_zeroes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = three_requests()
    close_ns = validator_module._round_time_ns(requests[0].response_close_round)
    clock = itertools.count(close_ns + 1)
    monkeypatch.setattr(validator_module.time, "time_ns", lambda: next(clock))
    bundle_root, _requests = await build_completed_bundle(
        tmp_path,
        monkeypatch,
        requests=requests,
    )
    manifest = EvidenceStore(bundle_root).load_manifest()
    assert all(outcome["failure_code"] == "late" for outcome in manifest["outcomes"])

    install_replay_decryptor(bundle_root, monkeypatch)
    replayed = replay_bundle(bundle_root)
    assert all(clip["failure_code"] == "late" for clip in replayed["per_clip"])
    assert all(clip["score"] == {"numerator": 0, "denominator": 1} for clip in replayed["per_clip"])
