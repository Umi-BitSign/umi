"""Sealed, miner-bound cases for the public SN78 endpoint pilot."""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import EvidenceStore
from .component import load_case, prepare_case
from .encoding import account_id32
from .external_miner_pilot import (
    ASSET_ATTRIBUTION,
    ASSET_LICENSE,
    ASSET_REFERENCES,
    ASSET_SHA256,
    ASSET_SIZE_BYTES,
    ASSET_SOURCE_URL,
    ASSET_URL,
)
from .protocol import (
    GROUND_TRUTH_SCHEMA,
    GROUND_TRUTH_TLE_PROFILE,
    PROTOCOL_VERSION,
    GroundTruthPayload,
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
)
from .scoring import normalize_text
from .window import QUICKNET_PERIOD_MS, ceil_div

CAMPAIGN_EXTENSION = "public_endpoint_pilot_campaign"
CAMPAIGN_SCHEMA = "umi-public-endpoint-pilot-campaign/1"
DEFAULT_SETUP_ALLOWANCE_SECONDS = 1_800.0
DEFAULT_RESPONSE_WINDOW_SECONDS = 300.0
DEFAULT_REVEAL_MARGIN_SECONDS = 60.0
_MAX_U16 = (1 << 16) - 1
# The wheel intentionally contains only ``src/umi``. Keep the checked-in
# attribution document's verified identity in the campaign descriptor without
# making an installed CLI depend on an unpackaged repository path.
_ATTRIBUTION_DOCUMENT_SHA256 = "d0d728ea55bc8bb6f3badc31ab20ad98c54d0a0b854d357ad13ca1dd1f5e1cda"
_CONSENT_PLACEHOLDER_SHA256 = hashlib.sha256(
    b"umi-component-no-consent-v1\0" + bytes.fromhex(_ATTRIBUTION_DOCUMENT_SHA256)
).hexdigest()

_CAMPAIGN_DESCRIPTOR: dict[str, Any] = {
    "schema": CAMPAIGN_SCHEMA,
    "protocol": PROTOCOL_VERSION,
    "request_profile": {
        "issued_block": 0,
        "deadline_block": 1,
        "video": {
            "url": ASSET_URL,
            "sha256": ASSET_SHA256,
            "size_bytes": ASSET_SIZE_BYTES,
            "media_type": "video/mp4",
            "source_url": ASSET_SOURCE_URL,
            "license": ASSET_LICENSE,
            "attribution": ASSET_ATTRIBUTION,
            "attribution_document_sha256": _ATTRIBUTION_DOCUMENT_SHA256,
        },
        "task": {
            "source_language": "ase",
            "target_language": "en",
            "stratum": "continuous",
        },
    },
    "ground_truth_profile": {
        "metric": "wer",
        "canary": False,
        "references": list(ASSET_REFERENCES),
        "consent_placeholder_sha256": _CONSENT_PLACEHOLDER_SHA256,
    },
    "claims": {
        "known_challenge": True,
        "fresh_benchmark_data": False,
        "activation_evidence": False,
        "validator_input_eligible": False,
    },
}
CAMPAIGN_ID = hashlib.sha256(
    b"umi-public-endpoint-pilot-campaign-v1\0" + canonical_json_bytes(_CAMPAIGN_DESCRIPTOR)
).hexdigest()
CAMPAIGN_POLICY_HASH = hashlib.sha256(
    b"umi-public-endpoint-pilot-policy-v1\0" + bytes.fromhex(CAMPAIGN_ID)
).hexdigest()


@dataclass(frozen=True, slots=True)
class PublicPilotCampaign:
    """Verified public-pilot metadata carried by one sealed component case."""

    case_root: Path
    campaign_id: str
    coordinator_hotkey: str
    expected_miner_uid: int
    expected_miner_hotkey: str
    response_close_round: int
    reveal_round: int


def _positive_seconds(value: float, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{label} must be finite and positive")
    return float(value)


def _uid(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_U16:
        raise ValueError("expected miner UID must be an integer in [0, 65535]")
    return value


def _hotkey(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty SS58 address")
    try:
        account_id32(value)
    except ValueError as error:
        raise ValueError(f"{label} is not a valid SS58 account") from error
    return value


def _campaign_script_hash() -> str:
    return hashlib.sha256(normalize_text(ASSET_REFERENCES[0]).encode()).hexdigest()


def _campaign_consent_placeholder() -> str:
    return _CONSENT_PLACEHOLDER_SHA256


def _validate_public_pilot_request(request: TranslationRequest) -> None:
    if request.protocol != PROTOCOL_VERSION:
        raise ValueError("public-pilot request protocol is not fixed by the campaign")
    if request.issued_block != 0 or request.deadline_block != 1:
        raise ValueError("public-pilot request block placeholders are not fixed by the campaign")
    if request.video.model_dump(mode="json") != {
        "url": ASSET_URL,
        "sha256": ASSET_SHA256,
        "size_bytes": ASSET_SIZE_BYTES,
        "media_type": "video/mp4",
    }:
        raise ValueError("public-pilot request does not bind the fixed campaign asset")
    if request.task.model_dump(mode="json") != {
        "source_language": "ase",
        "target_language": "en",
        "stratum": "continuous",
    }:
        raise ValueError("public-pilot request task is not fixed by the campaign")
    if request.scoring_policy_hash != CAMPAIGN_POLICY_HASH:
        raise ValueError("public-pilot request scoring policy is not fixed by the campaign")
    if request.response_close_round <= 0 or request.reveal_round <= request.response_close_round:
        raise ValueError("public-pilot request reveal schedule is invalid")


def validate_public_pilot_request(request: TranslationRequest) -> None:
    """Verify one request against the immutable public endpoint campaign profile."""

    if not isinstance(request, TranslationRequest):
        raise TypeError("public-pilot request must be a TranslationRequest")
    _validate_public_pilot_request(request)


def validate_public_pilot_replay(
    request: TranslationRequest,
    ground_truth: GroundTruthPayload,
) -> None:
    """Verify that revealed component evidence is exactly the published campaign."""

    if not isinstance(request, TranslationRequest) or not isinstance(
        ground_truth, GroundTruthPayload
    ):
        raise TypeError("public-pilot replay requires parsed request and ground truth")
    validate_public_pilot_request(request)
    if (
        ground_truth.schema_ != GROUND_TRUTH_SCHEMA
        or ground_truth.window_id != request.window_id
        or ground_truth.batch_id != request.batch_id
        or ground_truth.scoring_policy_hash != CAMPAIGN_POLICY_HASH
        or ground_truth.tle_profile != GROUND_TRUTH_TLE_PROFILE
        or ground_truth.response_close_round != request.response_close_round
        or ground_truth.reveal_round != request.reveal_round
        or len(ground_truth.items) != 1
    ):
        raise ValueError("public-pilot ground truth does not bind the fixed request")
    item = ground_truth.items[0]
    script_hash = _campaign_script_hash()
    if item.model_dump(mode="json") != {
        "challenge_id": request.challenge_id,
        "metric": "wer",
        "canary": False,
        "references": list(ASSET_REFERENCES),
        "canary_evidence": None,
        "normalized_script_sha256": script_hash,
        "retirement_script_sha256s": [script_hash],
        "consent_manifest_sha256": _campaign_consent_placeholder(),
    }:
        raise ValueError("public-pilot ground truth is not the fixed campaign answer set")


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("private pilot input write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_public_pilot_inputs(
    *,
    current_round: int,
    setup_allowance_seconds: float = DEFAULT_SETUP_ALLOWANCE_SECONDS,
    response_window_seconds: float = DEFAULT_RESPONSE_WINDOW_SECONDS,
    reveal_margin_seconds: float = DEFAULT_REVEAL_MARGIN_SECONDS,
    entropy: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[TranslationRequest, GroundTruthPayload]:
    """Build one known, no-weight challenge whose answers remain sealed until reveal."""

    if isinstance(current_round, bool) or not isinstance(current_round, int) or current_round <= 0:
        raise ValueError("current Quicknet round must be a positive integer")
    setup_seconds = _positive_seconds(setup_allowance_seconds, "setup allowance")
    response_seconds = _positive_seconds(response_window_seconds, "response window")
    reveal_seconds = _positive_seconds(reveal_margin_seconds, "reveal margin")
    period_seconds = QUICKNET_PERIOD_MS // 1000
    response_close_round = current_round + ceil_div(
        math.ceil(setup_seconds + response_seconds), period_seconds
    )
    reveal_round = response_close_round + ceil_div(math.ceil(reveal_seconds), period_seconds)

    batch_bytes = entropy(16)
    challenge_bytes = entropy(16)
    nonce = entropy(32)
    if len(batch_bytes) != 16 or len(challenge_bytes) != 16 or len(nonce) != 32:
        raise RuntimeError("entropy provider returned an invalid byte count")
    window_id = hashlib.sha256(
        b"umi-public-endpoint-pilot-window-v1\0"
        + nonce
        + response_close_round.to_bytes(8, "big")
        + reveal_round.to_bytes(8, "big")
    ).hexdigest()
    issued_block_hash = (
        "0x" + hashlib.sha256(b"umi-component-nonchain-block-v1\0" + nonce).hexdigest()
    )
    request = TranslationRequest.model_validate(
        {
            "protocol": PROTOCOL_VERSION,
            "window_id": window_id,
            "batch_id": base64url_encode(batch_bytes),
            "challenge_id": base64url_encode(challenge_bytes),
            "issued_block": 0,
            "issued_block_hash": issued_block_hash,
            "deadline_block": 1,
            "response_close_round": response_close_round,
            "reveal_round": reveal_round,
            "video": {
                "url": ASSET_URL,
                "sha256": ASSET_SHA256,
                "size_bytes": ASSET_SIZE_BYTES,
                "media_type": "video/mp4",
            },
            "task": {
                "source_language": "ase",
                "target_language": "en",
                "stratum": "continuous",
            },
            "scoring_policy_hash": CAMPAIGN_POLICY_HASH,
        }
    )
    script_hash = _campaign_script_hash()
    consent_placeholder = _campaign_consent_placeholder()
    truth = GroundTruthPayload.model_validate(
        {
            "schema": GROUND_TRUTH_SCHEMA,
            "window_id": request.window_id,
            "batch_id": request.batch_id,
            "scoring_policy_hash": request.scoring_policy_hash,
            "tle_profile": GROUND_TRUTH_TLE_PROFILE,
            "response_close_round": response_close_round,
            "reveal_round": reveal_round,
            "items": [
                {
                    "challenge_id": request.challenge_id,
                    "metric": "wer",
                    "canary": False,
                    "references": list(ASSET_REFERENCES),
                    "canary_evidence": None,
                    "normalized_script_sha256": script_hash,
                    "retirement_script_sha256s": [script_hash],
                    "consent_manifest_sha256": consent_placeholder,
                }
            ],
        }
    )
    validate_public_pilot_replay(request, truth)
    return request, truth


def prepare_public_pilot_case(
    output: Path,
    *,
    coordinator_hotkey: str,
    expected_miner_uid: int,
    expected_miner_hotkey: str,
    current_round: int,
    setup_allowance_seconds: float = DEFAULT_SETUP_ALLOWANCE_SECONDS,
    response_window_seconds: float = DEFAULT_RESPONSE_WINDOW_SECONDS,
    reveal_margin_seconds: float = DEFAULT_REVEAL_MARGIN_SECONDS,
    entropy: Callable[[int], bytes] = secrets.token_bytes,
) -> Path:
    """Create a sealed case restricted to one coordinator and registered miner."""

    coordinator = _hotkey(coordinator_hotkey, "coordinator hotkey")
    miner = _hotkey(expected_miner_hotkey, "expected miner hotkey")
    if account_id32(coordinator) == account_id32(miner):
        raise ValueError("coordinator and miner hotkeys must be distinct")
    uid = _uid(expected_miner_uid)
    request, truth = build_public_pilot_inputs(
        current_round=current_round,
        setup_allowance_seconds=setup_allowance_seconds,
        response_window_seconds=response_window_seconds,
        reveal_margin_seconds=reveal_margin_seconds,
        entropy=entropy,
    )
    with tempfile.TemporaryDirectory(prefix="umi-public-pilot-inputs-") as temporary:
        private_root = Path(temporary)
        request_path = private_root / "requests.json"
        truth_path = private_root / "ground-truth.json"
        _write_private(
            request_path,
            canonical_json_bytes([request.model_dump(mode="json", by_alias=True)]),
        )
        _write_private(truth_path, canonical_json_bytes(truth))
        manifest_path = prepare_case(request_path, truth_path, output)

    store = EvidenceStore(output)
    manifest = store.load_manifest()
    manifest[CAMPAIGN_EXTENSION] = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "coordinator_hotkey": coordinator,
        "expected_miner_uid": uid,
        "expected_miner_hotkey": miner,
        "known_challenge": True,
        "fresh_benchmark_data": False,
        "activation_evidence": False,
        "validator_input_eligible": False,
        "response_close_round": request.response_close_round,
        "reveal_round": request.reveal_round,
        "asset": {
            "url": ASSET_URL,
            "sha256": ASSET_SHA256,
            "size_bytes": ASSET_SIZE_BYTES,
            "source_url": ASSET_SOURCE_URL,
            "license": ASSET_LICENSE,
            "attribution": ASSET_ATTRIBUTION,
        },
    }
    store.write_manifest(manifest)
    # Re-read all content-addressed objects and bindings before returning a distributable case.
    load_public_pilot_campaign(output)
    return manifest_path


def load_public_pilot_campaign(case_root: Path) -> PublicPilotCampaign:
    """Load and strictly verify one miner-bound public-pilot case."""

    prepared = load_case(case_root)
    store = EvidenceStore(case_root)
    manifest = store.load_manifest()
    raw = manifest.get(CAMPAIGN_EXTENSION)
    if not isinstance(raw, dict) or set(raw) != {
        "schema",
        "campaign_id",
        "coordinator_hotkey",
        "expected_miner_uid",
        "expected_miner_hotkey",
        "known_challenge",
        "fresh_benchmark_data",
        "activation_evidence",
        "validator_input_eligible",
        "response_close_round",
        "reveal_round",
        "asset",
    }:
        raise ValueError("component case lacks the exact public-pilot campaign record")
    expected_asset: dict[str, Any] = {
        "url": ASSET_URL,
        "sha256": ASSET_SHA256,
        "size_bytes": ASSET_SIZE_BYTES,
        "source_url": ASSET_SOURCE_URL,
        "license": ASSET_LICENSE,
        "attribution": ASSET_ATTRIBUTION,
    }
    fixed = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "known_challenge": True,
        "fresh_benchmark_data": False,
        "activation_evidence": False,
        "validator_input_eligible": False,
        "asset": expected_asset,
    }
    for field, expected in fixed.items():
        if raw.get(field) != expected:
            raise ValueError(f"public-pilot campaign field is invalid: {field}")
    coordinator = _hotkey(raw.get("coordinator_hotkey"), "coordinator hotkey")
    miner = _hotkey(raw.get("expected_miner_hotkey"), "expected miner hotkey")
    uid = _uid(raw.get("expected_miner_uid"))
    if account_id32(coordinator) == account_id32(miner):
        raise ValueError("coordinator and miner hotkeys must be distinct")
    if len(prepared.requests) != 1:
        raise ValueError("public endpoint pilot must contain exactly one request")
    request = prepared.requests[0]
    validate_public_pilot_request(request)
    if raw.get("response_close_round") != request.response_close_round:
        raise ValueError("campaign response-close round does not match its request")
    if raw.get("reveal_round") != request.reveal_round:
        raise ValueError("campaign reveal round does not match its request")
    return PublicPilotCampaign(
        case_root=case_root,
        campaign_id=CAMPAIGN_ID,
        coordinator_hotkey=coordinator,
        expected_miner_uid=uid,
        expected_miner_hotkey=miner,
        response_close_round=request.response_close_round,
        reveal_round=request.reveal_round,
    )


__all__ = [
    "CAMPAIGN_EXTENSION",
    "CAMPAIGN_ID",
    "CAMPAIGN_POLICY_HASH",
    "CAMPAIGN_SCHEMA",
    "DEFAULT_RESPONSE_WINDOW_SECONDS",
    "DEFAULT_REVEAL_MARGIN_SECONDS",
    "DEFAULT_SETUP_ALLOWANCE_SECONDS",
    "PublicPilotCampaign",
    "build_public_pilot_inputs",
    "load_public_pilot_campaign",
    "prepare_public_pilot_case",
    "validate_public_pilot_replay",
    "validate_public_pilot_request",
]
