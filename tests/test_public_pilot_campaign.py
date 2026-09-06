from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import bittensor as bt
import pytest

from umi.protocol import GroundTruthPayload, TranslationRequest, canonical_json_bytes
from umi.public_pilot_campaign import (
    ASSET_REFERENCES,
    CAMPAIGN_EXTENSION,
    CAMPAIGN_ID,
    build_public_pilot_inputs,
    load_public_pilot_campaign,
    prepare_public_pilot_case,
    validate_public_pilot_replay,
)

from .factories import dev_wallet


def _entropy(size: int) -> bytes:
    return bytes([size]) * size


def _prepare(tmp_path: Path) -> Path:
    validator = dev_wallet("//PublicPilotValidator")
    miner = dev_wallet("//PublicPilotMiner")
    root = tmp_path / "case"
    prepare_public_pilot_case(
        root,
        coordinator_hotkey=validator.hotkey.ss58_address,
        expected_miner_uid=236,
        expected_miner_hotkey=miner.hotkey.ss58_address,
        current_round=bt.timelock.current_round(),
        setup_allowance_seconds=30,
        response_window_seconds=30,
        reveal_margin_seconds=30,
        entropy=_entropy,
    )
    return root


def test_public_pilot_case_is_exact_miner_bound_and_contains_no_plaintext_answers(
    tmp_path: Path,
) -> None:
    root = _prepare(tmp_path)
    campaign = load_public_pilot_campaign(root)
    validator = dev_wallet("//PublicPilotValidator")
    miner = dev_wallet("//PublicPilotMiner")

    assert campaign.campaign_id == CAMPAIGN_ID
    assert campaign.coordinator_hotkey == validator.hotkey.ss58_address
    assert campaign.expected_miner_uid == 236
    assert campaign.expected_miner_hotkey == miner.hotkey.ss58_address
    assert campaign.reveal_round - campaign.response_close_round == 10
    public_bytes = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    assert ASSET_REFERENCES[0].encode() not in public_bytes


def test_public_pilot_case_rejects_campaign_metadata_tampering(tmp_path: Path) -> None:
    root = _prepare(tmp_path)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest[CAMPAIGN_EXTENSION]["expected_miner_uid"] = 235
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    campaign = load_public_pilot_campaign(root)
    assert campaign.expected_miner_uid == 235

    manifest[CAMPAIGN_EXTENSION]["campaign_id"] = "00" * 32
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    with pytest.raises(ValueError, match="campaign_id"):
        load_public_pilot_campaign(root)


def test_public_pilot_input_timing_and_entropy_are_exact() -> None:
    request, truth = build_public_pilot_inputs(
        current_round=100,
        setup_allowance_seconds=30,
        response_window_seconds=30,
        reveal_margin_seconds=30,
        entropy=_entropy,
    )

    assert request.response_close_round == 120
    assert request.reveal_round == 130
    assert truth.response_close_round == 120
    assert truth.reveal_round == 130
    assert truth.items[0].references == list(ASSET_REFERENCES)
    validate_public_pilot_replay(request, truth)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("video", "url", "https://example.invalid/not-the-campaign.mp4"),
        ("video", "sha256", "99" * 32),
        ("video", "size_bytes", 123),
        ("task", "stratum", "short_utterance"),
        ("request", "scoring_policy_hash", "98" * 32),
    ),
)
def test_public_pilot_replay_rejects_noncampaign_request(
    section: str,
    field: str,
    value: object,
) -> None:
    request, truth = build_public_pilot_inputs(current_round=100, entropy=_entropy)
    raw = request.model_dump(mode="json", by_alias=True)
    if section == "request":
        raw[field] = value
    else:
        raw[section][field] = value
    changed = TranslationRequest.model_validate(raw)

    with pytest.raises(ValueError, match="public-pilot request"):
        validate_public_pilot_replay(changed, truth)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("metric", "cer"),
        (
            "references",
            ["an unrelated answer", "another unrelated answer", "a third unrelated answer"],
        ),
    ),
)
def test_public_pilot_replay_rejects_noncampaign_ground_truth(
    field: str,
    value: object,
) -> None:
    request, truth = build_public_pilot_inputs(current_round=100, entropy=_entropy)
    raw = deepcopy(truth.model_dump(mode="json", by_alias=True))
    raw["items"][0][field] = value
    changed = GroundTruthPayload.model_validate(raw)

    with pytest.raises(ValueError, match="fixed campaign answer set"):
        validate_public_pilot_replay(request, changed)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("expected_miner_uid", -1, "UID"),
        ("expected_miner_uid", True, "UID"),
        ("coordinator_hotkey", "not-ss58", "coordinator"),
        ("expected_miner_hotkey", "not-ss58", "miner"),
    ),
)
def test_public_pilot_case_rejects_invalid_identity_inputs(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    validator = dev_wallet("//PublicPilotValidator")
    miner = dev_wallet("//PublicPilotMiner")
    arguments: dict[str, object] = {
        "coordinator_hotkey": validator.hotkey.ss58_address,
        "expected_miner_uid": 236,
        "expected_miner_hotkey": miner.hotkey.ss58_address,
    }
    arguments[field] = value

    with pytest.raises(ValueError, match=message):
        prepare_public_pilot_case(
            tmp_path / field,
            current_round=100,
            entropy=_entropy,
            **arguments,  # type: ignore[arg-type]
        )
