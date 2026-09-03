from __future__ import annotations

import hashlib
from types import SimpleNamespace

import bittensor as bt

from umi.protocol import (
    GROUND_TRUTH_SCHEMA,
    GROUND_TRUTH_TLE_PROFILE,
    GroundTruthPayload,
    TranslationRequest,
    base64url_encode,
)

WINDOW_ID = "10" * 32
BATCH_ID = base64url_encode(b"B" * 16)
POLICY_HASH = "20" * 32
BLOCK_HASH = "0x" + "30" * 32
VIDEO_BYTES = b"not-a-real-mp4-component-fixture"
VIDEO_SHA256 = hashlib.sha256(VIDEO_BYTES).hexdigest()
TEST_REVEAL_ROUND = 10**9


def dev_wallet(uri: str, crypto_type: int = bt.sp_core.CRYPTO_SR25519):
    hotkey = bt.sp_core.Keypair.create_from_uri(uri, crypto_type=crypto_type)
    coldkey = bt.sp_core.Keypair.create_from_uri(f"{uri}//cold", crypto_type=crypto_type)
    return SimpleNamespace(coldkey=coldkey, coldkeypub=coldkey, hotkey=hotkey)


def challenge_request(
    index: int = 1,
    *,
    stratum: str = "short_utterance",
    reveal_round: int | None = None,
) -> TranslationRequest:
    reveal = TEST_REVEAL_ROUND if reveal_round is None else reveal_round
    return TranslationRequest.model_validate(
        {
            "protocol": "umi-asl/0.1",
            "window_id": WINDOW_ID,
            "batch_id": BATCH_ID,
            "challenge_id": base64url_encode(bytes([index]) * 16),
            "issued_block": 100,
            "issued_block_hash": BLOCK_HASH,
            "deadline_block": 110,
            "response_close_round": reveal - 2,
            "reveal_round": reveal,
            "video": {
                "url": f"https://objects.example/{index:032x}",
                "sha256": VIDEO_SHA256,
                "size_bytes": len(VIDEO_BYTES),
                "media_type": "video/mp4",
            },
            "task": {
                "source_language": "ase",
                "target_language": "en",
                "stratum": stratum,
            },
            "scoring_policy_hash": POLICY_HASH,
        }
    )


def three_requests(reveal_round: int | None = None) -> tuple[TranslationRequest, ...]:
    reveal = TEST_REVEAL_ROUND if reveal_round is None else reveal_round
    return (
        challenge_request(1, stratum="fingerspelling", reveal_round=reveal),
        challenge_request(2, stratum="short_utterance", reveal_round=reveal),
        challenge_request(3, stratum="continuous", reveal_round=reveal),
    )


def ground_truth(requests: tuple[TranslationRequest, ...]) -> GroundTruthPayload:
    items = []
    for request in requests:
        script_hash = f"{int.from_bytes(bytes([len(items) + 1]), 'big'):064x}"
        references = (
            ["hello", "h e l l o", "hello"]
            if request.task.stratum == "fingerspelling"
            else ["hello world", "hi world", "hello, world"]
        )
        items.append(
            {
                "challenge_id": request.challenge_id,
                "metric": "cer" if request.task.stratum == "fingerspelling" else "wer",
                "canary": False,
                "references": references,
                "canary_evidence": None,
                "normalized_script_sha256": script_hash,
                "retirement_script_sha256s": [script_hash],
                "consent_manifest_sha256": "40" * 32,
            }
        )
    first = requests[0]
    return GroundTruthPayload.model_validate(
        {
            "schema": GROUND_TRUTH_SCHEMA,
            "window_id": first.window_id,
            "batch_id": first.batch_id,
            "scoring_policy_hash": first.scoring_policy_hash,
            "tle_profile": GROUND_TRUTH_TLE_PROFILE,
            "response_close_round": first.response_close_round,
            "reveal_round": first.reveal_round,
            "items": items,
        }
    )
