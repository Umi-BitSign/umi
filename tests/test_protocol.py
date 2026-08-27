from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from umi.protocol import (
    GroundTruthPayload,
    ResponseEnvelope,
    ResponsePlaintext,
    TranslationRequest,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
    request_digest,
    response_digest,
    sha256_hex,
)

H0 = "00" * 32
H1 = "11" * 32
H2 = "22" * 32
BLOCK_HASH = "0x" + "ab" * 32
BATCH_ID = base64url_encode(bytes(range(16)))
CHALLENGE_ID = base64url_encode(bytes(range(16, 32)))


def request_data() -> dict:
    return {
        "protocol": "umi-asl/0.1",
        "window_id": H0,
        "batch_id": BATCH_ID,
        "challenge_id": CHALLENGE_ID,
        "issued_block": 123456,
        "issued_block_hash": BLOCK_HASH,
        "deadline_block": 123466,
        "response_close_round": 12345578,
        "reveal_round": 12345678,
        "video": {
            "url": "https://objects.example/opaque",
            "sha256": H1,
            "size_bytes": 1234567,
            "media_type": "video/mp4",
        },
        "task": {
            "source_language": "ase",
            "target_language": "en",
            "stratum": "short_utterance",
        },
        "scoring_policy_hash": H2,
    }


def response_plaintext_data() -> dict:
    return {
        "schema": "umi-response-plaintext/1",
        "protocol": "umi-asl/0.1",
        "window_id": H0,
        "batch_id": BATCH_ID,
        "challenge_id": CHALLENGE_ID,
        "request_digest": H1,
        "issued_block_hash": BLOCK_HASH,
        "validator_hotkey": "validator",
        "serving_hotkey": "miner",
        "status": "ok",
        "received_video_sha256": H2,
        "hypothesis": "Hello, world!",
        "model_revision": None,
        "error_code": None,
    }


def response_envelope_data() -> dict:
    encrypted = base64url_encode(b"portable-scale-envelope")
    return {
        "schema": "umi-response-envelope/1",
        "protocol": "umi-asl/0.1",
        "window_id": H0,
        "batch_id": BATCH_ID,
        "challenge_id": CHALLENGE_ID,
        "request_digest": H1,
        "issued_block_hash": BLOCK_HASH,
        "validator_hotkey": "validator",
        "serving_hotkey": "miner",
        "response_tle_profile": "umi-response-tle/1",
        "response_reveal_round": 12345678,
        "encrypted_response": encrypted,
        "encrypted_response_sha256": sha256_hex(b"portable-scale-envelope"),
        "signature_scheme": "sr25519",
    }


def ground_truth_data() -> dict:
    return {
        "schema": "umi-ground-truth/1",
        "window_id": H0,
        "batch_id": BATCH_ID,
        "scoring_policy_hash": H2,
        "tle_profile": "umi-tle/1",
        "response_close_round": 12345578,
        "reveal_round": 12345678,
        "items": [
            {
                "challenge_id": CHALLENGE_ID,
                "metric": "wer",
                "canary": False,
                "references": ["hello world", "hello, world", "hi world"],
                "canary_evidence": None,
                "normalized_script_sha256": H1,
                "retirement_script_sha256s": [H1],
                "consent_manifest_sha256": H2,
            }
        ],
    }


def test_canonical_json_and_sha256_are_stable() -> None:
    canonical = canonical_json_bytes({"z": [3, 2, 1], "a": "value"})
    assert canonical == b'{"a":"value","z":[3,2,1]}'
    assert sha256_hex(canonical) == hashlib.sha256(canonical).hexdigest()


def test_request_digest_uses_exact_domain_separator() -> None:
    request = TranslationRequest.model_validate(request_data())
    canonical = canonical_json_bytes(request)
    expected = hashlib.sha256(b"umi-request-v1\0" + canonical).hexdigest()
    assert request_digest(request) == expected


def test_response_digest_uses_exact_domain_separator() -> None:
    envelope = ResponseEnvelope.model_validate(response_envelope_data())
    canonical = canonical_json_bytes(envelope)
    expected = hashlib.sha256(b"umi-response-envelope-v1\0" + canonical).hexdigest()
    assert response_digest(envelope) == expected


def test_base64url_is_strict_unpadded_and_canonical() -> None:
    raw = bytes(range(16))
    encoded = base64url_encode(raw)
    assert "=" not in encoded
    assert base64url_decode(encoded) == raw

    for invalid in (encoded + "=", "not+url-safe", "A", "AB"):
        with pytest.raises(ValueError):
            base64url_decode(invalid)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("window_id",), "AA" * 32),
        (("batch_id",), base64url_encode(b"too short")),
        (("task", "source_language"), "asl"),
        (("task", "target_language"), "fr"),
        (("task", "stratum"), "unknown"),
    ],
)
def test_request_rejects_invalid_protocol_fields(path: tuple[str, ...], value: object) -> None:
    data = request_data()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        TranslationRequest.model_validate(data)


def test_request_rejects_deadline_round_order_and_extras() -> None:
    for field, value in (
        ("deadline_block", 123456),
        ("reveal_round", 12345578),
    ):
        data = request_data()
        data[field] = value
        with pytest.raises(ValidationError):
            TranslationRequest.model_validate(data)

    data = request_data()
    data["unexpected"] = True
    with pytest.raises(ValidationError):
        TranslationRequest.model_validate(data)


def test_response_plaintext_enforces_success_and_error_shapes() -> None:
    ok = ResponsePlaintext.model_validate(response_plaintext_data())
    assert ok.status == "ok"

    missing_hypothesis = response_plaintext_data()
    missing_hypothesis["hypothesis"] = None
    with pytest.raises(ValidationError):
        ResponsePlaintext.model_validate(missing_hypothesis)

    error = response_plaintext_data()
    error.update(
        status="error",
        received_video_sha256=None,
        hypothesis=None,
        model_revision=None,
        error_code="video_fetch_failed",
    )
    parsed_error = ResponsePlaintext.model_validate(error)
    assert parsed_error.status == "error"

    error["model_revision"] = H0
    with pytest.raises(ValidationError):
        ResponsePlaintext.model_validate(error)


def test_response_plaintext_rejects_more_than_128_normalized_tokens() -> None:
    data = response_plaintext_data()
    data["hypothesis"] = " ".join(f"word{i}" for i in range(129))
    with pytest.raises(ValidationError):
        ResponsePlaintext.model_validate(data)


def test_response_plaintext_rejects_resource_heavy_single_token() -> None:
    data = response_plaintext_data()
    data["hypothesis"] = "a" * 513
    with pytest.raises(ValidationError, match="512 normalized graphemes"):
        ResponsePlaintext.model_validate(data)


def test_response_envelope_rejects_padding_and_extra_signature() -> None:
    padded = response_envelope_data()
    padded["encrypted_response"] += "="
    with pytest.raises(ValidationError):
        ResponseEnvelope.model_validate(padded)

    signed = response_envelope_data()
    signed["signature"] = "0x" + "00" * 64
    with pytest.raises(ValidationError):
        ResponseEnvelope.model_validate(signed)


def test_ground_truth_payload_accepts_ordinary_item_and_rejects_bad_shapes() -> None:
    payload = GroundTruthPayload.model_validate(ground_truth_data())
    assert payload.items[0].references[0] == "hello world"

    bad_retirement = ground_truth_data()
    bad_retirement["items"][0]["retirement_script_sha256s"] = [H0]
    with pytest.raises(ValidationError):
        GroundTruthPayload.model_validate(bad_retirement)

    bad_round = ground_truth_data()
    bad_round["reveal_round"] = bad_round["response_close_round"]
    with pytest.raises(ValidationError):
        GroundTruthPayload.model_validate(bad_round)

    extra = ground_truth_data()
    extra["items"][0]["prompt"] = "must remain private"
    with pytest.raises(ValidationError):
        GroundTruthPayload.model_validate(extra)


def test_canary_evidence_binds_scoring_references_and_retirement() -> None:
    data = ground_truth_data()
    item = data["items"][0]
    item.update(
        canary=True,
        references=["wrong text", "different text", "unrelated text"],
        normalized_script_sha256=H0,
        retirement_script_sha256s=[H0, H1],
        canary_evidence={
            "actual_references": ["hello world", "hello, world", "hi world"],
            "actual_script_sha256": H0,
            "reserved_script_sha256": H1,
            "mismatched_references": ["wrong text", "different text", "unrelated text"],
        },
    )
    assert GroundTruthPayload.model_validate(data).items[0].canary is True

    for field, value in (
        ("references", ["not the evidence", "different text", "unrelated text"]),
        ("retirement_script_sha256s", [H1, H0]),
        ("normalized_script_sha256", H2),
    ):
        malformed = ground_truth_data()
        malformed_item = malformed["items"][0]
        malformed_item.update(item)
        malformed_item[field] = value
        with pytest.raises(ValidationError):
            GroundTruthPayload.model_validate(malformed)
