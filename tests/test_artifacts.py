from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from umi.artifacts import (
    PUBLIC_BATCH_MANIFEST_SCHEMA,
    PUBLISHER_CAPACITY_SCHEMA,
    PublicBatchManifest,
    PublisherCapacityStatement,
    public_batch_manifest_hash,
    publisher_capacity_digest,
    validate_public_batch_manifest,
    validate_publisher_capacity_statement,
    validate_revealed_batch_shape,
)
from umi.canary import wer_canary_stratum
from umi.encoding import account_id32
from umi.policy import activation_equivalence_digest, scoring_policy_hash
from umi.protocol import GroundTruthPayload, base64url_encode, canonical_json_bytes

from .test_policy import make_policy


def manifest_data() -> dict:
    policy = make_policy()
    window_id = "10" * 32
    batch_id = base64url_encode(b"B" * 16)
    publisher = policy.publisher_registry[0].publisher_hotkey
    items = []
    ordinary_strata = ["fingerspelling"] * 2 + ["short_utterance"] * 4 + ["continuous"] * 6
    all_strata = [
        *ordinary_strata,
        "fingerspelling",
        wer_canary_stratum(window_id, batch_id),
    ]
    for index, stratum in enumerate(all_strata):
        items.append(
            {
                "challenge_id": base64url_encode(bytes([index]) * 16),
                "metric": "cer" if stratum == "fingerspelling" else "wer",
                "stratum": stratum,
                "media": {
                    "sha256": f"{index + 1:064x}",
                    "frame_digest": f"{index + 101:064x}",
                    "size_bytes": 1_000_000,
                    "duration_ms": 5_000,
                    "width": 1280,
                    "height": 720,
                    "frame_rate_numerator": 30_000,
                    "frame_rate_denominator": 1_001,
                    "media_type": "video/mp4",
                    "container": "mp4",
                    "video_codec": "h264",
                    "audio_track_count": 0,
                    "metadata_stripped": True,
                },
                "signer_id_sha256": f"{1_000 + index // 2:064x}",
                "consent_manifest_sha256": f"{2_000 + index:064x}",
                "provenance_manifest_sha256": f"{3_000 + index:064x}",
            }
        )
    return {
        "schema": PUBLIC_BATCH_MANIFEST_SCHEMA,
        "protocol": "umi-asl/0.1",
        "window_id": window_id,
        "batch_id": batch_id,
        "publisher_hotkey": publisher,
        "scoring_policy_hash": scoring_policy_hash(policy),
        "tle_profile": "umi-tle/1",
        "response_close_round": 12_345_000,
        "reveal_round": 12_345_100,
        "ciphertext_sha256": "99" * 32,
        "items": items,
    }


def ground_truth_data() -> dict:
    manifest = manifest_data()
    items = []
    for index, public in enumerate(manifest["items"]):
        canary = index >= 12
        script_hash = f"{4_000 + index:064x}"
        if canary:
            reserved_hash = f"{5_000 + index:064x}"
            if public["metric"] == "cer":
                actual = ["aaaaaaaa", "aaaaaaaaa", "aaaaaaa"]
                mismatched = ["zzzzzzzz", "zzzzzzzzz", "zzzzzzz"]
            else:
                actual = ["hello world", "greetings earth", "good morning"]
                mismatched = ["purple chairs", "zebra quantum", "distant ocean"]
            evidence = {
                "actual_references": actual,
                "actual_script_sha256": script_hash,
                "reserved_script_sha256": reserved_hash,
                "mismatched_references": mismatched,
            }
            references = mismatched
            retirement = sorted([script_hash, reserved_hash])
        else:
            evidence = None
            references = ["hello world", "hello, world", "hi world"]
            retirement = [script_hash]
        items.append(
            {
                "challenge_id": public["challenge_id"],
                "metric": public["metric"],
                "canary": canary,
                "references": references,
                "canary_evidence": evidence,
                "normalized_script_sha256": script_hash,
                "retirement_script_sha256s": retirement,
                "consent_manifest_sha256": public["consent_manifest_sha256"],
            }
        )
    return {
        "schema": "umi-ground-truth/1",
        "window_id": manifest["window_id"],
        "batch_id": manifest["batch_id"],
        "scoring_policy_hash": manifest["scoring_policy_hash"],
        "tle_profile": manifest["tle_profile"],
        "response_close_round": manifest["response_close_round"],
        "reveal_round": manifest["reveal_round"],
        "items": items,
    }


def capacity_data() -> dict:
    policy = make_policy()
    group = policy.control_group_registry[0]
    publisher_hotkeys = sorted(
        (
            entry.publisher_hotkey
            for entry in policy.publisher_registry
            if entry.control_group_id == group.control_group_id
        ),
        key=account_id32,
    )
    # One publisher exists per launch group, so its canonical order is already fixed.
    scheduled_windows = 1_800
    return {
        "schema": PUBLISHER_CAPACITY_SCHEMA,
        "control_group_id": group.control_group_id,
        "administrator": group.administrator,
        "publisher_hotkeys": publisher_hotkeys,
        "scoring_policy_hash": scoring_policy_hash(policy),
        "activation_equivalence_digest": activation_equivalence_digest(policy),
        "issued_block": 900,
        "issued_block_hash": "0x" + "44" * 32,
        "valid_from_block": 1_000,
        "valid_through_block": 1_000 + scheduled_windows * 360,
        "cadence": {
            "window_stride_blocks": 360,
            "target_block_interval_seconds": 12,
            "scheduled_windows": scheduled_windows,
        },
        "per_window_capacity": {
            "candidate_batches": 1,
            "emission_bearing_clips": 12,
            "canary_clips": 2,
            "delivered_clips": 14,
            "maximum_retired_script_groups": 16,
        },
        "runway_totals": {
            "candidate_batches": scheduled_windows,
            "delivered_clips": 14 * scheduled_windows,
            "maximum_retired_script_groups": 16 * scheduled_windows,
        },
        "one_group_loss": {
            "minimum_remaining_groups": 2,
            "this_group_continues_at_declared_capacity": True,
        },
        "control_disclosure_sha256": "55" * 32,
    }


def test_public_manifest_validates_exact_launch_shape_and_policy_binding() -> None:
    policy = make_policy()
    manifest = PublicBatchManifest.model_validate(manifest_data())

    validate_public_batch_manifest(manifest, policy)
    assert len(manifest.items) == 14
    assert b'"canary"' not in canonical_json_bytes(manifest)
    assert len({item.signer_id_sha256 for item in manifest.items}) == 7
    assert (
        public_batch_manifest_hash(manifest)
        == hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    )


@pytest.mark.parametrize("fault", ["shape", "strata", "order", "signers", "video"])
def test_public_manifest_rejects_invalid_batch_invariants(fault: str) -> None:
    data = manifest_data()
    if fault == "shape":
        data["items"].pop()
    elif fault == "strata":
        data["items"][1]["stratum"] = "short_utterance"
        data["items"][1]["metric"] = "wer"
    elif fault == "order":
        data["items"][0], data["items"][1] = data["items"][1], data["items"][0]
    elif fault == "signers":
        data["items"][2]["signer_id_sha256"] = data["items"][0]["signer_id_sha256"]
    else:
        data["items"][1]["media"]["sha256"] = data["items"][0]["media"]["sha256"]

    with pytest.raises(ValidationError):
        PublicBatchManifest.model_validate(data)


def test_public_manifest_rejects_unknown_publisher_and_extra_fields() -> None:
    policy = make_policy()
    data = manifest_data()
    data["uncommitted_prompt"] = "not allowed"
    with pytest.raises(ValidationError):
        PublicBatchManifest.model_validate(data)

    leaked_canary_label = manifest_data()
    leaked_canary_label["items"][0]["canary"] = False
    with pytest.raises(ValidationError):
        PublicBatchManifest.model_validate(leaked_canary_label)

    data = manifest_data()
    data["publisher_hotkey"] = policy.control_group_registry[0].administrator
    manifest = PublicBatchManifest.model_validate(data)
    with pytest.raises(ValueError, match="not in the active policy"):
        validate_public_batch_manifest(manifest, policy)


def test_revealed_batch_binds_hidden_canary_shape_and_separation() -> None:
    policy = make_policy()
    manifest = PublicBatchManifest.model_validate(manifest_data())
    ground_truth = GroundTruthPayload.model_validate(ground_truth_data())

    validate_revealed_batch_shape(manifest, ground_truth, policy)

    wrong_canary = ground_truth_data()
    expected = wer_canary_stratum(manifest.window_id, manifest.batch_id)
    wrong_index = next(
        index
        for index, item in enumerate(manifest.items[:12])
        if item.metric == "wer" and item.stratum != expected
    )
    wrong_canary["items"][13]["canary"] = False
    wrong_canary["items"][13]["canary_evidence"] = None
    wrong_canary["items"][13]["references"] = ["hello world", "hello, world", "hi world"]
    wrong_canary["items"][13]["retirement_script_sha256s"] = [
        wrong_canary["items"][13]["normalized_script_sha256"]
    ]
    replacement = wrong_canary["items"][wrong_index]
    replacement["canary"] = True
    replacement["references"] = ["purple chairs", "zebra quantum", "distant ocean"]
    reserved = "88" * 32
    replacement["canary_evidence"] = {
        "actual_references": ["hello world", "greetings earth", "good morning"],
        "actual_script_sha256": replacement["normalized_script_sha256"],
        "reserved_script_sha256": reserved,
        "mismatched_references": replacement["references"],
    }
    replacement["retirement_script_sha256s"] = sorted(
        [replacement["normalized_script_sha256"], reserved]
    )
    malformed_reveal = GroundTruthPayload.model_validate(wrong_canary)
    with pytest.raises(ValueError, match=r"2/4/6|policy-derived"):
        validate_revealed_batch_shape(manifest, malformed_reveal, policy)


def test_capacity_statement_reproduces_digest_arithmetic_and_runway() -> None:
    policy = make_policy()
    statement = PublisherCapacityStatement.model_validate(capacity_data())

    validate_publisher_capacity_statement(statement, policy)
    assert statement.cadence.scheduled_windows == 1_800
    assert statement.runway_totals.delivered_clips == 25_200
    assert (
        publisher_capacity_digest(statement)
        == hashlib.sha256(b"umi-publisher-capacity-v1\0" + canonical_json_bytes(statement)).digest()
    )


def test_capacity_statement_rejects_bad_totals_policy_and_validity() -> None:
    bad_total = capacity_data()
    bad_total["runway_totals"]["delivered_clips"] -= 1
    with pytest.raises(ValidationError, match="runway totals"):
        PublisherCapacityStatement.model_validate(bad_total)

    policy = make_policy()
    bad_digest = capacity_data()
    bad_digest["activation_equivalence_digest"] = "66" * 32
    statement = PublisherCapacityStatement.model_validate(bad_digest)
    with pytest.raises(ValueError, match="equivalence"):
        validate_publisher_capacity_statement(statement, policy)

    short_validity = capacity_data()
    short_validity["valid_through_block"] -= 1
    statement = PublisherCapacityStatement.model_validate(short_validity)
    with pytest.raises(ValueError, match="complete runway"):
        validate_publisher_capacity_statement(statement, policy)


def test_capacity_statement_rejects_cadence_or_per_window_drift() -> None:
    policy = make_policy()
    cadence = capacity_data()
    cadence["cadence"]["window_stride_blocks"] = 720
    statement = PublisherCapacityStatement.model_validate(cadence)
    with pytest.raises(ValueError, match="cadence"):
        validate_publisher_capacity_statement(statement, policy)

    per_window = capacity_data()
    per_window["per_window_capacity"].update(
        canary_clips=3,
        delivered_clips=15,
        maximum_retired_script_groups=18,
    )
    per_window["runway_totals"].update(
        delivered_clips=27_000,
        maximum_retired_script_groups=32_400,
    )
    statement = PublisherCapacityStatement.model_validate(per_window)
    with pytest.raises(ValueError, match="per-window"):
        validate_publisher_capacity_statement(statement, policy)
