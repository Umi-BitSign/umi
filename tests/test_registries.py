from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import bittensor as bt
import bittensor_core
import pytest

from umi.artifacts import PublicBatchManifest
from umi.crypto import TimelockDecryptionError, parse_sealed_response
from umi.drand import DrandPulse
from umi.pool import PoolBatchEntry, batch_commitment
from umi.protocol import GroundTruthPayload, base64url_encode, canonical_json_bytes
from umi.registries import (
    ZERO_ROOT,
    PublisherFaultFinding,
    PublisherFaultReason,
    PublisherFaultState,
    PublisherRevealEvidence,
    PublisherRevealOutcome,
    SpentCohortBatch,
    SpentRegistryState,
    classify_publisher_reveal,
    publisher_fault_leaf,
    spent_batch_leaf,
    spent_frame_leaf,
    spent_script_leaf,
    spent_video_leaf,
)

from .test_artifacts import ground_truth_data, manifest_data
from .test_drand import ROUND, pulse_record
from .test_policy import make_policy


def _truth_data() -> dict:
    data = ground_truth_data()
    data["response_close_round"] = ROUND - 100
    data["reveal_round"] = ROUND
    return data


def _hash(byte: int) -> bytes:
    return bytes([byte]) * 32


def _batch(index: int, *, scripts: tuple[bytes, ...] | None = None) -> SpentCohortBatch:
    return SpentCohortBatch(
        batch_commitment=_hash(index),
        video_hashes=(_hash(index + 20),),
        frame_digests=(_hash(index + 40),),
        revealed_script_hashes=scripts if scripts is not None else (_hash(index + 60),),
    )


def _publisher_reveal_evidence(
    *,
    plaintext: bytes | None = None,
    ground_truth: dict | None = None,
    outcome: PublisherRevealOutcome = PublisherRevealOutcome.DECRYPTED,
    prior_spent_leaves: frozenset[bytes] = frozenset(),
) -> PublisherRevealEvidence:
    public_data = manifest_data()
    public_data["response_close_round"] = ROUND - 100
    public_data["reveal_round"] = ROUND

    truth_data = _truth_data() if ground_truth is None else ground_truth
    if plaintext is None:
        plaintext = canonical_json_bytes(truth_data)

    encrypted_data, encrypted_round = bittensor_core.encrypt_at_round(plaintext, ROUND)
    assert encrypted_round == ROUND
    portable = bytes(
        bt.timelock.Timelocked(
            ciphertext=encrypted_data,
            reveal_round=encrypted_round,
        )
    )
    ciphertext_sha256 = hashlib.sha256(portable).hexdigest()
    public_data["ciphertext_sha256"] = ciphertext_sha256
    manifest = PublicBatchManifest.model_validate(public_data)
    sealed = parse_sealed_response(
        base64url_encode(portable),
        reveal_round=ROUND,
        sha256_hex=ciphertext_sha256,
    )
    entry = PoolBatchEntry.model_validate(
        {
            "batch_id": manifest.batch_id,
            "batch_commitment": batch_commitment(manifest, portable, ROUND),
            "public_manifest_sha256": hashlib.sha256(canonical_json_bytes(manifest)).hexdigest(),
            "ciphertext_sha256": ciphertext_sha256,
            "reveal_round": ROUND,
        }
    )
    policy = make_policy()
    return PublisherRevealEvidence(
        control_group_id=policy.publisher_registry[0].control_group_id,
        pool_entry=entry,
        public_manifest=manifest,
        sealed_ground_truth=sealed,
        reveal_pulse=DrandPulse.from_json(pulse_record(), expected_round=ROUND),
        anchored_eligibility_evidence_sha256=_hash(250),
        outcome=outcome,
        decrypted_bytes=plaintext if outcome is PublisherRevealOutcome.DECRYPTED else None,
        decryption_error=(
            None
            if outcome is PublisherRevealOutcome.DECRYPTED
            else TimelockDecryptionError("verified timelock ciphertext could not be opened")
        ),
        prior_spent_leaves=prior_spent_leaves,
    )


def _manual_merkle(leaves: tuple[bytes, ...]) -> bytes:
    level = sorted(set(leaves))
    if not level:
        return hashlib.sha256(b"umi-spent-empty-v1\0").digest()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"umi-spent-node-v1\0" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0]


def test_spent_leaf_delta_merkle_and_state_root_reproduce_the_protocol() -> None:
    batch = SpentCohortBatch(
        batch_commitment=_hash(1),
        video_hashes=(_hash(21), _hash(22)),
        frame_digests=(_hash(41), _hash(42)),
        revealed_script_hashes=(_hash(61),),
    )
    next_state, transition = SpentRegistryState().apply(9_999, (batch,))

    manual_leaves = tuple(
        sorted(
            {
                hashlib.sha256(b"umi-spent-batch-v1\0" + _hash(1)).digest(),
                hashlib.sha256(b"umi-spent-video-v1\0" + _hash(21)).digest(),
                hashlib.sha256(b"umi-spent-video-v1\0" + _hash(22)).digest(),
                hashlib.sha256(b"umi-spent-frame-v1\0" + _hash(41)).digest(),
                hashlib.sha256(b"umi-spent-frame-v1\0" + _hash(42)).digest(),
                hashlib.sha256(b"umi-spent-script-v1\0" + _hash(61)).digest(),
            }
        )
    )
    delta_root = _manual_merkle(manual_leaves)
    resulting = hashlib.sha256(
        b"umi-spent-root-v1\0" + ZERO_ROOT + (9_999).to_bytes(8, "big") + delta_root
    ).digest()

    assert transition.delta_leaves == manual_leaves
    assert transition.delta_root == delta_root
    assert transition.resulting_root == resulting
    assert next_state.root == resulting
    assert next_state.leaves == frozenset(manual_leaves)
    assert not transition.has_eligibility_fault


def test_spent_transition_is_invariant_to_batch_and_item_permutation() -> None:
    first = SpentCohortBatch(
        batch_commitment=_hash(1),
        video_hashes=(_hash(21), _hash(22)),
        frame_digests=(_hash(41), _hash(42)),
        revealed_script_hashes=(_hash(61), _hash(62)),
    )
    first_reversed = SpentCohortBatch(
        batch_commitment=first.batch_commitment,
        video_hashes=tuple(reversed(first.video_hashes)),
        frame_digests=tuple(reversed(first.frame_digests)),
        revealed_script_hashes=tuple(reversed(first.revealed_script_hashes)),
    )
    second = _batch(2)

    state_a, transition_a = SpentRegistryState().apply(100, (first, second))
    state_b, transition_b = SpentRegistryState().apply(100, (second, first_reversed))
    assert state_a == state_b
    assert transition_a == transition_b


def test_spent_transition_reports_prior_collisions_and_cohort_duplicates() -> None:
    first_state, _ = SpentRegistryState().apply(100, (_batch(1),))
    reused_script = _hash(61)
    second_state, collision = first_state.apply(
        101,
        (_batch(2, scripts=(reused_script,)),),
    )
    assert spent_script_leaf(reused_script) in collision.prior_collisions
    assert collision.has_eligibility_fault
    assert second_state.last_reveal_round == 101

    duplicate_video = _hash(90)
    duplicate_frame = _hash(91)
    duplicate_a = SpentCohortBatch(
        batch_commitment=_hash(3),
        video_hashes=(duplicate_video,),
        frame_digests=(duplicate_frame,),
    )
    duplicate_b = SpentCohortBatch(
        batch_commitment=_hash(4),
        video_hashes=(duplicate_video,),
        frame_digests=(duplicate_frame,),
    )
    _, duplicate = SpentRegistryState().apply(102, (duplicate_a, duplicate_b))
    assert duplicate.duplicate_video_hashes == (duplicate_video,)
    assert duplicate.duplicate_frame_digests == (duplicate_frame,)
    assert duplicate.has_eligibility_fault


def test_spent_transition_rejects_nonmonotonic_rounds_and_duplicate_batches() -> None:
    state, _ = SpentRegistryState().apply(100, (_batch(1),))
    with pytest.raises(ValueError, match="reveal-round order"):
        state.apply(100, (_batch(2),))
    with pytest.raises(ValueError, match="duplicate batch commitment"):
        SpentRegistryState().apply(101, (_batch(1), _batch(1)))


def test_spent_registry_advances_an_empty_scheduled_reveal() -> None:
    state, transition = SpentRegistryState().apply(100, ())
    empty_delta = hashlib.sha256(b"umi-spent-empty-v1\0").digest()
    expected_root = hashlib.sha256(
        b"umi-spent-root-v1\0" + ZERO_ROOT + (100).to_bytes(8, "big") + empty_delta
    ).digest()

    assert transition.delta_leaves == ()
    assert transition.delta_root == empty_delta
    assert transition.resulting_root == expected_root
    assert not transition.has_eligibility_fault
    assert state.root == expected_root
    assert state.leaves == frozenset()
    assert state.last_reveal_round == 100


def test_publisher_fault_leaf_reproduces_the_protocol_hash_only() -> None:
    leaf = publisher_fault_leaf(_hash(1), _hash(2), _hash(3), _hash(4), 7)
    expected_leaf = hashlib.sha256(
        b"umi-publisher-fault-leaf-v1\0"
        + _hash(1)
        + _hash(2)
        + _hash(3)
        + _hash(4)
        + (7).to_bytes(2, "big")
    ).digest()
    assert leaf == expected_leaf


def test_publisher_reveal_classifier_accepts_valid_reveal_without_a_fault() -> None:
    evidence = _publisher_reveal_evidence()
    assert classify_publisher_reveal(evidence, policy=make_policy()) == ()


def test_publisher_reveal_classifier_emits_only_the_four_objective_reasons() -> None:
    failed = _publisher_reveal_evidence(outcome=PublisherRevealOutcome.TIMELOCK_DECRYPTION_FAILED)
    findings = classify_publisher_reveal(failed, policy=make_policy())
    assert tuple(finding.reason for finding in findings) == (
        PublisherFaultReason.TIMELOCK_DECRYPTION_FAILED,
    )

    malformed = _publisher_reveal_evidence(plaintext=b'{"schema":"not-umi-ground-truth"}')
    findings = classify_publisher_reveal(malformed, policy=make_policy())
    assert tuple(finding.reason for finding in findings) == (
        PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID,
    )

    truth = _truth_data()
    truth["window_id"] = "ab" * 32
    mismatch = _publisher_reveal_evidence(ground_truth=truth)
    findings = classify_publisher_reveal(mismatch, policy=make_policy())
    assert tuple(finding.reason for finding in findings) == (
        PublisherFaultReason.COMMITTED_BINDING_MISMATCH,
    )

    duplicate_truth = _truth_data()
    duplicate_script = bytes.fromhex(duplicate_truth["items"][0]["normalized_script_sha256"])
    duplicate = _publisher_reveal_evidence(
        ground_truth=duplicate_truth,
        prior_spent_leaves=frozenset({spent_script_leaf(duplicate_script)}),
    )
    findings = classify_publisher_reveal(duplicate, policy=make_policy())
    assert tuple(finding.reason for finding in findings) == (
        PublisherFaultReason.SPENT_SCRIPT_DUPLICATE,
    )


def test_publisher_reveal_classifier_rejects_noncanonical_plaintext() -> None:
    truth = GroundTruthPayload.model_validate(_truth_data())
    noncanonical = json.dumps(
        truth.model_dump(mode="json", by_alias=True),
        indent=2,
    ).encode()
    findings = classify_publisher_reveal(
        _publisher_reveal_evidence(plaintext=noncanonical),
        policy=make_policy(),
    )
    assert tuple(finding.reason for finding in findings) == (
        PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID,
    )


def test_local_retrieval_and_generic_failures_cannot_become_publisher_fault_evidence() -> None:
    failed = _publisher_reveal_evidence(outcome=PublisherRevealOutcome.TIMELOCK_DECRYPTION_FAILED)
    with pytest.raises(TypeError, match="TimelockDecryptionError"):
        replace(failed, decryption_error=OSError("local mirror failed"))
    with pytest.raises(TypeError, match="SealedResponse"):
        replace(failed, sealed_ground_truth=None)
    assert "canary_hit" not in {reason.value for reason in PublisherFaultReason}
    assert "consent_dispute" not in {reason.value for reason in PublisherFaultReason}

    valid = _publisher_reveal_evidence()
    wrong_group = replace(valid, control_group_id=_hash(249))
    with pytest.raises(ValueError, match="wrong control-group attribution"):
        classify_publisher_reveal(wrong_group, policy=make_policy())
    policy = make_policy()
    wrong_policy = policy.model_copy(update={"activation_block": policy.activation_block + 1})
    with pytest.raises(ValueError, match="different scoring policy"):
        classify_publisher_reveal(valid, policy=wrong_policy)


@pytest.mark.parametrize(
    "mutation",
    [
        "window",
        "batch",
        "policy",
        "schema",
        "response_close_round",
        "reveal_round",
        "item_set",
        "metric",
        "public_consent_hash",
    ],
)
def test_every_committed_ground_truth_binding_mismatch_is_classified(mutation: str) -> None:
    truth = _truth_data()
    if mutation == "window":
        truth["window_id"] = "ab" * 32
    elif mutation == "batch":
        truth["batch_id"] = base64url_encode(b"Z" * 16)
    elif mutation == "policy":
        truth["scoring_policy_hash"] = "ab" * 32
    elif mutation == "schema":
        # A different schema is not a valid umi-ground-truth/1 object, so this
        # belongs to the schema reason rather than the binding reason.
        truth["schema"] = "not-umi-ground-truth/1"
    elif mutation == "response_close_round":
        truth["response_close_round"] -= 1
    elif mutation == "reveal_round":
        truth["reveal_round"] += 1
    elif mutation == "item_set":
        truth["items"].pop()
    elif mutation == "metric":
        truth["items"][0]["metric"] = "wer"
    else:
        truth["items"][0]["consent_manifest_sha256"] = "ab" * 32

    evidence = _publisher_reveal_evidence(ground_truth=truth)
    findings = classify_publisher_reveal(evidence, policy=make_policy())
    expected = (
        PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID
        if mutation == "schema"
        else PublisherFaultReason.COMMITTED_BINDING_MISMATCH
    )
    assert tuple(finding.reason for finding in findings) == (expected,)


def test_empty_fault_transitions_cover_every_scheduled_window() -> None:
    first, first_transition = PublisherFaultState().advance_empty_window(0)
    expected_first = hashlib.sha256(
        b"umi-publisher-fault-root-v1\0"
        + ZERO_ROOT
        + (0).to_bytes(8, "big")
        + (0).to_bytes(4, "big")
    ).digest()
    assert first.root == expected_first
    assert first_transition.fault_leaves == ()
    assert first_transition.struck_groups == ()

    second, second_transition = first.advance_empty_window(1)
    expected_second = hashlib.sha256(
        b"umi-publisher-fault-root-v1\0"
        + expected_first
        + (1).to_bytes(8, "big")
        + (0).to_bytes(4, "big")
    ).digest()
    assert second.root == expected_second
    assert second_transition.previous_root == expected_first
    with pytest.raises(ValueError, match="every scheduled window"):
        second.advance_empty_window(3)
    with pytest.raises(ValueError, match="every scheduled window"):
        second.advance_empty_window(1)


def test_restored_fault_state_preserves_cooldown_and_version_exclusion_semantics() -> None:
    state = PublisherFaultState(
        strikes=((_hash(1), 1), (_hash(2), 2)),
        cooldown_ends=((_hash(1), 14),),
        last_window_index=10,
    )
    assert not state.is_eligible(_hash(1), 14)
    assert state.is_eligible(_hash(1), 15)
    assert not state.is_eligible(_hash(2), 1_000_000)


def test_fault_transition_keeps_all_leaves_but_adds_one_strike_per_group() -> None:
    group = _hash(1)
    findings = (
        PublisherFaultFinding(
            control_group_id=group,
            publisher_hotkey=_hash(2),
            window_id=_hash(3),
            batch_commitment=_hash(4),
            reason=PublisherFaultReason.COMMITTED_BINDING_MISMATCH,
            reason_code=3,
        ),
        PublisherFaultFinding(
            control_group_id=group,
            publisher_hotkey=_hash(2),
            window_id=_hash(3),
            batch_commitment=_hash(4),
            reason=PublisherFaultReason.SPENT_SCRIPT_DUPLICATE,
            reason_code=4,
        ),
    )
    state, transition = PublisherFaultState().advance_window(
        0,
        tuple(reversed(findings)),
        cooldown_windows=4,
    )
    leaves = tuple(sorted(finding.leaf for finding in findings))
    expected_root = hashlib.sha256(
        b"umi-publisher-fault-root-v1\0"
        + ZERO_ROOT
        + (0).to_bytes(8, "big")
        + len(leaves).to_bytes(4, "big")
        + b"".join(leaves)
    ).digest()
    assert transition.fault_leaves == leaves
    assert transition.struck_groups == (group,)
    assert transition.resulting_root == expected_root
    assert state.strikes == ((group, 1),)
    assert state.cooldown_ends == ((group, 4),)
    assert not state.is_eligible(group, 1)
    assert not state.is_eligible(group, 4)
    assert state.is_eligible(group, 5)


def test_second_strike_excludes_group_for_the_protocol_version() -> None:
    group = _hash(1)
    first_finding = PublisherFaultFinding(
        control_group_id=group,
        publisher_hotkey=_hash(2),
        window_id=_hash(3),
        batch_commitment=_hash(4),
        reason=PublisherFaultReason.TIMELOCK_DECRYPTION_FAILED,
        reason_code=1,
    )
    state, _ = PublisherFaultState().advance_window(
        0,
        (first_finding,),
        cooldown_windows=4,
    )
    for window_index in range(1, 5):
        state, _ = state.advance_empty_window(window_index)

    second_finding = PublisherFaultFinding(
        control_group_id=group,
        publisher_hotkey=_hash(2),
        window_id=_hash(5),
        batch_commitment=_hash(6),
        reason=PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID,
        reason_code=2,
    )
    state, _ = state.advance_window(5, (second_finding,), cooldown_windows=4)
    assert state.strikes == ((group, 2),)
    assert not state.is_eligible(group, 1_000_000)


def test_fault_transition_rejects_a_batch_from_a_group_still_in_cooldown() -> None:
    group = _hash(1)
    finding = PublisherFaultFinding(
        control_group_id=group,
        publisher_hotkey=_hash(2),
        window_id=_hash(3),
        batch_commitment=_hash(4),
        reason=PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID,
        reason_code=2,
    )
    state, _ = PublisherFaultState().advance_window(0, (finding,), cooldown_windows=4)
    later = PublisherFaultFinding(
        control_group_id=group,
        publisher_hotkey=_hash(2),
        window_id=_hash(5),
        batch_commitment=_hash(6),
        reason=PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID,
        reason_code=2,
    )
    with pytest.raises(ValueError, match="ineligible publisher group"):
        state.advance_window(1, (later,), cooldown_windows=4)


def test_spent_typed_leaves_are_domain_separated() -> None:
    value = _hash(9)
    assert (
        len(
            {
                spent_batch_leaf(value),
                spent_script_leaf(value),
                spent_video_leaf(value),
                spent_frame_leaf(value),
            }
        )
        == 4
    )
