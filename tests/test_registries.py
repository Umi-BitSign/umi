from __future__ import annotations

import hashlib

import pytest

from umi.registries import (
    ZERO_ROOT,
    PublisherFaultState,
    SpentCohortBatch,
    SpentRegistryState,
    publisher_fault_leaf,
    spent_batch_leaf,
    spent_frame_leaf,
    spent_script_leaf,
    spent_video_leaf,
)


def _hash(byte: int) -> bytes:
    return bytes([byte]) * 32


def _batch(index: int, *, scripts: tuple[bytes, ...] | None = None) -> SpentCohortBatch:
    return SpentCohortBatch(
        batch_commitment=_hash(index),
        video_hashes=(_hash(index + 20),),
        frame_digests=(_hash(index + 40),),
        revealed_script_hashes=scripts if scripts is not None else (_hash(index + 60),),
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
