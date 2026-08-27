"""Deterministic spent-content and publisher-fault registry transitions."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .encoding import (
    account_id32,
    binary_merkle_root,
    raw_sha256,
    sha256_domain,
    u16be,
    u32be,
    u64be,
)

ZERO_ROOT = bytes(32)


def spent_batch_leaf(batch_commitment: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-batch-v1\0",
        raw_sha256(batch_commitment, field="batch commitment"),
    )


def spent_script_leaf(script_hash: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-script-v1\0",
        raw_sha256(script_hash, field="normalized script hash"),
    )


def spent_video_leaf(video_hash: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-video-v1\0",
        raw_sha256(video_hash, field="video hash"),
    )


def spent_frame_leaf(frame_digest: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-frame-v1\0",
        raw_sha256(frame_digest, field="frame digest"),
    )


@dataclass(frozen=True)
class SpentCohortBatch:
    batch_commitment: str | bytes
    video_hashes: tuple[str | bytes, ...]
    frame_digests: tuple[str | bytes, ...]
    revealed_script_hashes: tuple[str | bytes, ...] = ()

    def __post_init__(self) -> None:
        raw_sha256(self.batch_commitment, field="batch commitment")
        if not self.video_hashes or not self.frame_digests:
            raise ValueError("spent batch must carry public video and frame hashes")
        if len(self.video_hashes) != len(self.frame_digests):
            raise ValueError("spent batch video and frame hash counts disagree")
        for value in self.video_hashes:
            raw_sha256(value, field="video hash")
        for value in self.frame_digests:
            raw_sha256(value, field="frame digest")
        for value in self.revealed_script_hashes:
            raw_sha256(value, field="normalized script hash")


@dataclass(frozen=True)
class SpentTransition:
    reveal_round: int
    previous_root: bytes
    delta_leaves: tuple[bytes, ...]
    delta_root: bytes
    resulting_root: bytes
    prior_collisions: tuple[bytes, ...]
    duplicate_video_hashes: tuple[bytes, ...]
    duplicate_frame_digests: tuple[bytes, ...]

    @property
    def has_eligibility_fault(self) -> bool:
        return bool(
            self.prior_collisions or self.duplicate_video_hashes or self.duplicate_frame_digests
        )


@dataclass(frozen=True)
class SpentRegistryState:
    root: bytes = ZERO_ROOT
    leaves: frozenset[bytes] = frozenset()
    last_reveal_round: int = 0

    def __post_init__(self) -> None:
        raw_sha256(self.root, field="spent registry root")
        for leaf in self.leaves:
            raw_sha256(leaf, field="spent registry leaf")
        if self.last_reveal_round < 0:
            raise ValueError("last reveal round must not be negative")

    def apply(
        self,
        reveal_round: int,
        batches: tuple[SpentCohortBatch, ...],
    ) -> tuple[SpentRegistryState, SpentTransition]:
        if reveal_round <= self.last_reveal_round:
            raise ValueError("spent transitions must advance in reveal-round order")
        if not batches:
            raise ValueError("spent cohort must contain at least one batch")
        commitments = [
            raw_sha256(batch.batch_commitment, field="batch commitment") for batch in batches
        ]
        if len(set(commitments)) != len(commitments):
            raise ValueError("spent cohort contains a duplicate batch commitment")

        raw_videos = [
            raw_sha256(value, field="video hash")
            for batch in batches
            for value in batch.video_hashes
        ]
        raw_frames = [
            raw_sha256(value, field="frame digest")
            for batch in batches
            for value in batch.frame_digests
        ]
        duplicate_videos = tuple(
            sorted(value for value, count in Counter(raw_videos).items() if count > 1)
        )
        duplicate_frames = tuple(
            sorted(value for value, count in Counter(raw_frames).items() if count > 1)
        )
        cohort_leaves: set[bytes] = set()
        for batch in batches:
            cohort_leaves.add(spent_batch_leaf(batch.batch_commitment))
            cohort_leaves.update(spent_video_leaf(value) for value in batch.video_hashes)
            cohort_leaves.update(spent_frame_leaf(value) for value in batch.frame_digests)
            cohort_leaves.update(spent_script_leaf(value) for value in batch.revealed_script_hashes)

        collisions = tuple(sorted(cohort_leaves.intersection(self.leaves)))
        delta = tuple(sorted(cohort_leaves.difference(self.leaves)))
        delta_root = binary_merkle_root(
            delta,
            node_domain=b"umi-spent-node-v1\0",
            empty_domain=b"umi-spent-empty-v1\0",
        )
        resulting_root = sha256_domain(
            b"umi-spent-root-v1\0",
            self.root,
            u64be(reveal_round),
            delta_root,
        )
        next_state = SpentRegistryState(
            root=resulting_root,
            leaves=frozenset(self.leaves.union(cohort_leaves)),
            last_reveal_round=reveal_round,
        )
        transition = SpentTransition(
            reveal_round=reveal_round,
            previous_root=self.root,
            delta_leaves=delta,
            delta_root=delta_root,
            resulting_root=resulting_root,
            prior_collisions=collisions,
            duplicate_video_hashes=duplicate_videos,
            duplicate_frame_digests=duplicate_frames,
        )
        return next_state, transition


def publisher_fault_leaf(
    control_group_id: str | bytes,
    publisher_hotkey: str | bytes,
    window_id: str | bytes,
    batch_commitment: str | bytes,
    reason_code: int,
) -> bytes:
    """Reproduce the Section 8.6 leaf for already-classified evidence.

    This function only implements the binary hash formula. It does not establish
    that a batch was anchored-eligible or that the reason code follows from
    objective reveal evidence. No public API in the rehearsal package currently
    converts this primitive into a strike.
    """

    return sha256_domain(
        b"umi-publisher-fault-leaf-v1\0",
        raw_sha256(control_group_id, field="control group ID"),
        account_id32(publisher_hotkey),
        raw_sha256(window_id, field="window ID"),
        raw_sha256(batch_commitment, field="batch commitment"),
        u16be(reason_code),
    )


@dataclass(frozen=True)
class PublisherFaultTransition:
    window_index: int
    previous_root: bytes
    fault_leaves: tuple[bytes, ...]
    resulting_root: bytes
    struck_groups: tuple[bytes, ...]


@dataclass(frozen=True)
class PublisherFaultState:
    root: bytes = ZERO_ROOT
    strikes: tuple[tuple[bytes, int], ...] = ()
    cooldown_ends: tuple[tuple[bytes, int], ...] = ()
    last_window_index: int = -1

    def __post_init__(self) -> None:
        raw_sha256(self.root, field="publisher fault root")
        strike_groups = [group for group, _ in self.strikes]
        cooldown_groups = [group for group, _ in self.cooldown_ends]
        if strike_groups != sorted(strike_groups) or len(set(strike_groups)) != len(strike_groups):
            raise ValueError("publisher strikes must be unique and sorted by group")
        if cooldown_groups != sorted(cooldown_groups) or len(set(cooldown_groups)) != len(
            cooldown_groups
        ):
            raise ValueError("publisher cooldowns must be unique and sorted by group")
        for group, count in self.strikes:
            raw_sha256(group, field="control group ID")
            if count not in {1, 2}:
                raise ValueError("publisher strike count must be one or two")
        for group, end in self.cooldown_ends:
            raw_sha256(group, field="control group ID")
            if end < 0:
                raise ValueError("publisher cooldown end must not be negative")

    def is_eligible(self, control_group_id: str | bytes, window_index: int) -> bool:
        group = raw_sha256(control_group_id, field="control group ID")
        strikes = dict(self.strikes).get(group, 0)
        if strikes >= 2:
            return False
        return window_index > dict(self.cooldown_ends).get(group, -1)

    def advance_empty_window(
        self,
        window_index: int,
    ) -> tuple[PublisherFaultState, PublisherFaultTransition]:
        """Advance one scheduled window when no admissible fault was classified.

        The root advances for every scheduled window, including an empty one. A
        nonempty transition is intentionally unavailable until UMI has a
        finalized-chain-bound classifier for anchored-eligible reveal evidence.
        """

        if isinstance(window_index, bool) or not isinstance(window_index, int):
            raise TypeError("publisher fault window index must be an integer")
        if window_index != self.last_window_index + 1:
            raise ValueError("publisher fault transitions must cover every scheduled window")
        leaves: tuple[bytes, ...] = ()
        resulting_root = sha256_domain(
            b"umi-publisher-fault-root-v1\0",
            self.root,
            u64be(window_index),
            u32be(len(leaves)),
            b"".join(leaves),
        )
        next_state = PublisherFaultState(
            root=resulting_root,
            strikes=self.strikes,
            cooldown_ends=self.cooldown_ends,
            last_window_index=window_index,
        )
        transition = PublisherFaultTransition(
            window_index=window_index,
            previous_root=self.root,
            fault_leaves=leaves,
            resulting_root=resulting_root,
            struck_groups=(),
        )
        return next_state, transition


__all__ = [
    "PublisherFaultState",
    "PublisherFaultTransition",
    "SpentCohortBatch",
    "SpentRegistryState",
    "SpentTransition",
    "publisher_fault_leaf",
    "spent_batch_leaf",
    "spent_frame_leaf",
    "spent_script_leaf",
    "spent_video_leaf",
]
