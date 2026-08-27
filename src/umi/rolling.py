"""Global rolling batch state, exact miner utility, and deterministic weights."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from .encoding import account_id32, raw_sha256
from .protocol import base64url_decode
from .scoring import mean_score, utility_score, weighted_accuracy

Stratum = Literal["fingerspelling", "short_utterance", "continuous"]
STRATA: tuple[Stratum, ...] = ("fingerspelling", "short_utterance", "continuous")
U16_MAX = 65_535


def _score(value: Fraction) -> Fraction:
    if not isinstance(value, Fraction):
        raise TypeError("assignment score must use exact Fraction arithmetic")
    if not 0 <= value <= 1:
        raise ValueError("assignment score must be between zero and one")
    return value


@dataclass(frozen=True)
class AssignmentScore:
    miner_root: str | bytes
    challenge_id: str
    request_leaf: str | bytes
    stratum: Stratum
    canary: bool
    score: Fraction | None

    def __post_init__(self) -> None:
        account_id32(self.miner_root)
        if len(base64url_decode(self.challenge_id)) != 16:
            raise ValueError("assignment challenge ID must encode exactly 16 bytes")
        raw_sha256(self.request_leaf, field="request leaf")
        if self.stratum not in STRATA:
            raise ValueError("assignment has an unknown stratum")
        if not isinstance(self.canary, bool):
            raise TypeError("assignment canary flag must be boolean")
        if self.canary:
            if self.score is not None:
                raise ValueError("canary assignments must not carry a rolling score")
        elif self.score is None:
            raise ValueError("every non-canary assignment must carry a score, including zero")
        else:
            _score(self.score)

    @property
    def root(self) -> bytes:
        return account_id32(self.miner_root)

    @property
    def key(self) -> tuple[bytes, bytes]:
        return self.root, base64url_decode(self.challenge_id)

    @property
    def leaf(self) -> bytes:
        return raw_sha256(self.request_leaf, field="request leaf")


@dataclass(frozen=True)
class ScoredBatch:
    window_index: int
    batch_rank: str | bytes
    pool_leaf: str | bytes
    challenge_ids: tuple[str, ...]
    miner_roots: tuple[str | bytes, ...]
    assignments: tuple[AssignmentScore, ...]

    def __post_init__(self) -> None:
        if isinstance(self.window_index, bool) or self.window_index < 0:
            raise ValueError("batch window index must be a non-negative integer")
        raw_sha256(self.batch_rank, field="batch rank")
        raw_sha256(self.pool_leaf, field="pool leaf")
        challenge_bytes = tuple(base64url_decode(value) for value in self.challenge_ids)
        if not challenge_bytes or any(len(value) != 16 for value in challenge_bytes):
            raise ValueError("scored batch challenge IDs must encode exactly 16 bytes")
        if challenge_bytes != tuple(sorted(challenge_bytes)) or len(set(challenge_bytes)) != len(
            challenge_bytes
        ):
            raise ValueError("scored batch challenge IDs must be unique and sorted")
        miner_bytes = tuple(account_id32(value) for value in self.miner_roots)
        if not miner_bytes:
            raise ValueError("scored batch miner panel must not be empty")
        if miner_bytes != tuple(sorted(miner_bytes)) or len(set(miner_bytes)) != len(miner_bytes):
            raise ValueError("scored batch miner roots must be unique and sorted")
        expected_keys = {
            (miner_root, challenge_id)
            for miner_root in miner_bytes
            for challenge_id in challenge_bytes
        }
        assignment_keys = [assignment.key for assignment in self.assignments]
        if len(set(assignment_keys)) != len(assignment_keys):
            raise ValueError("scored batch contains a duplicate miner/challenge assignment")
        if set(assignment_keys) != expected_keys:
            raise ValueError("scored batch assignments are not the complete issued cross-product")
        request_leaves = [assignment.leaf for assignment in self.assignments]
        if len(set(request_leaves)) != len(request_leaves):
            raise ValueError("scored batch reuses a request leaf")
        if tuple(assignment_keys) != tuple(sorted(assignment_keys)):
            raise ValueError("scored batch assignments must be sorted by miner and challenge")

    @property
    def order_key(self) -> tuple[bytes, bytes]:
        return (
            raw_sha256(self.batch_rank, field="batch rank"),
            raw_sha256(self.pool_leaf, field="pool leaf"),
        )

    @property
    def identity(self) -> tuple[int, bytes]:
        return self.window_index, raw_sha256(self.pool_leaf, field="pool leaf")


@dataclass(frozen=True)
class MinerScore:
    miner_root: bytes
    assigned_clips: int
    stratum_counts: tuple[tuple[Stratum, int], ...]
    stratum_means: tuple[tuple[Stratum, Fraction], ...]
    accuracy: Fraction
    eligible: bool
    utility: Fraction


@dataclass(frozen=True)
class WeightBuild:
    root_vector: tuple[tuple[bytes, Fraction], ...]
    uid_vector: tuple[tuple[int, Fraction], ...]
    quantized_row: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class RollingScoreState:
    batches: tuple[ScoredBatch, ...] = ()

    def __post_init__(self) -> None:
        identities = [batch.identity for batch in self.batches]
        if len(set(identities)) != len(identities):
            raise ValueError("rolling queue contains a duplicate batch")
        window_indices = [batch.window_index for batch in self.batches]
        if window_indices != sorted(window_indices):
            raise ValueError("rolling queue batches must be ordered by window index")
        request_leaves = [
            assignment.leaf for batch in self.batches for assignment in batch.assignments
        ]
        if len(set(request_leaves)) != len(request_leaves):
            raise ValueError("rolling queue reuses a request leaf")
        by_window: dict[int, list[ScoredBatch]] = defaultdict(list)
        for batch in self.batches:
            by_window[batch.window_index].append(batch)
        for window_batches in by_window.values():
            if len(window_batches) != 2:
                raise ValueError("rolling queue must retain complete two-batch windows")
            if tuple(sorted(window_batches, key=lambda batch: batch.order_key)) != tuple(
                window_batches
            ):
                raise ValueError("rolling queue batches must preserve canonical window order")
            if window_batches[0].miner_roots != window_batches[1].miner_roots:
                raise ValueError("both batches in a window must use the same miner panel")

    def advance(
        self,
        current_window_index: int,
        *,
        new_batches: tuple[ScoredBatch, ...] = (),
        rolling_batch_count: int,
        score_max_age_windows: int,
    ) -> RollingScoreState:
        if current_window_index < 0:
            raise ValueError("current window index must not be negative")
        if self.batches and current_window_index < self.batches[-1].window_index:
            raise ValueError("rolling queue cannot move backward by window index")
        if rolling_batch_count <= 0 or score_max_age_windows <= 0:
            raise ValueError("rolling count and maximum age must be positive")
        if rolling_batch_count % 2:
            raise ValueError("rolling batch count must retain complete two-batch windows")
        if new_batches:
            if len(new_batches) != 2:
                raise ValueError("a valid scoring window requires one atomic two-batch update")
            if any(batch.window_index != current_window_index for batch in new_batches):
                raise ValueError("new batches must belong to the current window")
            if tuple(sorted(new_batches, key=lambda batch: batch.order_key)) != new_batches:
                raise ValueError("new batches must be ordered by batch rank and pool leaf")
            if new_batches[0].miner_roots != new_batches[1].miner_roots:
                raise ValueError("both batches in a window must use the same miner panel")
        retained = [
            batch
            for batch in self.batches
            if 0 <= current_window_index - batch.window_index < score_max_age_windows
        ]
        combined = retained + list(new_batches)
        identities = [batch.identity for batch in combined]
        if len(set(identities)) != len(identities):
            raise ValueError("rolling queue update contains a duplicate batch")
        return RollingScoreState(tuple(combined[-rolling_batch_count:]))

    def miner_scores(
        self,
        *,
        minimum_assigned_clips: int,
        minimum_clips_per_stratum: int,
        quality_floor: Fraction,
    ) -> tuple[MinerScore, ...]:
        if minimum_assigned_clips <= 0 or minimum_clips_per_stratum <= 0:
            raise ValueError("assignment eligibility thresholds must be positive")
        if not isinstance(quality_floor, Fraction) or not 0 <= quality_floor <= 1:
            raise ValueError("quality floor must be an exact fraction in the unit interval")
        grouped: dict[bytes, dict[Stratum, list[Fraction]]] = defaultdict(
            lambda: {stratum: [] for stratum in STRATA}
        )
        for batch in self.batches:
            for assignment in batch.assignments:
                if not assignment.canary:
                    assert assignment.score is not None
                    grouped[assignment.root][assignment.stratum].append(assignment.score)

        results: list[MinerScore] = []
        for root in sorted(grouped):
            by_stratum = grouped[root]
            counts = tuple((stratum, len(by_stratum[stratum])) for stratum in STRATA)
            means = tuple(
                (
                    stratum,
                    mean_score(tuple(by_stratum[stratum]))
                    if by_stratum[stratum]
                    else Fraction(0, 1),
                )
                for stratum in STRATA
            )
            assigned = sum(count for _, count in counts)
            eligible = assigned >= minimum_assigned_clips and all(
                count >= minimum_clips_per_stratum for _, count in counts
            )
            mean_by_stratum = dict(means)
            accuracy = weighted_accuracy(
                mean_by_stratum["fingerspelling"],
                mean_by_stratum["short_utterance"],
                mean_by_stratum["continuous"],
            )
            utility = utility_score(accuracy, quality_floor) if eligible else Fraction(0, 1)
            results.append(
                MinerScore(
                    miner_root=root,
                    assigned_clips=assigned,
                    stratum_counts=counts,
                    stratum_means=means,
                    accuracy=accuracy,
                    eligible=eligible,
                    utility=utility,
                )
            )
        return tuple(results)

    def build_weights(
        self,
        *,
        minimum_assigned_clips: int,
        minimum_clips_per_stratum: int,
        quality_floor: Fraction,
        uid_by_root: dict[bytes, int | None],
        minimum_positive_weights: int,
        maximum_weight_limit_u16: int = U16_MAX,
    ) -> WeightBuild:
        """Build a row only from scores recomputed from this verified rolling state."""

        return _build_weights_from_scores(
            self.miner_scores(
                minimum_assigned_clips=minimum_assigned_clips,
                minimum_clips_per_stratum=minimum_clips_per_stratum,
                quality_floor=quality_floor,
            ),
            uid_by_root=uid_by_root,
            minimum_positive_weights=minimum_positive_weights,
            maximum_weight_limit_u16=maximum_weight_limit_u16,
        )


def _build_weights_from_scores(
    miner_scores: tuple[MinerScore, ...],
    *,
    uid_by_root: dict[bytes, int | None],
    minimum_positive_weights: int,
    maximum_weight_limit_u16: int = U16_MAX,
) -> WeightBuild:
    if minimum_positive_weights <= 0:
        raise ValueError("minimum positive weight count must be positive")
    if (
        isinstance(maximum_weight_limit_u16, bool)
        or not isinstance(maximum_weight_limit_u16, int)
        or not 0 < maximum_weight_limit_u16 <= U16_MAX
    ):
        raise ValueError("maximum weight limit must be a positive u16 value")
    positive = [score for score in miner_scores if score.utility > 0]
    if len(positive) < minimum_positive_weights:
        raise ValueError("positive utilities are below MinAllowedWeights")
    utility_total = sum((score.utility for score in positive), Fraction(0, 1))
    root_vector = tuple(
        (score.miner_root, score.utility / utility_total)
        for score in sorted(positive, key=lambda item: item.miner_root)
    )

    resolved: list[tuple[int, Fraction]] = []
    seen_uids: set[int] = set()
    for root, normalized in root_vector:
        uid = uid_by_root.get(root)
        if uid is None:
            continue
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= U16_MAX:
            raise ValueError("resolved UID must fit u16")
        if uid in seen_uids:
            raise ValueError("different miner roots resolve to the same UID")
        seen_uids.add(uid)
        resolved.append((uid, normalized))
    if len(resolved) < minimum_positive_weights:
        raise ValueError("resolved positive destinations are below MinAllowedWeights")
    if len(resolved) * maximum_weight_limit_u16 < U16_MAX:
        raise ValueError("maximum weight limit is infeasible for the resolved destination count")
    resolved_total = sum((weight for _, weight in resolved), Fraction(0, 1))
    uid_vector = tuple(sorted((uid, weight / resolved_total) for uid, weight in resolved))
    uids = [uid for uid, _ in uid_vector]
    float_weights = [float(weight) for _, weight in uid_vector]
    from bittensor.intents.weights import clip_to_max_weight, normalize

    if maximum_weight_limit_u16 < U16_MAX:
        float_weights = clip_to_max_weight(
            float_weights,
            maximum_weight_limit_u16 / U16_MAX,
        )
        uid_vector = tuple(
            (uid, Fraction.from_float(weight))
            for uid, weight in zip(uids, float_weights, strict=True)
        )
    quantized_uids, quantized_values = normalize(uids, float_weights)
    quantized = tuple(zip(quantized_uids, quantized_values, strict=True))
    if len(quantized) < minimum_positive_weights:
        raise ValueError("quantization drops the row below MinAllowedWeights")
    quantized_total = sum(value for _, value in quantized)
    if quantized_total <= 0:
        raise ValueError("quantization produced a zero-weight row")
    if max(value for _, value in quantized) * U16_MAX > (
        maximum_weight_limit_u16 * quantized_total
    ):
        raise ValueError("quantized row exceeds the live maximum-weight ratio")
    return WeightBuild(
        root_vector=root_vector,
        uid_vector=uid_vector,
        quantized_row=quantized,
    )


__all__ = [
    "STRATA",
    "AssignmentScore",
    "MinerScore",
    "RollingScoreState",
    "ScoredBatch",
    "WeightBuild",
]
