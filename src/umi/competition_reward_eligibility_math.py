"""Pre-consensus eligibility for the explicitly selected Subtensor epoch profile.

Arithmetic follows c004cebf360f4088187ee49d851dfb1a1eaaf710's stake inheritance,
activity and sparse-row masks. This module neither authenticates its inputs nor
proves that the reviewed revision is deployed. The native consumer must bind a
separately qualified runtime code hash and the complete state at one root.
"""

from __future__ import annotations

from dataclasses import dataclass

from .competition_chain import _uint

U64_MAX = 2**64 - 1
U128_MAX = 2**128 - 1
I128_MAX = 2**127 - 1
Q32 = 2**32
Q64 = 2**64


@dataclass(frozen=True)
class EpochEligibilityInputs:
    block: int
    validator_uid: int
    owner_uid: int | None
    last_updates: tuple[int, ...]
    registration_blocks: tuple[int, ...]
    permits: tuple[bool, ...]
    alpha: tuple[int, ...]
    tao: tuple[int, ...]
    # Each parent entry contains its proportion, direct alpha and direct root
    # stake. Inheritance uses direct parent balances, never recursive totals.
    parents: tuple[tuple[tuple[int, int, int], ...], ...]
    children: tuple[tuple[int, ...], ...]
    tao_weight: int
    stake_threshold: int
    tempo: int
    activity_factor_milli: int
    row: tuple[tuple[int, int], ...]


def _inherited(
    initial: int, parents: tuple[tuple[int, int], ...], children: tuple[int, ...]
) -> int:
    # Subtensor uses U96F32 proportions and saturates each sum/subtraction,
    # then truncates the resulting inherited balance to a saturated u64.
    outgoing = min(U128_MAX, sum(initial * ((p * Q32) // U64_MAX) for p in children))
    incoming = min(U128_MAX, sum(stake * ((p * Q32) // U64_MAX) for p, stake in parents))
    balance = min(U128_MAX, max(0, initial * Q32 - outgoing) + incoming)
    return min(U64_MAX, balance // Q32)


def epoch_eligibility(state: EpochEligibilityInputs) -> str:
    """Return a bounded eligibility reason, not a reward or signing decision.

    Every positive row entry must survive the pre-consensus masks. Consensus and
    actual emission distribution remain separate; an eligible row can earn nothing.
    Unsupported arithmetic ranges hold instead of assuming overflow semantics.
    """
    if type(state) is not EpochEligibilityInputs or type(state.alpha) is not tuple:
        raise ValueError("eligibility inputs have an invalid type")
    n = len(state.alpha)
    if not 1 <= n <= 256 or any(
        type(v) is not tuple or len(v) != n
        for v in (
            state.alpha,
            state.tao,
            state.last_updates,
            state.registration_blocks,
            state.permits,
            state.parents,
            state.children,
        )
    ):
        raise ValueError("eligibility vectors do not cover the complete registry")
    block = _uint(state.block, U64_MAX)
    uid = _uint(state.validator_uid, n - 1)
    owner = None if state.owner_uid is None else _uint(state.owner_uid, n - 1)
    weight = _uint(state.tao_weight, U64_MAX) * Q32 // U64_MAX
    threshold = _uint(state.stake_threshold, U64_MAX)
    cutoff = max(
        1, _uint(state.tempo, 65535) * _uint(state.activity_factor_milli, 2**32 - 1) // 1000
    )
    for entries in (state.alpha, state.tao):
        for value in entries:
            _uint(value, U64_MAX)
    for entries in (state.last_updates, state.registration_blocks):
        for value in entries:
            _uint(value, block)
    if any(type(value) is not bool for value in state.permits):
        raise ValueError("eligibility permits are malformed")
    for parents, children in zip(state.parents, state.children, strict=True):
        if type(parents) is not tuple or type(children) is not tuple:
            raise ValueError("eligibility inheritance is malformed")
        for parent in parents:
            if type(parent) is not tuple or len(parent) != 3:
                raise ValueError("eligibility parent is malformed")
            for value in parent:
                _uint(value, U64_MAX)
        for value in children:
            _uint(value, U64_MAX)
    if type(state.row) is not tuple or len(state.row) > n:
        raise ValueError("eligibility row is malformed")
    destinations = []
    for entry in state.row:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError("eligibility row entry is malformed")
        destinations.append(_uint(entry[0], n - 1))
        _uint(entry[1], 65535)
    if destinations != sorted(set(destinations)):
        raise ValueError("eligibility row has repeated or unordered destinations")

    filtered = []
    for i in range(n):
        parents, children = state.parents[i], state.children[i]
        alpha = _inherited(state.alpha[i], tuple((p, a) for p, a, _ in parents), children)
        tao = _inherited(state.tao[i], tuple((p, t) for p, _, t in parents), children)
        # Both inherited integers first enter signed I64F64 independently.
        alpha_fixed, tao_fixed = min(I128_MAX, alpha * Q64), min(I128_MAX, tao * Q64)
        total = min(I128_MAX, alpha_fixed + (tao_fixed * weight // Q32))
        filtered.append(total if i == owner or total // Q64 >= threshold else 0)
    summed = sum(filtered)
    if summed > I128_MAX:
        raise ValueError("eligibility stake sum exceeds the reviewed arithmetic range")
    # Normalize I64F64, then truncate to I32F32. Nested positive truncations
    # reduce to this integer quotient; a small nonzero stake may become zero.
    stake = 0 if not summed else filtered[uid] * Q32 // summed
    if min(U64_MAX, state.last_updates[uid] + cutoff) < block:
        return "inactive"
    if not state.permits[uid] and owner != uid:
        return "permit_missing"
    if filtered[uid] == 0:
        return "stake_unavailable"
    if stake == 0:
        return "stake_rounds_to_zero"
    positive = [dest for dest, amount in state.row if amount > 0]
    if not positive:
        return "no_positive_weights"
    if any(
        (dest == uid and owner != uid) or state.last_updates[uid] <= state.registration_blocks[dest]
        for dest in positive
    ):
        return "weight_masked"
    return "eligible"
