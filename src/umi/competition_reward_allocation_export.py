"""Deliver already validated compact allocations through an owner-selected sink."""

from collections.abc import Callable

from .competition_cohort_reward_allocation import CohortRewardAllocation
from .competition_transport_verification import TransferProgress
from .open_competition import digest


def export_reward_allocations(
    sink: Callable[[CohortRewardAllocation], None] | None,
    original: CohortRewardAllocation,
    effective: CohortRewardAllocation,
) -> None:
    """Reuse native results without creating reward authority or a new file format.

    The caller owns validation and its durable completion. An interrupted export
    retries the same immutable files through the existing atomic publication sink.
    """
    if sink is None:
        return
    allocations = (original,) if digest(original) == digest(effective) else (original, effective)
    with TransferProgress(
        "reward_allocation_export",
        len(allocations),
        unit="allocations",
        planning_unit_seconds=(0.001, 1),
    ) as progress:
        for allocation in allocations:
            sink(allocation)
            progress.advance(1)
