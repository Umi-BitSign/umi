"""Operational settlement byte envelopes derived from explicit replay limits.

These limits do not change signed policy, evidence, or reservation budgets.
Larger profiles use one proposal and one request at a time. Raw byte ceilings
are not an RSS guarantee; deployment still needs a measured memory budget.
"""

from dataclasses import dataclass

from .competition_publication import PublicationReplayLimits
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES, MAX_PRIVATE_BYTES


@dataclass(frozen=True, slots=True)
class SettlementCapacity:
    preparation_bytes: int
    page_size: int
    concurrent_requests: int

    @property
    def reply_bytes(self) -> int:
        return self.page_size * self.preparation_bytes + 8192


def settlement_capacity(limits: PublicationReplayLimits) -> SettlementCapacity:
    # Preserve existing profiles and journal bindings. Increasing explicit
    # replay limits requires a separately reviewed config/journal transition.
    if limits.maximum_evidence_bytes <= MAX_PRIVATE_BYTES:
        return SettlementCapacity(MAX_PRIVATE_BYTES, 4, 2)
    # Evidence includes submissions. Allow another roster, two certificates,
    # and an envelope; round up to 64 MiB so 256/4/4 MiB selects 320 MiB.
    needed = (
        limits.maximum_evidence_bytes
        + limits.maximum_roster_bytes
        + 2 * limits.maximum_certificate_bytes
        + 1024**2
    )
    size = ((needed + MAX_PRIVATE_BYTES - 1) // MAX_PRIVATE_BYTES) * MAX_PRIVATE_BYTES
    if size > MAX_CONFIGURED_PRIVATE_BYTES:
        raise ValueError("settlement replay limits exceed the maximum preparation profile")
    return SettlementCapacity(size, 1, 1)
