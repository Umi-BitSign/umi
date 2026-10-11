"""Local aggregate evidence capacity, separate from signed policy and object limits.

The aggregate configuration ceiling is 4 GiB; each selected deployment budget
requires separate complete-path and resource qualification.
Hosts select one explicit budget across the request-to-reward path; changing
capacity never changes the selected policy, signed clocks or source identities.
"""

from typing import Annotated

from pydantic import Field

MAX_AGGREGATE_EVIDENCE_BYTES = 4 * 1024**3
LEGACY_AGGREGATE_REPLAY_BYTES = 256 * 1024**2
AggregateEvidenceCapacity = Annotated[int, Field(ge=1024, le=MAX_AGGREGATE_EVIDENCE_BYTES)]


def check_aggregate_evidence_bytes(maximum_bytes: int) -> int:
    if type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= MAX_AGGREGATE_EVIDENCE_BYTES:
        raise ValueError("cohort aggregate evidence capacity is outside runtime bounds")
    return maximum_bytes


def request_evidence_bytes(selected: int | None, legacy_export_bytes: int) -> int:
    """Preserve explicit old export limits until the operator selects an upgrade."""
    return check_aggregate_evidence_bytes(legacy_export_bytes if selected is None else selected)
