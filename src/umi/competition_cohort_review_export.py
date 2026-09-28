"""Configured identities and resource bounds for native phase review exports."""

from .competition_cohort_intake import CohortIntakeBinding
from .open_competition import CompetitionPolicy, identity
from .protocol import canonical_json_bytes

MAX_EXPORT_BYTES = 64 * 1024**2


def review_export_limits(maximum_bytes: int, timeout_seconds: int) -> None:
    if type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= 512 * 1024**2:
        raise ValueError("phase review export capacity is outside bounds")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 1200:
        raise ValueError("phase review timeout is outside bounds")


def review_selection(
    policy: CompetitionPolicy, cohorts: tuple[CohortIntakeBinding, ...], owner: str
) -> tuple[CompetitionPolicy, tuple[CohortIntakeBinding, ...], str]:
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    cohorts = tuple(
        CohortIntakeBinding.model_validate_json(canonical_json_bytes(c)) for c in cohorts
    )
    keys = tuple(c.cohort_sha256 for c in cohorts)
    if not 1 <= len(keys) <= 512 or keys != tuple(sorted(set(keys))):
        raise ValueError("phase reviewer needs unique ordered cohort bindings")
    owner = identity(owner)
    if owner not in {identity(e.hotkey) for e in policy.evaluators}:
        raise ValueError("phase reviewer owner is outside the configured evaluator set")
    return policy, cohorts, owner
