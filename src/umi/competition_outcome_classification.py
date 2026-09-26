"""Deterministic disposition of complete authenticated paired observations.

Callers must first verify exact case/evaluator coverage and retained execution.
No observation can be manufactured from a missing response or an elapsed clock.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .open_competition import CaseOutput, CompetitionPolicy

VoidReason = Literal[
    "infrastructure_failure",
    "incumbent_failure",
    "observation_disagreement",
    "coordinator_outcome_unavailable",
]


class ScorableObservations(ValueError):
    """Complete observations agree and must use ordinary scoring."""


@dataclass(frozen=True)
class PairedObservationOutputs:
    candidate: tuple[CaseOutput, ...]
    incumbent: tuple[CaseOutput, ...]
    coordinator_outcome_unavailable: bool = False


def _eligible(output: CaseOutput, policy: CompetitionPolicy) -> bool:
    return (
        output.status == "ok"
        and output.elapsed_ms <= policy.maximum_inference_ms
        and len(output.hypothesis.encode("utf-8")) <= policy.maximum_output_bytes
    )


def observation_void_reason(
    views: tuple[PairedObservationOutputs, ...], policy: CompetitionPolicy
) -> VoidReason:
    if any(v.coordinator_outcome_unavailable for v in views):
        return "coordinator_outcome_unavailable"
    if not views or any(not v.candidate or not v.incumbent for v in views):
        raise ValueError("void classification requires complete paired observations")
    if any(
        o.status == "infrastructure_failure"
        for v in views
        for role in ("candidate", "incumbent")
        for o in getattr(v, role)
    ):
        return "infrastructure_failure"
    if any(not _eligible(o, policy) for v in views for o in v.incumbent):
        return "incumbent_failure"
    for role in ("candidate", "incumbent"):
        for outputs in zip(*(getattr(v, role) for v in views), strict=True):
            if (
                len({(o.case_id, o.status, o.hypothesis, _eligible(o, policy)) for o in outputs})
                != 1
            ):
                return "observation_disagreement"
    raise ScorableObservations("complete agreeing scored observations cannot be voided")
