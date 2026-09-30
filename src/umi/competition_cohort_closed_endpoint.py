"""Bind endpoint content metrics to the exact certified whole-cohort closure."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Literal

from pydantic import Field

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    EndpointReplayArchive,
    read_endpoint_object,
)
from .competition_cohort_endpoint_quality import (
    EndpointArchiveQuality,
    replay_endpoint_archive_quality,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_request_closure import (
    CohortRequestClosure,
    verify_certified_request_closure,
)
from .competition_cohort_request_terminal import SignedRequestTerminal
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_endpoint_execution import RetainedRevealPulse
from .open_competition import CompetitionPolicy, EvaluationSuite, digest, identity
from .protocol import Hex32, StrictProtocolModel


class ClosedEndpointQuality(StrictProtocolModel):
    schema_: Literal["umi-cohort-closed-endpoint-quality/1"] = Field(alias="schema")
    request_closure_sha256: Hex32
    quality: EndpointArchiveQuality
    service_credit_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


def replay_closed_endpoint_quality(
    archive: EndpointReplayArchive,
    closure: CohortRequestClosure,
    roster: RecoverableRosterEvidence,
    objects: EndpointObjectSource,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    history: CohortRecoveryHistory,
    *,
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    pulses: Callable[[int], RetainedRevealPulse],
    expected_tip_sha256: str,
    current_block: int,
) -> ClosedEndpointQuality:
    """Full coverage is required even when reading one miner's content metrics.

    Original service timing, aggregate/dependence gates and reward allocation
    remain separate. A content-quality report cannot authorize a weight row.
    """
    closure = verify_certified_request_closure(
        closure,
        roster,
        objects,
        policy,
        history,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    quality = replay_endpoint_archive_quality(
        archive,
        objects,
        suite,
        policy,
        history,
        pulses=pulses,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    member = next(
        (p for p in closure.participants if p.submission_sha256 == quality.submission_sha256),
        None,
    )
    ref = (
        next(
            (
                r
                for r in member.evaluators
                if identity(r.evaluator_hotkey) == identity(quality.evaluator_hotkey)
            ),
            None,
        )
        if member is not None
        else None
    )
    if ref is None:
        raise ValueError("endpoint quality has no certified participant/evaluator terminal")
    terminal = SignedRequestTerminal.model_validate_json(
        read_endpoint_object(objects, ref.terminal_sha256)
    )
    if terminal.terminal.endpoint_archive_sha256 != digest(archive):
        raise ValueError("endpoint quality archive was not selected by certified request closure")
    return ClosedEndpointQuality(
        schema="umi-cohort-closed-endpoint-quality/1",
        request_closure_sha256=digest(closure),
        quality=quality,
    )
