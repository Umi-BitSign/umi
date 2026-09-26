"""Complete reference-free request closure for the certified accepted roster.

Every selected order and every assigned evaluator must supply its complete
signed terminal evidence. A missing peer or object keeps closure pending.
This module does not grant service credit or attest physical execution.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_endpoint_archive import EndpointObjectSource, read_endpoint_object
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_orders import SignedRecoverableEvaluationOrder, verify_recoverable_order
from .competition_cohort_request_progress import (
    certified_request_prefix,
)
from .competition_cohort_request_terminal import SignedRequestTerminal, read_request_terminal
from .competition_cohort_roster import (
    RecoverableRosterEvidence,
    verify_recoverable_roster_membership,
)
from .competition_execution import ExecutionBoundary
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class PendingRequestClosure(ValueError):
    def __init__(self, obligations: tuple[tuple[str, str], ...]):
        self.obligations = obligations
        super().__init__(f"request closure still has {len(obligations)} pending obligations")


class RequestEvaluatorTerminal(StrictProtocolModel):
    evaluator_hotkey: Hotkey
    terminal_sha256: Hex32


class RequestParticipantTerminal(StrictProtocolModel):
    submission_sha256: Hex32
    order_sha256: Hex32
    evaluators: Annotated[tuple[RequestEvaluatorTerminal, ...], Field(min_length=1, max_length=64)]


class CohortRequestClosure(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-closure/1"] = Field(alias="schema")
    roster_sha256: Hex32
    recovery_tip_sha256: Hex32
    observation: ExecutionBoundary
    participants: Annotated[
        tuple[RequestParticipantTerminal, ...], Field(min_length=1, max_length=512)
    ]
    chain_submission_authorized: Literal[False] = False


def review_request_closure(
    closure: CohortRequestClosure,
    roster: RecoverableRosterEvidence,
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    history: CohortRecoveryHistory,
    *,
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    expected_tip_sha256: str,
    current_block: int,
) -> CohortRequestClosure:
    """Review before reference release, or replay the identical original prefix.

    An independent owner must authenticate proof sources, the current tip and
    the closure observation. Service outage accounting is a separate required
    input to native phase progress; this manifest cannot shorten that window.
    """
    closure = CohortRequestClosure.model_validate_json(canonical_json_bytes(closure))
    members = verify_recoverable_roster_membership(
        roster,
        policy,
        history,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    if (
        view.state.phase != "requests"
        or closure.roster_sha256 != digest(roster)
        or closure.recovery_tip_sha256 != view.state.tip_sha256
        or not view.state.observed_at_block <= closure.observation.block <= current_block
    ):
        raise ValueError("request closure differs from its roster, open history or observation")
    keys = tuple(p.submission_sha256 for p in closure.participants)
    if keys != tuple(members):
        raise ValueError("request closure must cover the exact complete accepted roster")
    catalog = None
    for participant in closure.participants:
        retained = members[participant.submission_sha256]
        order = SignedRecoverableEvaluationOrder.model_validate_json(
            read_endpoint_object(objects, participant.order_sha256)
        )
        verify_recoverable_order(
            order,
            policy,
            retained.record.request.consent,
            retained.admission,
            retained.record.snapshot,
            history,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        if (
            order.order.round != roster.round
            or order.order.submission != retained.record.request.signed_submission
        ):
            raise ValueError("request closure substituted a selected order or submission")
        if catalog is not None and order.order.cases != catalog:
            raise ValueError("request closure has inconsistent assigned case catalogs")
        catalog = order.order.cases
        expected = tuple(identity(k) for k in order.order.evaluators)
        if tuple(identity(r.evaluator_hotkey) for r in participant.evaluators) != expected:
            raise ValueError("request closure must cover every assigned evaluator exactly once")
        for ref in participant.evaluators:
            signed = SignedRequestTerminal.model_validate_json(
                read_endpoint_object(objects, ref.terminal_sha256)
            )
            assignment = read_request_terminal(
                signed,
                objects,
                policy,
                opened_at_block=view.closure("preparation").observed_at_block,
                completed_by_block=closure.observation.block,
            )
            if (
                assignment.certificate != order
                or identity(assignment.delivery.receipt.evaluator_hotkey)
                != identity(ref.evaluator_hotkey)
                or assignment.participant.consent != retained.record.request.consent
                or assignment.participant.admission != retained.admission
                or assignment.participant.admission_snapshot != retained.record.snapshot
            ):
                raise ValueError("request terminal differs from the exact assigned participant")
    return closure


def build_request_closure(
    roster: RecoverableRosterEvidence,
    orders: Iterable[SignedRecoverableEvaluationOrder],
    terminal_source: Callable[
        [SignedRecoverableEvaluationOrder, str], SignedRequestTerminal | None
    ],
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    history: CohortRecoveryHistory,
    observation: ExecutionBoundary,
    *,
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    expected_tip_sha256: str,
    current_block: int,
) -> CohortRequestClosure:
    """Gather exact retained objects; absence is a durable obligation, never a zero.

    Sources own object publication. Their returned signed values must already
    be independently retrievable by digest before a complete result is returned.
    """
    selected = {}
    for order in orders:
        order = SignedRecoverableEvaluationOrder.model_validate_json(canonical_json_bytes(order))
        key = digest(order.order.submission.submission)
        if key in selected:
            raise ValueError("request closure repeats a selected order")
        selected[key] = order
    wanted = tuple(p.submission_sha256 for p in roster.round.participants)
    if selected.keys() - set(wanted):
        raise ValueError("request closure includes an unselected participant")
    pending, participants = [], []
    for key in wanted:
        order = selected.get(key)
        if order is None:
            pending.append((key, "order"))
            continue
        evaluators = []
        for evaluator in order.order.evaluators:
            terminal = terminal_source(order, evaluator)
            if terminal is None:
                pending.append((key, identity(evaluator)))
                continue
            evaluators.append(
                RequestEvaluatorTerminal(
                    evaluator_hotkey=evaluator,
                    terminal_sha256=digest(terminal),
                )
            )
        if len(evaluators) == len(order.order.evaluators):
            participants.append(
                RequestParticipantTerminal(
                    submission_sha256=key,
                    order_sha256=digest(order),
                    evaluators=tuple(evaluators),
                )
            )
    if pending:
        raise PendingRequestClosure(tuple(pending))
    closure = CohortRequestClosure(
        schema="umi-cohort-request-closure/1",
        roster_sha256=digest(roster),
        recovery_tip_sha256=expected_tip_sha256,
        observation=observation,
        participants=tuple(participants),
    )
    return review_request_closure(
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


def verify_certified_request_closure(
    closure: CohortRequestClosure,
    roster: RecoverableRosterEvidence,
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    history: CohortRecoveryHistory,
    *,
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    expected_tip_sha256: str,
    current_block: int,
) -> CohortRequestClosure:
    """Require the native phase decision to bind this exact complete manifest."""
    prefix = certified_request_prefix(
        closure,
        objects,
        policy,
        history,
        decision_source=decision_source,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    return review_request_closure(
        closure,
        roster,
        objects,
        policy,
        prefix,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=history_tip(prefix),
        current_block=closure.observation.block,
    )
