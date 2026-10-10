"""Reference-free request closure preserving the exact certified accepted roster.

Version 1 requires all original terminals. Version 3 explicitly partitions
complete participants from remaining work under the certified request-tail rule.
Missing or corrupt referenced evidence still blocks review. Neither version
grants service credit or attests physical execution.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_endpoint_archive import EndpointObjectSource, read_endpoint_object
from .competition_cohort_execution_journal import step_count
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_orders import (
    SignedRecoverableEvaluationOrder,
    recoverable_order_job,
    verify_recoverable_order,
)
from .competition_cohort_request_inventory import read_request_inventory, review_request_inventory
from .competition_cohort_request_partial import PartialRequestManifest
from .competition_cohort_request_progress import (
    certified_request_prefix,
)
from .competition_cohort_request_tail import RequestTailObservation, review_request_tail
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


class PendingRequestCertification(PendingRequestClosure):
    """Genuine completed work cannot be skipped while its certification is pending."""


class RequestEvaluatorTerminal(StrictProtocolModel):
    evaluator_hotkey: Hotkey
    terminal_sha256: Hex32


class RequestParticipantTerminal(StrictProtocolModel):
    submission_sha256: Hex32
    order_sha256: Hex32
    evaluators: Annotated[tuple[RequestEvaluatorTerminal, ...], Field(min_length=1, max_length=64)]


class SkippedRequestParticipant(StrictProtocolModel):
    submission_sha256: Hex32
    order_sha256: Hex32 | None
    evaluators: Annotated[tuple[RequestEvaluatorTerminal, ...], Field(max_length=64)]
    retained_objects: Annotated[tuple[Hex32, ...], Field(max_length=4096)] = ()
    inventory_sha256s: Annotated[tuple[Hex32, ...], Field(max_length=64)] = ()
    reason: Literal["unfinished_at_request_tail_cutoff"] = "unfinished_at_request_tail_cutoff"

    @model_validator(mode="after")
    def retained_inventory(self):
        for values in (self.retained_objects, self.inventory_sha256s):
            if values != tuple(sorted(set(values))):
                raise ValueError("skipped participant retained objects must be unique and ordered")
        if self.order_sha256 is None and (
            self.evaluators or self.retained_objects or self.inventory_sha256s
        ):
            raise ValueError("partial request evidence requires its original order")
        return self


class CohortRequestClosure(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-closure/1", "umi-cohort-request-closure/3"] = Field(
        alias="schema"
    )
    roster_sha256: Hex32
    recovery_tip_sha256: Hex32
    observation: ExecutionBoundary
    participants: Annotated[tuple[RequestParticipantTerminal, ...], Field(max_length=512)]
    tail: RequestTailObservation | None = None
    skipped: Annotated[tuple[SkippedRequestParticipant, ...], Field(max_length=512)] = ()
    chain_submission_authorized: Literal[False] = False

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.schema_ == "umi-cohort-request-closure/1":
            if self.tail is None:
                value.pop("tail", None)
            if not self.skipped:
                value.pop("skipped", None)
        return value

    @model_validator(mode="after")
    def selected_version(self):
        if self.schema_ == "umi-cohort-request-closure/1":
            if self.tail is not None or self.skipped or not self.participants:
                raise ValueError("legacy request closure requires complete original participants")
        elif self.tail is None:
            raise ValueError("request tail closure requires its explicit observation")
        return self


def unfinished_request_miners(closure: CohortRequestClosure, roster) -> tuple[str, ...]:
    """Count an incomplete original miner once, across every selected entry."""
    members = {
        digest(p.record.request.signed_submission.submission): identity(
            p.record.request.signed_submission.submission.hotkey
        )
        for p in roster.participants
    }
    try:
        return tuple(sorted({members[p.submission_sha256] for p in closure.skipped}))
    except KeyError:
        raise ValueError("request tail skipped an unselected participant") from None


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
    the closure observation. Service outage accounting remains a separate native
    input; only an explicit independently certified tail can close its window early.
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
    skipped = tuple(p.submission_sha256 for p in closure.skipped)
    if (
        keys != tuple(sorted(set(keys)))
        or skipped != tuple(sorted(set(skipped)))
        or set(keys) & set(skipped)
        or tuple(sorted((*keys, *skipped))) != tuple(members)
    ):
        raise ValueError("request closure must cover the exact complete accepted roster")
    if closure.tail is not None:
        review_request_tail(
            closure.tail,
            roster=roster,
            history=history,
            decision_source=decision_source,
            observation=closure.observation,
            required_unfinished_hotkeys=unfinished_request_miners(closure, roster),
        )
    catalog = None
    for participant in (*closure.participants, *closure.skipped):
        retained = members[participant.submission_sha256]
        incomplete = isinstance(participant, SkippedRequestParticipant)
        if incomplete and participant.order_sha256 is None:
            raise PendingRequestClosure(((participant.submission_sha256, "order_inventory"),))
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
        actual = tuple(identity(r.evaluator_hotkey) for r in participant.evaluators)
        if incomplete:
            if actual != tuple(who for who in expected if who in actual) or actual == expected:
                raise ValueError(
                    "skipped participant must preserve a strict original evaluator subset"
                )
        elif actual != expected:
            raise ValueError("request closure must cover every assigned evaluator exactly once")
        if incomplete:
            partial_evaluators = set()
            inventories = {}
            for inventory_key in participant.inventory_sha256s:
                assignment, manifest, signed = review_request_inventory(
                    inventory_key,
                    objects,
                    policy,
                    order,
                    opened_at_block=view.closure("preparation").observed_at_block,
                    selected_at_block=(
                        closure.tail.selected_observation or closure.tail.observation
                    ).block,
                    completed_by_block=closure.observation.block,
                )
                key = signed.inventory.manifest_sha256
                if key in inventories:
                    raise ValueError("partial request repeats an authenticated inventory")
                inventories[key] = assignment
            if set(inventories) != set(participant.retained_objects):
                raise PendingRequestClosure(
                    ((participant.submission_sha256, "authenticated_inventory"),)
                )
            for key in participant.retained_objects:
                assignment = inventories[key]
                who = identity(assignment.delivery.receipt.evaluator_hotkey)
                if (
                    who not in expected
                    or who in actual
                    or who in partial_evaluators
                    or assignment.participant.consent != retained.record.request.consent
                    or assignment.participant.admission != retained.admission
                    or assignment.participant.admission_snapshot != retained.record.snapshot
                ):
                    raise ValueError(
                        "partial request repeats an evaluator or changes its original participant"
                    )
                partial_evaluators.add(who)
                manifest = PartialRequestManifest.model_validate_json(
                    read_endpoint_object(objects, key)
                )
                certified_cases = {case.case_id for case in manifest.cases}
                pending_cases = tuple(
                    (
                        participant.submission_sha256,
                        f"case_certification:{who}:{response.case_id}",
                    )
                    for response in manifest.responses
                    if response.retirement_sha256 is not None
                    and response.case_id not in certified_cases
                )
                if pending_cases:
                    raise PendingRequestCertification(pending_cases)
                job = recoverable_order_job(
                    order.order, assignment.delivery.receipt.evaluator_hotkey
                )
                if len(manifest.steps) == step_count(job) and (
                    job.mode == "paired_model" or len(manifest.cases) == len(job.cases)
                ):
                    raise PendingRequestCertification(
                        ((participant.submission_sha256, f"terminal_certification:{who}"),)
                    )
            missing = set(expected) - set(actual) - partial_evaluators
            if missing:
                raise PendingRequestClosure(
                    tuple(
                        (participant.submission_sha256, f"partial_inventory:{who}")
                        for who in sorted(missing)
                    )
                )
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
    tail: RequestTailObservation | None = None,
    partial_source: Callable[[str], Iterable[str]] | None = None,
    inventory_source: Callable[..., Iterable[str]] | None = None,
) -> CohortRequestClosure:
    """Gather exact retained objects; an unfinished obligation is never a zero.

    Sources own object publication. Their returned signed values must already
    be independently retrievable by digest. Only an explicit tail observation
    permits a missing terminal; failed reads and corrupt evidence still raise.
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
    pending, participants, skipped = [], [], []

    def retain_skipped(key, order, evaluators=()):
        inventories = (
            tuple(
                sorted(
                    set(
                        inventory_source(
                            key,
                            selected_at_block=(tail.selected_observation or tail.observation).block,
                            completed_by_block=tail.observation.block,
                        )
                    )
                )
            )
            if inventory_source is not None
            else ()
        )
        retained = (
            tuple(
                sorted(
                    {
                        read_request_inventory(value, objects).inventory.manifest_sha256
                        for value in inventories
                    }
                )
            )
            if inventories
            else (tuple(sorted(set(partial_source(key)))) if partial_source is not None else ())
        )
        skipped.append(
            SkippedRequestParticipant(
                submission_sha256=key,
                order_sha256=None if order is None else digest(order),
                evaluators=tuple(evaluators),
                retained_objects=retained,
                inventory_sha256s=inventories,
            )
        )

    for key in wanted:
        order = selected.get(key)
        if order is None:
            pending.append((key, "order"))
            if tail is not None:
                retain_skipped(key, None)
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
        elif tail is not None:
            retain_skipped(key, order, evaluators)
    if pending and tail is None:
        raise PendingRequestClosure(tuple(pending))
    closure = CohortRequestClosure(
        schema="umi-cohort-request-closure/1" if tail is None else "umi-cohort-request-closure/3",
        roster_sha256=digest(roster),
        recovery_tip_sha256=expected_tip_sha256,
        observation=observation,
        participants=tuple(participants),
        tail=tail,
        skipped=tuple(skipped),
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
        tail=closure.tail,
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
