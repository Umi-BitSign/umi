"""Portable replay of terminal responses and every certified predecessor.

Objects are addressed by digest and individually bounded. Long retry histories
remain separate objects, rather than a recursively growing signed document.
Missing objects prevent completion; retrieval never creates absence evidence.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Literal

from pydantic import Field

from .competition_cohort_endpoint_decision import (
    EndpointCaseReview,
    SignedCohortEndpointCaseDecision,
    parse_case_review,
    verify_case_decision,
)
from .competition_cohort_endpoint_schedule import CohortEndpointSchedule
from .competition_cohort_endpoint_selection import (
    CohortEndpointReplacementSelection,
    selected_request,
    selection_grant,
    selection_slot,
)
from .competition_cohort_endpoint_terminal import EndpointTerminalSelection
from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_miner_case import verify_replacement_parent
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_round_journal import RoundJournal
from .open_competition import CompetitionPolicy, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_ARCHIVE_OBJECT_BYTES = 16 * 1024**2
EndpointObjectSource = Callable[[str], bytes]


class EndpointReplayArchive(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-replay-archive/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    terminal_sha256: Hex32
    request_closure_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


def read_endpoint_object(source: EndpointObjectSource, sha256: str) -> bytes:
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise ValueError("invalid endpoint archive identity")
    raw = source(sha256)
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ARCHIVE_OBJECT_BYTES:
        raise ValueError("endpoint archive object differs from its bounded identity")
    value = json.loads(raw)
    if canonical_json_bytes(value) != raw or digest(value) != sha256:
        raise ValueError("endpoint archive object differs from its bounded identity")
    return raw


class JournalEndpointObjects:
    """Owning-service adapter; use exported objects for independent replay."""

    def __init__(self, journal: RoundJournal):
        self.journal = journal

    def put(self, value: StrictProtocolModel) -> str:
        raw = canonical_json_bytes(value)
        if len(raw) > MAX_ARCHIVE_OBJECT_BYTES:
            raise ValueError("endpoint archive object exceeds its byte bound")
        sha = digest(value)
        self.journal.put("endpoint_replay_object", sha, value)
        return sha

    def __call__(self, sha256: str) -> bytes:
        value = self.journal.get("endpoint_replay_object", sha256)
        if value is None:
            raise FileNotFoundError("endpoint archive object is unavailable")
        return canonical_json_bytes(value)


def endpoint_archive_header(
    archive: EndpointReplayArchive, source: EndpointObjectSource, policy: CompetitionPolicy
) -> tuple[CohortExecutionAssignment, EndpointTerminalSelection, RecoverableExecutionJob]:
    archive = EndpointReplayArchive.model_validate_json(canonical_json_bytes(archive))
    assignment = CohortExecutionAssignment.model_validate_json(
        read_endpoint_object(source, archive.assignment_sha256)
    )
    terminal = EndpointTerminalSelection.model_validate_json(
        read_endpoint_object(source, archive.terminal_sha256)
    )
    order = assignment.certificate.order
    verify_recovery_quorum(order, assignment.certificate.signatures, policy)
    if any(
        identity(s.hotkey) == identity(order.submission.submission.hotkey)
        for s in assignment.certificate.signatures
    ):
        raise ValueError("miner cannot authorize its own endpoint archive")
    delivery = check_delivery_receipt(assignment.certificate, assignment.delivery)
    job = recoverable_order_job(order, delivery.receipt.evaluator_hotkey)
    if (
        job.mode != "endpoint_incumbent"
        or terminal.assignment_sha256 != digest(assignment)
        or terminal.job_sha256 != digest(job)
        or [c.case_id for c in terminal.cases] != [c.case_id for c in job.cases]
        or len({c.case_id for c in terminal.cases}) != len(terminal.cases)
    ):
        raise ValueError("endpoint archive must cover its exact complete assignment")
    return assignment, terminal, job


def endpoint_archive_cases(
    archive: EndpointReplayArchive,
    source: EndpointObjectSource,
    policy: CompetitionPolicy,
    *,
    request_interval: tuple[int, int] | None = None,
) -> Iterator[EndpointCaseReview]:
    """Verify all ancestry for each case. Consumers must exhaust the iterator.

    This checks signed content, not current authority or request closure. A
    caller must never publish a partial prefix as a completed assignment.
    """
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    assignment, terminal, _ = endpoint_archive_header(archive, source, policy)
    original_selection = None
    for ref in terminal.cases:
        review = parse_case_review(read_endpoint_object(source, ref.review_sha256))
        certificate = SignedCohortEndpointCaseDecision.model_validate_json(
            read_endpoint_object(source, ref.decision_sha256)
        )
        if (
            digest(review.selection) != ref.selection_sha256
            or selection_slot(review.selection) != ref.selection_slot
            or certificate.decision.disposition != "retain_response"
        ):
            raise ValueError("endpoint terminal reference differs from retained response")
        final = review
        while True:
            verify_case_decision(certificate, review, policy)
            if (
                review.assignment != assignment
                or review.retirement.case_id != ref.case_id
                or review.selection.transport_policy != final.selection.transport_policy
            ):
                raise ValueError("endpoint archive lineage changed its assignment or case")
            selected = review.selection
            if request_interval is not None:
                opened, closed = request_interval
                request = selected_request(selected, ref.case_id)
                if not (
                    opened < request.issued_block <= request.deadline_block <= closed
                    and request.issued_block <= review.retirement.observed_block <= closed
                ):
                    raise ValueError("endpoint attempt is outside certified request phases")
            if not isinstance(selected, CohortEndpointReplacementSelection):
                if selected.order.order.attempt_number != 1:
                    raise ValueError("endpoint archive lacks its first attempt")
                if original_selection is not None and digest(selected) != original_selection:
                    raise ValueError("endpoint archive selected conflicting original attempts")
                original_selection = digest(selected)
                break
            prior = selected.order.order.prior_decision
            parent = parse_case_review(read_endpoint_object(source, prior.decision.review_sha256))
            verify_replacement_parent(selected.grant, selection_grant(parent.selection, assignment))
            if selected.order.order.prior_retirement != parent.retirement.retirement:
                raise ValueError("endpoint archive changed its predecessor retirement")
            # Parent verification enforces a strictly decreasing attempt number.
            # There is no history-length timeout or recursively nested grant.
            review, certificate = parent, prior
        yield final


def export_endpoint_archive(schedule: CohortEndpointSchedule, slot: str) -> EndpointReplayArchive:
    """Checkpoint complete signed evidence before acknowledging replay readiness."""
    terminal = schedule.complete(slot)
    if terminal is None:
        raise ValueError("endpoint assignment still has pending cases")
    saved = schedule.load(slot)
    objects = JournalEndpointObjects(schedule.journal)
    for ref in terminal.cases:
        selected_slot = ref.selection_slot
        while True:
            review = schedule.attempts.decisions._review(selected_slot, ref.case_id)
            certificate = schedule.attempts.decisions.retained(selected_slot, ref.case_id)
            if review is None or certificate is None:
                raise FileNotFoundError("endpoint archive lacks a certified attempt")
            objects.put(review)
            objects.put(certificate)
            selected = review.selection
            if not isinstance(selected, CohortEndpointReplacementSelection):
                break
            parent_slot = selected.order.order.parent_grant_slot
            if schedule.journal.get("endpoint_recovery_selection", parent_slot) is None:
                parent_slot = selected.assignment_slot
            selected_slot = parent_slot
    archive = EndpointReplayArchive(
        schema="umi-cohort-endpoint-replay-archive/1",
        assignment_sha256=objects.put(saved.assignment),
        terminal_sha256=objects.put(terminal),
    )
    for _ in endpoint_archive_cases(archive, objects, schedule.owner.policy):
        pass
    # Content objects commit first. A lost final acknowledgement reuses them.
    schedule.journal.put("endpoint_replay_archive", slot, archive)
    return archive
