"""Portable original partial work, without a terminal, score or absence claim."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal, Protocol

from pydantic import Field, model_validator

from .competition_cohort_attempt_worker import EndpointAttemptSuccessor
from .competition_cohort_endpoint import (
    endpoint_obligation_sha256,
    validate_recoverable_endpoint_transport,
)
from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    read_endpoint_case,
    read_endpoint_object,
)
from .competition_cohort_endpoint_decision import (
    SignedCohortEndpointCaseDecision,
    parse_case_review,
    verify_case_decision,
)
from .competition_cohort_endpoint_retirement import CohortRetiredEndpointCase
from .competition_cohort_endpoint_selection import (
    CohortEndpointReplacementSelection,
    CohortRecoveredEndpointCase,
    case_record_key,
    parse_endpoint_selection,
    selected_request,
    selection_grant,
    selection_slot,
)
from .competition_cohort_endpoint_terminal import EndpointTerminalCase
from .competition_cohort_execution import _ordered
from .competition_cohort_execution_journal import (
    CohortExecutionAssignment,
    CohortExecutionJournal,
    step_count,
)
from .competition_cohort_miner_case import validate_case_attempt, verify_replacement_parent
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_order_signer import order_slot
from .competition_cohort_orders import SignedRecoverableEvaluationOrder, recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import ExecutionStep
from .competition_runner import validate_case_execution
from .config import Limits
from .endpoint_response_recovery import verify_recovered_response
from .endpoint_retirement import verify_retirement_receipt
from .open_competition import CompetitionPolicy, digest, identity
from .protocol import Hex32, StrictProtocolModel

MAX_PARTIAL_ITEMS = 8192


class _PartialObjectCollector(Protocol):
    def retain(self, value: StrictProtocolModel) -> str: ...


class PartialExecutionStep(StrictProtocolModel):
    index: Annotated[int, Field(ge=0, le=4095)]
    sha256: Hex32


class PartialEndpointResponse(StrictProtocolModel):
    case_id: Hex32
    selection_sha256: Hex32
    response_sha256: Hex32
    retirement_sha256: Hex32 | None = None


class PartialRequestManifest(StrictProtocolModel):
    schema_: Literal["umi-cohort-partial-request/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    steps: Annotated[tuple[PartialExecutionStep, ...], Field(max_length=4096)]
    cases: Annotated[tuple[EndpointTerminalCase, ...], Field(max_length=2048)]
    responses: Annotated[tuple[PartialEndpointResponse, ...], Field(max_length=2048)]
    request_completion_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @property
    def item_count(self):
        return (
            len(self.steps)
            + len(self.cases)
            + len(self.responses)
            + sum(r.retirement_sha256 is not None for r in self.responses)
        )

    @model_validator(mode="after")
    def ordered_inventory(self):
        for keys in (
            tuple(s.index for s in self.steps),
            tuple(c.case_id for c in self.cases),
            tuple(r.case_id for r in self.responses),
        ):
            if keys != tuple(sorted(set(keys))):
                raise ValueError("partial request inventory repeats or reorders original work")
        if self.item_count > MAX_PARTIAL_ITEMS:
            raise ValueError("partial request inventory exceeds its bound")
        return self


def _review_selection(selected, assignment, objects, policy, case_id, opened, closed):
    """Authenticate the original grant and every certified replacement parent."""
    job = recoverable_order_job(
        assignment.certificate.order, assignment.delivery.receipt.evaluator_hotkey
    )
    original_transport = selected.transport_policy
    while True:
        if (
            selected.assignment_slot != order_slot(assignment.certificate.order)
            or selected.order.order.job != job
            or selected.transport_policy != original_transport
        ):
            raise ValueError("partial response selection changed its original assignment")
        request = selected_request(selected, case_id)
        if not opened < request.issued_block <= closed:
            raise ValueError("partial response ancestry is outside certified request phases")
        selection_grant(selected, assignment)
        if not isinstance(selected, CohortEndpointReplacementSelection):
            validate_recoverable_endpoint_transport(selected.order, policy, original_transport)
            if selected.order.order.attempt_number != 1:
                raise ValueError("partial response lacks its original attempt")
            return digest(selected)
        validate_case_attempt(selected.order, policy, original_transport)
        prior = selected.order.order.prior_decision
        parent = parse_case_review(read_endpoint_object(objects, prior.decision.review_sha256))
        verify_case_decision(prior, parent, policy)
        if (
            parent.assignment != assignment
            or selected.order.order.prior_retirement != parent.retirement.retirement
            or parent.retirement.case_id != case_id
            or not opened < parent.retirement.observed_block <= closed
        ):
            raise ValueError("partial response changed its predecessor evidence")
        verify_replacement_parent(selected.grant, selection_grant(parent.selection, assignment))
        selected = parent.selection


def review_partial_request(
    refsha: str,
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    expected_order: SignedRecoverableEvaluationOrder,
    *,
    opened_at_block: int,
    completed_by_block: int,
) -> CohortExecutionAssignment:
    """Replay partial originals; never infer completion, eligibility or absence."""
    manifest = PartialRequestManifest.model_validate_json(read_endpoint_object(objects, refsha))
    assignment = CohortExecutionAssignment.model_validate_json(
        read_endpoint_object(objects, manifest.assignment_sha256)
    )
    if assignment.certificate != expected_order:
        raise ValueError("partial request changed its exact original order")
    order = assignment.certificate.order
    verify_recovery_quorum(order, assignment.certificate.signatures, policy)
    if any(
        identity(s.hotkey) == identity(order.submission.submission.hotkey)
        for s in assignment.certificate.signatures
    ):
        raise ValueError("miner cannot authorize its own partial request")
    check_delivery_receipt(assignment.certificate, assignment.delivery)
    evaluator = assignment.delivery.receipt.evaluator_hotkey
    job = recoverable_order_job(order, evaluator)
    width = 2 if job.mode == "paired_model" else 1
    previous = None
    for ref in manifest.steps:
        if ref.index >= step_count(job):
            raise ValueError("partial execution step is outside its original assignment")
        step = ExecutionStep.model_validate_json(read_endpoint_object(objects, ref.sha256))
        case = job.cases[ref.index // width]
        role = "candidate" if width == 2 and ref.index % 2 == 0 else "incumbent"
        model = (
            job.submission.submission.model_revision
            if role == "candidate"
            else digest(job.incumbent)
        )
        if (
            step.role != role
            or step.execution.output.case_id != case.case_id
            or step.execution.video_sha256 != case.video_sha256
            or step.execution.model_sha256 != model
            or step.execution.runtime_sha256 != digest(job.runtime)
        ):
            raise ValueError("partial execution changed its original step, model or input")
        validate_case_execution(step.execution, policy)
        for boundary in (step.started, step.finished):
            _ordered(
                boundary, previous, started_after=opened_at_block, finished_by=completed_by_block
            )
            previous = boundary
    assigned_cases = {case.case_id for case in job.cases}
    if (manifest.cases or manifest.responses) and job.mode != "endpoint_incumbent":
        raise ValueError("partial model work contains unassigned endpoint responses")
    original = None
    for ref in manifest.cases:
        if ref.case_id not in assigned_cases:
            raise ValueError("partial endpoint case is outside its original assignment")
        _, selected = read_endpoint_case(
            assignment,
            ref,
            objects,
            policy,
            request_interval=(opened_at_block, completed_by_block),
        )
        if original is not None and original != selected:
            raise ValueError("partial endpoint cases selected conflicting original attempts")
        original = selected
    for ref in manifest.responses:
        if ref.case_id not in assigned_cases:
            raise ValueError("partial response is outside its original assignment")
        selected = parse_endpoint_selection(read_endpoint_object(objects, ref.selection_sha256))
        first = _review_selection(
            selected,
            assignment,
            objects,
            policy,
            ref.case_id,
            opened_at_block,
            completed_by_block,
        )
        if original is not None and original != first:
            raise ValueError("partial responses selected conflicting original attempts")
        original = first
        response = CohortRecoveredEndpointCase.model_validate_json(
            read_endpoint_object(objects, ref.response_sha256)
        )
        request = selected_request(selected, ref.case_id)
        if (
            response.case_id != ref.case_id
            or response.selection_sha256 != ref.selection_sha256
            or not opened_at_block < request.issued_block <= completed_by_block
        ):
            raise ValueError("partial response changed its selected request or interval")
        verify_recovered_response(
            response.response,
            request=request,
            validator_hotkey=job.evaluator_hotkey,
            miner_hotkey=job.submission.submission.hotkey,
            limits=Limits.from_policy(selected.transport_policy),
        )
        if ref.retirement_sha256 is not None:
            retired = CohortRetiredEndpointCase.model_validate_json(
                read_endpoint_object(objects, ref.retirement_sha256)
            )
            receipt = verify_retirement_receipt(
                retired.retirement,
                request=request,
                grant_sha256=digest(selection_grant(selected, assignment)),
                miner_hotkey=job.submission.submission.hotkey,
                evaluator_hotkey=job.evaluator_hotkey,
            ).receipt
            if (
                retired.selection_sha256 != ref.selection_sha256
                or retired.case_id != ref.case_id
                or receipt.result != "response_retained"
                or receipt.response_sha256
                != hashlib.sha256(bytes.fromhex(response.response.envelope_hex)).hexdigest()
                or not request.issued_block <= retired.observed_block <= completed_by_block
            ):
                raise ValueError("partial response retirement differs from its retained original")
    return assignment


def collect_partial_request(
    owner: CohortExecutionJournal, slot: str, collected: _PartialObjectCollector
) -> PartialRequestManifest:
    """Owning-service reads of immutable originals; no journal writes or RPC."""
    assignment, job = owner.assignment_and_job(slot)
    evidence = owner.evidence(slot)
    if evidence is not None:
        steps = list(enumerate(evidence.steps))
    else:
        with owner.journal.read_transaction() as db:
            steps = [
                (index, step)
                for index in range(step_count(job))
                if (step := owner.step(job, index, db=db)) is not None
            ]

    def retained_review(selected, case_id):
        key = digest(["umi-cohort-endpoint-case-review-record/1", digest(selected), case_id])
        raw = owner.journal.get_raw("endpoint_case_review", key)
        if raw is None:
            raise FileNotFoundError("partial endpoint case is missing original review")
        review = parse_case_review(raw)
        collected.retain(review)
        return key, review

    def parents(selected, case_id):
        seen = set()
        while isinstance(selected, CohortEndpointReplacementSelection):
            parent_slot = selected.order.order.parent_grant_slot
            if parent_slot in seen:
                raise ValueError("partial endpoint ancestry is cyclic")
            seen.add(parent_slot)
            raw = owner.journal.get_raw("endpoint_recovery_selection", parent_slot)
            if raw is None:
                raw = owner.journal.get_raw("endpoint_recovery_selection", slot)
            if raw is None:
                raise FileNotFoundError("partial endpoint predecessor is unavailable")
            parent = parse_endpoint_selection(raw)
            _, review = retained_review(parent, case_id)
            if digest(review) != selected.order.order.prior_decision.decision.review_sha256:
                raise ValueError("partial endpoint predecessor changed its original review")
            collected.retain(selected.order.order.prior_decision)
            selected = parent

    cases, responses = [], []
    if job.mode == "endpoint_incumbent":
        for case in job.cases:
            raw = owner.journal.get(
                "endpoint_terminal_case", endpoint_obligation_sha256(job, case.case_id)
            )
            if raw is not None:
                ref = EndpointTerminalCase.model_validate(raw)
                if ref.case_id != case.case_id:
                    raise ValueError("partial terminal case changed its original obligation")
                key = digest(
                    ["umi-cohort-endpoint-case-review-record/1", ref.selection_sha256, ref.case_id]
                )
                review_raw = owner.journal.get_raw("endpoint_case_review", key)
                certificate_raw = owner.journal.get_raw("endpoint_case_decision", key)
                if review_raw is None or certificate_raw is None:
                    raise FileNotFoundError("partial terminal case lacks original signed evidence")
                review = parse_case_review(review_raw)
                certificate = SignedCohortEndpointCaseDecision.model_validate_json(certificate_raw)
                if (
                    collected.retain(review) != ref.review_sha256
                    or collected.retain(certificate) != ref.decision_sha256
                ):
                    raise ValueError("partial terminal case changed its original objects")
                parents(review.selection, case.case_id)
                cases.append(ref)
            selected_slot, seen = slot, set()
            while True:
                if selected_slot in seen:
                    raise ValueError("partial endpoint successor is cyclic")
                seen.add(selected_slot)
                raw = owner.journal.get_raw("endpoint_recovery_selection", selected_slot)
                if raw is None:
                    if selected_slot != slot:
                        raise FileNotFoundError("partial endpoint successor is unavailable")
                    break
                selected = parse_endpoint_selection(raw)
                if selection_slot(selected) != selected_slot:
                    raise ValueError("partial endpoint selection changed its slot")
                record_key = case_record_key(selected, case.case_id)
                next_raw = owner.journal.get("endpoint_attempt_successor", record_key)
                if next_raw is not None:
                    next_ = EndpointAttemptSuccessor.model_validate(next_raw)
                    if (
                        next_.previous_selection_sha256 != digest(selected)
                        or next_.case_id != case.case_id
                    ):
                        raise ValueError("partial endpoint successor changed its original parent")
                    selected_slot = next_.selection_slot
                    continue
                value = owner.journal.get("endpoint_recovered_case", record_key)
                if value is not None:
                    response = CohortRecoveredEndpointCase.model_validate(value)
                    retired = owner.journal.get("endpoint_retired_case", record_key)
                    parents(selected, case.case_id)
                    responses.append(
                        PartialEndpointResponse(
                            case_id=case.case_id,
                            selection_sha256=collected.retain(selected),
                            response_sha256=collected.retain(response),
                            retirement_sha256=None
                            if retired is None
                            else collected.retain(
                                CohortRetiredEndpointCase.model_validate(retired)
                            ),
                        )
                    )
                break
    collected.retain(assignment.certificate)
    return PartialRequestManifest(
        schema="umi-cohort-partial-request/1",
        assignment_sha256=collected.retain(assignment),
        steps=tuple(
            PartialExecutionStep(index=index, sha256=collected.retain(step))
            for index, step in steps
        ),
        cases=tuple(sorted(cases, key=lambda value: value.case_id)),
        responses=tuple(sorted(responses, key=lambda value: value.case_id)),
    )
