"""Retain one fenced signed response for each original service-work identity.

No quality or receipt latency is inferred here. Missing responses stay pending.
Quorum request closure authenticates these records before reference reveal.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import Field

from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    JournalEndpointObjects,
    read_endpoint_object,
)
from .competition_cohort_order_signer import CohortOrderHistory, remember_order_history
from .competition_cohort_service_grant import (
    ServiceMinerGrant,
    review_service_request_current,
    service_grant_slot,
    service_obligation,
    verify_service_grant,
    verify_service_parent,
)
from .competition_cohort_service_requests import ServiceWorkRequests
from .competition_cohort_service_work import ServiceWorkAssignment, review_service_assignment
from .competition_execution import ExecutionBoundary
from .config import Limits
from .endpoint_response_recovery import RecoveredEndpointResponse, verify_recovered_response
from .endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ServiceTerminal(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-terminal/1"] = Field(alias="schema")
    work_sha256: Hex32
    grant_sha256: Hex32
    response_sha256: Hex32
    retirement_sha256: Hex32
    source_sha256: Hex32
    observation: ExecutionBoundary
    chain_submission_authorized: Literal[False] = False


class SignedServiceTerminal(StrictProtocolModel):
    terminal: ServiceTerminal
    signature: Signature


def review_service_terminal(
    terminal: ServiceTerminal,
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    transport: ScoringPolicy,
    *,
    request_interval: tuple[int, int] | None = None,
) -> ServiceMinerGrant:
    """Replay exact selected response, signed retirement and every retry parent.

    Source finality and the admission owner are authenticated by independent
    closure reviewers. Retrieval time is never used as original execution time.
    """
    terminal = ServiceTerminal.model_validate_json(canonical_json_bytes(terminal))
    grant = verify_service_grant(
        ServiceMinerGrant.model_validate_json(read_endpoint_object(objects, terminal.grant_sha256)),
        policy,
        transport,
    )
    body = grant.body
    if terminal.work_sha256 != body.assignment.admission.work_sha256:
        raise ValueError("service terminal substituted its original work")
    source = CohortOrderHistory.model_validate_json(
        read_endpoint_object(objects, terminal.source_sha256)
    )
    review_service_request_current(body, policy, source, terminal.observation.block)
    retired = verify_retirement_receipt(
        SignedEndpointRetirementReceipt.model_validate_json(
            read_endpoint_object(objects, terminal.retirement_sha256)
        ),
        request=body.request,
        grant_sha256=digest(grant),
        miner_hotkey=body.assignment.admission.submission.submission.hotkey,
        evaluator_hotkey=body.evaluator_hotkey,
    )
    response = verify_recovered_response(
        RecoveredEndpointResponse.model_validate_json(
            read_endpoint_object(objects, terminal.response_sha256)
        ),
        request=body.request,
        validator_hotkey=body.evaluator_hotkey,
        miner_hotkey=body.assignment.admission.submission.submission.hotkey,
        limits=Limits.from_policy(transport),
    )
    if (
        retired.receipt.response_sha256
        != hashlib.sha256(bytes.fromhex(response.envelope_hex)).hexdigest()
    ):
        raise ValueError("service terminal response differs from signed retirement")
    current = grant
    while True:
        if request_interval is not None:
            opened, closed = request_interval
            req = current.body.request
            if not (
                opened < req.issued_block <= closed
                and req.issued_block <= req.deadline_block
                and req.issued_block <= terminal.observation.block <= closed
            ):
                raise ValueError("service terminal lies outside certified request phases")
        if current.body.attempt_number == 1:
            break
        parent = verify_service_grant(
            ServiceMinerGrant.model_validate_json(
                read_endpoint_object(objects, current.body.parent_grant_sha256)
            ),
            policy,
            transport,
        )
        verify_service_parent(current, parent)
        current = parent
    return grant


def read_service_terminal(signed, objects, policy, transport, *, request_interval=None):
    signed = SignedServiceTerminal.model_validate_json(canonical_json_bytes(signed))
    grant = review_service_terminal(
        signed.terminal,
        objects,
        policy,
        transport,
        request_interval=request_interval,
    )
    if identity(signed.signature.hotkey) != identity(grant.body.evaluator_hotkey):
        raise ValueError("service terminal signer differs from selected evaluator")
    verify_signature(signed.terminal, signed.signature)
    return grant


class ServiceWorkTerminals:
    """Owner methods use the request journal; signing happens outside its lock.

    The caller signs only the returned immutable intent. Recovery after an
    acknowledgement loss supplies no fresh execution inputs and does not infer.
    """

    def __init__(self, requests: ServiceWorkRequests):
        self.requests = requests
        self.journal, self.policy = requests.journal, requests.policy
        self.objects = JournalEndpointObjects(self.journal)

    def read(
        self, assignment: ServiceWorkAssignment, *, preserve_completed: bool = False
    ) -> SignedServiceTerminal | None:
        """Recover the original terminal and any interrupted immutable export."""
        with self.journal.locked():
            return self.read_locked(assignment, preserve_completed=preserve_completed)

    def read_locked(
        self, assignment: ServiceWorkAssignment, *, preserve_completed: bool = False
    ) -> SignedServiceTerminal | None:
        """Read while the caller holds the queue's compound inventory lease."""
        assignment = review_service_assignment(assignment, self.policy)
        owned = self.requests.queue.assignment(assignment.admission.claim)
        if owned != assignment:
            raise ValueError("service terminal lookup changed its accepted assignment")
        work = owned.admission.work_sha256
        raw = self.journal.get("service_terminal", work)
        if raw is None:
            if preserve_completed:
                self._require_unperformed(owned)
            return None
        signed = SignedServiceTerminal.model_validate_json(canonical_json_bytes(raw))
        intent = self.journal.get("service_terminal_intent", work)
        if intent is None or canonical_json_bytes(intent) != canonical_json_bytes(signed.terminal):
            raise ValueError("service terminal differs from its original signing intent")
        grant = read_service_terminal(signed, self.objects, self.policy, self.requests.transport)
        if grant.body.assignment != owned:
            raise ValueError("service terminal belongs to another accepted assignment")
        # Retention can commit before export acknowledges. Recover that
        # exact object without another signature or fresh execution.
        self.objects.put(signed)
        return signed

    def _require_unperformed(self, assignment: ServiceWorkAssignment) -> None:
        """Signed paid responses must finish fencing/certification, never become skips."""
        intent = self.journal.get("service_terminal_intent", assignment.admission.work_sha256)
        if intent is not None:
            grant = review_service_terminal(
                ServiceTerminal.model_validate_json(canonical_json_bytes(intent)),
                self.objects,
                self.policy,
                self.requests.transport,
            )
            if grant.body.assignment != assignment:
                raise ValueError("pending service certification changed its accepted assignment")
            raise FileNotFoundError("completed service work awaits terminal certification")
        selected = self.journal.get("service_work_evaluator", assignment.admission.work_sha256)
        if selected is None:
            return
        if not isinstance(selected, dict):
            raise ValueError("pending service work has an invalid evaluator binding")
        evaluator = next(
            (e for e in self.policy.evaluators if identity(e.hotkey) == selected.get("evaluator")),
            None,
        )
        if evaluator is None:
            raise ValueError("pending service work has an unselected evaluator")
        body = self.requests.latest(assignment.admission.claim, evaluator.hotkey)
        if body is None:
            return
        slot = service_grant_slot(body)
        response = self.journal.get("service_response", slot)
        retirement = self.journal.get("service_retirement", slot)
        if response is None and retirement is None:
            return
        raw = self.journal.get("service_grant", slot)
        if raw is None:
            raise FileNotFoundError("retained service response lacks its original grant")
        grant = verify_service_grant(
            ServiceMinerGrant.model_validate_json(canonical_json_bytes(raw)),
            self.policy,
            self.requests.transport,
        )
        if grant.body != body or body.assignment != assignment:
            raise ValueError("retained service response changed its accepted assignment")
        if retirement is not None:
            retired = verify_retirement_receipt(
                SignedEndpointRetirementReceipt.model_validate_json(
                    canonical_json_bytes(retirement)
                ),
                request=body.request,
                grant_sha256=digest(grant),
                miner_hotkey=assignment.admission.submission.submission.hotkey,
                evaluator_hotkey=body.evaluator_hotkey,
            )
            if retired.receipt.response_sha256 is not None and response is None:
                raise FileNotFoundError(
                    "completed service response awaits recovery and certification"
                )
        if response is None:
            return
        verify_recovered_response(
            RecoveredEndpointResponse.model_validate_json(canonical_json_bytes(response)),
            request=body.request,
            validator_hotkey=body.evaluator_hotkey,
            miner_hotkey=assignment.admission.submission.submission.hotkey,
            limits=Limits.from_policy(self.requests.transport),
        )
        raise FileNotFoundError("completed service response awaits fencing and certification")

    def prepare(self, slot, response=None, retirement=None, source=None, observation=None):
        body = self.requests._body(slot)
        work = body.assignment.admission.work_sha256
        with self.journal.locked():
            old = self.journal.get("service_terminal_intent", work)
            if old is not None:
                terminal = ServiceTerminal.model_validate_json(canonical_json_bytes(old))
                selected = review_service_terminal(
                    terminal,
                    self.objects,
                    self.policy,
                    self.requests.transport,
                )
                if service_grant_slot(selected.body) != slot or any(
                    supplied is not None and digest(supplied) != wanted
                    for supplied, wanted in (
                        (response, terminal.response_sha256),
                        (retirement, terminal.retirement_sha256),
                    )
                ):
                    raise ValueError("service terminal changed its selected response")
                return terminal
            successor_slot = digest(
                [
                    "umi-cohort-service-request-slot/1",
                    service_obligation(body.assignment, body.evaluator_hotkey),
                    body.attempt_number + 1,
                ]
            )
            if self.journal.get("service_request", successor_slot) is not None:
                raise ValueError("service terminal cannot select a superseded attempt")
            if any(v is None for v in (response, retirement, source, observation)):
                raise FileNotFoundError("service terminal response or retirement is still pending")
            raw = self.journal.get("service_grant", slot)
            if raw is None:
                raise FileNotFoundError("service terminal lacks its selected grant")
            grant = ServiceMinerGrant.model_validate_json(canonical_json_bytes(raw))
            if grant.body != body:
                raise ValueError("service terminal grant differs from its selected request")
            current = grant
            while True:
                self.objects.put(current)
                if current.body.attempt_number == 1:
                    break
                raw = self.journal.get("service_grant", current.body.parent_grant_slot)
                if raw is None:
                    raise FileNotFoundError("service terminal lacks its selected parent")
                current = ServiceMinerGrant.model_validate_json(canonical_json_bytes(raw))
            terminal = ServiceTerminal(
                schema="umi-cohort-service-terminal/1",
                work_sha256=work,
                grant_sha256=digest(grant),
                response_sha256=self.objects.put(response),
                retirement_sha256=self.objects.put(retirement),
                source_sha256=self.objects.put(source),
                observation=observation,
            )
            review_service_terminal(terminal, self.objects, self.policy, self.requests.transport)
            catalog = body.assignment.catalog.catalog
            remember_order_history(
                self.journal,
                {catalog.cohort_sha256: catalog.authority_sha256},
                self.policy,
                source,
                observation.block,
            )
            self.journal.put("service_terminal_intent", work, terminal)
            return terminal

    def retain(self, terminal: ServiceTerminal, signature: Signature) -> SignedServiceTerminal:
        terminal = ServiceTerminal.model_validate_json(canonical_json_bytes(terminal))
        work = terminal.work_sha256
        with self.journal.locked():
            old = self.journal.get("service_terminal_intent", work)
            if old is None or canonical_json_bytes(old) != canonical_json_bytes(terminal):
                raise ValueError("service terminal differs from committed signing intent")
            retained = self.journal.get("service_terminal", work)
            signed = (
                SignedServiceTerminal.model_validate_json(canonical_json_bytes(retained))
                if retained is not None
                else SignedServiceTerminal(terminal=terminal, signature=signature)
            )
            if signed.terminal != terminal:
                raise ValueError("service terminal changed its committed intent")
            read_service_terminal(signed, self.objects, self.policy, self.requests.transport)
            self.journal.put("service_terminal", work, signed)
            self.objects.put(signed)
            return signed
