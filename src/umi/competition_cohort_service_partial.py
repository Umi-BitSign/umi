"""Signed no-credit paid evidence after the original admission cutoff.

This first version covers an authenticated response whose miner retirement is
absent. It cannot replace a terminal, a terminal intent, or a certifiable pair.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_cohort_endpoint_archive import read_endpoint_object
from .competition_cohort_order_signer import CohortOrderHistory, remember_order_history
from .competition_cohort_service_fence import ServiceTailAdmissionFence
from .competition_cohort_service_grant import (
    ServiceMinerGrant,
    review_service_request_current,
    verify_service_grant,
    verify_service_parent,
)
from .competition_cohort_service_terminal import PendingServiceTerminal, ServiceWorkTerminals
from .competition_cohort_service_work import ServiceWorkAssignment, review_service_assignment
from .competition_execution import ExecutionBoundary
from .competition_round_journal import RecordReservation
from .config import Limits
from .endpoint_response_recovery import RecoveredEndpointResponse, verify_recovered_response
from .open_competition import Hotkey, Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ServicePaidPartialInventory(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-paid-partial/1"] = Field(alias="schema")
    work_sha256: Hex32
    assignment_sha256: Hex32
    grant_sha256: Hex32
    evaluator_hotkey: Hotkey
    response_sha256: Hex32
    retirement_sha256: None = None
    fence_sha256: Hex32
    source_sha256: Hex32
    observation: ExecutionBoundary
    disposition: Literal["response_without_retirement_no_credit"] = (
        "response_without_retirement_no_credit"
    )
    chain_submission_authorized: Literal[False] = False


class SignedServicePaidPartialInventory(StrictProtocolModel):
    inventory: ServicePaidPartialInventory
    signature: Signature


class PendingPaidPartialInventory(FileNotFoundError):
    """Authenticated incomplete work has not yet received its signed inventory."""


def paid_partial_observations(closure, objects):
    return tuple(
        SignedServicePaidPartialInventory.model_validate_json(
            read_endpoint_object(objects, key)
        ).inventory.observation
        for catalog in closure.catalogs
        for key in (catalog.paid_partials or ())
    )


def review_paid_partial(body, objects, policy, transport, *, request_interval=None):
    """Replay all original bytes; finality is checked by native phase reviewers."""
    body = ServicePaidPartialInventory.model_validate_json(canonical_json_bytes(body))
    assignment = review_service_assignment(
        ServiceWorkAssignment.model_validate_json(
            read_endpoint_object(objects, body.assignment_sha256)
        ),
        policy,
    )
    grant = verify_service_grant(
        ServiceMinerGrant.model_validate_json(read_endpoint_object(objects, body.grant_sha256)),
        policy,
        transport,
    )
    if (
        grant.body.assignment != assignment
        or body.work_sha256 != assignment.admission.work_sha256
        or identity(body.evaluator_hotkey) != identity(grant.body.evaluator_hotkey)
    ):
        raise ValueError("paid partial changed its accepted work or selected evaluator")
    source = CohortOrderHistory.model_validate_json(
        read_endpoint_object(objects, body.source_sha256)
    )
    review_service_request_current(grant.body, policy, source, body.observation.block)
    fence = ServiceTailAdmissionFence.model_validate_json(
        read_endpoint_object(objects, body.fence_sha256)
    )
    if (
        fence.policy_sha256 != digest(policy)
        or fence.cohort_sha256 != assignment.catalog.catalog.cohort_sha256
        or assignment.admission.catalog_sha256 not in fence.catalog_sha256s
        or fence.tail.selected_observation is not None
        or identity(assignment.admission.submission.submission.hotkey)
        not in fence.tail.unfinished_hotkeys
        or not fence.tail.observation.block < body.observation.block
    ):
        raise ValueError("paid partial changed its original cutoff or snapshot boundary")
    verify_recovered_response(
        RecoveredEndpointResponse.model_validate_json(
            read_endpoint_object(objects, body.response_sha256)
        ),
        request=grant.body.request,
        validator_hotkey=body.evaluator_hotkey,
        miner_hotkey=assignment.admission.submission.submission.hotkey,
        limits=Limits.from_policy(transport),
    )
    current = grant
    while True:
        if request_interval is not None:
            opened, closed = request_interval
            if not opened < current.body.request.issued_block <= body.observation.block <= closed:
                raise ValueError("paid partial lies outside certified request phases")
        if current.body.request.issued_block > body.observation.block:
            raise ValueError("paid partial snapshot precedes its original request")
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
    return assignment, fence, source


def read_paid_partial(key, objects, policy, transport, *, request_interval=None):
    signed = SignedServicePaidPartialInventory.model_validate_json(
        read_endpoint_object(objects, key)
    )
    assignment, fence, source = review_paid_partial(
        signed.inventory, objects, policy, transport, request_interval=request_interval
    )
    if identity(signed.signature.hotkey) != identity(signed.inventory.evaluator_hotkey):
        raise ValueError("paid partial signer differs from selected evaluator")
    verify_signature(signed.inventory, signed.signature)
    return signed, assignment, fence, source


class ServicePaidPartials:
    """One durable exact signing intent per work and fixed admission fence.

    Preparation and closure reads own the original queue's compound lease.
    Signing happens outside it. An acknowledgement loss retries the same body;
    a newly available certifiable result supersedes eligibility, never its bytes.
    """

    def __init__(self, terminals: ServiceWorkTerminals):
        self.terminals = terminals
        self.requests, self.journal = terminals.requests, terminals.journal
        self.queue, self.objects = self.requests.queue, terminals.objects

    @staticmethod
    def _key(assignment, fence):
        return digest(
            ["umi-service-paid-partial-intent/1", assignment.admission.work_sha256, digest(fence)]
        )

    def _incomplete_locked(self, assignment):
        if self.terminals.read_locked(assignment) is not None:
            return None
        return self.terminals.incomplete_locked(assignment, allow_partial=True)

    def prepare(self, assignment, source=None, observation=None):
        # This is the same compound journal lease as closure_inventory; the
        # immutable assignment read authenticates this accepted identity without
        # rescanning every unrelated accepted job for each worker turn.
        with self.journal.locked():
            fence = self.queue._tail_admission_fence()
            if fence is None:
                return None
            key = self._key(assignment, fence)
            old = self.journal.get("service_paid_partial_intent", key)
            if old is None and self.journal.get("service_paid_partial", key) is not None:
                raise FileNotFoundError("paid partial lost its original signing intent")
            try:
                originals = self._incomplete_locked(assignment)
            except PendingServiceTerminal:
                return None
            if originals is None:
                if old is not None and self.terminals.read_locked(assignment) is None:
                    raise FileNotFoundError("paid partial lost its referenced native response")
                return None
            grant, response = originals
            if old is not None:
                body = ServicePaidPartialInventory.model_validate_json(canonical_json_bytes(old))
                self._originals(body, assignment, fence, grant, response)
                review_paid_partial(
                    body, self.objects, self.requests.policy, self.requests.transport
                )
                return body
            if source is None or observation is None:
                return None
            if observation.block <= fence.tail.observation.block:
                return None
            current = grant
            while True:
                self.objects.put(current)
                if current.body.attempt_number == 1:
                    break
                raw = self.journal.get("service_grant", current.body.parent_grant_slot)
                if raw is None:
                    raise FileNotFoundError("paid partial lacks its selected parent grant")
                current = ServiceMinerGrant.model_validate_json(canonical_json_bytes(raw))
            body = ServicePaidPartialInventory(
                schema="umi-cohort-service-paid-partial/1",
                work_sha256=assignment.admission.work_sha256,
                assignment_sha256=self.objects.put(assignment),
                grant_sha256=digest(grant),
                evaluator_hotkey=grant.body.evaluator_hotkey,
                response_sha256=self.objects.put(response),
                fence_sha256=self.objects.put(fence),
                source_sha256=self.objects.put(source),
                observation=observation,
            )
            review_paid_partial(body, self.objects, self.requests.policy, self.requests.transport)
            catalog = assignment.catalog.catalog
            remember_order_history(
                self.journal,
                {catalog.cohort_sha256: catalog.authority_sha256},
                self.requests.policy,
                source,
                observation.block,
            )
            self.journal.reserve_records(
                key,
                (
                    RecordReservation("service_paid_partial_intent", key, 16384),
                    RecordReservation("service_paid_partial", key, 32768),
                ),
            )
            self.journal.put("service_paid_partial_intent", key, body)
            return body

    @staticmethod
    def _originals(body, assignment, fence, grant, response):
        if (
            body.assignment_sha256 != digest(assignment)
            or body.fence_sha256 != digest(fence)
            or body.grant_sha256 != digest(grant)
            or body.response_sha256 != digest(response)
        ):
            raise ValueError("paid partial differs from the original native inventory")

    def read_locked(self, assignment, fence):
        key = self._key(assignment, fence)
        intent = self.journal.get("service_paid_partial_intent", key)
        raw = self.journal.get("service_paid_partial", key)
        if raw is not None and intent is None:
            raise FileNotFoundError("paid partial lost its original signing intent")
        originals = self._incomplete_locked(assignment)
        if originals is None:
            if intent is not None and self.terminals.read_locked(assignment) is None:
                raise FileNotFoundError("paid partial lost its referenced native response")
            return None
        if raw is None:
            raise PendingPaidPartialInventory("paid response awaits its signed partial inventory")
        signed = SignedServicePaidPartialInventory.model_validate_json(canonical_json_bytes(raw))
        if intent is None or canonical_json_bytes(intent) != canonical_json_bytes(signed.inventory):
            raise ValueError("paid partial changed its durable signing intent")
        self._originals(signed.inventory, assignment, fence, *originals)
        self.objects.put(signed)
        read_paid_partial(
            digest(signed), self.objects, self.requests.policy, self.requests.transport
        )
        return signed

    def retain(self, body, signature):
        body = ServicePaidPartialInventory.model_validate_json(canonical_json_bytes(body))
        assignment = ServiceWorkAssignment.model_validate_json(
            read_endpoint_object(self.objects, body.assignment_sha256)
        )
        fence = ServiceTailAdmissionFence.model_validate_json(
            read_endpoint_object(self.objects, body.fence_sha256)
        )
        key = self._key(assignment, fence)
        with self.journal.locked():
            intent = self.journal.get("service_paid_partial_intent", key)
            if intent is None or canonical_json_bytes(intent) != canonical_json_bytes(body):
                raise ValueError("paid partial differs from committed signing intent")
            raw = self.journal.get("service_paid_partial", key)
            signed = (
                SignedServicePaidPartialInventory(inventory=body, signature=signature)
                if raw is None
                else SignedServicePaidPartialInventory.model_validate_json(
                    canonical_json_bytes(raw)
                )
            )
            if signed.inventory != body:
                raise ValueError("paid partial changed its committed signing intent")
            if identity(signed.signature.hotkey) != identity(body.evaluator_hotkey):
                raise ValueError("paid partial signer differs from selected evaluator")
            review_paid_partial(body, self.objects, self.requests.policy, self.requests.transport)
            verify_signature(body, signed.signature)
            self.journal.put("service_paid_partial", key, signed)
            self.objects.put(signed)
            return signed

    def retained(self, body):
        assignment = ServiceWorkAssignment.model_validate_json(
            read_endpoint_object(self.objects, body.assignment_sha256)
        )
        fence = ServiceTailAdmissionFence.model_validate_json(
            read_endpoint_object(self.objects, body.fence_sha256)
        )
        raw = self.journal.get("service_paid_partial", self._key(assignment, fence))
        if raw is None:
            return None
        signed = SignedServicePaidPartialInventory.model_validate_json(canonical_json_bytes(raw))
        if signed.inventory != body:
            raise ValueError("paid partial changed its original signing intent")
        return self.retain(body, signed.signature)
