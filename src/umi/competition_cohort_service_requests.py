"""Select exact service requests and retain quorum votes in the owning queue.

The host authenticates current history, registration and verified window sources.
Each independent reviewer must replay those sources and the original admission
before voting. This owner records selection and votes; it neither signs on a
reviewer's behalf nor claims that a selected request has been delivered.
"""

from __future__ import annotations

from .competition_chain import RegistrationCapture
from .competition_cohort_endpoint_decision_contracts import SignedCohortEndpointCaseDecision
from .competition_cohort_order_signer import CohortOrderHistory, remember_order_history
from .competition_cohort_request_window import CohortAttemptRequestWindow, EndpointRequestWindow
from .competition_cohort_service_grant import (
    ServiceMinerGrant,
    ServiceRequestBody,
    review_service_request_current,
    service_grant_slot,
    service_obligation,
    service_wire_ids,
    validate_service_body,
    verify_service_grant,
    verify_service_parent_body,
)
from .competition_cohort_service_queue import ServiceWorkQueue
from .competition_cohort_service_work import SignedServiceWorkClaim
from .competition_execution import execution_boundary
from .competition_round_journal import RecordReservation
from .endpoint_retirement import SignedEndpointRetirementReceipt
from .open_competition import Signature, digest, identity, verify_signature
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import Video, canonical_json_bytes


class ServiceWorkRequests:
    def __init__(self, queue: ServiceWorkQueue, transport: ScoringPolicy):
        self.queue, self.journal, self.policy = queue, queue.journal, queue.policy
        self.transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))

    def latest(self, claim: SignedServiceWorkClaim, evaluator: str) -> ServiceRequestBody | None:
        """Recover selected ancestry before consulting any fresh execution source."""
        assignment = self.queue.assignment(claim)
        selected = self.journal.get("service_work_evaluator", assignment.admission.work_sha256)
        if selected is not None and selected != {
            "evaluator": identity(evaluator),
            "transport": scoring_policy_hash(self.transport),
        }:
            raise ValueError("service work already has another evaluator or transport")
        obligation = service_obligation(assignment, evaluator)
        latest, number = None, 1
        while True:
            slot = digest(["umi-cohort-service-request-slot/1", obligation, number])
            if self.journal.get("service_request", slot) is None:
                if selected is not None and latest is None:
                    raise ValueError("service work lost its original selected request")
                return latest
            latest = self._body(slot)
            if latest.assignment != assignment:
                raise ValueError("service request changed the original assignment")
            number += 1

    def _body(self, slot):
        raw = self.journal.get("service_request", slot)
        if raw is None:
            raise FileNotFoundError("service request has not been selected")
        value = validate_service_body(
            ServiceRequestBody.model_validate_json(canonical_json_bytes(raw)),
            self.policy,
            self.transport,
        )
        if service_grant_slot(value) != slot:
            raise ValueError("service request changed its selected slot")
        original = self.queue.assignment(value.assignment.admission.claim)
        if original != value.assignment:
            raise ValueError("service request changed the accepted owner record")
        current, seen = value, {slot}
        while current.attempt_number > 1:
            key = current.parent_grant_slot
            if key in seen:
                raise ValueError("service request lineage is cyclic")
            seen.add(key)
            raw = self.journal.get("service_grant", key)
            if raw is None:
                raise FileNotFoundError("selected service parent certificate is missing")
            parent = verify_service_grant(
                ServiceMinerGrant.model_validate_json(canonical_json_bytes(raw)),
                self.policy,
                self.transport,
            )
            selected = self.journal.get("service_request", key)
            if selected is None or canonical_json_bytes(parent.body) != canonical_json_bytes(
                selected
            ):
                raise ValueError("service parent certificate differs from its selection")
            verify_service_parent_body(current, parent)
            current = parent.body
        return value

    def prepare(
        self,
        claim: SignedServiceWorkClaim,
        evaluator: str,
        video: Video | None,
        window: CohortAttemptRequestWindow | EndpointRequestWindow | None,
        source: CohortOrderHistory | None,
        capture: RegistrationCapture | None,
        *,
        parent: ServiceMinerGrant | None = None,
        decision: SignedCohortEndpointCaseDecision | None = None,
        retirement: SignedEndpointRetirementReceipt | None = None,
    ) -> ServiceRequestBody:
        """Recover the original selection, or persist a newly authorized attempt."""
        assignment = self.queue.assignment(claim)
        number = 1 if parent is None else parent.body.attempt_number + 1
        obligation = service_obligation(assignment, evaluator)
        slot = digest(["umi-cohort-service-request-slot/1", obligation, number])
        # queue.assignment owns its own lock; never call it under this mutex.
        with self.journal.locked():
            old = self.journal.get("service_request", slot)
            if old is not None:
                body = validate_service_body(
                    ServiceRequestBody.model_validate_json(canonical_json_bytes(old)),
                    self.policy,
                    self.transport,
                )
                if (
                    service_grant_slot(body) != slot
                    or body.assignment != assignment
                    or body.parent_grant_sha256 != (None if parent is None else digest(parent))
                    or body.prior_decision != decision
                    or body.prior_retirement != retirement
                ):
                    raise ValueError("service request selection changed its original inputs")
                self._reserve(slot, body)
                return body
            if self.journal.get("service_terminal_intent", assignment.admission.work_sha256):
                raise ValueError("service work already has a terminal response selected")
            if video is None or window is None or source is None or capture is None:
                raise ValueError("new service request requires current execution inputs")
            boundary = execution_boundary(capture)
            item = assignment.catalog.catalog.work[assignment.admission.ordinal - 1]
            body = ServiceRequestBody(
                schema="umi-cohort-service-request/1",
                assignment=assignment,
                evaluator_hotkey=evaluator,
                attempt_number=number,
                request=window.request_with_ids(
                    item, video, service_wire_ids(assignment, evaluator, number), self.transport
                ),
                window=window,
                parent_grant_slot=None if parent is None else service_grant_slot(parent.body),
                parent_grant_sha256=None if parent is None else digest(parent),
                prior_decision=decision,
                prior_retirement=retirement,
            )
            validate_service_body(body, self.policy, self.transport)
            review_service_request_current(body, self.policy, source, boundary.block)
            if parent is not None:
                # The selected certificate must exist in this owner's journal.
                raw = self.journal.get("service_grant", body.parent_grant_slot)
                if raw is None or canonical_json_bytes(raw) != canonical_json_bytes(parent):
                    raise ValueError("service replacement parent is not the selected certificate")
                verify_service_grant(parent, self.policy, self.transport)
                verify_service_parent_body(body, parent)
            selection = {
                "evaluator": identity(evaluator),
                "transport": scoring_policy_hash(self.transport),
            }
            selected = self.journal.get("service_work_evaluator", assignment.admission.work_sha256)
            if selected is not None and selected != selection:
                raise ValueError("service work already has another evaluator or transport")
            catalog = assignment.catalog.catalog
            remember_order_history(
                self.journal,
                {catalog.cohort_sha256: catalog.authority_sha256},
                self.policy,
                source,
                boundary.block,
            )
            self.journal.put_many(
                (
                    ("service_work_evaluator", assignment.admission.work_sha256, selection),
                    ("service_request", slot, body),
                )
            )
            self._reserve(slot, body)
            return body

    def _reserve(self, slot, body):
        # Retain selection before sizing its recovery allowance. A crash must
        # not reserve one size then construct a different request on restart.
        # No selected body is returned for voting until reservation succeeds.
        size = len(canonical_json_bytes(body))
        reservations = [RecordReservation("service_grant", slot, size + 32 * 1024)]
        reservations.extend(
            RecordReservation("service_request_vote", self._vote_key(slot, e.hotkey), 2048)
            for e in self.policy.evaluators
        )
        self.journal.reserve_records(slot, tuple(reservations))
        work = body.assignment.admission.work_sha256
        # A separate batch preserves existing request reservations. One logical
        # work retains one result allowance across all attempts.
        self.journal.reserve_records(
            digest(["umi-service-terminal-reservation/1", work]),
            (
                RecordReservation("service_terminal_intent", work, 16384),
                RecordReservation("service_terminal", work, 32768),
            ),
        )

    @staticmethod
    def _vote_key(slot, hotkey):
        return digest(["umi-cohort-service-request-vote/1", slot, identity(hotkey)])

    def collect(self, slot, signature: Signature):
        # Authenticate the original record before holding the queue write lock.
        body = self._body(slot)
        signature = Signature.model_validate_json(canonical_json_bytes(signature))
        who = identity(signature.hotkey)
        if who not in {identity(e.hotkey) for e in self.policy.evaluators} or who == identity(
            body.assignment.admission.submission.submission.hotkey
        ):
            raise ValueError("service vote signer is not an independent reviewer")
        verify_signature(body, signature)
        key = self._vote_key(slot, signature.hotkey)
        with self.journal.locked():
            old = self.journal.get("service_request_vote", key)
            if old is not None:
                existing = Signature.model_validate_json(canonical_json_bytes(old))
                verify_signature(body, existing)
                if identity(existing.hotkey) != who:
                    raise ValueError("service vote changed its reviewer")
                return existing
            self._reserve(slot, body)
            self.journal.put("service_request_vote", key, signature)
            return signature

    def _retained_certificate(self, slot, body) -> ServiceMinerGrant | None:
        old = self.journal.get("service_grant", slot)
        if old is None:
            return None
        value = verify_service_grant(
            ServiceMinerGrant.model_validate_json(canonical_json_bytes(old)),
            self.policy,
            self.transport,
        )
        if value.body != body:
            raise ValueError("service certificate changed its selected request")
        return value

    def certificate(self, slot) -> ServiceMinerGrant:
        body = self._body(slot)
        # Retained grants and selections are immutable. Recovery must not take
        # queue writer ownership just to authenticate a completed certificate.
        retained = self._retained_certificate(slot, body)
        if retained is not None:
            return retained
        with self.journal.locked():
            retained = self._retained_certificate(slot, body)
            if retained is not None:
                return retained
            self._reserve(slot, body)
            votes, groups = [], set()
            for evaluator in sorted(self.policy.evaluators, key=lambda e: identity(e.hotkey)):
                raw = self.journal.get(
                    "service_request_vote", self._vote_key(slot, evaluator.hotkey)
                )
                if raw is None:
                    continue
                vote = Signature.model_validate_json(canonical_json_bytes(raw))
                if identity(vote.hotkey) != identity(evaluator.hotkey):
                    raise ValueError("service vote changed its indexed reviewer")
                verify_signature(body, vote)
                if evaluator.control_group not in groups:
                    groups.add(evaluator.control_group)
                    votes.append(vote)
            value = ServiceMinerGrant(
                schema="umi-cohort-miner-service-grant/1",
                body=body,
                signatures=tuple(votes),
            )
            verify_service_grant(value, self.policy, self.transport)
            self.journal.put("service_grant", slot, value)
            return value
