"""Durable recovery of selected cohort endpoint responses.

The selected signed attempt is immutable. Retrieval cannot dispatch work,
replace an unknown attempt, close an obligation, or certify receipt timing.
"""

from __future__ import annotations

import hashlib
from typing import Any

import bittensor as bt
import httpx

from .competition_cohort_endpoint import (
    SignedRecoverableEndpointOrder,
    validate_recoverable_endpoint_transport,
)
from .competition_cohort_endpoint_selection import (
    CohortEndpointRecoverySelection as CohortEndpointRecoverySelection,
)
from .competition_cohort_endpoint_selection import (
    CohortEndpointReplacementSelection,
    EndpointSelection,
    case_record_key,
    parse_endpoint_selection,
    selected_request,
    selected_requests,
    selection_grant,
    selection_slot,
)
from .competition_cohort_endpoint_selection import (
    CohortRecoveredEndpointCase as CohortRecoveredEndpointCase,
)
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_miner_case import (
    CohortCaseMinerGrant,
    validate_case_attempt,
    verify_replacement_parent,
)
from .competition_cohort_order_signer import order_slot
from .competition_cohort_origin import CohortEndpointOrigin
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread
from .config import Limits
from .endpoint_response_recovery import (
    EndpointRecoveryOutcome,
    retrieve_endpoint_response,
    verify_recovered_response,
)
from .open_competition import digest, identity
from .policy import ScoringPolicy
from .protocol import canonical_json_bytes


def recovery_slot(assignment_slot: str) -> str:
    return digest({"schema": "umi-cohort-endpoint-recovery-lock/1", "slot": assignment_slot})


class CohortEndpointResponseRecovery:
    def __init__(
        self,
        origin: CohortEndpointOrigin,
        wallet: Any,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.origin, self.wallet, self.transport = origin, wallet, transport
        self.journal = origin.authority.journal
        if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
            self.journal.config.signer
        ):
            raise ValueError("response recovery wallet differs from evaluator")
        with self.journal.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS endpoint_recovery_queue "
                "(obligation TEXT PRIMARY KEY, slot TEXT NOT NULL, case_id TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS endpoint_recovery_cursor "
                "(id INTEGER PRIMARY KEY CHECK(id=1), obligation TEXT NOT NULL)"
            )

    def _validate_one(self, selected: EndpointSelection, assignment=None):
        selected = parse_endpoint_selection(canonical_json_bytes(selected))
        if assignment is None:
            assignment = self.journal.assignment(selected.assignment_slot)
        job = self.journal.validate_assignment(assignment)
        validate = (
            validate_case_attempt
            if isinstance(selected, CohortEndpointReplacementSelection)
            else validate_recoverable_endpoint_transport
        )
        signed = validate(selected.order, self.journal.policy, selected.transport_policy)
        selection_grant(selected, assignment)
        if job != signed.order.job:
            raise ValueError("response recovery attempt differs from acknowledged assignment")
        return selected, assignment, job

    def _validate(self, selected: EndpointSelection, assignment=None):
        result = self._validate_one(selected, assignment)
        current, assignment, _ = result
        seen = set()
        while isinstance(current, CohortEndpointReplacementSelection):
            key = current.order.order.parent_grant_slot
            if key in seen:
                raise ValueError("endpoint replacement parent cycle")
            seen.add(key)
            # Replacement selection slots are their immutable grant slots.
            # The original whole-attempt selection keeps its historical key.
            parent_slot = key
            raw = self.journal.journal.get("endpoint_recovery_selection", parent_slot)
            if raw is None:
                parent_slot = current.assignment_slot
                raw = self.journal.journal.get("endpoint_recovery_selection", parent_slot)
            if raw is None:
                raise FileNotFoundError("endpoint replacement parent is not retained")
            parent, parent_assignment, _ = self._validate_one(
                parse_endpoint_selection(canonical_json_bytes(raw))
            )
            if selection_slot(parent) != parent_slot:
                raise ValueError("endpoint parent selection changed its slot")
            verify_replacement_parent(current.grant, selection_grant(parent, parent_assignment))
            current, assignment = parent, parent_assignment
        return result

    def selection(self, slot: str):
        raw = self.journal.journal.get("endpoint_recovery_selection", slot)
        if raw is None:
            raise FileNotFoundError("endpoint response selection is not retained")
        selected, assignment, job = self._validate(
            parse_endpoint_selection(canonical_json_bytes(raw))
        )
        if selection_slot(selected) != slot:
            raise ValueError("response recovery selection changed its slot")
        return selected, assignment, job

    async def prepare(
        self,
        assignment: CohortExecutionAssignment,
        signed: SignedRecoverableEndpointOrder,
        transport_policy: ScoringPolicy,
    ) -> CohortEndpointRecoverySelection:
        """Retain one original attempt before work; this is not a dispatch grant."""
        assignment = CohortExecutionAssignment.model_validate_json(canonical_json_bytes(assignment))
        job = self.journal.validate_assignment(assignment)
        signed = validate_recoverable_endpoint_transport(
            signed, self.journal.policy, transport_policy
        )
        if job != signed.order.job:
            raise ValueError("response recovery attempt differs from acknowledged assignment")
        selected = CohortEndpointRecoverySelection(
            schema="umi-cohort-endpoint-recovery-selection/1",
            assignment_slot=order_slot(assignment.certificate.order),
            order=signed,
            transport_policy=transport_policy,
        )
        return await self._prepare(selected, assignment)

    async def prepare_case(self, grant: CohortCaseMinerGrant, transport_policy: ScoringPolicy):
        selected = CohortEndpointReplacementSelection(
            schema="umi-cohort-endpoint-replacement-selection/1",
            grant=grant,
            transport_policy=transport_policy,
        )
        return await self._prepare(selected, grant.assignment)

    async def _prepare(self, selected: EndpointSelection, assignment):
        selected, retained_assignment, _ = self._validate(selected, assignment)
        if assignment != retained_assignment:
            raise ValueError("endpoint selection assignment changed")
        slot = selection_slot(selected)
        with self.journal.locked(recovery_slot(slot)):
            if self.journal.journal.get("endpoint_recovery_selection", slot) is not None:
                previous, old_assignment, _ = self.selection(slot)
                if previous != selected or old_assignment != assignment:
                    raise ValueError("endpoint attempt selection is already retained")
                return previous
            # Use the execution lock only for authority retention. collect() below
            # owns that same lock itself; nesting it would deadlock recovery.
            with self.journal.locked(selected.assignment_slot):
                source, boundary = await self.origin.authority.current(assignment)
                await run_owned_thread(self.journal.retain, assignment, source, boundary.block)
            # Preserve complete bytes, not just a reservation hash. A crash or
            # capacity error after this commit is resumable from the queue alone.
            prior_intent = self.journal.journal.get("endpoint_recovery_intent", slot)
            if prior_intent is not None and canonical_json_bytes(
                prior_intent
            ) != canonical_json_bytes(selected):
                raise ValueError("endpoint attempt intent is already retained")

            def retain_intent():
                def enqueue(db):
                    for case_id, _ in selected_requests(selected):
                        key = case_record_key(selected, case_id)
                        old = db.execute(
                            "SELECT slot,case_id FROM endpoint_recovery_queue WHERE obligation=?",
                            (key,),
                        ).fetchone()
                        if old is not None and old != (slot, case_id):
                            raise ValueError("endpoint recovery queue binding conflict")
                        db.execute(
                            "INSERT OR IGNORE INTO endpoint_recovery_queue VALUES (?,?,?)",
                            (key, slot, case_id),
                        )

                self.journal.journal.put_many(
                    (("endpoint_recovery_intent", slot, selected),),
                    index=enqueue,
                )

            await run_owned_thread(retain_intent)
            # Full output allowance is reserved before any retrieval. Repeated
            # attempts consume no new allowance and cannot replace this selection.
            raw = canonical_json_bytes(selected)
            await run_owned_thread(
                self.journal.journal.reserve_records,
                recovery_slot(slot),
                (
                    RecordReservation(
                        "endpoint_recovery_selection",
                        slot,
                        len(raw),
                        hashlib.sha256(raw).hexdigest(),
                    ),
                    *(
                        RecordReservation(
                            "endpoint_recovered_case",
                            case_record_key(selected, case_id),
                            136 * 1024,
                        )
                        for case_id, _ in selected_requests(selected)
                    ),
                ),
            )

            await run_owned_thread(
                self.journal.journal.put, "endpoint_recovery_selection", slot, selected
            )
            return selected

    def _case(self, selected, job, case_id):
        return selected_request(selected, case_id)

    def _retained(self, selected, job, case_id):
        request = self._case(selected, job, case_id)
        raw = self.journal.journal.get(
            "endpoint_recovered_case", case_record_key(selected, case_id)
        )
        if raw is None:
            return None
        value = CohortRecoveredEndpointCase.model_validate_json(canonical_json_bytes(raw))
        if value.selection_sha256 != digest(selected) or value.case_id != case_id:
            raise ValueError("retained response differs from selected attempt")
        verify_recovered_response(
            value.response,
            request=request,
            validator_hotkey=job.evaluator_hotkey,
            miner_hotkey=job.submission.submission.hotkey,
            limits=Limits.from_policy(selected.transport_policy),
        )
        return value

    def retained(self, slot: str, case_id: str) -> CohortRecoveredEndpointCase | None:
        selected, _, job = self.selection(slot)
        return self._retained(selected, job, case_id)

    async def recover(self, slot: str, case_id: str) -> EndpointRecoveryOutcome:
        if self.journal.journal.get("endpoint_recovery_selection", slot) is None:
            raw = self.journal.journal.get("endpoint_recovery_intent", slot)
            if raw is None:
                raise FileNotFoundError("endpoint response intent is not retained")
            selected, assignment, job = self._validate(
                parse_endpoint_selection(canonical_json_bytes(raw))
            )
            if selection_slot(selected) != slot:
                raise ValueError("response recovery intent changed its slot")
            self._case(selected, job, case_id)
            await self._prepare(selected, assignment)
        with self.journal.locked(recovery_slot(slot)):
            selected, assignment, job = self.selection(slot)
            request = self._case(selected, job, case_id)
            prior = self._retained(selected, job, case_id)
            if prior is not None:
                return EndpointRecoveryOutcome(
                    "recovered", "retained_original_response", response=prior.response
                )
            # Re-prove the current chain origin before sending the original body,
            # which can contain a clip capability. This also checks open authority.
            capture = await self.origin.collect(assignment)
            if capture.submission_sha256 != digest(job.submission.submission) or identity(
                capture.hotkey
            ) != identity(job.submission.submission.hotkey):
                raise ValueError("response recovery origin differs from assigned miner")
            outcome = await retrieve_endpoint_response(
                request,
                wallet=self.wallet,
                validator_hotkey=job.evaluator_hotkey,
                miner_hotkey=job.submission.submission.hotkey,
                miner_url=capture.origin,
                resolver=capture.transport_resolver(),
                limits=Limits.from_policy(selected.transport_policy),
                timeout_seconds=self.journal.config.read_timeout_seconds,
                transport=self.transport,
            )
            if outcome.response is not None:
                value = CohortRecoveredEndpointCase(
                    schema="umi-cohort-recovered-endpoint-case/1",
                    selection_sha256=digest(selected),
                    case_id=case_id,
                    origin_evidence_sha256=capture.evidence_sha256,
                    response=outcome.response,
                )
                # Persist exact bytes before acknowledgement. Do not request new
                # finality here: its failure must not discard an already read body.
                await run_owned_thread(
                    self.journal.journal.put,
                    "endpoint_recovered_case",
                    case_record_key(selected, case_id),
                    value,
                )
            return outcome
