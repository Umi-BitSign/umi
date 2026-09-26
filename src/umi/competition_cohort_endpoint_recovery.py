"""Durable recovery of selected cohort endpoint responses.

The selected signed attempt is immutable. Retrieval cannot dispatch work,
replace an unknown attempt, close an obligation, or certify receipt timing.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

import bittensor as bt
import httpx
from pydantic import Field

from .competition_cohort_endpoint import (
    SignedRecoverableEndpointOrder,
    endpoint_obligation_sha256,
    validate_recoverable_endpoint_transport,
)
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_order_signer import order_slot
from .competition_cohort_origin import CohortEndpointOrigin
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread
from .config import Limits
from .endpoint_response_recovery import (
    EndpointRecoveryOutcome,
    RecoveredEndpointResponse,
    retrieve_endpoint_response,
    verify_recovered_response,
)
from .open_competition import digest, identity
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortEndpointRecoverySelection(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-recovery-selection/1"] = Field(alias="schema")
    assignment_slot: Hex32
    order: SignedRecoverableEndpointOrder
    transport_policy: ScoringPolicy


class CohortRecoveredEndpointCase(StrictProtocolModel):
    schema_: Literal["umi-cohort-recovered-endpoint-case/1"] = Field(alias="schema")
    selection_sha256: Hex32
    case_id: Hex32
    origin_evidence_sha256: Hex32
    response: RecoveredEndpointResponse
    # This is deliberately not a RecoverableEndpointTranscript or a score.
    original_receipt_timing_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


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

    def _validate(self, selected: CohortEndpointRecoverySelection):
        selected = CohortEndpointRecoverySelection.model_validate_json(
            canonical_json_bytes(selected)
        )
        assignment = self.journal.assignment(selected.assignment_slot)
        job = self.journal.validate_assignment(assignment)
        signed = validate_recoverable_endpoint_transport(
            selected.order, self.journal.policy, selected.transport_policy
        )
        if job != signed.order.job:
            raise ValueError("response recovery attempt differs from acknowledged assignment")
        return selected, assignment, job

    def selection(self, slot: str):
        raw = self.journal.journal.get("endpoint_recovery_selection", slot)
        if raw is None:
            raise FileNotFoundError("endpoint response selection is not retained")
        selected, assignment, job = self._validate(
            CohortEndpointRecoverySelection.model_validate_json(canonical_json_bytes(raw))
        )
        if selected.assignment_slot != slot:
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
        slot = selected.assignment_slot
        with self.journal.locked(recovery_slot(slot)):
            if self.journal.journal.get("endpoint_recovery_selection", slot) is not None:
                previous, old_assignment, _ = self.selection(slot)
                if previous != selected or old_assignment != assignment:
                    raise ValueError("endpoint attempt selection is already retained")
                return previous
            # Use the execution lock only for authority retention. collect() below
            # owns that same lock itself; nesting it would deadlock recovery.
            with self.journal.locked(slot):
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
                    for case in job.cases:
                        key = endpoint_obligation_sha256(job, case.case_id)
                        old = db.execute(
                            "SELECT slot,case_id FROM endpoint_recovery_queue WHERE obligation=?",
                            (key,),
                        ).fetchone()
                        if old is not None and old != (slot, case.case_id):
                            raise ValueError("endpoint recovery queue binding conflict")
                        db.execute(
                            "INSERT OR IGNORE INTO endpoint_recovery_queue VALUES (?,?,?)",
                            (key, slot, case.case_id),
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
                            endpoint_obligation_sha256(job, c.case_id),
                            136 * 1024,
                        )
                        for c in job.cases
                    ),
                ),
            )

            await run_owned_thread(
                self.journal.journal.put, "endpoint_recovery_selection", slot, selected
            )
            return selected

    def _case(self, selected, job, case_id):
        matches = [i for i, case in enumerate(job.cases) if case.case_id == case_id]
        if len(matches) != 1:
            raise ValueError("response recovery case is not uniquely assigned")
        return selected.order.order.requests[matches[0]]

    def _retained(self, selected, job, case_id):
        request = self._case(selected, job, case_id)
        raw = self.journal.journal.get(
            "endpoint_recovered_case", endpoint_obligation_sha256(job, case_id)
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
                CohortEndpointRecoverySelection.model_validate_json(canonical_json_bytes(raw))
            )
            if selected.assignment_slot != slot:
                raise ValueError("response recovery intent changed its slot")
            self._case(selected, job, case_id)
            await self.prepare(assignment, selected.order, selected.transport_policy)
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
                    endpoint_obligation_sha256(job, case_id),
                    value,
                )
            return outcome
