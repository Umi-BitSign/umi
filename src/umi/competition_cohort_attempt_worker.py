"""Resume one endpoint case through dispatch, retirement and certified replacement."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_cohort_endpoint_dispatch import CohortEndpointDispatcher
from .competition_cohort_endpoint_selection import (
    case_record_key,
    selected_request,
    selection_grant,
    selection_slot,
)
from .competition_cohort_miner_case import CohortCaseMinerGrant, verify_replacement_parent
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class EndpointAttemptSuccessor(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-attempt-successor/1"] = Field(alias="schema")
    previous_selection_sha256: Hex32
    selection_slot: Hex32
    case_id: Hex32


class CohortEndpointAttemptWorker:
    def __init__(self, requests, decisions):
        if requests.recovery is not decisions.recovery:
            raise ValueError("endpoint attempt workers must share one recovery owner")
        self.requests, self.decisions = requests, decisions
        self.recovery = requests.recovery
        self.dispatcher = CohortEndpointDispatcher(self.recovery, requests.signer.blocks)

    def current(self, slot, case_id):
        seen = set()
        while True:
            if slot in seen:
                raise ValueError("endpoint successor selection is cyclic")
            seen.add(slot)
            selected, assignment, job = self.recovery.selection(slot)
            selected_request(selected, case_id)
            key = case_record_key(selected, case_id)
            raw = self.recovery.journal.journal.get("endpoint_attempt_successor", key)
            if raw is None:
                return slot, selected, assignment, job
            successor = EndpointAttemptSuccessor.model_validate_json(canonical_json_bytes(raw))
            if (
                successor.previous_selection_sha256 != digest(selected)
                or successor.case_id != case_id
            ):
                raise ValueError("endpoint successor changed its parent selection")
            child, child_assignment, _ = self.recovery.selection(successor.selection_slot)
            grant = selection_grant(child, child_assignment)
            if (
                not isinstance(grant, CohortCaseMinerGrant)
                or grant.attempt.order.case_id != case_id
            ):
                raise ValueError("endpoint successor changed its case")
            verify_replacement_parent(grant, selection_grant(selected, assignment))
            slot = successor.selection_slot

    async def advance(self, original_slot, case_id, *, video=None):
        slot, selected, assignment, _ = await run_owned_thread(self.current, original_slot, case_id)
        # Lost sends only poll the original response. Retirement performs the
        # remote fence before any replacement request can be constructed.
        sent = await self.dispatcher.dispatch(slot, case_id)
        result = await self.decisions.advance(slot, case_id)
        if result.certificate is None:
            return {
                "status": "pending",
                "reason": result.reason,
                "dispatch": sent["reason"],
                "selection_slot": slot,
            }
        if result.certificate.decision.disposition == "retain_response":
            return {
                "status": "completed",
                "reason": "certified_terminal_response",
                "selection_slot": slot,
                "certificate": result.certificate,
            }
        review = await run_owned_thread(self.decisions._review, slot, case_id)
        parent = selection_grant(selected, assignment)
        # A host may refresh an expired clip capability before the *next* intent.
        # An already retained request always preserves its exact original URL.
        plan = await self.requests.replacement(
            parent,
            result.certificate,
            review.retirement.retirement,
            selected.transport_policy,
            video
            if video is not None or self.requests.video_source is not None
            else selected_request(selected, case_id).video,
        )
        outcome = await self.requests.advance(plan)
        if outcome.selection is None:
            return {"status": "pending", "reason": outcome.reason, "selection_slot": slot}
        successor = EndpointAttemptSuccessor(
            schema="umi-cohort-endpoint-attempt-successor/1",
            previous_selection_sha256=digest(selected),
            case_id=case_id,
            selection_slot=selection_slot(outcome.selection),
        )
        # The certified child is durable before the pointer. A crash here finds
        # its frozen signing intent again instead of choosing another window.
        await run_owned_thread(
            self.recovery.journal.journal.put,
            "endpoint_attempt_successor",
            case_record_key(selected, case_id),
            successor,
        )
        return {
            "status": "pending",
            "reason": "certified_replacement_ready",
            "selection_slot": successor.selection_slot,
        }
