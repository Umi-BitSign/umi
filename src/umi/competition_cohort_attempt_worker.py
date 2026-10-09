"""Resume one endpoint case through dispatch, retirement and certified replacement."""

from __future__ import annotations

from typing import Literal

import bittensor as bt
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

    def _answered_peers(self, original_slot, case_id, job):
        """Find authenticated answers still occupying this miner's old windows."""
        pending = []
        for case in job.cases:
            if case.case_id == case_id:
                continue
            peer_slot, _, _, _ = self.current(original_slot, case.case_id)
            if self.recovery.retained(peer_slot, case.case_id) is None:
                continue
            if self.decisions.retirement.retained(peer_slot, case.case_id) is None:
                pending.append((peer_slot, case.case_id))
        return pending

    def phase(self, original_slot, case_id):
        slot, selected, _, _ = self.current(original_slot, case_id)
        if self.decisions.retirement.retained(slot, case_id) is not None:
            return "certification"
        if (
            self.recovery.journal.journal.get(
                "endpoint_dispatch_intent", case_record_key(selected, case_id)
            )
            is not None
            or self.recovery.retained(slot, case_id) is not None
            or bt.timelock.current_round()
            >= selected_request(selected, case_id).response_close_round
        ):
            # An expired unsent request still needs native retirement and a
            # certified replacement. A scheduling hint never proves absence.
            return "recovery"
        return "dispatch"

    async def advance(self, original_slot, case_id, *, video=None, one_stage=False):
        slot, selected, assignment, job = await run_owned_thread(
            self.current, original_slot, case_id
        )
        phase = await run_owned_thread(self.phase, original_slot, case_id) if one_stage else None
        # A response can be saved while its retirement HTTP exchange is held.
        # Rotating to another case must not leave that answered window occupying
        # the miner's slots. Fence existing answers before transmitting more work;
        # do not wait for their scoring or reviewer votes, or rerun those answers.
        if (
            phase != "certification"
            and await run_owned_thread(self.recovery.retained, slot, case_id) is None
        ):
            peers = await run_owned_thread(self._answered_peers, original_slot, case_id, job)
            for peer_slot, peer_case in peers:
                retired = await self.decisions.retirement.retire(peer_slot, peer_case)
                if retired.value is None:
                    return {
                        "status": "pending",
                        "reason": "answered_peer_retirement_pending",
                        "retirement_reason": retired.reason,
                        "selection_slot": slot,
                    }
        # Recover the sealed response first, then permit one durable retry of
        # the original request within its signed transmission/window budget.
        # Retirement fences execution before a replacement can be constructed.
        dispatcher = CohortEndpointDispatcher(
            self.recovery, self.requests.signer.blocks_for(selected.transport_policy)
        )
        sent = (
            {"status": "pending", "reason": "retirement_retained"}
            if phase == "certification"
            else await dispatcher.dispatch(slot, case_id)
        )
        if (
            sent["status"] == "pending"
            and sent["reason"].startswith(("miner_grant_", "miner_window_"))
            and bt.timelock.current_round()
            < selected_request(selected, case_id).response_close_round
        ):
            return {
                "status": "pending",
                "reason": sent["reason"],
                "selection_slot": slot,
            }
        # A miner can retain a grant even when its acknowledgment was lost.
        # After expiry, a failed grant retry must not prevent asking that miner
        # for the original request's signed retirement. Unknown grants remain
        # pending: neither the clock nor the failed delivery proves absence.
        if one_stage and phase != "certification":
            if phase == "dispatch":
                return {"status": "pending", "reason": sent["reason"], "selection_slot": slot}
            retired = await self.decisions.retirement.retire(slot, case_id)
            return {
                "status": "pending",
                "reason": "retirement_retained" if retired.value is not None else retired.reason,
                "selection_slot": slot,
            }
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
