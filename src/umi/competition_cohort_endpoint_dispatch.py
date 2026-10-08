"""Bound selected-request transmission; recover uncertain sends without re-inference.

Dispatch intent commits before the network call. After a crash, the miner's
sealed response or certified retirement resolves that attempt. Receipt times
remain host observations and do not establish original publication timing.
"""

from __future__ import annotations

import time
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field

from .anchors import VerifiedAuthEvidence
from .competition_cohort_endpoint_recovery import CohortRecoveredEndpointCase, recovery_slot
from .competition_cohort_endpoint_retirement import CohortEndpointRetirement
from .competition_cohort_endpoint_selection import (
    case_record_key,
    selected_request,
    selection_grant,
    selection_slot,
)
from .competition_cohort_grant_delivery import CohortEndpointGrantDelivery, verify_grant_receipt
from .competition_cohort_request_admission import CohortRequestWindowAuthority
from .competition_cohort_window_store import WindowAdmissionHeld
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread, wait_for_owned
from .config import Limits
from .endpoint_response_recovery import RecoveredEndpointResponse, verify_recovered_response
from .miner_admission import MinerAdmissionError
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator import PreparedRequestAttempt, prepare_request_attempt, send_prepared_request


class CohortDispatchIntent(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-dispatch-intent/1"] = Field(alias="schema")
    selection_sha256: Hex32
    case_id: Hex32
    origin_evidence_sha256: Hex32
    origin_block: Annotated[int, Field(ge=0)]
    auth_headers: Annotated[tuple[tuple[str, str], ...], Field(min_length=1, max_length=8)]
    started_at_unix_ns: Annotated[str, Field(pattern=r"^(?:0|[1-9][0-9]{0,19})$")]


class CohortDispatchRetryIntent(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-dispatch-retry-intent/1"] = Field(alias="schema")
    original_intent_sha256: Hex32
    transmission_number: Literal[2] = 2
    intent: CohortDispatchIntent


class CohortDispatchReceipt(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-dispatch-receipt/1"] = Field(alias="schema")
    intent_sha256: Hex32
    finished_at_unix_ns: Annotated[str, Field(pattern=r"^(?:0|[1-9][0-9]{0,19})$")]
    received_at_unix_ns: str | None
    envelope_hex: Annotated[str, Field(max_length=128 * 1024)] | None
    response_signature: Annotated[str, Field(max_length=130)] | None
    received_body_prefix_hex: Annotated[str, Field(max_length=128 * 1024)] | None
    received_bytes_sha256: Hex32 | None
    failure_code: Annotated[str, Field(max_length=128)] | None
    chain_submission_authorized: Literal[False] = False


class CohortEndpointDispatcher:
    def __init__(self, recovery, finalized_blocks):
        self.recovery, self.finalized_blocks = recovery, finalized_blocks

    async def _reserve_window(self, selected, assignment, case_id):
        if self.recovery.windows is None:
            return None
        try:
            status = await self.recovery.windows.reserve(
                selection_grant(selected, assignment), selected_request(selected, case_id)
            )
        except (OSError, WindowAdmissionHeld):
            return {"status": "pending", "reason": "miner_window_admission_pending"}
        if status == "retired":
            return {"status": "pending", "reason": "dispatch_request_retired"}
        if status != "reserved":
            raise ValueError("window owner did not reserve the selected request")
        return None

    def _intent(self, selected, job, case_id):
        journal = self.recovery.journal.journal
        key = case_record_key(selected, case_id)
        raw = journal.get("endpoint_dispatch_intent", key)
        if raw is None:
            return None
        intent = CohortDispatchIntent.model_validate_json(canonical_json_bytes(raw))
        return self._verify_intent(selected, job, case_id, intent)

    def _verify_intent(self, selected, job, case_id, intent):
        request = selected_request(selected, case_id)
        if intent.selection_sha256 != digest(selected) or intent.case_id != case_id:
            raise ValueError("dispatch intent changed its selected request")
        auth = VerifiedAuthEvidence.from_headers(
            dict(intent.auth_headers),
            request=request,
            expected_validator_hotkey=job.evaluator_hotkey,
            expected_miner_hotkey=job.submission.submission.hotkey,
        )
        PreparedRequestAttempt(
            request,
            canonical_json_bytes(request),
            job.evaluator_hotkey,
            job.submission.submission.hotkey,
            intent.auth_headers,
            auth,
        )
        return intent

    def _response(self, selected, job, case_id, intent, receipt_kind="endpoint_dispatch_receipt"):
        """Recover a committed valid wire reply even if the miner is now offline."""
        with self.recovery.journal.locked(recovery_slot(selection_slot(selected))):
            return self._response_locked(selected, job, case_id, intent, receipt_kind)

    def _response_locked(self, selected, job, case_id, intent, receipt_kind):
        journal = self.recovery.journal.journal
        key = case_record_key(selected, case_id)
        raw = journal.get(receipt_kind, key)
        if raw is None:
            return None
        receipt = CohortDispatchReceipt.model_validate_json(canonical_json_bytes(raw))
        if receipt.intent_sha256 != digest(intent) or int(receipt.finished_at_unix_ns) < int(
            intent.started_at_unix_ns
        ):
            raise ValueError("dispatch receipt differs from original intent")
        if (
            receipt.envelope_hex is None
            or receipt.response_signature is None
            or receipt.received_at_unix_ns is None
        ):
            return None
        try:
            response = verify_recovered_response(
                RecoveredEndpointResponse(
                    schema="umi-recovered-endpoint-response/1",
                    envelope_hex=receipt.envelope_hex,
                    signature=receipt.response_signature,
                    retrieval_started_at_unix_ns=intent.started_at_unix_ns,
                    retrieved_at_unix_ns=receipt.received_at_unix_ns,
                ),
                request=selected_request(selected, case_id),
                validator_hotkey=job.evaluator_hotkey,
                miner_hotkey=job.submission.submission.hotkey,
                limits=Limits.from_policy(selected.transport_policy),
            )
        except ValueError:
            # Invalid/partial wire replies stay retained but are not responses.
            return None
        old = self.recovery._retained(selected, job, case_id)
        if old is not None:
            if (old.response.envelope_hex, old.response.signature) != (
                response.envelope_hex,
                response.signature,
            ):
                raise ValueError("wire reply conflicts with retained miner response")
            return old
        value = CohortRecoveredEndpointCase(
            schema="umi-cohort-recovered-endpoint-case/1",
            selection_sha256=digest(selected),
            case_id=case_id,
            origin_evidence_sha256=intent.origin_evidence_sha256,
            response=response,
        )
        journal.put("endpoint_recovered_case", key, value)
        return value

    def _retry_intent(self, selected, job, case_id, original):
        raw = self.recovery.journal.journal.get(
            "endpoint_dispatch_retry_intent", case_record_key(selected, case_id)
        )
        if raw is None:
            return None
        retry = CohortDispatchRetryIntent.model_validate_json(canonical_json_bytes(raw))
        if retry.original_intent_sha256 != digest(original) or int(
            retry.intent.started_at_unix_ns
        ) < int(original.started_at_unix_ns):
            raise ValueError("dispatch retry differs from original intent")
        self._verify_intent(selected, job, case_id, retry.intent)
        return retry

    async def _retry(self, slot, selected, assignment, job, case_id, original):
        recovery, journal = self.recovery, self.recovery.journal
        retry = await run_owned_thread(self._retry_intent, selected, job, case_id, original)
        if retry is not None:
            response = await run_owned_thread(
                self._response,
                selected,
                job,
                case_id,
                retry.intent,
                "endpoint_dispatch_retry_receipt",
            )
            if response is not None:
                return {"status": "recovered", "reason": "retained_dispatch_retry_response"}
        # An unknown first or second outcome is not proof of absence. Try the
        # miner's sealed response before any additional transmission.
        outcome = await recovery.recover(slot, case_id)
        if outcome.status == "recovered" or retry is not None:
            return {"status": outcome.status, "reason": outcome.reason}
        limits = Limits.from_policy(selected.transport_policy)
        if (
            min(
                limits.maximum_request_transmissions_per_assignment,
                limits.maximum_response_bodies_per_assignment,
            )
            < 2
        ):
            return {"status": "pending", "reason": "dispatch_transmission_budget_exhausted"}
        retired = await run_owned_thread(CohortEndpointRetirement(recovery).retained, slot, case_id)
        if retired is not None:
            return {"status": "pending", "reason": "dispatch_request_retired"}
        request = selected_request(selected, case_id)
        timeout = journal.config.read_timeout_seconds
        authority = CohortRequestWindowAuthority(
            policy=selected.transport_policy,
            finalized_blocks=self.finalized_blocks,
            job=job,
            attempt_number=selection_grant(selected, assignment).attempt.order.attempt_number,
        )
        try:
            await wait_for_owned(authority.authorize(request), timeout=timeout)
        except MinerAdmissionError as error:
            return {"status": "pending", "reason": error.reason_code}
        if bt.timelock.current_round() >= request.response_close_round:
            return {"status": "pending", "reason": "request_response_window_elapsed"}
        capture = await recovery.origin.collect(assignment)
        if capture.submission_sha256 != digest(job.submission.submission) or identity(
            capture.hotkey
        ) != identity(job.submission.submission.hotkey):
            raise ValueError("dispatch retry origin differs from its assigned miner")
        held = await self._reserve_window(selected, assignment, case_id)
        if held is not None:
            return held
        try:
            await wait_for_owned(authority.authorize(request), timeout=timeout)
        except MinerAdmissionError as error:
            return {"status": "pending", "reason": error.reason_code}
        if bt.timelock.current_round() >= request.response_close_round:
            return {"status": "pending", "reason": "request_response_window_elapsed"}
        key = case_record_key(selected, case_id)
        await run_owned_thread(
            journal.journal.reserve_records,
            digest(["umi-cohort-dispatch-retry-reservation/1", key]),
            (
                RecordReservation("endpoint_dispatch_retry_intent", key, 16 * 1024),
                RecordReservation("endpoint_dispatch_retry_receipt", key, 300 * 1024),
            ),
        )
        # Keep request/video bytes immutable; only refresh HTTP authentication.
        prepared = prepare_request_attempt(
            request, wallet=recovery.wallet, miner_hotkey=job.submission.submission.hotkey
        )
        retry = CohortDispatchRetryIntent(
            schema="umi-cohort-endpoint-dispatch-retry-intent/1",
            original_intent_sha256=digest(original),
            intent=CohortDispatchIntent(
                schema="umi-cohort-endpoint-dispatch-intent/1",
                selection_sha256=digest(selected),
                case_id=case_id,
                origin_evidence_sha256=capture.evidence_sha256,
                origin_block=capture.block,
                auth_headers=prepared.auth_headers,
                started_at_unix_ns=str(time.time_ns()),
            ),
        )
        # An intent without its receipt consumes this final transmission too.
        # Restart can recover/retire it, but cannot send a third request.
        await run_owned_thread(journal.journal.put, "endpoint_dispatch_retry_intent", key, retry)
        await self._send(
            selected,
            job,
            case_id,
            retry.intent,
            prepared,
            capture,
            "endpoint_dispatch_retry_receipt",
        )
        response = await run_owned_thread(
            self._response, selected, job, case_id, retry.intent, "endpoint_dispatch_retry_receipt"
        )
        return {
            "status": "recovered" if response else "pending",
            "reason": "dispatch_retry_response_retained" if response else "dispatch_retry_pending",
        }

    async def _send(self, selected, job, case_id, intent, prepared, capture, receipt_kind):
        recovery, journal = self.recovery, self.recovery.journal
        # One exchange per committed intent; no outer timeout may discard a
        # body already read by the native transport.
        outcome = await send_prepared_request(
            prepared,
            miner_url=capture.origin,
            limits=Limits.from_policy(selected.transport_policy),
            timeout_seconds=journal.config.read_timeout_seconds,
            transport=recovery.transport,
            resolver=capture.transport_resolver(),
            maximum_request_transmissions=1,
            maximum_response_bodies=1,
        )
        receipt = CohortDispatchReceipt(
            schema="umi-cohort-endpoint-dispatch-receipt/1",
            intent_sha256=digest(intent),
            finished_at_unix_ns=str(time.time_ns()),
            received_at_unix_ns=outcome.received_at_unix_ns,
            envelope_hex=None if outcome.envelope_bytes is None else outcome.envelope_bytes.hex(),
            response_signature=outcome.response_signature,
            received_body_prefix_hex=None
            if outcome.received_body_prefix is None
            else outcome.received_body_prefix.hex(),
            received_bytes_sha256=outcome.received_bytes_sha256,
            failure_code=outcome.failure_code,
        )
        await run_owned_thread(
            journal.journal.put, receipt_kind, case_record_key(selected, case_id), receipt
        )

    async def dispatch(self, slot, case_id):
        recovery, journal = self.recovery, self.recovery.journal
        selected, assignment, job = recovery.selection(slot)
        key = case_record_key(selected, case_id)
        # Separate from the response/retirement mutex; miner retirement owns the
        # remote execution fence. At most two durable intents consume the
        # policy transmission budget; a lost receipt never authorizes a third.
        with journal.locked(digest(["umi-cohort-endpoint-dispatch-lock/1", key])):
            prior = await run_owned_thread(recovery.retained, slot, case_id)
            if prior is not None:
                return {"status": "recovered", "reason": "retained_original_response"}
            intent = await run_owned_thread(self._intent, selected, job, case_id)
            if intent is not None:
                response = await run_owned_thread(self._response, selected, job, case_id, intent)
                if response is not None:
                    return {"status": "recovered", "reason": "retained_dispatch_response"}
                return await self._retry(slot, selected, assignment, job, case_id, intent)
            delivery = await CohortEndpointGrantDelivery(recovery).deliver(slot)
            if delivery.receipt is None:
                return {"status": "pending", "reason": delivery.reason}
            verify_grant_receipt(delivery.receipt, selection_grant(selected, assignment))
            request = selected_request(selected, case_id)
            timeout = journal.config.read_timeout_seconds
            # Each side independently checks the live transport window.
            authority = CohortRequestWindowAuthority(
                policy=selected.transport_policy,
                finalized_blocks=self.finalized_blocks,
                job=job,
                attempt_number=selection_grant(selected, assignment).attempt.order.attempt_number,
            )
            try:
                await wait_for_owned(authority.authorize(request), timeout=timeout)
            except MinerAdmissionError as error:
                return {"status": "pending", "reason": error.reason_code}
            if bt.timelock.current_round() >= request.response_close_round:
                return {"status": "pending", "reason": "request_response_window_elapsed"}
            capture = await recovery.origin.collect(assignment)
            if capture.submission_sha256 != digest(job.submission.submission) or identity(
                capture.hotkey
            ) != identity(job.submission.submission.hotkey):
                raise ValueError("dispatch origin differs from its assigned miner")
            held = await self._reserve_window(selected, assignment, case_id)
            if held is not None:
                return held
            # Slow origin proofs may cross either deadline. Recheck before intent.
            try:
                await wait_for_owned(authority.authorize(request), timeout=timeout)
            except MinerAdmissionError as error:
                return {"status": "pending", "reason": error.reason_code}
            if bt.timelock.current_round() >= request.response_close_round:
                return {"status": "pending", "reason": "request_response_window_elapsed"}
            await run_owned_thread(
                journal.journal.reserve_records,
                digest(["umi-cohort-dispatch-reservation/1", key]),
                (RecordReservation("endpoint_dispatch_receipt", key, 300 * 1024),),
            )
            prepared = prepare_request_attempt(
                request, wallet=recovery.wallet, miner_hotkey=job.submission.submission.hotkey
            )
            intent = CohortDispatchIntent(
                schema="umi-cohort-endpoint-dispatch-intent/1",
                selection_sha256=digest(selected),
                case_id=case_id,
                origin_evidence_sha256=capture.evidence_sha256,
                origin_block=capture.block,
                auth_headers=prepared.auth_headers,
                started_at_unix_ns=str(time.time_ns()),
            )
            await run_owned_thread(journal.journal.put, "endpoint_dispatch_intent", key, intent)
            await self._send(
                selected, job, case_id, intent, prepared, capture, "endpoint_dispatch_receipt"
            )
            response = await run_owned_thread(self._response, selected, job, case_id, intent)
            return {
                "status": "recovered" if response else "pending",
                "reason": "dispatch_response_retained" if response else "dispatch_outcome_pending",
            }
