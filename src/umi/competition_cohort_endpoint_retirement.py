"""Reconcile an old endpoint request without authorizing replacement or scoring.

A signed absence receipt closes protocol execution only. It cannot prove that
inference never ran, supply original timing evidence, or bypass retry review.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Literal

import bittensor as bt
import httpx
from pydantic import Field

from .auth import REQUEST_BODY_SHA256_HEADER
from .competition_cohort_endpoint_recovery import (
    CohortEndpointResponseRecovery,
    CohortRecoveredEndpointCase,
    recovery_slot,
)
from .competition_cohort_endpoint_selection import case_record_key, selection_grant
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread
from .config import Limits
from .endpoint_protocol import COHORT_RETIRE_PATH
from .endpoint_response_recovery import retrieve_endpoint_response
from .endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator import (
    ComponentResponseError,
    _header_size,
    _pinned_public_origin,
    _read_response_body,
)


class CohortRetiredEndpointCase(StrictProtocolModel):
    schema_: Literal["umi-cohort-retired-endpoint-case/1"] = Field(alias="schema")
    selection_sha256: Hex32
    case_id: Hex32
    origin_evidence_sha256: Hex32
    observed_block: int = Field(ge=0)
    observed_round: int = Field(ge=0)
    retirement: SignedEndpointRetirementReceipt
    original_receipt_timing_proven: Literal[False] = False
    replacement_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


@dataclass(frozen=True)
class CohortRetirementOutcome:
    status: Literal["pending", "retained"]
    reason: str
    value: CohortRetiredEndpointCase | None = None


class CohortEndpointRetirement:
    def __init__(self, recovery: CohortEndpointResponseRecovery):
        self.recovery = recovery

    def _verify(self, value, selected, assignment, job, case_id):
        value = CohortRetiredEndpointCase.model_validate_json(canonical_json_bytes(value))
        if value.selection_sha256 != digest(selected) or value.case_id != case_id:
            raise ValueError("retirement differs from selected endpoint case")
        request = self.recovery._case(selected, job, case_id)
        grant = selection_grant(selected, assignment)
        receipt = verify_retirement_receipt(
            value.retirement,
            request=request,
            grant_sha256=digest(grant),
            miner_hotkey=job.submission.submission.hotkey,
            evaluator_hotkey=job.evaluator_hotkey,
        )
        if receipt.receipt.result == "no_response_retained" and (
            value.observed_block <= request.deadline_block
            or value.observed_round < request.response_close_round
        ):
            raise ValueError("absence receipt precedes request expiry")
        return value

    def _response_agrees(self, receipt, recovered):
        expected = receipt.receipt.response_sha256
        if expected is None:
            return recovered is None
        return (
            recovered is not None
            and hashlib.sha256(bytes.fromhex(recovered.response.envelope_hex)).hexdigest()
            == expected
        )

    def retained(self, slot: str, case_id: str) -> CohortRetiredEndpointCase | None:
        recovery = self.recovery
        selected, assignment, job = recovery.selection(slot)
        recovery._case(selected, job, case_id)
        raw = recovery.journal.journal.get(
            "endpoint_retired_case", case_record_key(selected, case_id)
        )
        if raw is None:
            return None
        value = self._verify(raw, selected, assignment, job, case_id)
        if not self._response_agrees(value.retirement, recovery._retained(selected, job, case_id)):
            raise ValueError("retirement and retained response disagree")
        return value

    async def retire(self, slot: str, case_id: str) -> CohortRetirementOutcome:
        recovery, journal = self.recovery, self.recovery.journal
        with journal.locked(recovery_slot(slot)):
            selected, assignment, job = recovery.selection(slot)
            request = recovery._case(selected, job, case_id)
            old = self.retained(slot, case_id)
            if old is not None:
                return CohortRetirementOutcome("retained", "retained_endpoint_retirement", old)
            key = case_record_key(selected, case_id)
            await run_owned_thread(
                journal.journal.reserve_records,
                digest({"schema": "umi-cohort-endpoint-retirement-reservation/1", "case": key}),
                (RecordReservation("endpoint_retired_case", key, 16 * 1024),),
            )
            capture = await recovery.origin.collect(assignment)
            if capture.submission_sha256 != digest(job.submission.submission) or identity(
                capture.hotkey
            ) != identity(job.submission.submission.hotkey):
                raise ValueError("retirement origin differs from assigned miner")
            body = canonical_json_bytes(request)
            limits = Limits.from_policy(selected.transport_policy)
            if len(body) > limits.maximum_request_body_bytes:
                raise ValueError("retirement request exceeds transport bound")
            timeout = journal.config.read_timeout_seconds

            async def exchange():
                origin, host, sni = await _pinned_public_origin(
                    capture.origin, resolver=capture.transport_resolver()
                )
                headers = bt.http_auth.sign(
                    recovery.wallet,
                    method="POST",
                    path=COHORT_RETIRE_PATH,
                    body=body,
                    receiver_ss58=capture.hotkey,
                )
                headers.update(
                    {
                        "Content-Type": "application/json",
                        "Accept-Encoding": "identity",
                        "Host": host,
                        REQUEST_BODY_SHA256_HEADER: hashlib.sha256(body).hexdigest(),
                    }
                )
                async with httpx.AsyncClient(
                    base_url=origin,
                    transport=recovery.transport,
                    timeout=timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    wire = client.build_request(
                        "POST", COHORT_RETIRE_PATH, content=body, headers=headers
                    )
                    wire.extensions["sni_hostname"] = sni
                    if _header_size(wire.headers) > limits.maximum_http_header_bytes:
                        raise ComponentResponseError("resource_limit", "retirement header bound")
                    response = await client.send(wire, stream=True)
                    try:
                        if _header_size(response.headers) > limits.maximum_http_header_bytes:
                            raise ComponentResponseError(
                                "resource_limit", "retirement header bound"
                            )
                        if response.status_code != 200:
                            return None
                        return await _read_response_body(response, 16 * 1024, prefix=bytearray())
                    finally:
                        await response.aclose()

            try:
                raw = await asyncio.wait_for(exchange(), timeout)
            except (OSError, httpx.HTTPError, TimeoutError, ComponentResponseError):
                return CohortRetirementOutcome("pending", "retirement_transport_unavailable")
            if raw is None:
                return CohortRetirementOutcome("pending", "retirement_not_acknowledged")
            try:
                receipt = SignedEndpointRetirementReceipt.model_validate_json(raw)
                if canonical_json_bytes(receipt) != raw:
                    raise ValueError("noncanonical retirement receipt")
                value = self._verify(
                    CohortRetiredEndpointCase(
                        schema="umi-cohort-retired-endpoint-case/1",
                        selection_sha256=digest(selected),
                        case_id=case_id,
                        origin_evidence_sha256=capture.evidence_sha256,
                        observed_block=capture.block,
                        observed_round=bt.timelock.current_round(),
                        retirement=receipt,
                    ),
                    selected,
                    assignment,
                    job,
                    case_id,
                )
            except ValueError:
                return CohortRetirementOutcome("pending", "retirement_receipt_invalid")
            recovered = recovery._retained(selected, job, case_id)
            if receipt.receipt.result == "response_retained" and recovered is None:
                outcome = await retrieve_endpoint_response(
                    request,
                    wallet=recovery.wallet,
                    validator_hotkey=job.evaluator_hotkey,
                    miner_hotkey=job.submission.submission.hotkey,
                    miner_url=capture.origin,
                    resolver=capture.transport_resolver(),
                    limits=limits,
                    timeout_seconds=timeout,
                    transport=recovery.transport,
                )
                if outcome.response is None:
                    return CohortRetirementOutcome("pending", "retirement_response_pending")
                recovered = CohortRecoveredEndpointCase(
                    schema="umi-cohort-recovered-endpoint-case/1",
                    selection_sha256=digest(selected),
                    case_id=case_id,
                    origin_evidence_sha256=capture.evidence_sha256,
                    response=outcome.response,
                )
            if not self._response_agrees(receipt, recovered):
                return CohortRetirementOutcome("pending", "retirement_response_conflict")
            records = [("endpoint_retired_case", key, value)]
            if recovered is not None:
                records.append(("endpoint_recovered_case", key, recovered))
            # Commit the receipt together with its original response, then ACK.
            # Failure or cancellation cannot authorize a replacement.
            await run_owned_thread(journal.journal.put_many, tuple(records))
            return CohortRetirementOutcome("retained", "endpoint_retirement_retained", value)
