"""Deliver an immutable cohort grant and retain the miner's signed storage receipt."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass

import bittensor as bt
import httpx

from .auth import REQUEST_BODY_SHA256_HEADER
from .competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery, recovery_slot
from .competition_cohort_endpoint_selection import selection_grant
from .competition_cohort_miner import (
    MAX_COHORT_GRANT_BYTES,
    SignedCohortMinerGrantReceipt,
)
from .competition_cohort_miner_case import MinerGrant
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread
from .endpoint_protocol import COHORT_GRANT_PATH
from .open_competition import digest, identity, verify_signature
from .protocol import canonical_json_bytes
from .validator import (
    ComponentResponseError,
    _header_size,
    _pinned_public_origin,
    _read_response_body,
)


@dataclass(frozen=True)
class CohortGrantDeliveryOutcome:
    status: str
    reason: str
    receipt: SignedCohortMinerGrantReceipt | None = None


def verify_grant_receipt(value, grant: MinerGrant):
    value = SignedCohortMinerGrantReceipt.model_validate_json(canonical_json_bytes(value))
    miner = grant.attempt.order.job.submission.submission.hotkey
    if (
        value.receipt.grant_sha256 != digest(grant)
        or identity(value.receipt.miner_hotkey) != identity(miner)
        or identity(value.signature.hotkey) != identity(miner)
    ):
        raise ValueError("miner grant receipt differs from original assignment")
    verify_signature(value.receipt, value.signature)
    return value


class CohortEndpointGrantDelivery:
    def __init__(self, recovery: CohortEndpointResponseRecovery):
        self.recovery = recovery

    async def deliver(self, slot: str) -> CohortGrantDeliveryOutcome:
        recovery, journal = self.recovery, self.recovery.journal
        with journal.locked(recovery_slot(slot)):
            selected, assignment, job = recovery.selection(slot)
            grant = selection_grant(selected, assignment)
            key = digest(grant)
            old = journal.journal.get("miner_grant_delivery", key)
            if old is not None:
                return CohortGrantDeliveryOutcome(
                    "retained", "retained_miner_grant_receipt", verify_grant_receipt(old, grant)
                )
            await run_owned_thread(
                journal.journal.reserve_records,
                digest({"schema": "umi-cohort-miner-grant-delivery-reservation/1", "grant": key}),
                (RecordReservation("miner_grant_delivery", key, 64 * 1024),),
            )
            capture = await recovery.origin.collect(assignment)
            if capture.submission_sha256 != digest(job.submission.submission) or identity(
                capture.hotkey
            ) != identity(job.submission.submission.hotkey):
                raise ValueError("grant delivery origin differs from assignment")
            body = canonical_json_bytes(grant)
            if len(body) > MAX_COHORT_GRANT_BYTES:
                raise ValueError("cohort grant exceeds transport bound")
            timeout = journal.config.read_timeout_seconds

            async def exchange():
                origin, host, sni = await _pinned_public_origin(
                    capture.origin, resolver=capture.transport_resolver()
                )
                headers = bt.http_auth.sign(
                    recovery.wallet,
                    method="POST",
                    path=COHORT_GRANT_PATH,
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
                        "POST", COHORT_GRANT_PATH, content=body, headers=headers
                    )
                    wire.extensions["sni_hostname"] = sni
                    if _header_size(wire.headers) > 16 * 1024:
                        raise ComponentResponseError("resource_limit", "grant request header bound")
                    response = await client.send(wire, stream=True)
                    try:
                        if _header_size(response.headers) > 16 * 1024:
                            raise ComponentResponseError(
                                "resource_limit", "grant response header bound"
                            )
                        if response.status_code != 200:
                            return None
                        return await _read_response_body(response, 64 * 1024, prefix=bytearray())
                    finally:
                        await response.aclose()

            try:
                raw = await asyncio.wait_for(exchange(), timeout)
            except (OSError, httpx.HTTPError, TimeoutError, ComponentResponseError):
                return CohortGrantDeliveryOutcome("pending", "miner_grant_delivery_unavailable")
            if raw is None:
                return CohortGrantDeliveryOutcome("pending", "miner_grant_not_acknowledged")
            try:
                receipt = SignedCohortMinerGrantReceipt.model_validate_json(raw)
                if canonical_json_bytes(receipt) != raw:
                    raise ValueError("noncanonical grant receipt")
                receipt = verify_grant_receipt(receipt, grant)
            except ValueError:
                return CohortGrantDeliveryOutcome("pending", "miner_grant_receipt_invalid")
            await run_owned_thread(journal.journal.put, "miner_grant_delivery", key, receipt)
            return CohortGrantDeliveryOutcome("retained", "miner_grant_receipt_retained", receipt)
