"""Bounded service dispatch and recovery using the miner's native routes.

The owning worker holds its process lease across these calls. Origin providers
must authenticate current cohort authority and fresh chain registration. A
selected request is sent once; uncertain sends use recovery and retirement.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Literal

import bittensor as bt
import httpx
from pydantic import Field

from .auth import REQUEST_BODY_SHA256_HEADER
from .competition_cohort_grant_delivery import verify_grant_receipt
from .competition_cohort_miner import SignedCohortMinerGrantReceipt
from .competition_cohort_service_grant import service_grant_slot
from .competition_cohort_service_requests import ServiceWorkRequests
from .competition_cohort_service_work import ServiceWorkAssignment
from .competition_origin import EndpointOriginCapture, public_https_origin
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread, wait_for_owned
from .config import Limits
from .endpoint_protocol import COHORT_GRANT_PATH, COHORT_RETIRE_PATH
from .endpoint_response_recovery import (
    RecoveredEndpointResponse,
    retrieve_endpoint_response,
    verify_recovered_response,
)
from .endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from .miner_admission import MinerAdmissionError, ProofBackedMinerWindowAuthority
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator import (
    ComponentResponseError,
    _header_size,
    _pinned_public_origin,
    _read_response_body,
    prepare_request_attempt,
    send_prepared_request,
)

ServiceOriginSource = Callable[[ServiceWorkAssignment], Awaitable[EndpointOriginCapture]]


class ServiceDispatchIntent(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-dispatch-intent/1"] = Field(alias="schema")
    grant_sha256: Hex32
    origin_evidence_sha256: Hex32
    started_at_unix_ns: Annotated[str, Field(pattern=r"^(?:0|[1-9][0-9]{0,19})$")]


@dataclass(frozen=True)
class ServiceTransportOutcome:
    reason: str
    response: RecoveredEndpointResponse | None = None
    retirement: SignedEndpointRetirementReceipt | None = None


class ServiceWorkTransport:
    def __init__(
        self,
        requests: ServiceWorkRequests,
        wallet,
        blocks,
        origin: ServiceOriginSource,
        *,
        timeout_seconds: float = 2400,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 3600
        ):
            raise ValueError("service transport timeout is outside bounds")
        self.requests, self.journal = requests, requests.journal
        self.wallet, self.blocks, self.origin = wallet, blocks, origin
        self.evaluator = bt.resolve_signer(wallet, role="hotkey").ss58_address
        if identity(self.evaluator) not in {identity(e.hotkey) for e in requests.policy.evaluators}:
            raise ValueError("service transport signer is outside evaluator policy")
        self.timeout, self.transport = timeout_seconds, transport
        self.limits = Limits.from_policy(requests.transport)

    def _response(self, grant, raw):
        return verify_recovered_response(
            raw,
            request=grant.body.request,
            validator_hotkey=grant.body.evaluator_hotkey,
            miner_hotkey=grant.body.assignment.admission.submission.submission.hotkey,
            limits=self.limits,
        )

    def _retirement(self, grant, raw):
        return verify_retirement_receipt(
            raw,
            request=grant.body.request,
            grant_sha256=digest(grant),
            miner_hotkey=grant.body.assignment.admission.submission.submission.hotkey,
            evaluator_hotkey=grant.body.evaluator_hotkey,
        )

    async def _capture(self, grant):
        capture = await wait_for_owned(self.origin(grant.body.assignment), timeout=self.timeout)
        submission = grant.body.assignment.admission.submission.submission
        if (
            capture.submission_sha256 != digest(submission)
            or identity(capture.hotkey) != identity(submission.hotkey)
            or public_https_origin(capture.origin) != public_https_origin(submission.endpoint_url)
        ):
            raise ValueError("service origin differs from its accepted submission")
        return capture

    async def _exchange(self, capture, path, value, maximum):
        body = canonical_json_bytes(value)

        async def exchange():
            origin, host, sni = await _pinned_public_origin(
                capture.origin, resolver=capture.transport_resolver()
            )
            headers = bt.http_auth.sign(
                self.wallet, method="POST", path=path, body=body, receiver_ss58=capture.hotkey
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
                transport=self.transport,
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                wire = client.build_request("POST", path, content=body, headers=headers)
                wire.extensions["sni_hostname"] = sni
                if _header_size(wire.headers) > self.limits.maximum_http_header_bytes:
                    raise ValueError("service request header bound")
                reply = await client.send(wire, stream=True)
                try:
                    if _header_size(reply.headers) > self.limits.maximum_http_header_bytes:
                        raise ValueError("service response header bound")
                    if reply.status_code != 200:
                        return None
                    return await _read_response_body(reply, maximum, prefix=bytearray())
                finally:
                    await reply.aclose()

        try:
            return await wait_for_owned(exchange(), timeout=self.timeout)
        except (OSError, httpx.HTTPError, asyncio.TimeoutError, ComponentResponseError):
            return None

    async def _recover(self, grant, capture):
        result = await retrieve_endpoint_response(
            grant.body.request,
            wallet=self.wallet,
            validator_hotkey=grant.body.evaluator_hotkey,
            miner_hotkey=capture.hotkey,
            miner_url=capture.origin,
            limits=self.limits,
            timeout_seconds=self.timeout,
            resolver=capture.transport_resolver(),
            transport=self.transport,
        )
        if result.response is not None:
            await run_owned_thread(
                self.journal.put,
                "service_response",
                service_grant_slot(grant.body),
                result.response,
            )
        return result.response

    async def advance(self, slot: str) -> ServiceTransportOutcome:
        grant = await run_owned_thread(self.requests.certificate, slot)
        if identity(grant.body.evaluator_hotkey) != identity(self.evaluator):
            raise ValueError("service transport signer differs from original evaluator")
        await run_owned_thread(
            self.journal.reserve_records,
            digest(["umi-service-transport-reservation/1", slot]),
            (
                RecordReservation("service_grant_delivery", slot, 64 * 1024),
                RecordReservation("service_dispatch_intent", slot, 2048),
                RecordReservation("service_response", slot, 144 * 1024),
                RecordReservation("service_retirement", slot, 16 * 1024),
            ),
        )
        raw = await run_owned_thread(self.journal.get, "service_response", slot)
        response = None if raw is None else await run_owned_thread(self._response, grant, raw)
        raw = await run_owned_thread(self.journal.get, "service_retirement", slot)
        retired = None if raw is None else self._retirement(grant, raw)
        if retired is None:
            capture = await self._capture(grant)
            raw = await run_owned_thread(self.journal.get, "service_grant_delivery", slot)
            if raw is None:
                raw = await self._exchange(capture, COHORT_GRANT_PATH, grant, 64 * 1024)
                if raw is None:
                    return ServiceTransportOutcome("grant_pending", response)
                receipt = SignedCohortMinerGrantReceipt.model_validate_json(raw)
                if canonical_json_bytes(receipt) != raw:
                    raise ValueError("service grant acknowledgement is noncanonical")
                verify_grant_receipt(receipt, grant)
                await run_owned_thread(self.journal.put, "service_grant_delivery", slot, receipt)
            else:
                verify_grant_receipt(raw, grant)
            intent = await run_owned_thread(self.journal.get, "service_dispatch_intent", slot)
            if intent is not None:
                intent = ServiceDispatchIntent.model_validate_json(canonical_json_bytes(intent))
                if intent.grant_sha256 != digest(grant):
                    raise ValueError("service dispatch intent changed its grant")
            if response is None and intent is None:
                # Grant acknowledgement may be slow. Acquire fresh origin and
                # authority after it, then check the transport window again.
                capture = await self._capture(grant)
                authority = ProofBackedMinerWindowAuthority(
                    policy=self.requests.transport, finalized_blocks=self.blocks
                )
                try:
                    await wait_for_owned(
                        authority.authorize(grant.body.request), timeout=self.timeout
                    )
                    live = bt.timelock.current_round() < grant.body.request.response_close_round
                except MinerAdmissionError:
                    live = False
                if live:
                    prepared = prepare_request_attempt(
                        grant.body.request, wallet=self.wallet, miner_hotkey=capture.hotkey
                    )
                    intent = ServiceDispatchIntent(
                        schema="umi-cohort-service-dispatch-intent/1",
                        grant_sha256=digest(grant),
                        origin_evidence_sha256=capture.evidence_sha256,
                        started_at_unix_ns=str(time.time_ns()),
                    )
                    await run_owned_thread(
                        self.journal.put, "service_dispatch_intent", slot, intent
                    )
                    outcome = await send_prepared_request(
                        prepared,
                        miner_url=capture.origin,
                        limits=self.limits,
                        timeout_seconds=self.timeout,
                        transport=self.transport,
                        resolver=capture.transport_resolver(),
                        maximum_request_transmissions=1,
                        maximum_response_bodies=1,
                    )
                    if all(
                        v is not None
                        for v in (
                            outcome.envelope_bytes,
                            outcome.response_signature,
                            outcome.received_at_unix_ns,
                        )
                    ):
                        try:
                            response = await run_owned_thread(
                                self._response,
                                grant,
                                RecoveredEndpointResponse(
                                    schema="umi-recovered-endpoint-response/1",
                                    envelope_hex=outcome.envelope_bytes.hex(),
                                    signature=outcome.response_signature,
                                    retrieval_started_at_unix_ns=intent.started_at_unix_ns,
                                    retrieved_at_unix_ns=outcome.received_at_unix_ns,
                                ),
                            )
                        except ValueError:
                            response = None
                        if response is not None:
                            await run_owned_thread(
                                self.journal.put, "service_response", slot, response
                            )
            if response is None:
                response = await self._recover(grant, capture)
            raw = await self._exchange(capture, COHORT_RETIRE_PATH, grant.body.request, 16 * 1024)
            if raw is None:
                return ServiceTransportOutcome("retirement_pending", response)
            retired = SignedEndpointRetirementReceipt.model_validate_json(raw)
            if canonical_json_bytes(retired) != raw:
                raise ValueError("service retirement acknowledgement is noncanonical")
            retired = self._retirement(grant, retired)
            if retired.receipt.result == "no_response_retained" and (
                capture.block <= grant.body.request.deadline_block
                or bt.timelock.current_round() < grant.body.request.response_close_round
            ):
                return ServiceTransportOutcome("request_window_open", response)
            # Retirement may race completion. Recover before recording that fence.
            if retired.receipt.result == "response_retained" and response is None:
                response = await self._recover(grant, capture)
                if response is None:
                    return ServiceTransportOutcome("retired_response_pending")
            self._agrees(retired, response)
            await run_owned_thread(self.journal.put, "service_retirement", slot, retired)
        self._agrees(retired, response)
        return ServiceTransportOutcome(
            "response_retained" if response else "retry_required", response, retired
        )

    @staticmethod
    def _agrees(retired, response):
        expected = (
            None
            if response is None
            else hashlib.sha256(bytes.fromhex(response.envelope_hex)).hexdigest()
        )
        if retired.receipt.response_sha256 != expected:
            raise ValueError("service retirement conflicts with original response")
