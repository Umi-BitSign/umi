"""Authenticated lookup of an original FIFO service assignment.

The signed challenge binds the configured owner and exact miner claim. It is
not a request grant: reviewers must still verify admission, history and proofs.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import Literal

from pydantic import Field

from .competition_cohort_review_export import review_export_limits
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_cohort_service_queue import ServiceWorkQueue
from .competition_cohort_service_work import (
    MAX_SERVICE_REQUEST_BYTES,
    ServiceWorkAssignment,
    SignedServiceWorkClaim,
    review_service_assignment,
    verify_service_claim,
)
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

PATH = "/internal/cohorts/service-work"


class ServiceWorkLookup(StrictProtocolModel):
    schema_: Literal["umi-service-work-lookup/1"] = Field(alias="schema")
    claim: SignedServiceWorkClaim
    challenge: Hex32


class ServiceWorkResponse(StrictProtocolModel):
    schema_: Literal["umi-service-work-response/1"] = Field(alias="schema")
    assignment: ServiceWorkAssignment
    challenge: Hex32


class SignedServiceWorkResponse(StrictProtocolModel):
    response: ServiceWorkResponse
    signature: Signature


class ServiceWorkExporter:
    def __init__(
        self,
        queue: ServiceWorkQueue,
        owner: str,
        sign: Callable[[ServiceWorkResponse], Awaitable[Signature]],
        *,
        timeout_seconds=30,
    ):
        review_export_limits(MAX_SERVICE_REQUEST_BYTES, timeout_seconds)
        self.queue, self.owner, self.sign = queue, identity(owner), sign
        if self.owner not in {identity(e.hotkey) for e in queue.policy.evaluators}:
            raise ValueError("service export owner is outside configured policy")
        self.maximum_bytes, self.timeout_seconds = MAX_SERVICE_REQUEST_BYTES, timeout_seconds

    async def respond(self, request: ServiceWorkLookup) -> bytes:
        request = ServiceWorkLookup.model_validate_json(canonical_json_bytes(request))
        verify_service_claim(request.claim)
        assignment = await run_owned_thread(self.queue.assignment, request.claim)
        response = ServiceWorkResponse(
            schema="umi-service-work-response/1",
            assignment=assignment,
            challenge=request.challenge,
        )
        signature = await wait_for_owned(self.sign(response), timeout=self.timeout_seconds)
        if identity(signature.hotkey) != self.owner:
            raise ValueError("service export was signed by another owner")
        verify_signature(response, signature)
        raw = canonical_json_bytes(
            SignedServiceWorkResponse(response=response, signature=signature)
        )
        if len(raw) > self.maximum_bytes:
            raise OSError("service export exceeds capacity; preserve and retry")
        return raw


class ServiceWorkReader:
    def __init__(
        self,
        policy: CompetitionPolicy,
        owner: str,
        fetch: Callable[[ServiceWorkLookup], Awaitable[bytes]],
        *,
        timeout_seconds=30,
    ):
        review_export_limits(MAX_SERVICE_REQUEST_BYTES, timeout_seconds)
        self.policy, self.owner, self.fetch = policy, identity(owner), fetch
        if self.owner not in {identity(e.hotkey) for e in policy.evaluators}:
            raise ValueError("service reader owner is outside configured policy")
        self.timeout = timeout_seconds

    async def __call__(self, assignment: ServiceWorkAssignment) -> SignedServiceWorkResponse:
        assignment = review_service_assignment(assignment, self.policy)
        request = ServiceWorkLookup(
            schema="umi-service-work-lookup/1",
            claim=assignment.admission.claim,
            challenge=secrets.token_hex(32),
        )
        raw = await wait_for_owned(self.fetch(request), timeout=self.timeout)
        if type(raw) is not bytes or len(raw) > MAX_SERVICE_REQUEST_BYTES:
            raise ValueError("service lookup response exceeds its byte bound")
        signed = SignedServiceWorkResponse.model_validate_json(raw)
        if (
            canonical_json_bytes(signed) != raw
            or identity(signed.signature.hotkey) != self.owner
            or signed.response.challenge != request.challenge
            or signed.response.assignment != assignment
        ):
            raise ValueError("service owner lookup changed its challenge or original assignment")
        verify_signature(signed.response, signed.signature)
        return signed


def service_work_routes(exporter: ServiceWorkExporter, *, token: str):
    return phase_review_routes(exporter, token=token, path=PATH, request_model=ServiceWorkLookup)


class ServiceWorkHTTPClient(PhaseReviewHTTPClient[ServiceWorkLookup]):
    def __init__(self, client, origin, *, token, timeout_seconds=30):
        super().__init__(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=MAX_SERVICE_REQUEST_BYTES,
            timeout_seconds=timeout_seconds,
        )
