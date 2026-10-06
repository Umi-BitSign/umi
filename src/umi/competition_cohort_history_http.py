"""Fresh owner-authenticated history, with original native decision evidence."""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import Literal

from pydantic import Field

from .canonical_reuse import canonical_json_reuse
from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_intake import CohortIntake
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_review_export import MAX_EXPORT_BYTES, review_export_limits
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

PATH = "/internal/cohorts/history"


class CohortHistoryRequest(StrictProtocolModel):
    schema_: Literal["umi-cohort-history-request/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    challenge: Hex32


class CohortHistoryResponse(StrictProtocolModel):
    schema_: Literal["umi-cohort-history-response/1"] = Field(alias="schema")
    source: CohortOrderHistory
    challenge: Hex32


class SignedCohortHistoryResponse(StrictProtocolModel):
    response: CohortHistoryResponse
    signature: Signature


class CohortHistoryExporter:
    def __init__(self, intake: CohortIntake, owner: str, sign, *, timeout_seconds=2400):
        review_export_limits(MAX_EXPORT_BYTES, timeout_seconds)
        self.intake, self.owner, self.sign = intake, identity(owner), sign
        if self.owner not in {identity(e.hotkey) for e in intake.policy.evaluators}:
            raise ValueError("history owner is outside configured evaluator set")
        self.maximum_bytes, self.timeout_seconds = MAX_EXPORT_BYTES, timeout_seconds

    def read(self, cohort):
        self.intake._allowed(cohort)
        with self.intake._connection() as (_, store):
            history = store.published_history(cohort)
            keys = sorted(
                {
                    t.transition.evidence_sha256
                    for t in history.transitions
                    if t.transition.operation != "revoke"
                }
            )
            decisions, size = [], len(canonical_json_bytes(history))
            for key in keys:
                value = store.source(cohort, key, CohortDecisionInput)
                size += len(canonical_json_bytes(value))
                if size > self.maximum_bytes - 2048:
                    raise ValueError("history response exceeds delivery capacity")
                decisions.append(value)
            result = CohortOrderHistory(history=history, decisions=tuple(decisions))
            result.inputs()
            return result

    async def respond(self, request: CohortHistoryRequest) -> bytes:
        request = CohortHistoryRequest.model_validate_json(canonical_json_bytes(request))
        response = await run_owned_thread(self._response, request)
        signature = await wait_for_owned(self.sign(response), timeout=self.timeout_seconds)
        return await run_owned_thread(self._signed_response, response, signature)

    @canonical_json_reuse()
    def _response(self, request: CohortHistoryRequest) -> CohortHistoryResponse:
        response = CohortHistoryResponse(
            schema="umi-cohort-history-response/1",
            challenge=request.challenge,
            source=self.read(request.cohort_sha256),
        )
        if len(canonical_json_bytes(response)) > self.maximum_bytes - 2048:
            raise ValueError("history response exceeds delivery capacity")
        return response

    @canonical_json_reuse()
    def _signed_response(self, response: CohortHistoryResponse, signature: Signature) -> bytes:
        if identity(signature.hotkey) != self.owner:
            raise ValueError("history response signed by another owner")
        verify_signature(response, signature)
        return canonical_json_bytes(
            SignedCohortHistoryResponse(response=response, signature=signature)
        )


def cohort_history_routes(exporter: CohortHistoryExporter, *, token: str):
    return phase_review_routes(exporter, token=token, path=PATH, request_model=CohortHistoryRequest)


class CohortHistoryReader:
    def __init__(
        self,
        owner: str,
        fetch: Callable[[CohortHistoryRequest], Awaitable[bytes]],
        *,
        timeout_seconds=2400,
    ):
        review_export_limits(MAX_EXPORT_BYTES, timeout_seconds)
        self.owner, self.fetch, self.timeout = identity(owner), fetch, timeout_seconds

    async def __call__(self, cohort: str) -> CohortOrderHistory:
        request = CohortHistoryRequest(
            schema="umi-cohort-history-request/1",
            cohort_sha256=cohort,
            challenge=secrets.token_hex(32),
        )
        raw = await wait_for_owned(self.fetch(request), timeout=self.timeout)
        return await run_owned_thread(self._verify, raw, request)

    @canonical_json_reuse()
    def _verify(self, raw: bytes, request: CohortHistoryRequest) -> CohortOrderHistory:
        # Authenticate each fresh challenge and replay all native inputs. The
        # bounded serialization cache holds bytes only within this operation.
        if type(raw) is not bytes or len(raw) > MAX_EXPORT_BYTES:
            raise ValueError("owner history exceeds delivery capacity")
        signed = SignedCohortHistoryResponse.model_validate_json(raw)
        if (
            canonical_json_bytes(signed) != raw
            or signed.response.challenge != request.challenge
            or identity(signed.signature.hotkey) != self.owner
            or digest(signed.response.source.history.plan) != request.cohort_sha256
        ):
            raise ValueError("owner history changed its challenge, cohort or signer")
        verify_signature(signed.response, signed.signature)
        signed.response.source.inputs()
        # Consumers independently replay quorum, authority and monotonicity.
        return signed.response.source


class CohortHistoryHTTPClient(PhaseReviewHTTPClient[CohortHistoryRequest]):
    def __init__(self, client, origin, *, token, timeout_seconds=2400):
        super().__init__(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=MAX_EXPORT_BYTES,
            timeout_seconds=timeout_seconds,
        )
