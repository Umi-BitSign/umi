"""Private admission history and votes using the original native signer.

Registration proofs arrive in the reviewer's selected proof inbox. Neither an
HTTP caller nor the intake owner can replace independent finality review.
"""

from __future__ import annotations

import secrets
from typing import Literal

from pydantic import Field

from .competition_cohort_admission_journal import CohortAdmissionVote
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_admission_signer import AdmissionHistory, CohortAdmissionSigner
from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_history_http import CohortHistoryRequest
from .competition_cohort_intake_records import RetainedCohortParticipation, read_participation
from .competition_cohort_intake_seal import CohortIntakeSeal
from .competition_cohort_review_export import (
    MAX_EXPORT_BYTES,
    review_export_limits,
    review_selection,
)
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

HISTORY_PATH = "/internal/cohorts/admission-history"
VOTE_PATH = "/internal/cohorts/admission/votes"
MAX_VOTE_BYTES = 16 * 1024
MAX_VOTE_REQUEST_BYTES = 4 * 1024**2 + 1024


class AdmissionHistoryResponse(StrictProtocolModel):
    schema_: Literal["umi-cohort-admission-history-response/1"] = Field(alias="schema")
    history: CohortRecoveryHistory
    seal: CohortIntakeSeal | None
    closure: CohortDecisionInput | None
    challenge: Hex32


class SignedAdmissionHistoryResponse(StrictProtocolModel):
    response: AdmissionHistoryResponse
    signature: Signature


class AdmissionHistoryExporter:
    def __init__(self, queue: CohortAdmissionQueue, owner: str, sign, *, timeout_seconds=30):
        review_export_limits(MAX_EXPORT_BYTES, timeout_seconds)
        _, _, self.owner = review_selection(queue.policy, queue.intake.config.cohorts, owner)
        self.queue, self.sign = queue, sign
        self.maximum_bytes, self.timeout_seconds = MAX_EXPORT_BYTES, timeout_seconds

    async def respond(self, request: CohortHistoryRequest) -> bytes:
        source = await run_owned_thread(self.queue.history, request.cohort_sha256)
        response = AdmissionHistoryResponse(
            schema="umi-cohort-admission-history-response/1",
            history=source.history,
            seal=source.seal,
            closure=source.closure,
            challenge=request.challenge,
        )
        if len(canonical_json_bytes(response)) > self.maximum_bytes - 2048:
            raise ValueError("admission history exceeds delivery capacity")
        signature = await wait_for_owned(self.sign(response), timeout=self.timeout_seconds)
        if identity(signature.hotkey) != self.owner:
            raise ValueError("admission history signed by another owner")
        verify_signature(response, signature)
        return canonical_json_bytes(
            SignedAdmissionHistoryResponse(response=response, signature=signature)
        )


def admission_history_routes(exporter: AdmissionHistoryExporter, *, token: str):
    return phase_review_routes(
        exporter, token=token, path=HISTORY_PATH, request_model=CohortHistoryRequest
    )


class AdmissionHistoryReader:
    def __init__(self, owner: str, fetch, *, timeout_seconds=300):
        review_export_limits(MAX_EXPORT_BYTES, timeout_seconds)
        self.owner, self.fetch, self.timeout = identity(owner), fetch, timeout_seconds

    async def __call__(self, cohort: str) -> AdmissionHistory:
        request = CohortHistoryRequest(
            schema="umi-cohort-history-request/1",
            cohort_sha256=cohort,
            challenge=secrets.token_hex(32),
        )
        raw = await wait_for_owned(self.fetch(request), timeout=self.timeout)
        if type(raw) is not bytes or len(raw) > MAX_EXPORT_BYTES:
            raise ValueError("admission history exceeds delivery capacity")
        signed = SignedAdmissionHistoryResponse.model_validate_json(raw)
        value = signed.response
        if (
            canonical_json_bytes(signed) != raw
            or value.challenge != request.challenge
            or identity(signed.signature.hotkey) != self.owner
            or digest(value.history.plan) != cohort
        ):
            raise ValueError("admission history changes challenge, cohort or owner")
        verify_signature(value, signed.signature)
        # CohortAdmissionSigner checks quorum, original selection and rollback.
        return AdmissionHistory(value.history, value.seal, value.closure)


class AdmissionHistoryHTTPClient(PhaseReviewHTTPClient[CohortHistoryRequest]):
    def __init__(self, client, origin, *, token, timeout_seconds=300):
        super().__init__(
            client,
            origin,
            token=token,
            path=HISTORY_PATH,
            maximum_bytes=MAX_EXPORT_BYTES,
            timeout_seconds=timeout_seconds,
        )


class AdmissionVoteRequest(StrictProtocolModel):
    schema_: Literal["umi-cohort-admission-vote-request/1"] = Field(alias="schema")
    record: RetainedCohortParticipation


class _VoteResponder:
    def __init__(self, signer: CohortAdmissionSigner, timeout_seconds: int):
        review_export_limits(MAX_VOTE_BYTES, timeout_seconds)
        self.signer = signer
        self.maximum_bytes, self.timeout_seconds = MAX_VOTE_BYTES, timeout_seconds

    async def respond(self, request: AdmissionVoteRequest) -> bytes:
        raw = canonical_json_bytes(request.record)
        read_participation(raw)
        # A committed vote returns before accessing the inbox, owner or RPC.
        return canonical_json_bytes(await self.signer.attest(raw))


def admission_vote_routes(signer: CohortAdmissionSigner, *, token: str, timeout_seconds=1200):
    return phase_review_routes(
        _VoteResponder(signer, timeout_seconds),
        token=token,
        path=VOTE_PATH,
        request_model=AdmissionVoteRequest,
        maximum_request_bytes=MAX_VOTE_REQUEST_BYTES,
    )


class AdmissionVotePeer:
    """Admission worker vote port; owns no validator key or signing journal."""

    def __init__(self, client, origin, *, policy, cohorts, signer, token, timeout_seconds=1200):
        self.policy, self.cohorts, self.account = review_selection(policy, cohorts, signer)
        self.signer = signer
        self.timeout = timeout_seconds
        self.transport = PhaseReviewHTTPClient[AdmissionVoteRequest](
            client,
            origin,
            token=token,
            path=VOTE_PATH,
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=MAX_VOTE_REQUEST_BYTES,
            timeout_seconds=timeout_seconds,
        )

    async def attest(self, raw: bytes) -> CohortAdmissionVote:
        record = read_participation(raw)
        if record.proposed_admission.cohort_sha256 not in {c.cohort_sha256 for c in self.cohorts}:
            raise ValueError("admission vote is outside configured cohorts")
        request = AdmissionVoteRequest(schema="umi-cohort-admission-vote-request/1", record=record)
        response = await wait_for_owned(self.transport(request), timeout=self.timeout)
        vote = CohortAdmissionVote.model_validate_json(response)
        if (
            canonical_json_bytes(vote) != response
            or identity(vote.signature.hotkey) != self.account
            or vote.admission != record.proposed_admission
        ):
            raise ValueError("admission vote changes original body or selected reviewer")
        verify_signature(vote.admission, vote.signature)
        return vote
