"""Private coordinator-to-reviewer votes backed by native durable signing.

The coordinator selects a phase and reviewer identity. Remote responses must
verify against that exact body and identity; a transport receipt is not a vote.
The reviewer reuses CohortProgressSigner, including its original intent, recovery
and one-transition-per-predecessor rules. No separate signing implementation lives
in this transport.
"""

from __future__ import annotations

from typing import Literal

import httpx
from fastapi import APIRouter
from pydantic import Field

from .competition_cohort_coordinator import CohortDecisionInput, CohortPhaseProgress
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_progress_signer import CohortProgressSigner
from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_cohort_review_export import review_export_limits, review_selection
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .concurrency import wait_for_owned
from .open_competition import CompetitionPolicy, Hotkey, Signature, identity, verify_signature
from .protocol import StrictProtocolModel, canonical_json_bytes

Phase = Literal["intake", "preparation", "requests"]
MAX_VOTE_BYTES = 2048
MAX_REQUEST_BYTES = 256 * 1024


class ProgressVoteRequest(StrictProtocolModel):
    schema_: Literal["umi-cohort-progress-vote-request/1"] = Field(alias="schema")
    progress: CohortPhaseProgress


class DecisionVoteRequest(StrictProtocolModel):
    schema_: Literal["umi-cohort-decision-vote-request/1"] = Field(alias="schema")
    transition: CohortRecoveryTransition
    evidence: CohortDecisionInput


class PhaseVotePeerIdentity(StrictProtocolModel):
    signer: Hotkey
    phase: Phase


def _path(phase: Phase, kind: str) -> str:
    if phase not in ("intake", "preparation", "requests") or kind not in ("progress", "decision"):
        raise ValueError("unknown native phase vote route")
    return f"/internal/cohorts/{phase}/votes/{kind}"


def _check_phase(progress: CohortPhaseProgress, phase: Phase, cohorts) -> None:
    if progress.phase != phase or progress.cohort_sha256 not in {c.cohort_sha256 for c in cohorts}:
        raise ValueError("vote request is outside configured phase or cohorts")


class _VoteResponder:
    def __init__(self, signer: CohortProgressSigner, phase: Phase, timeout_seconds: int):
        review_export_limits(MAX_VOTE_BYTES, timeout_seconds)
        self.signer, self.phase = signer, phase
        self.timeout_seconds, self.maximum_bytes = timeout_seconds, MAX_VOTE_BYTES

    async def respond(self, request: ProgressVoteRequest | DecisionVoteRequest) -> bytes:
        progress = (
            request.progress
            if isinstance(request, ProgressVoteRequest)
            else request.evidence.progress.progress
        )
        _check_phase(progress, self.phase, self.signer.config.cohorts)
        vote = (
            await self.signer.attest(progress)
            if isinstance(request, ProgressVoteRequest)
            else await self.signer.certify(request.transition, request.evidence)
        )
        return canonical_json_bytes(vote)


def phase_vote_routes(
    signer: CohortProgressSigner, *, phase: Phase, token: str, timeout_seconds: int = 1200
) -> APIRouter:
    responder = _VoteResponder(signer, phase, timeout_seconds)
    router = APIRouter()
    for kind, model in (("progress", ProgressVoteRequest), ("decision", DecisionVoteRequest)):
        router.include_router(
            phase_review_routes(
                responder,
                token=token,
                path=_path(phase, kind),
                request_model=model,
                maximum_request_bytes=MAX_REQUEST_BYTES,
            )
        )
    return router


class PhaseVotePeer:
    """CertifiedPhaseObserver peer with no local hotkey or signing journal."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        origin: str,
        *,
        policy: CompetitionPolicy,
        cohorts: tuple[CohortIntakeBinding, ...],
        signer: str,
        phase: Phase,
        token: str,
        timeout_seconds: int = 1200,
    ):
        self.policy, self.cohorts, _account = review_selection(policy, cohorts, signer)
        self.config = PhaseVotePeerIdentity(signer=signer, phase=phase)
        self.timeout_seconds = timeout_seconds
        self.progress_transport = PhaseReviewHTTPClient[ProgressVoteRequest](
            client,
            origin,
            token=token,
            path=_path(phase, "progress"),
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=MAX_REQUEST_BYTES,
            timeout_seconds=timeout_seconds,
        )
        self.decision_transport = PhaseReviewHTTPClient[DecisionVoteRequest](
            client,
            origin,
            token=token,
            path=_path(phase, "decision"),
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=MAX_REQUEST_BYTES,
            timeout_seconds=timeout_seconds,
        )

    def _vote(self, raw: bytes, body: StrictProtocolModel) -> Signature:
        vote = Signature.model_validate_json(raw)
        if canonical_json_bytes(vote) != raw or identity(vote.hotkey) != identity(
            self.config.signer
        ):
            raise ValueError("remote phase vote changes its canonical bytes or selected reviewer")
        verify_signature(body, vote)
        return vote

    async def attest(self, progress: CohortPhaseProgress) -> Signature:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        _check_phase(progress, self.config.phase, self.cohorts)
        request = ProgressVoteRequest(
            schema="umi-cohort-progress-vote-request/1", progress=progress
        )
        raw = await wait_for_owned(self.progress_transport(request), timeout=self.timeout_seconds)
        return self._vote(raw, progress)

    async def certify(
        self, transition: CohortRecoveryTransition, evidence: CohortDecisionInput
    ) -> Signature:
        transition = CohortRecoveryTransition.model_validate_json(canonical_json_bytes(transition))
        evidence = CohortDecisionInput.model_validate_json(canonical_json_bytes(evidence))
        _check_phase(evidence.progress.progress, self.config.phase, self.cohorts)
        if transition.cohort_sha256 != evidence.progress.progress.cohort_sha256:
            raise ValueError("remote phase decision and progress belong to different cohorts")
        request = DecisionVoteRequest(
            schema="umi-cohort-decision-vote-request/1", transition=transition, evidence=evidence
        )
        raw = await wait_for_owned(self.decision_transport(request), timeout=self.timeout_seconds)
        return self._vote(raw, transition)
