"""Typed request-rule adoption through the existing owner and reviewer services.

The operator selects exact native proposal bytes. Owner reservation compares the
predecessor atomically; reviewers share ordinary phase non-equivocation slots.
No phase progress, new plan, wallet loader or secondary SQLite writer is created.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import Field, model_validator

from .competition_cohort_coordinator import replay_cohort_decisions
from .competition_cohort_intake import history_tip
from .competition_cohort_recovery import (
    CohortRecoveryTransition,
    SignedCohortRecoveryTransition,
    propose_recovery_transition,
    verify_recovery_quorum,
)
from .competition_cohort_request_rule import prepare_request_tail_adoption
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_execution import execution_boundary
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

ROOT = "/internal/cohorts/request-tail-adoption"
VOTE_PATH = ROOT + "/vote"
MAX_PROPOSAL_BYTES = 32 * 1024


def require_adoption(transition):
    transition = CohortRecoveryTransition.model_validate_json(canonical_json_bytes(transition))
    if transition.operation != "adopt_request_tail_rule":
        raise ValueError("request-rule endpoint requires an adoption transition")
    return transition


class RequestTailAdoptionProposal(StrictProtocolModel):
    schema_: Literal["umi-request-tail-adoption-proposal/1"] = Field(alias="schema")
    series_sha256: Hex32
    transition: CohortRecoveryTransition

    @model_validator(mode="after")
    def adoption(self):
        require_adoption(self.transition)
        return self


class RequestTailAdoptionPrepare(StrictProtocolModel):
    schema_: Literal["umi-request-tail-adoption-prepare/1"] = Field(alias="schema")
    series_sha256: Hex32
    cohort_sha256: Hex32
    predecessor_sha256: Hex32


class RequestTailAdoptionCommit(StrictProtocolModel):
    schema_: Literal["umi-request-tail-adoption-commit/1"] = Field(alias="schema")
    series_sha256: Hex32
    certificate: SignedCohortRecoveryTransition

    @model_validator(mode="after")
    def adoption(self):
        require_adoption(self.certificate.transition)
        return self


def assemble_request_tail_adoption(proposal, signatures, policy):
    """Offline assembly verifies quorum over the exact prepared transition."""
    proposal = RequestTailAdoptionProposal.model_validate_json(canonical_json_bytes(proposal))
    votes = tuple(
        sorted(
            (Signature.model_validate_json(canonical_json_bytes(s)) for s in signatures),
            key=lambda s: identity(s.hotkey),
        )
    )
    verify_recovery_quorum(proposal.transition, votes, policy)
    return SignedCohortRecoveryTransition(transition=proposal.transition, signatures=votes)


class RequestTailAdoptionReviewer:
    def __init__(self, series, policy, provider, history, reservation):
        self.series, self.policy = series, policy
        self.provider, self.history = provider, history
        self.reservation = reservation
        if provider.policy != policy:
            raise ValueError("request-rule reviewer finality has another policy")

    async def __call__(self, transition):
        transition = require_adoption(transition)
        cohort = transition.cohort_sha256
        plan = next((p for p in self.series.cohorts if digest(p) == cohort), None)
        if plan is None:
            raise ValueError("request-rule adoption is outside selected series")
        source = await self.history(cohort)
        if source.history.plan != plan or source.history.authority != self.series.recovery:
            raise ValueError("request-rule adoption changed original series authority")
        state, _, _ = replay_cohort_decisions(
            source.history, self.policy, source.inputs().__getitem__
        )
        observation = execution_boundary(await self.provider.collect())
        if observation.block < transition.observed_at_block:
            raise ValueError("request-rule adoption is ahead of owned finality")
        expected = propose_recovery_transition(
            state,
            source.history.authority.authority,
            operation="adopt_request_tail_rule",
            observed_at_block=transition.observed_at_block,
            evidence_sha256=transition.evidence_sha256,
            request_tail_adoption=transition.request_tail_adoption,
        )
        if canonical_json_bytes(expected) != canonical_json_bytes(transition):
            raise ValueError("request-rule adoption differs from selected native proposal")
        current = await self.history(cohort)
        if current.history != source.history:
            raise OSError("request-rule history changed during independent review")
        await self.reservation(transition, current.history)
        # Fresh challenges and later finality heads validate the same intent.
        # Keep its retained audit identity stable across a lost signing reply.
        return {
            "series_sha256": digest(self.series),
            "history_sha256": digest(source.history),
            "proposal_sha256": digest(transition),
            "review_rule": "owned_finality_and_same_tip_dual_reservation/1",
        }


class _AdoptionVoteResponder:
    maximum_bytes = 2048

    def __init__(self, signer, series, timeout_seconds):
        self.signer, self.series = signer, series
        self.timeout_seconds = timeout_seconds

    async def respond(self, request):
        if request.series_sha256 != digest(self.series):
            raise ValueError("request-rule vote selected another series")
        return canonical_json_bytes(
            await self.signer.certify_request_tail_adoption(request.transition)
        )


def request_tail_adoption_vote_routes(signer, series, *, token, timeout_seconds=2400):
    return phase_review_routes(
        _AdoptionVoteResponder(signer, series, timeout_seconds),
        token=token,
        path=VOTE_PATH,
        request_model=RequestTailAdoptionProposal,
        maximum_request_bytes=MAX_PROPOSAL_BYTES,
    )


class RequestTailAdoptionVotePeer:
    def __init__(self, client, origin, *, signer, token, timeout_seconds=2400):
        self.signer = identity(signer)
        self.transport = PhaseReviewHTTPClient(
            client,
            origin,
            token=token,
            path=VOTE_PATH,
            maximum_bytes=2048,
            maximum_request_bytes=MAX_PROPOSAL_BYTES,
            timeout_seconds=timeout_seconds,
        )

    async def certify(self, proposal):
        proposal = RequestTailAdoptionProposal.model_validate_json(canonical_json_bytes(proposal))
        raw = await self.transport(proposal)
        vote = Signature.model_validate_json(raw)
        if canonical_json_bytes(vote) != raw or identity(vote.hotkey) != self.signer:
            raise ValueError("request-rule vote changed canonical bytes or selected signer")
        verify_signature(proposal.transition, vote)
        return vote


class RequestTailAdoptionOwner:
    """Use only nodes already opened and locked by the lifecycle service."""

    maximum_bytes = 128 * 1024

    def __init__(self, lifecycle, kind):
        self.lifecycle, self.kind = lifecycle, kind
        self.timeout_seconds = lifecycle.timeout_seconds

    async def respond(self, request):
        host = self.lifecycle
        if request.series_sha256 != digest(host.service.config.series):
            raise ValueError("request-rule control selected another series")
        transition = (
            None
            if isinstance(request, RequestTailAdoptionPrepare)
            else request.certificate.transition
            if isinstance(request, RequestTailAdoptionCommit)
            else request.transition
        )
        cohort = request.cohort_sha256 if transition is None else transition.cohort_sha256
        node = host.nodes.get(cohort)
        if node is None:
            raise OSError("request-rule control awaits the existing lifecycle owner")
        async with node.serial, node.controller.serial, node.controller.sampling_lock:
            control = node.controller
            history, state, _, _ = control._history()
            _, pending = control.store.status(cohort)
            if self.kind == "prepare":
                if history_tip(history) != request.predecessor_sha256 or pending is not None:
                    raise ValueError("request-rule preparation lost its selected predecessor")
                observation = execution_boundary(await host.provider.collect())
                transition = prepare_request_tail_adoption(history, host.policy, observation)
            elif self.kind == "reserve":
                prior = any(s.transition == transition for s in history.transitions)
                if not prior:
                    if pending is not None and pending != transition:
                        raise ValueError("request-rule reservation conflicts with pending control")
                    expected = propose_recovery_transition(
                        state,
                        history.authority.authority,
                        operation="adopt_request_tail_rule",
                        observed_at_block=transition.observed_at_block,
                        evidence_sha256=transition.evidence_sha256,
                        request_tail_adoption=transition.request_tail_adoption,
                    )
                    if expected != transition:
                        raise ValueError("request-rule reservation lost its selected control tip")
                if not prior and pending != transition:
                    observation = execution_boundary(await host.provider.collect())
                    if observation.block < transition.observed_at_block:
                        raise ValueError("request-rule reservation is ahead of owned finality")
                # Hold lifecycle progress while the intake owner atomically
                # validates receipt heights and gates fresh participation.
                # Its durable reservation is reconciled into control on restart.
                await run_owned_thread(
                    host.service.intake.reserve_request_tail_adoption, transition
                )
                transition = control.store.reserve_exact(transition)
            elif self.kind == "commit":
                if pending != transition and not any(
                    s.transition == transition for s in history.transitions
                ):
                    raise ValueError("request-rule certificate lacks its exact owner reservation")
                control.store.commit(request.certificate)
                history, state, _, _ = control._history()
                await node._publish(history)
                return canonical_json_bytes(state)
            else:
                raise ValueError("unknown request-rule control operation")
            return canonical_json_bytes(
                RequestTailAdoptionProposal(
                    schema="umi-request-tail-adoption-proposal/1",
                    series_sha256=request.series_sha256,
                    transition=transition,
                )
            )


def request_tail_adoption_owner_routes(lifecycle, *, token):
    router = APIRouter()
    for kind, model in (
        ("prepare", RequestTailAdoptionPrepare),
        ("reserve", RequestTailAdoptionProposal),
        ("commit", RequestTailAdoptionCommit),
    ):
        router.include_router(
            phase_review_routes(
                RequestTailAdoptionOwner(lifecycle, kind),
                token=token,
                path=ROOT + "/" + kind,
                request_model=model,
                maximum_request_bytes=128 * 1024,
            )
        )
    return router
