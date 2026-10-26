"""Typed evaluation-suite adoption through the existing owner and reviewer services.

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
from .competition_cohort_model_delivery_api import adoption_owner_node
from .competition_cohort_recovery import (
    CohortRecoveryTransition,
    SignedCohortRecoveryTransition,
    propose_recovery_transition,
    verify_recovery_quorum,
)
from .competition_cohort_review_budget import PhaseReviewBudget, checked_budget
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_cohort_suite_adoption_candidate import EvaluationSuiteAdoptionCandidate
from .competition_work_progress import await_progress
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

ROOT = "/internal/cohorts/evaluation-suite-adoption"
VOTE_PATH = ROOT + "/vote"
MAX_PROPOSAL_BYTES = 32 * 1024


def require_adoption(transition):
    transition = CohortRecoveryTransition.model_validate_json(canonical_json_bytes(transition))
    if transition.operation != "adopt_evaluation_suite":
        raise ValueError("evaluation-suite endpoint requires an adoption transition")
    return transition


class EvaluationSuiteAdoptionProposal(StrictProtocolModel):
    schema_: Literal["umi-evaluation-suite-adoption-proposal/1"] = Field(alias="schema")
    series_sha256: Hex32
    transition: CohortRecoveryTransition

    @model_validator(mode="after")
    def adoption(self):
        require_adoption(self.transition)
        return self


class EvaluationSuiteAdoptionPrepare(StrictProtocolModel):
    schema_: Literal["umi-evaluation-suite-adoption-prepare/1"] = Field(alias="schema")
    series_sha256: Hex32
    cohort_sha256: Hex32
    predecessor_sha256: Hex32


class EvaluationSuiteAdoptionCommit(StrictProtocolModel):
    schema_: Literal["umi-evaluation-suite-adoption-commit/1"] = Field(alias="schema")
    series_sha256: Hex32
    certificate: SignedCohortRecoveryTransition

    @model_validator(mode="after")
    def adoption(self):
        require_adoption(self.certificate.transition)
        return self


def assemble_evaluation_suite_adoption(proposal, signatures, policy):
    """Offline assembly verifies quorum over the exact prepared transition."""
    proposal = EvaluationSuiteAdoptionProposal.model_validate_json(canonical_json_bytes(proposal))
    votes = tuple(
        sorted(
            (Signature.model_validate_json(canonical_json_bytes(s)) for s in signatures),
            key=lambda s: identity(s.hotkey),
        )
    )
    verify_recovery_quorum(proposal.transition, votes, policy)
    return SignedCohortRecoveryTransition(transition=proposal.transition, signatures=votes)


def _owner_budget(host):
    selected = getattr(host.service.config.admission_owner, "phase_review_budget", None)
    return (
        None
        if selected is None
        else checked_budget(selected, host.policy, selected.maximum_aggregate_evidence_bytes)
    )


async def _owned_block(provider, budget):
    # The native method verifies observer liveness, authenticated finalized
    # header, startup/minimum floors, freshness and rollback guards. Adoption
    # needs no membership capture; never fabricate a RegistrationCapture or
    # accept a height from the operator/RPC as a substitute.
    work = provider.current_finalized_block()
    block = (
        await work
        if budget is None
        else await wait_for_owned(work, timeout=budget.authority_seconds)
    )
    if type(block) is not int or not 0 <= block <= 2**53 - 1:
        raise ValueError("evaluation-suite adoption owned block is invalid")
    return block


class EvaluationSuiteAdoptionReviewer:
    def __init__(self, series, policy, provider, history, reservation, *, candidates, budget=None):
        self.series, self.policy = series, policy
        self.provider, self.history = provider, history
        self.budget = (
            None
            if budget is None
            else checked_budget(budget, policy, budget.maximum_aggregate_evidence_bytes)
        )
        self.reservation = reservation
        self.candidates = dict(candidates)
        if provider.policy != policy:
            raise ValueError("evaluation-suite reviewer finality has another policy")

    def _replay(self, source):
        return replay_cohort_decisions(source.history, self.policy, source.inputs().__getitem__)

    async def __call__(self, transition):
        transition = require_adoption(transition)
        cohort = transition.cohort_sha256
        plan = next((p for p in self.series.cohorts if digest(p) == cohort), None)
        if plan is None:
            raise ValueError("evaluation-suite adoption is outside selected series")
        source = await await_progress(
            self.history(cohort), stage="adoption_history_before", cohort=cohort
        )
        if source.history.plan != plan or source.history.authority != self.series.recovery:
            raise ValueError("evaluation-suite adoption changed original series authority")
        state, _, _ = await await_progress(
            run_owned_thread(self._replay, source), stage="adoption_history_replay", cohort=cohort
        )
        block = await await_progress(
            _owned_block(self.provider, self.budget),
            stage="adoption_owned_finality",
            cohort=cohort,
        )
        if block < transition.observed_at_block:
            raise ValueError("evaluation-suite adoption is ahead of owned finality")
        expected = propose_recovery_transition(
            state,
            source.history.authority.authority,
            operation="adopt_evaluation_suite",
            observed_at_block=transition.observed_at_block,
            evidence_sha256=transition.evidence_sha256,
            evaluation_suite_adoption=transition.evaluation_suite_adoption,
        )
        if canonical_json_bytes(expected) != canonical_json_bytes(transition):
            raise ValueError("evaluation-suite adoption differs from selected native proposal")
        candidate = self.candidates.get(cohort)
        if candidate is None:
            raise ValueError("suite vote requires its independently selected private candidate")
        await await_progress(
            candidate.verify(source.history, transition),
            stage="evaluation_suite_candidate_review",
            cohort=cohort,
        )
        current = await await_progress(
            self.history(cohort), stage="adoption_history_after", cohort=cohort
        )
        if current.history != source.history:
            raise OSError("evaluation-suite history changed during independent review")
        await await_progress(
            self.reservation(transition, current.history),
            stage="adoption_reservation_proof",
            cohort=cohort,
        )
        final_block = await _owned_block(self.provider, self.budget)
        if final_block < block:
            raise ValueError("suite adoption owned finality regressed during review")
        # Fresh challenges and later finality heads validate the same intent.
        # Keep its retained audit identity stable across a lost signing reply.
        return {
            "series_sha256": digest(self.series),
            "history_sha256": await run_owned_thread(digest, source.history),
            "proposal_sha256": digest(transition),
            "review_rule": "native_suite_selection_media_and_same_tip_dual_reservation/1",
            "suite_sha256": transition.evaluation_suite_adoption.suite_sha256,
            "selection_manifest_sha256": (
                transition.evaluation_suite_adoption.selection_manifest_sha256
            ),
        }


class _AdoptionVoteResponder:
    maximum_bytes = 2048

    def __init__(self, signer, series, timeout_seconds):
        self.signer, self.series = signer, series
        self.timeout_seconds = timeout_seconds

    async def respond(self, request):
        if request.series_sha256 != digest(self.series):
            raise ValueError("evaluation-suite vote selected another series")
        return canonical_json_bytes(
            await self.signer.certify_evaluation_suite_adoption(request.transition)
        )


def evaluation_suite_adoption_vote_routes(
    signer, series, *, token, timeout_seconds=2400, budget: PhaseReviewBudget | None = None
):
    if budget is not None:
        budget = checked_budget(
            budget,
            signer.policy,
            budget.maximum_aggregate_evidence_bytes,
            signing_seconds=signer.config.signing_timeout_seconds,
        )
        timeout_seconds = budget.vote_seconds("adoption")
    return phase_review_routes(
        _AdoptionVoteResponder(signer, series, timeout_seconds),
        token=token,
        path=VOTE_PATH,
        request_model=EvaluationSuiteAdoptionProposal,
        maximum_request_bytes=MAX_PROPOSAL_BYTES,
    )


class EvaluationSuiteAdoptionVotePeer:
    def __init__(
        self,
        client,
        origin,
        *,
        signer,
        token,
        timeout_seconds=2400,
        budget: PhaseReviewBudget | None = None,
        policy=None,
    ):
        if budget is not None:
            if policy is None:
                raise ValueError("adoption vote budget requires its selected policy")
            budget = checked_budget(budget, policy, budget.maximum_aggregate_evidence_bytes)
            timeout_seconds = budget.vote_exchange_seconds("adoption")
        self.signer = identity(signer)
        self.budget = budget
        self.timeout_seconds = timeout_seconds
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
        proposal = EvaluationSuiteAdoptionProposal.model_validate_json(
            canonical_json_bytes(proposal)
        )
        raw = (
            await self.transport(proposal)
            if self.budget is None
            else await wait_for_owned(self.transport(proposal), timeout=self.timeout_seconds)
        )
        vote = Signature.model_validate_json(raw)
        if canonical_json_bytes(vote) != raw or identity(vote.hotkey) != self.signer:
            raise ValueError("evaluation-suite vote changed canonical bytes or selected signer")
        verify_signature(proposal.transition, vote)
        return vote


def selected_owner_candidate(host, cohort):
    candidates = host.evaluation_suite_candidates
    if cohort not in candidates:
        config = next(
            (
                c
                for c in host.config.evaluation_suite_adoption_candidates
                if c.cohort_sha256 == cohort
            ),
            None,
        )
        if config is None:
            raise ValueError("suite adoption has no privately selected candidate")
        candidates[cohort] = EvaluationSuiteAdoptionCandidate(config, host.policy)
    return candidates[cohort]


class EvaluationSuiteAdoptionOwner:
    """Use only nodes already opened and locked by the lifecycle service."""

    maximum_bytes = 128 * 1024

    def __init__(self, lifecycle, kind):
        self.lifecycle, self.kind = lifecycle, kind
        self.timeout_seconds = lifecycle.timeout_seconds

    async def respond(self, request):
        host = self.lifecycle
        if request.series_sha256 != digest(host.service.config.series):
            raise ValueError("evaluation-suite control selected another series")
        transition = (
            None
            if isinstance(request, EvaluationSuiteAdoptionPrepare)
            else request.certificate.transition
            if isinstance(request, EvaluationSuiteAdoptionCommit)
            else request.transition
        )
        cohort = request.cohort_sha256 if transition is None else transition.cohort_sha256
        candidate = selected_owner_candidate(host, cohort)
        node = await adoption_owner_node(host, cohort)
        async with node.serial, node.controller.serial, node.controller.sampling_lock:
            control = node.controller
            history, state, _, _ = control._history()
            _, pending = control.store.status(cohort)
            if self.kind == "commit":
                if pending != transition and not any(
                    s.transition == transition for s in history.transitions
                ):
                    raise ValueError(
                        "evaluation-suite certificate lacks its exact owner reservation"
                    )
                control.store.commit(request.certificate)
                history, state, _, _ = control._history()
                await node._publish(history)
                return canonical_json_bytes(state)
            if self.kind == "prepare":
                self._prepare_tip(request, history, pending)
                observed = None if pending is None else pending.observed_at_block
            elif self.kind == "reserve":
                prior = self._reservation_tip(transition, history, state, pending)
                already_reserved = prior or pending == transition
            else:
                raise ValueError("unknown evaluation-suite control operation")

        # First native media/annotation qualification owns no live journal or
        # lifecycle lock. Intake and ordinary sampling can continue throughout.
        qualification = None
        if self.kind == "prepare":
            block = (
                observed
                if observed is not None
                else await _owned_block(host.provider, _owner_budget(host))
            )
            transition, qualification = await run_owned_thread(
                candidate.prepare_qualified, history, block
            )
        elif not already_reserved:
            block = await _owned_block(host.provider, _owner_budget(host))
            if block < transition.observed_at_block:
                raise ValueError("evaluation-suite reservation is ahead of owned finality")
            qualification = await run_owned_thread(candidate.qualify, history, transition)

        async with node.serial, node.controller.serial, node.controller.sampling_lock:
            history, state, _, _ = control._history()
            _, pending = control.store.status(cohort)
            if self.kind == "prepare":
                self._prepare_tip(request, history, pending)
                self._reservation_tip(transition, history, state, pending)
                if pending is not None and transition != pending:
                    raise ValueError("evaluation-suite preparation changes its retained candidate")
            else:
                self._reservation_tip(transition, history, state, pending)
            if qualification is not None:
                # Identity-only validation: no reread, rehash, media decode or
                # completed native selection repeats while the owner is locked.
                candidate.require_qualification(qualification, transition)
            if self.kind == "reserve":
                await run_owned_thread(
                    host.service.intake.reserve_evaluation_suite_adoption, transition
                )
                transition = control.store.reserve_exact(transition)
            return canonical_json_bytes(
                EvaluationSuiteAdoptionProposal(
                    schema="umi-evaluation-suite-adoption-proposal/1",
                    series_sha256=request.series_sha256,
                    transition=transition,
                )
            )

    @staticmethod
    def _prepare_tip(request, history, pending):
        if history_tip(history) != request.predecessor_sha256:
            raise ValueError("evaluation-suite preparation lost its selected predecessor")
        if pending is not None and pending.operation != "adopt_evaluation_suite":
            raise ValueError("evaluation-suite preparation conflicts with pending control")

    @staticmethod
    def _reservation_tip(transition, history, state, pending):
        prior = any(s.transition == transition for s in history.transitions)
        if not prior:
            if pending is not None and pending != transition:
                raise ValueError("evaluation-suite reservation conflicts with pending control")
            expected = propose_recovery_transition(
                state,
                history.authority.authority,
                operation="adopt_evaluation_suite",
                observed_at_block=transition.observed_at_block,
                evidence_sha256=transition.evidence_sha256,
                evaluation_suite_adoption=transition.evaluation_suite_adoption,
            )
            if expected != transition:
                raise ValueError("evaluation-suite reservation lost its selected control tip")
        return prior


def evaluation_suite_adoption_owner_routes(lifecycle, *, token):
    router = APIRouter()
    for kind, model in (
        ("prepare", EvaluationSuiteAdoptionPrepare),
        ("reserve", EvaluationSuiteAdoptionProposal),
        ("commit", EvaluationSuiteAdoptionCommit),
    ):
        router.include_router(
            phase_review_routes(
                EvaluationSuiteAdoptionOwner(lifecycle, kind),
                token=token,
                path=ROOT + "/" + kind,
                request_model=model,
                maximum_request_bytes=128 * 1024,
            )
        )
    return router
