"""Typed model-delivery adoption through the existing owner and reviewer services.

The operator selects exact native proposal bytes and a private candidate.
Owner reservation compares the
predecessor atomically; reviewers share ordinary phase non-equivocation slots.
No phase progress, new plan, wallet loader or secondary SQLite writer is created.
"""

from __future__ import annotations

from functools import partial
from typing import Literal

from fastapi import APIRouter
from pydantic import Field, model_validator

from .competition_cohort_coordinator import replay_cohort_decisions
from .competition_cohort_intake import history_tip
from .competition_cohort_model_delivery_candidate import ModelDeliveryAdoptionCandidate
from .competition_cohort_model_delivery_census import census_model_delivery
from .competition_cohort_recovery import (
    CohortRecoveryTransition,
    SignedCohortRecoveryTransition,
    propose_recovery_transition,
    verify_recovery_quorum,
)
from .competition_cohort_review_budget import (
    PhaseReviewBudget,
    check_review_seconds,
    checked_budget,
)
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_work_progress import await_progress
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

ROOT = "/internal/cohorts/model-delivery-adoption"
VOTE_PATH = ROOT + "/vote"
PREPARE_RESERVED_PATH = ROOT + "/prepare-reserved"
MAX_PROPOSAL_BYTES = 32 * 1024


def require_adoption(transition):
    transition = CohortRecoveryTransition.model_validate_json(canonical_json_bytes(transition))
    if transition.operation != "adopt_model_delivery":
        raise ValueError("model-delivery endpoint requires an adoption transition")
    return transition


class ModelDeliveryAdoptionProposal(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-adoption-proposal/1"] = Field(alias="schema")
    series_sha256: Hex32
    transition: CohortRecoveryTransition

    @model_validator(mode="after")
    def adoption(self):
        require_adoption(self.transition)
        return self


class ModelDeliveryAdoptionPrepare(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-adoption-prepare/1"] = Field(alias="schema")
    series_sha256: Hex32
    cohort_sha256: Hex32
    predecessor_sha256: Hex32


class ModelDeliveryAdoptionCommit(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-adoption-commit/1"] = Field(alias="schema")
    series_sha256: Hex32
    certificate: SignedCohortRecoveryTransition

    @model_validator(mode="after")
    def adoption(self):
        require_adoption(self.certificate.transition)
        return self


def assemble_model_delivery_adoption(proposal, signatures, policy):
    """Offline assembly verifies quorum over the exact prepared transition."""
    proposal = ModelDeliveryAdoptionProposal.model_validate_json(canonical_json_bytes(proposal))
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
        raise ValueError("model-delivery adoption owned block is invalid")
    return block


class ModelDeliveryAdoptionReviewer:
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
            raise ValueError("model-delivery reviewer finality has another policy")

    def _replay(self, source):
        return replay_cohort_decisions(source.history, self.policy, source.inputs().__getitem__)

    async def __call__(self, transition):
        transition = require_adoption(transition)
        cohort = transition.cohort_sha256
        plan = next((p for p in self.series.cohorts if digest(p) == cohort), None)
        if plan is None:
            raise ValueError("model-delivery adoption is outside selected series")
        source = await await_progress(
            self.history(cohort), stage="adoption_history_before", cohort=cohort
        )
        if source.history.plan != plan or source.history.authority != self.series.recovery:
            raise ValueError("model-delivery adoption changed original series authority")
        state, _, _ = await await_progress(
            run_owned_thread(self._replay, source), stage="adoption_history_replay", cohort=cohort
        )
        block = await await_progress(
            _owned_block(self.provider, self.budget),
            stage="adoption_owned_finality",
            cohort=cohort,
        )
        if block < transition.observed_at_block:
            raise ValueError("model-delivery adoption is ahead of owned finality")
        expected = propose_recovery_transition(
            state,
            source.history.authority.authority,
            operation="adopt_model_delivery",
            observed_at_block=transition.observed_at_block,
            evidence_sha256=transition.evidence_sha256,
            model_delivery_adoption=transition.model_delivery_adoption,
        )
        if canonical_json_bytes(expected) != canonical_json_bytes(transition):
            raise ValueError("model-delivery adoption differs from selected native proposal")
        candidate = self.candidates.get(cohort)
        if candidate is None:
            raise ValueError("model delivery vote has no privately selected candidate")
        await await_progress(
            candidate.verify(source.history, transition),
            stage="model_delivery_adoption_remote_review",
            cohort=cohort,
        )
        current = await await_progress(
            self.history(cohort), stage="adoption_history_after", cohort=cohort
        )
        if current.history != source.history:
            raise OSError("model-delivery history changed during independent review")
        await await_progress(
            self.reservation(transition, current.history),
            stage="adoption_reservation_proof",
            cohort=cohort,
        )
        # Remote byte verification may span many bounded exchanges. Signing
        # requires fresh independent owned finality after that work, too.
        final_block = await await_progress(
            _owned_block(self.provider, self.budget),
            stage="adoption_final_owned_finality",
            cohort=cohort,
        )
        if final_block < block:
            raise ValueError("model-delivery owned finality regressed during review")
        # Fresh challenges and later finality heads validate the same intent.
        # Keep its retained audit identity stable across a lost signing reply.
        return {
            "series_sha256": digest(self.series),
            "history_sha256": await run_owned_thread(digest, source.history),
            "proposal_sha256": digest(transition),
            "review_rule": "native_census_remote_bytes_and_same_tip_dual_reservation/1",
            "legacy_inventory_sha256": transition.model_delivery_adoption.legacy_inventory_sha256,
            "preservation_inventory_sha256": (
                transition.model_delivery_adoption.preservation_inventory_sha256
            ),
        }


class _AdoptionVoteResponder:
    maximum_bytes = 2048

    def __init__(self, signer, series, timeout_seconds):
        self.signer, self.series = signer, series
        self.timeout_seconds = timeout_seconds

    async def respond(self, request):
        if request.series_sha256 != digest(self.series):
            raise ValueError("model-delivery vote selected another series")
        return canonical_json_bytes(
            await self.signer.certify_model_delivery_adoption(request.transition)
        )


def model_delivery_adoption_vote_routes(
    signer, series, *, token, timeout_seconds=2400, budget: PhaseReviewBudget | None = None
):
    if budget is not None:
        budget = checked_budget(
            budget,
            signer.policy,
            budget.maximum_aggregate_evidence_bytes,
            signing_seconds=signer.config.signing_timeout_seconds,
        )
        timeout_seconds = (
            budget.vote_seconds("adoption") + budget.replay_seconds + budget.authority_seconds
        )
        check_review_seconds(timeout_seconds)
    return phase_review_routes(
        _AdoptionVoteResponder(signer, series, timeout_seconds),
        token=token,
        path=VOTE_PATH,
        request_model=ModelDeliveryAdoptionProposal,
        maximum_request_bytes=MAX_PROPOSAL_BYTES,
    )


class ModelDeliveryAdoptionVotePeer:
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
            timeout_seconds = (
                budget.vote_exchange_seconds("adoption")
                + budget.replay_seconds
                + budget.authority_seconds
            )
            check_review_seconds(timeout_seconds)
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
        proposal = ModelDeliveryAdoptionProposal.model_validate_json(canonical_json_bytes(proposal))
        raw = (
            await self.transport(proposal)
            if self.budget is None
            else await wait_for_owned(self.transport(proposal), timeout=self.timeout_seconds)
        )
        vote = Signature.model_validate_json(raw)
        if canonical_json_bytes(vote) != raw or identity(vote.hotkey) != self.signer:
            raise ValueError("model-delivery vote changed canonical bytes or selected signer")
        verify_signature(proposal.transition, vote)
        return vote


def selected_owner_candidate(host, cohort):
    candidates = host.model_delivery_candidates
    if cohort not in candidates:
        config = next(
            (
                value
                for value in host.config.model_delivery_adoption_candidates
                if value.source.cohort_sha256 == cohort
            ),
            None,
        )
        if config is None:
            raise ValueError("model delivery control has no privately selected candidate")
        candidates[cohort] = ModelDeliveryAdoptionCandidate(config, host.policy)
    return candidates[cohort]


async def adoption_owner_node(host, cohort):
    node = host.nodes.get(cohort)
    if node is None:
        if cohort not in host.config.automatic_progression_hold_cohorts:
            raise OSError("model delivery control awaits existing lifecycle owner")
        # An authenticated explicit action may initialize the existing owner
        # under a hold. It never invokes tick, clears the hold or signs a phase.
        async with host.model_delivery_serial:
            node = host.nodes.get(cohort)
            if node is None:
                node = await host.node(cohort)
    return node


class ModelDeliveryAdoptionOwner:
    """Use only nodes already opened and locked by the lifecycle service."""

    maximum_bytes = 128 * 1024

    def __init__(self, lifecycle, kind):
        self.lifecycle, self.kind = lifecycle, kind
        budget = _owner_budget(lifecycle)
        self.timeout_seconds = (
            lifecycle.timeout_seconds
            if budget is None
            else budget.export_seconds + budget.replay_seconds + budget.authority_seconds
        )
        check_review_seconds(self.timeout_seconds)

    async def respond(self, request):
        host = self.lifecycle
        if request.series_sha256 != digest(host.service.config.series):
            raise ValueError("model-delivery control selected another series")
        transition = (
            None
            if isinstance(request, ModelDeliveryAdoptionPrepare)
            else request.certificate.transition
            if isinstance(request, ModelDeliveryAdoptionCommit)
            else request.transition
        )
        cohort = request.cohort_sha256 if transition is None else transition.cohort_sha256
        candidate = selected_owner_candidate(host, cohort)
        node = await adoption_owner_node(host, cohort)
        async with node.serial, node.controller.serial, node.controller.sampling_lock:
            control = node.controller
            history, state, _, _ = control._history()
            _, pending = control.store.status(cohort)
            prepared = pending
            if self.kind == "prepare-reserved" and prepared is None:
                prepared = await run_owned_thread(
                    host.service.intake.pending_policy_adoption, cohort
                )
            if self.kind == "prepare-reserved" and prepared is not None:
                if history_tip(history) != request.predecessor_sha256:
                    raise ValueError("model-delivery preparation lost its selected predecessor")
                expected = await run_owned_thread(
                    candidate.prepare, history, prepared.observed_at_block
                )
                if expected != prepared:
                    raise ValueError("model-delivery preparation conflicts with pending control")
                # The existing exact reservation owns the completed review.
                # Reconcile its current local census without another remote
                # pass, including after a lost response or owner restart.
                await run_owned_thread(
                    partial(
                        census_model_delivery,
                        host.service.intake,
                        host.service.uploads,
                        prepared,
                        candidate,
                        reserve=True,
                    )
                )
                transition = control.store.reserve_exact(prepared)
            elif self.kind in {"prepare", "prepare-reserved"}:
                if history_tip(history) != request.predecessor_sha256 or pending is not None:
                    raise ValueError("model-delivery preparation lost its selected predecessor")
                block = await await_progress(
                    _owned_block(host.provider, _owner_budget(host)),
                    stage="adoption_preparation_owned_finality",
                    cohort=cohort,
                )
                transition = await run_owned_thread(candidate.prepare, history, block)
                await candidate.verify(history, transition)
                reserve = self.kind == "prepare-reserved"
                if reserve:
                    final_block = await await_progress(
                        _owned_block(host.provider, _owner_budget(host)),
                        stage="adoption_reservation_owned_finality",
                        cohort=cohort,
                    )
                    if final_block < block:
                        raise ValueError("model-delivery owned finality regressed during review")
                await run_owned_thread(
                    partial(
                        census_model_delivery,
                        host.service.intake,
                        host.service.uploads,
                        transition,
                        candidate,
                        reserve=reserve,
                    )
                )
                if reserve:
                    transition = control.store.reserve_exact(transition)
            elif self.kind == "reserve":
                prior = any(s.transition == transition for s in history.transitions)
                if not prior:
                    if pending is not None and pending != transition:
                        raise ValueError(
                            "model-delivery reservation conflicts with pending control"
                        )
                    expected = propose_recovery_transition(
                        state,
                        history.authority.authority,
                        operation="adopt_model_delivery",
                        observed_at_block=transition.observed_at_block,
                        evidence_sha256=transition.evidence_sha256,
                        model_delivery_adoption=transition.model_delivery_adoption,
                    )
                    if expected != transition:
                        raise ValueError("model-delivery reservation lost its selected control tip")
                if not prior and pending != transition:
                    block = await _owned_block(host.provider, _owner_budget(host))
                    if block < transition.observed_at_block:
                        raise ValueError("model-delivery reservation is ahead of owned finality")
                # Hold lifecycle progress while the intake owner atomically
                # validates receipt heights and gates fresh participation.
                # Its durable reservation is reconciled into control on restart.
                if not prior:
                    # An exact pending control is written only after the first
                    # candidate check and intake gate. Restart restores that
                    # same decision; keep the fresh local dual census below,
                    # without another remote model pass for an unchanged intent.
                    if pending != transition:
                        await candidate.verify(history, transition)
                    await run_owned_thread(
                        partial(
                            census_model_delivery,
                            host.service.intake,
                            host.service.uploads,
                            transition,
                            candidate,
                            reserve=True,
                        )
                    )
                transition = control.store.reserve_exact(transition)
            elif self.kind == "commit":
                if pending != transition and not any(
                    s.transition == transition for s in history.transitions
                ):
                    raise ValueError("model-delivery certificate lacks its exact owner reservation")
                control.store.commit(request.certificate)
                history, state, _, _ = control._history()
                await node._publish(history)
                return canonical_json_bytes(state)
            else:
                raise ValueError("unknown model-delivery control operation")
            return canonical_json_bytes(
                ModelDeliveryAdoptionProposal(
                    schema="umi-model-delivery-adoption-proposal/1",
                    series_sha256=request.series_sha256,
                    transition=transition,
                )
            )


def model_delivery_adoption_owner_routes(lifecycle, *, token):
    router = APIRouter()
    for kind, model in (
        ("prepare", ModelDeliveryAdoptionPrepare),
        ("prepare-reserved", ModelDeliveryAdoptionPrepare),
        ("reserve", ModelDeliveryAdoptionProposal),
        ("commit", ModelDeliveryAdoptionCommit),
    ):
        router.include_router(
            phase_review_routes(
                ModelDeliveryAdoptionOwner(lifecycle, kind),
                token=token,
                path=ROOT + "/" + kind,
                request_model=model,
                maximum_request_bytes=128 * 1024,
            )
        )
    return router
