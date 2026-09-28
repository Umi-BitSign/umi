"""Immutable requests and independently reviewed settlement votes.

Each approved cohort has eight fixed request slots. Replication can retry without
a deadline or access to a signing key or live SQLite database. Every new vote
requires native result replay and the reviewer's own original-proof check.
"""

from __future__ import annotations

import asyncio
import logging
import math
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_recovery import (
    CohortRecoveryTransition,
    StandingCohortRecoveryAuthority,
)
from .competition_cohort_settlement_controller import (
    CohortSettlementPhases,
    SettlementPeer,
    SettlementPeerReviewer,
)
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_cohort_settlement_proofs import SettlementRegistrationFiles
from .competition_execution import ExecutionBoundary
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import ensure_private_directory, private_path, publish_private_model
from .private_files import read_private_model as read
from .protocol import Hex32, StrictProtocolModel

logger = logging.getLogger(__name__)
PHASES = ("reference_reveal", "evidence", "review", "certification")
MAX_REQUEST_BYTES = 8 * 1024**2


class SettlementRequestHistory(StrictProtocolModel):
    history: CohortRecoveryHistory
    decisions: Annotated[tuple[CohortDecisionInput, ...], Field(max_length=128)]


class SettlementProgressRequest(SettlementRequestHistory):
    schema_: Literal["umi-settlement-progress-request/1"] = Field(alias="schema")
    progress: AttestedCohortPhaseProgress
    observation: ExecutionBoundary


class SettlementTransitionRequest(SettlementRequestHistory):
    schema_: Literal["umi-settlement-transition-request/1"] = Field(alias="schema")
    transition: CohortRecoveryTransition
    evidence: CohortDecisionInput
    proposer_vote: Signature


class SettlementVoteDelivery(StrictProtocolModel):
    request_sha256: Hex32
    vote: Signature


Request = SettlementProgressRequest | SettlementTransitionRequest


class SettlementReviewExchange:
    def __init__(
        self,
        phases: CohortSettlementPhases,
        *,
        proposer: str,
        inbox: Path,
        outbox: Path,
        proofs: SettlementRegistrationFiles,
    ):
        if type(phases) is not CohortSettlementPhases or not isinstance(
            phases.owner.authority.authority, StandingCohortRecoveryAuthority
        ):
            raise TypeError("settlement exchange requires native standing cohort phases")
        self.phases, self.proposer = phases, identity(proposer)
        if self.proposer not in phases.signer.groups:
            raise ValueError("settlement proposer is outside the approved evaluator set")
        if type(proofs) is not SettlementRegistrationFiles or digest(
            proofs.provider.policy
        ) != digest(phases.owner.policy):
            raise ValueError("settlement proof delivery differs from the selected policy")
        self.proofs = proofs
        self.reviewer = (
            SettlementPeerReviewer(phases, proofs.provider, proofs.read, proposer=proposer)
            if self.proposer != phases.signer.account
            else None
        )
        self.inbox, self.outbox = (Path(private_path(str(p))) for p in (inbox, outbox))
        if self.inbox.is_relative_to(self.outbox) or self.outbox.is_relative_to(self.inbox):
            raise ValueError("settlement exchange stores must be disjoint")
        for path in (self.inbox, self.outbox):
            ensure_private_directory(path)

    def _request_path(self, root: Path, phase: str, kind: str) -> Path:
        if phase not in PHASES or kind not in ("progress", "transition"):
            raise ValueError("unknown settlement request slot")
        return root / "requests" / self.phases.cohort / (phase + "-" + kind + ".json")

    def _vote_path(self, root: Path, request: Request, hotkey: str) -> Path:
        return root / "votes" / self.phases.cohort / digest(request) / (identity(hotkey) + ".json")

    @staticmethod
    def _body(request: Request):
        return (
            request.progress.progress
            if isinstance(request, SettlementProgressRequest)
            else request.transition
        )

    def _check(self, request: Request) -> tuple[str, str]:
        owner = self.phases.owner
        if request.history.plan != owner.plan or request.history.authority != owner.authority:
            raise ValueError("settlement request changes the configured cohort or authority")
        body = self._body(request)
        if isinstance(request, SettlementProgressRequest):
            if len(request.progress.signatures) != 1:
                raise ValueError("settlement request needs exactly its proposer's vote")
            vote, observation, kind = (
                request.progress.signatures[0],
                request.observation,
                "progress",
            )
        else:
            vote, observation, kind = (
                request.proposer_vote,
                request.evidence.observation,
                "transition",
            )
        if identity(vote.hotkey) != self.proposer:
            raise ValueError("settlement request changes its configured proposer")
        verify_signature(body, vote)
        decisions = {digest(d): d for d in request.decisions}
        expected = {
            t.transition.evidence_sha256
            for t in request.history.transitions
            if t.transition.operation != "revoke"
        }
        if len(decisions) != len(request.decisions) or set(decisions) != expected:
            raise ValueError("settlement request needs every original decision exactly once")
        state, restored, unavailable = replay_cohort_decisions(
            request.history, owner.policy, decisions.__getitem__
        )
        progress = body if kind == "progress" else request.evidence.progress.progress
        if (
            state.phase not in PHASES
            or progress.cohort_sha256 != self.phases.cohort
            or progress.recovery_tip_sha256 != state.tip_sha256
            or progress.phase != state.phase
            or progress.completion != "complete"
            or progress.observed_at_block != observation.block
            or observation.block < state.observed_at_block
        ):
            raise ValueError("settlement request changes its original phase or observation")
        if kind == "transition":
            proposed, _ = _choice(
                state,
                owner.authority.authority,
                owner.policy,
                request.evidence,
                restored,
                unavailable,
            )
            if proposed != request.transition:
                raise ValueError("settlement request changes its deterministic transition")
        return state.phase, kind

    def _history(self) -> dict:
        history = self.phases.source().inputs.history
        return dict(
            history=history,
            decisions=tuple(
                self.phases.owner.decisions(t.transition.evidence_sha256)
                for t in history.transitions
                if t.transition.operation != "revoke"
            ),
        )

    async def _publish(self, request: Request) -> None:
        if self.phases.signer.account != self.proposer:
            raise ValueError("only the selected proposer publishes settlement requests")
        phase, kind = self._check(request)
        body = self._body(request)
        local = self.phases.signer.retained_vote(body)
        supplied = request.progress.signatures[0] if kind == "progress" else request.proposer_vote
        if local != supplied:
            raise ValueError("settlement request changes the original durable proposer vote")
        # Export the original provider-owned proof before publishing a request.
        # A completed export remains usable without that provider after restart.
        observation = request.observation if kind == "progress" else request.evidence.observation
        await self.proofs.publish(observation)
        # A reviewer needs the exact certificate objects referenced by this
        # proposal, including any signatures whose envelopes differ locally.
        # Publish them before the request; interrupted delivery simply retries.
        await run_owned_thread(self.publish_objects)
        await run_owned_thread(
            partial(
                publish_private_model,
                self._request_path(self.outbox, phase, kind),
                request,
                maximum_bytes=MAX_REQUEST_BYTES,
            )
        )

    def publish_objects(self) -> None:
        files = SettlementEvidenceFiles(self.outbox / "objects")
        for key in self.phases.owner.journal.keys("endpoint_replay_object"):
            files.publish(key, self.phases.owner.archive)

    def request(self, phase: str, kind: str) -> Request:
        model = SettlementProgressRequest if kind == "progress" else SettlementTransitionRequest
        request = read(
            self._request_path(self.inbox, phase, kind), model, maximum_bytes=MAX_REQUEST_BYTES
        )
        if self._check(request) != (phase, kind):
            raise ValueError("settlement request was delivered to a different slot")
        return request

    async def _vote(self, request: Request, hotkey: str) -> Signature:
        delivery = await run_owned_thread(
            partial(
                read,
                self._vote_path(self.inbox, request, hotkey),
                SettlementVoteDelivery,
                maximum_bytes=2048,
            )
        )
        return self._check_vote(request, delivery, hotkey)

    def _check_vote(self, request, delivery, hotkey):
        if delivery.request_sha256 != digest(request) or identity(delivery.vote.hotkey) != identity(
            hotkey
        ):
            raise ValueError("settlement delivery changes its request or selected voter")
        verify_signature(self._body(request), delivery.vote)
        return delivery.vote

    def peer(self, hotkey: str) -> SettlementPeer:
        account = identity(hotkey)
        if account not in self.phases.signer.groups or account == self.proposer:
            raise ValueError("settlement peer is outside the selected independent reviewers")

        async def progress(body, observation):
            request = SettlementProgressRequest(
                schema="umi-settlement-progress-request/1",
                progress=body,
                observation=observation,
                **self._history(),
            )
            await self._publish(request)
            return await self._vote(request, hotkey)

        async def transition(body, evidence):
            request = SettlementTransitionRequest(
                schema="umi-settlement-transition-request/1",
                transition=body,
                evidence=evidence,
                proposer_vote=self.phases.signer.retained_vote(body),
                **self._history(),
            )
            await self._publish(request)
            return await self._vote(request, hotkey)

        return SettlementPeer(hotkey, progress, transition)

    async def review(self, request: Request) -> Signature:
        # Authenticate before adopting history or touching the proof transport.
        self._check(request)
        reviewer = self.reviewer
        if reviewer is None:
            raise ValueError("the proposer cannot act as an independent settlement reviewer")
        path = self._vote_path(self.outbox, request, self.phases.signer.hotkey)
        try:
            delivered = await run_owned_thread(
                partial(read, path, SettlementVoteDelivery, maximum_bytes=2048)
            )
        except FileNotFoundError:
            pass
        else:
            # Only this owned outbox records completed native review. Incoming
            # copied votes never stand in for local review. Old delivered votes
            # can be retransmitted after the local history advances.
            return self._check_vote(request, delivered, self.phases.signer.hotkey)
        try:
            vote = self.phases.signer.retained_vote(self._body(request))
        except FileNotFoundError:
            vote = None
        if vote is not None:
            # Recover a lost outbox from the signer's original reviewed intent
            # and exact signature, even after the phase ledger has advanced.
            await self._deliver(path, request, vote)
            return vote
        observation = (
            request.observation
            if isinstance(request, SettlementProgressRequest)
            else request.evidence.observation
        )
        # Authenticate original finality before importing history; unavailable
        # or invalid delivery cannot advance the receiver's retained tip.
        original = await reviewer.verify_observation(observation)
        self.phases.store.publish_history(
            request.history,
            self.phases.owner.policy,
            current_block=original.replayed_at.block_number,
        )
        for decision in request.decisions:
            self.phases.store.retain_source(self.phases.cohort, decision)
        evidence = request.evidence if isinstance(request, SettlementTransitionRequest) else None
        progress = request.progress.progress if evidence is None else evidence.progress.progress
        reviewed = await self.phases.review(observation, progress)
        if evidence is not None and reviewed.transition(evidence) != request.transition:
            raise ValueError("settlement request differs from native transition review")
        vote = await self.phases.signer.attest(reviewed, evidence)
        await self._deliver(path, request, vote)
        return vote

    async def _deliver(self, path: Path, request: Request, vote: Signature) -> None:
        await run_owned_thread(
            partial(
                publish_private_model,
                path,
                SettlementVoteDelivery(request_sha256=digest(request), vote=vote),
                maximum_bytes=2048,
            )
        )

    async def run_reviewer(self, stop: asyncio.Event, *, poll_seconds: float = 5) -> None:
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 60:
            raise ValueError("settlement reviewer poll interval is invalid")
        if self.reviewer is None:
            raise ValueError("the proposer cannot run an independent settlement reviewer")
        completed: dict[tuple[str, str], str] = {}
        while not stop.is_set():
            self.proofs.provider.ensure_observer_running()
            for phase in PHASES:
                for kind in ("progress", "transition"):
                    if stop.is_set():
                        return
                    try:
                        request = await run_owned_thread(self.request, phase, kind)
                    except FileNotFoundError:
                        continue
                    except Exception as error:
                        logger.warning(
                            "settlement_request_retry cohort=%s phase=%s kind=%s error_type=%s",
                            self.phases.cohort,
                            phase,
                            kind,
                            type(error).__name__,
                        )
                        continue
                    try:
                        key = (phase, kind)
                        sha = digest(request)
                        if key in completed and completed[key] != sha:
                            raise ValueError("completed settlement request changed")
                        await self.review(request)
                        if key not in completed:
                            logger.info(
                                "settlement_review_delivered cohort=%s phase=%s kind=%s",
                                self.phases.cohort,
                                phase,
                                kind,
                            )
                        completed[key] = sha
                    except Exception as error:
                        logger.warning(
                            "settlement_review_retry cohort=%s phase=%s kind=%s error_type=%s",
                            self.phases.cohort,
                            phase,
                            kind,
                            type(error).__name__,
                        )
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
