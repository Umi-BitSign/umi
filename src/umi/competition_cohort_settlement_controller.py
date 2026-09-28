"""Native settlement observer/certifier ports for the recurring cohort loop.

The host owns source delivery, finality, signer lifecycle and the process lock.
Peer ports transport proposals and signatures; every peer must run its own
SettlementPhaseReview before using its named key. No port supplies readiness.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import partial

from .competition_chain import RegistrationCapture
from .competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
    CohortProgressIntent,
)
from .competition_cohort_quality_signing import SignedClosedQualityVote
from .competition_cohort_recovery import (
    CohortRecoveryState,
    CohortRecoveryTransition,
    verify_recovery_quorum,
)
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_cohort_reward_package import RewardReplayInputs
from .competition_cohort_service_certification import ServiceAllocationVote
from .competition_cohort_settlement import CohortSettlement
from .competition_cohort_settlement_signing import (
    SettlementPhaseReview,
    SettlementPhaseSigner,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SettlementInputBatch:
    inputs: RewardReplayInputs
    intake: tuple[tuple[str, bytes], ...]
    quality_votes: tuple[SignedClosedQualityVote, ...] = ()
    service_votes: tuple[ServiceAllocationVote, ...] = ()


@dataclass(frozen=True)
class SettlementPeer:
    hotkey: str
    progress: Callable[[AttestedCohortPhaseProgress, ExecutionBoundary], Awaitable[Signature]]
    transition: Callable[[CohortRecoveryTransition, CohortDecisionInput], Awaitable[Signature]]


class SettlementPhaseQuorumPending(RuntimeError):
    pass


class CohortSettlementPhases:
    def __init__(
        self,
        *,
        owner: CohortSettlement,
        store: CohortRecoveryStore,
        signer: SettlementPhaseSigner,
        source: Callable[[], SettlementInputBatch],
        peers: tuple[SettlementPeer, ...],
    ):
        accounts = tuple(identity(peer.hotkey) for peer in peers)
        if (
            digest(owner.policy) != digest(signer.policy)
            or len(set(accounts)) != len(accounts)
            or any(who not in signer.groups or who == signer.account for who in accounts)
        ):
            raise ValueError("settlement controller peers differ from the selected evaluator set")
        self.owner, self.store, self.signer = owner, store, signer
        self.source, self.peers = source, peers
        self.cohort = digest(owner.plan)

    async def review(
        self, observation: ExecutionBoundary, proposed_progress=None
    ) -> SettlementPhaseReview:
        state, _ = self.store.status(self.cohort)
        batch = self.source()
        # Snapshot controller-owned SQLite sources on its owning thread. The
        # slow native replay can then run without starving the finality loop.
        # No worker thread borrows this controller's live SQLite connection.
        decisions = {
            item.transition.evidence_sha256: self.owner.decisions(item.transition.evidence_sha256)
            for item in batch.inputs.history.transitions
            if item.transition.operation != "revoke"
        }
        owner = copy.copy(self.owner)
        owner.decisions = decisions.__getitem__
        reviewed = await run_owned_thread(
            partial(
                SettlementPhaseReview,
                owner,
                batch.inputs,
                batch.intake,
                observation=observation,
                expected_tip_sha256=state.tip_sha256,
                current_block=observation.block,
                quality_votes=batch.quality_votes,
                service_votes=batch.service_votes,
                proposed_progress=proposed_progress,
            )
        )
        if self.store.status(self.cohort)[0] != state:
            raise RuntimeError("settlement history changed during native review")
        return reviewed

    async def _certificate(self, review, evidence=None):
        local = await self.signer.attest(review, evidence)
        certificate = await self.signer.collect(review, (local,), evidence)
        if certificate is not None:
            return certificate
        body = review.progress if evidence is None else review.transition(evidence)
        for peer in self.peers:
            try:
                if evidence is None:
                    # Authenticate the configured proposer's original vote;
                    # this envelope is not a quorum completion certificate.
                    request = AttestedCohortPhaseProgress(progress=body, signatures=(local,))
                    vote = await wait_for_owned(
                        peer.progress(request, review.observation), timeout=self.signer.timeout
                    )
                else:
                    vote = await wait_for_owned(
                        peer.transition(body, evidence), timeout=self.signer.timeout
                    )
                if identity(vote.hotkey) != identity(peer.hotkey):
                    raise ValueError("settlement peer changed its selected signer")
                verify_signature(body, vote)
            except (OSError, ValueError, asyncio.TimeoutError) as error:
                logger.info(
                    "settlement_peer_pending cohort=%s signer=%s error_type=%s",
                    self.cohort,
                    identity(peer.hotkey),
                    type(error).__name__,
                )
                continue
            # Local persistence errors must propagate, not be blamed on peers.
            certificate = await self.signer.collect(review, (vote,), evidence)
            if certificate is not None:
                return certificate
        raise SettlementPhaseQuorumPending("settlement phase awaits independent evaluator votes")

    async def sample(
        self, state: CohortRecoveryState, capture: RegistrationCapture
    ) -> CohortPhaseProgress:
        if state.cohort_sha256 != self.cohort:
            raise ValueError("settlement observer belongs to another cohort")
        reviewed = await self.review(execution_boundary(capture))
        if reviewed.state != state:
            raise ValueError("settlement history changed before observation")
        return reviewed.progress

    async def attest(self, progress: CohortPhaseProgress):
        original = self.store.progress_intent(
            self.cohort, progress.recovery_tip_sha256, CohortProgressIntent
        )
        if original is None or original.progress != progress:
            raise ValueError("settlement signing lacks the controller's original observation")
        return await self._certificate(await self.review(original.observation, progress))

    async def certify(self, proposal: CohortRecoveryTransition, evidence: CohortDecisionInput):
        reviewed = await self.review(evidence.observation, evidence.progress.progress)
        if reviewed.transition(evidence) != proposal:
            raise ValueError("settlement proposal differs from native phase replay")
        return await self._certificate(reviewed, evidence)


class SettlementPeerReviewer:
    """Independently review the original finalized capture and native results.

    The host selects history, original evidence delivery, finality and the named
    signer. Request transport cannot supply a verification flag or new policy.
    This port grants no current registration or chain-submission permission.
    """

    def __init__(
        self,
        phases: CohortSettlementPhases,
        provider: HistoricalRegistrationProvider,
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
        *,
        proposer: str,
    ):
        self.phases, self.provider, self.archive = phases, provider, archive
        self.proposer = identity(proposer)
        if (
            digest(provider.policy) != digest(phases.owner.policy)
            or self.proposer not in phases.signer.groups
            or self.proposer == phases.signer.account
        ):
            raise ValueError("settlement peer has a different policy or proposer")

    async def verify_observation(self, observation: ExecutionBoundary):
        """Authenticate original finality before a receiver adopts its history."""
        raw, metadata = await self.archive(observation)
        original = await self.provider.review_archive(observation, raw, metadata)
        if (
            original.original != observation
            or original.replayed_at.block_number < observation.block
        ):
            raise ValueError("settlement peer did not verify the original observation")
        return original

    async def _review(self, progress, observation):
        if observation.block != progress.observed_at_block:
            raise ValueError("settlement peer observation belongs to another block")
        await self.verify_observation(observation)
        return await self.phases.review(observation, progress)

    async def progress(self, request: AttestedCohortPhaseProgress, observation: ExecutionBoundary):
        request = AttestedCohortPhaseProgress.model_validate_json(canonical_json_bytes(request))
        observation = ExecutionBoundary.model_validate_json(canonical_json_bytes(observation))
        if len(request.signatures) != 1 or identity(request.signatures[0].hotkey) != self.proposer:
            raise ValueError("settlement request lacks the configured proposer's signature")
        verify_signature(request.progress, request.signatures[0])
        return await self.phases.signer.attest(await self._review(request.progress, observation))

    async def transition(self, proposal: CohortRecoveryTransition, evidence: CohortDecisionInput):
        proposal = CohortRecoveryTransition.model_validate_json(canonical_json_bytes(proposal))
        evidence = CohortDecisionInput.model_validate_json(canonical_json_bytes(evidence))
        verify_recovery_quorum(
            evidence.progress.progress, evidence.progress.signatures, self.phases.owner.policy
        )
        # Quorum-authenticated progress also authenticates this deterministic
        # transition; native transition() checks the complete original decision.
        reviewed = await self._review(evidence.progress.progress, evidence.observation)
        if reviewed.transition(evidence) != proposal:
            raise ValueError("settlement peer received another phase transition")
        return await self.phases.signer.attest(reviewed, evidence)
