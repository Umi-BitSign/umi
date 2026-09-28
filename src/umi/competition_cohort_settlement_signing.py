"""Native settlement phase review with durable, independently collected votes.

These ports are for the evidence, review and certification phases only. The
host selects current history and original finality independently; replay does
not authorize new miner work, change membership or submit chain transactions.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable

from .competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_recovery import (
    CohortRecoveryTransition,
    SignedCohortRecoveryTransition,
    verify_recovery_quorum,
)
from .competition_cohort_reward_package import RewardReplayInputs
from .competition_cohort_settlement import CohortSettlement
from .competition_execution import ExecutionBoundary
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import await_owned_task, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import StrictProtocolModel, canonical_json_bytes, sha256_hex


def phase_slot(cohort_sha256: str, recovery_tip_sha256: str) -> str:
    return digest(["umi-settlement-phase-slot/1", cohort_sha256, recovery_tip_sha256])


class SettlementPhaseReview:
    """Recompute progress from this reviewer's own selected native sources."""

    def __init__(
        self,
        owner: CohortSettlement,
        inputs: RewardReplayInputs,
        intake_records: Iterable[tuple[str, bytes]],
        *,
        observation: ExecutionBoundary,
        expected_tip_sha256: str,
        current_block: int,
        quality_votes=(),
        service_votes=(),
        proposed_progress: CohortPhaseProgress | None = None,
    ):
        if type(current_block) is not int or not observation.block <= current_block <= 2**53 - 1:
            raise ValueError("settlement observation is ahead of owned finality")
        result = owner.advance(
            inputs,
            intake_records,
            expected_tip_sha256=expected_tip_sha256,
            current_block=observation.block,
            quality_votes=quality_votes,
            service_votes=service_votes,
            proposed_progress=proposed_progress,
        )
        if result.progress is None:
            raise RuntimeError("settlement phase is not ready for attestation")
        if proposed_progress is not None and result.progress != proposed_progress:
            raise ValueError("proposed progress differs from independently replayed settlement")
        self.progress, self.policy = result.progress, owner.policy
        self.observation = ExecutionBoundary.model_validate_json(canonical_json_bytes(observation))
        self.state, self.restored, self.unavailable = replay_cohort_decisions(
            inputs.history,
            self.policy,
            owner.decisions,
        )
        self.authority = inputs.history.authority.authority

    def transition(self, evidence: CohortDecisionInput):
        evidence = CohortDecisionInput.model_validate_json(canonical_json_bytes(evidence))
        if evidence.progress.progress != self.progress or evidence.observation != self.observation:
            raise ValueError("phase decision differs from independently replayed settlement")
        proposed, _ = _choice(
            self.state,
            self.authority,
            self.policy,
            evidence,
            self.restored,
            self.unavailable,
        )
        if proposed is None or proposed.operation != "close_phase":
            raise ValueError("settlement review cannot authorize this phase operation")
        return proposed


class SettlementPhaseSigner:
    """Original intent and signature survive cancellation, restart and missing peers.

    Use a private signer-bound journal, separate from the native evidence owner.
    The configured signing port must use only this evaluator's named hotkey.
    """

    def __init__(
        self,
        journal: RoundJournal,
        policy: CompetitionPolicy,
        hotkey: str,
        sign: Callable[[StrictProtocolModel], Awaitable[Signature]],
        *,
        timeout_seconds: int = 300,
    ):
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.hotkey, self.account = hotkey, identity(hotkey)
        self.groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        if (
            self.account not in self.groups
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 3600
        ):
            raise ValueError(
                "settlement phase signer requires an eligible key and bounded operation"
            )
        self.journal, self.sign, self.timeout = journal, sign, timeout_seconds
        self.serial = asyncio.Lock()

    def retained_vote(self, body: CohortPhaseProgress | CohortRecoveryTransition) -> Signature:
        """Read an exact locally reviewed vote before publishing a peer request."""
        if isinstance(body, CohortPhaseProgress):
            kind, tip = "settlement_progress", body.recovery_tip_sha256
        elif isinstance(body, CohortRecoveryTransition):
            kind, tip = "settlement_transition", body.predecessor_sha256
        else:
            raise TypeError("unknown settlement vote body")
        slot = phase_slot(body.cohort_sha256, tip)
        with self.journal.locked():
            intent = self.journal.get(kind + "_intent", slot)
            if intent is None:
                raise FileNotFoundError("settlement request lacks its original reviewed intent")
            if canonical_json_bytes(intent) != canonical_json_bytes(body):
                raise ValueError("settlement request lacks its original reviewed intent")
            vote = self._saved(kind, slot, body, self.account)
            if vote is None:
                raise FileNotFoundError("settlement request lacks its original durable vote")
            return vote

    def _body(self, review: SettlementPhaseReview, evidence: CohortDecisionInput | None):
        if type(review) is not SettlementPhaseReview or digest(review.policy) != digest(
            self.policy
        ):
            raise ValueError("phase signer requires its own policy's native settlement review")
        return review.progress if evidence is None else review.transition(evidence)

    def _intent(self, kind, slot, body):
        raw = canonical_json_bytes(body)
        self.journal.reserve_records(
            kind + ":" + slot,
            (
                RecordReservation(kind + "_intent", slot, len(raw), sha256_hex(raw)),
                RecordReservation(kind + "_certificate", slot, len(raw) + 32768),
                *(
                    RecordReservation(kind + "_vote", digest([slot, who]), 2048)
                    for who in sorted(self.groups)
                ),
            ),
        )
        self.journal.put(kind + "_intent", slot, body)

    def _saved(self, kind, slot, body, who):
        old = self.journal.get(kind + "_vote", digest([slot, who]))
        if old is None:
            return None
        saved = Signature.model_validate_json(canonical_json_bytes(old))
        if identity(saved.hotkey) != who:
            raise ValueError("retained phase vote changed its selected signer")
        verify_signature(body, saved)
        return saved

    def _vote(self, kind, slot, body, vote):
        vote = Signature.model_validate_json(canonical_json_bytes(vote))
        who = identity(vote.hotkey)
        if who not in self.groups:
            raise ValueError("phase vote signer is outside the selected evaluator set")
        verify_signature(body, vote)
        key = digest([slot, who])
        old = self._saved(kind, slot, body, who)
        if old is not None:
            return old
        self.journal.put(kind + "_vote", key, vote)
        return vote

    async def attest(
        self, review: SettlementPhaseReview, evidence: CohortDecisionInput | None = None
    ):
        return await await_owned_task(asyncio.create_task(self._attest(review, evidence)))

    async def _attest(self, review, evidence):
        body = self._body(review, evidence)
        kind = "settlement_progress" if evidence is None else "settlement_transition"
        slot = phase_slot(review.progress.cohort_sha256, review.progress.recovery_tip_sha256)
        async with self.serial:
            with self.journal.locked():
                self._intent(kind, slot, body)
                old = self._saved(kind, slot, body, self.account)
                if old is not None:
                    return old
                vote = await wait_for_owned(self.sign(body), timeout=self.timeout)
                if identity(vote.hotkey) != self.account:
                    raise ValueError("phase signing port returned another evaluator's signature")
                return self._vote(kind, slot, body, vote)

    async def collect(
        self,
        review: SettlementPhaseReview,
        votes: Iterable[Signature],
        evidence: CohortDecisionInput | None = None,
    ) -> AttestedCohortPhaseProgress | SignedCohortRecoveryTransition | None:
        body = self._body(review, evidence)
        kind = "settlement_progress" if evidence is None else "settlement_transition"
        model = AttestedCohortPhaseProgress if evidence is None else SignedCohortRecoveryTransition
        slot = phase_slot(review.progress.cohort_sha256, review.progress.recovery_tip_sha256)
        async with self.serial:
            with self.journal.locked():
                self._intent(kind, slot, body)
                for count, vote in enumerate(votes, 1):
                    if count > len(self.groups):
                        raise ValueError("phase vote batch exceeds its evaluator slots")
                    self._vote(kind, slot, body, vote)
                prior = self.journal.get(kind + "_certificate", slot)
                if prior is not None:
                    certificate = model.model_validate_json(canonical_json_bytes(prior))
                    expected = certificate.progress if evidence is None else certificate.transition
                    if expected != body:
                        raise ValueError("phase certificate changed its retained body")
                    verify_recovery_quorum(body, certificate.signatures, self.policy)
                    return certificate
                signatures, groups = [], set()
                for who in sorted(self.groups):
                    vote = self._saved(kind, slot, body, who)
                    if vote is None or self.groups[who] in groups:
                        continue
                    signatures.append(vote)
                    groups.add(self.groups[who])
                if len(groups) < self.policy.required_evaluator_groups:
                    return None
                certificate = model(
                    **{
                        "progress" if evidence is None else "transition": body,
                        "signatures": tuple(signatures),
                    }
                )
                verify_recovery_quorum(body, certificate.signatures, self.policy)
                self.journal.put(kind + "_certificate", slot, certificate)
                return certificate
