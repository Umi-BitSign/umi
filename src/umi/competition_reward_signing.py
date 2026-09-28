"""Immutable standing decision intents, resumable signatures and retained quorum.

Native review precedes intent retention. Retries reuse the original body and
signature; partial quorum has no age limit. Process ownership covers signing
and persistence, including cancellation cleanup. Publication and chain effects
remain separate, independently recoverable operations.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

from .competition_cohort_recovery import verify_recovery_authority, verify_recovery_quorum
from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_decision_review import (
    ReviewedRewardDecision,
    RewardDecisionIntent,
    validate_reward_decision_review,
)
from .competition_reward_decisions import (
    MAX_DECISION_BYTES,
    MAX_DECISIONS,
    RewardControlDecision,
    SignedRewardControlDecision,
    StandingRewardSeries,
    verify_reward_decision_proposal,
    verify_reward_decisions,
)
from .competition_reward_files import StandingRewardFiles
from .competition_reward_publication import retain_standing_reward_inputs
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import canonical_json_bytes


class RewardQuorumPending(ValueError):
    """More independent evaluator votes are needed; retained votes remain valid."""


class RewardDecisionJournal:
    """One series and signer; directory/capacity changes do not change authority."""

    def __init__(
        self,
        root: Path,
        series: StandingRewardSeries,
        policy: CompetitionPolicy,
        signer: str,
        *,
        expected_chain_config_sha256: str,
        maximum_bytes: int,
    ):
        self.series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.signer = identity(signer)
        self.reviewers = {identity(e.hotkey): e for e in self.policy.evaluators}
        if self.series.policy_sha256 != digest(self.policy) or self.signer not in self.reviewers:
            raise ValueError("reward signer differs from its approved series or evaluators")
        verify_recovery_authority(self.series.recovery, self.policy)
        self.chain_config_sha256 = expected_chain_config_sha256
        if len(self.chain_config_sha256) != 64 or any(
            v not in "0123456789abcdef" for v in self.chain_config_sha256
        ):
            raise ValueError("reward signer chain configuration digest is invalid")
        self.journal = RoundJournal(
            root,
            {
                "schema": "umi-reward-decision-journal/1",
                "series": digest(self.series),
                "signer": self.signer,
                "chain_config": self.chain_config_sha256,
            },
            maximum_rounds=MAX_DECISIONS,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=MAX_DECISION_BYTES,
        )

    def _slot(self, sequence: int) -> str:
        if type(sequence) is not int or not 0 <= sequence < len(self.series.cohorts) + 2:
            raise ValueError("reward sequence lies outside its admitted series")
        return f"{sequence:04d}"

    def prefix(self, count: int) -> tuple[SignedRewardControlDecision, ...]:
        if count == 0:
            return ()
        self._slot(count - 1)
        values = []
        for sequence in range(count):
            raw = self.journal.get("reward_certificate", self._slot(sequence))
            if raw is None:
                raise FileNotFoundError("reward signing prefix is incomplete")
            values.append(
                SignedRewardControlDecision.model_validate_json(canonical_json_bytes(raw))
            )
        return verify_reward_decisions(self.series, self.policy, tuple(values))

    def load(self, sequence: int) -> RewardDecisionIntent | None:
        raw = self.journal.get("reward_intent", self._slot(sequence))
        if raw is None:
            return None
        intent = RewardDecisionIntent.model_validate_json(canonical_json_bytes(raw))
        if (
            intent.decision.sequence != sequence
            or intent.manifest_sha256 != self.series.manifest_sha256
            or intent.chain_config_sha256 != self.chain_config_sha256
        ):
            raise ValueError("retained reward intent changed its slot or selected authority")
        verify_reward_decision_proposal(
            self.series, self.policy, self.prefix(sequence), intent.decision
        )
        return intent

    def reserve(self, review: ReviewedRewardDecision) -> RewardDecisionIntent:
        """Under the process lock, retain prefix/intent and reserve result room atomically."""
        intent = validate_reward_decision_review(review)
        sequence, body = intent.decision.sequence, intent.decision
        slot = self._slot(sequence)
        verify_reward_decision_proposal(self.series, self.policy, review.preceding, body)
        if (
            intent.manifest_sha256 != self.series.manifest_sha256
            or intent.chain_config_sha256 != self.chain_config_sha256
        ):
            raise ValueError("reward review differs from signer configuration")
        old = self.load(sequence)
        if old is not None:
            if old != intent:
                raise ValueError("reward sequence already has a different retained intent")
            return old
        known = self.journal.keys("reward_intent") + self.journal.keys("reward_certificate")
        if any(key >= slot for key in known):
            raise ValueError("new reward intent would roll back a retained sequence")
        records = []
        for signed in review.preceding:
            key = self._slot(signed.decision.sequence)
            raw = self.journal.get("reward_certificate", key)
            if raw is not None:
                existing = SignedRewardControlDecision.model_validate_json(
                    canonical_json_bytes(raw)
                )
                verify_recovery_quorum(existing.decision, existing.signatures, self.policy)
                if existing.decision != signed.decision:
                    raise ValueError("reward prefix conflicts with a retained certificate")
            else:
                prior = self.journal.get("reward_intent", key)
                if (
                    prior is not None
                    and RewardDecisionIntent.model_validate_json(
                        canonical_json_bytes(prior)
                    ).decision
                    != signed.decision
                ):
                    raise ValueError("reward prefix conflicts with an unfinished local vote")
                records.append(("reward_certificate", key, signed))
        records.append(("reward_intent", slot, intent))

        def reserve_results(db):
            self.journal.reserve_records(
                slot,
                (
                    RecordReservation("reward_certificate", slot, MAX_DECISION_BYTES),
                    *(
                        RecordReservation("reward_vote", self._vote_key(slot, key), 2048)
                        for key in self.reviewers
                    ),
                ),
                db=db,
            )

        self.journal.put_many(records, index=reserve_results)
        return intent

    @staticmethod
    def _vote_key(slot: str, account: str) -> str:
        return digest(["umi-reward-decision-vote/1", slot, account])

    def _vote(self, intent: RewardDecisionIntent, signature: Signature) -> Signature:
        signature = Signature.model_validate_json(canonical_json_bytes(signature))
        if identity(signature.hotkey) not in self.reviewers:
            raise ValueError("reward vote has an unauthorized evaluator")
        verify_signature(intent.decision, signature)
        return signature

    def vote(self, sequence: int, hotkey: str) -> Signature | None:
        intent = self.load(sequence)
        if intent is None:
            return None
        account = identity(hotkey)
        raw = self.journal.get("reward_vote", self._vote_key(self._slot(sequence), account))
        if raw is None:
            return None
        vote = self._vote(intent, raw)
        if identity(vote.hotkey) != account:
            raise ValueError("retained reward vote changed its evaluator")
        return vote

    def collect(self, sequence: int, signature: Signature) -> Signature:
        intent = self.load(sequence)
        if intent is None:
            raise FileNotFoundError("reward vote has no retained intent")
        signature = self._vote(intent, signature)
        old = self.vote(sequence, signature.hotkey)
        if old is not None:
            return old
        self.journal.put(
            "reward_vote",
            self._vote_key(self._slot(sequence), identity(signature.hotkey)),
            signature,
        )
        return signature

    def certify(self, sequence: int) -> SignedRewardControlDecision:
        intent = self.load(sequence)
        raw = self.journal.get("reward_certificate", self._slot(sequence))
        if raw is not None:
            result = SignedRewardControlDecision.model_validate_json(canonical_json_bytes(raw))
            if intent is not None and result.decision != intent.decision:
                raise ValueError("reward certificate differs from retained intent")
        else:
            if intent is None:
                raise FileNotFoundError("reward certificate has no retained intent")
            groups, votes = set(), []
            for _account, evaluator in sorted(self.reviewers.items()):
                vote = self.vote(sequence, evaluator.hotkey)
                if vote is not None and evaluator.control_group not in groups:
                    groups.add(evaluator.control_group)
                    votes.append(vote)
            if len(groups) < self.policy.required_evaluator_groups:
                raise RewardQuorumPending("reward decision awaits independent evaluator quorum")
            result = SignedRewardControlDecision(decision=intent.decision, signatures=tuple(votes))
        verify_reward_decisions(self.series, self.policy, (*self.prefix(sequence), result))
        self.journal.put("reward_certificate", self._slot(sequence), result)
        return result


class RewardDecisionSigner:
    def __init__(
        self,
        journal: RewardDecisionJournal,
        sign: Callable[[RewardControlDecision], Awaitable[Signature]],
        *,
        signing_timeout_seconds: int = 300,
    ):
        if type(signing_timeout_seconds) is not int or not 1 <= signing_timeout_seconds <= 3600:
            raise ValueError("reward signing timeout must bound one retryable operation")
        self.journal, self.sign, self.timeout = journal, sign, signing_timeout_seconds
        self.serial = asyncio.Lock()

    async def attest(self, review: ReviewedRewardDecision) -> Signature:
        # Drain the whole operation on caller cancellation so a returned
        # signature is committed before releasing single-writer ownership.
        return await await_owned_task(asyncio.create_task(self._attest(review)))

    async def _attest(self, review: ReviewedRewardDecision) -> Signature:
        async with self.serial:
            with self.journal.journal.locked():
                intent = await run_owned_thread(self.journal.reserve, review)
                sequence = intent.decision.sequence
                saved = await run_owned_thread(
                    self.journal.vote,
                    sequence,
                    self.journal.reviewers[self.journal.signer].hotkey,
                )
                if saved is not None:
                    return saved
                vote = await wait_for_owned(self.sign(intent.decision), timeout=self.timeout)
                if identity(vote.hotkey) != self.journal.signer:
                    raise ValueError("reward signing port returned another evaluator's signature")
                return await run_owned_thread(self.journal.collect, sequence, vote)

    async def collect(self, sequence: int, signature: Signature) -> Signature:
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.collect, sequence, signature)

    async def certify(self, sequence: int) -> SignedRewardControlDecision:
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.certify, sequence)

    async def publish(
        self,
        sequence: int,
        files: StandingRewardFiles,
        packages: Callable[[str], CohortRewardPackage],
    ) -> str:
        """Retain quorum before delivery; a lost reply resumes without re-signing.

        This prepares private replication. It neither proves remote delivery
        nor commits control on-chain.
        """

        def retain():
            self.journal.certify(sequence)
            return retain_standing_reward_inputs(
                files,
                self.journal.series,
                self.journal.policy,
                self.journal.prefix(sequence + 1),
                packages,
            )

        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(retain)
