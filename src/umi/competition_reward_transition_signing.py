"""Native-reviewed adoption intents and resumable independent evaluator votes.

An operator request or elapsed timer is not a signature. The producer supplies
the existing native review result, retains the exact intent before signing and
publishes only a completed quorum through the shared authenticated feed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from .competition_cohort_recovery import verify_recovery_authority, verify_recovery_quorum
from .competition_reward_adoption import SignedRewardModelAdoption
from .competition_reward_adoption_consumer import RewardAdoptionConsumer
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_signing import RewardQuorumPending
from .competition_reward_transition_native import (
    RewardAdoptionReviewIntent,
    validate_reward_adoption_review,
)
from .competition_round_journal import RecordReservation, RoundJournal
from .competition_work_progress import WorkProgress
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import canonical_json_bytes

MAX_ADOPTION_BYTES = 4 * 1024**2


class RewardAdoptionJournal(RewardAdoptionConsumer):
    def __init__(
        self,
        root: Path,
        *,
        series,
        policy,
        signer,
        chain_config_sha256,
        maximum_bytes: int,
        reward_adoptions=None,
        reward_adoption_feed=None,
    ):
        self.series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.signer = identity(signer)
        self.reviewers = {identity(e.hotkey): e for e in self.policy.evaluators}
        if self.series.policy_sha256 != digest(self.policy) or self.signer not in self.reviewers:
            raise ValueError("adoption signer differs from selected series or evaluator authority")
        verify_recovery_authority(self.series.recovery, self.policy)
        if (
            type(chain_config_sha256) is not str
            or len(chain_config_sha256) != 64
            or any(c not in "0123456789abcdef" for c in chain_config_sha256)
        ):
            raise ValueError("adoption signer needs its exact native chain configuration")
        self.chain_config_sha256 = chain_config_sha256
        self._configure_reward_adoptions(
            reward_adoptions, series=self.series, policy=self.policy, feed=reward_adoption_feed
        )
        self.journal = RoundJournal(
            root,
            {
                "schema": "umi-reward-adoption-signing-owner/1",
                "series": digest(self.series),
                "policy": digest(self.policy),
                "signer": self.signer,
                "chain": chain_config_sha256,
            },
            maximum_rounds=4096,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=MAX_ADOPTION_BYTES,
        )

    @staticmethod
    def slot(proposal):
        return f"{proposal.cohort_sha256}-{proposal.revision:06d}"

    def _intent(self, intent):
        body = intent.proposal
        if (
            body.series_sha256 != digest(self.series)
            or body.policy_sha256 != digest(self.policy)
            or body.authority_sha256 != digest(self.series.recovery.authority)
            or body.cohort_sha256 not in {digest(plan) for plan in self.series.cohorts[1:]}
            or intent.chain_config_sha256 != self.chain_config_sha256
            or intent.manifest_sha256 != self.series.manifest_sha256
            or body.early_release is None
            or body.early_release.predecessor_decision_sha256 != intent.predecessor_decision_sha256
            or body.early_release.manifest_sha256 != intent.manifest_sha256
        ):
            raise ValueError(
                "retained adoption intent changed its selected authority or predecessor"
            )
        return intent

    def load(self, slot):
        raw = self.journal.get("adoption_intent", slot)
        if raw is None:
            return None
        intent = self._intent(
            RewardAdoptionReviewIntent.model_validate_json(canonical_json_bytes(raw))
        )
        if self.slot(intent.proposal) != slot:
            raise ValueError("retained adoption intent changed its cohort revision")
        return intent

    def reserve(self, review):
        intent = self._intent(validate_reward_adoption_review(review))
        body = intent.proposal
        slot = self.slot(body)
        old = self.load(slot)
        if old is not None:
            if old != intent:
                raise ValueError("adoption revision already has a different retained intent")
            return old
        selected = self.reward_adoptions
        latest = None if selected is None else selected.latest(body.cohort_sha256)
        if latest is None:
            valid = body.revision == 1 and body.predecessor_adoption_sha256 is None
        else:
            valid = body == latest.adoption or (
                body.revision == latest.adoption.revision + 1
                and body.predecessor_adoption_sha256 == digest(latest.adoption)
            )
        if not valid:
            raise ValueError("adoption intent does not extend the selected signed frontier")

        def reserve_results(db):
            self.journal.reserve_records(
                slot,
                (
                    RecordReservation("adoption_certificate", slot, MAX_ADOPTION_BYTES),
                    *(
                        RecordReservation("adoption_vote", self._vote_key(slot, account), 2048)
                        for account in self.reviewers
                    ),
                ),
                db=db,
            )

        self.journal.put_many((("adoption_intent", slot, intent),), index=reserve_results)
        return intent

    @staticmethod
    def _vote_key(slot, account):
        return digest(["umi-reward-adoption-vote/1", slot, account])

    def _vote(self, intent, value):
        signature = Signature.model_validate_json(canonical_json_bytes(value))
        if identity(signature.hotkey) not in self.reviewers:
            raise ValueError("adoption vote has an unauthorized evaluator")
        verify_signature(intent.proposal, signature)
        return signature

    def vote(self, slot, hotkey):
        intent = self.load(slot)
        if intent is None:
            return None
        account = identity(hotkey)
        raw = self.journal.get("adoption_vote", self._vote_key(slot, account))
        if raw is None:
            return None
        signature = self._vote(intent, raw)
        if identity(signature.hotkey) != account:
            raise ValueError("retained adoption vote changed its evaluator")
        return signature

    def collect(self, slot, signature):
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("adoption vote has no native-reviewed retained intent")
        signature = self._vote(intent, signature)
        old = self.vote(slot, signature.hotkey)
        if old is not None:
            return old
        self.journal.put(
            "adoption_vote", self._vote_key(slot, identity(signature.hotkey)), signature
        )
        return signature

    def certify(self, slot):
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("adoption certificate has no retained intent")
        raw = self.journal.get("adoption_certificate", slot)
        if raw is not None:
            result = SignedRewardModelAdoption.model_validate_json(canonical_json_bytes(raw))
            if result.adoption != intent.proposal:
                raise ValueError("adoption certificate differs from its retained intent")
        else:
            groups, votes = set(), []
            for _account, evaluator in sorted(self.reviewers.items()):
                vote = self.vote(slot, evaluator.hotkey)
                if vote is not None and evaluator.control_group not in groups:
                    groups.add(evaluator.control_group)
                    votes.append(vote)
            if len(groups) < self.policy.required_evaluator_groups:
                raise RewardQuorumPending("adoption awaits independent evaluator quorum")
            result = SignedRewardModelAdoption(adoption=intent.proposal, signatures=tuple(votes))
        verify_recovery_quorum(result.adoption, result.signatures, self.policy)
        self.journal.put("adoption_certificate", slot, result)
        return result


class RewardAdoptionSigner:
    def __init__(self, journal, sign, *, signing_timeout_seconds=300):
        if type(journal) is not RewardAdoptionJournal:
            raise TypeError("adoption signer requires its owned durable journal")
        if type(signing_timeout_seconds) is not int or not 1 <= signing_timeout_seconds <= 3600:
            raise ValueError("adoption signing timeout must bound one retryable operation")
        self.journal, self.sign, self.timeout = journal, sign, signing_timeout_seconds
        self.serial = asyncio.Lock()

    async def attest(self, review):
        return await await_owned_task(asyncio.create_task(self._attest(review)))

    async def _attest(self, review):
        async with self.serial:
            with self.journal.journal.locked():
                with WorkProgress(
                    "reward_adoption_sign",
                    2,
                    unit="stages",
                    estimate=False,
                    planning_range_seconds=(0, self.timeout),
                    planning_basis="one durable intent and configured bounded signing call",
                ) as progress:
                    intent = await run_owned_thread(self.journal.reserve, review)
                    slot = self.journal.slot(intent.proposal)
                    progress.advance()
                    saved = await run_owned_thread(
                        self.journal.vote, slot, self.journal.reviewers[self.journal.signer].hotkey
                    )
                    if saved is None:
                        vote = await wait_for_owned(
                            self.sign(intent.proposal), timeout=self.timeout
                        )
                        if identity(vote.hotkey) != self.journal.signer:
                            raise ValueError("adoption signing port returned another evaluator")
                        saved = await run_owned_thread(self.journal.collect, slot, vote)
                    progress.advance()
                    return saved

    async def collect(self, slot, vote):
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.collect, slot, vote)

    async def certify(self, slot):
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.certify, slot)

    async def publish(self, slot, feed):
        async with self.serial:
            with self.journal.journal.locked():
                signed = await run_owned_thread(self.journal.certify, slot)
                if feed.series != self.journal.series or feed.policy != self.journal.policy:
                    raise ValueError("adoption publication changed its configured authority")
                return await run_owned_thread(feed.publish, signed)
