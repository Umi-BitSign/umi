"""Durable per-case reviewer intent, votes and quorum collection.

The host supplies owned finality and the current certified phase history.
Original evidence is retained before signing; an outage never converts a
missing signature into a terminal result or permits changing the selection.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_admission_journal import CohortAdmissionSignerConfig
from .competition_cohort_endpoint_decision import (
    MAX_CASE_REVIEW_BYTES,
    CohortEndpointCaseDecision,
    EndpointCaseReview,
    SignedCohortEndpointCaseDecision,
    case_decision_slot,
    certify_case_decision,
    review_case_decision,
    validate_case_review,
    verify_case_decision,
)
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    OrderFinality,
    remember_order_history,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import StrictProtocolModel, canonical_json_bytes


class CohortEndpointDecisionConfig(CohortAdmissionSignerConfig):
    schema_: Literal["umi-cohort-endpoint-decision-config/1"] = Field(alias="schema")
    read_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 300


class CohortEndpointDecisionIntent(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-decision-intent/1"] = Field(alias="schema")
    review: EndpointCaseReview
    decision: CohortEndpointCaseDecision
    source: CohortOrderHistory
    observation: ExecutionBoundary
    observed_round: Annotated[int, Field(ge=0)]


def _vote_key(slot: str, hotkey: str) -> str:
    return digest(["umi-cohort-endpoint-decision-vote/1", slot, identity(hotkey)])


class CohortEndpointDecisionJournal:
    def __init__(self, config: CohortEndpointDecisionConfig, policy: CompetitionPolicy):
        self.config = CohortEndpointDecisionConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        config, policy = self.config, self.policy
        self.reviewers = {identity(e.hotkey): e.hotkey for e in self.policy.evaluators}
        if config.policy_sha256 != digest(self.policy) or identity(config.signer) not in (
            self.reviewers
        ):
            raise ValueError("endpoint decision signer differs from configured policy")
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in config.cohorts}
        self.journal = RoundJournal(
            Path(config.directory),
            config.model_dump(
                mode="json",
                by_alias=True,
                exclude={
                    "maximum_votes",
                    "maximum_bytes",
                    "signing_timeout_seconds",
                    "read_timeout_seconds",
                },
            ),
            maximum_rounds=config.maximum_votes,
            maximum_bytes=config.maximum_bytes,
            maximum_record_bytes=MAX_CASE_REVIEW_BYTES,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )

    def remember(self, source: CohortOrderHistory, block: int):
        remember_order_history(self.journal, self.cohorts, self.policy, source, block)

    def _intent(self, intent: CohortEndpointDecisionIntent):
        raw = canonical_json_bytes(intent)
        if len(raw) > MAX_CASE_REVIEW_BYTES:
            raise ValueError("endpoint decision intent exceeds its byte bound")
        intent = CohortEndpointDecisionIntent.model_validate_json(raw)
        expected = review_case_decision(
            intent.review,
            self.policy,
            intent.source,
            observed_block=intent.observation.block,
            observed_round=intent.observed_round,
        )
        if (
            intent.decision != expected
            or self.cohorts.get(expected.cohort_sha256)
            != digest(intent.source.history.authority.authority)
            or identity(self.config.signer)
            == identity(intent.review.assignment.certificate.order.submission.submission.hotkey)
        ):
            raise ValueError("endpoint decision intent differs from configured authority")
        return intent

    def load(self, slot: str) -> CohortEndpointDecisionIntent | None:
        raw = self.journal.get("endpoint_decision_intent", slot)
        if raw is None:
            return None
        intent = self._intent(
            CohortEndpointDecisionIntent.model_validate_json(canonical_json_bytes(raw))
        )
        if case_decision_slot(intent.decision) != slot:
            raise ValueError("endpoint decision intent changed its attempt slot")
        return intent

    def reserve(self, intent: CohortEndpointDecisionIntent):
        intent = self._intent(intent)
        slot = case_decision_slot(intent.decision)
        old = self.load(slot)
        if old is not None:
            if old.review != intent.review or old.decision != intent.decision:
                raise ValueError("endpoint attempt already has another decision intent")
            return old
        # Result room is claimed before retaining an intent that may be signed.
        self.journal.reserve_records(
            slot,
            (
                RecordReservation("endpoint_decision_certificate", slot, 32 * 1024),
                *(
                    RecordReservation("endpoint_decision_vote", _vote_key(slot, key), 2048)
                    for key in self.reviewers.values()
                ),
            ),
        )

        def bounded(db):
            count = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='endpoint_decision_intent'"
            ).fetchone()[0]
            if count > self.config.maximum_votes:
                raise ValueError("endpoint decision capacity exhausted")

        self.journal.put_many((("endpoint_decision_intent", slot, intent),), index=bounded)
        return intent

    def _vote(self, intent, signature):
        signature = Signature.model_validate_json(canonical_json_bytes(signature))
        miner = intent.review.assignment.certificate.order.submission.submission.hotkey
        if identity(signature.hotkey) not in self.reviewers or identity(signature.hotkey) == (
            identity(miner)
        ):
            raise ValueError("endpoint decision vote has an unauthorized reviewer")
        verify_signature(intent.decision, signature)
        return signature

    def vote(self, slot: str, hotkey: str) -> Signature | None:
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("endpoint decision intent is not retained")
        raw = self.journal.get("endpoint_decision_vote", _vote_key(slot, hotkey))
        if raw is None:
            return None
        signature = self._vote(intent, raw)
        if identity(signature.hotkey) != identity(hotkey):
            raise ValueError("endpoint decision vote changed its key")
        return signature

    def collect(self, slot: str, signature: Signature):
        """Called under the process mutex; retain partial quorum before reply."""
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("endpoint decision intent is not retained")
        signature = self._vote(intent, signature)
        key = _vote_key(slot, signature.hotkey)
        old = self.vote(slot, signature.hotkey)
        if old is None:
            self.journal.put("endpoint_decision_vote", key, signature)
        # Valid signature variants sign the same already reserved decision.
        return old or signature

    def certificate(self, slot: str) -> SignedCohortEndpointCaseDecision | None:
        intent = self.load(slot)
        if intent is None:
            return None
        raw = self.journal.get("endpoint_decision_certificate", slot)
        if raw is None:
            return None
        return verify_case_decision(
            SignedCohortEndpointCaseDecision.model_validate_json(canonical_json_bytes(raw)),
            intent.review,
            self.policy,
        )

    def certify(self, slot: str) -> SignedCohortEndpointCaseDecision:
        """Freeze the first valid quorum; no current network is needed to recover it."""
        old = self.certificate(slot)
        if old is not None:
            return old
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("endpoint decision intent is not retained")
        groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        seen, selected = set(), []
        for account, key in sorted(self.reviewers.items()):
            vote = self.vote(slot, key)
            if vote is not None and groups[account] not in seen:
                seen.add(groups[account])
                selected.append(vote)
        votes = tuple(selected)
        certificate = certify_case_decision(intent.review, votes, self.policy)
        self.journal.put("endpoint_decision_certificate", slot, certificate)
        return certificate


class CohortEndpointDecisionSigner:
    def __init__(
        self,
        journal: CohortEndpointDecisionJournal,
        provider: OrderFinality,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        current_round: Callable[[], int],
        sign: Callable[[CohortEndpointCaseDecision], Awaitable[Signature]],
    ):
        if provider.policy != journal.policy:
            raise ValueError("endpoint decision finality belongs to another policy")
        self.journal, self.provider, self.history = journal, provider, history
        self.current_round, self.sign = current_round, sign
        self.serial = asyncio.Lock()

    async def attest(self, review: EndpointCaseReview) -> Signature:
        review, decision = await run_owned_thread(validate_case_review, review, self.journal.policy)
        if decision.cohort_sha256 not in self.journal.cohorts:
            raise ValueError("endpoint decision cohort has no configured authority")
        slot, config = case_decision_slot(decision), self.journal.config
        if identity(config.signer) == identity(
            review.assignment.certificate.order.submission.submission.hotkey
        ):
            raise ValueError("miner cannot sign its own endpoint decision")
        async with self.serial:
            with self.journal.journal.locked():
                old = await run_owned_thread(self.journal.load, slot)
                if old is not None:
                    if old.review != review or old.decision != decision:
                        raise ValueError("endpoint attempt already has another decision intent")
                    vote = await run_owned_thread(self.journal.vote, slot, config.signer)
                    if vote is not None:
                        return vote
                source = await wait_for_owned(
                    self.history(decision.cohort_sha256), timeout=config.read_timeout_seconds
                )
                observation = execution_boundary(
                    await wait_for_owned(
                        self.provider.collect(), timeout=config.read_timeout_seconds
                    )
                )
                observed_round = self.current_round()
                await run_owned_thread(self.journal.remember, source, observation.block)
                await run_owned_thread(
                    partial(
                        review_case_decision,
                        review,
                        self.journal.policy,
                        source,
                        observed_block=observation.block,
                        observed_round=observed_round,
                    )
                )
                if old is None:
                    intent = CohortEndpointDecisionIntent(
                        schema="umi-cohort-endpoint-decision-intent/1",
                        review=review,
                        decision=decision,
                        source=source,
                        observation=observation,
                        observed_round=observed_round,
                    )
                    await run_owned_thread(self.journal.reserve, intent)
                current = await wait_for_owned(
                    self.history(decision.cohort_sha256), timeout=config.read_timeout_seconds
                )
                if current != source:
                    fresh = execution_boundary(
                        await wait_for_owned(
                            self.provider.collect(), timeout=config.read_timeout_seconds
                        )
                    )
                    await run_owned_thread(self.journal.remember, current, fresh.block)
                    raise OSError("endpoint decision authority changed during review")

                async def commit():
                    signature = await self.sign(decision)
                    if identity(signature.hotkey) != identity(config.signer):
                        raise ValueError("endpoint decision signed by another reviewer")
                    return await run_owned_thread(self.journal.collect, slot, signature)

                return await wait_for_owned(commit(), timeout=config.signing_timeout_seconds)

    async def collect(self, slot: str, vote: Signature):
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.collect, slot, vote)

    async def certify(self, slot: str):
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.certify, slot)

    async def recover(self, slot: str):
        intent = await run_owned_thread(self.journal.load, slot)
        if intent is None:
            raise FileNotFoundError("endpoint decision intent is not retained")
        return await self.attest(intent.review)
