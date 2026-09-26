"""Durable reference-free order selection before evaluator work begins.

A vote assigns work; it does not authorize transport, prove publication timing,
fence a migrated writer or close an obligation. Delivery must independently
check current authority. The host owns finality and the current history source.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import Field

from .competition_cohort_admission_journal import CohortAdmissionSignerConfig
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    RecoveryFinality,
    replay_cohort_decisions,
)
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_orders import (
    MAX_ORDER_BYTES,
    RecoverableEvaluationOrder,
    SignedRecoverableEvaluationOrder,
    verify_recoverable_order_body,
)
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import (
    CompetitionPolicy,
    RegistrationSnapshot,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class OrderFinality(RecoveryFinality, Protocol):
    policy: CompetitionPolicy


class CohortOrderSignerConfig(CohortAdmissionSignerConfig):
    schema_: Literal["umi-cohort-order-signer-config/1"] = Field(alias="schema")


class CohortOrderHistory(StrictProtocolModel):
    history: CohortRecoveryHistory
    decisions: Annotated[tuple[CohortDecisionInput, ...], Field(max_length=65536)]

    def inputs(self) -> dict[str, CohortDecisionInput]:
        values = {digest(d): d for d in self.decisions}
        wanted = {
            s.transition.evidence_sha256
            for s in self.history.transitions
            if s.transition.operation != "revoke"
        }
        if len(values) != len(self.decisions) or set(values) != wanted:
            raise ValueError("order history requires exactly its original decision inputs")
        return values


class CohortOrderParticipant(StrictProtocolModel):
    consent: SignedCohortParticipationConsent
    admission: AttestedCohortParticipantAdmission
    admission_snapshot: RegistrationSnapshot


class CohortOrderIntent(StrictProtocolModel):
    schema_: Literal["umi-cohort-order-intent/1"] = Field(alias="schema")
    order: RecoverableEvaluationOrder
    participant: CohortOrderParticipant
    source: CohortOrderHistory
    observation: ExecutionBoundary


class CohortOrderVote(StrictProtocolModel):
    order_sha256: Hex32
    signature: Signature


def order_slot(order: RecoverableEvaluationOrder) -> str:
    return digest(
        {
            "schema": "umi-cohort-order-slot/1",
            "round": digest(order.round),
            "submission": digest(order.submission.submission),
        }
    )


def review_order(
    order: RecoverableEvaluationOrder,
    participant: CohortOrderParticipant,
    source: CohortOrderHistory,
    policy: CompetitionPolicy,
    block: int,
) -> RecoverableEvaluationOrder:
    source = CohortOrderHistory.model_validate_json(canonical_json_bytes(source))
    participant = CohortOrderParticipant.model_validate_json(canonical_json_bytes(participant))
    history = source.history
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=history_tip(history), current_block=block
    )
    decisions = source.inputs()
    state, _, _ = replay_cohort_decisions(history, policy, decisions.__getitem__)
    if state != view.state or state.phase != "requests":
        raise ValueError("new order signatures require an open request phase")
    preparation = view.closure("preparation")
    if decisions[preparation.evidence_sha256].progress.progress.phase_result_sha256 != digest(
        order.round
    ):
        raise ValueError("order round differs from certified preparation")
    return verify_recoverable_order_body(
        order,
        policy,
        participant.consent,
        participant.admission,
        participant.admission_snapshot,
        history,
        expected_tip_sha256=history_tip(history),
        current_block=block,
    )


class CohortOrderJournal:
    def __init__(self, config: CohortOrderSignerConfig, policy: CompetitionPolicy):
        self.config = CohortOrderSignerConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if self.config.policy_sha256 != digest(self.policy) or identity(self.config.signer) not in {
            identity(e.hotkey) for e in self.policy.evaluators
        }:
            raise ValueError("order signer does not belong to its configured policy")
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in self.config.cohorts}
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json",
                by_alias=True,
                exclude={"maximum_votes", "maximum_bytes", "signing_timeout_seconds"},
            ),
            maximum_rounds=self.config.maximum_votes,
            maximum_bytes=self.config.maximum_bytes,
            maximum_record_bytes=MAX_ORDER_BYTES,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )

    def remember(self, source: CohortOrderHistory, block: int) -> None:
        source = CohortOrderHistory.model_validate_json(canonical_json_bytes(source))
        history = source.history
        cohort = digest(history.plan)
        if self.cohorts.get(cohort) != digest(history.authority.authority):
            raise ValueError("order signer has no configured cohort authority")
        verify_cohort_history(
            history, self.policy, expected_tip_sha256=history_tip(history), current_block=block
        )
        replay_cohort_decisions(history, self.policy, source.inputs().__getitem__)

        def index(db):
            row = db.execute("SELECT history FROM order_heads WHERE cohort=?", (cohort,)).fetchone()
            if row is not None:
                raw = self.journal.get("order_history", row[0], db=db)
                old = CohortOrderHistory.model_validate_json(canonical_json_bytes(raw))
                if (
                    digest(old) != row[0]
                    or old.history.genesis != history.genesis
                    or (
                        history.transitions[: len(old.history.transitions)]
                        != old.history.transitions
                    )
                ):
                    raise ValueError("order history rolled back or forked")
            db.execute(
                "INSERT INTO order_heads VALUES (?,?) ON CONFLICT(cohort) "
                "DO UPDATE SET history=excluded.history",
                (cohort, digest(source)),
            )

        self.journal.observe(block)
        self.journal.put_many((("order_history", digest(source), source),), index=index)

    def load(self, slot: str) -> tuple[CohortOrderIntent, CohortOrderVote | None] | None:
        with self.journal.transaction() as db:
            raw = self.journal.get("intent", slot, db=db)
            if raw is None:
                return None
            intent = CohortOrderIntent.model_validate_json(canonical_json_bytes(raw))
            if order_slot(intent.order) != slot or self.cohorts.get(
                intent.order.round.cohort_sha256
            ) != digest(intent.source.history.authority.authority):
                raise ValueError("retained order intent changed its slot or authority")
            review_order(
                intent.order,
                intent.participant,
                intent.source,
                self.policy,
                intent.observation.block,
            )
            value = self.journal.get("order_vote", slot, db=db)
            vote = (
                None
                if value is None
                else CohortOrderVote.model_validate_json(canonical_json_bytes(value))
            )
            if vote is not None:
                self.check_vote(intent, vote)
            return intent, vote

    def reserve(self, intent: CohortOrderIntent) -> None:
        intent = CohortOrderIntent.model_validate_json(canonical_json_bytes(intent))
        review_order(
            intent.order, intent.participant, intent.source, self.policy, intent.observation.block
        )
        if self.cohorts.get(intent.order.round.cohort_sha256) != digest(
            intent.source.history.authority.authority
        ):
            raise ValueError("order intent has no configured authority")
        slot = order_slot(intent.order)
        # Reserve bounded result space before signing. A crash here leaves an
        # empty result allowance; retrying the same participant reuses it.
        self.journal.reserve_records(slot, (RecordReservation("order_vote", slot, 2048),))
        self.journal.put("intent", slot, intent)

    def check_vote(self, intent: CohortOrderIntent, vote: CohortOrderVote) -> None:
        if (
            vote.order_sha256 != digest(intent.order)
            or identity(vote.signature.hotkey) != identity(self.config.signer)
            or identity(self.config.signer) == identity(intent.order.submission.submission.hotkey)
        ):
            raise ValueError("order vote differs from this signer's retained selection")
        verify_signature(intent.order, vote.signature)

    def commit(self, slot: str, vote: CohortOrderVote) -> CohortOrderVote:
        saved = self.load(slot)
        if saved is None:
            raise ValueError("order vote has no retained selection")
        self.check_vote(saved[0], vote)
        if saved[1] is not None:
            return saved[1]
        self.journal.put("order_vote", slot, vote)
        return vote


class CohortOrderSigner:
    def __init__(
        self,
        journal: CohortOrderJournal,
        provider: OrderFinality,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        sign: Callable[[RecoverableEvaluationOrder], Awaitable[Signature]],
    ):
        if provider.policy != journal.policy:
            raise ValueError("order signer finality belongs to another policy")
        self.journal, self.provider, self.history, self.sign = journal, provider, history, sign
        self.serial = asyncio.Lock()

    async def recover(self, slot: str) -> CohortOrderVote:
        saved = await run_owned_thread(self.journal.load, slot)
        if saved is None:
            raise FileNotFoundError("no retained order selection")
        return await self.attest(saved[0].order, saved[0].participant)

    async def attest(
        self, order: RecoverableEvaluationOrder, participant: CohortOrderParticipant
    ) -> CohortOrderVote:
        order = RecoverableEvaluationOrder.model_validate_json(canonical_json_bytes(order))
        participant = CohortOrderParticipant.model_validate_json(canonical_json_bytes(participant))
        if identity(self.journal.config.signer) == identity(order.submission.submission.hotkey):
            raise ValueError("a submitting hotkey cannot sign its own order")
        if order.round.cohort_sha256 not in self.journal.cohorts:
            raise ValueError("order signer is not configured for this cohort")
        slot = order_slot(order)
        async with self.serial:
            with self.journal.journal.locked():
                saved = await run_owned_thread(self.journal.load, slot)
                if saved is not None:
                    if saved[0].order != order or saved[0].participant != participant:
                        raise ValueError(
                            "order slot already reserved for different original inputs"
                        )
                    if saved[1] is not None:
                        return saved[1]
                source = await self.history(order.round.cohort_sha256)
                capture = await self.provider.collect()
                boundary = execution_boundary(capture)
                await run_owned_thread(self.journal.remember, source, boundary.block)
                await run_owned_thread(
                    review_order, order, participant, source, self.journal.policy, boundary.block
                )
                if saved is None:
                    intent = CohortOrderIntent(
                        schema="umi-cohort-order-intent/1",
                        order=order,
                        participant=participant,
                        source=source,
                        observation=boundary,
                    )
                    await run_owned_thread(self.journal.reserve, intent)
                current = await self.history(order.round.cohort_sha256)
                if current != source:
                    # Remember newer closure/revocation even though signing is
                    # deferred. A stale source cannot roll it back on restart.
                    capture = await self.provider.collect()
                    await run_owned_thread(
                        self.journal.remember, current, execution_boundary(capture).block
                    )
                    raise OSError("order history changed during review; retry retained selection")

                async def sign_and_commit() -> CohortOrderVote:
                    signature = await self.sign(order)
                    vote = CohortOrderVote(order_sha256=digest(order), signature=signature)
                    return await run_owned_thread(self.journal.commit, slot, vote)

                return await wait_for_owned(
                    sign_and_commit(), timeout=self.journal.config.signing_timeout_seconds
                )


def certify_order_votes(
    order: RecoverableEvaluationOrder, votes: Sequence[CohortOrderVote], policy: CompetitionPolicy
) -> SignedRecoverableEvaluationOrder:
    order = RecoverableEvaluationOrder.model_validate_json(canonical_json_bytes(order))
    if not 1 <= len(votes) <= 64:
        raise ValueError("order certificate vote count is outside bounds")
    checked = tuple(CohortOrderVote.model_validate_json(canonical_json_bytes(v)) for v in votes)
    if any(
        v.order_sha256 != digest(order)
        or identity(v.signature.hotkey) == identity(order.submission.submission.hotkey)
        for v in checked
    ):
        raise ValueError("order certificate changed its selection or contains a self-vote")
    signatures = tuple(sorted((v.signature for v in checked), key=lambda s: identity(s.hotkey)))
    verify_recovery_quorum(order, signatures, policy)
    return SignedRecoverableEvaluationOrder(order=order, signatures=signatures)
