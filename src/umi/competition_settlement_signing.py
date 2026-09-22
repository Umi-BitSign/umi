"""Independent settlement endorsements from retained execution and local review.

No remote proposal creates local evidence receipts or promotion history. A vote
authenticates the replayed settlement, not global receipt timing or weight authority.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from .competition_evaluator import (
    order_job,
    validate_evidence_observation,
    validate_order,
    validate_void_observation,
)
from .competition_execution import (
    ModelExecutionEvidence,
    execution_slot,
    registration_boundary,
    run_record_from_execution,
)
from .competition_publication import (
    PublicationReplayLimits,
    settlement_publication_digest,
    settlement_signer_eligible,
    sign_settlement_publication,
    verify_settlement_endorsement,
)
from .competition_round_journal import RoundJournal
from .competition_round_plan import RoundProposal
from .competition_rounds import (
    CutoffEndorsement,
    validate_proposal,
    verify_endorsement,
)
from .competition_settlement_capacity import settlement_capacity
from .competition_settlement_preparation import MAX_BYTES, validate_preparation
from .competition_void import VoidEvaluationEvidence, validate_own_void
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class SettlementEndorsement(StrictProtocolModel):
    publication_sha256: Hex32
    signature: Signature


def validate_local_execution(worker, order, independent, own, suite, head):
    hotkey = worker.config.evaluator_hotkey
    body = own.announcement
    verify_signature(body, own.signature)
    if (
        body.order_sha256 != digest(order)
        or identity(body.evaluator_hotkey) != identity(hotkey)
        or identity(own.signature.hotkey) != identity(hotkey)
    ):
        raise ValueError("local execution announcement belongs to another evaluator")
    job = order_job(order, hotkey, worker.policy, worker.legacy)
    actual_job = (
        body.evidence.job
        if isinstance(body.evidence, ModelExecutionEvidence)
        else body.evidence.incumbent.job
    )
    if actual_job != job:
        raise ValueError("local execution differs from the retained assignment")
    expected = run_record_from_execution(
        body.evidence, independent.attested_result.result, suite, worker.policy, current_block=head
    )
    runs = [
        r.run
        for r in independent.evaluator_runs
        if identity(r.run.evaluator_hotkey) == identity(hotkey)
    ]
    if runs != [expected]:
        raise ValueError("missing the exact independently executed run")


class IndependentSettlementSigner:
    def __init__(self, worker, cutoff_journal, review_store, *, limits):
        if review_store.policy != worker.policy:
            raise ValueError("settlement review store belongs to another policy")
        self.worker, self.cutoffs, self.reviews = worker, cutoff_journal, review_store
        self.limits = PublicationReplayLimits.model_validate_json(canonical_json_bytes(limits))
        self.capacity = settlement_capacity(self.limits)
        self.journal = RoundJournal(
            Path(worker.config.state_directory) / "settlement-signing",
            {
                "policy": digest(worker.policy),
                "hotkey": identity(worker.config.evaluator_hotkey),
                "cutoffs": str(cutoff_journal.path),
                "review_store": str(review_store.path),
                "limits": self.limits.model_dump(mode="json"),
            },
            maximum_rounds=worker.config.maximum_orders,
            maximum_bytes=worker.config.maximum_journal_bytes,
            maximum_record_bytes=self.capacity.preparation_bytes,
        )
        self.serial = asyncio.Lock()

    def _cutoff(self, prepared):
        round_ = prepared.publication.round
        slot = str(round_.sequence)
        raw, vote = self.cutoffs.get("intent", slot), self.cutoffs.get("vote", slot)
        if raw is None or vote is None:
            raise ValueError("settlement signer did not independently reserve the cutoff")
        proposal = validate_proposal(
            RoundProposal.model_validate_json(canonical_json_bytes(raw)),
            self.worker.policy,
            self.limits,
        )
        vote = verify_endorsement(
            CutoffEndorsement.model_validate_json(canonical_json_bytes(vote)),
            proposal,
            self.worker.policy,
        )
        if (
            identity(vote.signature.hotkey) != identity(self.worker.config.evaluator_hotkey)
            or proposal.cutoff != prepared.cutoff.publication
            or proposal.submissions != prepared.roster.submissions
            or self.cutoffs.get("suite", round_.suite_sha256) != {"proposal": digest(proposal)}
        ):
            raise ValueError("settlement cutoff differs from its local reservation")

    def _local_evidence(self, prepared, head):
        worker = self.worker
        publication = prepared.publication
        round_, settlement = publication.round, publication.settlement
        hotkey = worker.config.evaluator_hotkey
        for entry in prepared.evidence.entries:
            slot = execution_slot(round_, entry.submission, hotkey)
            is_void = isinstance(entry.evidence, VoidEvaluationEvidence)
            signed, independent, receipt, own = worker.journal.settlement_evidence(
                slot, void=is_void
            )
            validate_order(signed, worker.policy, worker.legacy)
            order = signed.order
            if (
                order.round != round_
                or order.submission != entry.submission
                or (independent != entry.evidence)
            ):
                raise ValueError("settlement differs from the completed local evaluation")
            validate_observation = (
                validate_void_observation if is_void else validate_evidence_observation
            )
            validate_observation(
                receipt,
                order,
                independent,
                hotkey,
                cutoff_block=settlement.cutoff_schedule.evidence_cutoff_block,
            )
            if is_void:
                validate_own_void(
                    independent.certificate.void,
                    own_observation=own,
                    evaluator_hotkey=hotkey,
                    signed_order=signed,
                    suite=settlement.suite,
                    policy=worker.policy,
                    legacy=worker.legacy,
                    current_block=head,
                )
            else:
                validate_local_execution(worker, order, independent, own, settlement.suite, head)

    def _promotion(self, prepared):
        actual = self.reviews.reviewed_promotion_head(
            prepared.publication.round_sha256, maximum_bytes=MAX_BYTES
        )
        if actual != prepared.publication.settlement.promotion_head:
            raise ValueError("settlement promotion differs from independently reviewed history")

    async def _current(self, prepared):
        current = await self.worker.boundary()
        self.journal.observe(current.block)
        settlement, round_ = prepared.publication.settlement, prepared.publication.round
        snapshot = settlement.registration_snapshot
        if (
            not max(settlement.observed_block, snapshot.block)
            <= current.block
            <= min(
                round_.valid_through_block,
                snapshot.block + self.worker.policy.maximum_snapshot_age_blocks,
            )
        ):
            raise ValueError("settlement signing window elapsed or snapshot is stale")
        return current.block

    async def endorse(self, prepared):
        async with self.serial:
            worker = self.worker
            prepared = validate_preparation(prepared, worker.policy, self.limits)
            publication = prepared.publication
            hotkey = worker.config.evaluator_hotkey
            if not settlement_signer_eligible(
                hotkey, publication, worker.policy, prepared.roster.submissions
            ):
                raise ValueError("unauthorized or self-interested settlement signer")
            self._cutoff(prepared)
            slot = str(publication.round.sequence)
            intent = self.journal.get("intent", slot)
            if intent is not None:
                self.journal.put("intent", slot, publication)
            old = self.journal.get("vote", slot)
            head = await self._current(prepared)
            self._local_evidence(prepared, head)
            self._promotion(prepared)
            if old is not None:
                if intent is None or self.journal.get("suite", publication.round.suite_sha256) != {
                    "publication": settlement_publication_digest(publication)
                }:
                    raise ValueError("settlement endorsement is missing its original reservations")
                vote = SettlementEndorsement.model_validate_json(canonical_json_bytes(old))
            else:
                snapshot = publication.settlement.registration_snapshot
                capture = await worker.provider.collect_at(snapshot.block)
                registration_boundary(capture)
                if capture.snapshot != snapshot:
                    raise ValueError("independent settlement registration snapshot differs")
                # Recheck local conflict and promotion state after the awaited proof.
                head = await self._current(prepared)
                self._local_evidence(prepared, head)
                self._promotion(prepared)
                self._cutoff(prepared)
                # Full evidence replay can take time. Do not sign against the
                # head captured before that CPU work.
                head = await self._current(prepared)
                # The final owned-head read yields to evidence/cutoff collection.
                # Recheck their current holds before reserving or signing a vote.
                self._local_evidence(prepared, head)
                self._cutoff(prepared)
                self._promotion(prepared)
                self.journal.put("intent", slot, publication)
                self.journal.put(
                    "suite",
                    publication.round.suite_sha256,
                    {"publication": settlement_publication_digest(publication)},
                )
                vote = SettlementEndorsement(
                    publication_sha256=settlement_publication_digest(publication),
                    signature=sign_settlement_publication(publication, worker.wallet),
                )
                self._verify(vote, prepared)
                self.journal.put("vote", slot, vote)
            self._verify(vote, prepared)
            return vote

    def _verify(self, vote, prepared):
        if vote.publication_sha256 != settlement_publication_digest(prepared.publication) or (
            identity(vote.signature.hotkey) != identity(self.worker.config.evaluator_hotkey)
        ):
            raise ValueError("settlement endorsement identity or publication differs")
        verify_settlement_endorsement(
            vote.signature, prepared.publication, self.worker.policy, prepared.roster.submissions
        )
