"""Deliver explicitly reviewed model promotions; never create a rights approval."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .competition_chain import RegistrationCapture
from .competition_evidence import IndependentEvaluationEvidence
from .competition_execution import execution_boundary, execution_slot
from .competition_store import (
    AgreedPromotionReview,
    AttestedPromotionReview,
    CompetitionStore,
    verify_review,
)
from .concurrency import run_owned_thread
from .open_competition import EvaluationRound, EvaluationSuite, SignedSubmission, digest
from .protocol import StrictProtocolModel, canonical_json_bytes


class ReviewedPromotion(StrictProtocolModel):
    schema_: Literal["umi-reviewed-promotion-delivery/1"] = Field(alias="schema")
    review: AttestedPromotionReview
    round: EvaluationRound
    submission: SignedSubmission
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self):
        body, sub = self.review.review, self.submission.submission
        if not isinstance(body, AgreedPromotionReview) or (
            body.round_sha256 != digest(self.round)
            or body.submission_sha256 != digest(sub)
            or body.policy_sha256 != self.round.policy_sha256
            or body.model_sha256 != sub.model_revision
            or body.incumbent_model_sha256 != self.round.incumbent_model_sha256
            or sub.track != "model"
            or digest(sub) not in self.round.roster
        ):
            raise ValueError("review delivery does not bind a contributed model and round")
        return self


def validate_delivery(value, policy):
    raw = canonical_json_bytes(value)
    if len(raw) > 256 * 1024:
        raise ValueError("review delivery exceeds byte limit")
    value = ReviewedPromotion.model_validate_json(raw)
    verify_review(value.review, policy)
    return value


def retain_delivery(journal, value, policy):
    value = validate_delivery(value, policy)
    key = "promotion:" + str(value.review.review.sequence)
    # Different valid signature orderings certify the same decision. A distinct
    # decision for an already reserved sequence creates a durable conflict hold.
    journal.put(
        "promotion-decision",
        key,
        {
            "review": value.review.review.model_dump(mode="json", by_alias=True),
            "round": value.round.model_dump(mode="json", by_alias=True),
            "submission": value.submission.submission.model_dump(mode="json", by_alias=True),
        },
    )
    if journal.get("promotion-certificate", key) is None:
        journal.put("promotion-certificate", key, value)


async def apply_reviewed_promotion(store, provider, value, *, suite, archive):
    """Apply only locally retained independent evidence at the actual owned head."""
    value = validate_delivery(value, store.policy)
    existing = await run_owned_thread(store.accepted_review, value)
    if existing is not None:
        return existing
    capture = await provider.collect()
    current = execution_boundary(capture).block
    retained, evidence = await run_owned_thread(
        _retained_promotion_evidence, store, value, suite, current
    )
    if digest(evidence.attested_result.result) != value.review.review.evaluation_result_sha256:
        raise ValueError("review differs from locally retained independent evaluation")
    # Replay can take time. Collect a fresh head for the actual state mutation.
    capture = await provider.collect()
    head = execution_boundary(capture).block
    if head < current:
        raise ValueError("promotion finalized head regressed")
    return await run_owned_thread(
        _commit_reviewed_promotion, store, value, retained, evidence, suite, archive, capture
    )


def _retained_promotion_evidence(
    store: CompetitionStore, value: ReviewedPromotion, suite: EvaluationSuite, current: int
) -> tuple[SignedSubmission, IndependentEvaluationEvidence]:
    """Read and replay local evidence on one owned worker thread."""
    with store._connection() as connection:
        retained, _ = store._recorded_evaluation(
            connection, digest(value.round), digest(value.submission.submission)
        )
    if retained.submission != value.submission.submission:
        raise ValueError("promotion differs from retained submission")
    # A fresh valid signature authenticates the same body. Replay the original
    # locally retained envelope without replacing admission or execution evidence.
    evidence = store.promotion_evidence(
        round_=value.round,
        signed=retained,
        suite=suite,
        current_block=current,
    )
    return retained, evidence


def _commit_reviewed_promotion(
    store: CompetitionStore,
    value: ReviewedPromotion,
    retained: SignedSubmission,
    evidence: IndependentEvaluationEvidence,
    suite: EvaluationSuite,
    archive: Path,
    capture: RegistrationCapture,
) -> dict:
    """Keep the final window check and durable promotion inside owned work."""
    head = execution_boundary(capture).block
    with store._connection() as connection:
        cutoff = store._fixed_cutoff(connection, digest(value.round))
    if head > cutoff.evidence_cutoff_block:
        raise ValueError("promotion evidence window elapsed during review replay")
    return store.promote(
        signed=retained,
        attested=evidence.attested_result,
        round_=value.round,
        suite=suite,
        review=value.review,
        archive=archive,
        snapshot=capture.snapshot,
        current_block=head,
    )


async def apply_evaluator_promotion(worker, value):
    from .competition_evaluator import validate_evidence_observation, validate_order
    from .competition_settlement_signing import validate_local_execution
    from .private_files import read_private_model as _read

    value = validate_delivery(value, worker.policy)
    if worker.review_store is None:
        raise ValueError("review delivery requires evaluator-owned history")
    existing = await run_owned_thread(worker.review_store.accepted_review, value)
    if existing is not None:
        return existing
    slot = execution_slot(value.round, value.submission, worker.config.evaluator_hotkey)
    signed, evidence, receipt, own = await run_owned_thread(
        worker.journal.settlement_evidence, slot
    )
    validate_order(signed, worker.policy, worker.legacy)
    if (
        signed.order.round != value.round
        or signed.order.submission.submission != value.submission.submission
    ):
        raise ValueError("review differs from the local execution order")
    validate_evidence_observation(receipt, signed.order, evidence, worker.config.evaluator_hotkey)
    suite = await run_owned_thread(
        _read,
        Path(worker.config.reveal_directory) / (value.round.suite_sha256 + ".json"),
        EvaluationSuite,
    )
    current = (await worker.boundary()).block
    await run_owned_thread(
        validate_local_execution, worker, signed.order, evidence, own, suite, current
    )
    return await apply_reviewed_promotion(
        worker.review_store,
        worker.provider,
        value,
        suite=suite,
        archive=Path(worker.config.archive_directory),
    )
