"""Independently selected, non-equivocating votes for cohort batch adoption."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_model_batch import (
    ModelBatchCertificationAdoption,
    prepare_model_batch_certification_adoption,
)
from .competition_execution import execution_boundary
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes


class ModelBatchAdoptionReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-model-batch-adoption-review-request/1"] = Field(
        alias="schema", default="umi-model-batch-adoption-review-request/1"
    )
    adoption: ModelBatchCertificationAdoption
    operator_request_reference: Annotated[str, Field(min_length=1, max_length=2048)]

    @field_validator("operator_request_reference")
    @classmethod
    def explicit_reference(cls, value):
        if not value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("model batch adoption requires an explicit operator request reference")
        return value


class ModelBatchAdoptionVote(StrictProtocolModel):
    adoption: ModelBatchCertificationAdoption
    signature: Signature


def check_model_batch_adoption_vote(vote, request, policy, *, signer=None):
    account = identity(vote.signature.hotkey)
    if (
        vote.adoption != request.adoption
        or account not in {identity(e.hotkey) for e in policy.evaluators}
        or (signer is not None and account != identity(signer))
    ):
        raise ValueError("model batch adoption vote changes its selected body or reviewer")
    verify_signature(vote.adoption, vote.signature)


async def attest_model_batch_adoption(reviewer, request):
    """A request cannot select itself; reserve the private candidate before signing.

    One immutable slot per cohort prevents changing a signed or unfinished
    adoption. Completed votes return without capture, history or approval reads.
    Unfinished signing reuses its original bytes and rechecks current authority.
    """
    request = ModelBatchAdoptionReviewRequest.model_validate_json(canonical_json_bytes(request))
    adoption, cohort = request.adoption, request.adoption.cohort_sha256
    if reviewer.cohorts.get(cohort) != adoption.authority_sha256:
        raise ValueError("model batch adoption is outside configured cohort authority")
    directory = reviewer.config.batch_certification_adoptions_directory
    if directory is None:
        raise ValueError("model batch adoption candidates are not configured")
    async with reviewer.serial:
        with reviewer.journal.locked():
            saved = await run_owned_thread(
                reviewer.journal.get, "model_batch_adoption_request", cohort
            )
            vote = await run_owned_thread(reviewer.journal.get, "model_batch_adoption_vote", cohort)
            if saved is not None and canonical_json_bytes(saved) != canonical_json_bytes(request):
                raise ValueError("model batch adoption changes its original operator request")
            if vote is not None:
                if saved is None:
                    raise ValueError("model batch adoption vote lost its intent; repair required")
                vote = ModelBatchAdoptionVote.model_validate(vote)
                check_model_batch_adoption_vote(
                    vote, request, reviewer.policy, signer=reviewer.config.signer
                )
                return vote

            with (
                work_heartbeats(),
                WorkProgress(
                    "model_batch_adoption_review",
                    1,
                    unit="adoptions",
                    cohort=cohort,
                    estimate=False,
                    planning_range_seconds=(0, reviewer.config.signing_timeout_seconds),
                    planning_basis="planning_current_authority_check_and_configured_signing_budget",
                ) as progress,
            ):
                if saved is None:
                    approved = await run_owned_thread(
                        partial(
                            read_private_model,
                            Path(directory) / (cohort + ".candidate.json"),
                            ModelBatchAdoptionReviewRequest,
                            maximum_bytes=64 * 1024,
                        )
                    )
                    if approved != request:
                        raise ValueError(
                            "model batch adoption differs from private operator selection"
                        )
                source = await reviewer.history(cohort)
                current = source.history
                block = execution_boundary(await reviewer.capture()).block
                view = verify_cohort_history(
                    current,
                    reviewer.policy,
                    expected_tip_sha256=history_tip(current),
                    current_block=block,
                )
                if view.state.phase != "intake" or adoption.effective_at_block > block:
                    raise ValueError("model batch adoption requires current intake authority")
                original = current
                if saved is not None:
                    raw = await run_owned_thread(
                        reviewer.journal.get, "model_batch_adoption_history", cohort
                    )
                    if raw is None:
                        raise ValueError(
                            "model batch adoption lost original history; repair required"
                        )
                    original = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(raw))
                    prefix = current.model_copy(
                        update={"transitions": current.transitions[: len(original.transitions)]}
                    )
                    if digest(prefix) != digest(original) or (
                        len(current.transitions) > len(original.transitions)
                        and adoption.effective_at_block
                        > current.transitions[
                            len(original.transitions)
                        ].transition.observed_at_block
                    ):
                        raise ValueError("model batch adoption history rolled back or changed")
                expected = prepare_model_batch_certification_adoption(
                    original,
                    reviewer.policy,
                    expected_tip_sha256=adoption.predecessor_sha256,
                    effective_at_block=adoption.effective_at_block,
                )
                if expected != adoption:
                    raise ValueError("model batch adoption changes independently retained history")
                await run_owned_thread(
                    reviewer.journal.put_many,
                    (
                        ("model_batch_adoption_request", cohort, request),
                        ("model_batch_adoption_history", cohort, original),
                    ),
                )
                signature = await wait_for_owned(
                    reviewer.sign(adoption), timeout=reviewer.config.signing_timeout_seconds
                )
                vote = ModelBatchAdoptionVote(adoption=adoption, signature=signature)
                check_model_batch_adoption_vote(
                    vote, request, reviewer.policy, signer=reviewer.config.signer
                )
                await run_owned_thread(
                    reviewer.journal.put, "model_batch_adoption_vote", cohort, vote
                )
                progress.advance()
                return vote
