"""Independent preparation checkpoints and one signature over a cohort batch."""

from __future__ import annotations

import asyncio
import sqlite3
from functools import partial
from pathlib import Path
from typing import Annotated

from pydantic import Field, model_validator

from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_model_acceptance import (
    ModelAcceptanceIntent,
    ModelArtifactVote,
    ModelReviewRequest,
    check_model_vote,
)
from .competition_cohort_model_batch import (
    ModelAcceptanceBatch,
    SignedModelBatchCertificationAdoption,
    model_acceptance_batch_root,
    verify_model_acceptance_batch_body,
)
from .competition_execution import execution_boundary
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes


def model_batch_candidate_snapshot(requests, batch):
    """Bind all original records without exposing private review documents."""
    return digest(
        {
            "schema": "umi-model-batch-candidate-snapshot/1",
            "cohort_sha256": batch.cohort_sha256,
            "policy_sha256": batch.policy_sha256,
            "authority_sha256": batch.authority_sha256,
            "history_tip_sha256": batch.recovery_tip_sha256,
            "adoption_sha256": batch.adoption_sha256,
            "roster_sha256": batch.roster_sha256,
            "requests": [
                [digest(r.acceptance), digest(r.record), digest(r.admission)] for r in requests
            ],
        }
    )


class ModelBatchReviewRequest(StrictProtocolModel):
    batch: ModelAcceptanceBatch
    adoption: SignedModelBatchCertificationAdoption
    requests: Annotated[tuple[ModelReviewRequest, ...], Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def exact_candidate(self):
        keys = tuple(r.acceptance.submission_sha256 for r in self.requests)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("model batch requests must be unique and ordered")
        if self.batch.candidate_snapshot_sha256 != model_batch_candidate_snapshot(
            self.requests, self.batch
        ):
            raise ValueError("model batch changes its original candidate snapshot")
        acceptances = tuple(r.acceptance for r in self.requests)
        if (
            len(acceptances) != self.batch.accepted_count
            or model_acceptance_batch_root(acceptances) != self.batch.merkle_root_sha256
            or any(
                a.policy_sha256 != self.batch.policy_sha256
                or a.cohort_sha256 != self.batch.cohort_sha256
                or a.authority_sha256 != self.batch.authority_sha256
                or a.accepted_at_block > self.batch.certified_at_block
                for a in acceptances
            )
        ):
            raise ValueError("model batch membership differs from its original requests")
        return self


class ModelBatchArtifactVote(StrictProtocolModel):
    batch: ModelAcceptanceBatch
    signature: Signature


def check_model_batch_vote(vote, request, policy, *, signer=None):
    account = identity(vote.signature.hotkey)
    if (
        vote.batch != request.batch
        or account not in {identity(e.hotkey) for e in policy.evaluators}
        or account in {identity(r.acceptance.recipient_hotkey) for r in request.requests}
        or (signer is not None and account != identity(signer))
    ):
        raise ValueError("model batch vote changes body or independent reviewer")
    verify_signature(vote.batch, vote.signature)


async def _prepare_entry(reviewer, request, history, block):
    """Reuse the same durable per-model intent used by individual certification."""
    a = request.acceptance
    slot = a.cohort_sha256 + ":" + a.submission_sha256
    saved = await run_owned_thread(reviewer.journal.get, "model_request", slot)
    raw = await run_owned_thread(reviewer.journal.get, "model_intent", slot)
    vote = await run_owned_thread(reviewer.journal.get, "model_vote", slot)
    if saved is not None:
        if canonical_json_bytes(saved) != canonical_json_bytes(request) or raw is None:
            raise ValueError("batch review changes or loses an original model intent")
        intent = ModelAcceptanceIntent.model_validate_json(canonical_json_bytes(raw))
        if intent.acceptance != a:
            raise ValueError("batch review changes its original acceptance")
        if vote is not None:
            check_model_vote(
                ModelArtifactVote.model_validate(vote),
                a,
                reviewer.policy,
                signer=reviewer.config.signer,
            )
        await run_owned_thread(reviewer._qualify_transport, a)
        return
    if raw is not None or vote is not None:
        raise ValueError("batch review intent lacks its original request; repair required")
    reviewer._validate(request, history, block, history_verified=True)
    intent = await reviewer._review_inputs(request, verified_snapshot=(history, block))
    # Journal transactions serialize only these small immutable commits. Remote
    # model I/O holds neither a SQLite transaction nor a live owner connection.
    await run_owned_thread(reviewer._reserve, request, intent, history)
    await run_owned_thread(reviewer._qualify_transport, a, history)


async def _prepare_all(reviewer, request, history, block):
    remaining = iter(request.requests)
    errors = []
    workers = min(reviewer.config.preparation_concurrency, len(request.requests))
    with (
        work_heartbeats(),
        WorkProgress(
            "model_batch_independent_preparation",
            len(request.requests),
            unit="models",
            cohort=request.batch.cohort_sha256,
            planning_range_seconds=(0, 600 * ((len(request.requests) + workers - 1) // workers)),
            planning_basis="planning_600_seconds_per_worker_wave_provider_and_model_size_dependent",
        ) as progress,
    ):

        async def work():
            for item in remaining:
                try:
                    await _prepare_entry(reviewer, item, history, block)
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    errors.append(error)
                else:
                    progress.advance()

        async def run():
            results = await asyncio.gather(
                *(work() for _ in range(workers)),
                return_exceptions=True,
            )
            for result in results:
                if isinstance(result, BaseException):
                    raise result

        # Never abandon a worker writing a checkpoint when an HTTP caller leaves.
        await await_owned_task(asyncio.create_task(run()))
        if errors:
            raise OSError("model batch preparation remains incomplete") from errors[0]


async def attest_model_batch(reviewer, request):
    request = ModelBatchReviewRequest.model_validate_json(canonical_json_bytes(request))
    batch, cohort = request.batch, request.batch.cohort_sha256
    if reviewer.cohorts.get(cohort) != batch.authority_sha256:
        raise ValueError("model batch review is outside configured cohort authority")
    directory = reviewer.config.batch_certification_adoptions_directory
    if directory is None:
        raise ValueError("model batch certification adoption is not selected")
    approved = await run_owned_thread(
        partial(
            read_private_model,
            Path(directory) / (cohort + ".json"),
            SignedModelBatchCertificationAdoption,
            maximum_bytes=64 * 1024,
        )
    )
    if approved != request.adoption:
        raise ValueError("model batch changes the independently selected adoption")
    key, request_sha = digest(batch), digest(request)
    async with reviewer.serial:
        with reviewer.journal.locked():
            saved = await run_owned_thread(reviewer.journal.get, "model_batch_request", key)
            selected = await run_owned_thread(
                reviewer.journal.get,
                "model_batch_selected_candidate",
                cohort + ":" + digest(approved.adoption),
            )
            if selected is not None and canonical_json_bytes(selected) != canonical_json_bytes(
                batch
            ):
                raise ValueError("model batch changes the selected final candidate")
            if saved is not None and saved != {"request_sha256": request_sha}:
                raise ValueError("model batch retry changes its exact original request")
            vote = await run_owned_thread(reviewer.journal.get, "model_batch_vote", key)
            if vote is not None:
                if saved is None or selected is None:
                    raise ValueError("model batch vote lost its original intent; repair required")
                vote = ModelBatchArtifactVote.model_validate(vote)
                check_model_batch_vote(
                    vote, request, reviewer.policy, signer=reviewer.config.signer
                )
                return vote
            source = await reviewer.history(cohort)
            history = source.history
            block = execution_boundary(await reviewer.capture()).block
            view = verify_cohort_history(
                history,
                reviewer.policy,
                expected_tip_sha256=history_tip(history),
                current_block=block,
            )
            if view.state.phase != "intake":
                raise ValueError("model batch signing requires open native intake")
            verify_model_acceptance_batch_body(
                batch,
                approved,
                history,
                reviewer.policy,
                maximum_block=block,
            )
            if identity(reviewer.config.signer) in {
                identity(item.acceptance.recipient_hotkey) for item in request.requests
            }:
                raise ValueError("model submitters cannot review their own artifacts")
            # A selected cohort/adoption has one final signing candidate. Retain
            # it before external work so a restart cannot sign a conflicting
            # replacement header while old signatures are still in flight.
            await run_owned_thread(
                reviewer.journal.put,
                "model_batch_selected_candidate",
                cohort + ":" + digest(approved.adoption),
                batch,
            )
            await _prepare_all(reviewer, request, history, block)
            # Artifact I/O can take minutes. Check the mutable owner head once
            # before signing; completed immutable model checks remain retained
            # if an authenticated transition changed the signing context.
            current = await reviewer.history(cohort)
            final_block = execution_boundary(await reviewer.capture()).block
            if current.history != history:
                current_view = verify_cohort_history(
                    current.history,
                    reviewer.policy,
                    expected_tip_sha256=history_tip(current.history),
                    current_block=final_block,
                )
                if current_view.state.phase != "intake":
                    raise OSError("model batch intake closed during preparation")
            verify_model_acceptance_batch_body(
                batch,
                approved,
                current.history,
                reviewer.policy,
                maximum_block=final_block,
            )
            await run_owned_thread(
                reviewer.journal.put_many,
                (
                    ("model_batch_request", key, {"request_sha256": request_sha}),
                    ("model_batch_adoption", cohort, approved),
                    ("model_batch_candidate", batch.candidate_snapshot_sha256, batch),
                ),
            )
            with WorkProgress(
                "model_batch_signing",
                1,
                unit="certificates",
                cohort=cohort,
                estimate=False,
                planning_range_seconds=(0, reviewer.config.signing_timeout_seconds),
                planning_basis="planning_configured_signer_response_budget",
            ) as progress:
                signature = await wait_for_owned(
                    reviewer.sign(batch),
                    timeout=reviewer.config.signing_timeout_seconds,
                )
                vote = ModelBatchArtifactVote(batch=batch, signature=signature)
                check_model_batch_vote(
                    vote, request, reviewer.policy, signer=reviewer.config.signer
                )
                await run_owned_thread(reviewer.journal.put, "model_batch_vote", key, vote)
                progress.advance()
            return vote
