"""Reconcile artifact proposals, independent certificates and immutable exports.

Private reviewed inputs and reviewer certificates arrive through the configured
exchange directory. Partial delivery remains pending; committed work recovers
before finality, source inputs or reviewers are contacted again.
"""

import sqlite3
from functools import partial
from pathlib import Path

from .competition_cohort_model_acceptance import (
    ModelAcceptancePublication,
    ModelArtifactReviewInputs,
)
from .competition_cohort_model_acceptance_store import (
    MAX_PUBLICATION_BYTES,
    CohortModelAcceptances,
    PendingModelArtifacts,
)
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import publish_private_model, read_private_model


class ModelAcceptanceWorker:
    def __init__(
        self,
        owner: CohortModelAcceptances,
        capture,
        inputs: Path,
        output: Path,
        *,
        batch_size=16,
        reviewers=(),
        promote=None,
    ):
        if type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ValueError("model acceptance batch is outside bounds")
        self.owner, self.capture = owner, capture
        self.inputs, self.output, self.batch_size = inputs, output, batch_size
        self.cursors = {}
        self.reviewers = tuple(reviewers)
        self.promote = promote
        if (
            len(self.reviewers) > 64
            or any(
                p.policy != owner.intake.policy or p.cohorts != owner.intake.config.cohorts
                for p in self.reviewers
            )
            or len({identity(p.signer) for p in self.reviewers}) != len(self.reviewers)
            or (self.promote is not None and not callable(self.promote))
        ):
            raise ValueError("model reviewers change policy, cohorts or repeat a signer")

    async def _review(self, cohort, key):
        try:
            return await run_owned_thread(self.owner.certified_votes, cohort, key)
        except PendingModelArtifacts:
            pass
        request = await run_owned_thread(self.owner.review_request, cohort, key)
        votes = await run_owned_thread(self.owner.votes, cohort, key)
        retained = {identity(v.signature.hotkey) for v in votes}
        for peer in self.reviewers:
            if identity(peer.signer) in retained:
                continue
            try:
                vote = await peer.attest(request)
                await run_owned_thread(self.owner.publish_vote, vote)
            except (OSError, ValueError, RuntimeError, sqlite3.Error):
                # Persist each independent response; one unavailable reviewer
                # cannot discard another reviewer's completed vote.
                continue
        return await run_owned_thread(self.owner.certified_votes, cohort, key)

    async def _one(self, cohort, sub):
        key = digest(sub)
        retained = True
        try:
            approved = await run_owned_thread(self.owner.retained, cohort, key)
        except PendingModelArtifacts:
            retained = False
            intent = await run_owned_thread(self.owner.intent, cohort, key)
            if intent is None:
                selected = await run_owned_thread(
                    partial(
                        read_private_model,
                        self.inputs / "model-reviews" / (sub.model_revision + ".json"),
                        ModelArtifactReviewInputs,
                        maximum_bytes=MAX_PUBLICATION_BYTES,
                    )
                )
                capture = await self.capture()
                await run_owned_thread(self.owner.prepare, cohort, key, selected, capture)
                intent = await run_owned_thread(self.owner.intent, cohort, key)
            await run_owned_thread(
                partial(
                    publish_private_model,
                    self.output / "model-acceptance-proposals" / cohort / (key + ".json"),
                    intent,
                    maximum_bytes=MAX_PUBLICATION_BYTES,
                )
            )
            approved = (
                await self._review(cohort, key)
                if self.reviewers
                else await run_owned_thread(
                    partial(
                        read_private_model,
                        self.inputs / "model-acceptance-publications" / cohort / (key + ".json"),
                        ModelAcceptancePublication,
                        maximum_bytes=MAX_PUBLICATION_BYTES,
                    )
                )
            )
            if (
                approved.certificate.acceptance != intent.acceptance
                or approved.inputs != intent.inputs
            ):
                raise ValueError(
                    "delivered model acceptance differs from the selected original proposal"
                ) from None
        if self.promote is not None:
            await self.promote(approved)
        if not retained:
            await run_owned_thread(self.owner.publish, approved, await self.capture())
        await run_owned_thread(self.owner.export, cohort, key, self.output)

    async def poll_once(self):
        ready = pending = 0
        error_type = ""
        for binding in self.owner.intake.config.cohorts:
            cohort = binding.cohort_sha256
            try:
                entries = await run_owned_thread(
                    partial(
                        self.owner.entries,
                        cohort,
                        after=self.cursors.get(cohort, ""),
                        limit=self.batch_size,
                    )
                )
                for _, sub in entries:
                    try:
                        await self._one(cohort, sub)
                        ready += 1
                    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                        pending += 1
                        error_type = type(error).__name__
                self.cursors[cohort] = entries[-1][0] if len(entries) == self.batch_size else ""
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                pending += 1
                error_type = type(error).__name__
        return {
            "status": "model_acceptance_pending" if pending else "model_acceptance_current",
            "entries_exported": ready,
            "entries_pending": pending,
            "last_error_type": error_type,
            "chain_submission_authorized": False,
        }
