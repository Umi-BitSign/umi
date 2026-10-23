"""Reconcile artifact proposals, independent certificates and immutable exports.

Private reviewed inputs and reviewer certificates arrive through the configured
exchange directory. Partial delivery remains pending; committed work recovers
before finality, source inputs or reviewers are contacted again.
"""

import logging
import sqlite3
import time
from contextlib import contextmanager
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
from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS
from .competition_progress import _failure_details
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import publish_private_model, read_private_model
from .protocol import canonical_json_bytes

_LOG = logging.getLogger("umi.competition.progress")


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
        prepare_review=None,
    ):
        if type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ValueError("model acceptance batch is outside bounds")
        self.owner, self.capture = owner, capture
        self.inputs, self.output, self.batch_size = inputs, output, batch_size
        self.cursors = {}
        self.reviewers = tuple(reviewers)
        self.promote = promote
        self.prepare_review = prepare_review
        if (
            len(self.reviewers) > 64
            or any(
                p.policy != owner.intake.policy or p.cohorts != owner.intake.config.cohorts
                for p in self.reviewers
            )
            or len({identity(p.signer) for p in self.reviewers}) != len(self.reviewers)
            or (self.promote is not None and not callable(self.promote))
            or (prepare_review is not None and not callable(prepare_review))
        ):
            raise ValueError("model reviewers change policy, cohorts or repeat a signer")

    @contextmanager
    def _stage(self, cohort, key, stage):
        # Stage identity is public digest metadata; exception text can contain
        # private review documents and must never enter these diagnostics.
        started = time.monotonic()
        body = {
            "schema": "umi-model-acceptance-stage/1",
            "cohort_sha256": cohort,
            "submission_sha256": key,
            "stage": stage,
            "total": 1,
            "eta_seconds": None,
            "eta_basis": "awaiting_owned_operation",
            "eta_scope": "current_acceptance_substage",
            "certification_authority": False,
        }
        PUBLIC_COHORT_PROGRESS.record("acceptance", {**body, "status": "running"})
        _LOG.info(
            "model_acceptance_stage %s",
            canonical_json_bytes(
                {
                    **body,
                    "status": "running",
                    "completed": 0,
                    "elapsed_seconds": 0,
                    "stalled_or_retrying": False,
                }
            ).decode(),
        )
        try:
            with WorkProgress(
                "model_acceptance_" + stage, 1, unit="submissions", cohort=cohort, estimate=False
            ) as progress:
                yield
                progress.advance()
        except BaseException as error:
            PUBLIC_COHORT_PROGRESS.record(
                "acceptance",
                {
                    **body,
                    "status": "pending",
                    "error_type": type(error).__name__,
                    "stalled_or_retrying": True,
                },
            )
            if stage != "retained_lookup" or not isinstance(error, PendingModelArtifacts):
                self.owner.intake.model_certification_progress.operation(
                    cohort, key, stage, error_type=type(error).__name__
                )
            _LOG.info(
                "model_acceptance_stage %s",
                canonical_json_bytes(
                    {
                        **body,
                        "status": "pending",
                        "completed": 0,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "stalled_or_retrying": True,
                        "error_type": type(error).__name__,
                        "causes": _failure_details(error),
                    }
                ).decode(),
            )
            raise
        else:
            PUBLIC_COHORT_PROGRESS.record("acceptance", {**body, "status": "completed"})
            self.owner.intake.model_certification_progress.operation(cohort, key, stage)
            _LOG.info(
                "model_acceptance_stage %s",
                canonical_json_bytes(
                    {
                        **body,
                        "status": "completed",
                        "completed": 1,
                        "eta_seconds": 0,
                        "eta_basis": "completed_scope",
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "stalled_or_retrying": False,
                    }
                ).decode(),
            )

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
            with self._stage(cohort, key, "retained_lookup"):
                approved = await run_owned_thread(self.owner.retained, cohort, key)
        except PendingModelArtifacts:
            retained = False
            selected = None
            with self._stage(cohort, key, "input_readiness"):
                # A missing external review cannot be repaired by reading model
                # bytes. Existing intents retain their original inputs, so their
                # recovery never depends on this external delivery file.
                if not await run_owned_thread(self.owner.has_intent, cohort, key):
                    path = self.inputs / "model-reviews" / (sub.model_revision + ".json")
                    try:
                        selected = await run_owned_thread(
                            partial(
                                read_private_model,
                                path,
                                ModelArtifactReviewInputs,
                                maximum_bytes=MAX_PUBLICATION_BYTES,
                            )
                        )
                    except FileNotFoundError:
                        if self.prepare_review is None:
                            raise
                        selected = await self.prepare_review(cohort, sub)
                        if selected.model_sha256 != sub.model_revision:
                            raise ValueError(
                                "prepared model review differs from selected bundle"
                            ) from None
                        await run_owned_thread(
                            partial(
                                publish_private_model,
                                path,
                                selected,
                                maximum_bytes=MAX_PUBLICATION_BYTES,
                            )
                        )
            with self._stage(cohort, key, "payload"):
                await self.owner.ensure_payload(cohort, key)
            with self._stage(cohort, key, "intent_lookup"):
                intent = await run_owned_thread(self.owner.intent, cohort, key)
            if intent is None:
                with self._stage(cohort, key, "intent_preparation"):
                    if selected is None:
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
            with self._stage(cohort, key, "proposal_publication"):
                await run_owned_thread(
                    partial(
                        publish_private_model,
                        self.output / "model-acceptance-proposals" / cohort / (key + ".json"),
                        intent,
                        maximum_bytes=MAX_PUBLICATION_BYTES,
                    )
                )
            with self._stage(cohort, key, "review_quorum"):
                approved = (
                    await self._review(cohort, key)
                    if self.reviewers
                    else await run_owned_thread(
                        partial(
                            read_private_model,
                            self.inputs
                            / "model-acceptance-publications"
                            / cohort
                            / (key + ".json"),
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
            with self._stage(cohort, key, "promotion"):
                await self.promote(approved)
        if not retained:
            with self._stage(cohort, key, "publication"):
                await run_owned_thread(self.owner.publish, approved, await self.capture())
        with self._stage(cohort, key, "export"):
            await run_owned_thread(self.owner.export, cohort, key, self.output)

    async def _report_inventory(self, cohort):
        try:
            inventory = await run_owned_thread(self.owner.certification_inventory, cohort)
            report = self.owner.intake.model_certification_progress.report(inventory)
            _LOG.info(
                "cohort_intake_model_certification_progress %s",
                canonical_json_bytes(report).decode(),
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
            # Diagnostics cannot alter certification, reserve another writer or
            # turn missing measurement into a native admission failure.
            _LOG.warning(
                "cohort_intake_model_progress_unavailable cohort=%s error_type=%s",
                cohort,
                type(error).__name__,
            )

    async def poll_once(self):
        ready = pending = 0
        error_type = ""
        for binding in self.owner.intake.config.cohorts:
            cohort = binding.cohort_sha256
            try:
                await self._report_inventory(cohort)
                entries = await run_owned_thread(
                    partial(
                        self.owner.entries,
                        cohort,
                        after=self.cursors.get(cohort, ""),
                        limit=self.batch_size,
                    )
                )
                priority = await run_owned_thread(
                    partial(
                        self.owner.pending_latest_entries,
                        cohort,
                        limit=min(self.batch_size, 16),
                    )
                )
                # Latest uncertified candidates run before old exports. Keep
                # the original fair cursor independent of this bounded prefix.
                work = dict((*priority, *entries))
                for sub in work.values():
                    try:
                        with work_heartbeats():
                            await self._one(cohort, sub)
                        ready += 1
                    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                        pending += 1
                        error_type = type(error).__name__
                self.cursors[cohort] = entries[-1][0] if len(entries) == self.batch_size else ""
                await self._report_inventory(cohort)
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
