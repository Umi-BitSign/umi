"""Reconcile artifact proposals, independent certificates and immutable exports.

Private reviewed inputs and reviewer certificates arrive through the configured
exchange directory. Partial delivery remains pending; committed work recovers
before finality, source inputs or reviewers are contacted again.
"""

import logging
import sqlite3
import time
from contextlib import contextmanager, suppress
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
        priority_cohorts=None,
    ):
        if type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ValueError("model acceptance batch is outside bounds")
        self.owner, self.capture = owner, capture
        self.inputs, self.output, self.batch_size = inputs, output, batch_size
        self.cursors = {}
        self._fair_start = 0
        self._priority_offsets = {}
        self.reviewers = tuple(reviewers)
        self.promote = promote
        self.prepare_review = prepare_review
        self.priority_cohorts = tuple(priority_cohorts or ())
        known = {binding.cohort_sha256 for binding in owner.intake.config.cohorts}
        if (
            len(set(self.priority_cohorts)) != len(self.priority_cohorts)
            or not set(self.priority_cohorts) <= known
        ):
            raise ValueError("model acceptance priority must name distinct configured cohorts")
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
            return True
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
            # Diagnostics cannot alter certification, reserve another writer or
            # turn missing measurement into a native admission failure.
            _LOG.warning(
                "cohort_intake_model_progress_unavailable cohort=%s error_type=%s",
                cohort,
                type(error).__name__,
            )
            return False

    async def report_inventory_once(self, cohorts=None):
        """Observe one bounded cohort group independently of other groups."""
        started = time.monotonic()
        cohorts = (
            tuple(binding.cohort_sha256 for binding in self.owner.intake.config.cohorts)
            if cohorts is None
            else tuple(cohorts)
        )
        observed = 0
        for cohort in cohorts:
            observed += bool(await self._report_inventory(cohort))
        return {
            "stage": "model_certification_inventory",
            "status": "completed" if observed == len(cohorts) else "retrying",
            "completed": observed,
            "total": len(cohorts),
            "percent": 100 * observed / len(cohorts) if cohorts else 100,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "eta_seconds": 0 if observed == len(cohorts) else None,
            "eta_basis": "completed" if observed == len(cohorts) else "retry_next_poll",
            "stalled_or_retrying": observed != len(cohorts),
            "reason_code": None if observed == len(cohorts) else "native_inventory_unavailable",
            "chain_submission_authorized": False,
        }

    async def poll_once(self):
        started = time.monotonic()
        ready = pending = 0
        error_type = ""
        # Discover pending successors before acceptance work. The independent
        # inventory owner refreshes public counts even during a long review.
        bindings = self.owner.intake.config.cohorts
        probe_order = sorted(
            bindings, key=lambda binding: binding.cohort_sha256 not in self.priority_cohorts
        )
        priority_entries = {}
        for binding in probe_order:
            cohort = binding.cohort_sha256
            # A diagnostic scheduling hint never suppresses the native scan.
            with suppress(OSError, ValueError, RuntimeError, sqlite3.Error):
                priority_entries[cohort] = await run_owned_thread(
                    partial(
                        self.owner.pending_latest_entries,
                        cohort,
                        limit=min(self.batch_size, 16),
                        offset=self._priority_offsets.get(cohort, 0),
                    )
                )
                if not priority_entries[cohort] and self._priority_offsets.get(cohort, 0):
                    # The moving pending set reached its end. The empty page
                    # verified the boundary without replaying a prior item.
                    self._priority_offsets[cohort] = 0
                    priority_entries[cohort] = await run_owned_thread(
                        partial(
                            self.owner.pending_latest_entries,
                            cohort,
                            limit=min(self.batch_size, 16),
                            offset=0,
                        )
                    )
        urgent = any(priority_entries.values())
        contended = sum(bool(entries) for entries in priority_entries.values()) > 1
        # The intake bindings are sorted by hash, not by cohort date. A full
        # pending batch from each earlier hash can otherwise delay a later
        # cohort by many large model transfers. Give every pending cohort one
        # attempt per pass and rotate the first cohort between passes.
        rotated = (*bindings[self._fair_start :], *bindings[: self._fair_start])
        self._fair_start = (self._fair_start + 1) % len(bindings)
        ordered = (
            sorted(
                rotated,
                key=lambda binding: (
                    not bool(priority_entries.get(binding.cohort_sha256)),
                    not contended
                    and binding.cohort_sha256 not in self.priority_cohorts,
                ),
            )
            if urgent
            else bindings
        )
        for binding in ordered:
            cohort = binding.cohort_sha256
            priority = priority_entries.get(cohort)
            batch = self.batch_size if not urgent or priority else 1
            try:
                if contended and priority:
                    # Pending latest work already identifies the selected
                    # submission. Avoid a second ledger scan and leave the
                    # export cursor for the ordinary catch-up pass.
                    work = dict(priority[:1])
                    entries = ()
                    scanned_entries = False
                else:
                    self._priority_offsets[cohort] = 0
                    scanned_entries = True
                    entries = await run_owned_thread(
                        partial(
                            self.owner.entries,
                            cohort,
                            after=self.cursors.get(cohort, ""),
                            limit=batch,
                        )
                    )
                    if priority is None:
                        priority = await run_owned_thread(
                            partial(
                                self.owner.pending_latest_entries,
                                cohort,
                                limit=min(batch, 16),
                                offset=0,
                            )
                        )
                    work = dict((*priority, *entries))
                for sub in work.values():
                    try:
                        with work_heartbeats():
                            await self._one(cohort, sub)
                        ready += 1
                    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                        pending += 1
                        error_type = type(error).__name__
                        if contended and priority:
                            # A failed latest entry remains pending. Advance
                            # past it so later entries still get a turn.
                            self._priority_offsets[cohort] = (
                                self._priority_offsets.get(cohort, 0) + 1
                            )
                if scanned_entries:
                    self.cursors[cohort] = entries[-1][0] if len(entries) == batch else ""
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                pending += 1
                error_type = type(error).__name__
        return {
            "status": "model_acceptance_pending" if pending else "model_acceptance_current",
            "entries_exported": ready,
            "entries_pending": pending,
            "last_error_type": error_type,
            "pending_latest_cohorts": [
                binding.cohort_sha256
                for binding in ordered
                if priority_entries.get(binding.cohort_sha256)
            ],
            "fair_rotation_next": self._fair_start,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "eta_seconds": 0,
            "eta_basis": "completed_current_poll_scope",
            "stalled_or_retrying": bool(pending),
            "chain_submission_authorized": False,
        }
