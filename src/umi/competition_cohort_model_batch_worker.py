"""Bounded model preparation followed by one retained cohort signing artifact."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from functools import partial
from pathlib import Path

from .competition_cohort_model_acceptance import (
    ModelAcceptancePublication,
    ModelArtifactReviewInputs,
    model_acceptance_batch_certificates,
)
from .competition_cohort_model_acceptance_store import MAX_PUBLICATION_BYTES, PendingModelArtifacts
from .competition_cohort_model_batch import SignedModelBatchCertificationAdoption
from .competition_cohort_model_batch_review import check_model_batch_vote
from .competition_cohort_model_batch_store import CohortModelBatchStore
from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import digest, identity
from .private_files import publish_private_model, read_private_model

_ERRORS = (OSError, ValueError, RuntimeError, sqlite3.Error)


class ModelBatchAcceptanceWorker:
    def __init__(self, worker, directory, *, concurrency=10):
        if type(concurrency) is not int or not 1 <= concurrency <= 16:
            raise ValueError("model preparation concurrency is outside bounds")
        self.worker, self.directory = worker, Path(directory)
        self.concurrency = concurrency
        self.store = CohortModelBatchStore(worker.owner)

    async def _bounded(self, items, operation, *, cohort, stage):
        items = tuple(items)
        pending = iter(items)
        failures = []
        started = time.monotonic()
        workers = min(self.concurrency, len(items))
        high = 600 * ((len(items) + max(workers, 1) - 1) // max(workers, 1))
        completed = 0

        def report(status):
            elapsed = time.monotonic() - started
            remaining = len(items) - completed
            measured = elapsed * remaining / completed if completed else None
            PUBLIC_COHORT_PROGRESS.record(
                "acceptance",
                {
                    "cohort_sha256": cohort,
                    "stage": stage,
                    "status": status,
                    "completed": completed,
                    "total": len(items),
                    "percent": 100 * completed / len(items) if items else 100,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": measured if not failures else None,
                    "planning_eta_seconds": [0, high] if not completed and not failures else None,
                    "eta_basis": "retrying_unfinished_items"
                    if failures
                    else (
                        "completed_models_per_batch_wallclock"
                        if completed
                        else "planning_600_seconds_per_worker_wave_provider_and_size_dependent"
                    ),
                    "eta_scope": "current_model_batch_stage_only",
                    "eta_samples": completed,
                    "stalled_or_retrying": bool(failures),
                    "preparation_concurrency": workers,
                },
            )

        report("running")
        with (
            work_heartbeats(),
            WorkProgress(
                stage,
                len(items),
                unit="models",
                cohort=cohort,
                planning_range_seconds=(0, high),
                planning_basis="planning_600_seconds_per_worker_wave_provider_and_size_dependent",
            ) as progress,
        ):

            async def work():
                nonlocal completed
                for item in pending:
                    try:
                        await operation(item)
                    except _ERRORS as error:
                        failures.append(error)
                    else:
                        completed += 1
                        progress.advance()
                    report("running" if not failures else "pending")

            async def run():
                results = await asyncio.gather(
                    *(work() for _ in range(workers)), return_exceptions=True
                )
                for result in results:
                    if isinstance(result, BaseException):
                        raise result

            await await_owned_task(asyncio.create_task(run()))
        report("pending" if failures else "completed")
        if failures:
            raise PendingModelArtifacts(
                "model batch has unfinished item preparation"
            ) from failures[0]

    async def _inputs(self, cohort, sub):
        worker, owner = self.worker, self.worker.owner
        key = digest(sub)
        if await run_owned_thread(owner.has_intent, cohort, key):
            await owner.ensure_payload(cohort, key)
            return
        path = worker.inputs / "model-reviews" / (sub.model_revision + ".json")
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
            if worker.prepare_review is None:
                raise
            selected = await worker.prepare_review(cohort, sub)
            if selected.model_sha256 != sub.model_revision:
                raise ValueError(
                    "prepared batch model review changes its selected bundle"
                ) from None
            await run_owned_thread(
                partial(publish_private_model, path, selected, maximum_bytes=MAX_PUBLICATION_BYTES)
            )
        if selected.model_sha256 != sub.model_revision:
            raise ValueError("model batch input changes its selected bundle")
        await owner.ensure_payload(cohort, key)

    async def _prepare(self, cohort, adoption):
        worker, owner = self.worker, self.worker.owner
        original = await run_owned_thread(self.store.selected, cohort)
        # Worker children hold no intake transaction or signing/capture capability.
        await self._bounded(
            (sub for sub in original.submissions if digest(sub) not in original.retained),
            partial(self._inputs, cohort),
            cohort=cohort,
            stage="model_batch_preparation",
        )
        # Ordinals and capture clocks are reserved under one coordinator only.
        unreserved = []
        for sub in sorted(original.submissions, key=digest):
            if not await run_owned_thread(owner.has_intent, cohort, digest(sub)):
                unreserved.append(sub)
        capture = await worker.capture() if unreserved else None
        with WorkProgress(
            "model_batch_intent_reservation",
            len(unreserved),
            unit="models",
            cohort=cohort,
            planning_range_seconds=(0, 30 * len(unreserved)),
            planning_basis="planning_serial_metadata_reservation",
        ) as progress:
            for sub in unreserved:
                key = digest(sub)
                inputs = await run_owned_thread(
                    partial(
                        read_private_model,
                        worker.inputs / "model-reviews" / (sub.model_revision + ".json"),
                        ModelArtifactReviewInputs,
                        maximum_bytes=MAX_PUBLICATION_BYTES,
                    )
                )
                await run_owned_thread(owner.prepare, cohort, key, inputs, capture)
                progress.advance()
        # New/replaced requests are never silently omitted from the signed artifact.
        selected = await run_owned_thread(
            partial(self.store.selected, cohort, require_drained=True)
        )
        if selected.roster_sha256 != original.roster_sha256 or selected.history != original.history:
            raise PendingModelArtifacts(
                "model batch candidate changed during preparation; resume new items"
            )
        return await run_owned_thread(
            self.store.reserve, selected, adoption, await worker.capture()
        )

    async def _quorum(self, request):
        try:
            return await run_owned_thread(self.store.certificate, request)
        except PendingModelArtifacts:
            pass
        retained = {
            identity(v.signature.hotkey) for v in await run_owned_thread(self.store.votes, request)
        }
        groups = {
            identity(e.hotkey): e.control_group for e in self.worker.owner.intake.policy.evaluators
        }
        completed = {groups[key] for key in retained}
        total = self.worker.owner.intake.policy.required_evaluator_groups
        started, retrying = time.monotonic(), False

        def report():
            PUBLIC_COHORT_PROGRESS.record(
                "acceptance",
                {
                    "cohort_sha256": request.batch.cohort_sha256,
                    "stage": "model_batch_independent_quorum",
                    "status": "running",
                    "completed": min(len(completed), total),
                    "total": total,
                    "percent": 100 * min(len(completed), total) / total,
                    "elapsed_seconds": time.monotonic() - started,
                    "eta_seconds": None,
                    "planning_eta_seconds": [0, 600] if not retrying else None,
                    "eta_basis": "reviewer_retry_pending"
                    if retrying
                    else "planning_independent_batch_review",
                    "eta_scope": "independent_batch_signatures_only",
                    "stalled_or_retrying": retrying,
                },
            )

        report()
        # Two configured independent peers may prepare concurrently; each result
        # is retained before the other peer completes or a caller disconnects.
        peers = iter(p for p in self.worker.reviewers if identity(p.signer) not in retained)

        async def review():
            nonlocal retrying
            for peer in peers:
                try:
                    vote = await peer.attest_batch(request)
                    check_model_batch_vote(
                        vote, request, self.worker.owner.intake.policy, signer=peer.signer
                    )
                    await run_owned_thread(self.store.publish_vote, request, vote)
                    completed.add(groups[identity(vote.signature.hotkey)])
                except _ERRORS:
                    retrying = True
                report()

        async def run():
            results = await asyncio.gather(
                *(review() for _ in range(min(2, len(self.worker.reviewers)))),
                return_exceptions=True,
            )
            for result in results:
                if isinstance(result, BaseException):
                    raise result

        await await_owned_task(asyncio.create_task(run()))
        return await run_owned_thread(self.store.certificate, request)

    async def poll_cohort(self, cohort, adoption):
        worker, owner = self.worker, self.worker.owner
        completed = await run_owned_thread(self.store.completed, cohort, adoption, worker.output)
        if completed is not None:
            return completed
        request = await run_owned_thread(self.store.retained_request, cohort, adoption)
        if request is None:
            request = await self._prepare(cohort, adoption)
        manifest = await self._quorum(request)
        # Publish a single actual batch certificate; per-model exports carry proofs.
        await run_owned_thread(
            partial(
                publish_private_model,
                worker.output
                / "model-acceptance-batches"
                / cohort
                / (digest(request.batch) + ".json"),
                manifest,
                maximum_bytes=MAX_PUBLICATION_BYTES,
            )
        )
        certificates = model_acceptance_batch_certificates(manifest)
        unfinished = []
        for certificate in certificates:
            if not await run_owned_thread(
                self.store.exported,
                request,
                certificate.acceptance.submission_sha256,
                worker.output,
            ):
                unfinished.append(certificate)
        # One authenticated finalized boundary for publication metadata only.
        # Every publication still fences the current native history itself.
        publication_capture = await worker.capture() if unfinished else None

        async def publish(certificate):
            key = certificate.acceptance.submission_sha256
            if await run_owned_thread(self.store.exported, request, key, worker.output):
                return
            try:
                publication = await run_owned_thread(owner.retained, cohort, key)
            except PendingModelArtifacts:
                intent = await run_owned_thread(owner.intent, cohort, key)
                if intent is None or intent.acceptance != certificate.acceptance:
                    raise ValueError(
                        "model batch projection lost its original owner intent"
                    ) from None
                publication = ModelAcceptancePublication(
                    certificate=certificate, inputs=intent.inputs
                )
                if worker.promote is not None:
                    await worker.promote(publication)
                await run_owned_thread(owner.publish, publication, publication_capture)
            # Existing individually signed publication is retained byte-for-byte.
            await run_owned_thread(owner.export, cohort, key, worker.output)
            await run_owned_thread(self.store.mark_exported, request, publication, worker.output)

        await self._bounded(unfinished, publish, cohort=cohort, stage="model_batch_publication")
        return await run_owned_thread(self.store.mark_completed, request, manifest, worker.output)

    async def poll_once(self, bindings):
        handled, reports = set(), []
        for binding in bindings:
            cohort = binding.cohort_sha256
            # Prospective format selection must not suspend continuous scalar
            # review during open intake. The existing authenticated deadline
            # controls dispatch; final preparation still requires native drain.
            admission = self.worker.owner.intake.admission_status(cohort)
            if admission is None or admission["new_admissions_open"]:
                continue
            try:
                adoption = await run_owned_thread(
                    partial(
                        read_private_model,
                        self.directory / (cohort + ".json"),
                        SignedModelBatchCertificationAdoption,
                        maximum_bytes=64 * 1024,
                    )
                )
            except FileNotFoundError:
                continue
            handled.add(cohort)
            try:
                if adoption.adoption.cohort_sha256 != cohort:
                    raise ValueError("model batch selected adoption belongs to another cohort")
                reports.append(await self.poll_cohort(cohort, adoption))
            except _ERRORS as error:
                reports.append(
                    {
                        "cohort_sha256": cohort,
                        "status": "pending",
                        "error_type": type(error).__name__,
                        "eta_seconds": None,
                        "eta_basis": "unfinished_batch_stage",
                        "stalled_or_retrying": True,
                    }
                )
        return handled, reports
