"""Pinned CPU sandbox port for retained cohort invocations."""

from __future__ import annotations

import asyncio
import inspect
import os
import shutil
from collections.abc import Callable
from contextlib import asynccontextmanager, nullcontext
from pathlib import Path

from .competition_artifacts import preserved_bundle_available
from .competition_cohort_direct_model_review import DirectModelArtifactReviewer
from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_execution_journal import CohortExecutionAttempt, case_role_model
from .competition_cohort_model_acceptance import ModelReviewRequest
from .competition_cohort_public_progress import PUBLIC_COHORT_SCOPE
from .competition_evaluation_runtime import prepared_runtime_authorization
from .competition_execution import read_case_video
from .competition_model_cache_space import BootDiskModelCache, managed_model_slot
from .competition_runner import (
    EvaluationInfrastructureError,
    OfflineCaseExecution,
    OfflineCpuRuntime,
    execute_offline_case,
    stop_retained_cpu_invocation,
)
from .competition_transport_verification import TransferProgress
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import CompetitionPolicy, digest
from .private_files import ensure_private_directory, private_path


class CohortCpuSandbox:
    def __init__(
        self,
        policy: CompetitionPolicy,
        *,
        archive: Path,
        videos: Path,
        workspace: Path,
        execution_admission=None,
    ):
        self.policy, self.archive, self.videos, self.workspace = policy, archive, videos, workspace
        self.execution_admission = execution_admission
        ensure_private_directory(workspace)
        for path in (archive, videos):
            private_path(str(path))
            if path == workspace or path in workspace.parents or workspace in path.parents:
                raise ValueError(
                    "cohort scratch must be separate from retained artifacts and videos"
                )

    def _path(self, attempt: CohortExecutionAttempt) -> Path:
        path = self.workspace / digest(attempt)
        ensure_private_directory(path)
        return path

    async def reconcile(
        self, job: RecoverableExecutionJob, attempt: CohortExecutionAttempt
    ) -> None:
        if attempt.job_sha256 != digest(job) or not isinstance(job.runtime, OfflineCpuRuntime):
            raise ValueError("sandbox recovery differs from its retained CPU job")
        await stop_retained_cpu_invocation(digest(attempt))
        # Exact owner-private invocation input copies only, after container exit.
        # No model, video archive, journal or another invocation is removed.
        path = self._path(attempt)
        await run_owned_thread(shutil.rmtree, path)

    async def invoke(
        self, job: RecoverableExecutionJob, attempt: CohortExecutionAttempt
    ) -> OfflineCaseExecution:
        result = await self._invoke(job, attempt, self.archive)
        path = self._path(attempt)
        await run_owned_thread(path.rmdir)
        return result

    async def _invoke(
        self,
        job: RecoverableExecutionJob,
        attempt: CohortExecutionAttempt,
        archive: Path,
    ) -> OfflineCaseExecution:
        if attempt.job_sha256 != digest(job) or not isinstance(job.runtime, OfflineCpuRuntime):
            raise EvaluationInfrastructureError(
                "retained cohort invocation requires its pinned CPU job"
            )
        case, _, model = case_role_model(job, attempt.step_index)
        runtime_authorization = prepared_runtime_authorization(job.round, self.policy)
        runtime_options = (
            {}
            if runtime_authorization is None
            else {"runtime_authorization": runtime_authorization}
        )
        path = self._path(attempt)

        async def execute(native_capacity=None):
            video = await run_owned_thread(
                read_case_video, self.videos, case.video_sha256, job.runtime.maximum_video_bytes
            )
            return await execute_offline_case(
                bundle=model,
                archive=archive,
                runtime=job.runtime,
                policy=self.policy,
                case_id=case.case_id,
                video_sha256=case.video_sha256,
                video=video,
                invocation_sha256=digest(attempt),
                workspace=path,
                **({} if native_capacity is None else {"native_capacity": native_capacity}),
                **runtime_options,
            )

        if self.execution_admission is None:
            return await execute()
        async with self.execution_admission.invocation(
            job.runtime, **runtime_options
        ) as native_capacity:
            return await execute(native_capacity)


def _direct_model_cache_path(workspace: Path, boot) -> Path:
    legacy = workspace / "direct-model-cache"
    with TransferProgress(
        "model_cache_path_selection", 1, unit="paths", planning_unit_seconds=(0.001, 0.1)
    ) as progress:
        if boot is None or legacy.is_relative_to(Path(boot.directory)):
            # Existing supported layouts keep their exact cache and invocation
            # bindings, including interrupted materializations.
            selected = legacy
        else:
            # A new explicit root must not silently strand an older cache.
            # Refuse before creating either root; its operator must qualify a
            # preserving migration or consumer release first.
            if legacy.is_symlink() or (
                legacy.exists() and (not legacy.is_dir() or any(legacy.iterdir()))
            ):
                progress.emit("repair_required", reason="legacy_model_cache_needs_migration")
                raise OSError("existing direct model cache requires a preserving migration")
            selected = Path(boot.directory) / "direct-model-cache"
        progress.advance(1)
        return selected


class DirectCohortCpuSandbox(CohortCpuSandbox):
    """Materialize at most a bounded number of R2 candidates per invocation."""

    def __init__(
        self,
        policy: CompetitionPolicy,
        *,
        archive: Path,
        videos: Path,
        workspace: Path,
        artifacts: DirectModelArtifactReviewer,
        request: Callable[[RecoverableExecutionJob], ModelReviewRequest],
        legacy_artifacts=None,
        execution_admission=None,
        concurrency=1,
    ) -> None:
        boot = getattr(getattr(artifacts, "config", None), "materialization_boot_disk_cache", None)
        cache = _direct_model_cache_path(workspace, boot)
        if boot is not None:
            # Create the selected private root before mkdir(parents=True) can
            # give an intermediate cache directory the process's ordinary umask.
            artifacts.verify_materialization_filesystem(Path(boot.directory))
        super().__init__(
            policy,
            archive=archive,
            videos=videos,
            workspace=workspace,
            execution_admission=execution_admission,
        )
        if not callable(request):
            raise ValueError("direct model execution request source is not callable")
        self.artifacts, self.request = artifacts, request
        self.legacy_artifacts = legacy_artifacts
        self.materializations = asyncio.Condition()
        self.cache = cache
        self.cached_request_sha256: str | None = None
        self.active_candidate_invocations = 0
        self.boot = boot
        self.paired_execution = asyncio.Lock()
        self.slot_identities: dict[Path, str] = {}
        self.slot_recency: dict[Path, int] = {}
        self.slot_clock = 0
        ensure_private_directory(self.cache)
        self.artifacts.verify_materialization_filesystem(self.cache)
        self.parallel = None
        if execution_admission is not None and boot is not None:
            from .competition_cohort_parallel_cache import ParallelModelCache

            self.parallel = ParallelModelCache(self, execution_admission, concurrency)

    @property
    def prepared_execution_scope(self):
        return getattr(self, "parallel", None) is not None

    @property
    def execution_scope_before_reserve(self):
        return getattr(self, "parallel", None) is not None

    async def models_available(self, orders):
        """Check one authenticated source per model, without filling the local cache."""
        plans, local, resolved = {}, {}, set()
        for order in orders:
            roles = (
                ("candidate", "incumbent")
                if order.submission.submission.track == "model"
                else ("incumbent",)
            )
            for role in roles:
                bundle = (
                    order.submission.submission.model_bundle
                    if role == "candidate"
                    else order.incumbent
                )
                source = (
                    digest(order.round),
                    role,
                    digest(bundle),
                    digest(order.submission.submission) if role == "candidate" else None,
                )
                if source in resolved:
                    continue
                plan = await self._source_plan(order, role)
                resolved.add(source)
                if plan is None:
                    local[digest(bundle)] = bundle
                else:
                    plans[(id(plan.materializer), plan.identity)] = plan
        for plan in plans.values():
            await plan.materializer.available(plan.request)
        for bundle in local.values():
            await run_owned_thread(preserved_bundle_available, bundle, self.archive, self.policy)

    def resume_model_revisions(self):
        """Names in bounded managed slots are startup preferences, not byte verdicts."""
        slots = (
            self.parallel.slots
            if self.parallel is not None
            else (self.cache / "archive", self.cache / "standby")
        )
        revisions = set()
        with TransferProgress("model_resume_inventory", len(slots), unit="slots") as progress:
            for slot in slots:
                if slot.is_dir() and not slot.is_symlink():
                    with os.scandir(slot) as entries:
                        for index, entry in enumerate(entries):
                            if index >= 32:
                                raise OSError("managed model slot exceeds startup inventory bound")
                            if (
                                len(entry.name) == 64
                                and all(c in "0123456789abcdef" for c in entry.name)
                                and entry.is_dir(follow_symlinks=False)
                            ):
                                revisions.add(entry.name)
                progress.advance(1)
        if len(revisions) > 32:
            raise OSError("resident model startup hints exceed their bound")
        return tuple(sorted(revisions))

    @asynccontextmanager
    async def execution_scope(self, order, *, before_reserve=None):
        """Finish a paired job while its bounded working set remains resident.

        This changes scheduling only. Every step retains its own authority,
        inference deadline and immutable checkpoint. Legacy ports keep their
        original one-step scheduling and cache layout.
        """
        enabled = self.boot is not None and order.submission.submission.track == "model"
        if not enabled:
            if before_reserve is not None:
                await before_reserve()
            yield False
            return
        if getattr(self, "parallel", None) is not None:
            token = PUBLIC_COHORT_SCOPE.set(order.round.cohort_sha256)
            try:
                async with self.parallel.scope(
                    order,
                    runtime_authorization=prepared_runtime_authorization(order.round, self.policy),
                    before_reserve=before_reserve,
                ) as active:
                    yield active
            finally:
                PUBLIC_COHORT_SCOPE.reset(token)
            return
        token = PUBLIC_COHORT_SCOPE.set(order.round.cohort_sha256)
        try:
            if before_reserve is not None:
                await before_reserve()
            with TransferProgress("model_pair_queue", 1, unit="jobs") as progress:
                await self.paired_execution.acquire()
                progress.advance(1)
            try:
                yield True
            finally:
                self.paired_execution.release()
        finally:
            PUBLIC_COHORT_SCOPE.reset(token)

    async def _evict_archive(self, archive, *, leased=False):
        # Only the fixed bounded managed roots are disposable model slots. Capacity
        # pressure must never remove another consumer's cache or owner state.
        if not managed_model_slot(archive, self.cache):
            raise ValueError("unmanaged model cache slot")
        budget = (
            None
            if self.boot is None
            else BootDiskModelCache(
                self.boot,
                reserve_bytes=self.artifacts.config.materialization_free_space_reserve_bytes,
            )
        )
        with (
            budget.allocation_lease() if budget is not None and not leased else nullcontext(),
            TransferProgress("model_cache_eviction", 1, unit="objects") as progress,
        ):
            ensure_private_directory(archive)
            await run_owned_thread(shutil.rmtree, archive)
            self.slot_identities.pop(archive, None)
            self.slot_recency.pop(archive, None)
            progress.advance(1)

    async def _select_archive(self, request, bundle, materializer, request_sha256, protected_model):
        slots = (self.cache / "archive", self.cache / "standby")
        # Preserve the original path, including interrupted transfers. Prefer a
        # matching source over an empty slot; no payload scan is needed here.
        for archive in slots:
            if self.slot_identities.get(archive) == request_sha256 or (
                archive.exists() and await materializer.resumable(request, archive)
            ):
                return archive
        empty = next((archive for archive in slots if not archive.exists()), None)
        if empty is not None:
            return empty
        # Process-local LRU starts empty after an upgrade. Keep the current
        # round's reference resident even then; this is scheduling only and the
        # materializer still authenticates its exact source before invocation.
        disposable = tuple(
            archive
            for archive in slots
            if protected_model is None or not (archive / protected_model).is_dir()
        )
        return min(disposable or slots, key=lambda path: self.slot_recency.get(path, 0))

    async def _admit_archive(self, archive, bundle):
        budget = BootDiskModelCache(
            self.boot,
            reserve_bytes=self.artifacts.config.materialization_free_space_reserve_bytes,
        )
        with (
            TransferProgress("model_pair_capacity", 1, unit="models") as progress,
            budget.allocation_lease(),
        ):
            if not await run_owned_thread(budget.fits_materialization, bundle, archive):
                other = next(
                    path
                    for path in (self.cache / "archive", self.cache / "standby")
                    if path != archive
                )
                if other.exists():
                    # No invocations are active: capacity fallback may release
                    # the idle peer, then retain the original single-slot bound.
                    await self._evict_archive(other, leased=True)
                if not await run_owned_thread(budget.fits_materialization, bundle, archive):
                    progress.emit("retrying", reason="model_pair_capacity_unavailable")
                    raise OSError(
                        "model cache capacity cannot fit selected model within its reserve"
                    )
            progress.advance(1)

    async def _candidate_archive(
        self, request, bundle, *, materializer=None, protected_model=None
    ) -> Path:
        materializer = self.artifacts if materializer is None else materializer
        request_sha256 = materializer.cache_identity(request)
        async with self.materializations:
            if self.active_candidate_invocations and self.cached_request_sha256 != request_sha256:
                with TransferProgress("model_cache_lease_wait", 1, unit="objects") as progress:
                    progress.emit("waiting", reason="active_candidate_invocations")
                    while (
                        self.active_candidate_invocations
                        and self.cached_request_sha256 != request_sha256
                    ):
                        await self.materializations.wait()
                    progress.advance(1)
            archive = (
                self.cache / "archive"
                if self.boot is None
                else await self._select_archive(
                    request, bundle, materializer, request_sha256, protected_model
                )
            )
            selected = archive / digest(bundle)
            reusable = selected.is_dir() and (
                (
                    self.cached_request_sha256 == request_sha256
                    if self.boot is None
                    else self.slot_identities.get(archive) == request_sha256
                )
                or await materializer.materialized(request, archive)
            )
            if not reusable:
                if self.active_candidate_invocations:
                    raise OSError("active direct model cache became unavailable")
                if archive.exists() and not await materializer.resumable(request, archive):
                    # Only the disposable cache is released. Durable remote
                    # byte results are in the service state outside this tree.
                    await self._evict_archive(archive)
                if self.boot is not None:
                    await self._admit_archive(archive, bundle)
                await materializer.materialize(request, archive)
            self.cached_request_sha256 = request_sha256
            self.slot_identities[archive] = request_sha256
            self.slot_clock += 1
            self.slot_recency[archive] = self.slot_clock
            self.active_candidate_invocations += 1
            return archive

    async def _release_candidate_archive(self) -> None:
        async with self.materializations:
            if self.active_candidate_invocations < 1:
                raise RuntimeError("direct model cache invocation accounting changed")
            self.active_candidate_invocations -= 1
            if not self.active_candidate_invocations:
                self.materializations.notify_all()

    async def invoke(
        self, job: RecoverableExecutionJob, attempt: CohortExecutionAttempt
    ) -> OfflineCaseExecution:
        _, role, bundle = case_role_model(job, attempt.step_index)
        plan = (
            self.parallel.plan(job, role)
            if self.parallel is not None and self.parallel.owns(job)
            else await self._source_plan(job, role)
        )
        if plan is None:
            return await super().invoke(job, attempt)
        path = self._path(attempt)
        completed = False
        archive = (
            await self.parallel.acquire(
                plan,
                job.runtime,
                runtime_authorization=prepared_runtime_authorization(job.round, self.policy),
            )
            if self.parallel is not None
            else await self._candidate_archive(
                plan.request,
                bundle,
                materializer=plan.materializer,
                protected_model=job.round.incumbent_model_sha256,
            )
        )
        try:
            result = await self._invoke(job, attempt, archive)
            completed = True
            return result
        finally:
            try:
                await await_owned_task(
                    asyncio.create_task(
                        self.parallel.release(archive)
                        if self.parallel is not None
                        else self._release_candidate_archive()
                    )
                )
            finally:
                if completed:
                    await run_owned_thread(path.rmdir)

    async def _source_plan(self, job, role):
        from .competition_cohort_parallel_cache import ModelPlan

        bundle = job.submission.submission.model_bundle if role == "candidate" else job.incumbent
        request = self.request(job) if role == "candidate" else None
        if inspect.isawaitable(request):
            request = await request
        source = None
        if self.legacy_artifacts is not None:
            resolve = getattr(self.legacy_artifacts, "resolve_execution_source", None)
            source = (
                await resolve(job, role, bundle, request)
                if resolve is not None
                else await run_owned_thread(
                    self.legacy_artifacts.execution_source, job, role, bundle, request
                )
            )
        if source is None and (role != "candidate" or request.direct_artifact is None):
            return None
        if bundle is None:
            raise ValueError("direct model execution has no bundle")
        selected = request if source is None else source
        materializer = self.artifacts if source is None else self.legacy_artifacts
        return ModelPlan(selected, bundle, materializer, materializer.cache_identity(selected))
