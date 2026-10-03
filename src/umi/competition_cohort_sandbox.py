"""Pinned CPU sandbox port for retained cohort invocations."""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Callable
from pathlib import Path

from .competition_cohort_direct_model_review import DirectModelArtifactReviewer
from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_execution_journal import CohortExecutionAttempt, case_role_model
from .competition_cohort_model_acceptance import ModelReviewRequest
from .competition_execution import read_case_video
from .competition_runner import (
    EvaluationInfrastructureError,
    OfflineCaseExecution,
    OfflineCpuRuntime,
    execute_offline_case,
    stop_retained_cpu_invocation,
)
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import CompetitionPolicy, digest
from .private_files import ensure_private_directory, private_path


class CohortCpuSandbox:
    def __init__(self, policy: CompetitionPolicy, *, archive: Path, videos: Path, workspace: Path):
        self.policy, self.archive, self.videos, self.workspace = policy, archive, videos, workspace
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
        video = await run_owned_thread(
            read_case_video, self.videos, case.video_sha256, job.runtime.maximum_video_bytes
        )
        path = self._path(attempt)
        result = await execute_offline_case(
            bundle=model,
            archive=archive,
            runtime=job.runtime,
            policy=self.policy,
            case_id=case.case_id,
            video_sha256=case.video_sha256,
            video=video,
            invocation_sha256=digest(attempt),
            workspace=path,
        )
        return result


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
    ) -> None:
        super().__init__(policy, archive=archive, videos=videos, workspace=workspace)
        if not callable(request):
            raise ValueError("direct model execution request source is not callable")
        self.artifacts, self.request = artifacts, request
        self.materializations = asyncio.Condition()
        self.cache = workspace / "direct-model-cache"
        self.cached_model_sha256: str | None = None
        self.active_candidate_invocations = 0
        ensure_private_directory(self.cache)
        self.artifacts.verify_materialization_filesystem(self.cache)

    async def _candidate_archive(self, request: ModelReviewRequest, bundle) -> Path:
        archive = self.cache / "archive"
        selected = archive / digest(bundle)
        model_sha256 = digest(bundle)
        async with self.materializations:
            while self.active_candidate_invocations and self.cached_model_sha256 != model_sha256:
                await self.materializations.wait()
            reusable = selected.is_dir() and (
                self.cached_model_sha256 == model_sha256
                or await self.artifacts.materialized(request, archive)
            )
            if not reusable:
                if self.active_candidate_invocations:
                    raise OSError("active direct model cache became unavailable")
                if archive.exists():
                    await run_owned_thread(shutil.rmtree, archive)
                await self.artifacts.materialize(request, archive)
            self.cached_model_sha256 = model_sha256
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
        _, role, _ = case_role_model(job, attempt.step_index)
        if role != "candidate":
            return await super().invoke(job, attempt)
        path = self._path(attempt)
        request = self.request(job)
        if request.direct_artifact is None:
            return await super().invoke(job, attempt)
        bundle = request.record.request.signed_submission.submission.model_bundle
        if bundle is None:
            raise ValueError("direct model execution has no bundle")
        completed = False
        archive = await self._candidate_archive(request, bundle)
        try:
            result = await self._invoke(job, attempt, archive)
            completed = True
            return result
        finally:
            try:
                await await_owned_task(asyncio.create_task(self._release_candidate_archive()))
            finally:
                if completed:
                    await run_owned_thread(path.rmdir)
