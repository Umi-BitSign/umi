"""Pinned CPU sandbox port for retained cohort invocations."""

from __future__ import annotations

import shutil
from pathlib import Path

from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_execution_journal import CohortExecutionAttempt, case_role_model
from .competition_execution import read_case_video
from .competition_runner import (
    EvaluationInfrastructureError,
    OfflineCaseExecution,
    OfflineCpuRuntime,
    execute_offline_case,
    stop_retained_cpu_invocation,
)
from .concurrency import run_owned_thread
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
            archive=self.archive,
            runtime=job.runtime,
            policy=self.policy,
            case_id=case.case_id,
            video_sha256=case.video_sha256,
            video=video,
            invocation_sha256=digest(attempt),
            workspace=path,
        )
        # A successful return already establishes container cleanup. Remove the
        # now-empty invocation directory; never recursively remove unknown data.
        await run_owned_thread(path.rmdir)
        return result
