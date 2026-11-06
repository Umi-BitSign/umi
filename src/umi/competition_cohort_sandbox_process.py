"""Owned process boundary for timed host execution, separate from review traffic."""

import asyncio
import os
import re
import signal
import sys
from contextlib import suppress
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_execution_journal import CohortExecutionAttempt
from .competition_cohort_sandbox_progress import ParentProgress
from .competition_cohort_suite_adoption_candidate import EvaluationSuiteAdoptionCandidates
from .competition_cpu_efficiency_policy import prepared_cpu_efficiency_authorization
from .competition_cpu_timing import CpuTimingInfrastructureError
from .competition_runner import OfflineCaseExecution, OfflineCpuRuntime
from .competition_transport_verification import TransferProgress
from .concurrency import await_owned_task
from .host_memory_runtime import HostMemoryAdmissionSelection
from .open_competition import CompetitionPolicy, digest
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_REQUEST_BYTES = 64 * 1024**2
MAX_RESPONSE_BYTES = 1024**2


class TimedSandboxRequest(StrictProtocolModel):
    schema_: Literal["umi-timed-sandbox-request/1"] = Field(alias="schema")
    policy: CompetitionPolicy
    job: RecoverableExecutionJob
    attempt: CohortExecutionAttempt
    archive: Directory
    videos: Directory
    workspace: Directory
    admission: HostMemoryAdmissionSelection
    suite_candidates: EvaluationSuiteAdoptionCandidates = ()

    @model_validator(mode="after")
    def exact_timed_attempt(self):
        if self.attempt.job_sha256 != digest(self.job) or not isinstance(
            self.job.runtime, OfflineCpuRuntime
        ):
            raise ValueError("timed worker request changes the retained execution attempt")
        if prepared_cpu_efficiency_authorization(self.job.round, self.policy) is None:
            raise ValueError("isolated timed worker requires adopted timing authority")
        return self


class TimedSandboxResponse(StrictProtocolModel):
    schema_: Literal["umi-timed-sandbox-response/1"] = Field(alias="schema")
    request_sha256: Hex32
    result: OfflineCaseExecution | None = None
    error_reason: str | None = None

    @model_validator(mode="after")
    def outcome(self):
        if (self.result is None) == (self.error_reason is None):
            raise ValueError("timed worker response requires exactly one outcome")
        if (
            self.error_reason is not None
            and re.fullmatch(r"[a-z][a-z0-9_]{0,119}", self.error_reason) is None
        ):
            raise ValueError("timed worker error must be a bounded safe reason")
        return self


async def _stop_worker(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.send_signal(signal.SIGTERM)
    # The child owns container cleanup and its native leases. Reap it before
    # the parent releases model residency; do not abandon it on cancellation.
    await process.wait()


async def run_timed_sandbox(request: TimedSandboxRequest) -> OfflineCaseExecution:
    raw = canonical_json_bytes(request)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("timed worker request exceeds its metadata bound")
    source = str(Path(__file__).resolve().parent.parent)
    launch = (
        "import sys,runpy;sys.path.insert(0," + repr(source) + ");"
        "runpy.run_module('umi.competition_cohort_sandbox_worker',run_name='__main__')"
    )
    process = None
    spawning = None
    exchange = None
    with TransferProgress(
        "timed_host_invocation",
        1,
        unit="cases",
        planning_unit_seconds=(1, 660 + request.policy.maximum_inference_ms / 1000),
    ) as progress:
        telemetry = None
        try:
            telemetry = ParentProgress(progress, digest(request), request.attempt.job_sha256)
        except OSError:
            progress.emit("retrying", reason="timed_child_progress_unavailable")
        try:
            telemetry_args = (
                () if telemetry is None else ("--progress-fd", str(telemetry.writer.fileno()))
            )
            telemetry_fds = () if telemetry is None else (telemetry.writer.fileno(),)
            spawning = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    launch,
                    "--parent-pid",
                    str(os.getpid()),
                    *telemetry_args,
                    pass_fds=telemetry_fds,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                )
            )
            process = await await_owned_task(spawning)
            if telemetry is not None:
                try:
                    telemetry.start(process.pid)
                except (OSError, RuntimeError):
                    telemetry.close()
                    telemetry = None
                    progress.emit("retrying", reason="timed_child_progress_unavailable")

            async def communicate():
                async def send():
                    process.stdin.write(raw)
                    await process.stdin.drain()
                    process.stdin.close()
                    await process.stdin.wait_closed()

                sending = asyncio.create_task(send())
                try:
                    output = bytearray()
                    while chunk := await process.stdout.read(
                        min(65536, MAX_RESPONSE_BYTES + 1 - len(output))
                    ):
                        output.extend(chunk)
                        if len(output) > MAX_RESPONSE_BYTES:
                            raise ValueError("timed worker response exceeds its metadata bound")
                    await sending
                    code = await process.wait()
                    if code:
                        raise CpuTimingInfrastructureError("timed_host_worker_exited")
                    return bytes(output)
                finally:
                    if not sending.done():
                        sending.cancel()
                    await asyncio.gather(sending, return_exceptions=True)

            exchange = asyncio.create_task(communicate())
            response = TimedSandboxResponse.model_validate_json(await exchange)
            if response.request_sha256 != digest(request):
                raise ValueError("timed worker result changes the retained request")
            if response.error_reason is not None:
                raise CpuTimingInfrastructureError(response.error_reason)
            progress.advance(1)
            return response.result
        finally:

            async def drain():
                # Cancellation can arrive while subprocess creation is still
                # returning its handle. Ownership includes that interval.
                child = process
                if child is None and spawning is not None:
                    with suppress(Exception):
                        child = await spawning
                if child is not None:
                    await _stop_worker(child)
                if exchange is not None:
                    if not exchange.done():
                        exchange.cancel()
                    await asyncio.gather(exchange, return_exceptions=True)

            try:
                await await_owned_task(asyncio.create_task(drain()))
            finally:
                if telemetry is not None:
                    telemetry.close()
