"""Execute one exact timed attempt with its own event loop and native leases."""

import argparse
import asyncio
import ctypes
import os
import re
import signal
import sys
from pathlib import Path

from .competition_cohort_sandbox import CohortCpuSandbox
from .competition_cohort_sandbox_process import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    TimedSandboxRequest,
    TimedSandboxResponse,
)
from .competition_progress import configure_progress_logging, report_execution_retry
from .host_model_execution import ModelExecutionAdmission
from .open_competition import digest
from .protocol import canonical_json_bytes


def bind_parent(parent_pid):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot bind timed worker lifetime")
    if os.getppid() != parent_pid:
        raise RuntimeError("timed worker parent exited before initialization")


async def execute_request(request):
    loop = asyncio.get_running_loop()
    current = asyncio.current_task()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, current.cancel)
    try:
        admission = ModelExecutionAdmission(request.admission, request.policy, reattach_worker=True)
        sandbox = CohortCpuSandbox(
            request.policy,
            archive=Path(request.archive),
            videos=Path(request.videos),
            workspace=Path(request.workspace),
            execution_admission=admission,
            suite_candidates=request.suite_candidates,
            _isolate_timed=False,
        )
        result = await sandbox._invoke(request.job, request.attempt, sandbox.archive)
        return TimedSandboxResponse(
            schema="umi-timed-sandbox-response/1", request_sha256=digest(request), result=result
        )
    except Exception as error:
        report_execution_retry(slot=None, error=error)
        reason = getattr(error, "reason_code", "timed_host_worker_failed")
        if type(reason) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,119}", reason) is None:
            reason = "timed_host_worker_failed"
        return TimedSandboxResponse(
            schema="umi-timed-sandbox-response/1",
            request_sha256=digest(request),
            error_reason=reason,
        )
    finally:
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(signum)


def main():
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise RuntimeError("timed host worker requires isolated Python without bytecode")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-pid", type=int, required=True)
    args = parser.parse_args()
    bind_parent(args.parent_pid)
    configure_progress_logging()
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("timed worker request exceeds its metadata bound")
    try:
        request = TimedSandboxRequest.model_validate_json(raw)
    except Exception as error:
        report_execution_retry(slot=None, error=error)
        return 2
    try:
        response = asyncio.run(execute_request(request))
    except asyncio.CancelledError:
        return 130
    body = canonical_json_bytes(response)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("timed worker response exceeds its metadata bound")
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
