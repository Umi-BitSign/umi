"""Owned timed subprocess lifecycle with native signed request bindings."""

import asyncio
import os
import signal
import sys
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from umi import competition_cohort_sandbox as sandbox
from umi import competition_cohort_sandbox_process as process
from umi import competition_cohort_sandbox_worker as worker
from umi.competition_cohort_public_progress import EXECUTION_JOB_SCOPE
from umi.competition_cpu_efficiency_policy import (
    CohortCpuEfficiencyAdoption,
    SignedCohortCpuEfficiencyAdoption,
)
from umi.competition_cpu_timing import CpuTimingInfrastructureError
from umi.competition_transport_verification import TransferProgress
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_sandbox import base_policy as base_policy
from .test_competition_cohort_sandbox import cpu as cpu
from .test_competition_cohort_sandbox import legacy_scenario as legacy_scenario
from .test_competition_cohort_sandbox import policy as policy
from .test_competition_cohort_sandbox import receipt_scenario as receipt_scenario
from .test_competition_cohort_sandbox import recovery as recovery
from .test_competition_cohort_sandbox import runtime as runtime
from .test_competition_cohort_sandbox import scenario as scenario


@pytest.fixture
def timed(cpu, tmp_path):
    job, attempt, port = cpu
    body = CohortCpuEfficiencyAdoption(
        schema="umi-cohort-cpu-efficiency-adoption/1",
        policy_sha256=digest(port.policy),
        authority_sha256="ab" * 32,
        cohort_sha256s=(job.round.cohort_sha256,),
        first_cohort_sequence=8,
        runtime_sha256=digest(job.runtime),
        issued_at_block=200,
        reason="Synthetic timed subprocess lifecycle qualification",
    )
    round_ = job.round.model_copy(
        update={
            "schema_": "umi-recoverable-evaluation-round/3",
            "sequence": 8,
            "cpu_efficiency_adoption": SignedCohortCpuEfficiencyAdoption(
                adoption=body, signatures=signatures(body)
            ),
        }
    )
    job = job.model_copy(update={"round": round_})
    attempt = attempt.model_copy(update={"job_sha256": digest(job)})
    return process.TimedSandboxRequest(
        schema="umi-timed-sandbox-request/1",
        policy=port.policy,
        job=job,
        attempt=attempt,
        archive=str(port.archive),
        videos=str(port.videos),
        workspace=str(port.workspace),
        admission={
            "policy_path": str(tmp_path / "missing-policy.json"),
            "policy_sha256": "ac" * 32,
            "host_identity_path": str(tmp_path / "identity.json"),
        },
    )


def test_request_roundtrip_and_changed_attempt_refusal(timed):
    assert process.TimedSandboxRequest.model_validate_json(canonical_json_bytes(timed)) == timed
    changed = timed.model_dump(by_alias=True)
    changed["attempt"]["job_sha256"] = "de" * 32
    with pytest.raises(ValidationError, match="retained execution attempt"):
        process.TimedSandboxRequest.model_validate(changed)
    changed = timed.model_dump(by_alias=True)
    changed["job"]["round"]["cpu_efficiency_adoption"]["adoption"]["reason"] = "changed"
    with pytest.raises(ValueError):
        process.TimedSandboxRequest.model_validate(changed)


@pytest.mark.parametrize("reason", ["private/path", "x" * 121, "\nsecret", ""])
def test_response_rejects_unsafe_error(reason):
    with pytest.raises(ValidationError):
        process.TimedSandboxResponse(
            schema="umi-timed-sandbox-response/1", request_sha256="ab" * 32, error_reason=reason
        )


async def test_selected_worker_uses_isolated_interpreter_and_safe_failure(timed):
    # This launches the actual selected module. Missing admission prevents all
    # model/container work and must return only a safe failure through the pipe.
    with pytest.raises(CpuTimingInfrastructureError, match="timed_host_worker_failed"):
        await asyncio.wait_for(process.run_timed_sandbox(timed), 15)


class Child:
    def __init__(self, body=b"", *, hold_send=False, hold_exit=False):
        self.returncode = None
        self.pid = os.getpid()
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(body)
        self.stdout.feed_eof()
        self.sent = bytearray()
        self.sending = asyncio.Event()
        self.send_release = asyncio.Event()
        self.stopping = asyncio.Event()
        self.exit_release = asyncio.Event()
        self.hold_send, self.hold_exit = hold_send, hold_exit
        self.signals = []
        self.stdin = self

    def write(self, raw):
        self.sent.extend(raw)

    async def drain(self):
        self.sending.set()
        if self.hold_send:
            await self.send_release.wait()

    def close(self):
        pass

    async def wait_closed(self):
        pass

    def send_signal(self, signum):
        self.signals.append(signum)
        self.stopping.set()

    async def wait(self):
        if self.hold_exit:
            await self.exit_release.wait()
        self.returncode = 0
        return 0


@pytest.mark.parametrize("phase", ["spawn", "send", "execute"])
async def test_repeated_cancellation_reaps_before_releasing_owner(timed, monkeypatch, phase):
    child = Child(hold_send=phase == "send", hold_exit=True)
    spawning, release_spawn = asyncio.Event(), asyncio.Event()

    async def spawn(*args, **kwargs):
        assert args[:3] == (sys.executable, "-I", "-B")
        assert "competition_cohort_sandbox_worker" in args[4]
        spawning.set()
        if phase == "spawn":
            await release_spawn.wait()
        return child

    monkeypatch.setattr(process.asyncio, "create_subprocess_exec", spawn)
    task = asyncio.create_task(process.run_timed_sandbox(timed))
    try:
        await asyncio.wait_for(spawning.wait(), 2)
        if phase != "spawn":
            await asyncio.wait_for(child.sending.wait(), 2)
        task.cancel()
        release_spawn.set()
        await asyncio.wait_for(child.stopping.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        child.exit_release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert child.returncode == 0 and child.signals == [signal.SIGTERM]
    finally:
        release_spawn.set()
        child.send_release.set()
        child.exit_release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("failure", ["binding", "oversize", "reason"])
async def test_response_bounds_and_request_binding(timed, monkeypatch, failure):
    body = canonical_json_bytes(
        process.TimedSandboxResponse(
            schema="umi-timed-sandbox-response/1",
            request_sha256="de" * 32 if failure == "binding" else digest(timed),
            error_reason="cpu_condition_host_observer_stalled",
        )
    )
    if failure == "oversize":
        body = b"x" * (process.MAX_RESPONSE_BYTES + 1)
    child = Child(body)

    async def spawn(*args, **kwargs):
        return child

    monkeypatch.setattr(process.asyncio, "create_subprocess_exec", spawn)
    error, match = (
        (CpuTimingInfrastructureError, "cpu_condition_host_observer_stalled")
        if failure == "reason"
        else (ValueError, "request|bound")
    )
    with pytest.raises(error, match=match):
        await process.run_timed_sandbox(timed)
    assert child.returncode == 0


async def test_parent_dispatches_without_acquiring_invocation_lease(timed, monkeypatch):
    admission = SimpleNamespace(selection=timed.admission, slots=(object(),))
    port = sandbox.CohortCpuSandbox(
        timed.policy,
        archive=Path(timed.archive),
        videos=Path(timed.videos),
        workspace=Path(timed.workspace),
        execution_admission=admission,
    )
    sentinel = object()

    async def run(request):
        assert request == timed
        return sentinel

    monkeypatch.setattr(sandbox, "run_timed_sandbox", run)
    assert await port._invoke(timed.job, timed.attempt, port.archive) is sentinel


async def test_child_owns_native_admission_and_preserves_result(timed, scenario, monkeypatch):
    result = scenario["artifacts"][0].steps[0].execution
    admission = object()
    calls = []

    def admit(selection, policy, *, reattach_worker):
        assert reattach_worker
        assert selection == timed.admission and policy == timed.policy
        assert EXECUTION_JOB_SCOPE.get() == timed.attempt.job_sha256
        calls.append("admission")
        return admission

    async def invoke(port, job, attempt, archive):
        assert not port._isolate_timed
        assert port.execution_admission is admission
        assert job == timed.job and attempt == timed.attempt
        assert TransferProgress("worker_scope_probe", 1).job_sha256 == timed.attempt.job_sha256
        calls.append("invoke")
        return result

    monkeypatch.setattr(worker, "ModelExecutionAdmission", admit)
    monkeypatch.setattr(worker.CohortCpuSandbox, "_invoke", invoke)
    assert EXECUTION_JOB_SCOPE.get() is None
    response = await worker.execute_request(timed)
    assert EXECUTION_JOB_SCOPE.get() is None
    assert calls == ["admission", "invoke"]
    assert response.request_sha256 == digest(timed)
    assert canonical_json_bytes(response.result) == canonical_json_bytes(result)


async def test_waiting_review_tasks_do_not_spawn_extra_workers(timed, monkeypatch):
    port = sandbox.CohortCpuSandbox(
        timed.policy,
        archive=Path(timed.archive),
        videos=Path(timed.videos),
        workspace=Path(timed.workspace),
        execution_admission=SimpleNamespace(selection=timed.admission, slots=(object(),)),
    )
    entered, cleanup, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    calls = 0

    async def run(request):
        nonlocal calls
        calls += 1
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleanup.set()
            await release.wait()

    monkeypatch.setattr(sandbox, "run_timed_sandbox", run)
    first = asyncio.create_task(port._invoke(timed.job, timed.attempt, port.archive))
    second = None
    try:
        await asyncio.wait_for(entered.wait(), 2)
        second = asyncio.create_task(port._invoke(timed.job, timed.attempt, port.archive))
        await asyncio.sleep(0)
        assert calls == 1
        first.cancel()
        await asyncio.wait_for(cleanup.wait(), 2)
        assert calls == 1 and not first.done()
        second.cancel()
        await asyncio.gather(second, return_exceptions=True)
        release.set()
        await asyncio.gather(first, return_exceptions=True)
        assert port._timed_workers._value == 1 and calls == 1
    finally:
        release.set()
        first.cancel()
        if second is not None:
            second.cancel()
        await asyncio.gather(first, *(() if second is None else (second,)), return_exceptions=True)


async def test_oversized_request_refuses_before_spawn(timed, monkeypatch):
    monkeypatch.setattr(process, "MAX_REQUEST_BYTES", 1)
    with pytest.raises(ValueError, match="request exceeds"):
        await process.run_timed_sandbox(timed)


def test_parent_exit_before_binding_refuses(monkeypatch):
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(prctl=lambda *a: 0))
    with pytest.raises(RuntimeError, match="parent exited"):
        worker.bind_parent(os.getppid() + 1)


@pytest.mark.skipif(sys.platform != "linux", reason="native parent-death signal is Linux-only")
async def test_parent_death_delivers_cooperative_shutdown(tmp_path):
    ready, stopped = tmp_path / "ready", tmp_path / "stopped"
    source = str(Path(worker.__file__).resolve().parent.parent)
    child_code = (
        "import sys,signal;from pathlib import Path;sys.path.insert(0," + repr(source) + ");"
        "from umi.competition_cohort_sandbox_worker import bind_parent;"
        "signal.signal(signal.SIGTERM,lambda *_:(Path(sys.argv[3]).write_text('stopped'),"
        "sys.exit(0)));bind_parent(int(sys.argv[1]));"
        "Path(sys.argv[2]).write_text('ready');signal.pause()"
    )
    parent_code = (
        "import os,subprocess,sys,time;from pathlib import Path;"
        "p=subprocess.Popen([sys.executable,'-I','-B','-c'," + repr(child_code) + ","
        "str(os.getpid()),sys.argv[1],sys.argv[2]],stdout=subprocess.DEVNULL);\n"
        "while not Path(sys.argv[1]).exists():\n"
        " if p.poll() is not None: raise RuntimeError('child exited before readiness')\n"
        " time.sleep(.01)\n"
        "print(p.pid,flush=True);sys.stdin.read()"
    )
    parent = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-B",
        "-c",
        parent_code,
        str(ready),
        str(stopped),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    child_pid = None
    try:
        child_pid = int(await asyncio.wait_for(parent.stdout.readline(), 10))
        parent.stdin.close()
        assert await asyncio.wait_for(parent.wait(), 5) == 0

        async def observed():
            while not stopped.exists():
                await asyncio.sleep(0.01)

        await asyncio.wait_for(observed(), 5)
        assert stopped.read_text() == "stopped"
    finally:
        if parent.returncode is None:
            parent.kill()
            await parent.wait()
        if child_pid is not None:
            with suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGTERM)


@pytest.mark.parametrize("failure", ["create", "listen"])
async def test_diagnostic_socket_failure_does_not_replace_native_result(
    timed, scenario, monkeypatch, failure
):
    result = scenario["artifacts"][0].steps[0].execution
    child = Child(
        canonical_json_bytes(
            process.TimedSandboxResponse(
                schema="umi-timed-sandbox-response/1",
                request_sha256=digest(timed),
                result=result,
            )
        )
    )

    async def spawn(*args, **kwargs):
        if failure == "create":
            assert "--progress-fd" not in args and kwargs["pass_fds"] == ()
        return child

    def unavailable(*args, **kwargs):
        raise OSError("diagnostic socket unavailable")

    monkeypatch.setattr(process.asyncio, "create_subprocess_exec", spawn)
    if failure == "create":
        monkeypatch.setattr(process, "ParentProgress", unavailable)
    else:
        monkeypatch.setattr(process.ParentProgress, "start", unavailable)
    assert await process.run_timed_sandbox(timed) == result
    assert child.returncode == 0
