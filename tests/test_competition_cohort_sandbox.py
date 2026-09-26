"""Retained CPU invocation boundaries; opt-in Linux checks use inert inputs."""

import asyncio
import hashlib
import os
import sys

import pytest

from umi import competition_cohort_sandbox as sandbox
from umi import competition_runner as runner
from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_execution_journal import CohortExecutionAttempt
from umi.open_competition import BundleFile, digest

from .test_competition_cohort_order_signer import base_policy as base_policy
from .test_competition_cohort_order_signer import legacy_scenario as legacy_scenario
from .test_competition_cohort_order_signer import policy as policy
from .test_competition_cohort_order_signer import receipt_scenario as receipt_scenario
from .test_competition_cohort_order_signer import recovery as recovery
from .test_competition_cohort_order_signer import runtime as runtime
from .test_competition_cohort_order_signer import scenario as scenario
from .test_competition_execution import boundary
from .test_open_competition import bundle_at, submission


@pytest.fixture
def cpu(scenario, tmp_path):
    job = scenario["artifacts"][0].job
    attempt = CohortExecutionAttempt(
        schema="umi-cohort-execution-attempt/1",
        job_sha256=digest(job),
        step_index=0,
        number=1,
        predecessor_sha256=None,
        started=boundary(1500),
        history_sha256="ac" * 32,
    )
    port = sandbox.CohortCpuSandbox(
        scenario["policy"],
        archive=tmp_path / "archive",
        videos=tmp_path / "videos",
        workspace=tmp_path / "scratch",
    )
    return job, attempt, port


async def test_reconciliation_removes_only_exact_workspace_after_stop(cpu, monkeypatch):
    job, attempt, port = cpu
    own = port._path(attempt)
    (own / "interrupted-input").write_bytes(b"private copy")
    other = port.workspace / ("de" * 32)
    other.mkdir()
    (other / "retained").write_bytes(b"another invocation")
    calls = []

    async def stop(key):
        calls.append(key)
        assert (own / "interrupted-input").exists()

    monkeypatch.setattr(sandbox, "stop_retained_cpu_invocation", stop)
    await port.reconcile(job, attempt)
    assert calls == [digest(attempt)] and not own.exists()
    assert (other / "retained").read_bytes() == b"another invocation"


async def test_failed_reconciliation_preserves_workspace(cpu, monkeypatch):
    job, attempt, port = cpu
    own = port._path(attempt)
    (own / "input").write_bytes(b"inert")

    async def stop(key):
        raise runner.EvaluationInfrastructureError("cannot establish container exit")

    monkeypatch.setattr(sandbox, "stop_retained_cpu_invocation", stop)
    with pytest.raises(runner.EvaluationInfrastructureError):
        await port.reconcile(job, attempt)
    assert (own / "input").exists()


async def test_cleanup_command_has_only_validated_invocation_name(monkeypatch):
    calls = []

    async def command(args):
        calls.append(args)
        return 0, b""

    monkeypatch.setattr(runner, "_small_command", command)
    await runner.stop_retained_cpu_invocation("ab" * 32)
    assert calls == [
        ("/usr/bin/podman", "rm", "--force", "--ignore", "--time=0", "umi-evaluation-" + "ab" * 16)
    ]
    for value in ("--all", "", "AB" * 32, "a" * 63, None):
        with pytest.raises(ValueError):
            await runner.stop_retained_cpu_invocation(value)
    assert len(calls) == 1


def test_workspace_cannot_overlap_archive_or_follow_symlink(cpu, tmp_path):
    _, _, port = cpu
    with pytest.raises(ValueError):
        sandbox.CohortCpuSandbox(
            port.policy,
            archive=port.workspace / "models",
            videos=port.videos,
            workspace=port.workspace,
        )
    (tmp_path / "linked").symlink_to(port.workspace, target_is_directory=True)
    with pytest.raises(ValueError):
        sandbox.CohortCpuSandbox(
            port.policy,
            archive=tmp_path / "linked",
            videos=port.videos,
            workspace=tmp_path / "scratch2",
        )


@pytest.mark.skipif(
    sys.platform != "linux" or not os.environ.get("UMI_OFFLINE_TEST_IMAGE"),
    reason="requires a preinstalled pinned Linux image; no pull or production inputs",
)
@pytest.mark.parametrize("interrupt", [False, True])
async def test_real_retained_cpu_invocation_and_orphan_cleanup(cpu, tmp_path, interrupt):
    """Real Podman and native port; synthetic job, video, model and observations."""
    job, attempt, port = cpu
    runtime = job.runtime.model_copy(
        update={
            "image": os.environ["UMI_OFFLINE_TEST_IMAGE"],
            "cpus": 1,
            "memory_bytes": 256 * 1024**2,
            "pids_limit": 32,
        }
    )
    policy = port.policy.model_copy(
        update={
            "evaluation_runtime_sha256": digest(runtime),
            "maximum_inference_ms": 60000,
        }
    )
    source = tmp_path / "model-source"
    bundle = bundle_at(source)
    code = (
        b"from pathlib import Path\nimport sys, time\n"
        b"assert Path(sys.argv[1]).read_bytes() == b'inert video'\n"
        + (b"time.sleep(50)\n" if interrupt else b"")
        + b"print('hello')\n"
    )
    (source / "inference.txt").unlink()
    (source / "infer.py").write_bytes(code)
    bundle = bundle.model_copy(
        update={
            "files": tuple(
                sorted(
                    (
                        BundleFile(
                            path="infer.py",
                            role=f.role,
                            sha256=hashlib.sha256(code).hexdigest(),
                            size_bytes=len(code),
                        )
                        if f.role == "inference"
                        else f
                        for f in bundle.files
                    ),
                    key=lambda f: f.path,
                )
            )
        }
    )
    preserve_bundle(bundle, source, port.archive, policy)
    video = b"inert video"
    video_sha = hashlib.sha256(video).hexdigest()
    port.videos.mkdir(mode=0o700)
    (port.videos / (video_sha + ".mp4")).write_bytes(video)
    job = job.model_copy(
        update={
            "runtime": runtime,
            "incumbent": bundle,
            "submission": submission(policy, bundle=bundle if job.mode == "paired_model" else None),
            "cases": tuple(c.model_copy(update={"video_sha256": video_sha}) for c in job.cases),
        }
    )
    attempt = attempt.model_copy(update={"job_sha256": digest(job)})
    port = sandbox.CohortCpuSandbox(
        policy,
        archive=port.archive,
        videos=port.videos,
        workspace=port.workspace,
    )
    name = runner.invocation_container_name(digest(attempt))
    if interrupt:
        # An orphaned container whose launching process has exited must be removed
        # before a replacement. Cross-host fencing and service cgroups are separate.
        inputs = port._path(attempt) / "input"
        inputs.mkdir()
        (inputs / "video.mp4").write_bytes(video)
        command = runner.model_command(
            runtime,
            name=name,
            model=port.archive / digest(bundle) / "model",
            inputs=inputs,
            entrypoint="infer.py",
            maximum_inference_ms=60000,
        )
        # Native command isolation is retained; only detach this inert test process.
        detached = (*command[:2], "--detach", *command[2:])
        try:
            assert (await runner._small_command(detached))[0] == 0
            assert (await runner._small_command(("/usr/bin/podman", "container", "exists", name)))[
                0
            ] == 0
            await port.reconcile(job, attempt)
        finally:
            await runner.stop_retained_cpu_invocation(digest(attempt))
    else:
        result = await asyncio.wait_for(port.invoke(job, attempt), 75)
        runner.validate_case_execution(result, policy)
        assert result.output.hypothesis == "hello" and result.output.status == "ok"
    assert not (port.workspace / digest(attempt)).exists()
    assert (await runner._small_command(("/usr/bin/podman", "container", "exists", name)))[0] == 1
    assert (port.videos / (video_sha + ".mp4")).read_bytes() == video
