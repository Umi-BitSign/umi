"""Retained CPU invocation boundaries; opt-in Linux checks use inert inputs."""

import asyncio
import hashlib
import json
import os
import sys
from types import SimpleNamespace

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


@pytest.mark.parametrize("layout", ("separate", "workspace", "ancestor"))
def test_explicit_boot_cache_directory_and_restart_preserve_native_files(cpu, tmp_path, layout):
    from umi.competition_model_cache_space import BootDiskModelCache, BootDiskModelCacheConfig

    _, _, original = cpu
    parent = tmp_path / "private-invocations"
    parent.mkdir(mode=0o700)
    workspace = parent / "work"
    workspace.mkdir(mode=0o700)
    boot_root = {
        "separate": tmp_path / "bounded-models",
        "workspace": workspace,
        "ancestor": parent,
    }[layout]
    cache_config = BootDiskModelCacheConfig(
        schema="umi-boot-disk-model-cache/1",
        directory=str(boot_root),
        maximum_allocated_bytes=16 * 1024**2,
    )
    native = BootDiskModelCache(cache_config, reserve_bytes=0)

    class Artifacts:
        config = SimpleNamespace(materialization_boot_disk_cache=cache_config)

        def verify_materialization_filesystem(self, root):
            native.validate_root(root)
            native.available_bytes()

    def start():
        return sandbox.DirectCohortCpuSandbox(
            original.policy,
            archive=original.archive,
            videos=original.videos,
            workspace=workspace,
            artifacts=Artifacts(),
            request=lambda _: None,
        )

    port = start()
    expected = (
        boot_root / "direct-model-cache"
        if layout == "separate"
        else workspace / "direct-model-cache"
    )
    assert port.cache == expected
    pending = port.cache / "retained-pending-materialization"
    pending.write_bytes(b"native invocation state must survive restart")
    pending.chmod(0o600)
    before = pending.stat()
    restarted = start()
    assert restarted.cache == port.cache
    assert pending.read_bytes() == b"native invocation state must survive restart"
    after = pending.stat()
    assert (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if layout == "separate":
        assert not (workspace / "direct-model-cache").exists()


@pytest.mark.parametrize("legacy_kind", ("pending", "symlink", "file"))
def test_moving_existing_legacy_cache_refuses_before_creating_new_roots(
    cpu, tmp_path, legacy_kind, caplog
):
    caplog.set_level("INFO", logger="umi.competition.progress")
    _, _, original = cpu
    workspace = tmp_path / "retained-workspace"
    workspace.mkdir(mode=0o700)
    legacy = workspace / "direct-model-cache"
    if legacy_kind == "pending":
        legacy.mkdir(mode=0o700)
        (legacy / "pending").write_bytes(b"must preserve")
    elif legacy_kind == "symlink":
        legacy.symlink_to(tmp_path / "unrelated-missing")
    else:
        legacy.write_bytes(b"must preserve")
    boot_root = tmp_path / "new-bounded-models"
    calls = []

    class Artifacts:
        config = SimpleNamespace(
            materialization_boot_disk_cache=SimpleNamespace(directory=str(boot_root))
        )

        def verify_materialization_filesystem(self, root):
            calls.append(root)
            pytest.fail("unsupported relocation created or checked a new cache before refusal")

    with pytest.raises(OSError, match="preserving migration"):
        sandbox.DirectCohortCpuSandbox(
            original.policy,
            archive=original.archive,
            videos=original.videos,
            workspace=workspace,
            artifacts=Artifacts(),
            request=lambda _: None,
        )
    assert not boot_root.exists() and not calls
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "umi.competition.progress"
    ]
    repair = next(event for event in events if event["status"] == "repair_required")
    assert repair["reason_code"] == "legacy_model_cache_needs_migration"
    assert repair["completed_units"] == 0 and repair["total_units"] == 1
    assert repair["elapsed_seconds"] >= 0 and repair["eta_seconds"] is None
    if legacy_kind == "pending":
        assert (legacy / "pending").read_bytes() == b"must preserve"
    elif legacy_kind == "file":
        assert legacy.read_bytes() == b"must preserve"
    else:
        assert legacy.is_symlink()


async def test_direct_candidate_cache_materializes_once_and_remains_bounded(
    cpu, tmp_path, monkeypatch
):
    job, attempt, original = cpu
    bundle = job.submission.submission.model_bundle
    if bundle is None:
        pytest.skip("endpoint jobs have no direct candidate")
    calls, checks, filesystems = [], [], []

    class Artifacts:
        config = SimpleNamespace(materialization_concurrency=1)

        async def resumable(self, request, archive):
            return False

        def cache_identity(self, request):
            return digest(bundle)

        def verify_materialization_filesystem(self, root):
            filesystems.append(root)

        async def materialized(self, request, archive):
            checks.append((request, archive))
            return (archive / digest(bundle) / "model").is_dir()

        async def materialize(self, request, archive):
            calls.append((request, archive))
            archive.mkdir(mode=0o700)
            (archive / digest(bundle) / "model").mkdir(parents=True)

    request = SimpleNamespace(
        direct_artifact=SimpleNamespace(),
        record=SimpleNamespace(
            request=SimpleNamespace(
                signed_submission=SimpleNamespace(submission=SimpleNamespace(model_bundle=bundle))
            )
        ),
    )
    artifacts = Artifacts()
    port = sandbox.DirectCohortCpuSandbox(
        original.policy,
        archive=original.archive,
        videos=original.videos,
        workspace=tmp_path / "direct-scratch",
        artifacts=artifacts,
        request=lambda _: request,
    )

    async def invoke(selected_job, selected_attempt, archive):
        assert selected_job == job
        assert (archive / digest(bundle) / "model").is_dir()
        return SimpleNamespace(attempt=selected_attempt)

    monkeypatch.setattr(port, "_invoke", invoke)
    first_path = port.workspace / digest(attempt)
    first = await port.invoke(job, attempt)
    second_attempt = attempt.model_copy(update={"number": 2})
    second_path = port.workspace / digest(second_attempt)
    second = await port.invoke(job, second_attempt)
    restarted = sandbox.DirectCohortCpuSandbox(
        original.policy,
        archive=original.archive,
        videos=original.videos,
        workspace=port.workspace,
        artifacts=artifacts,
        request=lambda _: request,
    )
    monkeypatch.setattr(restarted, "_invoke", invoke)
    third_attempt = attempt.model_copy(update={"number": 3})
    third_path = port.workspace / digest(third_attempt)
    third = await restarted.invoke(job, third_attempt)

    assert (
        first.attempt == attempt
        and second.attempt == second_attempt
        and third.attempt == third_attempt
    )
    assert len(calls) == 1
    assert len(checks) == 1
    assert filesystems == [port.cache, restarted.cache]
    assert tuple(path.name for path in port.cache.iterdir()) == ("archive",)
    assert not first_path.exists() and not second_path.exists() and not third_path.exists()


async def test_direct_candidate_cache_allows_same_model_cases_to_run_concurrently(
    cpu, tmp_path, monkeypatch
):
    job, attempt, original = cpu
    bundle = job.submission.submission.model_bundle
    if bundle is None:
        pytest.skip("endpoint jobs have no direct candidate")
    materializations = []

    class Artifacts:
        config = SimpleNamespace(materialization_concurrency=1)

        async def resumable(self, request, archive):
            return False

        def cache_identity(self, request):
            return digest(bundle)

        def verify_materialization_filesystem(self, root):
            return None

        async def materialized(self, request, archive):
            return False

        async def materialize(self, request, archive):
            materializations.append(archive)
            archive.mkdir(mode=0o700)
            (archive / digest(bundle) / "model").mkdir(parents=True)

    request = SimpleNamespace(
        direct_artifact=SimpleNamespace(),
        record=SimpleNamespace(
            request=SimpleNamespace(
                signed_submission=SimpleNamespace(submission=SimpleNamespace(model_bundle=bundle))
            )
        ),
    )
    port = sandbox.DirectCohortCpuSandbox(
        original.policy,
        archive=original.archive,
        videos=original.videos,
        workspace=tmp_path / "concurrent-direct-scratch",
        artifacts=Artifacts(),
        request=lambda _: request,
    )
    both_entered = asyncio.Event()
    release = asyncio.Event()
    active = 0
    maximum_active = 0

    async def invoke(selected_job, selected_attempt, archive):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        if active == 2:
            both_entered.set()
        await release.wait()
        active -= 1
        return SimpleNamespace(attempt=selected_attempt)

    monkeypatch.setattr(port, "_invoke", invoke)
    second_attempt = attempt.model_copy(update={"number": 2})
    tasks = (
        asyncio.create_task(port.invoke(job, attempt)),
        asyncio.create_task(port.invoke(job, second_attempt)),
    )
    try:
        await asyncio.wait_for(both_entered.wait(), 2)
        release.set()
        results = await asyncio.gather(*tasks)
    finally:
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)

    assert [result.attempt for result in results] == [attempt, second_attempt]
    assert maximum_active == 2
    assert len(materializations) == 1
    assert port.active_candidate_invocations == 0


async def test_direct_candidate_cancellation_releases_cache_ownership(cpu, tmp_path, monkeypatch):
    job, attempt, original = cpu
    bundle = job.submission.submission.model_bundle
    if bundle is None:
        pytest.skip("endpoint jobs have no direct candidate")

    class Artifacts:
        config = SimpleNamespace(materialization_concurrency=1)

        async def resumable(self, request, archive):
            return False

        def cache_identity(self, request):
            return digest(bundle)

        def verify_materialization_filesystem(self, root):
            return None

        async def materialized(self, request, archive):
            return False

        async def materialize(self, request, archive):
            archive.mkdir(mode=0o700)
            (archive / digest(bundle) / "model").mkdir(parents=True)

    request = SimpleNamespace(
        direct_artifact=SimpleNamespace(),
        record=SimpleNamespace(
            request=SimpleNamespace(
                signed_submission=SimpleNamespace(submission=SimpleNamespace(model_bundle=bundle))
            )
        ),
    )
    port = sandbox.DirectCohortCpuSandbox(
        original.policy,
        archive=original.archive,
        videos=original.videos,
        workspace=tmp_path / "cancelled-direct-scratch",
        artifacts=Artifacts(),
        request=lambda _: request,
    )
    entered = asyncio.Event()

    async def invoke(*_):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(port, "_invoke", invoke)
    task = asyncio.create_task(port.invoke(job, attempt))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert port.active_candidate_invocations == 0


async def test_direct_sandbox_routes_legacy_candidate_to_retained_archive(
    cpu, tmp_path, monkeypatch
):
    job, attempt, original = cpu
    bundle = job.submission.submission.model_bundle
    if bundle is None:
        pytest.skip("endpoint jobs have no direct candidate")

    class Artifacts:
        config = SimpleNamespace(materialization_concurrency=1)

        async def resumable(self, request, archive):
            return False

        def cache_identity(self, request):
            return digest(bundle)

        def verify_materialization_filesystem(self, root):
            return None

        async def materialized(self, request, archive):
            pytest.fail("legacy candidate checked the direct object cache")

        async def materialize(self, request, archive):
            pytest.fail("legacy candidate used the direct object cache")

    request = SimpleNamespace(
        direct_artifact=None,
        record=SimpleNamespace(
            request=SimpleNamespace(
                signed_submission=SimpleNamespace(submission=SimpleNamespace(model_bundle=bundle))
            )
        ),
    )
    port = sandbox.DirectCohortCpuSandbox(
        original.policy,
        archive=original.archive,
        videos=original.videos,
        workspace=tmp_path / "mixed-series-scratch",
        artifacts=Artifacts(),
        request=lambda _: request,
    )

    async def invoke(selected_job, selected_attempt, archive):
        assert selected_job == job
        assert selected_attempt == attempt
        assert archive == original.archive
        return SimpleNamespace(attempt=selected_attempt)

    monkeypatch.setattr(port, "_invoke", invoke)
    result = await port.invoke(job, attempt)

    assert result.attempt == attempt
    assert tuple(port.cache.iterdir()) == ()


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


async def test_direct_cache_waits_for_all_leases_before_changing_same_bundle_source(
    cpu, tmp_path, caplog
):
    job, _, original = cpu
    bundle = job.submission.submission.model_bundle
    if bundle is None:
        pytest.skip("endpoint jobs have no direct candidate")
    writes = []
    caplog.set_level("INFO", logger="umi.competition.progress")

    class Artifacts:
        config = SimpleNamespace(materialization_concurrency=1)

        def verify_materialization_filesystem(self, root):
            pass

        async def resumable(self, request, archive):
            return False

        def cache_identity(self, request):
            return request.source

        async def materialized(self, request, archive):
            return (archive / "source").read_text() == request.source

        async def materialize(self, request, archive):
            writes.append(request.source)
            archive.mkdir(mode=0o700)
            (archive / digest(bundle) / "model").mkdir(parents=True)
            (archive / "source").write_text(request.source)

    port = sandbox.DirectCohortCpuSandbox(
        original.policy,
        archive=original.archive,
        videos=original.videos,
        workspace=tmp_path / "source-cache",
        artifacts=Artifacts(),
        request=lambda _: None,
    )
    first, second = SimpleNamespace(source="first"), SimpleNamespace(source="second")
    archive = await port._candidate_archive(first, bundle)
    await port._candidate_archive(first, bundle)
    waiting = asyncio.create_task(port._candidate_archive(second, bundle))
    await asyncio.sleep(0)
    assert not waiting.done() and (archive / "source").read_text() == "first"
    await port._release_candidate_archive()
    await asyncio.sleep(0)
    assert not waiting.done() and port.active_candidate_invocations == 1
    await port._release_candidate_archive()
    assert await asyncio.wait_for(waiting, 2) == archive
    assert writes == ["first", "second"] and (archive / "source").read_text() == "second"
    await port._release_candidate_archive()
    events = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "umi.competition.progress"
    ]
    waits = [event for event in events if event["stage"] == "model_cache_lease_wait"]
    assert any(event["status"] == "waiting" and event["planning_eta_seconds"] for event in waits)
    assert waits[-1]["status"] == "completed" and waits[-1]["eta_seconds"] == 0
