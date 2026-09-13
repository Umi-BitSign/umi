from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

# Shared deterministic fixtures, never production wallets or model files.
from tests.test_open_competition import policy as competition_policy_fixture
from umi import competition_runner as runner
from umi.open_competition import BundleFile, ModelBundle, digest

policy = competition_policy_fixture


@pytest.fixture
def runtime():
    return runner.OfflineCpuRuntime(
        schema="umi-offline-cpu-runtime/1",
        image="ghcr.io/example/evaluator@sha256:" + "ab" * 32,
        cpus=2,
        memory_bytes=1024**3,
        scratch_bytes=16 * 1024**2,
        pids_limit=64,
        maximum_video_bytes=1024,
    )


def test_cpu_command_has_no_network_wallet_or_writable_model(runtime):
    command = runner.model_command(
        runtime,
        name="umi-evaluation-" + "ab" * 16,
        model=Path("/archive/model"),
        inputs=Path("/scratch/input"),
        entrypoint="infer.py",
        maximum_inference_ms=1000,
    )
    for required in (
        "--network=none",
        "--read-only",
        "--read-only-tmpfs=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--image-volume=ignore",
        "--pull=never",
        "--timeout=1",
        "--http-proxy=false",
        "--log-driver=none",
        "--pid=private",
        "--ipc=private",
    ):
        assert required in command
    mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--mount"]
    assert mounts == [
        "type=bind,src=/archive/model,dst=/model,ro=true",
        "type=bind,src=/scratch/input,dst=/input,ro=true",
    ]
    assert not any("wallet" in arg or "socket" in arg or "privileged" in arg for arg in command)
    assert command[-3:] == (runtime.image, "/model/infer.py", "/input/video.mp4")
    temporary = [command[i + 1] for i, arg in enumerate(command) if arg == "--tmpfs"]
    assert temporary == [f"/tmp:rw,nosuid,nodev,noexec,size={runtime.scratch_bytes},mode=1777"]


@pytest.mark.parametrize(
    "scratch", [1024**2, 1024**2 + 1, 16 * 1024**2, 256 * 1024**2, 512 * 1024**2]
)
def test_v2_private_shared_memory_divides_existing_scratch_budget(runtime, scratch):
    original = runtime.model_copy(
        update={"scratch_bytes": scratch, "memory_bytes": max(runtime.memory_bytes, scratch * 4)}
    )
    updated = original.model_copy(update={"schema_": "umi-offline-cpu-runtime/2"})
    assert digest(updated) != digest(original)
    updated = runner.OfflineCpuRuntime.model_validate_json(updated.model_dump_json(by_alias=True))
    command = runner.model_command(
        updated,
        name="umi-evaluation-" + "ab" * 16,
        model=Path("/archive/model"),
        inputs=Path("/scratch/input"),
        entrypoint="infer.py",
        maximum_inference_ms=1000,
    )
    temporary = [command[i + 1] for i, arg in enumerate(command) if arg == "--tmpfs"]
    assert len(temporary) == 2
    sizes = []
    for path, mount in zip(("/tmp", "/dev/shm"), temporary, strict=True):
        assert mount.startswith(f"{path}:rw,nosuid,nodev,noexec,size=")
        assert mount.endswith(",mode=1777")
        sizes.append(int(mount.split("size=")[1].split(",")[0]))
    assert 0 < sum(sizes) <= scratch
    assert all(size % (64 * 1024) == 0 for size in sizes)
    assert 0 < sizes[1] <= min(scratch // 4, 64 * 1024**2)
    assert "--ipc=private" in command
    assert "--read-only" in command


@pytest.mark.parametrize("path", ["/source,ro=false", "/source\nother", "relative"])
def test_mount_injection_is_rejected(runtime, path):
    with pytest.raises(ValueError, match="bind-mount"):
        runner.model_command(
            runtime,
            name="umi-evaluation-" + "ab" * 16,
            model=Path(path),
            inputs=Path("/input"),
            entrypoint="infer.py",
            maximum_inference_ms=1000,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode", ["success", "timeout", "overflow", "runtime_failure", "cleanup_failure"]
)
async def test_bounded_execution_removes_only_its_case_container(
    runtime, policy, tmp_path, monkeypatch, mode
):
    policy = policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})
    records = []
    for role in (
        "weights",
        "config",
        "processor",
        "inference",
        "environment",
        "license",
        "provenance",
    ):
        records.append(BundleFile(path=f"{role}.py", role=role, sha256="ab" * 32, size_bytes=0))
    bundle = ModelBundle(
        schema="umi-model-bundle/1",
        profile="offline_bundle/1",
        parent_baseline_sha256=None,
        license_id="CC-BY-SA-4.0",
        files=tuple(sorted(records, key=lambda x: x.path)),
    )

    async def verified(*args):
        pass

    monkeypatch.setattr(runner, "verify_runtime", verified)
    monkeypatch.setattr(runner, "verify_preserved_bundle", lambda *args: "ab" * 32)
    calls = []

    class Process:
        returncode = None

        def __init__(self):
            self.stdout = asyncio.StreamReader()
            if mode != "timeout":
                self.stdout.feed_data(b"x" * 200 if mode == "overflow" else b"hello")
                self.stdout.feed_eof()

        async def wait(self):
            if self.returncode is None:
                self.returncode = 125 if mode == "runtime_failure" else 0
            return self.returncode

        def kill(self):
            self.returncode = -9

    process = Process()

    async def spawn(*args, **kwargs):
        calls.append(args)
        return process

    async def cleanup(args, **kwargs):
        calls.append(args)
        return (1 if mode == "cleanup_failure" else 0), b""

    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(runner, "_small_command", cleanup)
    if mode == "timeout":
        policy = policy.model_copy(update={"maximum_inference_ms": 1})
    task = runner.evaluate_offline_case(
        bundle=bundle,
        archive=tmp_path,
        runtime=runtime,
        policy=policy,
        case_id="c1" * 32,
        video_sha256=hashlib.sha256(b"video").hexdigest(),
        video=b"video",
    )
    if mode in {"runtime_failure", "cleanup_failure"}:
        with pytest.raises(runner.EvaluationInfrastructureError):
            await task
    else:
        result = await task
        assert result.status == ("ok" if mode == "success" else "miner_failure")
        assert result.hypothesis == ("hello" if mode == "success" else "")
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[-1] == ("/usr/bin/podman", "rm", "--force", "--ignore", "--time=0", name)
    assert "--all" not in calls[-1]
    assert not list(tmp_path.glob("umi-evaluation-input-*"))


@pytest.mark.asyncio
async def test_repeated_cancellation_waits_for_cleanup_task():
    entered = asyncio.Event()
    release = asyncio.Event()
    exited = asyncio.Event()

    async def cleanup():
        entered.set()
        await release.wait()
        exited.set()
        return 0, b""

    task = asyncio.create_task(runner._drain_cleanup(cleanup()))
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    assert not exited.is_set()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert exited.is_set()
