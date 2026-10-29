from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Shared deterministic fixtures, never production wallets or model files.
from tests.test_open_competition import policy as competition_policy_fixture
from umi import competition_runner as runner
from umi.competition_artifacts import preserve_bundle
from umi.host_model_execution import ModelExecutionAdmission
from umi.open_competition import BundleFile, ModelBundle, digest
from umi.protocol import canonical_json_bytes

from .test_host_memory_admission import provisioned as provisioned
from .test_open_competition import bundle_at

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


def test_new_cpu_runtime_defaults_to_256_pids_without_rewriting_explicit_history(runtime):
    fields = runtime.model_dump(mode="json", by_alias=True)
    del fields["pids_limit"]
    assert runner.OfflineCpuRuntime.model_validate(fields).pids_limit == 256
    historical = runtime.model_copy(update={"pids_limit": 128})
    raw = canonical_json_bytes(historical)
    assert b'"pids_limit":128' in raw
    restored = runner.OfflineCpuRuntime.model_validate_json(raw)
    assert canonical_json_bytes(restored) == raw
    assert digest(restored) == digest(historical)


@pytest.mark.asyncio
async def test_runtime_preflight_allows_slow_container_runtime_startup(
    runtime, policy, monkeypatch
):
    policy = policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})
    calls = []

    async def command(arguments, *, timeout):
        calls.append((arguments, timeout))
        if arguments[1] == "info":
            return 0, b'{"host":{"security":{"rootless":true},"cgroupVersion":"v2"}}'
        return 0, b""

    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(runner, "_small_command", command)

    await runner.verify_runtime(runtime, policy)

    assert calls == [
        (("/usr/bin/podman", "info", "--format=json"), 60),
        (("/usr/bin/podman", "image", "exists", runtime.image), 60),
    ]


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
@pytest.mark.parametrize("routed", [False, True])
@pytest.mark.parametrize("admitted", [False, True])
@pytest.mark.parametrize(
    "mode", ["success", "fast_success", "timeout", "overflow", "runtime_failure", "cleanup_failure"]
)
async def test_bounded_execution_removes_only_its_case_container(
    runtime, policy, tmp_path, monkeypatch, mode, routed, admitted
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
    if routed:
        records.extend(
            BundleFile(path=path, role="inference", sha256="cd" * 32, size_bytes=0)
            for path in ("fs/route_child.py", "umi_inference.py")
        )
    bundle = ModelBundle(
        schema="umi-model-bundle/1",
        profile="offline_bundle/1",
        parent_baseline_sha256=None,
        license_id="CC-BY-SA-4.0",
        files=tuple(sorted(records, key=lambda x: x.path)),
    )

    async def verified(*args, **kwargs):
        pass

    monkeypatch.setattr(runner, "verify_runtime", verified)
    monkeypatch.setattr(runner, "verify_preserved_bundle", lambda *args: "ab" * 32)
    calls = []

    class Process:
        returncode = None

        def __init__(self):
            self.stdout = asyncio.StreamReader()
            if mode != "timeout":
                data = b"x" * 200 if mode == "overflow" else b"hello"
                if mode == "fast_success":
                    # A completed process need not wait for optional accounting.
                    self.stdout.feed_data(data)
                    self.stdout.feed_eof()
                    self.returncode = 0
                else:
                    # Model an actually running subprocess, rather than making
                    # every awaited read/wait complete synchronously in the fake.
                    loop = asyncio.get_running_loop()
                    loop.call_soon(self.stdout.feed_data, data)
                    loop.call_soon(self.stdout.feed_eof)

        async def wait(self):
            if self.returncode is None:
                self.returncode = 125 if mode == "runtime_failure" else 0
            return self.returncode

        def kill(self):
            self.returncode = -9

    process = Process()
    container_id = "cd" * 32
    bindings = []

    class Capacity:
        def bind_container(self, cid, path):
            assert cid == container_id
            assert path == f"/sys/fs/cgroup/test/libpod-{container_id}.scope/container"
            bindings.append((cid, path))
            return True

        def clear_container(self):
            bindings.append("cleared")

    async def spawn(*args, **kwargs):
        calls.append(args)
        if admitted:
            cidfile = Path(args[args.index("--cidfile") + 1])
            cidfile.write_text(container_id + "\n")
            cidfile.chmod(0o600)
        return process

    async def cleanup(args, **kwargs):
        calls.append(args)
        if args[1:3] == ("container", "inspect"):
            return 0, json.dumps(
                [
                    {
                        "Id": container_id,
                        "Name": calls[0][calls[0].index("--name") + 1],
                        "State": {
                            "Running": True,
                            "CgroupPath": f"/test/libpod-{container_id}.scope",
                        },
                    }
                ]
            ).encode()
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
        **(
            {
                "native_capacity": Capacity(),
                "invocation_sha256": "ef" * 32,
                "workspace": tmp_path / "invocation",
            }
            if admitted
            else {}
        ),
    )
    if mode in {"runtime_failure", "cleanup_failure"}:
        with pytest.raises(runner.EvaluationInfrastructureError):
            await task
    else:
        result = await task
        successful = mode in {"success", "fast_success"}
        assert result.status == ("ok" if successful else "miner_failure")
        assert result.hypothesis == ("hello" if successful else "")
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[0][-2] == ("/model/umi_inference.py" if routed else "/model/inference.py")
    assert calls[-1] == ("/usr/bin/podman", "rm", "--force", "--ignore", "--time=0", name)
    assert "--all" not in calls[-1]
    if admitted:
        if mode == "fast_success":
            assert bindings == ["cleared"]
            assert not any(call[1:3] == ("container", "inspect") for call in calls)
        else:
            assert len(bindings) == 2 and bindings[-1] == "cleared"
    else:
        assert not bindings and "--cidfile" not in calls[0]
    assert not list(tmp_path.glob("umi-evaluation-input-*"))


@pytest.mark.parametrize("identity", ["a" * 63, "A" * 64, "ab" * 33, "ab" * 32 + "extra"])
def test_capacity_container_identity_requires_full_exact_hex(tmp_path, identity):
    path = tmp_path / "container.cid"
    path.write_text(identity)
    if len(identity) < 64:
        assert runner._read_container_id(path) is None
    else:
        with pytest.raises(ValueError):
            runner._read_container_id(path)


def test_capacity_container_identity_refuses_links(tmp_path):
    original = tmp_path / "original"
    original.write_text("ab" * 32 + "\n")
    linked = tmp_path / "container.cid"
    linked.symlink_to(original)
    with pytest.raises(OSError):
        runner._read_container_id(linked)
    linked.unlink()
    os.link(original, linked)
    with pytest.raises(ValueError):
        runner._read_container_id(linked)


@pytest.mark.parametrize("changed", ["id", "name", "prefix", "traversal"])
async def test_unresolved_capacity_binding_stays_conservative(tmp_path, monkeypatch, changed):
    cid, name = "ab" * 32, "umi-evaluation-" + "cd" * 16
    path = tmp_path / "container.cid"
    path.write_text(cid + "\n")
    record = {
        "Id": cid,
        "Name": name,
        "State": {"Running": True, "CgroupPath": f"/test/libpod-{cid}.scope"},
    }
    if changed == "id":
        record["Id"] = "ef" * 32
    elif changed == "name":
        record["Name"] = "umi-evaluation-" + "ef" * 16
    elif changed == "prefix":
        record["State"]["CgroupPath"] = f"/test/libpod-{cid[:32]}.scope"
    else:
        record["State"]["CgroupPath"] = f"/test/../test/libpod-{cid}.scope"

    async def inspect(*_, **__):
        return 0, json.dumps([record]).encode()

    class Capacity:
        def bind_container(self, *_):
            pytest.fail("uncertain ownership cannot credit a live lease")

    monkeypatch.setattr(runner, "_small_command", inspect)
    await runner._bind_invocation_capacity(SimpleNamespace(returncode=None), path, name, Capacity())


async def test_capacity_binding_reuses_confirmed_inspection_while_kernel_scope_appears(
    tmp_path, monkeypatch
):
    cid, name = "ab" * 32, "umi-evaluation-" + "cd" * 16
    path = tmp_path / "container.cid"
    path.write_text(cid + "\n")
    inspections, attempts = [], []

    async def inspect(arguments, **_):
        inspections.append(arguments)
        return 0, json.dumps(
            [
                {
                    "Id": cid,
                    "Name": name,
                    "State": {"Running": True, "CgroupPath": f"/test/libpod-{cid}.scope"},
                }
            ]
        ).encode()

    class Capacity:
        def bind_container(self, container_id, cgroup):
            attempts.append((container_id, cgroup))
            return len(attempts) == 2

    monkeypatch.setattr(runner, "_small_command", inspect)
    await asyncio.wait_for(
        runner._bind_invocation_capacity(SimpleNamespace(returncode=None), path, name, Capacity()),
        3,
    )
    assert len(inspections) == 1 and len(attempts) == 2 and attempts[0] == attempts[1]


@pytest.mark.skipif(
    sys.platform != "linux" or not os.environ.get("UMI_OFFLINE_TEST_IMAGE"),
    reason="requires a preinstalled pinned Linux image; no pull or production inputs",
)
@pytest.mark.parametrize("interrupt", [False, True], ids=["normal", "cancel"])
async def test_real_capacity_binding_and_exact_cleanup(
    provisioned, policy, runtime, tmp_path, interrupt
):
    """Real CID/kernel binding; tiny inert container, actual invocation lease."""
    runtime = runtime.model_copy(
        update={
            "image": os.environ["UMI_OFFLINE_TEST_IMAGE"],
            "cpus": 1,
            "memory_bytes": 256 * 1024**2,
            "pids_limit": 32,
        }
    )
    policy = policy.model_copy(
        update={
            "evaluation_runtime_sha256": digest(runtime),
            "maximum_inference_ms": 60000,
        }
    )
    _, policy_path, original, write, _ = provisioned
    body = {
        k: v
        for k, v in original.items()
        if k not in ("maximum_aggregate_bytes", "settlement_gate", "settlement_signals")
    }
    body.update(
        schema="umi-host-model-execution-admission/1",
        minimum_available_bytes=4 * 1024**3,
        incremental_budget_bytes=513 * 1024**2,
        background_reservation_bytes=2 * 1024**3,
        protocol_policy_sha256=digest(policy),
        evaluation_runtime_sha256=digest(runtime),
        container_cgroup_roots=(
            f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service/user.slice",
        ),
        slots=[
            dict(original["slots"][0], reservation_bytes=1024**2),
            dict(original["slots"][1], reservation_bytes=runtime.memory_bytes),
            dict(
                original["slots"][2],
                reservation_bytes=runtime.memory_bytes,
                lane="transient",
                settlement_role=None,
            ),
        ],
    )
    admission = ModelExecutionAdmission(
        SimpleNamespace(
            policy_path=str(policy_path),
            policy_sha256=write(body),
            host_identity_path="/etc/machine-id",
        ),
        policy,
    )
    source, archive = tmp_path / "source", tmp_path / "archive"
    bundle = bundle_at(source)
    code = (
        "from pathlib import Path\nimport sys,time\n"
        "assert Path(sys.argv[1]).read_bytes() == b'inert video'\n"
        f"time.sleep({50 if interrupt else 3})\nprint('hello')\n"
    ).encode()
    (source / "inference.py").write_bytes(code)
    bundle = bundle.model_copy(
        update={
            "files": tuple(
                f.model_copy(
                    update={"sha256": hashlib.sha256(code).hexdigest(), "size_bytes": len(code)}
                )
                if f.role == "inference"
                else f
                for f in bundle.files
            )
        }
    )
    preserve_bundle(bundle, source, archive, policy)
    seed = os.environ.get("UMI_CAPACITY_QUALIFICATION_SEED", runner.uuid.uuid4().hex)
    invocation = hashlib.sha256(
        (seed + (":cancel" if interrupt else ":normal")).encode()
    ).hexdigest()
    name = runner.invocation_container_name(invocation)
    bound, cleared = asyncio.Event(), []
    observed = []
    task = None
    try:
        async with admission.invocation(runtime) as token:

            class Witness:
                def bind_container(self, cid, path):
                    if not token.bind_container(cid, path):
                        return False
                    assert len(cid) == 64 and path.endswith(f"/libpod-{cid}.scope/container")
                    probe = admission.controller.try_acquire_group("owner_export", 1)
                    assert probe is not None
                    try:
                        observed.append(dict(admission.controller.last_model_admission))
                    finally:
                        probe.close()
                    bound.set()
                    return True

                def clear_container(self):
                    token.clear_container()
                    cleared.append(True)

            task = asyncio.create_task(
                runner.execute_offline_case(
                    bundle=bundle,
                    archive=archive,
                    runtime=runtime,
                    policy=policy,
                    case_id="c1" * 32,
                    video_sha256=hashlib.sha256(b"inert video").hexdigest(),
                    video=b"inert video",
                    invocation_sha256=invocation,
                    workspace=tmp_path / "invocation",
                    native_capacity=Witness(),
                )
            )
            try:
                await asyncio.wait_for(bound.wait(), 20)
                assert len(observed) == 1
                assert observed[0]["owned_container_credit_bytes"] == runtime.memory_bytes
                if interrupt:
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(task, 15)
                else:
                    result = await asyncio.wait_for(task, 15)
                    assert result.output.status == "ok" and result.output.hypothesis == "hello"
                assert cleared == [True]
            finally:
                # Preserve the lease through cleanup even if observation fails.
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        assert (await runner._small_command(("/usr/bin/podman", "container", "exists", name)))[
            0
        ] == 1
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        # Same exact identities are available to the managed service's
        # ExecStopPost cleanup even if pytest never writes its final report.
        await runner.stop_retained_cpu_invocation(invocation)


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
