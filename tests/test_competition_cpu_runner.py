"""CPU timing runner ownership/ordering fixtures, with no containers or models."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_runner as runner
from umi.competition_cpu_timing import cpu_timing_limits_v1, finish_cpu_timing
from umi.competition_evaluation_runtime import prepared_runtime_authorization
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cpu_efficiency_policy import (
    adoption as adoption,
)
from .test_competition_cpu_efficiency_policy import (
    base_policy as base_policy,
)
from .test_competition_cpu_efficiency_policy import (
    efficiency_round,
    selected,
)
from .test_competition_cpu_efficiency_policy import (
    intake as intake,
)
from .test_competition_cpu_efficiency_policy import (
    original_runtime as original_runtime,
)
from .test_competition_cpu_efficiency_policy import (
    policy as policy,
)
from .test_competition_cpu_efficiency_policy import (
    preparation as preparation,
)
from .test_competition_cpu_efficiency_policy import (
    recovery as recovery,
)
from .test_competition_cpu_efficiency_policy import (
    runtime as runtime,
)
from .test_competition_cpu_efficiency_policy import (
    runtime_adoption as runtime_adoption,
)
from .test_competition_cpu_efficiency_policy import (
    scenario as scenario,
)
from .test_competition_cpu_timing import bundle_cache, conditions, context, sample
from .test_open_competition import bundle_at


def test_only_timed_command_requires_isolated_gate_and_kernel_cpu_parent(runtime):
    kwargs = dict(
        name="umi-evaluation-" + "ab" * 16,
        model=Path("/model"),
        inputs=Path("/input"),
        entrypoint="infer.py",
        maximum_inference_ms=1000,
    )
    original = runner.model_command(runtime, **kwargs)
    timed = runner.model_command(
        runtime,
        **kwargs,
        cpu_timing=SimpleNamespace(
            podman_parent="/umiexecution.slice/models/slot/uid1",
            podman_prefix=("/usr/bin/podman", "--cgroup-manager=cgroupfs"),
            cpu_set_argument="0,1",
        ),
    )
    assert original[-3:] == (runtime.image, "/model/infer.py", "/input/video.mp4")
    assert "--rm" in original and "--rm" not in timed
    assert "--cpuset-cpus" not in original and "--cgroup-parent" not in original
    assert timed[timed.index("--cpuset-cpus") + 1] == "0,1"
    assert timed[timed.index("--cgroup-parent") + 1] == "/umiexecution.slice/models/slot/uid1"
    assert timed[-7:-3] == ("-I", "-S", "-B", "-c")
    assert timed[-3] == runner._CPU_LAUNCH_GATE
    assert "os.execv" in timed[-3]


@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "crash",
        "timeout",
        "overflow",
        "cancel",
        "inspection_failure",
        "gate_budget_exhausted",
        "cleanup_failure",
    ],
)
async def test_native_timed_runner_gates_model_and_preserves_cleanup(
    scenario,
    policy,
    adoption,
    runtime_adoption,
    tmp_path,
    monkeypatch,
    mode,
):
    native = selected(scenario, policy, adoption)
    round_ = efficiency_round(scenario["round_"], adoption, runtime_adoption)
    runtime = runtime_adoption.adoption.runtime
    runtime_authority = prepared_runtime_authorization(round_, policy)
    bundle = bundle_at(tmp_path / "bundle")
    trace = []
    clock = SimpleNamespace(now=1_000_000)
    monkeypatch.setattr(
        runner,
        "time",
        SimpleNamespace(
            monotonic=lambda: clock.now / 1_000_000,
            monotonic_ns=lambda: clock.now * 1000,
        ),
    )
    ctx = context(memory_max_bytes=runtime.memory_bytes)
    inputs = None
    cid = "cd" * 32

    class Session:
        podman_parent = "/umiexecution.slice/models/slot/uid1"
        owned_parent = "/sys/fs/cgroup" + podman_parent
        podman_prefix = ("/usr/bin/podman", "--cgroup-manager=cgroupfs")
        cpu_set_argument = "0,1"

        async def prepare_conditions(self, invocation):
            assert invocation == "ef" * 32
            trace.append("conditions_before")

        async def finish_conditions(self):
            trace.append("conditions_after")

        def sample(self):
            trace.append("sample")
            elapsed = clock.now - 1_000_000
            return sample(
                ctx,
                now=clock.now,
                ticks=100 + elapsed // 10_000,
                busy=50 + elapsed // 20_000,
                usage=elapsed,
            )

        def finish(self, **kwargs):
            trace.append("finish")
            return finish_cpu_timing(
                contract_sha256=native.adoption_sha256,
                context=ctx,
                limits=cpu_timing_limits_v1(),
                conditions=conditions(
                    ctx,
                    started=kwargs["started_monotonic_us"],
                    finished=kwargs["finished_monotonic_us"],
                    invocation="ef" * 32,
                ),
                **kwargs,
            )

        def close(self):
            trace.append("close")

    class CacheLease:
        exclusive = True

        def check(self, given_bundle):
            assert given_bundle == bundle

        async def condition(self, given_bundle, invocation):
            assert given_bundle == bundle and invocation == "ef" * 32
            trace.append("cache_conditioned")
            return bundle_cache(model=digest(bundle), started=clock.now, invocation=invocation)

        def cleaned(self):
            trace.append("cache_marker_cleared")

    class Capacity:
        def begin_cpu_timing(self, given_runtime, authorization):
            assert given_runtime == runtime and authorization is native
            trace.append("begin")
            return Session()

        def bind_container(self, container_id, path):
            assert container_id == cid
            assert not (inputs / ".cpu-timing-ready").exists()
            trace.append("verified_kernel_binding")
            return True

        def clear_container(self):
            trace.append("clear")

    class Stdout:
        first = True

        async def read(self, limit):
            assert "verified_kernel_binding" in trace
            assert (inputs / ".cpu-timing-ready").exists()
            if not self.first:
                return b""
            self.first = False
            trace.append("model")
            clock.now = 2_001_000 if mode == "timeout" else 1_100_000
            if mode == "cancel":
                raise asyncio.CancelledError
            if mode == "timeout":
                raise asyncio.TimeoutError
            return b"x" * limit if mode == "overflow" else b"hello"

    class Process:
        returncode = None
        stdout = Stdout()

        async def wait(self):
            if self.returncode is None:
                self.returncode = 139 if mode == "crash" else 0
            return self.returncode

        def kill(self):
            trace.append("kill_client")
            self.returncode = -9

    process = Process()

    async def spawn(*args, **kwargs):
        nonlocal inputs
        trace.append("spawn")
        cidfile = Path(args[args.index("--cidfile") + 1])
        inputs = cidfile.parent
        assert not (inputs / ".cpu-timing-ready").exists()
        cidfile.write_text(cid + "\n")
        cidfile.chmod(0o600)
        clock.now = 2_000_000 if mode == "gate_budget_exhausted" else 1_001_000
        return process

    async def command(args, **kwargs):
        if args[2:4] == ("container", "inspect"):
            trace.append("inspect")
            if mode == "inspection_failure":
                return 1, b""
            return 0, json.dumps(
                [
                    dict(
                        Id=cid,
                        Name=runner.invocation_container_name("ef" * 32),
                        State=dict(
                            Running=True,
                            CgroupPath=f"/umiexecution.slice/models/slot/uid1/libpod-{cid}",
                        ),
                    )
                ]
            ).encode()
        assert args == (
            "/usr/bin/podman",
            "--cgroup-manager=cgroupfs",
            "rm",
            "--force",
            "--ignore",
            "--time=0",
            runner.invocation_container_name("ef" * 32),
        )
        trace.append("cleanup")
        return (1 if mode == "cleanup_failure" else 0), b""

    async def verified(*args, **kwargs):
        pass

    monkeypatch.setattr(runner, "verify_runtime", verified)
    monkeypatch.setattr(runner, "verify_preserved_bundle", lambda *args: "ab" * 32)
    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(runner, "_small_command", command)
    pending = runner.execute_offline_case(
        bundle=bundle,
        archive=tmp_path,
        runtime=runtime,
        policy=policy,
        case_id="c1" * 32,
        video_sha256=hashlib.sha256(b"video").hexdigest(),
        video=b"video",
        invocation_sha256="ef" * 32,
        workspace=tmp_path / "invocation",
        runtime_authorization=runtime_authority,
        native_capacity=Capacity(),
        cpu_efficiency_authorization=native,
        model_cache_lease=CacheLease(),
    )
    if mode in {"inspection_failure", "cleanup_failure", "gate_budget_exhausted"}:
        with pytest.raises(runner.EvaluationInfrastructureError):
            await pending
    elif mode == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await pending
    else:
        record = await pending
        assert trace.index("cache_conditioned") < trace.index("conditions_before")
        assert trace.index("conditions_before") < trace.index("spawn")
        assert trace.index("conditions_after") < trace.index("finish")
        assert record.schema_ == "umi-offline-case-execution/2"
        assert record.output.status == ("ok" if mode == "success" else "miner_failure")
        assert record.output.cpu_timing.launch_gate_elapsed_us == 1000
        assert record.output.elapsed_ms == (1001 if mode == "timeout" else 100)
        assert record.output.cpu_timing.speed_elapsed_ms == record.output.elapsed_ms - 1
        if mode in {"timeout", "overflow"}:
            assert trace.index("cleanup") < trace.index("finish")
        else:
            assert trace.index("finish") < trace.index("cleanup")
        assert (
            runner.OfflineCaseExecution.model_validate_json(canonical_json_bytes(record)) == record
        )
        with pytest.raises(ValueError, match="native cohort authority"):
            runner.validate_case_execution(record, policy, runtime_authorization=runtime_authority)
    assert trace[-1] == "close"
    assert "cleanup" in trace and "clear" in trace
    assert ("cache_marker_cleared" in trace) == (mode != "cleanup_failure")
    if "cache_marker_cleared" in trace:
        assert trace.index("cleanup") < trace.index("cache_marker_cleared")
    assert not inputs.exists()
    if mode in {"inspection_failure", "gate_budget_exhausted"}:
        assert "model" not in trace


def test_untimed_execution_keeps_original_schema_and_bytes(policy, runtime):
    record = runner.OfflineCaseExecution(
        schema="umi-offline-case-execution/1",
        model_sha256="a" * 64,
        runtime_sha256=digest(runtime),
        video_sha256="b" * 64,
        output=dict(case_id="c" * 64, status="ok", hypothesis="hello", elapsed_ms=1),
        stdout_hex=b"hello".hex(),
        reason="ok",
        returncode=0,
    )
    raw = canonical_json_bytes(record)
    assert b"cpu_timing" not in raw
    assert runner.OfflineCaseExecution.model_validate_json(raw) == record
    runner.validate_case_execution(record, policy)
