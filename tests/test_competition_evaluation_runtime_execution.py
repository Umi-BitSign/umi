"""PID-only amendments preserve receipt identity and native memory accounting."""

import asyncio
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_runner as runner
from umi import host_memory_admission as memory
from umi.competition_cohort_endpoint_host import EndpointHost
from umi.competition_cohort_evaluation import RecoverableEvaluationRound
from umi.competition_cohort_parallel_cache import ModelPlan
from umi.competition_cohort_sandbox import DirectCohortCpuSandbox
from umi.competition_evaluation_runtime import (
    AuthorizedEvaluationRuntime,
    CohortEvaluationRuntimeAdoption,
    SignedCohortEvaluationRuntimeAdoption,
    authorize_evaluation_runtime,
)
from umi.host_model_execution import ModelExecutionAdmission
from umi.open_competition import CaseOutput, digest

from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_runner import runtime as runtime
from .test_host_memory_admission import provisioned as provisioned
from .test_open_competition import bundle_at, submission
from .test_open_competition import policy as policy


@pytest.fixture
def amended(runtime, policy, recovery):
    original = runtime.model_copy(update={"pids_limit": 128})
    effective = original.model_copy(update={"pids_limit": 256})
    policy = policy.model_copy(update={"evaluation_runtime_sha256": digest(original)})
    plan = recovery[0].model_copy(update={"sequence": 7, "policy_sha256": digest(policy)})
    authority = recovery[1].authority.model_copy(
        update={"policy_sha256": digest(policy), "cohort_sha256s": (digest(plan),)}
    )
    fields = {
        "schema": "umi-cohort-evaluation-runtime-adoption/1",
        "policy_sha256": digest(policy),
        "authority_sha256": digest(authority),
        "cohort_sha256s": authority.cohort_sha256s,
        "first_cohort_sequence": 7,
        "original_runtime": original,
        "runtime": effective,
        "issued_at_block": 200,
        "reason": "Allow the declared CPU model to create bounded worker threads",
    }
    body = CohortEvaluationRuntimeAdoption(**fields)
    signed = SignedCohortEvaluationRuntimeAdoption(adoption=body, signatures=signatures(body))
    authorization = authorize_evaluation_runtime(
        signed, policy=policy, authority=authority, plan=plan, current_block=200
    )
    return SimpleNamespace(
        original=original,
        effective=effective,
        policy=policy,
        authorization=authorization,
        plan=plan,
        authority=authority,
        adoption=signed,
    )


def receipt(runtime):
    return runner.OfflineCaseExecution(
        schema="umi-offline-case-execution/1",
        model_sha256="ab" * 32,
        runtime_sha256=digest(runtime),
        video_sha256="bc" * 32,
        output=CaseOutput(case_id="cd" * 32, status="ok", hypothesis="hello", elapsed_ms=1),
        stdout_hex=b"hello".hex(),
        reason="ok",
        returncode=0,
    )


def test_receipts_require_the_actual_runtime_authorization(amended):
    before, after = receipt(amended.original), receipt(amended.effective)
    runner.validate_case_execution(before, amended.policy)
    with pytest.raises(ValueError, match="runtime mismatch"):
        runner.validate_case_execution(after, amended.policy)
    runner.validate_case_execution(
        after, amended.policy, runtime_authorization=amended.authorization
    )
    with pytest.raises(ValueError, match="runtime mismatch"):
        runner.validate_case_execution(
            before, amended.policy, runtime_authorization=amended.authorization
        )
    changed = amended.policy.model_copy(update={"maximum_inference_ms": 2000})
    with pytest.raises(ValueError, match="runtime mismatch"):
        runner.validate_case_execution(after, changed, runtime_authorization=amended.authorization)


@pytest.mark.parametrize("forgery", ["plain", "runtime", "adoption"])
def test_receipt_cannot_rebind_or_reconstruct_native_capability(amended, forgery):
    authorization = amended.authorization
    if forgery == "plain":
        authorization = AuthorizedEvaluationRuntime(
            policy_sha256=authorization.policy_sha256,
            original_runtime_sha256=authorization.original_runtime_sha256,
            runtime=authorization.runtime,
            adoption_sha256=authorization.adoption_sha256,
        )
    elif forgery == "runtime":
        authorization = replace(authorization, runtime=amended.original)
    else:
        authorization = replace(authorization, adoption_sha256="ef" * 32)
    with pytest.raises(ValueError, match="runtime mismatch"):
        runner.validate_case_execution(
            receipt(amended.effective), amended.policy, runtime_authorization=authorization
        )


async def test_effective_cpu_execution_preserves_actual_limits_and_receipt(
    amended, tmp_path, monkeypatch
):
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner.os, "geteuid", lambda: 1000)
    calls = []

    async def command(arguments, **kwargs):
        calls.append(arguments)
        if arguments[1] == "info":
            return 0, b'{"host":{"security":{"rootless":true},"cgroupVersion":"v2"}}'
        return 0, b""

    class Process:
        returncode = None

        def __init__(self):
            self.stdout = asyncio.StreamReader()
            self.stdout.feed_data(b"hello")
            self.stdout.feed_eof()

        async def wait(self):
            self.returncode = 0
            return 0

    async def spawn(*arguments, **kwargs):
        calls.append(arguments)
        return Process()

    monkeypatch.setattr(runner, "_small_command", command)
    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(runner, "verify_preserved_bundle", lambda *args: None)
    bundle = bundle_at(tmp_path / "bundle")
    arguments = dict(
        bundle=bundle,
        archive=tmp_path,
        runtime=amended.effective,
        policy=amended.policy,
        case_id="cd" * 32,
        video_sha256=hashlib.sha256(b"video").hexdigest(),
        video=b"video",
    )
    with pytest.raises(runner.EvaluationInfrastructureError, match="signed policy"):
        await runner.execute_offline_case(**arguments)
    assert calls == []
    result = await runner.execute_offline_case(
        **arguments, runtime_authorization=amended.authorization
    )
    assert result.runtime_sha256 == digest(amended.effective)
    assert result.runtime_sha256 != amended.policy.evaluation_runtime_sha256
    assert result.output.hypothesis == "hello"
    invoked = next(call for call in calls if call[1] == "run")
    assert invoked[invoked.index("--pids-limit") + 1] == "256"
    assert invoked[invoked.index("--cpus") + 1] == str(amended.original.cpus)
    assert invoked[invoked.index("--memory") + 1] == str(amended.original.memory_bytes)
    assert not list(tmp_path.glob("umi-evaluation-input-*"))


@pytest.fixture
def amended_capacity(amended, provisioned, monkeypatch):
    _, path, original, write, _ = provisioned
    slots = [
        dict(original["slots"][0], reservation_bytes=1024**3),
        dict(original["slots"][1], reservation_bytes=amended.original.memory_bytes),
        dict(
            original["slots"][2],
            reservation_bytes=amended.original.memory_bytes,
            lane="transient",
            settlement_role=None,
        ),
    ]
    body = {
        key: value
        for key, value in original.items()
        if key not in ("maximum_aggregate_bytes", "settlement_gate", "settlement_signals")
    }
    body.update(
        schema="umi-host-model-execution-admission/1",
        minimum_available_bytes=4 * 1024**3,
        incremental_budget_bytes=sum(slot["reservation_bytes"] for slot in slots),
        protocol_policy_sha256=digest(amended.policy),
        evaluation_runtime_sha256=digest(amended.original),
        container_cgroup_roots=("/sys/fs/cgroup/umi-isolated-test-absent",),
        slots=slots,
    )
    selection = SimpleNamespace(
        policy_path=str(path), policy_sha256=write(body), host_identity_path="/etc/machine-id"
    )
    monkeypatch.setattr(memory, "_available_memory", lambda: 32 * 1024**3)
    return ModelExecutionAdmission(selection, amended.policy)


async def test_amendment_reuses_original_memory_slots_without_bypassing_authorization(
    amended, amended_capacity
):
    admission = amended_capacity
    with pytest.raises(memory.AdmissionBindingError):
        admission.check_runtime(amended.effective)
    admission.check_runtime(amended.original)
    admission.check_runtime(amended.effective, runtime_authorization=amended.authorization)
    async with admission.hold(
        amended.effective, exclusive=True, runtime_authorization=amended.authorization
    ):
        async with admission.invocation(
            amended.effective, runtime_authorization=amended.authorization
        ):
            assert admission.controller.try_acquire_group("transient", 1) is None
        with pytest.raises(memory.AdmissionBindingError):
            async with admission.invocation(amended.effective):
                pytest.fail("nested active lease bypassed runtime authorization")
    available = admission.controller.try_acquire_group("transient", 2)
    assert available is not None
    available.close()
    changed = amended.effective.model_copy(update={"memory_bytes": 2 * 1024**3})
    with pytest.raises(memory.AdmissionBindingError):
        async with admission.hold(changed, runtime_authorization=amended.authorization):
            pytest.fail("PID amendment authorized a changed memory ceiling")


def test_readiness_authenticates_each_order_before_runtime_probe_deduplication(amended, tmp_path):
    round_ = RecoverableEvaluationRound(
        schema="umi-recoverable-evaluation-round/2",
        policy_sha256=digest(amended.policy),
        cohort_sha256=digest(amended.plan),
        intake_closure_sha256="aa" * 32,
        sequence=7,
        suite_sha256=amended.plan.suite_sha256,
        incumbent_model_sha256="bb" * 32,
        runtime_sha256=digest(amended.effective),
        eligible_tracks=("model",),
        participants=({"submission_sha256": "cc" * 32, "admission_sha256": "dd" * 32},),
        prepared_at_block=200,
        runtime_adoption=amended.adoption,
    )
    bundle = bundle_at(tmp_path / "bundle")
    order = SimpleNamespace(
        round=round_,
        runtime=amended.effective,
        incumbent=bundle,
        submission=SimpleNamespace(submission=SimpleNamespace(model_bundle=bundle)),
        cases=(),
    )
    assignment = SimpleNamespace(certificate=SimpleNamespace(order=order))
    host = object.__new__(EndpointHost)
    host.policy = amended.policy
    sandbox = object.__new__(DirectCohortCpuSandbox)
    sandbox.videos = tmp_path / "videos"
    host.benchmark = SimpleNamespace(sandbox=sandbox)
    history = SimpleNamespace(
        plan=amended.plan, authority=SimpleNamespace(authority=amended.authority)
    )
    selected, videos = host._ready_inputs((assignment, assignment), history)
    assert len(selected) == 1 and videos == ()
    runtime, authorization = selected[0]
    assert runtime == amended.effective and authorization == amended.authorization
    damaged = SimpleNamespace(**vars(order))
    damaged.round = round_.model_copy(
        update={"runtime_adoption": amended.adoption.model_copy(update={"signatures": ()})}
    )
    invalid = SimpleNamespace(certificate=SimpleNamespace(order=damaged))
    with pytest.raises(ValueError):
        host._ready_inputs((invalid, assignment), history)


async def test_remote_readiness_deduplicates_sources_and_propagates_damaged_metadata(
    amended, tmp_path
):
    bundle = bundle_at(tmp_path / "bundle")
    signed = submission(amended.policy, bundle=bundle)
    order = SimpleNamespace(
        round={"cohort": digest(amended.plan)}, submission=signed, incumbent=bundle
    )
    port = object.__new__(DirectCohortCpuSandbox)
    port.archive, port.policy = tmp_path / "absent-local-archive", amended.policy
    resolved, checked = [], []

    async def available(request):
        checked.append(request)

    materializer = SimpleNamespace(available=available)

    async def source(selected, role):
        assert selected is order
        resolved.append(role)
        return ModelPlan(role, bundle, materializer, role)

    port._source_plan = source
    await port.models_available((order,) * 16)
    assert resolved == checked == ["candidate", "incumbent"]
    assert not port.archive.exists()

    async def damaged(*args):
        raise ValueError("certified source metadata requires repair")

    port._source_plan = damaged
    with pytest.raises(ValueError, match="metadata requires repair"):
        await port.models_available((order,))
