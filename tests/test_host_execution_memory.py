"""One native policy owns graph/model exclusion and independent retained lanes."""

import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import host_memory_admission as native
from umi import host_memory_runtime as memory
from umi.host_execution_memory import ExecutionMemoryPolicy
from umi.host_memory_admission import HostMemoryAdmissionPolicy
from umi.host_model_execution import ModelExecutionAdmission
from umi.open_competition import digest

from .test_host_memory_admission import provisioned as provisioned
from .test_host_memory_workload_profile import profile_body, write_profile
from .test_host_model_execution import Policy, Runtime

GIB = 1024**3


@pytest.fixture
def joint(provisioned, monkeypatch, tmp_path):
    _, path, prior, write, _ = provisioned
    runtime = Runtime()
    policy = Policy(evaluation_runtime_sha256=digest(runtime))
    workload = write_profile(
        tmp_path / "workload-profile.json",
        profile_body(tmp_path, digest(policy), digest(runtime)),
    )
    body = dict(prior)
    body.update(
        schema="umi-host-execution-memory-admission/1",
        minimum_available_bytes=4 * GIB,
        incremental_budget_bytes=15 * GIB,
        background_reservation_bytes=GIB,
        maximum_aggregate_bytes=4 * GIB,
        protocol_policy_sha256=digest(policy),
        evaluation_runtime_sha256=digest(runtime),
        workload_profile=workload.model_dump(mode="json"),
        container_cgroup_roots=("/sys/fs/cgroup/umi-joint-isolated-test-absent",),
        slots=[
            dict(slot, reservation_bytes=size)
            for slot, size in zip(prior["slots"], (GIB, 8 * GIB, 3 * GIB, 3 * GIB), strict=True)
        ],
    )
    selection = memory.HostMemoryAdmissionSelection(
        policy_path=str(path), policy_sha256=write(body)
    )
    monkeypatch.setattr(native, "_available_memory", lambda: 32 * GIB)

    def graph():
        return native.HostMemoryAdmission(path, expected_sha256=selection.policy_sha256)

    return SimpleNamespace(
        body=body,
        policy=policy,
        runtime=runtime,
        selection=selection,
        graph=graph,
        model=lambda: ModelExecutionAdmission(selection, policy),
    )


def test_one_policy_counts_shared_slot_once_and_keeps_owner_and_replicas_independent(joint):
    graph, model = joint.graph(), joint.model()
    assert graph.policy_sha256 == model.controller.policy_sha256
    assert graph.policy.reserved_bytes == 15 * GIB
    assert len(graph.policy.slots) == 4 and len(model.slots) == 1
    graph_job = graph.try_acquire("transient")
    assert graph_job is not None
    assert model.controller.try_acquire_group("transient", 1) is None
    owner = model.controller.try_acquire_group("owner_export", 1)
    coordinator = graph.try_settlement("0" * 64, "coordinator")
    reviewer = model.controller.try_settlement("1".zfill(64), "reviewer")
    assert owner is not None and coordinator is not None and reviewer is not None
    owner.close()
    coordinator.close()
    reviewer.close()
    graph_job.close()
    model_job = model.controller.try_acquire_group("transient", 1)
    assert model_job is not None and graph.try_acquire("transient") is None
    model_job.close()
    resumed = graph.try_acquire("transient")
    assert resumed is not None
    resumed.close()


def test_joint_startup_charges_complete_envelope_and_legacy_floor_is_unchanged(joint, monkeypatch):
    required = 20 * GIB
    monkeypatch.setattr(native, "_available_memory", lambda: required - 1)
    with pytest.raises(OSError, match="startup"):
        joint.graph()
    with pytest.raises(OSError, match="startup"):
        joint.model()
    monkeypatch.setattr(native, "_available_memory", lambda: required)
    assert joint.graph().policy.minimum_available_bytes == 4 * GIB
    old = dict(joint.body)
    for key in (
        "protocol_policy_sha256",
        "evaluation_runtime_sha256",
        "container_cgroup_roots",
        "workload_profile",
    ):
        old.pop(key)
    old["schema"] = "umi-host-memory-admission/2"
    with pytest.raises(ValueError, match="minimum_available_bytes"):
        HostMemoryAdmissionPolicy.model_validate(old)


@pytest.mark.parametrize("role", ["intake", "phase_reviewer", "settlement"])
def test_joint_runtime_checks_actual_protocol_identity(joint, role):
    with memory.memory_runtime(
        joint.selection,
        maximum_aggregate_bytes=4 * GIB,
        role=role,
        protocol_policy_sha256=digest(joint.policy),
        evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
    ) as selected:
        assert selected.joint_execution_stage
    with (
        pytest.raises(native.AdmissionBindingError, match="runtime identity"),
        memory.memory_runtime(
            joint.selection,
            maximum_aggregate_bytes=4 * GIB,
            role=role,
            protocol_policy_sha256="f" * 64,
            evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
        ),
    ):
        pytest.fail("wrong protocol cannot enter the joint runtime")


def test_joint_runtime_refuses_unqualified_role_and_aggregate_limit(joint):
    with (
        pytest.raises(native.AdmissionBindingError, match="runtime identity"),
        memory.memory_runtime(
            joint.selection,
            maximum_aggregate_bytes=GIB,
            role="reward_writer",
            protocol_policy_sha256=digest(joint.policy),
            evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
        ),
    ):
        pytest.fail("another consumer requires its own qualified selection")
    with (
        pytest.raises(ValueError, match="aggregate limit"),
        memory.memory_runtime(
            joint.selection,
            maximum_aggregate_bytes=4 * GIB + 1,
            role="phase_reviewer",
            protocol_policy_sha256=digest(joint.policy),
            evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
        ),
    ):
        pytest.fail("oversized aggregates cannot borrow the smaller qualification")


def test_joint_runtime_keeps_native_verification_bounds_separate(joint):
    from umi.host_memory_request_bounds import stage_bounds

    before = stage_bounds()
    with memory.memory_runtime(
        joint.selection,
        maximum_aggregate_bytes=4 * GIB,
        role="phase_reviewer",
        protocol_policy_sha256=digest(joint.policy),
        evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
    ):
        assert stage_bounds() is before is None


async def test_public_intake_binds_actual_joint_runtime_and_bounds_each_asgi_root(
    joint, provisioned, tmp_path, monkeypatch
):
    from pydantic import BaseModel

    from umi import competition_service as service
    from umi.host_memory_workload_profile import selected_workload

    class Recovery(BaseModel):
        authority: dict[str, str]

    class Series(BaseModel):
        recovery: Recovery

    series = Series(recovery=Recovery(authority={"fixture": "actual-service-authority"}))
    body = profile_body(tmp_path, digest(joint.policy), digest(joint.runtime))
    body.update(series_sha256=digest(series), authority_sha256=digest(series.recovery.authority))
    workload = write_profile(tmp_path / "actual-owner-profile.json", body)
    policy = dict(joint.body, workload_profile=workload.model_dump(mode="json"))
    selection = memory.HostMemoryAdmissionSelection(
        policy_path=joint.selection.policy_path, policy_sha256=provisioned[3](policy)
    )
    owner = SimpleNamespace(
        host_memory_admission=selection,
        maximum_export_bytes=4 * GIB,
        request_evidence_bytes=4 * GIB,
        request_replay_bytes=4 * GIB,
    )
    config = SimpleNamespace(
        recoverable_service=SimpleNamespace(admission_owner=owner, series=series),
        api_limits=service.CompetitionApiLimits(capacity_wait_seconds=0.01),
    )
    monkeypatch.setattr(
        service, "CompetitionServiceConfig", SimpleNamespace(model_validate_json=lambda _: config)
    )
    monkeypatch.setattr(service, "canonical_json_bytes", lambda _: b"{}")
    entered, middleware, responses = [], [], []

    class App:
        state = SimpleNamespace()

        def add_middleware(self, factory, **kwargs):
            middleware.append(factory(self, **kwargs))

        async def __call__(self, scope, receive, send):
            assert selected_workload().sha256 == workload.sha256
            assert memory.selected_memory().policy_sha256 == selection.policy_sha256
            entered.append(scope["path"])
            await send(dict(type="http.response.start", status=200, headers=[]))
            await send(dict(type="http.response.body", body=b"ok"))

    app = App()

    def construct(*args, **kwargs):
        assert selected_workload().sha256 == workload.sha256
        return app

    monkeypatch.setattr(service, "_create_intake_app", construct)
    assert service.create_intake_app(config, joint.policy) is app
    assert memory.selected_memory() is None and selected_workload() is None
    assert len(middleware) == 1

    async def receive():
        pytest.fail("entry admission must happen before body reads")

    async def send(value):
        responses.append(value)

    scope = dict(
        type="http", method="POST", path="/native-intake", headers=[(b"content-length", b"0")]
    )
    await middleware[0](scope, receive, send)
    assert entered == ["/native-intake"] and responses[0]["status"] == 200
    responses.clear()
    scope["headers"] = [
        (
            b"content-length",
            str(workload_bytes := body["bounds"]["maximum_input_bytes"] + 1).encode(),
        )
    ]
    assert workload_bytes > 0
    await middleware[0](scope, receive, send)
    assert entered == ["/native-intake"] and responses[0]["status"] == 503
    assert selected_workload() is None and memory.selected_memory() is None


@pytest.mark.parametrize("actual_runtime", [None, "f" * 64])
def test_joint_runtime_requires_actual_configured_evaluation_identity(joint, actual_runtime):
    with (
        pytest.raises(ValueError, match="actual evaluation runtime"),
        memory.memory_runtime(
            joint.selection,
            maximum_aggregate_bytes=4 * GIB,
            role="phase_reviewer",
            protocol_policy_sha256=digest(joint.policy),
            evaluation_runtime_sha256=actual_runtime,
        ),
    ):
        pytest.fail("self-bound profile runtime is not the configured runtime")


def test_adaptive_expansion_refuses_joint_before_creating_any_slot(joint):
    from umi.host_model_lane_cli import prepare_lane_policy

    root = Path(joint.body["directory"])
    before = {path.name: path.stat().st_ino for path in root.iterdir()}
    with pytest.raises(ValueError, match="fixed single transient lane"):
        prepare_lane_policy(
            joint.selection,
            joint.runtime,
            None,
            output_policy=root / "must-not-exist.json",
            qualification_sha256="a" * 64,
        )
    assert {path.name: path.stat().st_ino for path in root.iterdir()} == before


@pytest.mark.parametrize("bad", ["minimum", "extra_slot", "repeated_inode", "roots", "roles"])
def test_joint_policy_refuses_ambiguous_or_under_reserved_selection(joint, bad):
    body = json.loads(json.dumps(joint.body))
    if bad == "minimum":
        body["minimum_available_bytes"] = 4 * GIB - 1
    elif bad == "extra_slot":
        body["slots"].append(body["slots"][1])
    elif bad == "repeated_inode":
        body["slots"][1]["inode"] = body["slots"][0]["inode"]
    elif bad == "roots":
        body["container_cgroupfs_roots"] = body["container_cgroup_roots"]
    else:
        body["slots"][2]["settlement_role"] = "reviewer"
    with pytest.raises(ValueError):
        ExecutionMemoryPolicy.model_validate(body)


@pytest.fixture(params=["systemd", "cgroupfs"])
def orphan(joint, tmp_path, monkeypatch, request):
    # Only this synthetic fixture bypasses kernel-filesystem detection. The
    # production policy still requires canonical selected cgroup2 roots.
    root = tmp_path / "kernel-container-view"
    root.mkdir()
    cid = "a" * 64
    target = root / ("libpod-" + cid)
    key = "container_cgroupfs_roots"
    if request.param == "systemd":
        target = root / ("libpod-" + cid + ".scope") / "container"
        key = "container_cgroup_roots"
    graph, model = joint.graph(), joint.model()
    for controller in (graph, model.controller):
        controller.policy = controller.policy.model_copy(update={key: (str(root),)})
    monkeypatch.setattr(native, "_require_cgroup2", lambda descriptor: None)

    def start():
        target.mkdir(parents=True)
        (target / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        (target / "memory.max").write_text(str(8 * GIB))

    def drain():
        (target / "cgroup.events").write_text("populated 0\nfrozen 0\n")

    return SimpleNamespace(
        graph=graph, model=model, start=start, drain=drain, target=target, cid=cid
    )


def test_released_owner_leaves_orphan_hold_even_with_spare_ram(orphan, monkeypatch):
    model = orphan.model.controller
    lease = model.try_acquire_group("transient", 1)
    assert lease is not None
    orphan.start()
    assert model.bind_model_container(lease, orphan.cid, orphan.target)
    lease.close()  # Process death releases these same kernel-owned descriptors.
    monkeypatch.setattr(native, "_available_memory", lambda: 100 * GIB)
    for controller, acquire in (
        (orphan.graph, lambda: orphan.graph.try_acquire("transient")),
        (model, lambda: model.try_acquire_group("transient", 1)),
    ):
        assert acquire() is None
        assert controller.last_model_admission["exclusive_orphan_hold"]
        assert controller.last_model_admission["orphan_container_count"] == 1
        assert controller.last_model_admission["unreserved_container_bytes"] == 8 * GIB
        assert controller.last_model_admission["owned_container_credit_bytes"] == 0
    orphan.drain()
    resumed = orphan.graph.try_acquire("transient")
    assert resumed is not None
    resumed.close()


def test_independent_lanes_charge_full_orphan_ceiling(orphan, monkeypatch):
    orphan.start()
    monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB - 1)
    assert orphan.graph.try_acquire("owner_export") is None
    assert orphan.graph.last_model_admission["required_available_bytes"] == 14 * GIB
    assert orphan.graph.try_settlement("0" * 64, "coordinator") is None
    assert orphan.graph.last_model_admission["required_available_bytes"] == 16 * GIB
    monkeypatch.setattr(native, "_available_memory", lambda: 32 * GIB)
    owner = orphan.graph.try_acquire("owner_export")
    retained = orphan.graph.try_settlement("0" * 64, "coordinator")
    assert owner is not None and retained is not None
    owner.close()
    retained.close()


@pytest.mark.parametrize("missing", ["memory.max", "cgroup.events", "population", "unlimited"])
def test_unknown_container_metadata_cannot_disappear_from_joint_accounting(orphan, missing):
    orphan.start()
    if missing in {"memory.max", "cgroup.events"}:
        (orphan.target / missing).unlink()
    elif missing == "population":
        (orphan.target / "cgroup.events").write_text("populated unknown\nfrozen 0\n")
    else:
        (orphan.target / "memory.max").write_text("max")
    with pytest.raises(native.AdmissionBindingError):
        orphan.graph.try_acquire("transient")
    with pytest.raises(native.AdmissionBindingError):
        orphan.model.controller.try_acquire_group("transient", 1)


def test_deleted_container_metadata_race_only_releases_an_absent_target(orphan, monkeypatch):
    import shutil

    orphan.start()
    original = native._cgroup_value
    removed = False

    def vanished(descriptor, name):
        nonlocal removed
        if not removed:
            shutil.rmtree(orphan.target)
            removed = True
        return original(descriptor, name)

    monkeypatch.setattr(native, "_cgroup_value", vanished)
    lease = orphan.graph.try_acquire("transient")
    assert lease is not None and removed
    lease.close()


async def test_orphan_wait_reports_scope_and_cancel_does_not_acquire_later(orphan, caplog):
    caplog.set_level("INFO", logger="umi.competition.progress")
    orphan.start()
    task = asyncio.create_task(orphan.graph.acquire("transient"))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    observations = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "umi.competition.progress"
    ]
    assert len(observations) == 1
    row = observations[0]
    assert row["status"] == "waiting" and row["orphan_container_count"] == 1
    assert row["completed"] == 0 and row["total"] == 1
    assert row["eta_seconds"] is None
    assert row["eta_basis"] == "awaiting_native_model_container_cleanup"
    orphan.drain()
    resumed = orphan.graph.try_acquire("transient")
    assert resumed is not None
    resumed.close()


def test_parent_process_death_does_not_release_a_live_container_into_graph_capacity(orphan):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            lease = orphan.model.controller.try_acquire_group("transient", 1)
            assert lease is not None
            orphan.start()
            assert orphan.model.controller.bind_model_container(lease, orphan.cid, orphan.target)
            os.write(write_fd, b"bound")
            os._exit(0)  # No Python context exits or native model cleanup.
        except BaseException:
            os._exit(1)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 5) == b"bound"
        assert os.waitpid(pid, 0)[1] == 0
    finally:
        os.close(read_fd)
    assert orphan.graph.try_acquire("transient") is None
    assert orphan.graph.last_model_admission["exclusive_orphan_hold"]
    orphan.drain()
    recovered = orphan.graph.try_acquire("transient")
    assert recovered is not None
    recovered.close()


@pytest.mark.parametrize("model_first", [False, True])
async def test_same_task_cross_runtime_nesting_refuses_without_waiting(joint, model_first):
    model = joint.model()
    with memory.memory_runtime(
        joint.selection,
        maximum_aggregate_bytes=4 * GIB,
        role="phase_reviewer",
        protocol_policy_sha256=digest(joint.policy),
        evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
    ):

        def graph():
            return memory.memory_operation_context(operation=None)

        first = model.hold(joint.runtime) if model_first else graph()
        second = graph() if model_first else model.hold(joint.runtime)
        async with first:
            with pytest.raises(RuntimeError, match=r"own.*capacity"):
                async with second:
                    pytest.fail("joint nesting must never acquire twice")
        async with model.invocation(joint.runtime), model.invocation(joint.runtime):
            pass  # Existing native same-task invocation reuse is supported.


@pytest.mark.parametrize("model_first", [False, True])
async def test_cross_runtime_inherited_child_refuses_parent_capacity_dependency(joint, model_first):
    model = joint.model()
    with memory.memory_runtime(
        joint.selection,
        maximum_aggregate_bytes=4 * GIB,
        role="phase_reviewer",
        protocol_policy_sha256=digest(joint.policy),
        evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
    ):

        def graph():
            return memory.memory_operation_context(operation=None)

        async def child():
            async with graph() if model_first else model.hold(joint.runtime):
                pytest.fail("child must not wait for capacity held by its awaiting parent")

        async with model.hold(joint.runtime) if model_first else graph():
            with pytest.raises(RuntimeError, match=r"own.*capacity"):
                await asyncio.wait_for(asyncio.create_task(child()), 1)


@pytest.mark.parametrize("model_first", [False, True])
async def test_unrelated_cross_runtime_task_contends_and_cancels_cleanly(joint, model_first):
    model = joint.model()
    entered = asyncio.Event()
    start = asyncio.Event()
    with memory.memory_runtime(
        joint.selection,
        maximum_aggregate_bytes=4 * GIB,
        role="phase_reviewer",
        protocol_policy_sha256=digest(joint.policy),
        evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
    ):

        def graph():
            return memory.memory_operation_context(operation=None)

        async def child():
            await start.wait()
            async with graph() if model_first else model.hold(joint.runtime):
                entered.set()

        # Born before either lease, this task has no inherited capacity dependency.
        task = asyncio.create_task(child())
        async with model.hold(joint.runtime) if model_first else graph():
            start.set()
            await asyncio.sleep(0)
            assert not entered.is_set() and not task.done()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        await child()
        assert entered.is_set()


@pytest.mark.parametrize("model_first", [False, True])
async def test_forked_child_refuses_its_inherited_live_capacity_descriptor(joint, model_first):
    model = joint.model()
    with memory.memory_runtime(
        joint.selection,
        maximum_aggregate_bytes=4 * GIB,
        role="phase_reviewer",
        protocol_policy_sha256=digest(joint.policy),
        evaluation_runtime_sha256=joint.policy.evaluation_runtime_sha256,
    ):

        def graph():
            return memory.memory_operation_context(operation=None)

        async def opposite():
            try:
                async with graph() if model_first else model.hold(joint.runtime):
                    return False
            except RuntimeError as error:
                return "own" in str(error) and "capacity" in str(error)

        async def bounded():
            return await asyncio.wait_for(opposite(), 1)

        async with model.hold(joint.runtime) if model_first else graph():
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    refused = asyncio.run(bounded())
                    os.write(write_fd, b"refused" if refused else b"acquired")
                    os._exit(0 if refused else 1)
                except BaseException:
                    os._exit(1)
            os.close(write_fd)
            try:
                response = os.read(read_fd, 8)
                _, status = os.waitpid(pid, 0)
                assert response == b"refused" and status == 0
            finally:
                os.close(read_fd)


def test_model_worker_reattaches_without_recharging_idle_startup_slots(joint, monkeypatch):
    parent = joint.model()
    monkeypatch.setattr(native, "_available_memory", lambda: 0)
    worker = ModelExecutionAdmission(joint.selection, joint.policy, reattach_worker=True)
    assert worker.controller.policy_sha256 == parent.controller.policy_sha256
    assert worker.controller.policy.minimum_available_bytes == 4 * GIB
    assert worker.controller.try_acquire_group("transient", 1) is None
    # The selected per-invocation envelope still has its exact reserve floor.
    monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB - 1)
    assert worker.controller.try_acquire_group("transient", 1) is None
    monkeypatch.setattr(native, "_available_memory", lambda: 13 * GIB)
    lease = worker.controller.try_acquire_group("transient", 1)
    assert lease is not None
    try:
        assert parent.controller.try_acquire_group("transient", 1) is None
    finally:
        lease.close()
    # Ordinary startup retains its original complete-envelope requirement.
    with pytest.raises(OSError, match="startup"):
        joint.model()


def test_worker_reattachment_preserves_selected_hash_and_busy_reservations(joint, monkeypatch):
    parent = joint.model()
    held = parent.controller.try_settlement("1".zfill(64), "coordinator")
    assert held is not None
    try:
        monkeypatch.setattr(native, "_available_memory", lambda: 16 * GIB - 1)
        worker = ModelExecutionAdmission(joint.selection, joint.policy, reattach_worker=True)
        assert worker.controller.try_acquire_group("transient", 1) is None
        changed = joint.selection.model_copy(update={"policy_sha256": "ab" * 32})
        with pytest.raises(native.AdmissionBindingError, match="differs from selection"):
            ModelExecutionAdmission(changed, joint.policy, reattach_worker=True)
    finally:
        held.close()


def test_worker_reattachment_refuses_graph_only_policy(provisioned):
    _, path, _, _, expected = provisioned
    with pytest.raises(native.AdmissionBindingError, match="model execution admission"):
        native.HostMemoryAdmission(path, expected_sha256=expected, _reattach_model_worker=True)


def test_startup_probe_remeasures_exact_native_envelope_without_leases(joint, monkeypatch, caplog):
    required = 20 * GIB
    monkeypatch.setattr(native, "_available_memory", lambda: required - 17)
    with pytest.raises(native.HostMemoryStartupPending) as caught:
        joint.graph()
    row = caught.value.observation
    assert row["required_available_bytes"] == required
    assert row["available_bytes"] == required - 17
    assert row["shortfall_bytes"] == 17
    assert row["reserved_bytes"] == 15 * GIB
    assert row["minimum_available_bytes"] == 4 * GIB
    assert row["background_reservation_bytes"] == GIB
    assert row["stalled_or_retrying"] and row["eta_seconds"] is None
    assert row["elapsed_seconds"] >= 0 and row["observed_unix_ms"] > 0
    assert not row["capacity_reserved"]
    emitted = json.loads(caplog.records[-1].message)
    assert emitted == row
    assert joint.selection.policy_path not in caplog.text

    def no_grant(*args, **kwargs):
        raise AssertionError("startup probe must not acquire a runtime lease")

    monkeypatch.setattr(native.HostMemoryAdmission, "try_acquire", no_grant)
    assert memory.probe_memory_startup(joint.selection)["status"] == "capacity_required"
    monkeypatch.setattr(native, "_available_memory", lambda: required)
    ready = memory.probe_memory_startup(joint.selection)
    assert ready["status"] == "admitted" and ready["shortfall_bytes"] == 0
    assert ready["completed"] == ready["total"] == required and ready["eta_seconds"] == 0
    monkeypatch.setattr(native, "_available_memory", lambda: required - 1)
    assert memory.probe_memory_startup(joint.selection)["shortfall_bytes"] == 1


def test_startup_probe_does_not_hide_invalid_bindings_as_capacity_wait(joint, monkeypatch):
    monkeypatch.setattr(native, "_available_memory", lambda: 0)
    changed = joint.selection.model_copy(update={"policy_sha256": "f" * 64})
    with pytest.raises(native.AdmissionBindingError, match="differs"):
        memory.probe_memory_startup(changed)


def test_startup_reporting_failure_preserves_native_stop(joint, monkeypatch):
    import logging

    monkeypatch.setattr(native, "_available_memory", lambda: 0)

    def failed(*args, **kwargs):
        raise OSError("diagnostic output unavailable")

    monkeypatch.setattr(logging.getLogger("umi.competition.progress"), "warning", failed)
    with pytest.raises(native.HostMemoryStartupPending, match="qualified headroom") as caught:
        joint.graph()
    assert caught.value.observation["shortfall_bytes"] == 20 * GIB


@pytest.fixture
def parallel_joint(joint, provisioned):
    from umi.host_execution_memory import expanded_execution_policy

    root, _, _, write, _ = provisioned
    path = root / "parallel-model.slot"
    path.write_bytes(b"")
    path.chmod(0o440)
    info = path.stat()
    added = native.HostMemorySlot(
        name=path.name,
        lane="transient",
        device=info.st_dev,
        inode=info.st_ino,
        reservation_bytes=8 * GIB,
    )
    before = ExecutionMemoryPolicy.model_validate_json(json.dumps(joint.body))
    after = expanded_execution_policy(before, [added], qualification_sha256="b" * 64)
    joint.selection = joint.selection.model_copy(
        update={"policy_sha256": write(after.model_dump(mode="json", by_alias=True))}
    )
    joint.body = after.model_dump(mode="json", by_alias=True)
    joint.graph = lambda: native.HostMemoryAdmission(
        Path(joint.selection.policy_path), expected_sha256=joint.selection.policy_sha256
    )
    joint.model = lambda: ModelExecutionAdmission(joint.selection, joint.policy)
    return joint, before, after


def test_parallel_joint_preserves_original_locks_and_old_schema(parallel_joint):
    _, before, after = parallel_joint
    assert after.slots[:-1] == before.slots
    for field in type(before).model_fields:
        if field not in {"schema_", "slots", "incremental_budget_bytes", "qualification_sha256"}:
            assert getattr(before, field) == getattr(after, field)
    assert after.incremental_budget_bytes == after.reserved_bytes == 23 * GIB
    raw = after.model_dump(mode="json", by_alias=True)
    raw["schema"] = "umi-host-execution-memory-admission/1"
    with pytest.raises(ValueError, match="legacy joint execution"):
        ExecutionMemoryPolicy.model_validate_json(json.dumps(raw))


@pytest.mark.skipif(sys.platform != "linux", reason="joint /2 uses native Linux OFD witnesses")
def test_parallel_joint_reconstructed_controllers_share_all_slots(parallel_joint):
    joint, _, _ = parallel_joint
    first, second, third = joint.graph(), joint.model(), joint.graph()
    assert len(second.slots) == 2
    graph_job = first.try_acquire("transient")
    assert graph_job is not None
    model_job = second.controller.try_acquire_group("transient", 1)
    assert model_job is not None
    assert third.try_acquire("transient") is None
    owner = third.try_acquire("owner_export")
    assert owner is not None
    owner.close()
    model_job.close()
    resumed = third.try_acquire("transient")
    assert resumed is not None
    resumed.close()
    graph_job.close()


@pytest.mark.skipif(sys.platform != "linux", reason="joint /2 uses native Linux OFD witnesses")
def test_parallel_joint_charges_startup_and_pending_work(parallel_joint, monkeypatch):
    joint, _, _ = parallel_joint
    monkeypatch.setattr(native, "_available_memory", lambda: 28 * GIB - 1)
    with pytest.raises(native.HostMemoryStartupPending):
        joint.graph()
    monkeypatch.setattr(native, "_available_memory", lambda: 28 * GIB)
    first, second = joint.graph(), joint.graph()
    held = first.try_acquire("transient")
    assert held is not None
    monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB - 1)
    assert second.try_acquire("transient") is None
    assert second.last_model_admission["pending_reservation_bytes"] == 16 * GIB
    monkeypatch.setattr(native, "_available_memory", lambda: 21 * GIB)
    another = second.try_acquire("transient")
    assert another is not None
    another.close()
    held.close()


@pytest.mark.parametrize("change", ["reservation", "lane", "duplicate", "budget"])
def test_parallel_joint_refuses_invalid_expansion(parallel_joint, change):
    joint, _, _ = parallel_joint
    raw = json.loads(json.dumps(joint.body))
    if change == "reservation":
        raw["slots"][-1]["reservation_bytes"] -= 1
    elif change == "lane":
        raw["slots"][-1]["lane"] = "owner_export"
    elif change == "duplicate":
        raw["slots"][-1] = raw["slots"][1]
    else:
        raw["incremental_budget_bytes"] -= 1
    with pytest.raises(ValueError):
        ExecutionMemoryPolicy.model_validate_json(json.dumps(raw))


@pytest.mark.skipif(sys.platform != "linux", reason="joint /2 uses native Linux OFD witnesses")
def test_parallel_joint_keeps_orphan_stop_even_with_another_free_slot(parallel_joint, monkeypatch):
    joint, _, _ = parallel_joint
    controller = joint.graph()

    original_scan = controller._model_container_reservations

    def retained_orphan(busy, *, residency=None):
        assert not busy
        controller.last_model_admission = dict(populated_containers=1)
        return 8 * GIB

    monkeypatch.setattr(controller, "_model_container_reservations", retained_orphan)
    assert controller.try_acquire("transient") is None
    assert controller.last_model_admission["exclusive_orphan_hold"] is True
    assert controller.last_model_admission["orphan_container_count"] == 1
    monkeypatch.setattr(controller, "_model_container_reservations", original_scan)
    jobs = [controller.try_acquire("transient") for _ in range(2)]
    assert all(jobs)
    for job in jobs:
        job.close()


@pytest.mark.skipif(sys.platform != "linux", reason="joint /2 uses native Linux OFD witnesses")
async def test_parallel_joint_cancellation_releases_only_its_own_slot(parallel_joint):
    joint, _, _ = parallel_joint
    controller, other = joint.graph(), joint.graph()
    held = controller.try_acquire("transient")
    entered = asyncio.Event()

    async def second():
        async with other.hold("transient"):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(second())
    await asyncio.wait_for(entered.wait(), 2)
    assert controller.try_acquire("transient") is None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    resumed = controller.try_acquire("transient")
    assert resumed is not None
    assert controller.try_acquire("transient") is None
    resumed.close()
    held.close()
