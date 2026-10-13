"""Admission integration tests with tiny graphs and no native/live state."""

import asyncio
import threading
import weakref
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from tests.test_competition_cohort_settlement_lifetime import blank, graph
from tests.test_host_memory_admission import provisioned as provisioned
from tests.test_host_memory_admission import selected
from umi import host_memory_admission as admission
from umi import host_memory_runtime as runtime
from umi.concurrency import run_owned_thread
from umi.protocol import StrictProtocolModel


def bind(provisioned, maximum=1024):
    selection = runtime.HostMemoryAdmissionSelection(
        policy_path=str(provisioned[1]), policy_sha256=provisioned[4]
    )
    return runtime.memory_runtime(selection, maximum_aggregate_bytes=maximum)


def test_grants_charge_pending_allocations_and_retained_allocator_rss(provisioned, monkeypatch):
    controller = selected(provisioned)
    floor = controller.policy.minimum_available_bytes
    monkeypatch.setattr(admission, "_available_memory", lambda: floor + 1500)
    reviewer = controller.try_acquire("transient")
    assert reviewer is not None
    # Both grants precede real allocation: a stale sample cannot admit two
    # operations whose combined reservation crosses the floor.
    assert controller.try_acquire("owner_export") is None
    monkeypatch.setattr(admission, "_available_memory", lambda: floor + 2048)
    owner = controller.try_acquire("owner_export")
    assert owner is not None
    owner.close()
    reviewer.close()
    # Logical release does not return an allocator's retained resident pages.
    monkeypatch.setattr(admission, "_available_memory", lambda: floor + 512)
    assert controller.try_acquire("transient") is None
    with pytest.raises(OSError, match="startup"):
        selected(provisioned)


def test_background_budget_and_effective_aggregate_limits_are_explicit(provisioned, monkeypatch):
    _, path, policy, write, _ = provisioned
    policy["background_reservation_bytes"] = 4096
    pinned = write()
    controller = admission.HostMemoryAdmission(path, expected_sha256=pinned)
    monkeypatch.setattr(
        admission, "_available_memory", lambda: policy["minimum_available_bytes"] + 4096
    )
    assert controller.try_acquire("transient") is None
    monkeypatch.setattr(
        admission, "_available_memory", lambda: policy["minimum_available_bytes"] + 100000
    )
    selection = runtime.HostMemoryAdmissionSelection(policy_path=str(path), policy_sha256=pinned)
    with (
        pytest.raises(ValueError, match="aggregate limit"),
        runtime.memory_runtime(
            selection, maximum_aggregate_bytes=policy["maximum_aggregate_bytes"] + 1
        ),
    ):
        raise AssertionError("unsupported capacity selected")


def test_six_cohort_replica_skew_uses_separate_bounded_role_slots(provisioned):
    coordinator, reviewer = selected(provisioned), selected(provisioned)
    for coordinator_index in range(6):
        for reviewer_index in range(6):
            ahead = f"{coordinator_index:064x}"
            behind = f"{reviewer_index:064x}"
            first = coordinator.try_settlement(ahead, "coordinator")
            assert first is not None
            # The restarted reviewer must reconstruct an earlier original
            # while a warm coordinator continues holding a later native graph.
            second = reviewer.try_settlement(behind, "reviewer")
            assert second is not None
            assert coordinator.try_settlement(behind, "coordinator") is None
            assert reviewer.try_settlement(ahead, "reviewer") is None
            first.close()
            restarted = selected(provisioned).try_settlement(behind, "coordinator")
            assert restarted is not None
            restarted.close()
            second.close()
    # A warm terminal coordinator owns no graph or group. A reviewer-only
    # restart must still be able to perform mandatory native reconstruction.
    recovering = reviewer.try_settlement("0" * 64, "reviewer")
    assert recovering is not None
    recovering.close()
    with pytest.raises(ValueError, match="cohort"):
        coordinator.try_settlement("f" * 64, "coordinator")
    with pytest.raises(ValueError, match="role/cohort"):
        coordinator.try_acquire("settlement_retained")


async def test_cohort_phase_rebuild_preserves_lease_and_failure_drops_drained_graph(provisioned):
    node = blank()
    node.cohort = "0" * 64
    node.config = SimpleNamespace(role="coordinator")
    node._memory_admission, node._memory_lease = selected(provisioned), None
    references = []

    async def load(history):
        assert all(ref() is None for ref in references)
        references.append(graph(node))
        if history == "fail":
            raise ValueError("bad native proof")

    node._load_active_inputs = load
    await node._start("first")
    held = node._memory_lease
    assert held is not None and not held.closed
    assert references[0]() is node.data
    await node._start("second")
    assert node._memory_lease is held and not held.closed
    with pytest.raises(ValueError, match="native proof"):
        await node._start("fail")
    assert held.closed and node._memory_lease is None
    assert all(ref() is None for ref in references)
    available = node._memory_admission.try_settlement("1".zfill(64), "coordinator")
    assert available is not None
    available.close()


async def test_cancelled_cohort_loader_drains_before_group_can_change(provisioned):
    node = blank()
    node.cohort = "0" * 64
    node.config = SimpleNamespace(role="coordinator")
    node._memory_admission, node._memory_lease = selected(provisioned), None
    entered, release = threading.Event(), threading.Event()
    references = []

    def work():
        entered.set()
        assert release.wait(10)

    async def load(history):
        references.append(graph(node))
        await run_owned_thread(work)

    node._load_active_inputs = load
    pending = asyncio.create_task(node._start("original"))
    assert await asyncio.to_thread(entered.wait, 5)
    held = node._memory_lease
    pending.cancel()
    await asyncio.sleep(0)
    assert not held.closed and references[0]() is not None
    assert node._memory_admission.try_settlement("1".zfill(64), "coordinator") is None
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert held.closed and references[0]() is None


async def test_complete_operation_drops_worker_validation_graph_before_releasing(provisioned):
    references = []

    class Graph:
        pass

    class Small(StrictProtocolModel):
        value: int

    def native():
        value = Graph()
        references.append(weakref.ref(value))
        Small.model_validate({"value": value})

    with bind(provisioned) as controller:
        with pytest.raises(ValueError, match="aggregate input validation") as failed:
            await runtime.run_memory_thread(native)
        assert failed.value.__cause__ is None and failed.value.__context__ is None
        assert references[0]() is None
        lease = controller.try_acquire("transient")
        assert lease is not None
        lease.close()
    assert runtime.selected_memory() is None


async def test_child_operations_do_not_share_inherited_capacity(provisioned):
    entered, release = asyncio.Event(), asyncio.Event()

    @runtime.memory_operation
    async def child():
        entered.set()
        await release.wait()

    with bind(provisioned) as controller:
        first = asyncio.create_task(child())
        await entered.wait()
        second = asyncio.create_task(child())
        await asyncio.sleep(0)
        assert not second.done() and controller.try_acquire("transient") is None
        release.set()
        await asyncio.wait_for(asyncio.gather(first, second), 2)

    @runtime.memory_operation
    async def nested():
        await asyncio.create_task(child())

    with bind(provisioned), pytest.raises(RuntimeError, match="nested"):
        await nested()


async def test_writer_package_scope_returns_compact_result_before_peer_opportunity(provisioned):
    from umi.competition_reward_executor import StandingRewardExecutor

    references = []

    class Package:
        pass

    with bind(provisioned) as controller:

        def load(key):
            assert controller.try_acquire("transient") is None
            package = Package()
            references.append(weakref.ref(package))
            return package

        async def prepare(package, **kwargs):
            assert references[0]() is package
            return "compact-prepared"

        owner = object.__new__(StandingRewardExecutor)
        owner.packages = load
        owner.preparation = SimpleNamespace(prepare=prepare)
        owner.decisions = object()
        result = await owner._prepare_package(
            SimpleNamespace(package_sha256="original"), "control", "history"
        )
        assert result == "compact-prepared" and references[0]() is None
        lease = controller.try_acquire("transient")
        assert lease is not None  # a subsequent opportunity/peer call can proceed
        lease.close()


async def test_reward_opportunity_runs_before_package_admission(provisioned, monkeypatch):
    from umi import competition_reward_coordinator as module

    async def verified(height):
        return "native-history"

    async def control(provider, height):
        return "native-control"

    monkeypatch.setattr(module, "verify_reward_decision_proposal", lambda *args: args[-1])
    monkeypatch.setattr(
        module, "review_reward_decision", lambda *args, **kwargs: "compact-decision"
    )
    owner = object.__new__(module.StandingRewardDecisionReviewer)
    # Native review is replaced by tiny ports; supply its owner scope explicitly.
    owner.verification_reuse = SimpleNamespace(selected=nullcontext)
    owner.history = SimpleNamespace(verified_prefix=verified, review_control=control)
    owner.provider = object()
    owner.reader = SimpleNamespace(
        series="series",
        policy="policy",
        review_history=lambda *args: SimpleNamespace(
            selection=SimpleNamespace(decision_sha256="predecessor")
        ),
    )
    owner.handoff = object()
    owner.manifest = owner.store = object()
    owner.maximum_promotion_bytes = 1024
    owner.model_artifacts = None
    calls = []

    with bind(provisioned) as controller:

        @runtime.memory_operation
        async def opportunity(activation):
            calls.append("opportunity")
            return "compact-opportunity"

        def package(key):
            assert calls == ["opportunity"]
            assert controller.try_acquire("transient") is None
            calls.append("package")
            return SimpleNamespace()

        owner.opportunity = opportunity
        owner.files = SimpleNamespace(verified_package=package, maximum_package_bytes=1024)
        body = SimpleNamespace(
            observed_at_block=1,
            activation=SimpleNamespace(package_sha256="original"),
            sequence=2,
            predecessor_sha256="predecessor",
        )
        result = await owner.review(body, ())
        assert result == "compact-decision" and calls == ["opportunity", "package"]


def test_omitted_local_selection_preserves_existing_config_serializers():
    from umi.competition_cohort_admission_host import AdmissionOwnerConfig
    from umi.competition_cohort_review_config import PhaseReviewServiceConfig
    from umi.competition_cohort_settlement_config import SettlementServiceConfig
    from umi.competition_reward_boot import StandingRewardBootConfig
    from umi.competition_reward_coordinator_boot import RewardCoordinatorConfig

    for model, method in (
        (AdmissionOwnerConfig, "preserve_legacy"),
        (PhaseReviewServiceConfig, "serialize"),
        (SettlementServiceConfig, "serialize"),
        (StandingRewardBootConfig, "omit_successor_inputs"),
        (RewardCoordinatorConfig, "omit_direct_model_review"),
    ):
        value = model.model_construct()
        result = getattr(value, method)(
            lambda _: {"host_memory_admission": None, "original": "bytes"}
        )
        assert result == {"original": "bytes"}


async def test_review_vote_transport_keeps_owner_export_lane_available(provisioned):
    import httpx
    from fastapi import FastAPI

    from tests.test_competition_cohort_review_http_lifetime import ReviewRequest
    from umi.competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes

    calls = []
    token = "separate-private-credential-" * 2

    with bind(provisioned) as controller:

        class Owner:
            maximum_bytes, timeout_seconds = 1024, 5

            async def respond(self, request):
                assert controller.try_acquire("owner_export") is None
                assert controller.try_acquire("transient") is None
                calls.append("owner")
                return b'{"native_evidence":true}'

        owner_app = FastAPI()
        owner_app.include_router(
            phase_review_routes(
                Owner(),
                token=token,
                path="/export",
                request_model=ReviewRequest,
                admission_lane="owner_export",
            )
        )
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=owner_app)) as client:
            fetch = PhaseReviewHTTPClient(
                client,
                "https://owner.example",
                token=token,
                path="/export",
                maximum_bytes=1024,
                timeout_seconds=5,
            )

            class Reviewer:
                maximum_bytes, timeout_seconds = 1024, 5

                @runtime.memory_operation
                async def respond(self, request):
                    calls.append("reviewer")
                    return await fetch(request)

            reviewer_app = FastAPI()
            reviewer_app.include_router(
                phase_review_routes(
                    Reviewer(),
                    token=token,
                    path="/vote",
                    request_model=ReviewRequest,
                )
            )
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=reviewer_app)) as voting:
                response = await asyncio.wait_for(
                    voting.post(
                        "https://reviewer.example/vote",
                        json={"challenge": "original"},
                        headers={"Authorization": "Bearer " + token},
                    ),
                    2,
                )
            assert response.status_code == 200
            assert response.content == b'{"native_evidence":true}'
        assert calls == ["reviewer", "owner"]
        owner_lease = controller.try_acquire("owner_export")
        reviewer_lease = controller.try_acquire("transient")
        assert owner_lease is not None and reviewer_lease is not None
        owner_lease.close()
        reviewer_lease.close()


@pytest.mark.parametrize("base", [ValueError, OSError, RuntimeError, asyncio.CancelledError])
async def test_operation_error_payloads_and_chains_die_before_release(
    provisioned, monkeypatch, base
):
    references = []
    closes = []

    class Graph:
        pass

    class NativeFailure(base):
        pass

    @runtime.memory_operation
    async def failed():
        graph = Graph()
        references.append(weakref.ref(graph))
        failure = NativeFailure("bounded-reason", graph)
        failure.reason_code = "native_reason"
        failure.graph = graph
        failure.__cause__ = ValueError(graph)
        raise failure

    original_close = admission.HostMemoryLease.close

    def checked_close(lease):
        if not lease.closed:
            closes.append(True)
            assert all(ref() is None for ref in references)
        original_close(lease)

    monkeypatch.setattr(admission.HostMemoryLease, "close", checked_close)
    with bind(provisioned), pytest.raises(NativeFailure) as raised:
        await failed()
    assert closes and raised.value.reason_code == "native_reason"
    assert raised.value.graph is None and raised.value.__context__ is None
    assert all(ref() is None for ref in references)


def test_qualified_conservative_headroom_allows_downstream_owner(provisioned, monkeypatch):
    controller = selected(provisioned)
    reservation = controller.policy.slots[0].reservation_bytes
    available = controller.policy.minimum_available_bytes + 8 * reservation
    monkeypatch.setattr(admission, "_available_memory", lambda: available)
    held = []
    try:
        held.append(controller.try_settlement("0" * 64, "coordinator"))
        available -= reservation
        held.append(controller.try_settlement("0" * 64, "reviewer"))
        available -= reservation
        held.append(controller.try_acquire("transient"))
        available -= reservation
        # Upstream allocations are already resident. Their full reservations
        # are charged again, yet a correctly qualified envelope still admits
        # the downstream owner without asking the waiting reviewer to release.
        held.append(controller.try_acquire("owner_export"))
        assert all(lease is not None for lease in held)
    finally:
        for lease in held:
            if lease is not None:
                lease.close()


async def test_owner_route_captures_selection_at_boot_outside_request_context(provisioned):
    import httpx
    from fastapi import FastAPI

    from tests.test_competition_cohort_review_http_lifetime import ReviewRequest
    from umi.competition_cohort_review_http import phase_review_routes

    with bind(provisioned) as controller:

        class Owner:
            maximum_bytes, timeout_seconds = 1024, 5

            async def respond(self, request):
                assert runtime.selected_memory() is None
                assert controller.try_acquire("owner_export") is None
                return b'{"evidence":true}'

        app = FastAPI()
        app.include_router(
            phase_review_routes(
                Owner(),
                token="owner-credential-" * 4,
                path="/review",
                request_model=ReviewRequest,
                admission_lane="owner_export",
            )
        )
        owner = Owner()
        owner.maximum_bytes = controller.policy.maximum_aggregate_bytes + 1
        with pytest.raises(ValueError, match="qualified host aggregate"):
            phase_review_routes(
                owner,
                token="owner-credential-" * 4,
                path="/review",
                request_model=ReviewRequest,
                admission_lane="owner_export",
            )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        response = await client.post(
            "https://owner.example/review",
            json={"challenge": "original"},
            headers={"Authorization": "Bearer " + "owner-credential-" * 4},
        )
    assert response.status_code == 200 and response.content == b'{"evidence":true}'
    lease = controller.try_acquire("owner_export")
    assert lease is not None
    lease.close()


def test_namespace_host_identity_override_is_explicit_and_validated(provisioned, monkeypatch):
    from pathlib import Path

    original = admission._host_identity
    calls = []

    def identity(path=Path("/etc/machine-id")):
        calls.append(path)
        return original()

    monkeypatch.setattr(admission, "_host_identity", identity)
    selection = runtime.HostMemoryAdmissionSelection(
        policy_path=str(provisioned[1]),
        policy_sha256=provisioned[4],
        host_identity_path="/run/umi-host-machine-id",
    )
    with runtime.memory_runtime(selection, maximum_aggregate_bytes=1024):
        assert calls == [Path("/run/umi-host-machine-id")]
    with pytest.raises(ValueError, match="absolute"):
        runtime.HostMemoryAdmissionSelection(
            policy_path=str(provisioned[1]),
            policy_sha256=provisioned[4],
            host_identity_path="relative-machine-id",
        )


def test_namespace_identity_path_preserves_normal_identity_and_refuses_alias(tmp_path):
    from pathlib import Path

    assert admission._host_identity(Path("/etc/machine-id")) == admission._host_identity()
    with pytest.raises(ValueError, match="absolute"):
        admission._host_identity(Path("relative-machine-id"))
    # A path traversing a symlink is rejected before attempting identity read.
    alias = tmp_path / "alias"
    alias.symlink_to("/etc", target_is_directory=True)
    with pytest.raises((OSError, ValueError)):
        admission._host_identity(alias / "machine-id")
