"""C5 stage isolation with tiny private fixtures; no native RSS qualification."""

import json
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from tests.test_host_memory_admission import Exporter, SmallRequest, request, send_response
from tests.test_host_memory_admission import provisioned as provisioned
from umi import host_memory_admission as admission
from umi import host_memory_runtime as runtime
from umi.competition_cohort_review_http import phase_review_routes
from umi.host_memory_request_bounds import check_stage_json
from umi.host_memory_requests import C5, OPERATIONS, RequestsStageMemoryPolicy


@pytest.fixture
def stage(provisioned):
    _, path, policy, write, _ = provisioned
    policy.pop("settlement_gate")
    policy.pop("settlement_signals")
    policy.update(
        schema="umi-c5-requests-memory-admission/1",
        cohort_sha256=C5,
        protocol_policy_sha256="1" * 64,
        series_sha256="2" * 64,
        authority_sha256="3" * 64,
        preparation_result_sha256="4" * 64,
        background_reservation_bytes=1024,
        operations=list(OPERATIONS),
        slots=policy["slots"][:2],
        bounds=dict(
            maximum_records=2,
            maximum_objects=3,
            maximum_services=2,
            maximum_orders=2,
            maximum_inventory_entries=2,
            maximum_participants=2,
            maximum_catalogs=2,
            maximum_input_bytes=1024 * 1024,
            maximum_object_bytes=16384,
            maximum_declaration_bytes=65536,
            maximum_json_values=128,
            maximum_json_depth=8,
        ),
    )
    pinned = write()
    controller = admission.HostMemoryAdmission(path, expected_sha256=pinned)
    return controller, policy, write, path


@contextmanager
def bind(stage):
    token = runtime._selected.set(stage[0])
    try:
        yield stage[0]
    finally:
        runtime._selected.reset(token)


@pytest.mark.parametrize("role", [None, "settlement", "reward_coordinator", "reward_writer"])
def test_stage_rejects_unqualified_boot_roles(stage, role):
    controller, _, _, path = stage
    selection = runtime.HostMemoryAdmissionSelection(
        policy_path=str(path),
        policy_sha256=controller.policy_sha256,
    )
    with (
        pytest.raises(ValueError, match="runtime identity"),
        runtime.memory_runtime(
            selection,
            maximum_aggregate_bytes=1024,
            role=role,
            protocol_policy_sha256="1" * 64,
            series_sha256="2" * 64,
            authority_sha256="3" * 64,
        ),
    ):
        pytest.fail("unqualified boot entered")


def test_boot_exact_identity_and_two_measured_lanes(stage):
    controller = stage[0]
    controller.bind_runtime("intake", "1" * 64, "2" * 64, "3" * 64)
    controller.bind_runtime("phase_reviewer", "1" * 64, "2" * 64, "3" * 64)
    with pytest.raises(ValueError):
        controller.bind_runtime("intake", "1" * 64, "2" * 64, "0" * 64)
    with pytest.raises(ValueError, match="settlement"):
        controller.try_settlement(C5, "coordinator")


@pytest.mark.parametrize(
    "field,value",
    [
        ("cohort_sha256", "0" * 64),
        ("background_reservation_bytes", 0),
        ("operations", ["requests_export"]),
        ("operations", ["preparation_republish", "fresh_preparation"]),
    ],
)
def test_policy_cannot_infer_extra_qualification(stage, field, value):
    policy = dict(stage[1], **{field: value})
    with pytest.raises(ValueError):
        RequestsStageMemoryPolicy.model_validate(policy)


@pytest.mark.parametrize(
    "operation,cohort,phase",
    [
        (None, C5, "requests"),
        ("requests_review", "0" * 64, "requests"),
        ("requests_review", C5, "preparation"),
        ("terminal_export", C5, "requests"),
    ],
)
async def test_refusal_precedes_waiting_and_callback(stage, monkeypatch, operation, cohort, phase):
    controller = stage[0]
    called = []

    async def forbidden(*args, **kwargs):
        called.append("wait")
        pytest.fail("unqualified work waited for capacity")

    monkeypatch.setattr(controller, "acquire", forbidden)

    @runtime.memory_operation(operation=operation, scope=lambda: (cohort, phase))
    async def callback():
        called.append("callback")

    with bind(stage), pytest.raises(ValueError, match="outside"):
        await callback()
    assert called == []


async def test_scoped_request_and_retained_preparation_release_capacity(stage):
    with bind(stage) as controller:
        for operation, phase in [
            ("requests_review", "requests"),
            ("preparation_republish", "preparation"),
        ]:

            @runtime.memory_operation(operation=operation, scope=lambda: (C5, phase))
            async def callback():
                assert runtime._active.get() is not None
                return 7

            assert await callback() == 7
            lease = controller.try_acquire("transient", operation=operation, cohort=C5, phase=phase)
            assert lease is not None
            lease.close()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"records":[0,0,0]}',
        b'{"\\u0072ecords":[0,0,0]}',
        b'{"outer":{"records":[{}, {}, {}]}}',
        b'{"participants":[[],[],[]]}',
        b"[" * 9 + b"0" + b"]" * 9,
        b"[" + b"0," * 130 + b"0]",
        b'{"records":[0,0,0],"records":[]}',
        b'{"records":[0,0,0]',
        b'{"records" []}',
        b'"' + b"\\" * 15000,
    ],
)
def test_shape_refuses_before_decode(stage, raw):
    with bind(stage), pytest.raises(ValueError):
        check_stage_json(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"records":[{"x":"a\\"b"},{}]}',
        b'{"records":[],"services":[1,2]}',
        b'{"nested":{"participants":[0,0]},"long":"' + b"a" * 10000 + b'"}',
        b"null",
        b"[]",
        b"{}",
    ],
)
def test_shape_allows_native_validation_of_bounded_json(stage, raw):
    with bind(stage):
        check_stage_json(raw)
        json.loads(raw)


def test_collector_refuses_count_before_loading_next_object(stage):
    from umi.competition_cohort_reward_package import ReplayObjectCollector

    seen = []
    collector = ReplayObjectCollector(lambda key: seen.append(key), 1024)
    collector.values = {str(i): b"null" for i in range(3)}
    with bind(stage), pytest.raises(ValueError, match="maximum_objects"):
        collector("a" * 64)
    assert not seen


async def test_http_export_owns_stage_lease_through_send(stage):
    controller = stage[0]
    exporter = Exporter()
    router = phase_review_routes(
        exporter,
        token="s" * 32,
        path="/export",
        request_model=SmallRequest,
        admission=controller,
        admission_lane="owner_export",
        admission_operation="requests_export",
        admission_scope=lambda _: (C5, "requests"),
    )
    response = await router.routes[0].endpoint(request())

    async def send(message):
        assert (
            controller.try_acquire(
                "owner_export", operation="requests_export", cohort=C5, phase="requests"
            )
            is None
        )

    await send_response(response, send)
    lease = controller.try_acquire(
        "owner_export", operation="requests_export", cohort=C5, phase="requests"
    )
    assert lease is not None
    lease.close()


async def test_unnamed_owner_export_is_refused_before_exporter(stage):
    exporter = Exporter()
    router = phase_review_routes(
        exporter,
        token="s" * 32,
        path="/export",
        request_model=SmallRequest,
        admission=stage[0],
        admission_lane="owner_export",
    )
    with pytest.raises(HTTPException) as failure:
        await router.routes[0].endpoint(request())
    assert failure.value.status_code == 503
    assert exporter.calls == 0


async def test_lifecycle_denies_other_cohorts_before_history_or_factory(stage):
    from umi.competition_cohort_lifecycle import CohortLifecycleService
    from umi.competition_cohort_lifecycle_host import LifecycleHost

    with bind(stage), pytest.raises(ValueError):
        await LifecycleHost.node(object(), "0" * 64)
    with bind(stage), pytest.raises(ValueError):
        await CohortLifecycleService._sample(
            object(), SimpleNamespace(cohort_sha256=C5, phase="preparation"), object()
        )


async def test_fresh_preparation_and_publication_denied_before_owner(stage):
    from umi.competition_cohort_preparation_owner import CohortPreparation
    from umi.competition_cohort_preparation_publisher import CohortPreparationPublisher

    with bind(stage), pytest.raises(ValueError):
        CohortPreparation.prepare(object(), C5, object(), expected_tip_sha256="0" * 64)
    with bind(stage), pytest.raises(ValueError):
        await CohortPreparationPublisher.poll_once(object())


async def test_retained_preparation_republication_is_allowed_and_leased(stage, monkeypatch):
    from umi import competition_cohort_preparation_publisher as module

    history = SimpleNamespace(plan=object())
    prepared = SimpleNamespace(roster=SimpleNamespace(round=object()))
    calls = []

    class Intake:
        def history(self, cohort):
            assert cohort == C5
            return history

    class Owner:
        queue = SimpleNamespace(intake=Intake(), policy=object())

        def retained(self, cohort, **kwargs):
            assert runtime._active.get() is not None
            assert cohort == C5
            calls.append("retained")
            return prepared

        def prepare(self, *args, **kwargs):
            pytest.fail("retained publication started fresh preparation")

    class Provider:
        def ensure_observer_running(self):
            pass

        async def current_finalized_block(self):
            return 1

    publisher = object.__new__(module.CohortPreparationPublisher)
    publisher.owner, publisher.provider = Owner(), Provider()

    async def publish(cohort, value):
        assert cohort == C5 and value is prepared
        assert runtime._active.get() is not None
        calls.append("published")

    publisher._publish_prepared = publish
    monkeypatch.setattr(module, "digest", lambda value: C5 if value is history.plan else "4" * 64)
    monkeypatch.setattr(module, "history_tip", lambda _: "0" * 64)
    monkeypatch.setattr(
        module,
        "verify_cohort_history",
        lambda *a, **kw: SimpleNamespace(state=SimpleNamespace(phase="requests")),
    )
    with bind(stage):
        await publisher.publish_history(history)
    assert calls == ["retained", "published"]


async def test_decision_mismatch_is_refused_before_selecting_reviewer(stage):
    from umi.competition_cohort_review_selection import SelectedPhaseReviewer

    transition = SimpleNamespace(cohort_sha256=C5, phase="requests")
    evidence = SimpleNamespace(
        progress=SimpleNamespace(progress=SimpleNamespace(cohort_sha256="0" * 64, phase="requests"))
    )
    with bind(stage), pytest.raises(ValueError, match="scope differs"):
        await SelectedPhaseReviewer.decision(object(), transition, evidence)


async def test_stage_only_guard_preserves_full_policy_callback(provisioned):
    from tests.test_host_memory_runtime import bind as full_bind

    @runtime.memory_operation(operation="preparation_republish", requests_stage_only=True)
    async def callback():
        assert runtime._active.get() is None
        return 1

    with full_bind(provisioned):
        assert await callback() == 1


@pytest.mark.parametrize("name", ["records", "objects", "services"])
def test_wire_elements_have_byte_bounds_before_graph_decode(stage, name):
    raw = json.dumps({name: [{"value": "x" * 16384}]}).encode()
    with bind(stage), pytest.raises(ValueError, match="element"):
        check_stage_json(raw)


def test_shared_declaration_budget_rejects_next_read_before_decode(stage, tmp_path):
    from umi.host_memory_request_bounds import bounded_stage_declarations
    from umi.private_files import read_private_model
    from umi.protocol import StrictProtocolModel

    class Declaration(StrictProtocolModel):
        value: str

    root = tmp_path / "declarations"
    root.mkdir(mode=0o700)
    for name in ("a", "b"):
        path = root / (name + ".json")
        path.write_bytes(json.dumps({"value": "x" * 40000}, separators=(",", ":")).encode())
        path.chmod(0o600)
    calls = []

    @bounded_stage_declarations
    def load():
        first = read_private_model(root / "a.json", Declaration)
        calls.append(first)
        read_private_model(root / "b.json", Declaration)

    with bind(stage), pytest.raises(ValueError, match="byte bound"):
        load()
    assert len(calls) == 1


def test_native_journal_checks_size_before_blob_or_canonical_decode(stage):
    from umi.competition_round_journal import RoundJournal

    class NativeOwnerConnection:
        def execute(self, sql, args):
            assert sql.startswith("SELECT length(body)")
            return SimpleNamespace(fetchone=lambda: (16385,))

    journal = SimpleNamespace(maximum_record_bytes=1024 * 1024)
    with bind(stage), pytest.raises(ValueError, match="byte bound"):
        RoundJournal._record(journal, NativeOwnerConnection(), "endpoint_replay_object", "x")


async def test_explicit_asgi_binding_covers_lifespan_children_and_sibling_http(stage):
    import asyncio

    seen = []

    async def application(scope, receive, send):
        assert runtime.selected_memory() is stage[0]
        if scope["type"] == "lifespan":

            async def child():
                seen.append(("child", runtime.selected_memory()))

            await asyncio.create_task(child())
        else:
            seen.append(("http", runtime.selected_memory()))

    async def unused(*args):
        pytest.fail("unexpected request body or response")

    wrapped = runtime.RequestsStageASGIBinding(
        application, controller=stage[0], private_role="intake"
    )
    assert runtime.selected_memory() is None
    await asyncio.gather(
        wrapped({"type": "lifespan"}, unused, unused),
        wrapped(
            {"type": "http", "method": "POST", "path": "/internal/cohorts/request-review"},
            unused,
            unused,
        ),
    )
    assert sorted(name for name, _ in seen) == ["child", "http"]
    assert all(controller is stage[0] for _, controller in seen)
    assert runtime.selected_memory() is None


@pytest.mark.parametrize(
    "private_role,path",
    [
        (None, "/v1/competition/submissions"),
        ("intake", "/internal/cohorts/window"),
        ("phase_reviewer", "/internal/cohorts/preparation/votes/progress"),
    ],
)
async def test_stage_http_refuses_unqualified_body_before_receive(stage, private_role, path):
    messages = []

    async def forbidden(*args):
        pytest.fail("unqualified ASGI operation consumed body or ran handler")

    async def send(message):
        messages.append(message)

    wrapped = runtime.RequestsStageASGIBinding(
        forbidden, controller=stage[0], private_role=private_role
    )
    await wrapped({"type": "http", "method": "POST", "path": path}, forbidden, send)
    assert messages[0]["status"] == 503


@pytest.mark.parametrize(
    "role,path",
    [
        ("intake", "/internal/cohorts/request-review"),
        ("phase_reviewer", "/internal/cohorts/requests/votes/progress"),
        ("phase_reviewer", "/internal/cohorts/requests/votes/decision"),
    ],
)
async def test_stage_private_scope_enters_native_route(stage, role, path):
    seen = []

    async def application(*args):
        seen.append(runtime.selected_memory())

    wrapped = runtime.RequestsStageASGIBinding(application, controller=stage[0], private_role=role)
    await wrapped({"type": "http", "method": "POST", "path": path}, None, None)
    assert seen == [stage[0]]


async def test_stage_allows_only_cached_reviewer_epoch_get_without_admission_work(stage):
    from fastapi import FastAPI

    from umi.competition_cohort_producer_epoch import producer_epoch_routes

    from .test_open_competition import wallet

    app = FastAPI()
    app.include_router(producer_epoch_routes(
        wallet("Charlie").hotkey.ss58_address, token="s" * 32, enabled=True,
    ))
    wrapped = runtime.RequestsStageASGIBinding(
        app, controller=stage[0], private_role="phase_reviewer"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=wrapped), base_url="https://review.example"
    ) as client:
        path = "/internal/cohorts/execution-producer"
        assert (await client.get(path)).status_code == 401
        response = await client.get(path, headers={"authorization": "Bearer " + "s" * 32})
        assert response.status_code == 200
        assert (await client.post(path, json={})).status_code == 503


async def test_no_lane_unknown_route_refuses_before_body_parse(stage):
    exporter = Exporter()
    with bind(stage):
        router = phase_review_routes(
            exporter,
            token="s" * 32,
            path="/window",
            request_model=SmallRequest,
            maximum_request_bytes=16 * 1024**2,
        )
    incoming = request()

    async def forbidden():
        pytest.fail("forbidden private route read its request body")

    incoming._receive = forbidden
    with pytest.raises(HTTPException) as failure:
        await router.routes[0].endpoint(incoming)
    assert failure.value.status_code == 503 and exporter.calls == 0


async def test_stage_holds_service_polling_until_stop_without_work(stage):
    import asyncio

    from umi.competition_cohort_service_host import ServiceAdmissionHost

    stop = asyncio.Event()
    with bind(stage):
        task = asyncio.create_task(ServiceAdmissionHost._poll(object(), stop))
        await asyncio.sleep(0)
        assert not task.done()
        stop.set()
        await task
        with pytest.raises(ValueError):
            await ServiceAdmissionHost._poll_catalogs(object())


def test_operation_shape_budget_accumulates_unique_sources_without_charging_replay(stage):
    from umi.host_memory_request_bounds import stage_evidence_budget

    first = json.dumps(list(range(80))).encode()
    second = json.dumps(list(range(81))).encode()
    with bind(stage), stage_evidence_budget():
        check_stage_json(first)
        for _ in range(10):
            check_stage_json(first)
        with pytest.raises(ValueError, match="value count"):
            check_stage_json(second)
    with bind(stage), stage_evidence_budget():
        check_stage_json(second)


async def test_memory_operation_installs_aggregate_shape_budget(stage):
    @runtime.memory_operation(operation="requests_review", scope=lambda: (C5, "requests"))
    async def callback():
        check_stage_json(json.dumps(list(range(80))).encode())
        check_stage_json(json.dumps(list(range(81))).encode())

    with bind(stage), pytest.raises(ValueError, match="value count"):
        await callback()


@pytest.mark.parametrize(
    "path",
    [
        "/v1/competition/status",
        "/v1/competition/services/catalogs",
        "/v1/competition/cohorts/" + C5 + "/requests/readiness",
        "/v1/competition/cohorts/" + "0" * 64 + "/authority",
    ],
)
async def test_public_reads_are_refused_before_native_graphs(stage, path):
    messages = []

    async def forbidden(*args):
        pytest.fail("unqualified public read entered native code")

    async def send(message):
        messages.append(message)

    wrapped = runtime.RequestsStageASGIBinding(forbidden, controller=stage[0])
    await wrapped({"type": "http", "method": "GET", "path": path}, forbidden, send)
    assert messages[0]["status"] == 503
