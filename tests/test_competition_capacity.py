from __future__ import annotations

import asyncio
import socket
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from umi.competition_api import CompetitionApiLimits, create_app
from umi.competition_artifacts import preserve_bundle
from umi.competition_chain import RegistrationCapture
from umi.competition_service import (
    CompetitionServiceConfig,
    RetainedIntakeState,
    create_intake_app,
)
from umi.competition_store import (
    AdmissionCapacity,
    AdmissionCapacityError,
    CompetitionStore,
)
from umi.competition_store_migration_cli import migrate
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_service import public_deployment as public_deployment
from .test_open_competition import bundle_at, snapshot, submission
from .test_open_competition import policy as policy


def capacity(records: int, payload_bytes: int = 10_000_000) -> AdmissionCapacity:
    return AdmissionCapacity(maximum_records=records, maximum_bytes=payload_bytes)


def test_record_capacity_is_atomic_and_exact_retries_survive_full_store(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy, admission_capacity=capacity(1))
    alice = submission(policy)
    bob = submission(policy, name="Bob")
    original = store.admit(alice, snapshot(), 110)
    before = store.admission_capacity_status()

    with pytest.raises(AdmissionCapacityError, match="exhausted"):
        store.admit(bob, snapshot(120), 120)

    assert store.admission_capacity_status() == before
    assert store.admit(alice, snapshot(120), 120) == original
    assert store.submissions() == [
        {"signed_submission": alice.model_dump(mode="json", by_alias=True), "receipt": original}
    ]

    reopened = CompetitionStore(store.directory, policy, admission_capacity=capacity(1))
    assert reopened.admit(alice, snapshot(120), 120) == original
    assert not reopened.admission_capacity_status()["accepting_new"]

    # The failed transaction did not retain block 120. Raising the operational
    # cap permits a new admission at the lower finalized block.
    raised = CompetitionStore(store.directory, policy, admission_capacity=capacity(2))
    raised.admit(bob, snapshot(111), 111)
    assert raised.admission_capacity_status()["records"] == 2


def test_payload_capacity_accepts_equality_and_rejects_one_byte_less(policy, tmp_path):
    measured = CompetitionStore(tmp_path / "measure", policy, admission_capacity=capacity(1))
    signed = submission(policy)
    measured.admit(signed, snapshot(), 110)
    exact_bytes = measured.admission_capacity_status()["payload_bytes"]

    exact = CompetitionStore(
        tmp_path / "exact",
        policy,
        admission_capacity=capacity(1, exact_bytes),
    )
    exact.admit(signed, snapshot(), 110)
    assert exact.admission_capacity_status()["payload_bytes"] == exact_bytes

    short = CompetitionStore(
        tmp_path / "short",
        policy,
        admission_capacity=capacity(1, exact_bytes - 1),
    )
    with pytest.raises(AdmissionCapacityError):
        short.admit(signed, snapshot(), 110)
    assert short.admission_capacity_status()["records"] == 0
    assert short.submissions() == []


def test_failure_after_insert_rolls_back_row_usage_and_observed_block(
    policy, tmp_path, monkeypatch
):
    store = CompetitionStore(tmp_path / "state", policy, admission_capacity=capacity(2))
    original_insert = store._insert_admission

    def fail_after_insert(connection, values, *, records, payload_bytes):
        original_insert(connection, values, records=records, payload_bytes=payload_bytes)
        raise RuntimeError("inert injected failure")

    monkeypatch.setattr(store, "_insert_admission", fail_after_insert)
    with pytest.raises(RuntimeError, match="injected"):
        store.admit(submission(policy), snapshot(120), 120)
    assert store.admission_capacity_status()["records"] == 0
    assert store.submissions() == []

    monkeypatch.setattr(store, "_insert_admission", original_insert)
    store.admit(submission(policy), snapshot(110), 110)
    assert store.admission_capacity_status()["records"] == 1


def test_legacy_over_limit_store_remains_readable_and_can_raise_cap(policy, tmp_path):
    initial = CompetitionStore(tmp_path / "state", policy, admission_capacity=capacity(2))
    alice = submission(policy)
    bob = submission(policy, name="Bob")
    alice_receipt = initial.admit(alice, snapshot(), 110)
    initial.admit(bob, snapshot(), 110)

    over_limit = CompetitionStore(initial.directory, policy, admission_capacity=capacity(1))
    assert len(over_limit.submissions()) == 2
    assert not over_limit.admission_capacity_status()["accepting_new"]
    assert over_limit.admit(alice, snapshot(115), 115) == alice_receipt
    with pytest.raises(AdmissionCapacityError):
        over_limit.admit(submission(policy, sequence=2), snapshot(115), 115)

    raised = CompetitionStore(initial.directory, policy, admission_capacity=capacity(3))
    raised.admit(submission(policy, sequence=2), snapshot(115), 115)
    assert raised.admission_capacity_status()["records"] == 3


def test_restart_reconciles_utf8_payload_bytes_from_existing_rows(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy, admission_capacity=capacity(2))
    store.admit(submission(policy), snapshot(), 110)
    with sqlite3.connect(store.path) as connection:
        connection.create_function("umi_writer_generation", 0, lambda: 2)
        expected = connection.execute(
            "SELECT COUNT(*), SUM(length(CAST(body AS BLOB)) + "
            "length(CAST(receipt AS BLOB))) FROM submissions"
        ).fetchone()
        connection.execute("UPDATE admission_usage SET records=999, payload_bytes=999")

    reopened = CompetitionStore(store.directory, policy, admission_capacity=capacity(2))
    status = reopened.admission_capacity_status()
    assert (status["records"], status["payload_bytes"]) == expected


def test_concurrent_new_admissions_cannot_cross_record_cap(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy, admission_capacity=capacity(1))
    barrier = threading.Barrier(2)

    def admit(signed):
        barrier.wait(timeout=2)
        return store.admit(signed, snapshot(), 110)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(admit, submission(policy)),
            pool.submit(admit, submission(policy, name="Bob")),
        ]
    outcomes = []
    for future in futures:
        try:
            outcomes.append(future.result())
        except AdmissionCapacityError as error:
            outcomes.append(error)
    assert sum(isinstance(value, dict) for value in outcomes) == 1
    assert sum(isinstance(value, AdmissionCapacityError) for value in outcomes) == 1
    assert store.admission_capacity_status()["records"] == 1


def test_concurrent_duplicate_uses_one_record_and_one_exact_receipt(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy, admission_capacity=capacity(1))
    signed = submission(policy)
    barrier = threading.Barrier(2)

    def admit():
        barrier.wait(timeout=2)
        return store.admit(signed, snapshot(), 110)

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = tuple(pool.map(lambda _index: admit(), range(2)))
    assert receipts[0] == receipts[1]
    assert store.admission_capacity_status()["records"] == 1


async def test_http_capacity_failure_is_generic_and_does_not_block_exact_retry(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy, admission_capacity=capacity(1))
    provider_calls = 0

    async def current():
        nonlocal provider_calls
        provider_calls += 1
        return snapshot()

    limits = CompetitionApiLimits(
        maximum_concurrent_submissions=1,
        maximum_concurrent_reads=1,
        maximum_concurrent_readiness=1,
        maximum_concurrent_registration_collections=1,
        maximum_page_offset=10,
        maximum_page_size=10,
        capacity_wait_seconds=0.05,
        socket_backlog=4,
    )
    app = create_app(store, current, limits=limits)
    alice = submission(policy)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://intake.example",
    ) as client:
        accepted = await client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(alice),
            headers={"content-type": "application/json"},
        )
        refused = await client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy, name="Bob")),
            headers={"content-type": "application/json"},
        )
        retry = await client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(alice),
            headers={"content-type": "application/json"},
        )
        status = await client.get("/v1/competition/status")
    assert accepted.status_code == 200
    assert refused.status_code == 503
    assert refused.json() == {
        "detail": "intake unavailable; retry the same signed submission later"
    }
    assert retry.json() == accepted.json()
    assert provider_calls == 2
    assert status.json()["admission_accepting_new"] is False


async def test_read_saturation_is_bounded_without_starving_submission(
    policy, tmp_path, monkeypatch
):
    store = CompetitionStore(tmp_path / "state", policy)
    entered = threading.Event()
    release = threading.Event()
    original = store.admission_summaries

    def blocked_summaries(*, offset=0, limit=20):
        entered.set()
        assert release.wait(timeout=2)
        return original(offset=offset, limit=limit)

    monkeypatch.setattr(store, "admission_summaries", blocked_summaries)

    async def current():
        return snapshot()

    limits = CompetitionApiLimits(
        maximum_concurrent_submissions=1,
        maximum_concurrent_reads=1,
        maximum_concurrent_readiness=1,
        maximum_concurrent_registration_collections=1,
        maximum_page_offset=10,
        maximum_page_size=10,
        capacity_wait_seconds=0.05,
        socket_backlog=4,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(store, current, limits=limits)),
        base_url="https://intake.example",
    ) as client:
        first_read = asyncio.create_task(client.get("/v1/competition/submissions"))
        assert await asyncio.to_thread(entered.wait, 1)
        saturated = await client.get("/v1/competition/status")
        admitted = await client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy)),
            headers={"content-type": "application/json"},
        )
        release.set()
        assert (await first_read).status_code == 200
    assert saturated.status_code == 503
    assert saturated.json() == {"detail": "service busy; retry the same request later"}
    assert saturated.headers["cache-control"] == "no-store"
    assert admitted.status_code == 200


async def test_cancelled_read_releases_its_capacity(policy, tmp_path, monkeypatch):
    store = CompetitionStore(tmp_path / "state", policy)
    entered = threading.Event()
    release = threading.Event()
    original = store.admission_summaries
    calls = 0

    def first_read_blocks(*, offset=0, limit=20):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            release.wait(timeout=2)
        return original(offset=offset, limit=limit)

    monkeypatch.setattr(store, "admission_summaries", first_read_blocks)

    async def current():
        return snapshot()

    limits = CompetitionApiLimits(
        maximum_concurrent_submissions=1,
        maximum_concurrent_reads=1,
        maximum_concurrent_readiness=1,
        maximum_concurrent_registration_collections=1,
        maximum_page_offset=10,
        maximum_page_size=10,
        capacity_wait_seconds=0.05,
        socket_backlog=4,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(store, current, limits=limits)),
        base_url="https://intake.example",
    ) as client:
        pending = asyncio.create_task(client.get("/v1/competition/submissions"))
        assert await asyncio.to_thread(entered.wait, 1)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert (await client.get("/v1/competition/status")).status_code == 200
        release.set()


class BlockingProvider:
    def __init__(self, _config, _policy):
        self.started = False
        self.closed = False
        self.calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        snap = snapshot()
        self.capture = RegistrationCapture(
            snapshot=snap,
            provenance={
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "genesis_block_hash": "0x" + "11" * 32,
                "block": snap.block,
                "block_hash": snap.block_hash,
                "state_root": "0x" + "22" * 32,
                "timestamp_ms": time.time_ns() // 1_000_000,
                "snapshot_sha256": digest(snap),
                "evidence_sha256": "33" * 32,
                "metadata_sha256": "44" * 32,
                "finality_evidence_sha256": "55" * 32,
                "finality_verifier_sha256": "66" * 32,
                "storage_proof_verifier_sha256": "77" * 32,
                "chain_submission_authorized": False,
            },
        )

    async def start(self):
        self.started = True

    async def collect(self):
        assert self.started and not self.closed
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        return self.capture

    async def aclose(self):
        self.closed = True
        self.release.set()


async def test_sustained_public_reads_cannot_starve_fresh_submission(
    policy, chain_config, tmp_path, public_deployment
):
    limits = CompetitionApiLimits(
        maximum_concurrent_submissions=2,
        maximum_concurrent_reads=1,
        maximum_concurrent_readiness=2,
        maximum_concurrent_registration_collections=1,
        maximum_page_offset=10,
        maximum_page_size=10,
        capacity_wait_seconds=0.05,
        socket_backlog=4,
    )
    archive = tmp_path / "archive"
    baseline = bundle_at(tmp_path / "baseline")
    preserve_bundle(baseline, tmp_path / "baseline", archive, policy)
    store = CompetitionStore(tmp_path / "intake", policy, admission_capacity=capacity(2))
    store.initialize_baseline(baseline, archive)
    historical = submission(policy)
    saved = store.admit(
        historical,
        snapshot(),
        110,
        registration_source="verifier_attested_finality",
    )
    config = CompetitionServiceConfig(
        schema="umi-competition-service-config/2",
        mode="intake_no_weight",
        policy_sha256=digest(policy),
        public_deployment=public_deployment,
        retained_state=RetainedIntakeState(
            schema="umi-competition-retained-intake-state/1",
            baseline_promotion_sha256=store.baseline_summary()["promotion_sha256"],
            required_submission_sha256s=(digest(historical.submission),),
        ),
        state_directory=str(tmp_path / "intake"),
        submission_head_checkpoint_directory=str(tmp_path / "intake-checkpoint"),
        chain=chain_config,
        admission_capacity=capacity(2),
        api_limits=limits,
    )
    (tmp_path / "intake-checkpoint").mkdir(mode=0o700)
    migrate(tmp_path / "intake", policy, confirmed=True, service_config=config)
    provider = BlockingProvider(config.chain, policy)
    app = create_intake_app(config, policy, provider_factory=lambda *_: provider)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://intake.example",
        ) as client,
    ):
        # The background collector owns the only provider call. A public read
        # may await that initial refresh but does not initiate another one.
        await asyncio.wait_for(provider.entered.wait(), timeout=1)
        assert provider.calls == 1
        provider.release.set()
        assert (await client.get("/v1/competition/readiness")).status_code == 200
        for _ in range(20):
            if app.state.registration_snapshot_cache._inflight is None:
                break
            await asyncio.sleep(0)
        assert app.state.registration_snapshot_cache._inflight is None

        # A new admission starts the next fresh collection. While it is held,
        # sustained status and readiness traffic is served from the verified
        # bounded-age cache and cannot take collection capacity from the POST.
        provider.entered.clear()
        provider.release.clear()
        fresh_submission = asyncio.create_task(
            client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(submission(policy, name="Bob")),
                headers={"content-type": "application/json"},
            )
        )
        await asyncio.wait_for(provider.entered.wait(), timeout=1)
        retry = await client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(historical),
            headers={"content-type": "application/json"},
        )
        for index in range(40):
            route = "status" if index % 2 else "readiness"
            assert (await client.get(f"/v1/competition/{route}")).status_code == 200
        assert provider.calls == 2
        assert not fresh_submission.done()
        provider.release.set()
        accepted = await asyncio.wait_for(fresh_submission, timeout=1)
    assert retry.status_code == 200
    assert retry.json() == saved
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "accepted_no_weight"
    assert provider.closed


async def test_idle_loopback_connections_cannot_consume_submission_capacity(policy, tmp_path):
    """The loopback listener leaves request isolation to the route semaphores.

    A single global Uvicorn connection ceiling would let idle proxy connections
    reject a POST before the ASGI submission reservation can run.
    """

    import uvicorn

    store = CompetitionStore(tmp_path / "state", policy)

    async def current():
        return snapshot()

    app = create_app(store, current)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.setblocking(False)
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            log_level="critical",
            lifespan="on",
            timeout_graceful_shutdown=2,
        )
    )
    serving = asyncio.create_task(server.serve(sockets=[listener]))
    idle = []
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        idle = [await asyncio.open_connection("127.0.0.1", port) for _ in range(80)]
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            response = await client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(submission(policy)),
                headers={"content-type": "application/json"},
            )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted_no_weight"
    finally:
        for _reader, writer in idle:
            writer.close()
        await asyncio.gather(
            *(writer.wait_closed() for _reader, writer in idle), return_exceptions=True
        )
        server.should_exit = True
        await asyncio.wait_for(serving, timeout=5)
        listener.close()


@pytest.mark.parametrize(
    "change",
    [
        {"maximum_concurrent_reads": 0},
        {"maximum_concurrent_registration_collections": 2},
        {"maximum_page_offset": 1_000_001},
        {"maximum_page_size": 101},
        {"maximum_http_connections": 2},
    ],
)
def test_api_limits_reject_invalid_values(change):
    with pytest.raises(ValueError):
        CompetitionApiLimits(**change)


async def test_public_pagination_is_bounded(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy)

    async def current():
        return snapshot()

    limits = CompetitionApiLimits(
        maximum_concurrent_submissions=1,
        maximum_concurrent_reads=1,
        maximum_concurrent_readiness=1,
        maximum_concurrent_registration_collections=1,
        maximum_page_offset=3,
        maximum_page_size=2,
        capacity_wait_seconds=0.05,
        socket_backlog=4,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(store, current, limits=limits)),
        base_url="https://intake.example",
    ) as client:
        assert (await client.get("/v1/competition/submissions?offset=4&limit=1")).status_code == 422
        assert (await client.get("/v1/competition/submissions?offset=0&limit=3")).status_code == 422
        assert (
            await client.get("/v1/competition/rounds/" + "00" * 32 + "?offset=4")
        ).status_code == 422
