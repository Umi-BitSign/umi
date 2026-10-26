"""Owner metadata, authenticated reviewer relay and public cache end to end."""

import asyncio
import json
import sqlite3
from collections import OrderedDict
from types import SimpleNamespace as NS

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_public_progress as public
from umi import competition_cohort_settlement_progress as module
from umi.competition_cohort_producer_epoch import ExecutionProducerEpochs, producer_epoch_routes
from umi.competition_work_progress import WorkProgress

from .test_competition_cohort_producer_epoch import EVALUATOR, EVALUATOR_ID, TOKEN

C, C7, SERIES = "c" * 64, "d" * 64, "e" * 64


@pytest.fixture(autouse=True)
def isolated_snapshots(monkeypatch):
    monkeypatch.setattr(public.PUBLIC_COHORT_PROGRESS, "entries", OrderedDict())


def producer(tmp_path, **kw):
    return module.SettlementProgressProducer(
        [tmp_path],
        series=SERIES,
        cohort=kw.pop("cohort", C),
        evaluator=EVALUATOR_ID,
        role=kw.pop("role", "coordinator"),
        **kw,
    )


def relay(tmp_path):
    return module.SettlementProgressRelay(
        tmp_path, series=SERIES, evaluator=EVALUATOR_ID, cohorts=(C, C7)
    )


async def test_native_progress_crosses_authenticated_relay_to_public_memory_only(
    tmp_path, monkeypatch
):
    p = producer(tmp_path)
    p.update("quality_vote_publication", phase="evidence")
    meter = WorkProgress("quality_vote_publication", 4, unit="published_votes", cohort=C)
    meter.advance()
    p.publish()
    original = p.observation
    assert original["completed"] == 1 and original["total"] == 4
    r = relay(tmp_path)
    r.sample()
    app = FastAPI()
    app.include_router(
        producer_epoch_routes(EVALUATOR, token=TOKEN, enabled=True, cohorts=(C, C7), settlement=r)
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("GET performed I/O or verification")

    with monkeypatch.context() as guard:
        guard.setattr(sqlite3, "connect", forbidden)
        guard.setattr(module, "_read_private_bytes", forbidden)
        guard.setattr(module, "checked", forbidden)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:19579"
        ) as client:
            assert (await client.get(module.PATH + C)).status_code == 401
            assert (
                await client.get(
                    module.PATH + "f" * 64, headers={"authorization": "Bearer " + TOKEN}
                )
            ).status_code == 404
            response = await client.get(
                module.PATH + C, headers={"authorization": "Bearer " + TOKEN}
            )
            assert response.status_code == 200
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:19579"
    ) as client:
        peer = ExecutionProducerEpochs(
            client, [NS(signer=EVALUATOR, origin="http://127.0.0.1:19579")], [TOKEN]
        )
        epochs = await peer.sample([EVALUATOR_ID])
        observed = await peer.settlement.sample(C, epochs, series=SERIES)
    assert observed["observed_unix_ms"] == original["observed_unix_ms"]
    state = public.CohortProgressSnapshots()
    state.record(
        "lifecycle", dict(cohort_sha256=C, phase="reference_reveal", stage="progress_review")
    )
    state.record("settlement", observed)
    with monkeypatch.context() as guard:
        guard.setattr(sqlite3, "connect", forbidden)
        guard.setattr(module, "_read_private_bytes", forbidden)
        guard.setattr(module, "checked", forbidden)
        result = state.snapshot(C)
    assert result["phase"] == "evidence" and result["stage"] == "quality_vote_publication"
    assert result["completed"] == 1 and result["total"] == 4 and result["percent"] == 25
    assert result["overall_percent"] is None and result["certification_authority"] is False
    assert result["observed_unix_ms"] == original["observed_unix_ms"]
    assert state.snapshot(C7)["completed"] is None
    meter.interrupt()


def test_snapshot_survives_relay_restart_without_freshening_dead_producer(tmp_path, monkeypatch):
    p = producer(tmp_path)
    p.update("settlement_phase_certification", phase="certification")
    p.publish()
    raw = json.loads(module._path(tmp_path, SERIES, C, "coordinator").read_bytes())
    raw["observed_unix_ms"] -= 150_000
    module._path(tmp_path, SERIES, C, "coordinator").write_bytes(module.canonical_json_bytes(raw))
    r = relay(tmp_path)
    r.sample()
    older = r.snapshot(C)[0]
    assert older["observed_unix_ms"] == raw["observed_unix_ms"]
    assert module.age(older)["stale"] and module.age(older)["eta_seconds"] is None
    r.sample()
    assert r.snapshot(C)[0]["observed_unix_ms"] == older["observed_unix_ms"]
    restarted = producer(tmp_path)
    assert restarted.epoch != p.epoch
    fresh = restarted.snapshot()
    assert fresh["phase"] is None and fresh["completed"] is None and fresh["percent"] is None


def test_native_retry_withdraws_eta_and_never_claims_unknown_percentage(tmp_path):
    p = producer(tmp_path)
    p.update("quality_vote_publication", phase="evidence")
    assert p.snapshot()["completed"] is None and p.snapshot()["percent"] is None
    p.update(p.stage, state="retrying", reason="sqlite_busy")
    body = p.snapshot()
    assert body["stalled_or_retrying"] and body["eta_seconds"] is None
    assert body["reason_code"] == "sqlite_busy"
    p.update("settlement_package_published", phase="complete", state="completed")
    body = p.snapshot()
    assert body["completed"] == body["total"] == 1 and body["percent"] == 100
    assert body["certification_authority"] is False


def test_metadata_accepts_byte_counts_without_accepting_unbounded_numbers(tmp_path):
    body = producer(tmp_path).snapshot()
    body.update(completed=2**30, total=2**31, percent=50, unit="bytes")
    assert module.checked(body, series=SERIES, cohort=C, evaluator=EVALUATOR_ID)["total"] == 2**31
    body["total"] = 2**53
    with pytest.raises(ValueError, match="work count"):
        module.checked(body, series=SERIES, cohort=C, evaluator=EVALUATOR_ID)


async def test_quality_publication_never_counts_an_assigned_slot_without_a_vote(
    tmp_path, monkeypatch
):
    from umi import competition_cohort_settlement_delivery as delivery

    node = object.__new__(delivery.SettlementResultVotes)
    node.account, node.hotkey, node.cohort = EVALUATOR_ID, EVALUATOR, C
    node.journal = node.sign = object()
    node.outbox = tmp_path
    node.inputs = NS(
        quality=NS(
            closure=NS(
                participants=(
                    NS(submission_sha256="a" * 64, evaluators=(NS(evaluator_hotkey=EVALUATOR),)),
                )
            ),
            outcome=lambda _: NS(runs=()),
        ),
        service=NS(slot="service"),
    )
    events, published = [], []
    record = public.PUBLIC_COHORT_PROGRESS.record

    def observed(kind, body):
        events.append(dict(body))
        return record(kind, body)

    async def service_vote(*args):
        return "native-service-vote"

    monkeypatch.setattr(public.PUBLIC_COHORT_PROGRESS, "record", observed)
    monkeypatch.setattr(delivery, "sign_service_allocation", service_vote)
    monkeypatch.setattr(delivery, "digest", lambda _: "a" * 64)
    monkeypatch.setattr(
        delivery, "publish_private_model", lambda path, value, **kw: published.append(path)
    )
    await node.publish()
    assert events[-1]["state"] == "accounting_mismatch"
    assert events[-1]["completed"] == 0 and events[-1]["total"] == 1
    assert events[-1]["percent"] == 0
    assert len(published) == 1 and "service" in published[0].parts


@pytest.mark.parametrize(
    "fault", ["series", "cohort", "evaluator", "role", "clock", "percent", "count", "nan"]
)
def test_changed_metadata_or_invented_measurement_is_rejected(tmp_path, fault):
    p = producer(tmp_path)
    body = p.snapshot()
    changes = {
        "series": {"series_sha256": "a" * 64},
        "cohort": {"cohort_sha256": C7},
        "evaluator": {"evaluator": "a" * 64},
        "role": {"role": "miner"},
        "clock": {"observed_unix_ms": 10**20},
        "percent": {"percent": 1},
        "count": {"completed": 1, "total": 0},
        "nan": {"eta_seconds": float("nan")},
    }
    body.update(changes[fault])
    with pytest.raises(ValueError):
        module.checked(body, series=SERIES, cohort=C, evaluator=EVALUATOR_ID)


async def test_old_peer_unavailability_does_not_create_completion_or_crash():
    app = FastAPI()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:19579"
    ) as client:
        reader = module.SettlementProgressObservations(
            client, {EVALUATOR_ID: ("http://127.0.0.1:19579", TOKEN)}, asyncio.Semaphore(1)
        )
        result = await reader.sample(C, {EVALUATOR_ID: "f" * 64}, series=SERIES)
    assert result["stage"] == "settlement_diagnostics_unavailable"
    assert result["completed"] is None and result["percent"] is None


def test_public_stale_settlement_does_not_borrow_intake_completion(tmp_path):
    p = producer(tmp_path)
    p.update("quality_vote_publication", phase="evidence")
    body = p.snapshot()
    body.update(
        observed_unix_ms=body["observed_unix_ms"] - 150_000,
        completed=1,
        total=2,
        percent=50,
        eta_seconds=30,
    )
    state = public.CohortProgressSnapshots()
    state.record(
        "lifecycle", dict(cohort_sha256=C, phase="reference_reveal", stage="handoff", percent=100)
    )
    state.record("settlement", body)
    result = state.snapshot(C)
    assert result["phase"] == "evidence" and result["percent"] == 50
    assert result["eta_seconds"] is None and result["stalled_or_retrying"]
    assert result["observed_unix_ms"] == body["observed_unix_ms"]


def test_request_hold_allows_only_exact_cached_settlement_get():
    from umi.host_memory_runtime import RequestsStageASGIBinding

    binding = RequestsStageASGIBinding(
        None, controller=NS(policy=NS(operations=())), private_role="phase_reviewer"
    )
    assert binding._permitted(dict(method="GET", path=module.PATH + C))
    for path in (module.PATH, module.PATH + C + "/", module.PATH + "../private"):
        assert not binding._permitted(dict(method="GET", path=path))
    assert not binding._permitted(dict(method="POST", path=module.PATH + C))


@pytest.mark.parametrize(
    "fault", ["epoch", "evaluator", "series", "cohort", "duplicate", "malformed", "oversized"]
)
async def test_transport_rejects_mixed_restart_scope_and_unbounded_metadata(tmp_path, fault):
    p = producer(tmp_path)
    p.update("quality_vote_publication", phase="evidence")

    def response(request):
        body = dict(
            schema="umi-settlement-work/1",
            evaluator=EVALUATOR_ID,
            reviewer_epoch_sha256="f" * 64,
            series_sha256=SERIES,
            cohort_sha256=C,
            snapshots=[p.snapshot()],
        )
        if fault in {"epoch", "evaluator", "series", "cohort"}:
            body[
                {
                    "epoch": "reviewer_epoch_sha256",
                    "evaluator": "evaluator",
                    "series": "series_sha256",
                    "cohort": "cohort_sha256",
                }[fault]
            ] = "a" * 64
        if fault == "duplicate":
            body["snapshots"] *= 2
        if fault == "malformed":
            return httpx.Response(200, json=[])
        if fault == "oversized":
            return httpx.Response(200, content=b" " * (module.MAX_BYTES + 1))
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        reader = module.SettlementProgressObservations(
            client, {EVALUATOR_ID: ("http://127.0.0.1:19579", TOKEN)}, asyncio.Semaphore(1)
        )
        value = await reader.sample(C, {EVALUATOR_ID: "f" * 64}, series=SERIES)
    assert value["stage"] == "settlement_diagnostics_unavailable" and value["percent"] is None


async def test_observation_cancellation_remains_owned(tmp_path):
    async def response(request):
        raise asyncio.CancelledError

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        reader = module.SettlementProgressObservations(
            client, {EVALUATOR_ID: ("http://127.0.0.1:19579", TOKEN)}, asyncio.Semaphore(1)
        )
        with pytest.raises(asyncio.CancelledError):
            await reader.sample(C, {EVALUATOR_ID: "f" * 64}, series=SERIES)


def test_durable_publication_survives_restart_with_auxiliary_retry_visible(tmp_path, monkeypatch):
    from .test_competition_cohort_publication_progress import (
        PREFIX,
        forbid_package_reads,
        output,
        publication,
    )

    path = output(tmp_path)
    progress = publication(tmp_path)
    forbid_package_reads(monkeypatch, path)
    p = producer(tmp_path, publication=progress)
    p.bind_publication(PREFIX)
    p.update("verification_dependencies", phase="first_admission")
    p.publish()
    original = p.observation["publication"]
    restarted = producer(tmp_path, publication=publication(tmp_path))
    restarted.bind_publication(PREFIX)
    restarted.update(
        "verification_dependencies", phase="first_admission", state="retrying", reason="sqlite_busy"
    )
    restarted.publish()
    result = restarted.observation
    assert result["stage"] == "settlement_package_published" and result["state"] == "completed"
    assert result["completed"] == result["total"] == 1 and result["percent"] == 100
    assert result["eta_seconds"] == 0 and not result["stalled_or_retrying"]
    assert result["elapsed_seconds"] is None  # Publication duration was not observed.
    assert "reason_code" not in result
    assert result["publication"] == original and result["certification_authority"] is False
    refresh = result["refresh"]
    assert refresh["stage"] == "verification_dependencies" and refresh["state"] == "retrying"
    assert refresh["reason_code"] == "sqlite_busy" and refresh["stalled_or_retrying"]
    assert refresh["eta_seconds"] is None
    r = relay(tmp_path)
    r.sample()
    relayed = r.snapshot(C)[0]
    assert relayed["publication"] == original and relayed["refresh"] == refresh
    state = public.CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, phase="first_admission"))
    state.record("settlement", relayed)

    def forbidden(*args, **kwargs):
        raise AssertionError("public snapshot performed I/O")

    with monkeypatch.context() as guard:
        guard.setattr(progress, "observe", forbidden)
        guard.setattr(module, "checked", forbidden)
        guard.setattr(module, "_read_private_bytes", forbidden)
        guard.setattr(sqlite3, "connect", forbidden)
        public_result = state.snapshot(C)
    assert public_result["percent"] == 100
    assert public_result["publication"] == original and public_result["refresh"] == refresh
    # A missing completed output is shown separately from auxiliary retry.
    path.unlink()
    restarted.publish()
    repaired = restarted.observation
    assert repaired["state"] == "repair_required" and repaired["percent"] is None
    assert repaired["reason_code"] == "publication_output_missing"
    assert repaired["refresh"]["reason_code"] == "sqlite_busy"


@pytest.mark.parametrize("fault", ["nested", "epoch", "scope", "publication_clock", "private"])
def test_publication_refresh_rejects_unbounded_or_mixed_diagnostics(tmp_path, fault):
    body = producer(tmp_path).snapshot()
    body["refresh"] = dict(body)
    if fault == "nested":
        body["refresh"]["refresh"] = {}
    elif fault == "epoch":
        body["refresh"]["producer_epoch_sha256"] = "f" * 64
    elif fault == "scope":
        body["refresh"]["cohort_sha256"] = C7
    else:
        body["publication"] = dict(state="completed", output_current=True)
        body["publication"][
            "observed_unix_ms" if fault == "publication_clock" else "private_path"
        ] = -1 if fault == "publication_clock" else "/secret"
    with pytest.raises(ValueError):
        module.checked(body, series=SERIES, cohort=C, evaluator=EVALUATOR_ID)
