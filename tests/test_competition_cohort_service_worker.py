"""Recurring FIFO service work through native miner routes and durable journals.

Finality, origin proofs, reviewer ports, media and inference are fixtures. No
installed coordinator, external reviewer host or chain effect is represented.
"""

import asyncio
import errno
import json
import sqlite3
import sys
from dataclasses import replace
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest

from umi.competition_cohort_endpoint_decision_contracts import (
    CohortEndpointCaseDecision,
    SignedCohortEndpointCaseDecision,
)
from umi.competition_cohort_service_grant import service_grant_slot, service_obligation
from umi.competition_cohort_service_queue import ServiceWorkQueue
from umi.competition_cohort_service_requests import ServiceWorkRequests
from umi.competition_cohort_service_terminal import read_service_terminal
from umi.competition_cohort_service_transport import ServiceWorkTransport
from umi.competition_cohort_service_work import SignedServiceWorkClaim
from umi.competition_cohort_service_worker import ServiceRequestInputs, ServiceWorkWorker
from umi.competition_origin import EndpointOriginCapture
from umi.endpoint_protocol import (
    COHORT_GRANT_PATH,
    COHORT_RETIRE_PATH,
    RESPONSE_RECOVERY_PATH,
    TRANSLATE_PATH,
)
from umi.miner import create_app
from umi.open_competition import digest, sign_object
from umi.private_files import PrivateStateBusyError
from umi.protocol import canonical_json_bytes, request_digest
from umi.sqlite_contention import is_sqlite_contention

from .test_competition_cohort_intake import history_tip
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import capture, fresh_window, restart_miner
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import harness as harness
from .test_competition_cohort_service_grants import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_grants import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_grants import miner_policy as miner_policy
from .test_competition_cohort_service_grants import original_harness as original_harness
from .test_competition_cohort_service_grants import policy as policy
from .test_competition_cohort_service_grants import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_grants import recovery as recovery
from .test_competition_cohort_service_grants import recovery_case as recovery_case
from .test_competition_cohort_service_grants import relay as relay
from .test_competition_cohort_service_grants import runtime as runtime
from .test_competition_cohort_service_grants import scenario as scenario
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group
from .test_open_competition import wallet


@pytest.fixture(params=["mutex", "sqlite"])
def contention_error(request, tmp_path):
    if request.param == "mutex":
        return PrivateStateBusyError("round_journal_lock", "ab" * 32, errno.EAGAIN)
    path = tmp_path / "actual-writer-contention.sqlite3"
    writer, reader = sqlite3.connect(path), sqlite3.connect(path, timeout=0)
    try:
        writer.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError) as caught:
            reader.execute("BEGIN IMMEDIATE")
        assert is_sqlite_contention(caught.value)
        return caught.value
    finally:
        writer.rollback()
        writer.close()
        reader.close()


@pytest.fixture
def loop(service_owner):
    c, p = service_owner, service_owner.p
    s = SimpleNamespace(
        c=c,
        p=p,
        paths=[],
        lost=None,
        offline=False,
        inputs=0,
        votes=0,
        signs=0,
        before_request=None,
    )

    class Network(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if s.offline:
                raise httpx.ConnectError("fixture private address must not reach logs")
            s.paths.append(request.url.path)
            if s.before_request is not None:
                await s.before_request(request.url.path)
            reply = await httpx.ASGITransport(app=create_app(p.miner)).handle_async_request(request)
            if request.url.path == s.lost:
                assert reply.status_code == 200
                await reply.aread()
                await reply.aclose()
                s.lost = None
                raise httpx.ReadError("fixture lost committed acknowledgement")
            return reply

    async def origin(assignment):
        assert assignment.catalog == c.assignment.catalog
        if s.offline:
            raise OSError("origin unavailable")
        return EndpointOriginCapture(
            submission_sha256=digest(assignment.admission.submission.submission),
            uid=1,
            hotkey=p.miner.hotkey_ss58,
            origin=assignment.admission.submission.submission.endpoint_url,
            block=p.finality.head,
            block_hash="a1" * 32,
            state_root="a2" * 32,
            timestamp_ms=1,
            evidence=b"fixture-origin-proof",
            connection_origin="https://93.184.216.34:443",
        )

    async def inputs(assignment):
        assert assignment.catalog == c.assignment.catalog
        s.inputs += 1
        if s.offline:
            raise OSError("private media source unavailable")
        video = p.service_video if assignment.admission.ordinal == 1 else p.requests[1].video
        return ServiceRequestInputs(video, c.window)

    async def observation(assignment):
        assert assignment.catalog == c.assignment.catalog
        if s.offline:
            raise OSError("history unavailable")
        return p.e.r.h.source, capture(p.finality.head)

    def reviewer(name):
        async def vote(body):
            s.votes += 1
            if s.offline:
                raise OSError("reviewer unavailable")
            assert body.assignment.catalog == c.assignment.catalog
            return sign_object(body, wallet(name))

        return vote

    async def retry(grant, retirement):
        raise OSError("retry reviewers unavailable")

    async def sign(terminal):
        s.signs += 1
        return sign_object(terminal, p.validator)

    s.origin, s.inputs_port, s.observation, s.sign, s.retry = (
        origin,
        inputs,
        observation,
        sign,
        retry,
    )
    s.reviewers = {wallet(n).hotkey.ss58_address: reviewer(n) for n in ("Charlie", "Dave")}

    def worker(**kwargs):
        requests = ServiceWorkRequests(ServiceWorkQueue(c.cfg, p.c.policy), p.transport_policy)
        transport = ServiceWorkTransport(
            requests, p.validator, p.finality, s.origin, transport=Network()
        )
        return ServiceWorkWorker(
            transport, s.inputs_port, s.observation, s.reviewers, s.retry, s.sign, **kwargs
        )

    s.worker = worker
    return s


async def test_batch_discovery_reads_while_an_unrelated_writer_is_busy(loop):
    import threading

    worker = loop.worker()
    expected = worker._batch(advance=False)
    entered, release = threading.Event(), threading.Event()

    def writer():
        with worker.journal.transaction() as db:
            db.execute("INSERT INTO holds VALUES ('unrelated-pending-hold')")
            entered.set()
            assert release.wait(60)

    pending = asyncio.create_task(asyncio.to_thread(writer))
    try:
        assert await asyncio.to_thread(entered.wait, 30)
        rows = await asyncio.wait_for(asyncio.to_thread(worker._batch, advance=False), 10)
        assert rows == expected
    finally:
        release.set()
        await pending
    assert worker._batch() == expected
    with worker.journal.read_transaction() as db:
        assert db.execute("SELECT ordinal FROM service_worker_cursor").fetchone() == (
            expected[-1].ordinal,
        )


async def test_pending_batch_wraps_without_treating_presence_as_credit(loop):
    worker = loop.worker()
    original = worker._batch(advance=False)
    worker._advance_cursor(8192)
    assert worker._batch(advance=False, pending_only=True) == original
    for value in original:
        worker.journal.put("service_terminal", value.work_sha256, {"unverified": True})
    assert worker._batch(advance=False, pending_only=True) == ()
    assert worker._batch(advance=False) == original
    with pytest.raises(ValueError):
        worker.terminals.read(loop.c.assignment)


async def finish(s):
    reports = []
    for _ in range(4):
        worker = s.worker()
        report = await worker.poll_once()
        reports.append(report)
        value = worker.terminals.read(s.c.assignment)
        if value is not None:
            return worker, value, reports
    # Surface native failure in the test, without making production log details public.
    await worker._advance(s.c.assignment.admission)
    raise AssertionError(reports)


@pytest.mark.parametrize(
    "stage",
    [
        "request_preparation",
        "preparation_inputs",
        "preparation_authority",
        "request_certificate",
        "miner_transport",
    ],
)
@pytest.mark.parametrize("cancel", [False, True])
async def test_rolling_reports_native_wait_stage_without_private_work(
    loop, monkeypatch, stage, cancel
):
    worker = loop.worker(concurrency=1)
    entered, release = asyncio.Event(), asyncio.Event()
    owner, name = {
        "request_preparation": (worker, "_prepare"),
        "preparation_inputs": (worker, "inputs"),
        "preparation_authority": (worker, "observation"),
        "request_certificate": (worker, "_certificate"),
        "miner_transport": (worker.transport, "advance"),
    }[stage]
    original = getattr(owner, name)

    async def held(*args, **kwargs):
        entered.set()
        await release.wait()
        return await original(*args, **kwargs)

    monkeypatch.setattr(owner, name, held)
    active = {}

    # Native stage boundaries persist before the next stage is scheduled.
    async def reach_stage():
        while not entered.is_set():
            await worker._rolling_poll(active)
            await asyncio.sleep(0.01)

    await asyncio.wait_for(reach_stage(), 120)
    try:
        await asyncio.wait_for(entered.wait(), 120)
        report = await worker._rolling_poll(active)
        assert report["in_flight_operations"] == 1
        assert report["in_flight_stage_counts"] == {stage: 1}
        assert report["oldest_in_flight_stage"] == stage
        assert report["oldest_in_flight_stage_seconds"] >= 0
        assert not report["request_closure_authorized"]
        assert not report["chain_submission_authorized"]
        encoded = json.dumps(report)
        assert loop.p.miner.hotkey_ss58 not in encoded
        assert loop.c.assignment.admission.work_sha256 not in encoded
        if cancel:
            await worker._stop_tasks(task for _, task in active.values())
        else:
            release.set()
            await asyncio.wait_for(asyncio.gather(*(task for _, task in active.values())), 120)
        assert not worker._operation_stages
    finally:
        release.set()
        await worker._stop_tasks(task for _, task in active.values())
    assert not worker._operation_stages


async def test_native_service_work_completes_and_restarts_offline(loop):
    s = loop
    worker, value, reports = await finish(s)
    read_service_terminal(value, worker.terminals.objects, s.p.c.policy, s.p.transport_policy)
    assert s.p.model.calls == s.p.fetcher.calls == 1
    assert s.inputs == 1 and s.votes == 2 and s.signs == 1
    assert all(not r["chain_submission_authorized"] for r in reports)
    original, paths = canonical_json_bytes(value), tuple(s.paths)
    restart_miner(s.c)
    s.offline = True
    worker, value, _ = await finish(s)
    assert canonical_json_bytes(value) == original and tuple(s.paths) == paths
    assert s.signs == 1


async def test_each_service_phase_resumes_after_restart_without_repeating_work(loop, monkeypatch):
    s = loop
    reasons = []
    for _ in range(8):
        worker = s.worker()
        # No terminal exists until the final phase. Each unfinished pass still
        # reads the accepted assignment once, then advances native state.
        monkeypatch.setattr(
            worker.terminals, "read", lambda _: pytest.fail("absent terminal replay")
        )
        status, reason = await worker._advance(s.c.assignment.admission, one_stage=True)
        reasons.append(reason)
        if status == "completed":
            break
    assert reasons == [
        "request_prepared",
        "request_certified",
        "request_retirement_pending",
        "retirement_retained",
        "terminal_retained",
    ]
    worker = s.worker()
    value = worker.terminals.read(s.c.assignment)
    assert value is not None
    read_service_terminal(value, worker.terminals.objects, s.p.c.policy, s.p.transport_policy)
    assert s.p.model.calls == s.p.fetcher.calls == 1
    assert s.inputs == 1 and s.votes == 2 and s.signs == 1
    s.offline = True
    assert await s.worker()._advance(s.c.assignment.admission, one_stage=True) == (
        "completed",
        "original_terminal_retained",
    )


async def test_terminal_hint_uses_owned_assignment_identity(loop):
    s = loop
    worker, value, _ = await finish(s)
    calls = s.p.model.calls, s.inputs, s.signs
    # A caller-supplied work label cannot hide the terminal of its real claim.
    changed = s.c.assignment.admission.model_copy(update={"work_sha256": "ff" * 32})
    assert await worker._advance(changed, one_stage=True) == (
        "completed",
        "original_terminal_retained",
    )
    assert (s.p.model.calls, s.inputs, s.signs) == calls
    assert worker.terminals.read(s.c.assignment) == value


async def test_saturated_preparation_does_not_take_dispatch_capacity(loop, monkeypatch):
    worker = loop.worker(concurrency=1)
    rows = [
        SimpleNamespace(
            work_sha256=str(i) * 64,
            ordinal=i,
            claim=SimpleNamespace(claim=SimpleNamespace(hotkey=wallet(name).hotkey.ss58_address)),
        )
        for i, name in enumerate(("Alice", "Bob", "Charlie"), 1)
    ]
    entered, dispatched, release = (asyncio.Event() for _ in range(3))
    started = []
    monkeypatch.setattr(worker, "_batch", lambda **kwargs: rows)
    monkeypatch.setattr(worker, "_advance_cursor", lambda _: None)
    monkeypatch.setattr(
        worker, "_ready_stage", lambda r: "dispatch" if r.ordinal == 3 else "preparation"
    )

    async def advance(row, **kwargs):
        started.append(row.ordinal)
        if row.ordinal == 3:
            dispatched.set()
            return "pending", "response_retained"
        entered.set()
        await release.wait()
        return "pending", "request_prepared"

    monkeypatch.setattr(worker, "_advance", advance)
    active = {}
    try:
        report = await worker._rolling_poll(active)
        await asyncio.wait_for(entered.wait(), 30)
        await asyncio.wait_for(dispatched.wait(), 30)
        assert started == [1, 3]
        assert report["in_flight_phase_counts"] == {"preparation": 1, "dispatch": 1}
        assert not release.is_set()
    finally:
        release.set()
        await worker._stop_tasks(task for _, task in active.values())


async def test_service_prepare_refreshes_inputs_after_mutex_contention(
    loop, monkeypatch, contention_error
):
    s = loop
    worker = s.worker()
    original = worker.requests.prepare
    attempts = []

    def contended(*args, **kwargs):
        attempts.append(args)
        if len(attempts) == 1:
            raise contention_error
        return original(*args, **kwargs)

    monkeypatch.setattr(worker.requests, "prepare", contended)
    body = await worker._prepare(s.c.assignment)
    assert len(attempts) == 2 and s.inputs == 2
    assert body.assignment == s.c.assignment


async def test_terminal_mutex_retry_refreshes_authority_without_repeating_work(
    loop, monkeypatch, contention_error
):
    s = loop
    worker = s.worker()
    for expected in (
        "request_prepared",
        "request_certified",
        "request_retirement_pending",
        "retirement_retained",
    ):
        assert await worker._advance(s.c.assignment.admission, one_stage=True) == (
            "pending",
            expected,
        )
    paths = tuple(s.paths)
    original = worker.terminals.prepare
    attempts = []

    def contended(*args):
        attempts.append(args)
        if len(attempts) == 1:
            s.p.finality.head += 1
            raise contention_error
        return original(*args)

    monkeypatch.setattr(worker.terminals, "prepare", contended)
    assert await worker._advance(s.c.assignment.admission, one_stage=True) == (
        "completed",
        "terminal_retained",
    )
    assert len(attempts) == 2
    assert attempts[1][-1].block == attempts[0][-1].block + 1
    assert attempts[1][:3] == attempts[0][:3]
    value = worker.terminals.read(s.c.assignment)
    read_service_terminal(value, worker.terminals.objects, s.p.c.policy, s.p.transport_policy)
    assert value.terminal.observation == attempts[1][-1]
    assert tuple(s.paths) == paths
    assert s.p.model.calls == s.p.fetcher.calls == s.inputs == s.signs == 1


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("invalid proof"),
        OSError("storage unavailable"),
        pytest.param(
            sqlite3.OperationalError("database is locked"),
            marks=pytest.mark.skipif(
                sys.version_info < (3, 11), reason="Python 3.10 classifies SQLite by message"
            ),
        ),
        sqlite3.OperationalError("disk I/O error"),
    ],
)
async def test_terminal_retry_does_not_hide_other_failures(loop, monkeypatch, failure):
    worker = loop.worker()
    calls = []

    def fail(*args):
        calls.append(args)
        raise failure

    monkeypatch.setattr(worker.terminals, "prepare", fail)
    with pytest.raises(type(failure), match=str(failure)):
        await worker._prepare_terminal(loop.c.assignment, "fixture-slot", None, None)
    assert len(calls) == 1 and loop.signs == 0 and loop.p.model.calls == 0


@pytest.mark.parametrize("path", [COHORT_GRANT_PATH, TRANSLATE_PATH, COHORT_RETIRE_PATH])
async def test_service_lost_acknowledgements_recover_without_duplicate_inference(loop, path):
    s = loop
    s.lost = path
    await s.worker().poll_once()
    restart_miner(s.c)
    _, value, _ = await finish(s)
    assert value.terminal.work_sha256 == s.c.assignment.admission.work_sha256
    assert s.paths.count(TRANSLATE_PATH) == 1
    assert s.p.model.calls == s.p.fetcher.calls == 1
    if path == TRANSLATE_PATH:
        assert RESPONSE_RECOVERY_PATH in s.paths


@pytest.mark.parametrize(
    "kind",
    ["service_dispatch_intent", "service_response", "service_terminal_intent", "service_terminal"],
)
async def test_service_owner_commit_loss_recovers_original(loop, monkeypatch, kind):
    s = loop
    worker = s.worker()
    original, saved = worker.journal.put, []

    def interrupt(record_kind, key, value):
        result = original(record_kind, key, value)
        if record_kind == kind:
            saved.append(canonical_json_bytes(value))
            raise OSError("fixture committed write lost its reply")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(worker.journal, "put", interrupt)
        report = await worker.poll_once()
    assert report["work_pending"] == 1 and len(saved) == 1
    restart_miner(s.c)
    if kind in {"service_terminal_intent", "service_terminal"}:
        s.offline = True
    restarted, value, _ = await finish(s)
    slot = service_grant_slot(
        restarted.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address)
    )
    key = (
        slot
        if kind in {"service_response", "service_dispatch_intent"}
        else value.terminal.work_sha256
    )
    assert canonical_json_bytes(restarted.journal.get(kind, key)) == saved[0]
    assert s.paths.count(TRANSLATE_PATH) == 1
    assert s.p.model.calls == 1


async def test_service_wrong_origin_does_not_send(loop):
    s = loop
    real = s.origin

    async def substituted(assignment):
        return replace(await real(assignment), submission_sha256="ff" * 32)

    s.origin = substituted
    report = await s.worker().poll_once()
    assert report["work_pending"] == 1 and report["last_pending_reason"] == "ValueError"
    assert report["retry_count"] == 1
    assert report["last_retry_details"][0]["reason_code"] == "validation_failed"
    assert report["last_retry_details"][0]["source_frames"]
    assert not s.paths and s.p.model.calls == 0


async def test_service_retry_diagnostics_keep_secrets_private_and_remain_retryable(tmp_path):
    worker = object.__new__(ServiceWorkWorker)
    worker.serial, worker.capacity = asyncio.Lock(), asyncio.Semaphore(1)
    worker.journal = SimpleNamespace(root=tmp_path)
    worker.transport = SimpleNamespace(timeout=5)
    admission = SimpleNamespace(
        claim=SimpleNamespace(
            claim=SimpleNamespace(hotkey="5HTFEEFA13x4hom2Nz5EFo7RSQ6PSAyCH1BgM8CbZhhdrSDb")
        )
    )
    worker._batch = lambda: [admission]
    calls = 0

    async def failing(_):
        nonlocal calls
        calls += 1
        try:
            raise OSError("https://private.example/?token=private-capability")
        except OSError as error:
            raise ValueError("private response bytes") from error

    worker._advance = failing
    for _ in range(2):
        report = await worker.poll_once()
        assert report["work_pending"] == 1 and report["work_complete"] == 0
        assert report["retry_count"] == 1
        assert [e["reason_code"] for e in report["last_retry_details"]] == [
            "validation_failed",
            "os_error",
        ]
        assert report["retry_examples"] == [report["last_retry_details"]]
        assert "private" not in json.dumps(report)
        assert not report["chain_submission_authorized"]
    assert calls == 2


async def test_service_outer_retry_preserves_safe_diagnostics(loop):
    worker = loop.worker()
    stop = asyncio.Event()
    reports = []

    async def failing(_active):
        raise OSError("private journal path")

    def report(value):
        reports.append(value)
        stop.set()

    worker._rolling_poll = failing
    await worker.run(stop, poll_seconds=0.01, report=report)
    assert len(reports) == 1
    assert reports[0]["status"] == "cohort_service_worker_retry"
    assert reports[0]["last_retry_details"][0]["reason_code"] == "os_error"
    assert "private" not in json.dumps(reports)


async def test_service_shutdown_drains_active_port_and_releases_process_lease(loop):
    s = loop
    entered, stopped, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def waiting(_):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    s.inputs_port = waiting
    worker = s.worker()
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01))
    await asyncio.wait_for(entered.wait(), 15)
    with pytest.raises(BlockingIOError):
        await s.worker().poll_once()
    stop.set()
    await asyncio.wait_for(task, 5)
    assert stopped.is_set()
    s.inputs_port = lambda _: asyncio.sleep(
        0, result=ServiceRequestInputs(s.p.service_video, s.c.window)
    )
    await finish(s)


async def test_expired_service_attempt_waits_for_certified_replacement_then_finishes(
    loop, monkeypatch
):
    s, p = loop, loop.p
    worker = s.worker()
    body = await worker._prepare(s.c.assignment)
    await worker._certificate(body)
    original = canonical_json_bytes(body)
    p.finality.head = body.request.deadline_block + 3000
    monkeypatch.setattr(
        bt.timelock, "current_round", lambda: body.request.response_close_round + 500
    )
    report = await s.worker().poll_once()
    assert report["work_pending"] == 1
    assert s.paths.count(TRANSLATE_PATH) == 0 and p.model.calls == 0
    assert worker.requests.latest(s.c.claim, p.validator.hotkey.ss58_address) == body

    async def retry(grant, retired):
        assert grant.body == body and retired.receipt.result == "no_response_retained"
        decision = CohortEndpointCaseDecision(
            schema="umi-cohort-endpoint-case-decision/1",
            policy_sha256=digest(p.c.policy),
            cohort_sha256=s.c.assignment.round.cohort_sha256,
            obligation_sha256=service_obligation(s.c.assignment, body.evaluator_hotkey),
            case_id=s.c.assignment.catalog.catalog.work[0].case_id,
            attempt_number=body.attempt_number,
            review_sha256=digest(retired),
            request_sha256=request_digest(body.request),
            disposition="retry_required",
            response_sha256=None,
        )
        return SignedCohortEndpointCaseDecision(decision=decision, signatures=signatures(decision))

    s.retry = retry
    s.c.window = fresh_window(p, body.request, monkeypatch)
    restarted, value, _ = await finish(s)
    selected = restarted.requests.latest(s.c.claim, p.validator.hotkey.ss58_address)
    assert (
        selected.attempt_number == 2 and selected.request.issued_block > body.request.deadline_block
    )
    assert selected.assignment == body.assignment
    assert canonical_json_bytes(restarted.requests._body(service_grant_slot(body))) == original
    read_service_terminal(value, restarted.terminals.objects, p.c.policy, p.transport_policy)
    assert s.paths.count(TRANSLATE_PATH) == 1 and p.model.calls == 1


async def test_expired_unsent_service_reaches_retirement_lane(loop, monkeypatch):
    s, p = loop, loop.p
    worker = s.worker()
    body = await worker._prepare(s.c.assignment)
    await worker._certificate(body)
    original = canonical_json_bytes(body)
    p.finality.head = body.request.deadline_block + 3000
    monkeypatch.setattr(
        bt.timelock, "current_round", lambda: body.request.response_close_round + 500
    )
    assert s.worker()._ready_stage(s.c.assignment.admission) == "recovery"
    assert await s.worker()._advance(s.c.assignment.admission, one_stage=True) == (
        "pending",
        "retirement_retained",
    )
    assert s.worker()._ready_stage(s.c.assignment.admission) == "certification"
    assert s.paths.count(TRANSLATE_PATH) == 0 and p.model.calls == 0
    assert (
        canonical_json_bytes(worker.requests.latest(s.c.claim, p.validator.hotkey.ss58_address))
        == original
    )


@pytest.mark.parametrize("expired,retained_grant", [(False, True), (True, True), (True, False)])
async def test_failed_grant_retry_does_not_block_expired_native_retirement(
    loop, monkeypatch, expired, retained_grant
):
    s, p = loop, loop.p
    worker = s.worker()
    body = await worker._prepare(s.c.assignment)
    await worker._certificate(body)
    slot = service_grant_slot(body)
    original = canonical_json_bytes(body)
    if retained_grant:
        s.lost = COHORT_GRANT_PATH
        first = await worker.transport.advance(slot, retire=False)
        assert first.reason == "grant_pending"
        assert worker.journal.get("service_grant_delivery", slot) is None

    # Restart with only the original durable state. Further grant deliveries
    # fail, while the miner's native recovery/retirement routes are available.
    worker = s.worker()
    exchange = worker.transport._exchange

    async def grant_unavailable(capture, path, body, maximum):
        if path == COHORT_GRANT_PATH:
            return None
        return await exchange(capture, path, body, maximum)

    monkeypatch.setattr(worker.transport, "_exchange", grant_unavailable)
    if expired:
        p.finality.head = body.request.deadline_block + 3000
        monkeypatch.setattr(
            bt.timelock, "current_round", lambda: body.request.response_close_round + 500
        )
    result = await worker.transport.advance(slot)
    if expired and retained_grant:
        assert result.reason == "retry_required"
        assert result.retirement.receipt.result == "no_response_retained"
        assert worker.journal.get("service_retirement", slot) is not None
        assert COHORT_RETIRE_PATH in s.paths
    else:
        assert result.reason == ("retirement_pending" if expired else "grant_pending")
        assert result.retirement is None
        assert worker.journal.get("service_retirement", slot) is None
        if not expired:
            assert COHORT_RETIRE_PATH not in s.paths
    assert worker.journal.get("service_dispatch_intent", slot) is None
    assert worker.journal.get("service_terminal", s.c.assignment.admission.work_sha256) is None
    assert s.paths.count(TRANSLATE_PATH) == p.model.calls == 0
    assert canonical_json_bytes(worker.requests._body(slot)) == original


async def test_queue_rotation_survives_restart_and_unavailable_first_miner_work(loop):
    s, c, p = loop, loop.c, loop.p
    claim = c.claim.claim.model_copy(update={"nonce": "02" * 32})
    signed = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, p.miner.wallet))
    c.queue.admit(
        signed,
        c.assignment.admission.submission,
        c.assignment.admission.participant,
        p.e.r.h.source,
        capture(p.finality.head),
        expected_tip_sha256=history_tip(p.e.r.h.source.history),
    )
    second = c.queue.assignment(signed)
    original_inputs = s.inputs_port

    async def blocked_first(assignment):
        if assignment == c.assignment:
            raise OSError("private https://clip.example/bearer-secret")
        return await original_inputs(assignment)

    s.inputs_port = blocked_first
    report = await s.worker(batch_size=1).poll_once()
    assert report["work_pending"] == 1
    assert "bearer-secret" not in str(report)
    worker = s.worker(batch_size=1)
    report = await worker.poll_once()
    assert report["work_complete"] == 1
    assert worker.terminals.read(second) is not None
    assert worker.terminals.read(c.assignment) is None
    assert p.model.calls == 1
    s.inputs_port = original_inputs
    report = await s.worker(batch_size=1).poll_once()
    assert report["work_complete"] == 1 and p.model.calls == 2


async def test_reviewer_identity_mismatch_does_not_create_grant(loop):
    s = loop

    async def wrong(body):
        return sign_object(body, wallet("Charlie"))

    s.reviewers[wallet("Dave").hotkey.ss58_address] = wrong
    report = await s.worker().poll_once()
    assert report["work_pending"] == 1
    assert not s.paths and s.p.model.calls == 0


async def test_repeated_cancellation_holds_lease_until_port_cleanup_finishes(loop):
    s = loop
    entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def waits(_):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()

    s.inputs_port = waits
    worker = s.worker()
    task = asyncio.create_task(worker.poll_once())
    await asyncio.wait_for(entered.wait(), 15)
    task.cancel()
    await asyncio.wait_for(cleaning.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(BlockingIOError):
        await s.worker().poll_once()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    s.inputs_port = lambda _: asyncio.sleep(
        0, result=ServiceRequestInputs(s.p.service_video, s.c.window)
    )
    await finish(s)


async def test_cancelled_native_send_drains_transport_before_releasing_worker(loop):
    s = loop
    entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def holding(path):
        if path != TRANSLATE_PATH:
            return
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()

    s.before_request = holding
    worker = s.worker()
    task = asyncio.create_task(worker.poll_once())
    await asyncio.wait_for(entered.wait(), 15)
    task.cancel()
    await asyncio.wait_for(cleaning.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(BlockingIOError):
        await s.worker().poll_once()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    s.before_request = None
    grant = worker.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address)
    slot = service_grant_slot(grant)
    intent = canonical_json_bytes(worker.journal.get("service_dispatch_intent", slot))
    restarted = s.worker()
    await restarted.poll_once()
    value = restarted.terminals.read(s.c.assignment)
    assert value is not None
    read_service_terminal(value, restarted.terminals.objects, s.p.c.policy, s.p.transport_policy)
    assert canonical_json_bytes(restarted.journal.get("service_dispatch_intent", slot)) == intent
    assert restarted.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address) == grant
    assert s.paths.count(TRANSLATE_PATH) == 2 and s.p.model.calls == s.p.fetcher.calls == 1
    s.offline = True
    await s.worker().poll_once()
    assert s.paths.count(TRANSLATE_PATH) == 2 and s.p.model.calls == 1


async def test_missing_original_selection_cannot_be_replaced_by_fresh_work(loop):
    s = loop
    worker = s.worker()
    body = await worker._prepare(s.c.assignment)
    with worker.journal.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind='service_request' AND id=?", (service_grant_slot(body),)
        )
    report = await s.worker().poll_once()
    assert report["work_pending"] == 1
    assert s.inputs == 1 and not s.paths and s.p.model.calls == 0


async def test_fresh_service_window_completes_native_work_and_restarts(loop, monkeypatch):
    import time
    from dataclasses import replace

    import bittensor as bt

    from umi.competition_cohort_request_window import capture_cohort_attempt_window
    from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, ceil_div

    from .test_drand import ROUND

    s, p, c = loop, loop.p, loop.c
    clock = p.transport_policy.clock
    budget_seconds = (
        ceil_div(
            clock.issue_allowance_seconds + clock.response_window_seconds,
            clock.target_block_interval_seconds,
        )
        * clock.target_block_interval_seconds
    )
    issued = c.window.issuance.height
    # Use the actual retained Quicknet pulse for native response decryption.
    # The finality port is a fixture; this does not claim live chain qualification.
    issuance = replace(
        p.finality.blocks[issued],
        timestamp_ms=(
            QUICKNET_GENESIS_MS
            + (ROUND - 1) * QUICKNET_PERIOD_MS
            - (budget_seconds + clock.reveal_margin_seconds) * 1000
        ),
    )
    p.finality.blocks[issued] = issuance
    c.window = await capture_cohort_attempt_window(
        p.transport_policy, p.finality, issued, c.assignment, 1
    )
    schedule = c.window.schedule(p.transport_policy)
    assert schedule.reveal_round == ROUND
    monkeypatch.setattr(bt.timelock, "current_round", lambda: schedule.selection_round)
    monkeypatch.setattr(time, "time", lambda: issuance.timestamp_ms / 1000)
    worker, value, reports = await finish(s)
    read_service_terminal(value, worker.terminals.objects, p.c.policy, p.transport_policy)
    assert p.model.calls == p.fetcher.calls == 1
    assert s.votes == 2
    assert any(r["work_complete"] for r in reports)
    exact = canonical_json_bytes(value)
    restart_miner(c)
    s.offline = True
    _, retained, _ = await finish(s)
    assert canonical_json_bytes(retained) == exact
    assert p.model.calls == 1


@pytest.mark.parametrize("shared_control_group", [True], indirect=True)
@pytest.mark.parametrize("slow_name", ["Eve", "Dave"])
async def test_service_certificate_waits_for_quorum_not_redundant_reviewer(
    loop, slow_name, monkeypatch
):
    s = loop
    entered, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
    slow_key = wallet(slow_name).hotkey.ss58_address

    async def slow(body):
        entered.set()
        try:
            await release.wait()
            return sign_object(body, wallet(slow_name))
        finally:
            cancelled.set()

    async def extra(body):
        return sign_object(body, wallet("Eve"))

    s.reviewers[wallet("Eve").hotkey.ss58_address] = extra
    s.reviewers[slow_key] = slow
    worker = s.worker()
    same_group_retained = asyncio.Event()
    retained_signers = set()
    event_loop = asyncio.get_running_loop()
    collect = worker.requests.collect

    def retained(who):
        retained_signers.add(who)
        if {
            wallet("Charlie").hotkey.ss58_address,
            wallet("Eve").hotkey.ss58_address,
        } <= retained_signers:
            same_group_retained.set()

    def tracked_collect(slot, signature):
        result = collect(slot, signature)
        event_loop.call_soon_threadsafe(retained, signature.hotkey)
        return result

    monkeypatch.setattr(worker.requests, "collect", tracked_collect)
    body = await worker._prepare(s.c.assignment)
    task = asyncio.create_task(worker._certificate(body))
    try:
        await asyncio.wait_for(entered.wait(), 120)
        if slow_name == "Dave":
            # Both same-group votes are already natively verified and persisted;
            # neither an early wakeup nor their raw count supplies Dave's group.
            await asyncio.wait_for(same_group_retained.wait(), 120)
            with pytest.raises(ValueError, match="lacks the policy evaluator quorum"):
                await worker._local(worker.requests.certificate, service_grant_slot(body))
            assert not task.done()
            release.set()
        grant = await asyncio.wait_for(asyncio.shield(task), 45)
        assert grant.body == body
        assert len(grant.signatures) == worker.requests.policy.required_evaluator_groups
        assert cancelled.is_set()
        if slow_name == "Eve":
            assert not release.is_set()
        assert worker.requests.certificate(service_grant_slot(body)) == grant
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def service_reject_first(s):
    seen = []
    worker = s.worker()
    original = worker.transport.transport

    class RejectFirst(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.path == TRANSLATE_PATH:
                seen.append((request.content, dict(request.headers)))
                if len(seen) == 1:
                    return httpx.Response(503, content=b"temporary admission unavailable")
            return await original.handle_async_request(request)

    worker.transport.transport = RejectFirst()
    first = await worker.poll_once()
    assert first["work_pending"] == 1 and s.p.model.calls == 0
    grant = worker.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address)
    return worker, service_grant_slot(grant), seen


async def test_service_admission_retries_original_without_replacing_grant(loop):
    s = loop
    worker, slot, seen = await service_reject_first(s)
    original = canonical_json_bytes(worker.journal.get("service_dispatch_intent", slot))
    await worker.poll_once()
    value = worker.terminals.read(s.c.assignment)
    assert value is not None
    read_service_terminal(value, worker.terminals.objects, s.p.c.policy, s.p.transport_policy)
    assert len(seen) == 2 and seen[0][0] == seen[1][0] and seen[0][1] != seen[1][1]
    assert s.p.model.calls == s.p.fetcher.calls == 1
    assert canonical_json_bytes(worker.journal.get("service_dispatch_intent", slot)) == original
    s.offline = True
    await s.worker().poll_once()
    assert s.p.model.calls == 1


@pytest.mark.parametrize("after", [False, True])
async def test_service_retry_intent_crash_consumes_at_most_two_sends(loop, monkeypatch, after):
    s = loop
    worker, _slot, seen = await service_reject_first(s)
    put = worker.journal.put

    def interrupted(kind, key, value):
        if kind == "service_dispatch_retry_intent":
            if after:
                put(kind, key, value)
            raise OSError("retry intent acknowledgement lost")
        return put(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(worker.journal, "put", interrupted)
        assert (await worker.poll_once())["work_pending"] == 1
    await worker.poll_once()
    if after:
        assert len(seen) == 1 and s.p.model.calls == 0
        assert worker.terminals.read(s.c.assignment) is None
    else:
        assert len(seen) == 2 and s.p.model.calls == 1
        assert worker.terminals.read(s.c.assignment) is not None
    before = len(seen)
    await worker.poll_once()
    assert len(seen) == before


async def test_service_unknown_second_send_cannot_repeat_after_restart(loop):
    s = loop
    worker, slot, seen = await service_reject_first(s)
    original = worker.transport.transport

    class LostAgain(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.path == TRANSLATE_PATH:
                seen.append((request.content, dict(request.headers)))
                raise httpx.ReadTimeout("second outcome unknown")
            return await original.handle_async_request(request)

    worker.transport.transport = LostAgain()
    assert (await worker.poll_once())["work_pending"] == 1
    for _ in range(2):
        assert (await s.worker().poll_once())["work_pending"] == 1
    assert len(seen) == 2 and s.p.model.calls == 0
    assert worker.journal.get("service_dispatch_retry_intent", slot) is not None
