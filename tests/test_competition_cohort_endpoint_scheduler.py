"""Native inbox-to-terminal scheduling with fixture network/finality and inference.

Real signed assignments, miner HTTP handlers, request votes, journals and
retirement certificates are exercised. No installed service or reward is claimed.
"""

import asyncio
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from itertools import pairwise
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_attempt_worker import CohortEndpointAttemptWorker
from umi.competition_cohort_endpoint_archive import (
    EndpointReplayArchive,
    JournalEndpointObjects,
    endpoint_archive_cases,
)
from umi.competition_cohort_endpoint_dispatch import CohortEndpointDispatcher
from umi.competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
from umi.competition_cohort_endpoint_retirement import (
    CohortEndpointRetirement,
    CohortRetirementOutcome,
)
from umi.competition_cohort_endpoint_selection import selected_request, selection_grant
from umi.competition_cohort_endpoint_worker import CohortEndpointWorker
from umi.competition_cohort_execution_journal import CohortExecutionJournal
from umi.endpoint_protocol import COHORT_GRANT_PATH, COHORT_RETIRE_PATH, TRANSLATE_PATH
from umi.miner import create_app
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_attempt_pipeline import expire_child
from .test_competition_cohort_endpoint_decision import coordinator
from .test_competition_cohort_miner_case import next_grant
from .test_competition_cohort_request_signer import base_policy as base_policy
from .test_competition_cohort_request_signer import chain as chain
from .test_competition_cohort_request_signer import chain_config as chain_config
from .test_competition_cohort_request_signer import decisions as decisions
from .test_competition_cohort_request_signer import delivery as delivery
from .test_competition_cohort_request_signer import endpoint as endpoint
from .test_competition_cohort_request_signer import execution as execution
from .test_competition_cohort_request_signer import granted as granted
from .test_competition_cohort_request_signer import harness as harness
from .test_competition_cohort_request_signer import known_video_bytes as known_video_bytes
from .test_competition_cohort_request_signer import legacy_scenario as legacy_scenario
from .test_competition_cohort_request_signer import policy as policy
from .test_competition_cohort_request_signer import receipt_scenario as receipt_scenario
from .test_competition_cohort_request_signer import recovery as recovery
from .test_competition_cohort_request_signer import recovery_case as recovery_case
from .test_competition_cohort_request_signer import relay as relay
from .test_competition_cohort_request_signer import retiring as retiring
from .test_competition_cohort_request_signer import runtime as runtime
from .test_competition_cohort_request_signer import scenario as scenario
from .test_competition_cohort_request_signer import signing as signing


@pytest.fixture
def scheduled(signing, tmp_path):
    s, p = signing, signing.p
    # Give the scheduler empty evaluator and miner grant journals. The earlier
    # fixture's manual grant is not used by this actual construction/delivery run.
    p.e.journal = lambda **kw: CohortExecutionJournal(
        p.e.cfg.model_copy(update={"directory": str(tmp_path / "scheduler-evaluator"), **kw}),
        p.c.policy,
    )
    p.miner = p.rebuild(directory=str(tmp_path / "scheduler-miner"))
    p.paths = []
    inner = httpx.ASGITransport(app=create_app(p.miner))

    class Trace(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            p.paths.append(request.url.path)
            return await inner.handle_async_request(request)

    p.delivery_recovery = CohortEndpointResponseRecovery(
        p.service(), p.validator, transport=Trace()
    )
    p.retirement = CohortEndpointRetirement(p.delivery_recovery)
    q = SimpleNamespace(
        s=s,
        p=p,
        media_calls=[],
        policy_calls=0,
        media_fail=False,
        policy_fail=False,
        media_suffix="",
    )

    async def video(job, case):
        if job != p.e.job:
            raise OSError("other miner unavailable")
        q.media_calls.append(case.case_id)
        if q.media_fail:
            raise OSError("https://private.example/clip/bearer-secret")
        index = next(i for i, item in enumerate(job.cases) if item.case_id == case.case_id)
        video = p.requests[index].video
        return video.model_copy(update={"url": video.url + q.media_suffix})

    async def transport(assignment):
        q.policy_calls += 1
        if q.policy_fail:
            raise OSError("policy source unavailable")
        return p.transport_policy

    def worker(**kwargs):
        requests = s.worker()
        requests.video_source = video
        attempts = CohortEndpointAttemptWorker(requests, coordinator(s.d))
        return CohortEndpointWorker(p.e.box, attempts, transport, **kwargs)

    q.worker = worker
    q.slot = p.retire_slot
    return q


async def finish(q, *, maximum_polls=12, **kwargs):
    reports = []
    for _ in range(maximum_polls):
        worker = q.worker(**kwargs)
        reports.append(await worker.poll_once())
        terminal = worker.schedule.complete(q.slot)
        if terminal is not None and worker.schedule.journal.get("endpoint_replay_archive", q.slot):
            return terminal, reports
    raise AssertionError(reports)


async def test_inbox_to_complete_terminal_selection_and_offline_restart(scheduled):
    q, p = scheduled, scheduled.p
    terminal, reports = await finish(q)
    assert len(terminal.cases) == len(p.e.job.cases)
    assert p.model.calls == len(p.e.job.cases)
    assert q.policy_calls == 1 and len(q.media_calls) == len(p.e.job.cases)
    assert all(
        not r["chain_submission_authorized"] and not r["request_closure_authorized"]
        for r in reports
    )
    calls = list(p.paths), len(q.s.calls), p.model.calls
    p.c.finality.fail = True
    p.finality.blocks.clear()
    q.s.peers_offline = q.media_fail = q.policy_fail = True
    worker = q.worker()
    report = await worker.poll_once()
    assert report["assignments_complete"] == 1 and report["cases_considered"] == 0
    assert worker.schedule.complete(q.slot) == terminal
    assert (list(p.paths), len(q.s.calls), p.model.calls) == calls
    archive = EndpointReplayArchive.model_validate_json(
        canonical_json_bytes(worker.schedule.journal.get("endpoint_replay_archive", q.slot))
    )
    # An independent consumer needs only the immutable content objects.
    with worker.schedule.journal.transaction() as db:
        objects = dict(
            db.execute("SELECT id,body FROM records WHERE kind='endpoint_replay_object'")
        )
    reviews = tuple(endpoint_archive_cases(archive, objects.__getitem__, p.c.policy))
    assert [r.retirement.case_id for r in reviews] == [c.case_id for c in terminal.cases]
    assert all(r.recovered is not None for r in reviews)


async def test_expired_unsent_endpoint_reaches_retirement_lane(scheduled, monkeypatch):
    q, p = scheduled, scheduled.p
    worker = q.worker()
    assert (await worker._prepare(q.slot))[0] == "prepared"
    selected, assignment, _ = p.delivery_recovery.selection(q.slot)
    grant = selection_grant(selected, assignment)
    original = canonical_json_bytes(grant)
    case = p.e.job.cases[0].case_id
    expire_child(p, grant, monkeypatch)
    assert q.worker().attempts.phase(q.slot, case) == "recovery"
    result = await q.worker().attempts.advance(q.slot, case, one_stage=True)
    assert result["reason"] == "retirement_retained"
    assert q.worker().attempts.phase(q.slot, case) == "certification"
    assert TRANSLATE_PATH not in p.paths and p.model.calls == 0
    assert (
        canonical_json_bytes(selection_grant(*p.delivery_recovery.selection(q.slot)[:2]))
        == original
    )


async def test_scheduling_hints_read_committed_state_without_waiting_for_writer(scheduled):
    q = scheduled
    worker = q.worker()
    assert (await worker._prepare(q.slot))[0] == "prepared"
    schedule = worker.schedule
    before = schedule.pending(2, advance=False)
    position = schedule.cursor("cases")
    entered, release = threading.Event(), threading.Event()

    def writer():
        with schedule.journal.transaction() as db:
            db.execute(
                "INSERT INTO endpoint_schedule_cursor VALUES ('cases',?) "
                "ON CONFLICT(name) DO UPDATE SET position=excluded.position",
                (q.slot,),
            )
            entered.set()
            assert release.wait(60)

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(writer)
        try:
            assert entered.wait(30)
            assert pool.submit(schedule.cursor, "cases").result(timeout=5) == position
            assert pool.submit(schedule.pending, 2, advance=False).result(timeout=5) == before
        finally:
            release.set()
        pending.result(timeout=30)
    assert schedule.cursor("cases") == q.slot
    assert schedule.pending(2, advance=False) == before


@pytest.mark.parametrize("grant_reached_miner", [False, True])
async def test_expired_grant_retry_cannot_block_native_retirement(
    scheduled, monkeypatch, grant_reached_miner
):
    from umi.competition_cohort_grant_delivery import CohortEndpointGrantDelivery

    q, p = scheduled, scheduled.p
    worker = q.worker()
    assert (await worker._prepare(q.slot))[0] == "prepared"
    selected, assignment, _ = p.delivery_recovery.selection(q.slot)
    grant = selection_grant(selected, assignment)
    case = p.e.job.cases[0].case_id
    original = p.delivery_recovery.transport
    calls = []

    class LostGrantAcknowledgment(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            calls.append(request.url.path)
            if request.url.path == COHORT_GRANT_PATH:
                if grant_reached_miner:
                    response = await original.handle_async_request(request)
                    assert response.status_code == 200
                raise httpx.ReadError("grant acknowledgment lost")
            return await original.handle_async_request(request)

    p.delivery_recovery.transport = LostGrantAcknowledgment()
    assert (await CohortEndpointGrantDelivery(p.delivery_recovery).deliver(q.slot)).receipt is None
    expire_child(p, grant, monkeypatch)

    class RejectGrantRetry(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            calls.append(request.url.path)
            if request.url.path == COHORT_GRANT_PATH:
                return httpx.Response(422)
            return await original.handle_async_request(request)

    p.delivery_recovery.transport = RejectGrantRetry()
    result = await worker.attempts.advance(q.slot, case, one_stage=True)
    assert COHORT_RETIRE_PATH in calls
    if grant_reached_miner:
        assert result["reason"] == "retirement_retained"
        assert worker.attempts.phase(q.slot, case) == "certification"
    else:
        # A local deadline is not evidence that the miner accepted or retired it.
        assert result["reason"] == "retirement_not_acknowledged"
        assert worker.attempts.decisions.retirement.retained(q.slot, case) is None
        assert worker.attempts.phase(q.slot, case) == "recovery"
        p.delivery_recovery.transport = original
        assert (await worker.attempts.advance(q.slot, case, one_stage=True))["reason"] == (
            "retirement_retained"
        )
    assert TRANSLATE_PATH not in calls and p.model.calls == 0
    assert canonical_json_bytes(selection_grant(*p.delivery_recovery.selection(q.slot)[:2])) == (
        canonical_json_bytes(grant)
    )


@pytest.mark.parametrize("retirement_held", [False, True])
async def test_answered_peer_retires_before_next_case_without_repeating_inference(
    scheduled, monkeypatch, retirement_held
):
    q, p = scheduled, scheduled.p
    worker = q.worker()
    assert (await worker._prepare(q.slot))[0] == "prepared"
    first, second = p.e.job.cases[:2]
    sent = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        q.slot, first.case_id
    )
    assert sent["status"] == "recovered" and p.model.calls == 1
    original_response = canonical_json_bytes(p.delivery_recovery.retained(q.slot, first.case_id))
    retirement = worker.attempts.decisions.retirement
    native_retire = retirement.retire

    async def held(slot, case_id):
        if case_id == first.case_id:
            return CohortRetirementOutcome("pending", "retirement_transport_unavailable")
        return await native_retire(slot, case_id)

    p.paths.clear()
    if retirement_held:
        monkeypatch.setattr(retirement, "retire", held)
        result = await worker.attempts.advance(q.slot, second.case_id)
        assert result["status"] == "pending"
        assert result["reason"] == "answered_peer_retirement_pending"
        assert p.model.calls == 1 and TRANSLATE_PATH not in p.paths
        assert p.delivery_recovery.retained(q.slot, second.case_id) is None
        monkeypatch.setattr(retirement, "retire", native_retire)
    result = await worker.attempts.advance(q.slot, second.case_id)
    assert result["status"] == "completed", result
    assert p.paths.index(COHORT_RETIRE_PATH) < p.paths.index(TRANSLATE_PATH)
    assert retirement.retained(q.slot, first.case_id) is not None
    assert p.model.calls == 2
    assert (
        canonical_json_bytes(p.delivery_recovery.retained(q.slot, first.case_id))
        == original_response
    )


async def test_media_failure_keeps_work_pending_without_secret_logs(scheduled):
    q = scheduled
    q.media_fail = True
    report = await q.worker().poll_once()
    assert report["retry_count"] > 0 and "bearer-secret" not in repr(report)
    assert report["last_retry_details"][0]["reason_code"] == "os_error"
    assert report["last_retry_details"][0]["source_frames"]
    assert all(
        frame["module"].startswith("umi.")
        for frame in report["last_retry_details"][0]["source_frames"]
    )
    assert q.p.model.calls == 0 and not q.s.calls
    assert q.worker().schedule.load(q.slot) is not None
    assert q.worker().schedule.complete(q.slot) is None
    q.media_fail = False
    terminal, _ = await finish(q)
    assert terminal.job_sha256 == digest(q.p.e.job)
    assert q.policy_calls == 1


async def test_case_failure_is_retained_in_report_after_prepare_failure(scheduled, monkeypatch):
    worker = scheduled.worker()
    assert (await worker._prepare(scheduled.slot))[0] == "prepared"

    async def missing_case(slot, case_id):
        raise FileNotFoundError("https://private.example/missing/bearer-secret")

    async def invalid_prepare(slot):
        raise ValueError("https://private.example/prepare/bearer-secret")

    monkeypatch.setattr(worker.attempts, "advance", missing_case)
    monkeypatch.setattr(worker, "_prepare", invalid_prepare)
    report = await worker.poll_once()
    assert report["last_retry_stage"] == "prepare"
    assert {(r["stage"], r["error_type"]) for r in report["retry_examples"]} == {
        ("case", "FileNotFoundError"),
        ("prepare", "ValueError"),
    }
    assert "bearer-secret" not in repr(report) and "private.example" not in repr(report)
    assert all(r["details"][0]["source_frames"] for r in report["retry_examples"])
    assert worker.schedule.complete(scheduled.slot) is None
    assert scheduled.p.model.calls == 0


async def test_rejected_miner_grant_stays_pending_without_retirement(scheduled, caplog):
    q, p = scheduled, scheduled.p
    original = p.delivery_recovery.transport

    class RejectGrant(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.path == COHORT_GRANT_PATH:
                return httpx.Response(422)
            return await original.handle_async_request(request)

    p.delivery_recovery.transport = RejectGrant()
    with caplog.at_level(logging.INFO, logger="umi.competition_cohort_grant_delivery"):
        report = await q.worker().poll_once()
    assert report["last_pending_reason"] == "miner_grant_http_422"
    assert report["retry_count"] == 0
    assert p.model.calls == 0
    assert q.worker().schedule.complete(q.slot) is None
    logs = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "umi.competition_cohort_grant_delivery"
    ]
    assert logs and all(log["reason_code"] == "miner_grant_http_422" for log in logs)
    assert all(log["selection_slot"] == q.slot for log in logs)
    assert all(log["miner_hotkey"] == p.e.job.submission.submission.hotkey for log in logs)
    assert all(
        set(log)
        == {
            "status",
            "selection_slot",
            "grant_sha256",
            "miner_hotkey",
            "reason_code",
            "chain_submission_authorized",
        }
        for log in logs
    )


@pytest.mark.parametrize(
    "kind",
    [
        "endpoint_schedule_assignment",
        "endpoint_terminal_case",
        "endpoint_terminal_selection",
        "endpoint_replay_object",
        "endpoint_replay_archive",
    ],
)
@pytest.mark.parametrize("after", [False, True])
async def test_interrupted_schedule_and_terminal_commits_resume(
    scheduled, monkeypatch, kind, after
):
    q, p = scheduled, scheduled.p
    db = p.delivery_recovery.journal.journal
    real_many, real_put = db.put_many, db.put
    fired = False

    def many(items, **kw):
        nonlocal fired
        items = tuple(items)
        if kind == "endpoint_schedule_assignment" and any(item[0] == kind for item in items):
            fired = True
            if after:
                real_many(items, **kw)
            raise OSError("commit reply lost")
        return real_many(items, **kw)

    def put(record_kind, key, value):
        nonlocal fired
        if record_kind == kind and kind != "endpoint_schedule_assignment":
            fired = True
            if after:
                real_put(record_kind, key, value)
            raise OSError("commit reply lost")
        return real_put(record_kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(db, "put_many", many)
        m.setattr(db, "put", put)
        for _ in range(8):
            report = await q.worker().poll_once()
            if fired:
                assert report["retry_count"] > 0
                break
        assert fired
    terminal, _ = await finish(q)
    assert len(terminal.cases) == len(p.e.job.cases)
    assert p.model.calls == len(p.e.job.cases)


async def add_second_assignment(q):
    from umi.competition_cohort_order_signer import CohortOrderParticipant

    from .test_competition_cohort_disposition import order as signed_order

    r, b = q.p.e.r, q.p.e.r.h.batch
    member = b["roster"].participants[1]
    order = signed_order(b["scenarios"][1]).order
    r.queue().select(
        order,
        CohortOrderParticipant(
            consent=member.record.request.consent,
            admission=member.admission,
            admission_snapshot=member.record.snapshot,
        ),
        r.h.source,
        await r.capture(),
    )
    await r.worker().poll_once()
    assert len(q.p.e.box.assignments()) == 2
    return next(slot for slot in q.p.e.box.assignments() if slot != q.slot)


async def test_unavailable_miner_does_not_starve_peer_after_restart(scheduled):
    q = scheduled
    other = await add_second_assignment(q)
    terminal, reports = await finish(q, maximum_polls=16, batch_size=1, concurrency=1)
    assert terminal is not None and any(r["retry_count"] for r in reports)
    assert q.worker().schedule.complete(other) is None
    assert q.p.model.calls == len(q.p.e.job.cases)
    # Once both inventories are known, one scan never assigns all parallel
    # slots to a single unavailable miner's cases.
    for _ in range(3):
        await q.worker(batch_size=2).poll_once()
    rows = q.worker().schedule.pending(2)
    assert rows and {row[1] for row in rows} == {other}
    assert len(rows) == 1


async def test_selected_request_precedes_unprepared_assignment_after_cursor_wrap(scheduled):
    q = scheduled
    other = await add_second_assignment(q)
    worker = q.worker()
    assert (await worker._prepare(q.slot))[0] == "prepared"
    worker.schedule.register(q.p.e.box.assignment(other), q.p.transport_policy)
    # The ordinary cursor would select the unrelated assignment first. Its
    # registration alone is not a runnable, signed request selection.
    with worker.schedule.journal.transaction() as db:
        db.execute(
            "INSERT INTO endpoint_schedule_cursor VALUES ('cases',?) "
            "ON CONFLICT(name) DO UPDATE SET position=excluded.position",
            (q.slot,),
        )
    rows = worker.schedule.pending(1)
    assert len(rows) == 1 and rows[0][1] == q.slot
    assert worker.schedule.load(other) is not None
    assert worker.schedule.journal.get("endpoint_recovery_selection", other) is None
    assert q.p.model.calls == 0
    terminal, _ = await finish(q, maximum_polls=16, batch_size=1, concurrency=1)
    assert terminal is not None
    assert worker.schedule.complete(other) is None


async def test_queue_selects_one_case_per_assignment_and_rotates_durably(scheduled):
    q = scheduled
    other = await add_second_assignment(q)
    schedule = q.worker().schedule
    for slot in q.p.e.box.assignments():
        schedule.register(q.p.e.box.assignment(slot), q.p.transport_policy)
    first = schedule.pending(2)
    second = q.worker().schedule.pending(2)
    assert {r[1] for r in first} == {q.slot, other}
    assert {r[1] for r in second} == {q.slot, other}
    assert {r[0] for r in first}.isdisjoint({r[0] for r in second})
    third = q.worker().schedule.pending(2)
    assert len({r[0] for r in (*first, *second, *third)}) == 6
    # Smaller batches must rotate assignments too, with both cursor levels
    # surviving reconstruction of the worker between every poll.
    single = [q.worker().schedule.pending(1)[0] for _ in range(6)]
    assert len({r[0] for r in single}) == 6
    assert all(a[1] != b[1] for a, b in pairwise(single))


async def test_capacity_growth_preserves_inventory_and_reserved_results(scheduled):
    q = scheduled
    small = q.worker(maximum_cases=1)
    report = await small.poll_once()
    assert report["retry_count"] > 0 and q.p.model.calls == 0
    with small.schedule.journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM endpoint_schedule_queue").fetchone()[0] == 0
    assert small.schedule.load(q.slot) is None
    terminal, _ = await finish(q, maximum_cases=len(q.p.e.job.cases))
    assert terminal is not None and q.p.model.calls == len(q.p.e.job.cases)


async def test_scheduler_stop_cancels_owned_read_and_recovers_inventory(scheduled, monkeypatch):
    q = scheduled
    entered, stop = asyncio.Event(), asyncio.Event()

    async def waiting(job, case):
        entered.set()
        await asyncio.Event().wait()

    worker = q.worker()
    worker.attempts.requests.video_source = waiting
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01))
    await asyncio.wait_for(entered.wait(), timeout=10)
    stop.set()
    await asyncio.wait_for(task, timeout=10)
    assert q.p.model.calls == 0 and worker.schedule.load(q.slot) is not None
    assert (await finish(q))[0] is not None


async def test_partial_quorum_recovers_same_request_without_reloading_media(scheduled):
    q = scheduled
    q.s.peers_offline = True
    assert (await q.worker().poll_once())["batch_pending"] > 0
    calls = len(q.media_calls)
    q.media_fail = q.policy_fail = True
    q.s.peers_offline = False
    terminal, _ = await finish(q)
    assert terminal is not None and len(q.media_calls) == calls


async def test_terminal_selection_rejects_changed_evidence(scheduled):
    q = scheduled
    terminal, _ = await finish(q)
    schedule = q.worker().schedule
    with schedule.journal.transaction() as db:
        raw = db.execute(
            "SELECT id,body FROM records WHERE kind='endpoint_terminal_case'"
        ).fetchone()
        assert raw is not None
    for field in (
        "selection_slot",
        "selection_sha256",
        "review_sha256",
        "decision_sha256",
        "case_id",
    ):
        damaged = json.loads(raw[1])
        damaged[field] = "ff" * 32
        with schedule.journal.transaction() as db:
            db.execute(
                "UPDATE records SET body=? WHERE kind='endpoint_terminal_case' AND id=?",
                (canonical_json_bytes(damaged), raw[0]),
            )
        with pytest.raises(ValueError, match="terminal case"):
            schedule.complete(q.slot)
        with schedule.journal.transaction() as db:
            db.execute(
                "UPDATE records SET body=? WHERE kind='endpoint_terminal_case' AND id=?",
                (raw[1], raw[0]),
            )
    assert schedule.complete(q.slot) == terminal
    with schedule.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='endpoint_terminal_case' AND id=?", (raw[0],))
    with pytest.raises(ValueError, match="missing a terminal case"):
        schedule.complete(q.slot)


async def test_single_writer_lock_prevents_second_scheduler_effects(scheduled):
    q = scheduled
    worker = q.worker()
    with (
        worker.schedule.owner.locked(digest(["umi-cohort-endpoint-scheduler/1"])),
        pytest.raises(BlockingIOError),
    ):
        await q.worker().poll_once()
    assert not q.media_calls and not q.s.calls and q.p.model.calls == 0


async def test_outage_keeps_completed_case_and_refreshes_only_missing_requests(
    scheduled, monkeypatch
):
    from umi.competition_cohort_request_files import RequestCompletionFiles
    from umi.competition_cohort_request_partial import (
        PartialRequestManifest,
        review_partial_request,
    )

    q, p = scheduled, scheduled.p
    first = q.worker()
    # A signed miner failure is also a completed response; it cannot be retried
    # for a better score when a different case needs a fresh transport window.
    p.model.fail = True
    assert (await first.poll_once())["cases_completed"] == 1
    p.model.fail = False
    completed = [
        c for c in p.e.job.cases if first.schedule.reference(q.slot, c.case_id) is not None
    ]
    assert len(completed) == 1
    saved = first.schedule.reference(q.slot, completed[0].case_id)
    partials = RequestCompletionFiles(first.schedule.journal.root.parent / "partial-exports")
    partial_sha = partials.publish_partial(
        first.schedule.owner, q.slot, completed_by_block=2**53 - 1
    )
    partial_manifest = PartialRequestManifest.model_validate_json(partials.objects(partial_sha))
    assert partial_manifest.cases == (saved,)
    selected, assignment, _ = p.delivery_recovery.selection(q.slot)
    original = canonical_json_bytes(selected)
    grant = selection_grant(selected, assignment)
    expire_child(p, grant, monkeypatch)
    missing = next(c for c in p.e.job.cases if c != completed[0])
    decisions = coordinator(q.s.d)
    certificate = (await decisions.advance(q.slot, missing.case_id)).certificate
    assert certificate.decision.disposition == "retry_required"
    review = decisions._review(q.slot, missing.case_id)
    # Fixture only advances chain/timelock clocks. The actual worker must build
    # and certify the replacement using the renewable media source itself.
    next_grant(q.s.d, grant, review, certificate, monkeypatch)
    q.media_fail = True
    report = await q.worker().poll_once()
    assert report["retry_count"] > 0 and p.model.calls == 1
    assert first.schedule.complete(q.slot) is None
    q.media_fail = False
    q.media_suffix = "?renewed=1"
    terminal, _ = await finish(q, maximum_polls=16)
    assert p.model.calls == len(p.e.job.cases)
    assert canonical_json_bytes(p.delivery_recovery.selection(q.slot)[0]) == original
    assert first.schedule.reference(q.slot, completed[0].case_id) == saved
    assert len({c.selection_slot for c in terminal.cases}) == len(p.e.job.cases)
    for case in terminal.cases:
        slot, chosen, _, _ = q.worker().attempts.current(q.slot, case.case_id)
        if case.case_id == completed[0].case_id:
            assert slot == q.slot
        else:
            assert chosen.grant.attempt.order.attempt_number == 2
            assert selected_request(chosen, case.case_id).video.url.endswith("?renewed=1")
    schedule = q.worker().schedule
    archive = EndpointReplayArchive.model_validate_json(
        canonical_json_bytes(schedule.journal.get("endpoint_replay_archive", q.slot))
    )
    objects = JournalEndpointObjects(schedule.journal)
    reviews = tuple(endpoint_archive_cases(archive, objects, p.c.policy))
    assert len(reviews) == len(terminal.cases)
    missing_review = next(r for r in reviews if r.retirement.case_id != completed[0].case_id)
    parent_sha = missing_review.selection.order.order.prior_decision.decision.review_sha256

    def missing_parent(sha):
        if sha == parent_sha:
            raise FileNotFoundError("parent evidence unavailable")
        return objects(sha)

    with pytest.raises(FileNotFoundError):
        tuple(endpoint_archive_cases(archive, missing_parent, p.c.policy))
    complete_sha = partials.publish_partial(schedule.owner, q.slot, completed_by_block=2**53 - 1)
    complete_manifest = PartialRequestManifest.model_validate_json(partials.objects(complete_sha))
    assert complete_manifest.item_count > partial_manifest.item_count
    assert complete_sha != partial_sha
    assert (
        review_partial_request(
            complete_sha,
            partials.objects,
            p.c.policy,
            assignment.certificate,
            opened_at_block=0,
            completed_by_block=2**53 - 1,
        )
        == assignment
    )

    def partial_missing_parent(sha):
        if sha == parent_sha:
            raise FileNotFoundError("partial predecessor unavailable")
        return partials.objects(sha)

    with pytest.raises(FileNotFoundError, match="partial predecessor"):
        review_partial_request(
            complete_sha,
            partial_missing_parent,
            p.c.policy,
            assignment.certificate,
            opened_at_block=0,
            completed_by_block=2**53 - 1,
        )


async def test_selected_case_advances_before_slow_assignment_preparation(scheduled, monkeypatch):
    q, p = scheduled, scheduled.p
    worker = q.worker()
    assert (await worker._prepare(q.slot))[0] == "prepared"
    entered, release = asyncio.Event(), asyncio.Event()
    original = worker._prepare

    async def slow_prepare(slot):
        entered.set()
        await release.wait()
        return await original(slot)

    monkeypatch.setattr(worker, "_prepare", slow_prepare)
    task = asyncio.create_task(worker.poll_once())
    try:
        await asyncio.wait_for(entered.wait(), timeout=120)
        # The real signed response and terminal reference must exist while the
        # next preparation is still waiting. Merely starting a task is not enough.
        assert p.model.calls == 1
        assert any(worker.schedule.reference(q.slot, c.case_id) for c in p.e.job.cases)
    finally:
        release.set()
        report = await task
    assert report["cases_completed"] == 1
    assert not report["request_closure_authorized"]


async def test_running_scheduler_completes_peer_while_other_preparation_waits(
    scheduled, monkeypatch
):
    q = scheduled
    other = await add_second_assignment(q)
    worker = q.worker(concurrency=1)
    assert (await worker._prepare(q.slot))[0] == "prepared"
    entered, release, complete, stop = (asyncio.Event() for _ in range(4))
    original = worker._prepare

    async def held_prepare(slot):
        if slot == other:
            entered.set()
            await release.wait()
        return await original(slot)

    def observe(report):
        if worker.schedule.journal.get("endpoint_replay_archive", q.slot) is not None:
            complete.set()

    monkeypatch.setattr(worker, "_prepare", held_prepare)
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01, report=observe))
    try:
        await asyncio.wait_for(entered.wait(), timeout=120)
        await asyncio.wait_for(complete.wait(), timeout=180)
        assert not release.is_set()
        assert not task.done()
        terminal = worker.schedule.complete(q.slot)
        assert terminal is not None and len(terminal.cases) == len(q.p.e.job.cases)
        assert q.p.model.calls == len(q.p.e.job.cases)
        assert worker.schedule.complete(other) is None
        archive = EndpointReplayArchive.model_validate_json(
            canonical_json_bytes(worker.schedule.journal.get("endpoint_replay_archive", q.slot))
        )
        objects = JournalEndpointObjects(worker.schedule.journal)
        assert len(tuple(endpoint_archive_cases(archive, objects, q.p.c.policy))) == len(
            q.p.e.job.cases
        )
    finally:
        stop.set()
        release.set()
        await asyncio.wait_for(task, timeout=120)


async def test_running_scheduler_keeps_owner_until_cancelled_operation_drains(
    scheduled, monkeypatch
):
    q = scheduled
    worker = q.worker()
    entered, cleaning, release, stop = (asyncio.Event() for _ in range(4))

    async def held_prepare(slot):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()

    monkeypatch.setattr(worker, "_prepare", held_prepare)
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01))
    try:
        await asyncio.wait_for(entered.wait(), timeout=120)
        stop.set()
        await asyncio.wait_for(cleaning.wait(), timeout=120)
        with pytest.raises(BlockingIOError):
            await q.worker().poll_once()
        assert not task.done()
        assert q.p.model.calls == 0
    finally:
        release.set()
        stop.set()
        await asyncio.wait_for(task, timeout=120)
    terminal, _ = await finish(q)
    assert terminal is not None
    assert q.p.model.calls == len(q.p.e.job.cases)


async def test_running_scheduler_discovers_work_beside_rejected_grants(scheduled, monkeypatch):
    q = scheduled
    other = await add_second_assignment(q)
    worker = q.worker(concurrency=1)
    assert (await worker._prepare(q.slot))[0] == "prepared"
    original_transport = q.p.delivery_recovery.transport

    class RejectGrant(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.path == COHORT_GRANT_PATH:
                return httpx.Response(422)
            return await original_transport.handle_async_request(request)

    q.p.delivery_recovery.transport = RejectGrant()
    discovered, rejected, stop = (asyncio.Event() for _ in range(3))
    original_prepare = worker._prepare

    async def observe_prepare(slot):
        if slot == other:
            discovered.set()
        return await original_prepare(slot)

    def observe(report):
        assert report.get("in_flight_operations", 0) <= 4
        assert all(n <= 1 for n in report.get("in_flight_phase_counts", {}).values())
        if report.get("last_pending_reason") == "miner_grant_http_422":
            rejected.set()

    monkeypatch.setattr(worker, "_prepare", observe_prepare)
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01, report=observe))
    try:
        await asyncio.wait_for(rejected.wait(), timeout=180)
        await asyncio.wait_for(discovered.wait(), timeout=180)
        assert worker.schedule.complete(q.slot) is None
        assert q.p.model.calls == 0
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=120)


async def test_busy_assignment_does_not_advance_its_unstarted_case_cursor(scheduled):
    q = scheduled
    other = await add_second_assignment(q)
    schedule = q.worker().schedule
    for slot in q.p.e.box.assignments():
        schedule.register(q.p.e.box.assignment(slot), q.p.transport_policy)
    before = schedule.pending(2)
    # While one assignment owns an in-flight operation, only the ready peer's
    # cases may rotate. Reconstruct the journal on every pass as after restart.
    ready = [q.worker().schedule.pending(1, exclude=(q.slot,))[0] for _ in range(3)]
    assert all(row[1] == other for row in ready)
    assert len({row[0] for row in ready}) == 3
    resumed = q.worker().schedule.pending(1, exclude=(other,))[0]
    initial = next(row for row in before if row[1] == q.slot)
    assert resumed[1] == q.slot and resumed[0] != initial[0]
    # Exactly the next original case is chosen; excluded polls cannot skip it.
    with schedule.journal.transaction() as db:
        ordered = [
            row[0]
            for row in db.execute(
                "SELECT obligation FROM endpoint_schedule_queue WHERE slot=? ORDER BY obligation",
                (q.slot,),
            )
        ]
    assert resumed[0] == ordered[(ordered.index(initial[0]) + 1) % len(ordered)]


async def test_running_scheduler_retry_binds_selection_without_private_text(scheduled, monkeypatch):
    q = scheduled
    worker = q.worker(concurrency=1)
    assert (await worker._prepare(q.slot))[0] == "prepared"
    observed, stop = asyncio.Event(), asyncio.Event()
    reports = []

    async def failed_case(row, **kwargs):
        raise ValueError("PRIVATE_DISPATCH_EXCEPTION")

    def report(value):
        reports.append(value)
        if value.get("last_retry_slot") == q.slot:
            observed.set()

    monkeypatch.setattr(worker, "_case", failed_case)
    task = asyncio.create_task(worker.run(stop, poll_seconds=0.01, report=report))
    try:
        await asyncio.wait_for(observed.wait(), 180)
        value = next(r for r in reports if r.get("last_retry_slot") == q.slot)
        assert value["last_retry_stage"] == "dispatch"
        assert value["last_retry_type"] == "ValueError"
        assert value["retry_examples"][0]["slot"] == q.slot
        assert "PRIVATE_DISPATCH_EXCEPTION" not in canonical_json_bytes(value).decode()
        assert worker.schedule.complete(q.slot) is None
        assert q.p.model.calls == 0
    finally:
        stop.set()
        await asyncio.wait_for(task, 120)


async def test_rolling_restart_finishes_interrupted_terminal_selection(scheduled, monkeypatch):
    q, p = scheduled, scheduled.p
    journal = p.delivery_recovery.journal.journal
    original_put = journal.put
    interrupted = False

    def put(kind, key, value):
        nonlocal interrupted
        if kind == "endpoint_terminal_selection":
            interrupted = True
            raise OSError("interrupted before aggregate terminal commit")
        return original_put(kind, key, value)

    with monkeypatch.context() as patch:
        patch.setattr(journal, "put", put)
        for _ in range(12):
            await q.worker().poll_once()
            if interrupted:
                break
    assert interrupted
    assert journal.get("endpoint_terminal_selection", q.slot) is None
    worker = q.worker()
    assert worker.schedule.pending(16) == ()
    calls = list(p.paths), len(q.s.calls), p.model.calls
    p.c.finality.fail = True
    p.finality.blocks.clear()
    q.s.peers_offline = q.media_fail = q.policy_fail = True
    active = {}
    try:
        await worker._rolling_poll(active)
        assert q.slot in active, "completed cases must still reach aggregate recovery"
        await asyncio.wait_for(asyncio.gather(*(task for _, task in active.values())), 180)
        report = await worker._rolling_poll(active)
        assert report["assignments_complete"] == 1
        archive = EndpointReplayArchive.model_validate(
            journal.get("endpoint_replay_archive", q.slot)
        )
        reviews = tuple(
            endpoint_archive_cases(archive, JournalEndpointObjects(journal), p.c.policy)
        )
        assert len(reviews) == len(p.e.job.cases)
        assert (list(p.paths), len(q.s.calls), p.model.calls) == calls
    finally:
        for _, task in active.values():
            task.cancel()
        await asyncio.gather(*(task for _, task in active.values()), return_exceptions=True)
