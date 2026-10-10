"""Native retained execution -> recurring exports -> complete request closure.

Registration/finality and inference are the parent fixture's synthetic ports.
Signing, journals, immutable delivery and request replay are native.
"""

import asyncio
import json
import threading
from contextlib import ExitStack
from functools import partial
from unittest.mock import AsyncMock

import pytest

from umi.competition_cohort_endpoint import endpoint_obligation_sha256
from umi.competition_cohort_endpoint_decision import (
    SignedCohortEndpointCaseDecision,
    parse_case_review,
)
from umi.competition_cohort_endpoint_selection import case_record_key
from umi.competition_cohort_endpoint_terminal import EndpointTerminalSelection
from umi.competition_cohort_execution_journal import execution_step_key
from umi.competition_cohort_order_signer import order_slot
from umi.competition_cohort_request_export_worker import RequestExportWorker
from umi.competition_cohort_request_files import RequestCompletionFiles
from umi.competition_cohort_request_partial import PartialRequestManifest, review_partial_request
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .cohort_replication_support import Replica
from .test_competition_cohort_request_phase import request_owner as request_owner
from .test_competition_cohort_service_grants import base_policy as base_policy
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
from .test_competition_cohort_service_grants import service as service
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_closed as service_closed
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group
from .test_open_competition import wallet


@pytest.fixture
def exporting(request_owner, tmp_path):
    h, calls = request_owner, []
    h.files = RequestCompletionFiles(tmp_path / "delivered")
    h.workers = []
    for name in ("Charlie", "Dave"):
        owners = []
        who = identity(wallet(name).hotkey.ss58_address)
        for (order_sha, evaluator), owner in h.b["owners"].items():
            if evaluator != who:
                continue
            order = next(o for o in h.b["orders"] if digest(o) == order_sha)
            slot = order_slot(order.order)
            with owner.journal.transaction() as db:
                db.execute(
                    "DELETE FROM records WHERE "
                    "kind IN ('request_terminal', 'request_terminal_intent')"
                )
            archive = h.b["endpoint_archives"][(order_sha, evaluator)]
            if archive is not None:
                owner.journal.put("endpoint_replay_archive", slot, archive)
            owners.append(owner)

        async def sign(body, name=name):
            calls.append((name, digest(body)))
            return sign_object(body, wallet(name))

        h.workers.append(
            RequestExportWorker(
                owners,
                h.provider,
                sign,
                h.files,
                RoundJournal(tmp_path / ("exporter-" + name), {"name": name}),
                batch_size=1,
            )
        )
    h.exports_signed = calls
    h.connect = lambda: connect(h)
    h.connect()
    return h


def connect(h):
    h.source.orders = partial(h.files.orders, h.b["roster"])
    h.source.terminals = h.files.terminal
    h.source.external = h.files.objects


async def publish_all(h):
    for worker in h.workers:
        report = await worker.poll_once()
        assert report["retry_count"] == 0, report
        assert report["assignments_exported"] == len(worker.executions), report


async def test_exports_use_owned_finality_without_fresh_membership(exporting, monkeypatch):
    h = exporting
    current = AsyncMock(return_value=h.block)
    collect = AsyncMock(side_effect=OSError("membership RPC unavailable"))
    monkeypatch.setattr(h.provider, "current_finalized_block", current, raising=False)
    monkeypatch.setattr(h.provider, "collect", collect)
    await publish_all(h)
    assert current.await_count == len(h.workers)
    collect.assert_not_awaited()
    assert h.window().completion == "complete"


async def test_export_finality_failure_does_not_fall_back_to_membership(exporting, monkeypatch):
    h = exporting
    current = AsyncMock(side_effect=OSError("owned finality unavailable"))
    collect = AsyncMock()
    monkeypatch.setattr(h.provider, "current_finalized_block", current, raising=False)
    monkeypatch.setattr(h.provider, "collect", collect)
    with pytest.raises(OSError, match="owned finality unavailable"):
        await h.workers[0].poll_once()
    collect.assert_not_awaited()
    assert not h.exports_signed
    assert list(h.files.orders(h.b["roster"])) == []


@pytest.mark.parametrize("block", [True, -1, 2**53, "100", None])
async def test_export_rejects_invalid_finalized_height(exporting, monkeypatch, block):
    h = exporting
    monkeypatch.setattr(
        h.provider, "current_finalized_block", AsyncMock(return_value=block), raising=False
    )
    with pytest.raises(ValueError, match="finalized block is invalid"):
        await h.workers[0].poll_once()
    assert not h.exports_signed


async def test_exports_still_wait_for_finality_to_cover_completed_work(exporting, monkeypatch):
    h = exporting
    current = AsyncMock(return_value=0)
    monkeypatch.setattr(h.provider, "current_finalized_block", current, raising=False)
    report = await h.workers[0].poll_once()
    assert report["assignments_exported"] == 0
    assert report["retry_count"] == len(h.workers[0].executions)
    assert list(h.files.orders(h.b["roster"])) == []
    count = len(h.exports_signed)
    current.return_value = h.block
    report = await h.workers[0].poll_once()
    assert report["assignments_exported"] == len(h.workers[0].executions)
    assert len(h.exports_signed) == count
    await publish_all(h)
    assert h.window().completion == "complete"


async def test_export_page_reads_while_execution_writer_is_busy(exporting):
    worker = exporting.workers[0]
    owner = worker.executions[0]
    expected = tuple(owner.journal.keys("assignment")[: worker.batch_size])
    entered, release = threading.Event(), threading.Event()

    def writer():
        with owner.journal.transaction() as db:
            db.execute("INSERT INTO holds VALUES ('unrelated-uncommitted-hold')")
            entered.set()
            assert release.wait(60)

    pending = asyncio.create_task(asyncio.to_thread(writer))
    try:
        assert await asyncio.to_thread(entered.wait, 30)
        assert await asyncio.wait_for(asyncio.to_thread(worker._page, owner), 10) == expected
    finally:
        release.set()
        await pending
    # Paging survives reopening its own cursor; no execution state was changed.
    assert worker._page(owner) == expected


async def test_late_evaluator_exports_close_original_work_after_restart(exporting):
    h = exporting
    assert list(h.files.orders(h.b["roster"])) == []
    await h.workers[0].poll_once()
    assert h.window().completion == "pending"
    assert h.c.queue.retained_seal() is not None
    h.block += 30000
    await h.workers[1].poll_once()
    # Reopen the request reader, then deliver originals without shared memory
    # or access to the evaluator databases.
    h.source = h.reopen()
    h.files = RequestCompletionFiles(h.files.root)
    h.connect()
    h.b["objects"].clear()
    progress = h.sample()
    assert progress.completion == "complete"
    assert h.source.read(progress).record.progress == progress
    count = len(h.exports_signed)
    await publish_all(h)
    assert len(h.exports_signed) == count


async def test_lost_export_ack_reuses_terminal_and_repairs_delivery(exporting, monkeypatch):
    h = exporting
    original = h.files.publish
    failing = True

    def lost_ack(*args, **kwargs):
        original(*args, **kwargs)
        if failing:
            raise OSError("synthetic acknowledgement loss with private bearer URL")

    monkeypatch.setattr(h.files, "publish", lost_ack)
    report = await h.workers[0].poll_once()
    assert report["retry_count"] == len(h.workers[0].executions)
    assert report["last_failure"]["reason_code"] == "os_error"
    assert report["last_failure"]["source_frames"]
    assert "private bearer" not in json.dumps(report)
    count = len(h.exports_signed)
    delivered = {
        digest(order): canonical_json_bytes(
            h.files.terminal(order, wallet("Charlie").hotkey.ss58_address)
        )
        for order in h.files.orders(h.b["roster"])
    }
    failing = False
    # Reset all process-local state while keeping only original journals/files.
    worker = h.workers[0]
    h.workers[0] = RequestExportWorker(
        worker.executions,
        worker.provider,
        worker.sign,
        RequestCompletionFiles(h.files.root),
        RoundJournal(worker.journal.root, {"name": "Charlie"}),
        batch_size=1,
    )
    assert (await h.workers[0].poll_once())["retry_count"] == 0
    assert len(h.exports_signed) == count
    for order in h.files.orders(h.b["roster"]):
        terminal = h.files.terminal(order, wallet("Charlie").hotkey.ss58_address)
        assert canonical_json_bytes(terminal) == delivered[digest(order)]


async def test_missing_local_steps_or_endpoint_archive_stays_pending(exporting):
    h = exporting
    owner = h.workers[0].executions[0]
    with owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='endpoint_replay_archive'")
    # Recovery may own this lock while producing the missing endpoint archive.
    # Pending exports must not compete with that producer for writer ownership.
    with owner.locked(owner.journal.keys("assignment")[0]):
        report = await h.workers[0].poll_once()
    assert report["retry_count"] == 0
    assert report["assignments_pending"] >= 1
    assert report["request_closure_authorized"] is False
    assert h.window().completion == "pending"
    # Another completed assignment is still exported in the same batch.
    assert len(h.exports_signed) == len(h.workers[0].executions) - 1


async def test_slow_certificate_does_not_block_other_completed_exports(exporting):
    h = exporting
    worker = h.workers[0]
    assert len(worker.executions) > 1
    entered, release = asyncio.Event(), asyncio.Event()
    sign = worker.sign
    first = True

    async def delayed(body):
        nonlocal first
        if first:
            first = False
            entered.set()
            await release.wait()
        return await sign(body)

    worker.sign = delayed
    task = asyncio.create_task(worker.poll_once())
    try:
        await asyncio.wait_for(entered.wait(), timeout=60)

        async def delivered():
            while not list(h.files.orders(h.b["roster"])):
                await asyncio.sleep(0.01)

        await asyncio.wait_for(delivered(), timeout=60)
        assert not task.done()
        # Partial certificates do not authorize closure of the original work.
        assert h.window().completion == "pending"
    finally:
        release.set()
        report = await asyncio.wait_for(task, timeout=120)
    assert report["assignments_exported"] == len(worker.executions)
    count = len(h.exports_signed)
    await worker.poll_once()
    assert len(h.exports_signed) == count


async def test_parallel_export_cancellation_drains_owned_threads(exporting, monkeypatch):
    from umi.concurrency import run_owned_thread

    worker = exporting.workers[0]
    worker.concurrency = 2
    entered, release = threading.Event(), threading.Event()
    active, peak = 0, 0

    def blocked():
        assert release.wait(60)

    async def export(owner, slot, block):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 2:
            entered.set()
        try:
            await run_owned_thread(blocked)
        finally:
            active -= 1
        return True

    monkeypatch.setattr(worker, "_export", export)
    task = asyncio.create_task(worker.poll_once())
    try:
        assert await asyncio.to_thread(entered.wait, 60)
        assert peak == 2
        task.cancel()
        await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done()
        assert worker.serial.locked()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=120)
    assert active == 0
    assert not worker.serial.locked()


async def test_partial_object_copy_never_publishes_terminal_index(exporting, monkeypatch):
    h = exporting
    original = h.files.objects.publish
    copied = 0

    def fail(key, source):
        nonlocal copied
        original(key, source)
        copied += 1
        raise OSError("synthetic disk full")

    monkeypatch.setattr(h.files.objects, "publish", fail)
    result = await h.workers[0].poll_once()
    assert copied and result["retry_count"]
    assert not list(h.files.orders(h.b["roster"]))
    count = len(h.exports_signed)
    monkeypatch.setattr(h.files.objects, "publish", original)
    await h.workers[0].poll_once()
    assert len(h.exports_signed) == count
    await h.workers[1].poll_once()
    assert h.window().completion == "complete"


async def test_exporter_keeps_retrying_when_finality_returns(exporting):
    h = exporting
    h.offline = True
    stop = asyncio.Event()
    task = asyncio.create_task(h.workers[0].run(stop, poll_seconds=0.01))
    try:
        await asyncio.sleep(0.03)
        assert not task.done()
        assert not h.exports_signed
        h.offline = False

        async def signed():
            while not h.exports_signed:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(signed(), timeout=10)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=10)


async def test_unchanged_exports_reuse_work_and_repair_missing_original(exporting, monkeypatch):
    h = exporting
    await publish_all(h)
    calls = len(h.exports_signed)
    # Only private durable publication receipts survive this process restart.
    h.files = RequestCompletionFiles(h.files.root)
    for worker in h.workers:
        worker.files = h.files
    h.connect()
    original = h.files.publish
    exported = []

    def record(*args, **kwargs):
        exported.append(digest(args[0]))
        return original(*args, **kwargs)

    monkeypatch.setattr(h.files, "publish", record)
    # Settlement may hold every execution lock while reviewing quality. A
    # sealed export must remain available without competing for those locks.
    with ExitStack() as locks:
        for worker in h.workers:
            for owner in worker.executions:
                for slot in worker._page(owner):
                    locks.enter_context(owner.locked(slot))
        await publish_all(h)
    assert not exported
    order = next(h.files.orders(h.b["roster"]))
    terminal = h.files.terminal(order, wallet("Charlie").hotkey.ss58_address)
    path = h.files.objects._path(terminal.terminal.execution_archive_sha256)
    before = path.read_bytes()
    path.unlink()
    await publish_all(h)
    assert digest(terminal) in exported
    assert path.read_bytes() == before
    assert len(h.exports_signed) == calls
    # The receiver still independently replays the complete signed originals.
    h.source = h.reopen()
    h.connect()
    h.b["objects"].clear()
    progress = h.window()
    assert progress.completion == "complete"
    assert h.source.read(progress).record.progress == progress


async def test_restart_cache_never_accepts_changed_export_or_verification_context(
    exporting, monkeypatch
):
    h = exporting
    await publish_all(h)
    order = next(h.files.orders(h.b["roster"]))
    terminal = h.files.terminal(order, wallet("Charlie").hotkey.ss58_address)
    policy = h.workers[0].executions[0].policy
    args = dict(policy_sha256=digest(policy), opened_at_block=0, completed_by_block=h.block)
    restarted = RequestCompletionFiles(h.files.root)
    assert restarted.current(digest(terminal), **args)
    assert not restarted.current(digest(terminal), **(args | {"policy_sha256": "f" * 64}))
    assert not restarted.current(digest(terminal), **(args | {"opened_at_block": h.block}))
    assert not restarted.current(digest(terminal), **(args | {"completed_by_block": 0}))
    smaller = RequestCompletionFiles(h.files.root, maximum_bytes=h.files.maximum_bytes // 2)
    assert not smaller.current(digest(terminal), **args)

    path = h.files.objects._path(terminal.terminal.execution_archive_sha256)
    before = path.read_bytes()
    path.write_bytes(b"{}")
    for worker in h.workers:
        worker.files = restarted
    reports = [await worker.poll_once() for worker in h.workers]
    assert sum(report["retry_count"] for report in reports) > 0
    assert all(report["request_closure_authorized"] is False for report in reports)
    assert path.read_bytes() == b"{}"
    # Restoring the exact original requires native replay before reuse resumes.
    path.write_bytes(before)
    assert not restarted.current(digest(terminal), **args)
    await publish_all(h)
    assert restarted.current(digest(terminal), **args)


@pytest.mark.parametrize("failure", ["corrupt", "symlink", "write_unavailable"])
async def test_disposable_publication_cache_failure_does_not_hold_exports(
    exporting, monkeypatch, failure
):
    from umi import competition_cohort_request_reuse as reuse

    h = exporting
    if failure == "write_unavailable":

        def unavailable(*args, **kwargs):
            raise OSError("synthetic cache write unavailable")

        monkeypatch.setattr(reuse, "publish_private_model", unavailable)
    await publish_all(h)
    count = len(h.exports_signed)
    cache = h.files.root / ".publication-verification"
    if failure == "corrupt":
        for path in cache.glob("*.json"):
            path.write_bytes(b"{broken")
    elif failure == "symlink":
        target = h.files.root / "invalid-cache-target"
        target.write_bytes(b"must remain untouched")
        for path in cache.glob("*.json"):
            path.unlink()
            path.symlink_to(target)

    restarted = RequestCompletionFiles(h.files.root)
    replayed = []
    original = restarted.publish

    def replay(*args, **kwargs):
        replayed.append(digest(args[0]))
        return original(*args, **kwargs)

    monkeypatch.setattr(restarted, "publish", replay)
    for worker in h.workers:
        worker.files = restarted
    await publish_all(h)
    assert replayed
    assert len(h.exports_signed) == count
    assert h.window().completion == "complete"
    if failure == "symlink":
        assert target.read_bytes() == b"must remain untouched"


def unfinished_endpoint(h):
    """Retain fixture originals as the endpoint owner does, withholding one retirement."""
    worker = h.workers[0]
    owner = next(
        e
        for e in worker.executions
        if e.assignment(
            e.journal.keys("assignment")[0]
        ).certificate.order.submission.submission.track
        == "endpoint"
    )
    slot = owner.journal.keys("assignment")[0]
    assignment, job = owner.assignment_and_job(slot)
    for evaluator in assignment.certificate.order.evaluators:
        if identity(evaluator) != identity(owner.config.signer):
            signed = h.b["terminals"][(digest(assignment.certificate), identity(evaluator))]
            h.files.publish(
                signed,
                h.b["objects"].__getitem__,
                h.b["policy"],
                opened_at_block=0,
                completed_by_block=h.block,
            )
    archive = h.b["endpoint_archives"][
        (digest(assignment.certificate), identity(owner.config.signer))
    ]
    terminal = EndpointTerminalSelection.model_validate_json(
        h.b["objects"][archive.terminal_sha256]
    )
    with owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='endpoint_replay_archive'")
    for ref in terminal.cases:
        review = parse_case_review(h.b["objects"][ref.review_sha256])
        owner.journal.put("endpoint_recovery_selection", slot, review.selection)
        owner.journal.put(
            "endpoint_recovered_case",
            case_record_key(review.selection, ref.case_id),
            review.recovered,
        )
    for ref in terminal.cases[:-1]:
        retain_case(h, owner, job, ref)
    return worker, owner, slot, assignment, job, terminal


def retain_case(h, owner, job, ref):
    key = digest(["umi-cohort-endpoint-case-review-record/1", ref.selection_sha256, ref.case_id])
    owner.journal.put(
        "endpoint_case_review", key, parse_case_review(h.b["objects"][ref.review_sha256])
    )
    owner.journal.put(
        "endpoint_case_decision",
        key,
        SignedCohortEndpointCaseDecision.model_validate_json(h.b["objects"][ref.decision_sha256]),
    )
    owner.journal.put("endpoint_terminal_case", endpoint_obligation_sha256(job, ref.case_id), ref)


def review_partial(h, files, refsha, assignment):
    return review_partial_request(
        refsha,
        files.objects,
        h.b["policy"],
        assignment.certificate,
        opened_at_block=0,
        completed_by_block=h.block,
    )


async def test_partial_originals_survive_replication_without_fabricated_terminal(
    exporting, tmp_path
):
    h = exporting
    worker, owner, slot, assignment, job, terminal = unfinished_endpoint(h)
    # Partial publication must read while the endpoint producer owns its job lock.
    with owner.locked(slot):
        assert await worker._export(owner, slot, h.block) is False
    assert h.exports_signed == []
    refs = h.files.partial(h.b["roster"], digest(job.submission.submission))
    assert len(refs) == 1
    manifest = PartialRequestManifest.model_validate_json(h.files.objects(refs[0]))
    assert len(manifest.cases) == len(job.cases) - 1
    assert len(manifest.responses) == len(job.cases)
    assert len(manifest.steps) == len(job.cases)
    assert set(r.case_id for r in manifest.responses) - set(c.case_id for c in manifest.cases) == {
        terminal.cases[-1].case_id
    }
    assert not manifest.request_completion_authorized
    assert not manifest.chain_submission_authorized
    assert h.files.terminal(assignment.certificate, owner.config.signer) is None
    replica = Replica(tmp_path / "partial-copy")
    replica.copy(h.files.root, tmp_path / "partial-import", "requests")
    delivered = RequestCompletionFiles(tmp_path / "partial-import")
    assert delivered.partial(h.b["roster"], digest(job.submission.submission)) == refs
    assert review_partial(h, delivered, refs[0], assignment) == assignment
    assert h.window().completion == "pending"


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
async def test_configured_lifecycle_reads_delivered_partial_originals(exporting, tmp_path):
    from pathlib import Path
    from types import SimpleNamespace

    from umi.competition_cohort_lifecycle_host import LifecycleHost
    from umi.competition_cohort_preparation import PreparedCohortRound
    from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
    from umi.competition_settlement import PromotionHeadBinding
    from umi.policy import scoring_policy_hash
    from umi.private_files import publish_private_model

    from .test_competition_execution import boundary

    h = exporting
    worker, owner, slot, _, job, _ = unfinished_endpoint(h)
    assert await worker._export(owner, slot, h.block) is False
    roster, sources = h.b["roster"], h.sources
    prepared = PreparedCohortRound(
        schema="umi-prepared-cohort-round/1",
        roster=roster,
        promotion_head=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="a1" * 32,
            model_sha256=roster.round.incumbent_model_sha256,
            contributor_hotkey=None,
        ),
        observation=boundary(roster.round.prepared_at_block),
    )
    publish_private_model(Path(sources.round_directory) / (h.cohort + ".json"), prepared)
    publish_private_model(
        Path(sources.transport_directory) / (scoring_policy_hash(h.b["transport"]) + ".json"),
        h.b["transport"],
    )
    terms_key = digest(h.c.terms)
    SettlementEvidenceFiles(Path(sources.objects_directory)).publish(
        terms_key, lambda _: canonical_json_bytes(h.c.terms)
    )
    catalog_key = h.c.queue.config.catalog_sha256
    host = SimpleNamespace(
        config=SimpleNamespace(
            sources=sources,
            maximum_state_bytes=64 * 1024**2,
            settlement_history_directory=str(tmp_path / "configured-request-handoff"),
        ),
        maximum_bytes=64 * 1024**2,
        root=tmp_path / "configured-request-owner",
        files=h.files,
        service=SimpleNamespace(
            intake=h.intake,
            queues={catalog_key: h.c.queue},
            config=SimpleNamespace(
                series=h.b["history"].plan,
                manifest=SimpleNamespace(
                    cohorts=(
                        SimpleNamespace(
                            cohort_sha256=h.cohort,
                            catalog_sha256s=(catalog_key,),
                            terms_sha256=terms_key,
                        ),
                    ),
                ),
                admission_owner=SimpleNamespace(maximum_sample_gap_blocks=300),
            ),
        ),
    )
    source = LifecycleHost._request_source(host, h.cohort)
    key = digest(job.submission.submission)
    refs = source.partial_source(key)
    assert refs == h.files.partial(roster, key) and refs
    assert source.inventory_source.func == h.files.inventories
    assert source.inventory_source.args == (roster,)
    assert source.terminals(owner.assignment(slot).certificate, owner.config.signer) is None
    manifest = PartialRequestManifest.model_validate_json(source._source(refs[0]))
    assert manifest.responses and manifest.cases
    source.publish_inventory_cutoff(SimpleNamespace(observation=boundary(h.block)))
    cutoff_path = Path(host.config.settlement_history_directory) / (
        h.cohort + "-inventory-cutoff.json"
    )
    original_cutoff = cutoff_path.read_bytes()
    source.publish_inventory_cutoff(SimpleNamespace(observation=boundary(h.block)))
    assert cutoff_path.read_bytes() == original_cutoff
    from umi.competition_cohort_request_inventory import RequestInventoryCutoff

    cutoff = RequestInventoryCutoff.model_validate_json(original_cutoff)
    assert cutoff.cohort_sha256 == h.cohort
    assert cutoff.policy_sha256 == digest(h.b["policy"])
    assert cutoff.observation == boundary(h.block)


async def test_partial_restart_adds_immutable_snapshot_and_complete_export_takes_over(exporting):
    h = exporting
    worker, owner, slot, assignment, job, terminal = unfinished_endpoint(h)
    assert await worker._export(owner, slot, h.block) is False
    originals = {
        p: p.read_bytes() for p in h.files.root.rglob("*.json") if ".publication" not in str(p)
    }
    first = h.files.partial(h.b["roster"], digest(job.submission.submission))
    retain_case(h, owner, job, terminal.cases[-1])
    worker.files = RequestCompletionFiles(h.files.root)
    assert await worker._export(owner, slot, h.block) is False
    second = worker.files.partial(h.b["roster"], digest(job.submission.submission))
    assert second != first
    assert review_partial(h, worker.files, second[0], assignment) == assignment
    assert all(p.read_bytes() == raw for p, raw in originals.items())
    archive = h.b["endpoint_archives"][
        (digest(assignment.certificate), identity(owner.config.signer))
    ]
    owner.journal.put("endpoint_replay_archive", slot, archive)
    assert await worker._export(owner, slot, h.block) is True
    assert worker.files.partial(h.b["roster"], digest(job.submission.submission)) == ()
    assert worker.files.objects(first[0])
    assert worker.files.objects(second[0])
    assert len(h.exports_signed) == 1


def authenticated_inventory_exports(h, worker, *, selected_at_block=None):
    from umi.competition_cohort_request_inventory import RequestInventoryCutoff
    from umi.competition_execution import execution_boundary

    from .test_competition_cohort_service_queue import capture

    proofs = []

    async def publish(observation):
        proofs.append(observation)

    worker.publish_inventory_proof = publish
    cutoff = RequestInventoryCutoff(
        schema="umi-private-request-inventory-cutoff/1",
        cohort_sha256=h.cohort,
        policy_sha256=digest(h.b["policy"]),
        observation=execution_boundary(
            capture(h.block - 1 if selected_at_block is None else selected_at_block)
        ),
    )
    worker.inventory_cutoff = lambda _: cutoff
    return proofs


async def test_inventory_unchanged_partial_needs_new_post_cutoff_snapshot(exporting, tmp_path):
    from umi.competition_cohort_request_inventory import review_request_inventory

    h = exporting
    worker, owner, slot, assignment, job, _ = unfinished_endpoint(h)
    proofs = authenticated_inventory_exports(h, worker, selected_at_block=h.block)
    submission = digest(job.submission.submission)
    cutoff = h.block
    assert await worker._export(owner, slot, h.block) is False
    with pytest.raises(FileNotFoundError, match="post-cutoff"):
        h.files.inventories(
            h.b["roster"], submission, selected_at_block=cutoff, completed_by_block=h.block
        )
    original_manifests = h.files.partial(h.b["roster"], submission)
    h.block += 1
    assert await worker._export(owner, slot, h.block) is False
    refs = h.files.inventories(
        h.b["roster"], submission, selected_at_block=cutoff, completed_by_block=h.block
    )
    assert len(refs) == 1 and len(proofs) == 1
    reviewed, manifest, signed = review_request_inventory(
        refs[0],
        h.files.objects,
        h.b["policy"],
        assignment.certificate,
        opened_at_block=0,
        selected_at_block=cutoff,
        completed_by_block=h.block,
    )
    assert reviewed == assignment
    assert signed.inventory.manifest_sha256 in original_manifests
    assert manifest.assignment_sha256 == digest(assignment)
    assert not signed.inventory.request_completion_authorized
    calls = len(h.exports_signed)
    worker.files = RequestCompletionFiles(h.files.root)
    assert await worker._export(owner, slot, h.block) is False
    assert len(h.exports_signed) == calls
    replica = Replica(tmp_path / "inventory-copy")
    replica.copy(h.files.root, tmp_path / "inventory-import", "requests")
    delivered = RequestCompletionFiles(tmp_path / "inventory-import")
    assert (
        delivered.inventories(
            h.b["roster"], submission, selected_at_block=cutoff, completed_by_block=h.block
        )
        == refs
    )
    assert review_request_inventory(
        refs[0],
        delivered.objects,
        h.b["policy"],
        assignment.certificate,
        opened_at_block=0,
        selected_at_block=cutoff,
        completed_by_block=h.block,
    ) == (reviewed, manifest, signed)


async def test_inventory_delayed_old_export_cannot_hide_new_completed_local_work(exporting):
    from umi.competition_cohort_request_inventory import review_request_inventory

    h = exporting
    worker, owner, slot, assignment, job, terminal = unfinished_endpoint(h)
    authenticated_inventory_exports(h, worker)
    assert await worker._export(owner, slot, h.block) is False
    old = h.files.partial(h.b["roster"], digest(job.submission.submission))[0]
    cutoff = h.block
    retain_case(h, owner, job, terminal.cases[-1])
    h.block += 1
    assert await worker._export(owner, slot, h.block) is False
    refs = h.files.inventories(
        h.b["roster"],
        digest(job.submission.submission),
        selected_at_block=cutoff,
        completed_by_block=h.block,
    )
    _, manifest, signed = review_request_inventory(
        refs[0],
        h.files.objects,
        h.b["policy"],
        assignment.certificate,
        opened_at_block=0,
        selected_at_block=cutoff,
        completed_by_block=h.block,
    )
    assert len(manifest.cases) == len(job.cases)
    assert signed.inventory.manifest_sha256 != old
    assert h.files.objects(old)
    with pytest.raises(ValueError, match="stale"):
        review_request_inventory(
            refs[0],
            h.files.objects,
            h.b["policy"],
            assignment.certificate,
            opened_at_block=0,
            selected_at_block=h.block,
            completed_by_block=h.block,
        )


@pytest.mark.parametrize("pending", ["terminal_intent", "finish"])
async def test_inventory_terminal_intent_blocks_partial_attestation(exporting, pending):
    from umi.competition_execution import execution_boundary

    h = exporting
    _worker, owner, slot, assignment, job, _ = unfinished_endpoint(h)
    if pending == "terminal_intent":
        intent = h.b["terminals"][
            (digest(assignment.certificate), identity(owner.config.signer))
        ].terminal
        owner.journal.put("request_terminal_intent", slot, intent)
    else:
        with owner.journal.transaction() as db:
            db.execute(
                "DELETE FROM records WHERE kind='step' AND id=?", (execution_step_key(job, 0),)
            )
    with pytest.raises(FileNotFoundError, match=r"original (terminal|finish)"):
        h.files.collect_inventory(owner, slot, execution_boundary(await h.provider.collect()))
    assert not h.exports_signed


async def test_inventory_restart_recovers_signed_intent_and_rejects_wrong_signer(exporting):
    from umi.competition_cohort_request_inventory import seal_request_inventory
    from umi.competition_execution import execution_boundary

    h = exporting
    worker, owner, slot, _, _, _ = unfinished_endpoint(h)
    body, assignment, manifest, collected = h.files.collect_inventory(
        owner, slot, execution_boundary(await h.provider.collect())
    )

    async def offline(_):
        raise OSError("inventory signer unavailable")

    with pytest.raises(OSError, match="unavailable"):
        await seal_request_inventory(
            body, worker.journal, offline, signer=owner.config.signer, timeout_seconds=10
        )
    assert worker.journal.get("request_inventory_intent", digest(body)) == body.model_dump(
        mode="json", by_alias=True
    )
    signed = await seal_request_inventory(
        body, worker.journal, worker.sign, signer=owner.config.signer, timeout_seconds=10
    )
    assert (
        await seal_request_inventory(
            body, worker.journal, offline, signer=owner.config.signer, timeout_seconds=10
        )
        == signed
    )
    key = h.files.publish_inventory(signed, assignment, manifest, collected)
    assert h.files.objects(key)
    with pytest.raises(ValueError, match="evaluator"):
        await seal_request_inventory(
            body,
            worker.journal,
            offline,
            signer=wallet("Alice").hotkey.ss58_address,
            timeout_seconds=10,
        )


async def test_inventory_elapsed_time_and_certified_closure_do_not_grow_signed_state(exporting):
    h = exporting
    worker, owner, slot, _, job, terminal = unfinished_endpoint(h)
    proofs = authenticated_inventory_exports(h, worker)
    selected = worker.inventory_cutoff
    worker.inventory_cutoff = lambda _: None
    assert await worker._export(owner, slot, h.block) is False
    h.block += 1_000_000
    assert await worker._export(owner, slot, h.block) is False
    assert proofs == [] and h.exports_signed == []
    worker.inventory_cutoff = selected
    assert await worker._export(owner, slot, h.block) is False
    calls = len(h.exports_signed)
    h.block += 1_000_000
    assert await worker._export(owner, slot, h.block) is False
    assert len(proofs) == 1 and len(h.exports_signed) == calls
    retain_case(h, owner, job, terminal.cases[-1])
    h.block += 1
    assert await worker._export(owner, slot, h.block) is False
    assert len(proofs) == 2 and len(h.exports_signed) == calls + 1
    worker.inventory_needed = lambda cohort: False
    h.block += 25
    assert await worker._export(owner, slot, h.block) is False
    assert len(proofs) == 2 and len(h.exports_signed) == calls + 1


async def test_partial_exports_available_local_steps_before_local_completion(exporting):
    h = exporting
    worker, owner, slot, assignment, job, _ = unfinished_endpoint(h)
    with owner.journal.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind='step' AND id=?",
            (execution_step_key(job, len(job.cases) - 1),),
        )
    assert owner.evidence(slot) is None
    assert await worker._export(owner, slot, h.block) is False
    refs = h.files.partial(h.b["roster"], digest(job.submission.submission))
    manifest = PartialRequestManifest.model_validate_json(h.files.objects(refs[0]))
    assert len(manifest.steps) == len(job.cases) - 1
    assert review_partial(h, h.files, refs[0], assignment) == assignment
    assert not h.exports_signed


@pytest.mark.parametrize(
    "kind", ["assignment", "step", "review", "decision", "response", "selection"]
)
async def test_partial_missing_or_corrupt_original_cannot_pass_native_review(exporting, kind):
    h = exporting
    worker, owner, slot, assignment, job, _ = unfinished_endpoint(h)
    assert await worker._export(owner, slot, h.block) is False
    key = h.files.partial(h.b["roster"], digest(job.submission.submission))[0]
    manifest = PartialRequestManifest.model_validate_json(h.files.objects(key))
    target = {
        "assignment": manifest.assignment_sha256,
        "step": manifest.steps[0].sha256,
        "review": manifest.cases[0].review_sha256,
        "decision": manifest.cases[0].decision_sha256,
        "response": manifest.responses[-1].response_sha256,
        "selection": manifest.responses[-1].selection_sha256,
    }[kind]
    path = h.files.objects._path(target)
    original = path.read_bytes()
    path.unlink()
    with pytest.raises(FileNotFoundError):
        review_partial(h, h.files, key, assignment)
    path.write_bytes(b"{}")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        review_partial(h, h.files, key, assignment)
    path.write_bytes(original)
    assert review_partial(h, h.files, key, assignment) == assignment


async def test_partial_interrupted_copy_retries_before_any_index(exporting, monkeypatch):
    h = exporting
    worker, owner, slot, assignment, job, _ = unfinished_endpoint(h)
    publish = h.files.objects.publish

    def interrupt(key, source):
        publish(key, source)
        raise OSError("synthetic interrupted copy")

    monkeypatch.setattr(h.files.objects, "publish", interrupt)
    with pytest.raises(OSError, match="interrupted"):
        await worker._export(owner, slot, h.block)
    assert not list((h.files.root / "partials").rglob("*.json"))
    with pytest.raises(FileNotFoundError, match="partial inventory"):
        h.files.partial(h.b["roster"], digest(job.submission.submission))
    monkeypatch.setattr(h.files.objects, "publish", publish)
    assert await worker._export(owner, slot, h.block) is False
    key = h.files.partial(h.b["roster"], digest(job.submission.submission))[0]
    assert review_partial(h, h.files, key, assignment) == assignment
    assert not h.exports_signed


async def test_partial_index_rejects_wrong_count_or_assignment(exporting):
    h = exporting
    worker, owner, slot, _, job, _ = unfinished_endpoint(h)
    assert await worker._export(owner, slot, h.block) is False
    index = next((h.files.root / "partials").rglob("*.json"))
    index.rename(index.with_name("06144.json"))
    with pytest.raises(ValueError, match="progress"):
        h.files.partial(h.b["roster"], digest(job.submission.submission))


async def test_partial_retirement_preserves_completed_response_awaiting_certification(exporting):
    h = exporting
    worker, owner, slot, assignment, job, terminal = unfinished_endpoint(h)
    assert await worker._export(owner, slot, h.block) is False
    first = h.files.partial(h.b["roster"], digest(job.submission.submission))[0]
    old = PartialRequestManifest.model_validate_json(h.files.objects(first))
    ref = terminal.cases[-1]
    review = parse_case_review(h.b["objects"][ref.review_sha256])
    owner.journal.put(
        "endpoint_retired_case", case_record_key(review.selection, ref.case_id), review.retirement
    )
    assert await worker._export(owner, slot, h.block) is False
    second = h.files.partial(h.b["roster"], digest(job.submission.submission))[0]
    new = PartialRequestManifest.model_validate_json(h.files.objects(second))
    assert new.item_count == old.item_count + 1
    assert new.cases == old.cases
    pending = next(r for r in new.responses if r.case_id == ref.case_id)
    assert pending.retirement_sha256 == digest(review.retirement)
    assert pending.case_id not in {c.case_id for c in new.cases}
    assert review_partial(h, h.files, second, assignment) == assignment
    assert not h.exports_signed


async def test_partial_restart_reuses_verification_until_an_original_changes(
    exporting, monkeypatch
):
    h = exporting
    worker, owner, slot, assignment, job, _ = unfinished_endpoint(h)
    assert await worker._export(owner, slot, h.block) is False
    key = h.files.partial(h.b["roster"], digest(job.submission.submission))[0]
    manifest = PartialRequestManifest.model_validate_json(h.files.objects(key))
    worker.files = RequestCompletionFiles(h.files.root)
    calls = []
    from umi import competition_cohort_request_files as module

    original = module.review_partial_request

    def observed(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "review_partial_request", observed)
    assert await worker._export(owner, slot, h.block) is False
    assert calls == []
    h.files.objects._path(manifest.steps[0].sha256).unlink()
    assert await worker._export(owner, slot, h.block) is False
    assert calls == [key]
    assert review_partial(h, worker.files, key, assignment) == assignment


@pytest.mark.parametrize("kind", ["response", "selection", "case_decision", "delivery", "step"])
async def test_partial_rekeyed_forgery_is_rejected_by_native_validation(exporting, kind):
    h = exporting
    worker, owner, slot, assignment, job, _ = unfinished_endpoint(h)
    assert await worker._export(owner, slot, h.block) is False
    key = h.files.partial(h.b["roster"], digest(job.submission.submission))[0]
    manifest = json.loads(h.files.objects(key))
    objects = {}

    def put(value):
        sha = digest(value)
        objects[sha] = canonical_json_bytes(value)
        return sha

    def source(sha):
        return objects[sha] if sha in objects else h.files.objects(sha)

    if kind == "response":
        ref = manifest["responses"][-1]
        value = json.loads(source(ref["response_sha256"]))
        value["response"]["signature"] = "0x" + "00" * 64
        ref["response_sha256"] = put(value)
    elif kind == "selection":
        ref = manifest["responses"][-1]
        value = json.loads(source(ref["selection_sha256"]))
        value["order"]["signatures"][0]["signature"] = "0x" + "00" * 64
        ref["selection_sha256"] = put(value)
    elif kind == "case_decision":
        ref = manifest["cases"][0]
        value = json.loads(source(ref["decision_sha256"]))
        value["signatures"][0]["signature"] = "0x" + "00" * 64
        ref["decision_sha256"] = put(value)
    elif kind == "delivery":
        value = json.loads(source(manifest["assignment_sha256"]))
        value["delivery"]["signature"]["signature"] = "0x" + "00" * 64
        manifest["assignment_sha256"] = put(value)
    else:
        ref = manifest["steps"][0]
        value = json.loads(source(ref["sha256"]))
        value["execution"]["model_sha256"] = "ab" * 32
        ref["sha256"] = put(value)
    forged = put(manifest)
    with pytest.raises(ValueError):
        review_partial_request(
            forged,
            source,
            h.b["policy"],
            assignment.certificate,
            opened_at_block=0,
            completed_by_block=h.block,
        )
