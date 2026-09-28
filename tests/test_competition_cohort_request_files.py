"""Native retained execution -> recurring exports -> complete request closure.

Registration/finality and inference are the parent fixture's synthetic ports.
Signing, journals, immutable delivery and request replay are native.
"""

import asyncio
from contextlib import ExitStack
from functools import partial

import pytest

from umi.competition_cohort_order_signer import order_slot
from umi.competition_cohort_request_export_worker import RequestExportWorker
from umi.competition_cohort_request_files import RequestCompletionFiles
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

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
            raise OSError("synthetic acknowledgement loss")

    monkeypatch.setattr(h.files, "publish", lost_ack)
    report = await h.workers[0].poll_once()
    assert report["retry_count"] == len(h.workers[0].executions)
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
    report = await h.workers[0].poll_once()
    assert report["assignments_pending"] >= 1
    assert report["request_closure_authorized"] is False
    assert h.window().completion == "pending"
    # Another completed assignment is still exported in the same batch.
    assert len(h.exports_signed) == len(h.workers[0].executions) - 1


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
