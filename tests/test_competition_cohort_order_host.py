"""Certified fixture roster to native outbox, private HTTP and native evaluator inboxes.

The retained preparation and finality sources are fixtures; every order review,
signature, selection and delivery receipt uses the native implementation.
"""

from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_order_host import CohortOrderHost, OrderHostConfig
from umi.competition_cohort_order_signer import order_slot
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_order_http import base_policy as base_policy
from .test_competition_cohort_order_http import harness as harness
from .test_competition_cohort_order_http import legacy_scenario as legacy_scenario
from .test_competition_cohort_order_http import network as network
from .test_competition_cohort_order_http import policy as policy
from .test_competition_cohort_order_http import receipt_scenario as receipt_scenario
from .test_competition_cohort_order_http import recovery as recovery
from .test_competition_cohort_order_http import relay as relay
from .test_competition_cohort_order_http import runtime as runtime
from .test_competition_cohort_order_http import scenario as scenario


@pytest.fixture
async def owner(network, tmp_path):
    n, r = network, network.r
    cfg = OrderHostConfig(
        schema="umi-cohort-order-host/1",
        queue=r.cfg.model_copy(update={"directory": str(tmp_path / "automatic-orders")}),
    )
    root = tmp_path / "objects"
    files = SettlementEvidenceFiles(root)
    for value in (r.h.batch["suite"], r.h.order.runtime, r.h.order.incumbent):
        files.publish(digest(value), lambda _, value=value: canonical_json_bytes(value))
    peers = tuple(
        SimpleNamespace(
            signer=who, origin="https://" + identity(who) + ".example", timeout_seconds=30
        )
        for who in cfg.queue.reviewers
    )
    o = SimpleNamespace(network=n, files=files, prepared_reads=0, fail_after=None)

    def retained(cohort, *, expected_tip_sha256, current_block):
        o.prepared_reads += 1
        assert cohort == r.cohort
        return SimpleNamespace(roster=r.h.batch["roster"])

    service = SimpleNamespace(
        config=SimpleNamespace(
            orders=cfg,
            admission_owner=SimpleNamespace(reviewers=peers),
            lifecycle=SimpleNamespace(sources=SimpleNamespace(objects_directory=str(root))),
        ),
        intake=SimpleNamespace(
            policy=r.h.batch["policy"], config=SimpleNamespace(cohorts=r.cfg.cohorts)
        ),
        provider=r.h.worker().provider,
        history=r.h.worker().history,
        preparation=SimpleNamespace(retained=retained),
    )

    class Route(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            who = request.url.host.removesuffix(".example")
            # Forward through the fixture's native authenticated ASGI route.
            return await n.clients[who]._transport.handle_async_request(request)

    async with httpx.AsyncClient(transport=Route()) as client:
        o.host = lambda: CohortOrderHost(service, client, ("private-order-token" * 3,) * len(peers))
        yield o


async def test_complete_roster_selected_and_delivered_without_manual_orders(owner):
    o, r = owner, owner.network.r
    host = o.host()
    count = len(r.h.batch["roster"].participants)
    assert await host.select(r.cohort) == count
    slots = host.queue.pending(r.cohort)
    assert len(slots) == count
    assert host.queue.intent(r.slot).order == r.h.order
    assert b'"references"' not in canonical_json_bytes(host.queue.intent(r.slot))
    report = await host.worker.poll_once()
    assert report["deliveries_acknowledged"] == count * len(r.h.order.evaluators)
    assert report["retry_count"] == 0
    for who in r.h.order.evaluators:
        box = r.inbox(who)
        for slot in slots:
            assert order_slot(box.assignment(slot).certificate.order) == slot
    r.h.fail_collect = True
    calls = len(r.h.calls), len(r.receipt_calls), o.prepared_reads
    resumed = o.host()
    assert await resumed.select(r.cohort) == count
    assert (await resumed.worker.poll_once())["retry_count"] == 0
    assert (len(r.h.calls), len(r.receipt_calls), o.prepared_reads) == calls


async def test_partial_selection_resumes_originals_after_long_outage(owner, monkeypatch):
    o, r = owner, owner.network.r
    host = o.host()
    select = host.queue.select
    saved = []

    def interrupted(*args):
        if saved:
            raise OSError("disk temporarily full")
        saved.append(select(*args))
        return saved[-1]

    monkeypatch.setattr(host.queue, "select", interrupted)
    with pytest.raises(OSError):
        await host.select(r.cohort)
    original = canonical_json_bytes(host.queue.intent(saved[0]))
    assert host.queue.journal.get("order_host_roster", r.cohort) is None
    r.h.block += 3000
    resumed = o.host()
    count = len(r.h.batch["roster"].participants)
    assert await resumed.select(r.cohort) == count
    assert canonical_json_bytes(resumed.queue.intent(saved[0])) == original
    assert len(resumed.queue.pending(r.cohort)) == count


async def test_missing_original_runtime_does_not_select_replacement_or_smaller_roster(owner):
    o, r = owner, owner.network.r
    o.files._path(digest(r.h.order.runtime)).unlink()
    host = o.host()
    with pytest.raises(FileNotFoundError):
        await host.select(r.cohort)
    assert host.queue.pending(r.cohort) == ()
    assert host.queue.journal.get("order_host_roster", r.cohort) is None
    o.files.publish(digest(r.h.order.runtime), lambda _: canonical_json_bytes(r.h.order.runtime))
    assert await host.select(r.cohort) == len(r.h.batch["roster"].participants)
