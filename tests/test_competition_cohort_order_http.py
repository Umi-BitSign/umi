"""Native order outbox, HTTP votes and evaluator inboxes with synthetic finality."""

import json
from contextlib import AsyncExitStack
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_order_http import (
    PREFIX,
    OrderDeliveryPeer,
    OrderReviewPeer,
    order_routes,
)
from umi.competition_cohort_order_worker import CohortOrderWorker
from umi.open_competition import identity

from .test_competition_cohort_order_delivery import base_policy as base_policy
from .test_competition_cohort_order_delivery import harness as harness
from .test_competition_cohort_order_delivery import legacy_scenario as legacy_scenario
from .test_competition_cohort_order_delivery import policy as policy
from .test_competition_cohort_order_delivery import receipt_scenario as receipt_scenario
from .test_competition_cohort_order_delivery import recovery as recovery
from .test_competition_cohort_order_delivery import relay as relay
from .test_competition_cohort_order_delivery import runtime as runtime
from .test_competition_cohort_order_delivery import scenario as scenario


@pytest.fixture
async def network(relay):
    r = relay
    n = SimpleNamespace(r=r, reviews={}, delivery={}, clients={}, lost=None, paths=[])
    async with AsyncExitStack() as resources:
        for who, name in r.names.items():
            signer = r.h.worker(name)
            box = r.inbox(signer.journal.config.signer)
            app = FastAPI()
            app.include_router(order_routes(signer, box, token="private-order-token" * 3))
            inner = httpx.ASGITransport(app=app)

            class Delivery(httpx.AsyncBaseTransport):
                def __init__(self, transport):
                    self.transport = transport

                async def handle_async_request(self, request):
                    n.paths.append(request.url.path)
                    response = await self.transport.handle_async_request(request)
                    if n.lost is not None and request.url.path.endswith(n.lost):
                        await response.aclose()
                        raise httpx.ReadError("lost original acknowledgement", request=request)
                    return response

            client = await resources.enter_async_context(
                httpx.AsyncClient(transport=Delivery(inner), base_url="https://review.example")
            )
            args = dict(
                policy=box.policy,
                cohorts=box.config.cohorts,
                signer=signer.journal.config.signer,
                token="private-order-token" * 3,
            )
            n.clients[who] = client
            n.reviews[who] = OrderReviewPeer(client, "https://review.example", **args)
            n.delivery[who] = OrderDeliveryPeer(client, "https://review.example", **args)

        async def vote(who, order, participant):
            return await n.reviews[identity(who)].attest(order, participant)

        async def votes(who, slot):
            return await n.reviews[identity(who)].lookup(slot)

        async def accept(who, certificate, participant):
            return await n.delivery[identity(who)].accept(certificate, participant)

        async def receipts(who, slot):
            return await n.delivery[identity(who)].lookup(slot)

        def worker():
            return CohortOrderWorker(
                r.queue(),
                r.h.worker().provider,
                r.h.worker().history,
                SimpleNamespace(lookup=votes, attest=vote),
                SimpleNamespace(lookup=receipts, accept=accept),
            )

        n.worker = worker
        yield n


async def test_native_delivery_and_offline_restart_over_private_http(network):
    n, r = network, network.r
    report = await n.worker().poll_once()
    assert report["votes_retained"] == 2 and report["deliveries_acknowledged"] == 2
    assert report["retry_count"] == 0
    assert all(r.inbox(who).assignment(r.slot) for who in r.h.order.evaluators)
    count = len(n.paths), len(r.h.calls), len(r.receipt_calls)
    r.h.fail_collect = True
    assert (await n.worker().poll_once())["retry_count"] == 0
    assert (len(n.paths), len(r.h.calls), len(r.receipt_calls)) == count


@pytest.mark.parametrize("action", ["attest", "accept"])
async def test_lost_http_ack_is_recovered_without_duplicate_signature(network, action):
    n, r = network, network.r
    n.lost = action
    assert (await n.worker().poll_once())["retry_count"] == 2
    count = len(r.h.calls), len(r.receipt_calls)
    n.lost = None
    if action == "accept":
        r.h.fail_collect = True
    assert (await n.worker().poll_once())["deliveries_acknowledged"] == 2
    assert len(r.h.calls) == count[0]
    assert len(r.receipt_calls) == (2 if action == "attest" else count[1])


async def test_authentication_precedes_parsing_or_native_signing(network):
    n = network
    client = next(iter(n.clients.values()))
    for path in ("votes/lookup", "votes/attest", "inbox/lookup", "inbox/accept"):
        response = await client.post(PREFIX + "/" + path, content=b"not JSON")
        assert response.status_code == 401
    assert not n.r.h.calls and not n.r.receipt_calls


@pytest.mark.parametrize("fault", ["slot", "identity", "bytes", "redirect"])
async def test_peer_rejects_corrupted_or_redirected_response(network, fault):
    n, r = network, network.r
    await n.worker().poll_once()
    who = r.h.order.evaluators[0]
    receipt = await r.inbox(who).lookup(r.slot)
    from umi.protocol import canonical_json_bytes

    body = {"slot": r.slot, "receipt": receipt.model_dump(mode="json", by_alias=True)}
    if fault == "slot":
        body["slot"] = "ff" * 32
    elif fault == "identity":
        body["receipt"]["receipt"]["evaluator_hotkey"] = r.h.order.submission.submission.hotkey
    raw = json.dumps(body).encode() if fault == "bytes" else canonical_json_bytes(body)

    def respond(request):
        assert request.url.host == "review.example"
        return httpx.Response(
            302 if fault == "redirect" else 200,
            content=raw,
            headers={"content-type": "application/json", "location": "https://elsewhere.example"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        peer = OrderDeliveryPeer(
            client,
            "https://review.example",
            policy=r.h.batch["policy"],
            cohorts=r.cfg.cohorts,
            signer=who,
            token="private-order-token" * 3,
        )
        with pytest.raises((ValueError, OSError)):
            await peer.lookup(r.slot)
