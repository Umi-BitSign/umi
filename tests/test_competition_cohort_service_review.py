"""Native owner lookup, proof replay and durable service voting.

RPC, verified blocks, codec/proof verification, DNS and inference use fixtures.
No installed host or live chain reward effect is represented.
"""

import asyncio
import hashlib
import json
from dataclasses import replace

import bittensor as bt
import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_service_authority import ServiceWorkAuthority
from umi.competition_cohort_service_export import (
    PATH,
    ServiceWorkExporter,
    ServiceWorkHTTPClient,
    ServiceWorkReader,
    SignedServiceWorkResponse,
    service_work_routes,
)
from umi.competition_cohort_service_grant import service_grant_slot
from umi.competition_cohort_service_queue import ServiceWorkQueue
from umi.competition_cohort_service_requests import ServiceWorkRequests
from umi.competition_cohort_service_review import (
    ServiceRequestReview,
    ServiceRetryReview,
    ServiceReviewConfig,
    ServiceWorkReviewer,
    certify_service_retry,
    service_retry_decision,
)
from umi.competition_execution import execution_boundary
from umi.competition_historical_registration import HistoricalRegistrationProvider
from umi.open_competition import digest, sign_object, verify_signature
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_service_authority import base_policy as base_policy
from .test_competition_cohort_service_authority import chain as chain
from .test_competition_cohort_service_authority import chain_config as chain_config
from .test_competition_cohort_service_authority import endpoint as endpoint
from .test_competition_cohort_service_authority import execution as execution
from .test_competition_cohort_service_authority import granted as granted
from .test_competition_cohort_service_authority import harness as harness
from .test_competition_cohort_service_authority import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_authority import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_authority import miner_policy as miner_policy
from .test_competition_cohort_service_authority import original_harness as original_harness
from .test_competition_cohort_service_authority import policy as policy
from .test_competition_cohort_service_authority import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_authority import recovery as recovery
from .test_competition_cohort_service_authority import recovery_case as recovery_case
from .test_competition_cohort_service_authority import relay as relay
from .test_competition_cohort_service_authority import runtime as runtime
from .test_competition_cohort_service_authority import scenario as scenario
from .test_competition_cohort_service_authority import (
    service_catalog_inputs as service_catalog_inputs,
)
from .test_competition_cohort_service_authority import service_owner as service_owner
from .test_competition_cohort_service_authority import shared_control_group as shared_control_group
from .test_competition_cohort_service_grants import fresh_window
from .test_competition_cohort_service_worker import finish, history_tip, wallet
from .test_competition_cohort_service_worker import loop as loop
from .test_competition_historical_registration import change_block


@pytest.fixture
async def reviewed(loop, tmp_path):
    s, c, p = loop, loop.c, loop.p
    chain = p.c
    s.lookups, s.signatures, s.archive_reads = 0, 0, 0
    original_at = chain.finality.verified_block_at
    blocks = {}

    async def move(height):
        encoded = change_block(chain, height)
        block = await original_at(height)
        evidence = canonical_json_bytes(
            {**json.loads(block.finality_evidence), "block": {"scale_header": encoded}}
        )
        blocks[height] = replace(
            block,
            finality_evidence=evidence,
            finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )

    await move(chain.finality.ref.block_number)

    async def at(height):
        return blocks.get(height)

    chain.finality.verified_block_at = at
    chain.config = chain.config.model_copy(update={"state_directory": str(tmp_path / "proofs")})

    def provider():
        return HistoricalRegistrationProvider(
            chain.config,
            chain.policy,
            finality=chain.finality,
            proofs=chain.proofs,
            now_ms=lambda: chain.clock.now,
        )

    chain.provider = provider()
    observed = await chain.provider.collect()
    original = c.assignment
    c.cfg = c.cfg.model_copy(update={"directory": str(tmp_path / "native-queue")})
    c.queue = ServiceWorkQueue(c.cfg, chain.policy)
    c.queue.install(
        original.catalog,
        original.round,
        original.source,
        observed,
        expected_tip_sha256=history_tip(original.source.history),
    )
    c.queue.admit(
        c.claim,
        original.admission.submission,
        original.admission.participant,
        original.source,
        observed,
        expected_tip_sha256=history_tip(original.source.history),
    )
    c.assignment = c.queue.assignment(c.claim)
    archive_bytes = await chain.provider.retained_archive(execution_boundary(observed))
    await move(p.finality.head)
    s.move = move

    async def history(cohort):
        if s.offline:
            raise OSError("history offline")
        assert cohort == c.assignment.round.cohort_sha256
        return p.e.r.h.source

    async def archive(expected):
        s.archive_reads += 1
        assert expected == c.assignment.admission.observation
        return archive_bytes

    async def owner_sign(body):
        return sign_object(body, p.validator)

    exporter = ServiceWorkExporter(c.queue, p.validator.hotkey.ss58_address, owner_sign)
    app = FastAPI()
    app.include_router(service_work_routes(exporter, token="t" * 32))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
    http = ServiceWorkHTTPClient(client, "https://coordinator.example", token="t" * 32)

    async def fetch(request):
        s.lookups += 1
        if s.offline:
            raise OSError("owner offline")
        return await http(request)

    owner = ServiceWorkReader(chain.policy, p.validator.hotkey.ss58_address, fetch)
    s.exporter, s.client, s.reader, s.fetch = exporter, client, owner, fetch
    s.requests = ServiceWorkRequests(c.queue, p.transport_policy)
    s.body = s.requests.prepare(
        c.claim,
        p.validator.hotkey.ss58_address,
        p.service_video,
        c.window,
        p.e.r.h.source,
        await chain.provider.collect(),
    )

    def reviewer(name="Charlie"):
        async def sign(body):
            s.signatures += 1
            return sign_object(body, wallet(name))

        config = ServiceReviewConfig(
            schema="umi-service-review-config/1",
            directory=str(tmp_path / ("review-" + name)),
            policy_sha256=digest(chain.policy),
            signer=wallet(name).hotkey.ss58_address,
            owner=p.validator.hotkey.ss58_address,
            cohorts=p.e.cfg.cohorts,
        )

        async def current_round():
            return bt.timelock.current_round()

        return ServiceWorkReviewer(
            config,
            chain.policy,
            p.transport_policy,
            provider(),
            p.finality,
            history,
            owner,
            archive,
            current_round,
            sign,
        )

    s.reviewer, s.history = reviewer, history
    origins = p.provider(state_directory=str(tmp_path / "origins"))
    authority = ServiceWorkAuthority(c.queue, chain.provider, history, origins)
    s.origin, s.observation = authority.origin, authority.observe
    s.reviewers = {}
    for name in ("Charlie", "Dave"):
        reviewer_ = reviewer(name)

        async def vote(body, reviewer_=reviewer_):
            parent = (
                None
                if body.parent_grant_slot is None
                else s.requests.certificate(body.parent_grant_slot)
            )
            return await reviewer_.attest(ServiceRequestReview(body=body, parent=parent))

        s.reviewers[wallet(name).hotkey.ss58_address] = vote
    try:
        yield s
    finally:
        await client.aclose()


async def test_independent_service_votes_drive_native_miner_and_recover_offline(reviewed):
    s = reviewed
    worker, terminal, _ = await finish(s)
    assert s.p.model.calls == 1 and s.signatures == 2 and s.archive_reads == 2
    assert terminal.terminal.work_sha256 == s.c.assignment.admission.work_sha256
    s.offline = True
    old = await s.reviewer().attest(ServiceRequestReview(body=s.body))
    verify_signature(s.body, old)
    assert s.signatures == 2
    _, recovered, _ = await finish(s)
    assert recovered == terminal
    assert worker.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address) == s.body


@pytest.mark.parametrize("kind", ["service_request_intent", "service_request_vote"])
async def test_service_vote_recovers_lost_committed_ack(reviewed, monkeypatch, kind):
    s, reviewer = reviewed, reviewed.reviewer()
    saved = []
    if kind.endswith("intent"):
        original = reviewer.journal.put_many

        def interrupted(records, **kwargs):
            records = tuple(records)
            result = original(records, **kwargs)
            if any(k == kind for k, _, _ in records):
                saved.append(True)
                raise OSError("committed intent reply lost")
            return result

        monkeypatch.setattr(reviewer.journal, "put_many", interrupted)
    else:
        original = reviewer.journal.put

        def interrupted(k, key, value):
            result = original(k, key, value)
            if k == kind:
                saved.append(True)
                raise OSError("committed vote reply lost")
            return result

        monkeypatch.setattr(reviewer.journal, "put", interrupted)
    with pytest.raises(OSError):
        await reviewer.attest(ServiceRequestReview(body=s.body))
    assert saved == [True]
    if kind.endswith("vote"):
        s.offline = True
    signature = await s.reviewer().attest(ServiceRequestReview(body=s.body))
    verify_signature(s.body, signature)
    assert s.signatures == 1 and s.archive_reads == 1


@pytest.mark.parametrize("damage", ["challenge", "signer", "claim", "bytes", "auth"])
async def test_service_lookup_rejects_substitution(reviewed, damage):
    s = reviewed

    async def fetch(request):
        if damage == "auth":
            response = await s.client.post(
                "https://coordinator.example" + PATH,
                content=canonical_json_bytes(request),
                headers={"content-type": "application/json"},
            )
            assert response.status_code == 401
            raise OSError("unauthenticated")
        raw = await s.fetch(request)
        signed = SignedServiceWorkResponse.model_validate_json(raw)
        response = signed.response
        if damage == "challenge":
            response = response.model_copy(update={"challenge": "00" * 32})
        elif damage == "claim":
            response = response.model_copy(
                update={
                    "assignment": response.assignment.model_copy(
                        update={
                            "admission": response.assignment.admission.model_copy(
                                update={"ordinal": 2}
                            )
                        }
                    )
                }
            )
        key = wallet("Alice") if damage == "signer" else s.p.validator
        raw = canonical_json_bytes(
            SignedServiceWorkResponse(response=response, signature=sign_object(response, key))
        )
        return raw + b" " if damage == "bytes" else raw

    reader = ServiceWorkReader(s.p.c.policy, s.p.validator.hotkey.ss58_address, fetch)
    with pytest.raises((OSError, ValueError)):
        await reader(s.c.assignment)
    assert s.signatures == 0


@pytest.mark.parametrize("damage", ["proof", "window", "owner", "history"])
async def test_service_review_requires_independent_evidence(reviewed, damage):
    s, reviewer = reviewed, reviewed.reviewer()
    if damage == "proof":
        s.p.c.rpc.bad_proof = True
    elif damage == "window":
        s.p.finality.blocks.pop(s.body.request.issued_block)
    elif damage == "owner":

        async def absent(assignment):
            raise FileNotFoundError("original work missing")

        reviewer.owner = absent
    else:
        from .test_competition_cohort_order_signer import source_for

        s.p.e.r.h.source = source_for(s.p.e.r.h.batch, s.p.e.r.h.batch["history"])
    with pytest.raises((OSError, ValueError, RuntimeError)):
        await reviewer.attest(ServiceRequestReview(body=s.body))
    assert s.signatures == 0


async def test_cancelled_signing_keeps_lease_until_durable_vote(reviewed):
    s, reviewer = reviewed, reviewed.reviewer()
    entered, release = asyncio.Event(), asyncio.Event()
    original = reviewer.sign

    async def slow(value):
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            # A signer may already own a non-cancellable hardware/thread operation.
            await release.wait()
        return await original(value)

    reviewer.sign = slow
    task = asyncio.create_task(reviewer.attest(ServiceRequestReview(body=s.body)))
    await asyncio.wait_for(entered.wait(), timeout=20)
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(BlockingIOError), s.reviewer().journal.locked():
        pass
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    s.offline = True
    await s.reviewer().attest(ServiceRequestReview(body=s.body))
    assert s.signatures == 1


async def test_service_review_resumes_original_intent_after_long_signing_outage(reviewed):
    s, reviewer = reviewed, reviewed.reviewer()

    async def unavailable(value):
        raise OSError("signer temporarily offline")

    reviewer.sign = unavailable
    with pytest.raises(OSError):
        await reviewer.attest(ServiceRequestReview(body=s.body))
    assert s.archive_reads == 1 and s.signatures == 0
    await s.move(s.p.finality.head + 1000000)
    s.p.finality.blocks.clear()
    recovered = s.reviewer()

    async def missing(expected):
        raise FileNotFoundError("original archive source offline")

    recovered.archive = missing
    vote = await recovered.attest(ServiceRequestReview(body=s.body))
    verify_signature(s.body, vote)
    assert s.signatures == 1 and s.archive_reads == 1


async def test_service_review_cannot_change_selected_request_after_restart(reviewed):
    s = reviewed
    await s.reviewer().attest(ServiceRequestReview(body=s.body))
    request = s.body.request.model_copy(
        update={
            "video": s.body.request.video.model_copy(
                update={"url": "https://example.com/other.mp4"}
            )
        }
    )
    changed = s.body.model_copy(update={"request": request})
    with pytest.raises(ValueError, match="original intent"):
        await s.reviewer().attest(ServiceRequestReview(body=changed))
    assert s.signatures == 1


async def retired_attempt(s, monkeypatch):
    worker = s.worker()
    grant = await worker._certificate(s.body)
    s.p.finality.head = s.body.request.deadline_block + 3000
    await s.move(s.p.finality.head)
    monkeypatch.setattr(
        bt.timelock, "current_round", lambda: s.body.request.response_close_round + 500
    )
    result = await worker.transport.advance(service_grant_slot(s.body))
    assert result.retirement.receipt.result == "no_response_retained"
    assert result.response is None and s.p.model.calls == 0
    return ServiceRetryReview(grant=grant, retirement=result.retirement)


async def test_native_retry_review_and_fresh_window_finish_original_work(reviewed, monkeypatch):
    s = reviewed
    review = await retired_attempt(s, monkeypatch)
    decision = service_retry_decision(review)
    votes = tuple([await s.reviewer(n).attest(review) for n in ("Charlie", "Dave")])
    certificate = certify_service_retry(review, s.p.c.policy, s.p.transport_policy, votes)
    assert certificate.decision == decision

    async def retry(grant, retired):
        assert ServiceRetryReview(grant=grant, retirement=retired) == review
        return certificate

    s.retry = retry
    s.c.window = fresh_window(s.p, s.body.request, monkeypatch)
    await s.move(s.p.finality.head)
    worker, terminal, _ = await finish(s)
    body = worker.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address)
    assert body.attempt_number == 2 and body.assignment == s.body.assignment
    assert s.p.model.calls == 1 and s.signatures == 6
    s.offline = True
    assert await s.reviewer().attest(review) == votes[0]
    assert terminal.terminal.work_sha256 == s.body.assignment.admission.work_sha256


@pytest.mark.parametrize("damage", ["early_round", "signature", "response"])
async def test_retry_rejects_early_or_unfenced_replacement(reviewed, monkeypatch, damage):
    s = reviewed
    review = await retired_attempt(s, monkeypatch)
    if damage == "early_round":
        monkeypatch.setattr(
            bt.timelock, "current_round", lambda: s.body.request.response_close_round - 1
        )
    else:
        fence = review.retirement
        if damage == "signature":
            fence = fence.model_copy(
                update={"signature": sign_object(fence.receipt, wallet("Alice"))}
            )
        else:
            body = fence.receipt.model_copy(
                update={"result": "response_retained", "response_sha256": "ab" * 32}
            )
            fence = fence.model_copy(
                update={"receipt": body, "signature": sign_object(body, s.p.miner.wallet)}
            )
        review = review.model_copy(update={"retirement": fence})
    with pytest.raises(ValueError):
        await s.reviewer().attest(review)
    assert s.signatures == 2
