"""Durable request construction/signing through real grant and miner handlers.

Finality, peer transport, DNS and inference are fixtures. Proof bytes are retained
but the fixture finality verifier is not a production chain qualification.
"""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_cohort_endpoint import validate_recoverable_endpoint_transport
from umi.competition_cohort_endpoint_dispatch import CohortEndpointDispatcher
from umi.competition_cohort_endpoint_selection import selection_slot
from umi.competition_cohort_grant_delivery import CohortEndpointGrantDelivery
from umi.competition_cohort_request_signer import (
    EndpointRequestJournal,
    EndpointRequestPlan,
    EndpointRequestSigner,
    EndpointRequestSignerConfig,
    request_slot,
)
from umi.competition_cohort_request_worker import CohortEndpointRequestWorker
from umi.endpoint_protocol import TRANSLATE_PATH
from umi.open_competition import identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_attempt_pipeline import expire_child
from .test_competition_cohort_endpoint_decision import base_policy as base_policy
from .test_competition_cohort_endpoint_decision import chain as chain
from .test_competition_cohort_endpoint_decision import chain_config as chain_config
from .test_competition_cohort_endpoint_decision import coordinator
from .test_competition_cohort_endpoint_decision import decisions as decisions
from .test_competition_cohort_endpoint_decision import delivery as delivery
from .test_competition_cohort_endpoint_decision import endpoint as endpoint
from .test_competition_cohort_endpoint_decision import execution as execution
from .test_competition_cohort_endpoint_decision import granted as granted
from .test_competition_cohort_endpoint_decision import harness as harness
from .test_competition_cohort_endpoint_decision import known_video_bytes as known_video_bytes
from .test_competition_cohort_endpoint_decision import legacy_scenario as legacy_scenario
from .test_competition_cohort_endpoint_decision import policy as policy
from .test_competition_cohort_endpoint_decision import receipt_scenario as receipt_scenario
from .test_competition_cohort_endpoint_decision import recovery as recovery
from .test_competition_cohort_endpoint_decision import recovery_case as recovery_case
from .test_competition_cohort_endpoint_decision import relay as relay
from .test_competition_cohort_endpoint_decision import retiring as retiring
from .test_competition_cohort_endpoint_decision import runtime as runtime
from .test_competition_cohort_endpoint_decision import scenario as scenario
from .test_competition_cohort_miner import request
from .test_competition_cohort_miner_case import next_grant
from .test_open_competition import wallet


@pytest.fixture
def signing(decisions, tmp_path):
    d, p = decisions, decisions.p
    p.c.finality.ref = replace(
        p.c.finality.ref, block_number=p.finality.head, block_hash=f"0x{p.finality.head:064x}"
    )
    s = SimpleNamespace(d=d, p=p, calls=[], fail_sign=False, peers_offline=False, overrides={})
    s.plan = EndpointRequestPlan(
        schema="umi-cohort-endpoint-request-plan/1",
        assignment=p.e.assignment,
        body=p.signed.order,
        transport=p.transport_policy,
    )

    s.own = next(
        n
        for n in ("Charlie", "Dave", "Eve", "Ferdie")
        if identity(wallet(n).hotkey.ss58_address) == identity(p.e.cfg.signer)
    )
    s.other = "Dave" if s.own != "Dave" else "Charlie"

    def signer(name=None):
        name = name or s.own
        fields = p.e.cfg.model_dump(
            by_alias=True, exclude={"schema_", "directory", "signer", "maximum_attempts"}
        )
        fields.update(s.overrides)
        fields["schema"] = "umi-cohort-endpoint-request-signer/1"
        cfg = EndpointRequestSignerConfig(
            **fields,
            directory=str(tmp_path / ("request-" + name)),
            signer=wallet(name).hotkey.ss58_address,
        )
        journal = EndpointRequestJournal(cfg, p.c.policy)

        async def sign(body):
            saved = journal.load(request_slot(body))
            assert saved is not None and saved.plan.body == body
            assert journal.journal.reservation(request_slot(body)) is not None
            s.calls.append((name, canonical_json_bytes(body)))
            if s.fail_sign:
                raise OSError("sign interrupted")
            return sign_object(body, wallet(name))

        return EndpointRequestSigner(journal, p.c.provider, p.finality, p.e.box.history, sign)

    async def peer(key, plan):
        if s.peers_offline:
            raise OSError("peer unavailable")
        name = next(
            n
            for n in ["Charlie", "Dave", "Eve", "Ferdie"]
            if identity(wallet(n).hotkey.ss58_address) == identity(key)
        )
        return await signer(name).attest(plan)

    s.signer = signer
    s.worker = lambda **options: CohortEndpointRequestWorker(
        signer(), p.delivery_recovery, peer, **options
    )
    return s


async def child_plan(s, monkeypatch, index=1):
    d, p = s.d, s.p
    review = await d.evidence(index=index)
    cert = (await coordinator(d).advance(p.retire_slot, review.retirement.case_id)).certificate
    # Only arrange fresh verified blocks. Production construction below supplies
    # the actual request and durable reviewer signatures.
    template = next_grant(d, p.grant, review, cert, monkeypatch)
    plan = await s.worker().replacement(
        p.grant,
        cert,
        review.retirement.retirement,
        p.transport_policy,
        template.attempt.order.requests[0].video,
    )
    assert plan.body == template.attempt.order
    return plan


async def test_request_quorum_retains_proofs_and_recovers_offline(signing):
    s = signing
    a, b = s.signer(), s.signer(s.other)
    av, bv = await a.attest(s.plan), await b.attest(s.plan)
    slot = request_slot(s.plan.body)
    saved = a.journal.load(slot)
    assert saved.windows and all(w.issuance.finality_evidence_hex for w in saved.windows)
    await a.collect(slot, bv)
    cert = await a.certify(slot)
    assert validate_recoverable_endpoint_transport(cert, s.p.c.policy, s.p.transport_policy) == cert
    s.p.c.finality.fail = True
    s.p.finality.blocks.clear()
    s.fail_sign = True
    assert await s.signer().recover(slot) == av
    assert await s.signer(s.other).recover(slot) == bv
    assert await s.signer().certify(slot) == cert
    assert len(s.calls) == 2


async def test_elapsed_historical_window_does_not_freeze_new_intent(signing, monkeypatch):
    import bittensor as bt

    s = signing
    worker = s.worker()
    close = s.plan.body.requests[0].response_close_round
    videos = tuple(request.video for request in s.plan.body.requests)
    monkeypatch.setattr(bt.timelock, "current_round", lambda: close)
    with pytest.raises(OSError, match="response window already elapsed"):
        await worker.initial(s.plan.assignment, s.plan.transport, videos)
    assert not s.calls
    with worker.signer.journal.journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 0

    # The same assignment remains usable once a live window is available.
    monkeypatch.setattr(bt.timelock, "current_round", lambda: close - 1)
    plan = await worker.initial(s.plan.assignment, s.plan.transport, videos)
    assert plan.body.job == s.plan.body.job
    assert all(request.response_close_round == close for request in plan.body.requests)
    assert worker.signer.journal.load(request_slot(plan.body)).plan == plan
    assert len(s.calls) == 1


async def test_partial_signature_finishes_after_transport_expiry(signing, monkeypatch):
    s = signing
    s.fail_sign = True
    with pytest.raises(OSError, match="sign interrupted"):
        await s.signer().attest(s.plan)
    slot = request_slot(s.plan.body)
    old = s.signer().journal.load(slot)
    expire_child(s.p, s.p.grant, monkeypatch)
    s.p.finality.blocks.clear()
    s.fail_sign = False
    await s.signer().recover(slot)
    assert s.signer().journal.load(slot) == old
    assert s.calls[0] == s.calls[1]


async def test_late_peer_can_sign_original_expired_request(signing, monkeypatch):
    s = signing
    await s.signer().attest(s.plan)
    expire_child(s.p, s.p.grant, monkeypatch)
    vote = await s.signer(s.other).attest(s.plan)
    await s.signer().collect(request_slot(s.plan.body), vote)
    assert (await s.signer().certify(request_slot(s.plan.body))).order == s.plan.body


@pytest.mark.parametrize("after", [False, True])
async def test_request_vote_commit_interruption(signing, monkeypatch, after):
    s = signing
    a = s.signer()
    real = a.journal.journal.put

    def put(kind, key, value):
        if kind == "request_vote":
            if after:
                real(kind, key, value)
            raise OSError("vote commit interrupted")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(a.journal.journal, "put", put)
        with pytest.raises(OSError, match="commit interrupted"):
            await a.attest(s.plan)
    s.fail_sign = after
    await s.signer().recover(request_slot(s.plan.body))
    assert len(s.calls) == (1 if after else 2)


async def test_request_window_and_parent_cannot_change_after_intent(signing, monkeypatch):
    s = signing
    plan = await child_plan(s, monkeypatch)
    changed = plan.body.model_copy(
        update={
            "requests": (
                plan.body.requests[0].model_copy(update={"issued_block_hash": "0x" + "ab" * 32}),
            )
        }
    )
    with pytest.raises(ValueError, match="reserved"):
        await s.signer().attest(plan.model_copy(update={"body": changed}))
    assert len(s.calls) == 1


@pytest.mark.parametrize("field", ["block_hash", "finality_evidence_sha256", "scoring_policy_hash"])
async def test_owned_window_mismatch_prevents_signing(signing, field):
    s = signing
    height = s.plan.body.requests[0].issued_block
    block = s.p.finality.blocks[height]
    if field == "finality_evidence_sha256":
        # Corruption after construction still fails capture/replay validation.
        object.__setattr__(block, field, "11" * 32)
    else:
        s.p.finality.blocks[height] = replace(
            block, **{field: ("0x" if field == "block_hash" else "") + "11" * 32}
        )
    with pytest.raises((ValueError, RuntimeError)):
        await s.signer().attest(s.plan)
    assert not s.calls


async def test_missing_proof_then_restore_retries_same_plan(signing):
    s = signing
    saved = dict(s.p.finality.blocks)
    s.p.finality.blocks.clear()
    with pytest.raises(OSError):
        await s.signer().attest(s.plan)
    assert not s.calls
    s.p.finality.blocks.update(saved)
    assert await s.signer().attest(s.plan)


async def test_replacement_construct_sign_deliver_and_infer(signing, monkeypatch):
    s, p = signing, signing.p
    plan = await child_plan(s, monkeypatch)
    outcome = await s.worker().advance(plan)
    assert outcome.status == "certified"
    slot = selection_slot(outcome.selection)
    assert (
        await CohortEndpointGrantDelivery(p.delivery_recovery).deliver(slot)
    ).status == "retained"
    result = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        slot, plan.body.case_id
    )
    assert result["status"] == "recovered", result
    final = await coordinator(s.d).advance(slot, plan.body.case_id)
    assert final.certificate.decision.disposition == "retain_response"
    assert final.certificate.decision.attempt_number == 2
    assert p.model.calls == 1


async def test_peer_outage_preserves_request_until_old_window_retires(signing, monkeypatch):
    s, p = signing, signing.p
    plan = await child_plan(s, monkeypatch)
    s.peers_offline = True
    assert (await s.worker().advance(plan)).status == "pending"
    slot = request_slot(plan.body)
    intent = s.signer().journal.load(slot)
    expire_child(p, SimpleNamespace(attempt=SimpleNamespace(order=plan.body)), monkeypatch)
    s.peers_offline = False
    outcome = await s.worker().recover(slot)
    assert outcome.status == "certified"
    assert s.signer().journal.load(slot) == intent
    chosen = selection_slot(outcome.selection)
    assert (
        await CohortEndpointGrantDelivery(p.delivery_recovery).deliver(chosen)
    ).status == "retained"
    assert (await request(p, TRANSLATE_PATH, plan.body.requests[0])).status_code == 422
    decision = (await coordinator(s.d).advance(chosen, plan.body.case_id)).certificate
    assert decision.decision.disposition == "retry_required"
    assert p.model.calls == 0


async def test_initial_constructor_uses_native_window(signing):
    s, p = signing, signing.p
    plan = await s.worker().initial(
        p.e.assignment, p.transport_policy, [r.video for r in p.requests]
    )
    assert plan.body == s.plan.body
    p.finality.blocks.clear()
    assert await s.worker().initial(p.e.assignment, p.transport_policy, []) == plan


@pytest.mark.parametrize("failed", [False, True])
async def test_dispatch_original_once_and_preserve_failure(signing, failed):
    p = signing.p
    p.model.fail = failed
    case = p.e.job.cases[0].case_id
    worker = CohortEndpointDispatcher(p.delivery_recovery, p.finality)
    result = await worker.dispatch(p.retire_slot, case)
    assert result["status"] == "recovered", result
    count = len(p.transmissions)
    p.c.finality.fail = True
    p.finality.blocks.clear()
    result = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        p.retire_slot, case
    )
    assert result["status"] == "recovered"
    assert p.model.calls == 1 and len(p.transmissions) == count


@pytest.mark.parametrize(
    "stage", ["intent_before", "intent_after", "receipt_before", "receipt_after"]
)
async def test_dispatch_interrupted_commit_recovers_without_duplicate_inference(
    signing, monkeypatch, stage
):
    p = signing.p
    case = p.e.job.cases[0].case_id
    worker = CohortEndpointDispatcher(p.delivery_recovery, p.finality)
    db = p.delivery_recovery.journal.journal
    real = db.put

    def put(kind, key, value):
        wanted = (
            "endpoint_dispatch_intent"
            if stage.startswith("intent")
            else "endpoint_dispatch_receipt"
        )
        if kind == wanted:
            if stage.endswith("after"):
                real(kind, key, value)
            raise OSError("dispatch commit interrupted")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(db, "put", put)
        with pytest.raises(OSError, match="commit interrupted"):
            await worker.dispatch(p.retire_slot, case)
    result = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        p.retire_slot, case
    )
    assert result["status"] == "recovered", result
    assert p.model.calls == 1


async def test_dispatch_lost_response_ack_fetches_sealed_reply(signing):
    import httpx

    p = signing.p
    original = p.delivery_recovery.transport

    class Lost(httpx.AsyncBaseTransport):
        async def handle_async_request(self, req):
            response = await original.handle_async_request(req)
            if req.url.path == TRANSLATE_PATH:
                assert response.status_code == 200
                raise httpx.ReadTimeout("reply lost")
            return response

    p.delivery_recovery.transport = Lost()
    worker = CohortEndpointDispatcher(p.delivery_recovery, p.finality)
    case = p.e.job.cases[0].case_id
    assert (await worker.dispatch(p.retire_slot, case))["status"] == "pending"
    assert p.model.calls == 1
    assert (await worker.dispatch(p.retire_slot, case))["status"] == "recovered"
    assert p.model.calls == 1
    assert sum(path == TRANSLATE_PATH for path, *_ in p.transmissions) == 1


async def reject_first_translate(p):
    import httpx

    original = p.delivery_recovery.transport
    seen = []

    class RejectFirst(httpx.AsyncBaseTransport):
        async def handle_async_request(self, req):
            if req.url.path == TRANSLATE_PATH:
                seen.append((req.content, dict(req.headers)))
                if len(seen) == 1:
                    return httpx.Response(503, content=b"temporary admission unavailable")
            return await original.handle_async_request(req)

    p.delivery_recovery.transport = RejectFirst()
    worker = CohortEndpointDispatcher(p.delivery_recovery, p.finality)
    assert (await worker.dispatch(p.retire_slot, p.case_id))["status"] == "pending"
    assert p.model.calls == 0
    return worker, seen


async def test_transient_admission_retries_same_request_with_fresh_auth(signing):
    from umi.competition_cohort_endpoint_selection import case_record_key

    p = signing.p
    worker, seen = await reject_first_translate(p)
    selected, *_ = p.delivery_recovery.selection(p.retire_slot)
    key = case_record_key(selected, p.case_id)
    db = p.delivery_recovery.journal.journal
    original = {
        kind: canonical_json_bytes(db.get(kind, key))
        for kind in ("endpoint_dispatch_intent", "endpoint_dispatch_receipt")
    }
    result = await worker.dispatch(p.retire_slot, p.case_id)
    assert result["status"] == "recovered", result
    assert len(seen) == 2 and seen[0][0] == seen[1][0]
    assert seen[0][1] != seen[1][1]
    assert p.model.calls == 1
    for kind, raw in original.items():
        assert canonical_json_bytes(db.get(kind, key)) == raw
    result = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        p.retire_slot, p.case_id
    )
    assert result["status"] == "recovered" and len(seen) == 2 and p.model.calls == 1
    decision = (await coordinator(signing.d).advance(p.retire_slot, p.case_id)).certificate
    assert decision.decision.disposition == "retain_response"


@pytest.mark.parametrize(
    "stage", ["intent_before", "intent_after", "receipt_before", "receipt_after"]
)
async def test_dispatch_retry_commit_interruption_never_sends_third(signing, monkeypatch, stage):
    p = signing.p
    worker, seen = await reject_first_translate(p)
    db = p.delivery_recovery.journal.journal
    real = db.put

    def put(kind, key, value):
        wanted = (
            "endpoint_dispatch_retry_intent"
            if stage.startswith("intent")
            else "endpoint_dispatch_retry_receipt"
        )
        if kind == wanted:
            if stage.endswith("after"):
                real(kind, key, value)
            raise OSError("retry commit interrupted")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(db, "put", put)
        with pytest.raises(OSError, match="retry commit interrupted"):
            await worker.dispatch(p.retire_slot, p.case_id)
    result = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        p.retire_slot, p.case_id
    )
    if stage == "intent_after":
        assert result["status"] == "pending" and len(seen) == 1 and p.model.calls == 0
    else:
        assert result["status"] == "recovered", result
        assert len(seen) == 2 and p.model.calls == 1
    before = len(seen)
    await worker.dispatch(p.retire_slot, p.case_id)
    assert len(seen) == before


async def test_dispatch_retry_does_not_repeat_inference_when_response_lookup_fails(signing):
    import httpx

    from umi.endpoint_protocol import RESPONSE_RECOVERY_PATH

    p = signing.p
    original = p.delivery_recovery.transport
    seen = []

    class Lost(httpx.AsyncBaseTransport):
        async def handle_async_request(self, req):
            if req.url.path == RESPONSE_RECOVERY_PATH:
                return httpx.Response(503)
            response = await original.handle_async_request(req)
            if req.url.path == TRANSLATE_PATH:
                seen.append(req.content)
                if len(seen) == 1:
                    assert response.status_code == 200
                    raise httpx.ReadTimeout("original acknowledgement lost")
            return response

    p.delivery_recovery.transport = Lost()
    worker = CohortEndpointDispatcher(p.delivery_recovery, p.finality)
    assert (await worker.dispatch(p.retire_slot, p.case_id))["status"] == "pending"
    assert (await worker.dispatch(p.retire_slot, p.case_id))["status"] == "recovered"
    assert len(seen) == 2 and seen[0] == seen[1] and p.model.calls == 1


async def test_dispatch_retry_expiry_keeps_original_and_consumes_no_new_intent(
    signing, monkeypatch
):
    from umi.competition_cohort_endpoint_selection import case_record_key

    p = signing.p
    worker, seen = await reject_first_translate(p)
    expire_child(p, p.grant, monkeypatch)
    result = await worker.dispatch(p.retire_slot, p.case_id)
    assert result["status"] == "pending"
    assert len(seen) == 1 and p.model.calls == 0
    selected, *_ = p.delivery_recovery.selection(p.retire_slot)
    assert (
        p.delivery_recovery.journal.journal.get(
            "endpoint_dispatch_retry_intent", case_record_key(selected, p.case_id)
        )
        is None
    )


async def test_dispatch_retry_unknown_second_outcome_exhausts_budget(signing):
    import httpx

    p = signing.p
    worker, seen = await reject_first_translate(p)
    original = p.delivery_recovery.transport

    class LostAgain(httpx.AsyncBaseTransport):
        async def handle_async_request(self, req):
            if req.url.path == TRANSLATE_PATH:
                seen.append((req.content, dict(req.headers)))
                raise httpx.ConnectTimeout("retry outcome unknown")
            return await original.handle_async_request(req)

    p.delivery_recovery.transport = LostAgain()
    assert (await worker.dispatch(p.retire_slot, p.case_id))["status"] == "pending"
    for _ in range(2):
        assert (
            await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
                p.retire_slot, p.case_id
            )
        )["status"] == "pending"
    assert len(seen) == 2 and p.model.calls == 0


async def test_dispatch_no_send_after_window_expiry(signing, monkeypatch):
    p = signing.p
    expire_child(p, p.grant, monkeypatch)
    count = len(p.transmissions)
    result = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        p.retire_slot, p.case_id
    )
    assert result["status"] == "pending" and "deadline" in result["reason"]
    assert p.model.calls == 0 and len(p.transmissions) == count


async def test_pending_request_signature_requires_current_authority(signing):
    from .test_competition_cohort_order_signer import source_for

    s = signing
    s.fail_sign = True
    with pytest.raises(OSError):
        await s.signer().attest(s.plan)
    s.fail_sign = False
    s.p.e.r.h.source = source_for(s.p.e.r.h.batch, s.p.e.r.h.batch["history"])
    with pytest.raises(ValueError, match="request phase"):
        await s.signer().recover(request_slot(s.plan.body))
    assert len(s.calls) == 1


@pytest.mark.parametrize("after", [False, True])
async def test_case_pipeline_recovers_interrupted_successor_handoff(signing, monkeypatch, after):
    from umi.competition_cohort_attempt_worker import CohortEndpointAttemptWorker

    s, p = signing, signing.p
    plan = await child_plan(s, monkeypatch)
    case = plan.body.case_id

    def pipeline():
        return CohortEndpointAttemptWorker(s.worker(), coordinator(s.d))

    db = p.delivery_recovery.journal.journal
    real = db.put

    def put(kind, key, value):
        if kind == "endpoint_attempt_successor":
            if after:
                real(kind, key, value)
            raise OSError("handoff interrupted")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(db, "put", put)
        with pytest.raises(OSError, match="handoff interrupted"):
            await pipeline().advance(p.retire_slot, case)
    result = await pipeline().advance(p.retire_slot, case)
    if result["status"] == "pending":
        assert result["reason"] == "certified_replacement_ready"
        result = await pipeline().advance(p.retire_slot, case)
    assert result["status"] == "completed", result
    assert result["certificate"].decision.attempt_number == 2
    assert p.model.calls == 1
    p.c.finality.fail = True
    p.finality.blocks.clear()
    s.peers_offline = True
    result = await pipeline().advance(p.retire_slot, case)
    assert result["status"] == "completed" and p.model.calls == 1


@pytest.mark.parametrize("after", [False, True])
async def test_certificate_commit_interruption_freezes_original_quorum(signing, monkeypatch, after):
    s = signing
    a, b = s.signer(), s.signer(s.other)
    await a.attest(s.plan)
    slot = request_slot(s.plan.body)
    await a.collect(slot, await b.attest(s.plan))
    real = a.journal.journal.put

    def put(kind, key, value):
        if kind == "request_certificate":
            if after:
                real(kind, key, value)
            raise OSError("certificate commit interrupted")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(a.journal.journal, "put", put)
        with pytest.raises(OSError, match="commit interrupted"):
            await a.certify(slot)
    s.p.c.finality.fail = True
    s.p.finality.blocks.clear()
    cert = await s.signer().certify(slot)
    assert cert.order == s.plan.body
    assert len(s.calls) == 2


async def test_request_capacity_can_grow_without_new_selection(signing):
    s = signing
    s.overrides = {"maximum_bytes": 1024}
    with pytest.raises(ValueError, match="capacity"):
        await s.signer().attest(s.plan)
    assert not s.calls
    s.overrides = {"maximum_bytes": 128 * 1024**2}
    await s.signer().attest(s.plan)
    assert s.signer().journal.load(request_slot(s.plan.body)).plan == s.plan


@pytest.mark.parametrize("close_during_admission", [False, True])
@pytest.mark.parametrize("miner_scope", ["all", "matched", "empty", "other"])
async def test_fresh_replacement_works_inside_legacy_blackout(
    signing, monkeypatch, close_during_admission, miner_scope
):
    import bittensor as bt

    from umi.competition_cohort_request_window import capture_request_window
    from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, quicknet_round_at_ms

    s, p = signing, signing.p
    review = await s.d.evidence(index=1)
    certificate = (
        await coordinator(s.d).advance(p.retire_slot, review.retirement.case_id)
    ).certificate
    parent_bytes = canonical_json_bytes(p.grant)
    template = next_grant(s.d, p.grant, review, certificate, monkeypatch)
    legacy = template.attempt.order.requests[0]
    issuance = p.finality.blocks[legacy.issued_block]
    # Proof collection or an outage crossed the old fixed issuance opportunity.
    issuance = replace(
        issuance,
        timestamp_ms=(QUICKNET_GENESIS_MS + (legacy.response_close_round + 1) * QUICKNET_PERIOD_MS),
    )
    p.finality.blocks[issuance.height] = issuance
    monkeypatch.setattr(
        bt.timelock, "current_round", lambda: quicknet_round_at_ms(issuance.timestamp_ms)
    )
    with pytest.raises(ValueError, match="outside its verified window"):
        await capture_request_window(p.transport_policy, p.finality, issuance.height)

    selected_miners = {
        "all": None,
        "matched": (p.e.job.submission.submission.hotkey,),
        "empty": (),
        "other": (wallet(s.own).hotkey.ss58_address,),
    }[miner_scope]
    worker = s.worker(fresh_windows=True, fresh_window_miner_hotkeys=selected_miners)
    if miner_scope in {"empty", "other"}:
        with pytest.raises(ValueError, match="outside its verified window"):
            await worker.replacement(
                p.grant, certificate, review.retirement.retirement, p.transport_policy, legacy.video
            )
        assert worker.signer.journal.load(request_slot(template.attempt.order)) is None
        assert canonical_json_bytes(p.grant) == parent_bytes
        assert p.model.calls == p.fetcher.calls == 0
        return
    plan = await worker.replacement(
        p.grant,
        certificate,
        review.retirement.retirement,
        p.transport_policy,
        legacy.video,
    )
    # Removing the canary selection cannot reinterpret a retained request.
    worker.fresh_window_miner_hotkeys = frozenset()
    assert (
        await worker.replacement(
            p.grant, certificate, review.retirement.retirement, p.transport_policy, legacy.video
        )
        == plan
    )
    signed_request = plan.body.requests[0]
    assert signed_request.response_close_round > bt.timelock.current_round()
    assert canonical_json_bytes(p.grant) == parent_bytes
    # Both clock representations use exactly the same issuance and nominal budget.
    round_ms = QUICKNET_GENESIS_MS + (signed_request.response_close_round - 1) * QUICKNET_PERIOD_MS
    block_ms = (signed_request.deadline_block - signed_request.issued_block) * (
        p.transport_policy.clock.target_block_interval_seconds * 1000
    )
    assert 0 <= round_ms - issuance.timestamp_ms - block_ms < QUICKNET_PERIOD_MS
    saved = worker.signer.journal.load(request_slot(plan.body))
    assert saved.windows[0].schema_ == "umi-cohort-attempt-window/2"
    # Restart the reviewer and replay the retained proof, before actual delivery.
    assert await s.signer().recover(request_slot(plan.body)) == worker.signer.journal.vote(
        request_slot(plan.body), worker.signer.journal.config.signer
    )
    outcome = await worker.advance(plan)
    assert outcome.status == "certified"
    selected = outcome.selection
    if close_during_admission:
        from umi.competition_cohort_request_admission import CohortRequestWindowAuthority

        from .test_competition_cohort_order_signer import source_for

        delivered = await CohortEndpointGrantDelivery(p.delivery_recovery).deliver(
            selection_slot(selected)
        )
        assert delivered.status == "retained", delivered
        original = CohortRequestWindowAuthority.authorize
        prior = p.e.r.h.source

        async def close_after_check(authority, candidate):
            admitted = await original(authority, candidate)
            p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
            return admitted

        monkeypatch.setattr(CohortRequestWindowAuthority, "authorize", close_after_check)
        response = await request(p, TRANSLATE_PATH, signed_request)
        assert response.status_code == 422, response.text
        monkeypatch.setattr(CohortRequestWindowAuthority, "authorize", original)
        p.miner = p.rebuild()
        p.e.r.h.source = prior
        response = await request(p, TRANSLATE_PATH, signed_request)
        assert response.status_code == 422, response.text
        assert p.model.calls == p.fetcher.calls == 0
        assert canonical_json_bytes(p.grant) == parent_bytes
        return
    dispatch = CohortEndpointDispatcher(p.delivery_recovery, p.finality)
    result = await dispatch.dispatch(selection_slot(selected), plan.body.case_id)
    assert result["status"] == "recovered", result
    assert p.model.calls == 1
    assert p.delivery_recovery.retained(selection_slot(selected), plan.body.case_id) is not None
    transmissions = len(p.transmissions)
    result = await CohortEndpointDispatcher(p.delivery_recovery, p.finality).dispatch(
        selection_slot(selected), plan.body.case_id
    )
    assert result["status"] == "recovered"
    assert p.model.calls == 1 and len(p.transmissions) == transmissions
    assert canonical_json_bytes(p.grant) == parent_bytes


@pytest.mark.parametrize("dependency", ["history", "collect"])
async def test_request_proof_wait_does_not_block_another_vote(signing, monkeypatch, dependency):
    s, entered, release = signing, asyncio.Event(), asyncio.Event()
    signer = s.signer()
    owner = signer if dependency == "history" else signer.provider
    original = getattr(owner, dependency)
    calls = 0

    async def delayed(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            await release.wait()
        return await original(*args)

    monkeypatch.setattr(owner, dependency, delayed)
    first = asyncio.create_task(signer.attest(s.plan))
    try:
        await asyncio.wait_for(entered.wait(), 30)
        with signer.journal.journal.locked():
            pass
        vote = await asyncio.wait_for(signer.attest(s.plan), 30)
    finally:
        release.set()
        result = await asyncio.wait_for(first, 30)
    assert result == vote
    assert len(s.calls) == 1
