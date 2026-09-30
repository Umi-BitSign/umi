"""Durable request construction/signing through real grant and miner handlers.

Finality, peer transport, DNS and inference are fixtures. Proof bytes are retained
but the fixture finality verifier is not a production chain qualification.
"""

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
    s.worker = lambda: CohortEndpointRequestWorker(signer(), p.delivery_recovery, peer)
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
    if stage == "intent_after":
        assert result["status"] == "pending"
        assert p.model.calls == 0
        expire_child(p, p.grant, monkeypatch)
        decision = (await coordinator(signing.d).advance(p.retire_slot, case)).certificate
        assert decision.decision.disposition == "retry_required"
    else:
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
