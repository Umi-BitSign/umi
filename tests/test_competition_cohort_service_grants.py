"""Catalog-scoped service grants through real miner ASGI and durable storage.

Finality, history, video and inference ports are fixtures. Native signatures,
grant admission, retirement and response recovery are exercised without logs of
request bodies or response envelopes.
"""

import hashlib
import time
from dataclasses import replace
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest

from umi.auth import HotkeyAuth, RequestAuthenticator
from umi.competition_cohort_endpoint_decision_contracts import (
    CohortEndpointCaseDecision,
    SignedCohortEndpointCaseDecision,
)
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_miner import (
    CohortMinerConfig,
    CohortServiceMinerConfig,
    SignedCohortMinerGrantReceipt,
)
from umi.competition_cohort_miner_case import grant_slot, parse_miner_grant
from umi.competition_cohort_order_signer import CohortOrderParticipant
from umi.competition_cohort_request_window import (
    EndpointRequestWindow,
    RetainedRequestBlock,
    capture_request_window,
)
from umi.competition_cohort_service_grant import (
    ServiceMinerGrant,
    service_grant_slot,
    service_obligation,
    service_wire_ids,
    verify_service_grant,
    verify_service_parent,
)
from umi.competition_cohort_service_queue import ServiceWorkQueue, ServiceWorkQueueConfig
from umi.competition_cohort_service_requests import ServiceWorkRequests
from umi.competition_cohort_service_work import (
    ServiceWorkAssignment,
    ServiceWorkCatalog,
    ServiceWorkClaim,
    SignedServiceWorkCatalog,
    SignedServiceWorkClaim,
)
from umi.config import Limits
from umi.endpoint_protocol import (
    COHORT_GRANT_PATH,
    COHORT_RETIRE_PATH,
    RESPONSE_RECOVERY_PATH,
    TRANSLATE_PATH,
)
from umi.endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from umi.miner import create_app
from umi.miner_resources import SQLiteMinerResourceLedger
from umi.open_competition import Evaluator, digest, identity, sign_object, verify_signature
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes, request_digest
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from . import test_competition_cohort_miner as miner_fixtures
from .test_competition_cohort_disposition import order as signed_order
from .test_competition_cohort_endpoint import endpoint_scenario
from .test_competition_cohort_miner import base_policy as base_policy
from .test_competition_cohort_miner import chain as chain
from .test_competition_cohort_miner import chain_config as chain_config
from .test_competition_cohort_miner import endpoint as endpoint
from .test_competition_cohort_miner import execution as execution
from .test_competition_cohort_miner import granted as granted
from .test_competition_cohort_miner import known_video_bytes as known_video_bytes
from .test_competition_cohort_miner import legacy_scenario as legacy_scenario
from .test_competition_cohort_miner import receipt_scenario as receipt_scenario
from .test_competition_cohort_miner import recovery as recovery
from .test_competition_cohort_miner import recovery_case as recovery_case
from .test_competition_cohort_miner import relay as relay
from .test_competition_cohort_miner import request
from .test_competition_cohort_miner import runtime as runtime
from .test_competition_cohort_miner import scenario as scenario
from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_service_queue import capture
from .test_open_competition import wallet
from .test_validator_plans import _block, _clock

miner_policy = miner_fixtures.policy
original_harness = miner_fixtures.harness


@pytest.fixture
def harness(original_harness):
    h = original_harness
    # Changing policy changes content-addressed roster ordering. Select the
    # actual Bob record required by the native miner fixture, not index zero.
    who = wallet("Bob").hotkey.ss58_address
    h.order = next(
        signed_order(s).order for s in h.batch["scenarios"] if s["signed"].submission.hotkey == who
    )
    p = next(
        p
        for p in h.batch["roster"].participants
        if p.record.request.signed_submission.submission.hotkey == who
    )
    h.participant = CohortOrderParticipant(
        consent=p.record.request.consent,
        admission=p.admission,
        admission_snapshot=p.record.snapshot,
    )
    return h


@pytest.fixture
def shared_control_group(request):
    return getattr(request, "param", False)


@pytest.fixture
def policy(miner_policy, shared_control_group):
    if not shared_control_group:
        return miner_policy
    # Add the second key before any cohort, catalog or request is signed.
    return miner_policy.model_copy(
        update={
            "evaluators": (
                *miner_policy.evaluators,
                Evaluator(hotkey=wallet("Eve").hotkey.ss58_address, control_group="c"),
            )
        }
    )


def admitted_service(p, directory, *, catalog_number=1, terms=None, references=None):
    source, round_ = p.e.r.h.source, p.e.job.round
    work = tuple(
        {
            "case_id": f"{900 + i:064x}",
            "video_sha256": p.service_video.sha256 if i == 0 else case.video_sha256,
            "reference_sha256": (
                digest(references[i])
                if references is not None
                else digest({"reference": f"service-reference-{i}"})
            ),
            "stratum": references[i].stratum if references is not None else case.stratum,
        }
        for i, case in enumerate(p.e.job.cases[:2])
    )
    assert not {w["case_id"] for w in work} & {c.case_id for c in p.e.job.cases}
    body = ServiceWorkCatalog(
        schema="umi-cohort-service-work-catalog/1",
        policy_sha256=digest(p.c.policy),
        cohort_sha256=round_.cohort_sha256,
        authority_sha256=digest(source.history.authority.authority),
        round_sha256=digest(round_),
        service_terms_sha256=digest(terms) if terms is not None else "a1" * 32,
        issued_at_block=399 + catalog_number,
        work=work,
        selection_rule="global_fifo_no_identity_quota",
        credit_rule="verified_terminal_work_only",
    )
    catalog = SignedServiceWorkCatalog(catalog=body, signatures=signatures(body))
    cfg = ServiceWorkQueueConfig(
        schema="umi-cohort-service-work-queue-config/1",
        directory=str(directory),
        policy_sha256=digest(p.c.policy),
        catalog_sha256=digest(body),
        service_terms_sha256=body.service_terms_sha256,
    )
    queue = ServiceWorkQueue(cfg, p.c.policy)
    observed = capture(body.issued_at_block)
    queue.install(
        catalog, round_, source, observed, expected_tip_sha256=history_tip(source.history)
    )
    submission, participant = p.e.job.submission, p.e.assignment.participant
    claim = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256=digest(body),
        hotkey=submission.submission.hotkey,
        submission_sha256=digest(submission.submission),
        nonce="01" * 32,
    )
    signed = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, p.miner.wallet))
    admission = queue.admit(
        signed,
        submission,
        participant,
        source,
        observed,
        expected_tip_sha256=history_tip(source.history),
    )
    # Export after reopening the queue; the exported assignment is retained evidence.
    queue = ServiceWorkQueue(cfg, p.c.policy)
    assignment = queue.assignment(signed)
    assert isinstance(assignment, ServiceWorkAssignment)
    assert assignment.admission == admission
    assert assignment.catalog == catalog and assignment.source == source
    assert assignment.previous is None
    assert not admission.service_credit_authorized and not admission.chain_submission_authorized
    return SimpleNamespace(queue=queue, cfg=cfg, claim=signed, assignment=assignment)


def signed_grant(body):
    return ServiceMinerGrant(
        schema="umi-cohort-miner-service-grant/1", body=body, signatures=signatures(body)
    )


def produce_grant(p, c, window, **parent):
    assignment = c.assignment
    case = assignment.catalog.catalog.work[assignment.admission.ordinal - 1]
    video = next(
        v
        for v in (p.service_video, *(r.video for r in p.requests))
        if v.sha256 == case.video_sha256
    )
    evaluator = p.validator.hotkey.ss58_address
    producer = ServiceWorkRequests(c.queue, p.transport_policy)
    body = producer.prepare(
        c.claim, evaluator, video, window, p.e.r.h.source, capture(p.finality.head), **parent
    )
    slot = service_grant_slot(body)
    for signature in signatures(body):
        producer.collect(slot, signature)
    return producer.certificate(slot)


@pytest.fixture
def service_catalog_inputs(request):
    return getattr(request, "param", False)


@pytest.fixture
async def service_owner(granted, tmp_path, monkeypatch, service_catalog_inputs):
    p = granted
    service_bytes = b"catalog-only-service-video-outside-benchmark-inventory"
    p.service_video = p.requests[0].video.model_copy(
        update={
            "sha256": hashlib.sha256(service_bytes).hexdigest(),
            "size_bytes": len(service_bytes),
            "url": "https://example.com/service-only-video.mp4",
        }
    )
    assert p.service_video.sha256 not in {case.video_sha256 for case in p.e.job.cases}
    fetch = p.fetcher.fetch

    async def service_fetch(descriptor):
        if descriptor.sha256 == p.service_video.sha256:
            p.fetcher.calls += 1
            return service_bytes
        return await fetch(descriptor)

    monkeypatch.setattr(p.fetcher, "fetch", service_fetch)
    terms, references = None, None
    if service_catalog_inputs:
        from umi.competition_cohort_service_quality import ServiceReference, ServiceTerms

        terms = ServiceTerms(
            schema="umi-cohort-service-terms/1",
            policy_sha256=digest(p.c.policy),
            transport_policy_sha256=scoring_policy_hash(p.transport_policy),
            service_pool_bps=7000,
            stratum_weights={"fingerspelling": 3, "continuous": 10},
        )
        references = tuple(
            ServiceReference(
                schema="umi-cohort-service-reference/1",
                case_id=f"{900 + i:064x}",
                video_sha256=p.service_video.sha256 if i == 0 else case.video_sha256,
                stratum="continuous"
                if service_catalog_inputs == "wer_partial" or i
                else "fingerspelling",
                salt="41" * 32,
                reference={"cer_partial": "hello worle", "wer_partial": "hello there"}.get(
                    service_catalog_inputs, "hello world"
                ),
            )
            for i, case in enumerate(p.e.job.cases[:2])
        )
    c = admitted_service(p, tmp_path / "service-queue", terms=terms, references=references)
    c.terms, c.references = terms, references
    if service_catalog_inputs == "miner_failure":
        p.model.fail = True
    c.p, c.tmp_path = p, tmp_path
    if service_catalog_inputs:
        from .test_drand import ROUND

        shift_ms = (p.requests[0].reveal_round - ROUND) * QUICKNET_PERIOD_MS
        p.finality.blocks = {
            height: replace(block, timestamp_ms=block.timestamp_ms - shift_ms)
            for height, block in p.finality.blocks.items()
        }
    c.window = await capture_request_window(
        p.transport_policy, p.finality, p.requests[0].issued_block
    )
    if service_catalog_inputs:
        # This native timelock fixture uses a retained, verifiable Quicknet pulse.
        # Keep the miner's execution clock inside its original request window.
        monkeypatch.setattr(time, "time", lambda: c.window.issuance.timestamp_ms / 1000)
    monkeypatch.setattr(
        bt.timelock, "current_round", lambda: c.window.schedule(p.transport_policy).selection_round
    )
    p.miner_cfg = CohortServiceMinerConfig.model_validate(
        {
            **p.miner_cfg.model_dump(by_alias=True),
            "schema": "umi-cohort-service-miner-config/1",
            "directory": str(tmp_path / "service-miner"),
            "service_terms_sha256": c.assignment.catalog.catalog.service_terms_sha256,
        }
    )
    p.miner = p.rebuild()
    try:
        yield c
    finally:
        p.miner.resource_ledger.close()


@pytest.fixture
def service(service_owner):
    c = service_owner
    c.grant = produce_grant(c.p, c, c.window)
    return c


def restart_miner(c):
    p = c.p
    p.miner.resource_ledger.close()
    ledger = SQLiteMinerResourceLedger(
        c.tmp_path / "miner.sqlite",
        miner_hotkey=p.miner.hotkey_ss58,
        scoring_policy_sha256=scoring_policy_hash(p.transport_policy),
        limits=Limits.from_policy(p.transport_policy),
        maximum_recovery_assignments=8,
    )
    p.miner = replace(
        p.rebuild(),
        resource_ledger=ledger,
        authenticator=RequestAuthenticator.in_memory(p.miner.hotkey_ss58),
    )


async def accept(c, grant=None):
    return await request(c.p, COHORT_GRANT_PATH, c.grant if grant is None else grant)


@pytest.mark.parametrize("stage", ["selection", "certificate"])
@pytest.mark.parametrize("after_commit", [False, True])
async def test_service_owner_recovers_selection_and_certificate_writes(
    service_owner, monkeypatch, stage, after_commit
):
    c, p = service_owner, service_owner.p
    producer = ServiceWorkRequests(c.queue, p.transport_policy)
    evaluator = p.validator.hotkey.ss58_address
    inputs = (
        c.claim,
        evaluator,
        p.service_video,
        c.window,
        p.e.r.h.source,
        capture(p.finality.head),
    )
    saved = []
    if stage == "selection":
        original = producer.journal.put_many

        def interrupted(records, **kwargs):
            records = tuple(records)
            selections = [value for kind, _, value in records if kind == "service_request"]
            if selections:
                saved.append(canonical_json_bytes(selections[0]))
                if after_commit:
                    original(records, **kwargs)
                raise OSError("fixture interrupted request selection")
            return original(records, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(producer.journal, "put_many", interrupted)
            with pytest.raises(OSError, match="fixture interrupted request selection"):
                producer.prepare(*inputs)
    else:
        body = producer.prepare(*inputs)
        slot = service_grant_slot(body)
        for signature in signatures(body):
            producer.collect(slot, signature)
        original = producer.journal.put

        def interrupted(kind, key, value, **kwargs):
            if kind == "service_grant":
                saved.append(canonical_json_bytes(value))
                if after_commit:
                    original(kind, key, value, **kwargs)
                raise OSError("fixture interrupted certificate")
            return original(kind, key, value, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(producer.journal, "put", interrupted)
            with pytest.raises(OSError, match="fixture interrupted certificate"):
                producer.certificate(slot)
    assert len(saved) == 1
    assert p.fetcher.calls == p.model.calls == 0
    c.queue = ServiceWorkQueue(c.cfg, p.c.policy)
    producer = ServiceWorkRequests(c.queue, p.transport_policy)
    # A committed selection recovers without current video, finality or history.
    if stage == "selection" and not after_commit:
        body = producer.prepare(*inputs)
    else:
        body = producer.prepare(c.claim, evaluator, None, None, None, None)
    slot = service_grant_slot(body)
    if stage == "selection":
        assert canonical_json_bytes(body) == saved[0]
        for signature in signatures(body):
            producer.collect(slot, signature)
    certificate = producer.certificate(slot)
    if stage == "certificate":
        assert canonical_json_bytes(certificate) == saved[0]
    assert canonical_json_bytes(producer.certificate(slot)) == canonical_json_bytes(certificate)
    assert c.queue.entries() == (c.assignment.admission,)
    assert (await accept(c, certificate)).status_code == 200
    result = await request(p, TRANSLATE_PATH, body.request)
    assert result.status_code == 200
    assert (await request(p, TRANSLATE_PATH, body.request)).content == result.content
    assert p.fetcher.calls == p.model.calls == 1


@pytest.mark.parametrize("after_commit", [False, True])
async def test_service_owner_reservation_loss_preserves_body_across_changed_window(
    service_owner, monkeypatch, after_commit
):
    c, p = service_owner, service_owner.p
    producer = ServiceWorkRequests(c.queue, p.transport_policy)
    original, saved = producer.journal.reserve_records, []

    def interrupted(slot, reservations):
        retained = producer.journal.get("service_request", slot)
        assert retained is not None
        saved.append(canonical_json_bytes(retained))
        if after_commit:
            original(slot, reservations)
        raise OSError("fixture interrupted recovery reservation")

    evaluator = p.validator.hotkey.ss58_address
    with monkeypatch.context() as patch:
        patch.setattr(producer.journal, "reserve_records", interrupted)
        with pytest.raises(OSError, match="fixture interrupted recovery reservation"):
            producer.prepare(
                c.claim,
                evaluator,
                p.service_video,
                c.window,
                p.e.r.h.source,
                capture(p.finality.head),
            )
    assert len(saved) == 1
    c.queue = ServiceWorkQueue(c.cfg, p.c.policy)
    producer = ServiceWorkRequests(c.queue, p.transport_policy)
    changed_window = fresh_window(p, p.requests[0], monkeypatch)
    assert changed_window != c.window
    changed_video = p.service_video.model_copy(
        update={
            "url": p.service_video.url + "?different-current-input=1",
        }
    )
    body = producer.prepare(
        c.claim,
        evaluator,
        changed_video,
        changed_window,
        p.e.r.h.source,
        capture(p.finality.head),
    )
    assert canonical_json_bytes(body) == saved[0]
    assert body.window == c.window
    assert producer.prepare(c.claim, evaluator, None, None, None, None) == body
    slot = service_grant_slot(body)
    for signature in signatures(body):
        producer.collect(slot, signature)
    certificate = producer.certificate(slot)
    assert (await accept(c, certificate)).status_code == 200
    # Recovery of selection does not retime the expired inference opportunity.
    assert (await request(p, TRANSLATE_PATH, body.request)).status_code == 422
    assert p.model.calls == p.fetcher.calls == 0


def test_service_owner_holds_evaluator_and_replays_original_selection(service_owner):
    c, p = service_owner, service_owner.p
    producer = ServiceWorkRequests(c.queue, p.transport_policy)
    evaluator = p.validator.hotkey.ss58_address
    body = producer.prepare(
        c.claim,
        evaluator,
        p.service_video,
        c.window,
        p.e.r.h.source,
        capture(p.finality.head),
    )
    other = next(
        e.hotkey for e in p.c.policy.evaluators if identity(e.hotkey) != identity(evaluator)
    )
    with pytest.raises(ValueError, match="another evaluator"):
        producer.prepare(
            c.claim,
            other,
            p.service_video,
            c.window,
            p.e.r.h.source,
            capture(p.finality.head),
        )
    producer = ServiceWorkRequests(ServiceWorkQueue(c.cfg, p.c.policy), p.transport_policy)
    assert producer.prepare(c.claim, evaluator, None, None, None, None) == body
    slot = service_grant_slot(body)
    votes = signatures(body)
    producer.collect(slot, votes[0])
    with pytest.raises(ValueError):
        producer.certificate(slot)
    for signature in votes[1:]:
        producer.collect(slot, signature)
    certificate = producer.certificate(slot)
    assert certificate.body == body
    assert p.model.calls == p.fetcher.calls == 0


@pytest.mark.parametrize("shared_control_group", [True], indirect=True)
async def test_service_certificate_keeps_one_authentic_vote_per_control_group(service_owner):
    c, p = service_owner, service_owner.p
    producer = ServiceWorkRequests(c.queue, p.transport_policy)
    body = producer.prepare(
        c.claim,
        p.validator.hotkey.ss58_address,
        p.service_video,
        c.window,
        p.e.r.h.source,
        capture(p.finality.head),
    )
    slot = service_grant_slot(body)
    for name in ("Charlie", "Eve"):
        producer.collect(slot, sign_object(body, wallet(name)))
    with pytest.raises(ValueError):
        producer.certificate(slot)
    producer.collect(slot, sign_object(body, wallet("Dave")))
    certificate = producer.certificate(slot)
    groups = {identity(e.hotkey): e.control_group for e in p.c.policy.evaluators}
    assert len(certificate.signatures) == 2
    assert len({groups[identity(s.hotkey)] for s in certificate.signatures}) == 2
    for signature in certificate.signatures:
        verify_signature(body, signature)
    with c.queue.journal.transaction() as db:
        assert (
            db.execute("SELECT count(*) FROM records WHERE kind='service_request_vote'").fetchone()[
                0
            ]
            == 3
        )
    producer = ServiceWorkRequests(ServiceWorkQueue(c.cfg, p.c.policy), p.transport_policy)
    assert canonical_json_bytes(producer.certificate(slot)) == canonical_json_bytes(certificate)
    assert (await accept(c, certificate)).status_code == 200
    assert (await request(p, TRANSLATE_PATH, body.request)).status_code == 200
    assert p.model.calls == p.fetcher.calls == 1


async def test_service_large_finality_proofs_survive_owner_and_native_grant_storage(service_owner):
    c, p = service_owner, service_owner.p
    for retained, marker in ((c.window.announcement, b"a"), (c.window.issuance, b"b")):
        proof = marker * (3 * 1024**2)
        block = replace(
            retained.verified(),
            finality_evidence=proof,
            finality_evidence_sha256=hashlib.sha256(proof).hexdigest(),
        )
        p.finality.blocks[block.height] = block
    window = await capture_request_window(
        p.transport_policy, p.finality, p.requests[0].issued_block
    )
    certificate = produce_grant(p, c, window)
    assert 8 * 1024**2 < len(canonical_json_bytes(certificate.body)) < 16 * 1024**2
    assert len(canonical_json_bytes(certificate)) < 16 * 1024**2
    producer = ServiceWorkRequests(ServiceWorkQueue(c.cfg, p.c.policy), p.transport_policy)
    assert (
        producer.prepare(c.claim, p.validator.hotkey.ss58_address, None, None, None, None)
        == certificate.body
    )
    assert producer.certificate(grant_slot(certificate)) == certificate
    ack = await accept(c, certificate)
    assert ack.status_code == 200
    restart_miner(c)
    assert (await accept(c, certificate)).content == ack.content
    response = await request(p, TRANSLATE_PATH, certificate.body.request)
    assert response.status_code == 200
    recovered = await request(p, RESPONSE_RECOVERY_PATH, certificate.body.request)
    assert recovered.status_code == 200 and recovered.content == response.content
    assert p.model.calls == p.fetcher.calls == 1


async def test_service_admission_lost_response_restart_recovers_exact_native_bytes(
    service, monkeypatch
):
    c, p = service, service.p
    grant, req = c.grant, c.grant.body.request
    assert req.video.sha256 not in {case.video_sha256 for case in p.e.job.cases}
    assert (await request(p, TRANSLATE_PATH, req)).status_code == 422
    assert parse_miner_grant(canonical_json_bytes(grant)) == grant
    verify_service_grant(grant, p.c.policy, p.transport_policy)
    assert set(grant.body.assignment.model_dump()) == {
        "catalog",
        "round",
        "admission",
        "previous",
        "source",
    }
    ack = await accept(c)
    assert ack.status_code == 200
    receipt = SignedCohortMinerGrantReceipt.model_validate_json(ack.content)
    verify_signature(receipt.receipt, receipt.signature)
    assert receipt.receipt.grant_sha256 == digest(grant)
    assert receipt.receipt.miner_hotkey == p.miner.hotkey_ss58
    assert not receipt.receipt.chain_submission_authorized
    assert p.fetcher.calls == p.model.calls == 0
    saved = []
    inner = httpx.ASGITransport(app=create_app(p.miner))

    class LoseReply(httpx.AsyncBaseTransport):
        async def handle_async_request(self, wire):
            reply = await inner.handle_async_request(wire)
            assert reply.status_code == 200
            saved.append((await reply.aread(), reply.headers["x-umi-signature"]))
            await reply.aclose()
            raise httpx.ReadError("fixture lost response", request=wire)

    async with httpx.AsyncClient(transport=LoseReply(), base_url="https://example.com") as client:
        with pytest.raises(httpx.ReadError, match="fixture lost response"):
            await client.post(
                TRANSLATE_PATH,
                content=canonical_json_bytes(req),
                auth=HotkeyAuth(p.validator, p.miner.hotkey_ss58),
            )
    assert len(saved) == 1 and p.fetcher.calls == p.model.calls == 1
    restart_miner(c)
    for path in (TRANSLATE_PATH, RESPONSE_RECOVERY_PATH):
        assert (await accept(c)).content == ack.content
        # The second inference transmission exhausts the unchanged wire
        # allowance; further recovery uses the durable response route.
        duplicate = await request(p, path, req)
        assert duplicate.status_code == 200
        assert (duplicate.content, duplicate.headers["x-umi-signature"]) == saved[0]
    p.finality.head = req.deadline_block + 3000
    monkeypatch.setattr(bt.timelock, "current_round", lambda: req.reveal_round + 100)
    p.miner.resource_ledger.prune_closed_windows(req.response_close_round)
    assert (await request(p, TRANSLATE_PATH, req)).status_code == 422
    restart_miner(c)
    recovered = await request(p, RESPONSE_RECOVERY_PATH, req)
    assert recovered.status_code == 200
    assert (recovered.content, recovered.headers["x-umi-signature"]) == saved[0]
    assert (await accept(c)).content == ack.content
    assert p.fetcher.calls == p.model.calls == 1


@pytest.mark.parametrize("after_commit", [False, True])
async def test_service_lost_grant_ack_recovers_after_restart_without_history(
    service, monkeypatch, after_commit
):
    c, p = service, service.p
    journal = p.miner.competition_authority.journal
    original, saved = journal.put, []

    def lose(kind, key, value, **kwargs):
        if kind == "miner_grant_receipt":
            if after_commit:
                original(kind, key, value, **kwargs)
                saved.append(canonical_json_bytes(value))
            raise OSError("fixture lost grant acknowledgement")
        return original(kind, key, value, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(journal, "put", lose)
        assert (await accept(c)).status_code == 503
    restart_miner(c)

    async def unavailable(*args):
        raise OSError("fixture history unavailable")

    p.miner.competition_authority.history = unavailable
    ack = await accept(c)
    assert ack.status_code == 200
    if after_commit:
        assert ack.content == saved[0]
    assert (await accept(c)).content == ack.content
    assert (await request(p, TRANSLATE_PATH, c.grant.body.request)).status_code == 503
    assert p.model.calls == p.fetcher.calls == 0


@pytest.mark.parametrize(
    "damage", ["benchmark_case", "other_service_case", "video", "request", "caller"]
)
async def test_service_grant_authorizes_only_its_exact_request_and_caller(service, damage):
    c, p = service, service.p
    assert (await accept(c)).status_code == 200
    req, caller = c.grant.body.request, None
    if damage == "benchmark_case":
        req = p.requests[0]
    elif damage == "other_service_case":
        case = c.assignment.catalog.catalog.work[1]
        req = c.window.request_with_ids(
            case,
            p.requests[1].video,
            service_wire_ids(c.assignment, p.validator.hotkey.ss58_address, 1),
            p.transport_policy,
        )
    elif damage == "video":
        req = req.model_copy(update={"video": req.video.model_copy(update={"sha256": "ee" * 32})})
    elif damage == "request":
        req = req.model_copy(
            update={
                "challenge_id": service_wire_ids(c.assignment, p.validator.hotkey.ss58_address, 2)[
                    1
                ]
            }
        )
    else:
        caller = next(
            wallet(n)
            for n in ("Charlie", "Dave", "Eve", "Ferdie")
            if identity(wallet(n).hotkey.ss58_address) != identity(p.validator.hotkey.ss58_address)
        )
    for path in (TRANSLATE_PATH, COHORT_RETIRE_PATH):
        assert (await request(p, path, req, caller=caller)).status_code == 422
    assert (await request(p, RESPONSE_RECOVERY_PATH, req, caller=caller)).status_code in {404, 422}
    assert p.model.calls == p.fetcher.calls == 0
    assert (await request(p, TRANSLATE_PATH, c.grant.body.request)).status_code == 200
    assert p.model.calls == p.fetcher.calls == 1


@pytest.mark.parametrize(
    "damage",
    [
        "signature",
        "catalog_signature",
        "claim_signature",
        "catalog_hash",
        "work_hash",
        "reference",
        "request_signature",
        "video",
        "wire_ids",
        "window",
        "caller",
        "terms",
    ],
)
async def test_service_rejects_mutated_signatures_commitments_and_scope(service, damage):
    c, p = service, service.p
    grant, body, caller = c.grant, c.grant.body, None
    assignment, admission = c.assignment, c.assignment.admission
    if damage == "signature":
        grant = grant.model_copy(update={"signatures": grant.signatures[:1]})
    elif damage == "catalog_signature":
        assignment = assignment.model_copy(
            update={
                "catalog": assignment.catalog.model_copy(
                    update={"signatures": assignment.catalog.signatures[:1]}
                )
            }
        )
    elif damage == "claim_signature":
        claim = admission.claim.model_copy(
            update={"signature": sign_object(admission.claim.claim, wallet("Alice"))}
        )
        assignment = assignment.model_copy(
            update={"admission": admission.model_copy(update={"claim": claim})}
        )
    elif damage in {"catalog_hash", "work_hash"}:
        field = "catalog_sha256" if damage == "catalog_hash" else "work_sha256"
        assignment = assignment.model_copy(
            update={"admission": admission.model_copy(update={field: "ee" * 32})}
        )
    elif damage == "reference":
        catalog = assignment.catalog.catalog
        changed = catalog.model_copy(
            update={
                "work": (
                    catalog.work[0].model_copy(update={"reference_sha256": "ee" * 32}),
                    *catalog.work[1:],
                )
            }
        )
        assignment = assignment.model_copy(
            update={
                "catalog": SignedServiceWorkCatalog(catalog=changed, signatures=signatures(changed))
            }
        )
    elif damage in {"request_signature", "video", "wire_ids", "window"}:
        req = body.request
        updates = {
            "request_signature": {
                "video": req.video.model_copy(update={"url": req.video.url + "?changed=1"})
            },
            "video": {"video": req.video.model_copy(update={"sha256": "ee" * 32})},
            "wire_ids": {"batch_id": p.requests[0].batch_id},
            "window": {"issued_block_hash": "0x" + "ee" * 32},
        }[damage]
        body = body.model_copy(update={"request": req.model_copy(update=updates)})
    elif damage == "caller":
        caller = next(
            wallet(n)
            for n in ("Charlie", "Dave", "Eve", "Ferdie")
            if identity(wallet(n).hotkey.ss58_address) != identity(body.evaluator_hotkey)
        )
    elif damage == "terms":
        p.miner = p.rebuild(
            directory=str(c.tmp_path / "wrong-terms"), service_terms_sha256="ee" * 32
        )
    body = body.model_copy(update={"assignment": assignment})
    if damage == "request_signature":
        grant = grant.model_copy(update={"body": body})
    elif damage != "signature":
        grant = signed_grant(body)
    assert (await request(p, COHORT_GRANT_PATH, grant, caller=caller)).status_code == 422
    assert (await request(p, TRANSLATE_PATH, body.request)).status_code == 422
    assert p.model.calls == p.fetcher.calls == 0


async def test_service_requires_explicit_config_opt_in(service):
    c, p = service, service.p
    p.miner_cfg = CohortMinerConfig.model_validate(
        {
            **p.miner_cfg.model_dump(by_alias=True, exclude={"service_terms_sha256"}),
            "schema": "umi-cohort-miner-config/1",
            "directory": str(c.tmp_path / "legacy-miner"),
        }
    )
    p.miner = p.rebuild()
    assert (await accept(c)).status_code == 422
    assert (await request(p, TRANSLATE_PATH, c.grant.body.request)).status_code == 422
    assert p.model.calls == p.fetcher.calls == 0


async def test_service_retained_slot_rejects_resigned_request_change(service):
    c, p = service, service.p
    ack = await accept(c)
    assert ack.status_code == 200
    req = c.grant.body.request
    changed = req.model_copy(
        update={
            "video": req.video.model_copy(update={"url": req.video.url + "?changed=1"}),
        }
    )
    grant = signed_grant(c.grant.body.model_copy(update={"request": changed}))
    verify_service_grant(grant, p.c.policy, p.transport_policy)
    assert grant_slot(grant) == grant_slot(c.grant)
    assert (await accept(c, grant)).status_code == 422
    assert (await request(p, TRANSLATE_PATH, changed)).status_code == 422
    assert p.model.calls == p.fetcher.calls == 0
    restart_miner(c)
    assert (await accept(c)).content == ack.content
    original = await request(p, TRANSLATE_PATH, req)
    assert original.status_code == 200
    assert (await request(p, TRANSLATE_PATH, req)).content == original.content
    assert p.model.calls == p.fetcher.calls == 1


async def test_service_closure_refuses_inference_but_recovers_original_ack_and_response(service):
    c, p = service, service.p
    ack = await accept(c)
    assert ack.status_code == 200
    req = c.grant.body.request
    result = await request(p, TRANSLATE_PATH, req)
    assert result.status_code == 200
    original = p.e.r.h.source
    p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
    assert (await request(p, TRANSLATE_PATH, req)).status_code == 422
    restart_miner(c)
    # Restart and even rollback of the live source cannot reopen retained closure.
    p.e.r.h.source = original
    assert (await request(p, TRANSLATE_PATH, req)).status_code == 422
    assert (await accept(c)).content == ack.content
    recovered = await request(p, RESPONSE_RECOVERY_PATH, req)
    assert recovered.status_code == 200
    assert recovered.content == result.content
    assert recovered.headers["x-umi-signature"] == result.headers["x-umi-signature"]
    assert p.fetcher.calls == p.model.calls == 1


async def test_service_ids_separate_catalogs_and_replays_do_not_repeat_inference(service):
    c, p = service, service.p
    other = admitted_service(p, c.tmp_path / "other-catalog", catalog_number=2)
    evaluator = p.validator.hotkey.ss58_address
    second = produce_grant(p, other, c.window)
    assert c.assignment.catalog.catalog.work == other.assignment.catalog.catalog.work
    assert c.assignment.admission.claim.claim.nonce == other.assignment.admission.claim.claim.nonce
    assert service_obligation(c.assignment, evaluator) != service_obligation(
        other.assignment, evaluator
    )
    first_ids, second_ids = (
        service_wire_ids(a, evaluator, 1) for a in (c.assignment, other.assignment)
    )
    assert all(a != b for a, b in zip(first_ids, second_ids, strict=True))
    assert grant_slot(c.grant) != grant_slot(second)
    for grant in (c.grant, second):
        ack = await accept(c, grant)
        assert ack.status_code == 200
        response = await request(p, TRANSLATE_PATH, grant.body.request)
        assert response.status_code == 200
        for path in (TRANSLATE_PATH, RESPONSE_RECOVERY_PATH):
            assert (await accept(c, grant)).content == ack.content
            assert (await request(p, path, grant.body.request)).content == response.content
    assert p.model.calls == 2
    # The two distinct obligations may reuse their content-addressed video.
    assert p.fetcher.calls == 1


def fresh_window(p, old, monkeypatch):
    transport = p.transport_policy
    index = (
        max(p.finality.head, old.deadline_block) - transport.activation_block
    ) // transport.clock.window_stride_blocks + 2
    height = transport.activation_block + index * transport.clock.window_stride_blocks
    now_ms = max(
        time.time_ns() // 1_000_000 + 120_000,
        QUICKNET_GENESIS_MS + (old.response_close_round + 2) * QUICKNET_PERIOD_MS,
    )
    announcement = _block(
        transport,
        0,
        height=height,
        block_byte="51",
        timestamp_ms=now_ms
        - 1000
        * (
            transport.clock.anchor_blocks * transport.clock.target_block_interval_seconds
            + transport.clock.selection_finality_buffer_seconds
        ),
    )
    schedule = _clock(transport).derive(
        index,
        netuid=transport.netuid,
        announcement_block_hash=announcement.block_hash,
        announcement_timestamp_ms=announcement.timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(transport),
    )
    issuance = _block(
        transport,
        0,
        height=schedule.closing_block + 1,
        block_byte="61",
        timestamp_ms=QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS,
    )
    p.finality.blocks.update({announcement.height: announcement, issuance.height: issuance})
    p.finality.head = issuance.height
    monkeypatch.setattr(bt.timelock, "current_round", lambda: schedule.selection_round)
    return EndpointRequestWindow(
        announcement=RetainedRequestBlock.capture(announcement),
        issuance=RetainedRequestBlock.capture(issuance),
    )


async def replacement(c, monkeypatch):
    p, parent = c.p, c.grant
    ack = await accept(c)
    assert ack.status_code == 200
    old = parent.body.request
    p.finality.head = old.deadline_block + 1
    monkeypatch.setattr(bt.timelock, "current_round", lambda: old.response_close_round + 1)
    reply = await request(p, COHORT_RETIRE_PATH, old)
    assert reply.status_code == 200
    retired = SignedEndpointRetirementReceipt.model_validate_json(reply.content)
    verify_retirement_receipt(
        retired,
        request=old,
        grant_sha256=digest(parent),
        miner_hotkey=p.miner.hotkey_ss58,
        evaluator_hotkey=p.validator.hotkey.ss58_address,
    )
    assert retired.receipt.result == "no_response_retained"
    assert retired.receipt.protocol_execution_fenced
    assert not retired.receipt.chain_submission_authorized
    assignment = parent.body.assignment
    decision = CohortEndpointCaseDecision(
        schema="umi-cohort-endpoint-case-decision/1",
        policy_sha256=digest(p.c.policy),
        cohort_sha256=assignment.round.cohort_sha256,
        obligation_sha256=service_obligation(assignment, parent.body.evaluator_hotkey),
        case_id=assignment.catalog.catalog.work[assignment.admission.ordinal - 1].case_id,
        attempt_number=parent.body.attempt_number,
        review_sha256=digest(retired),
        request_sha256=request_digest(old),
        disposition="retry_required",
        response_sha256=None,
    )
    cert = SignedCohortEndpointCaseDecision(decision=decision, signatures=signatures(decision))
    child = produce_grant(
        p,
        c,
        fresh_window(p, old, monkeypatch),
        parent=parent,
        decision=cert,
        retirement=retired,
    )
    verify_service_grant(child, p.c.policy, p.transport_policy)
    verify_service_parent(child, parent)
    return child, ack, reply


async def test_service_replacement_requires_native_retirement_then_new_window(service, monkeypatch):
    c, p = service, service.p
    child, parent_ack, retirement = await replacement(c, monkeypatch)
    old, req = c.grant.body.request, child.body.request
    assert req.issued_block > old.deadline_block
    assert req.batch_id != old.batch_id and req.challenge_id != old.challenge_id
    assert child.body.assignment == c.grant.body.assignment
    ack = await accept(c, child)
    assert ack.status_code == 200
    restart_miner(c)
    assert (await accept(c, child)).content == ack.content
    assert (await accept(c)).content == parent_ack.content
    assert (await request(p, COHORT_RETIRE_PATH, old)).content == retirement.content
    assert (await request(p, TRANSLATE_PATH, old)).status_code == 422
    response = await request(p, TRANSLATE_PATH, req)
    assert response.status_code == 200
    restart_miner(c)
    recovered = await request(p, RESPONSE_RECOVERY_PATH, req)
    assert recovered.status_code == 200 and recovered.content == response.content
    assert recovered.headers["x-umi-signature"] == response.headers["x-umi-signature"]
    assert (await request(p, TRANSLATE_PATH, req)).content == response.content
    assert p.model.calls == p.fetcher.calls == 1
    for grant in (c.grant, child):
        assert canonical_json_bytes(
            p.miner.competition_authority.journal.get("miner_grant", grant_slot(grant))
        ) == canonical_json_bytes(grant)


@pytest.mark.parametrize(
    "damage",
    [
        "parent_slot",
        "parent_hash",
        "decision_request",
        "decision_case",
        "decision_disposition",
        "decision_signature",
        "missing_decision",
        "missing_retirement",
        "retirement_request",
        "retirement_signature",
        "attempt",
        "overlap",
        "missing_parent",
    ],
)
async def test_service_replacement_rejects_parent_and_retry_evidence_mismatch(
    service, monkeypatch, damage
):
    c, p = service, service.p
    child, _, _ = await replacement(c, monkeypatch)
    body = child.body
    if damage in {"parent_slot", "parent_hash"}:
        field = "parent_grant_slot" if damage == "parent_slot" else "parent_grant_sha256"
        body = body.model_copy(update={field: "ee" * 32})
    elif damage in {"missing_decision", "missing_retirement"}:
        field = "prior_decision" if damage == "missing_decision" else "prior_retirement"
        body = body.model_copy(update={field: None})
    elif damage in {
        "decision_request",
        "decision_case",
        "decision_disposition",
        "decision_signature",
    }:
        cert = body.prior_decision
        if damage == "decision_signature":
            cert = cert.model_copy(update={"signatures": cert.signatures[:1]})
        else:
            update = {
                "decision_request": {"request_sha256": "ee" * 32},
                "decision_case": {"case_id": "ee" * 32},
                "decision_disposition": {"disposition": "retain_response"},
            }[damage]
            decision = cert.decision.model_copy(update=update)
            cert = cert.model_copy(
                update={"decision": decision, "signatures": signatures(decision)}
            )
        body = body.model_copy(update={"prior_decision": cert})
    elif damage in {"retirement_request", "retirement_signature"}:
        retired = body.prior_retirement
        if damage == "retirement_signature":
            retired = retired.model_copy(
                update={"signature": sign_object(retired.receipt, wallet("Alice"))}
            )
        else:
            receipt = retired.receipt.model_copy(update={"request_digest": "ee" * 32})
            retired = retired.model_copy(
                update={"receipt": receipt, "signature": sign_object(receipt, p.miner.wallet)}
            )
        body = body.model_copy(update={"prior_retirement": retired})
    elif damage == "attempt":
        body = body.model_copy(update={"attempt_number": 3})
    elif damage == "overlap":
        overlapping = c.window.request_with_ids(
            c.assignment.catalog.catalog.work[0],
            c.grant.body.request.video,
            service_wire_ids(c.assignment, body.evaluator_hotkey, 2),
            p.transport_policy,
        )
        body = body.model_copy(update={"request": overlapping, "window": c.window})
    else:
        p.miner = p.rebuild(directory=str(c.tmp_path / "missing-parent"))
    changed = child.model_copy(update={"body": body, "signatures": signatures(body)})
    if damage in {"parent_slot", "parent_hash", "overlap"}:
        with pytest.raises(ValueError):
            verify_service_parent(changed, c.grant)
    assert (await accept(c, changed)).status_code == 422
    assert (await request(p, TRANSLATE_PATH, body.request)).status_code == 422
    assert p.model.calls == p.fetcher.calls == 0


async def terminal_response(c):
    from umi.competition_cohort_service_terminal import ServiceWorkTerminals
    from umi.competition_execution import execution_boundary
    from umi.endpoint_response_recovery import RecoveredEndpointResponse

    p, req = c.p, c.grant.body.request
    assert (await accept(c)).status_code == 200
    reply = await request(p, TRANSLATE_PATH, req)
    assert reply.status_code == 200, reply.text
    retained = RecoveredEndpointResponse(
        schema="umi-recovered-endpoint-response/1",
        envelope_hex=reply.content.hex(),
        signature=reply.headers["x-umi-signature"],
        retrieval_started_at_unix_ns="1",
        retrieved_at_unix_ns="2",
    )
    retirement_reply = await request(p, COHORT_RETIRE_PATH, req)
    assert retirement_reply.status_code == 200
    retirement = SignedEndpointRetirementReceipt.model_validate_json(retirement_reply.content)
    owner = ServiceWorkTerminals(ServiceWorkRequests(c.queue, p.transport_policy))
    return (
        owner,
        retained,
        retirement,
        p.e.r.h.source,
        execution_boundary(capture(req.deadline_block + 1)),
    )


@pytest.mark.parametrize("replace_attempt", [False, True])
async def test_service_terminal_replays_native_response_and_all_parents(
    service,
    monkeypatch,
    replace_attempt,
):
    from umi.competition_cohort_service_terminal import ServiceWorkTerminals, read_service_terminal

    c, p = service, service.p
    if replace_attempt:
        c.grant, _, _ = await replacement(c, monkeypatch)
    owner, response, retirement, source, observation = await terminal_response(c)
    slot = service_grant_slot(c.grant.body)
    intent = owner.prepare(slot, response, retirement, source, observation)
    terminal = owner.retain(intent, sign_object(intent, p.validator))
    assert (
        read_service_terminal(
            terminal,
            owner.objects,
            p.c.policy,
            p.transport_policy,
            request_interval=(390, observation.block),
        )
        == c.grant
    )
    c.queue = ServiceWorkQueue(c.cfg, p.c.policy)
    owner = ServiceWorkTerminals(ServiceWorkRequests(c.queue, p.transport_policy))
    assert owner.prepare(slot) == intent
    # A retained certificate recovers even when the signer is unavailable.
    assert owner.retain(intent, None) == terminal
    assert p.model.calls == 1
    if replace_attempt:
        parent = c.grant.body.parent_grant_sha256
        with c.queue.journal.transaction() as db:
            db.execute(
                "DELETE FROM records WHERE kind='endpoint_replay_object' AND id=?", (parent,)
            )
        with pytest.raises(FileNotFoundError):
            read_service_terminal(terminal, owner.objects, p.c.policy, p.transport_policy)


@pytest.mark.parametrize("stage", ["service_terminal_intent", "service_terminal"])
@pytest.mark.parametrize("after_commit", [False, True])
async def test_service_terminal_interruption_replays_exact_committed_intent(
    service,
    monkeypatch,
    stage,
    after_commit,
):
    from umi.competition_cohort_service_terminal import ServiceWorkTerminals

    c, p = service, service.p
    owner, *args = await terminal_response(c)
    slot = service_grant_slot(c.grant.body)
    intent = None if stage.endswith("intent") else owner.prepare(slot, *args)
    original = c.queue.journal.put

    def interrupted(kind, key, value):
        if kind == stage:
            if after_commit:
                original(kind, key, value)
            raise OSError("fixture terminal acknowledgement lost")
        return original(kind, key, value)

    with monkeypatch.context() as patch:
        patch.setattr(c.queue.journal, "put", interrupted)
        with pytest.raises(OSError):
            if intent is None:
                owner.prepare(slot, *args)
            else:
                owner.retain(intent, sign_object(intent, p.validator))
    owner = ServiceWorkTerminals(
        ServiceWorkRequests(ServiceWorkQueue(c.cfg, p.c.policy), p.transport_policy)
    )
    intent = owner.prepare(slot, *args)
    first = owner.retain(intent, sign_object(intent, p.validator))
    assert owner.prepare(slot) == intent and owner.retain(intent, None) == first
    assert p.model.calls == 1


@pytest.mark.parametrize("damage", ["work", "signer", "retirement", "response", "late", "missing"])
async def test_service_terminal_rejects_substituted_or_incomplete_evidence(service, damage):
    from umi.competition_cohort_service_terminal import SignedServiceTerminal, read_service_terminal

    c, p = service, service.p
    owner, response, retirement, source, observation = await terminal_response(c)
    intent = owner.prepare(
        service_grant_slot(c.grant.body), response, retirement, source, observation
    )
    if damage == "work":
        intent = intent.model_copy(update={"work_sha256": "ff" * 32})
    elif damage == "retirement":
        bad = retirement.receipt.model_copy(update={"response_sha256": "ff" * 32})
        intent = intent.model_copy(
            update={
                "retirement_sha256": owner.objects.put(
                    retirement.model_copy(
                        update={"receipt": bad, "signature": sign_object(bad, p.miner.wallet)}
                    )
                )
            }
        )
    elif damage == "response":
        bad = response.model_copy(update={"signature": "0x" + "00" * 64})
        intent = intent.model_copy(update={"response_sha256": owner.objects.put(bad)})
    elif damage == "missing":
        intent = intent.model_copy(update={"response_sha256": "ff" * 32})
    signed = SignedServiceTerminal(
        terminal=intent,
        signature=sign_object(intent, wallet("Alice") if damage == "signer" else p.validator),
    )
    with pytest.raises((ValueError, FileNotFoundError)):
        read_service_terminal(
            signed,
            owner.objects,
            p.c.policy,
            p.transport_policy,
            request_interval=(390, observation.block - (1 if damage == "late" else 0)),
        )


async def test_service_terminal_absence_never_becomes_success_or_zero(service):
    from umi.competition_cohort_service_terminal import ServiceWorkTerminals

    c = service
    owner = ServiceWorkTerminals(ServiceWorkRequests(c.queue, c.p.transport_policy))
    with pytest.raises(FileNotFoundError, match="pending"):
        owner.prepare(service_grant_slot(c.grant.body))
    assert (
        c.queue.journal.get("service_terminal_intent", c.assignment.admission.work_sha256) is None
    )
    assert c.p.model.calls == 0


@pytest.fixture
async def service_closed(service, receipt_scenario, runtime, monkeypatch, tmp_path):
    from umi.competition_cohort_service_closure import (
        CohortServiceRequestClosure,
        ServiceCatalogClosure,
    )

    from .cohort_request_closure_fixture import closure_fixture
    from .test_competition_cohort_request_closure import put

    c, p = service, service.p
    owner, response, retirement, source, observation = await terminal_response(c)
    slot = service_grant_slot(c.grant.body)
    intent = owner.prepare(slot, response, retirement, source, observation)
    signed = owner.retain(intent, sign_object(intent, p.validator))
    seal = c.queue.seal(
        source, capture(observation.block), expected_tip_sha256=history_tip(source.history)
    )
    benchmark_endpoint = endpoint_scenario(
        receipt_scenario, tmp_path / "benchmark-input", runtime, monkeypatch
    )
    b = await closure_fixture(benchmark_endpoint, tmp_path / "benchmark", prepared=p.e.r.h.batch)
    b["closure"] = b["closure"].model_copy(update={"observation": observation})
    with c.queue.journal.transaction() as db:
        keys = tuple(
            r[0] for r in db.execute("SELECT id FROM records WHERE kind='endpoint_replay_object'")
        )
    b["objects"].update({k: owner.objects(k) for k in keys})
    benchmark = b["closure"]
    b["closure"] = CohortServiceRequestClosure(
        schema="umi-cohort-request-closure/2",
        benchmark_closure_sha256=put(b, benchmark),
        recovery_tip_sha256=benchmark.recovery_tip_sha256,
        observation=benchmark.observation,
        catalogs=(
            ServiceCatalogClosure(
                catalog_sha256=digest(c.assignment.catalog.catalog),
                seal_sha256=put(b, seal),
                terminals=(digest(signed),),
            ),
        ),
    )
    b.update(
        service_case=c, transport=p.transport_policy, service_seal=seal, service_terminal=signed
    )
    return b


def review_service_closed(b, *, certified=False, **overrides):
    from umi.competition_cohort_service_closure import (
        review_service_request_closure,
        verify_certified_service_request_closure,
    )

    from .test_competition_cohort_consumers import tip

    args = dict(
        closure=b["closure"],
        roster=b["roster"],
        objects=b["objects"].__getitem__,
        policy=b["policy"],
        history=b["history"],
        transport=b["transport"],
        expected_catalogs=(b["service_case"].assignment.catalog,),
        expected_seals=(b["service_seal"],),
        decision_source=b["decisions"].__getitem__,
        intake_records=iter(b["records"]),
        expected_tip_sha256=tip(b["history"]),
        current_block=b["closure"].observation.block,
    )
    args.update(overrides)
    fn = verify_certified_service_request_closure if certified else review_service_request_closure
    return fn(**args)


def test_complete_service_closure_binds_native_phase_and_survives_long_outage(service_closed):
    from .test_competition_cohort_consumers import tip
    from .test_competition_cohort_request_closure import certified_history

    b = service_closed
    assert review_service_closed(b) == b["closure"]
    h = certified_history(b)
    for block in (b["closure"].observation.block + 90, 2**53 - 1):
        assert (
            review_service_closed(
                b,
                certified=True,
                history=h,
                expected_tip_sha256=tip(h),
                current_block=block,
            )
            == b["closure"]
        )
    assert not b["closure"].chain_submission_authorized
    assert all(b'"references"' not in raw for raw in b["objects"].values())


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "extra",
        "work",
        "catalog",
        "terminal",
        "seal",
        "benchmark",
        "observation",
        "truncated",
    ],
)
def test_service_closure_requires_exact_catalog_work_and_benchmark_coverage(service_closed, damage):
    from .test_competition_cohort_request_closure import put

    b = service_closed
    closure, item = b["closure"], b["closure"].catalogs[0]
    if damage in {"missing", "extra", "terminal"}:
        terminals = (
            ()
            if damage == "missing"
            else ((*item.terminals, *item.terminals) if damage == "extra" else ("ff" * 32,))
        )
        item = item.model_copy(update={"terminals": terminals})
    elif damage in {"seal", "work"}:
        seal = b["service_seal"]
        if damage == "work":
            accepted = (seal.accepted[0].model_copy(update={"work_sha256": "ff" * 32}),)
            seal = seal.model_copy(update={"accepted": accepted})
        else:
            seal = seal.model_copy(update={"source_sha256": "ff" * 32})
        item = item.model_copy(update={"seal_sha256": put(b, seal)})
    elif damage == "truncated":
        shortened = b["service_seal"].model_copy(update={"accepted": ()})
        item = item.model_copy(update={"seal_sha256": put(b, shortened), "terminals": ()})
    elif damage == "catalog":
        item = item.model_copy(update={"catalog_sha256": "ff" * 32})
    elif damage == "benchmark":
        closure = closure.model_copy(update={"benchmark_closure_sha256": "ff" * 32})
    else:
        closure = closure.model_copy(
            update={"observation": closure.observation.model_copy(update={"block": 1681})}
        )
    closure = closure.model_copy(update={"catalogs": (item,)})
    with pytest.raises((ValueError, KeyError)):
        review_service_closed(b, closure=closure)


def test_service_manifest_needs_its_own_native_phase_certificate(service_closed):
    from .test_competition_cohort_consumers import tip
    from .test_competition_cohort_request_closure import certified_history

    b = service_closed
    h = certified_history(b, result=b["closure"].benchmark_closure_sha256)
    with pytest.raises(ValueError, match="exact closure"):
        review_service_closed(
            b,
            certified=True,
            history=h,
            expected_tip_sha256=tip(h),
            current_block=b["closure"].observation.block + 1000,
        )


def test_service_closure_missing_response_remains_pending_until_archive_recovers(service_closed):
    b = service_closed
    key = b["service_terminal"].terminal.response_sha256
    raw = b["objects"].pop(key)
    with pytest.raises(KeyError):
        review_service_closed(b, current_block=2**53 - 1)
    b["objects"][key] = raw
    assert review_service_closed(b, current_block=2**53 - 1) == b["closure"]


@pytest.fixture
def service_quality_inputs(service_closed):
    from umi.competition_cohort_service_quality import CatalogReferences, ServiceReferenceReveal

    from .test_competition_cohort_request_closure import certified_history, put

    b, c = service_closed, service_closed["service_case"]
    assert c.terms is not None
    reveal = ServiceReferenceReveal(
        schema="umi-cohort-service-reference-reveal/1",
        policy_sha256=digest(b["policy"]),
        request_closure_sha256=digest(b["closure"]),
        benchmark_suite_sha256=b["roster"].round.suite_sha256,
        catalogs=(
            CatalogReferences(
                catalog_sha256=digest(c.assignment.catalog.catalog),
                references=tuple(put(b, r) for r in c.references),
            ),
        ),
    )
    b["reveal"] = reveal
    b["history"] = certified_history(b, reveal_result=digest(reveal))
    return b


def service_quality(b, *, allocation=False, review=False, **changes):
    from umi.competition_cohort_service_quality import replay_closed_service_quality
    from umi.competition_endpoint_execution import RetainedRevealPulse

    from .test_competition_cohort_consumers import tip
    from .test_drand import pulse_record

    c = b["service_case"]
    args = dict(
        closure=b["closure"],
        roster=b["roster"],
        objects=b["objects"].__getitem__,
        policy=b["policy"],
        history=b["history"],
        transport=b["transport"],
        terms=c.terms,
        reveal=b["reveal"],
        expected_catalogs=(c.assignment.catalog,),
        expected_seals=(b["service_seal"],),
        expected_terms_sha256=digest(c.terms),
        decision_source=b["decisions"].__getitem__,
        intake_records=iter(b["records"]),
        pulses=lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(b["history"]),
        current_block=2**53 - 1,
    )
    args.update(changes)
    if review:
        from umi.competition_cohort_service_certification import ServiceAllocationReview

        return ServiceAllocationReview(**args)
    if allocation:
        from umi.competition_cohort_service_allocation import replay_service_allocation

        return replay_service_allocation(**args)
    return replay_closed_service_quality(**args)


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
def test_service_quality_replays_encrypted_work_after_unbounded_delay(service_quality_inputs):
    b = service_quality_inputs
    observed = service_quality(b)
    assert len(observed.work) == 1
    work = observed.work[0]
    assert work.work_sha256 == b["service_case"].assignment.admission.work_sha256
    assert work.quality.numerator == work.quality.denominator == "1"
    assert work.credit == work.quality and work.units == 1
    assert work.elapsed_ms is None
    assert work.recipient_hotkey == b["service_case"].assignment.admission.claim.claim.hotkey
    assert not observed.chain_submission_authorized
    assert service_quality(b) == observed
    assert b["service_case"].p.model.calls == 1


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
@pytest.mark.parametrize(
    "damage", ["terms", "term_selection", "reveal", "reference", "terminal", "pulse"]
)
def test_service_quality_rejects_changed_or_missing_evidence(service_quality_inputs, damage):
    b, changed = service_quality_inputs, {}
    if damage == "terms":
        changed["terms"] = b["service_case"].terms.model_copy(update={"service_pool_bps": 5000})
    elif damage == "term_selection":
        changed["expected_terms_sha256"] = "fe" * 32
    elif damage == "reveal":
        changed["reveal"] = b["reveal"].model_copy(update={"benchmark_suite_sha256": "fe" * 32})
    elif damage == "reference":
        b["objects"].pop(b["reveal"].catalogs[0].references[0])
    elif damage == "terminal":
        b["objects"].pop(b["closure"].catalogs[0].terminals[0])
    else:

        def missing(_):
            raise OSError("fixture pulse unavailable")

        changed["pulses"] = missing
    with pytest.raises((ValueError, KeyError, OSError)):
        service_quality(b, **changed)


@pytest.mark.parametrize(
    "service_catalog_inputs", ["cer_partial", "wer_partial", "miner_failure"], indirect=True
)
def test_service_quality_uses_exact_metric_and_explicit_miner_failure(
    service_quality_inputs, service_catalog_inputs
):
    b = service_quality_inputs
    result = service_quality(b).work[0]
    expected = {"cer_partial": ("9", "10"), "wer_partial": ("1", "2"), "miner_failure": ("0", "1")}
    assert (result.quality.numerator, result.quality.denominator) == expected[
        service_catalog_inputs
    ]
    assert result.credit == result.quality
    if service_catalog_inputs == "miner_failure":
        assert result.status == "miner_failure"
        assert result.reason_code == "signed_miner_error"
    else:
        assert result.status == "ok"
        assert result.reason_code is None


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
@pytest.mark.parametrize("error", [MemoryError, TimeoutError])
def test_service_quality_local_failure_recovers_without_zero_or_new_inference(
    service_quality_inputs, monkeypatch, error
):
    import bittensor_core

    b = service_quality_inputs
    original = bittensor_core.decrypt_with_signature

    def unavailable(*args):
        raise error("fixture local resource failure")

    monkeypatch.setattr(bittensor_core, "decrypt_with_signature", unavailable)
    with pytest.raises(error):
        service_quality(b)
    monkeypatch.setattr(bittensor_core, "decrypt_with_signature", original)
    recovered = service_quality(b).work[0]
    assert recovered.quality.numerator == recovered.quality.denominator == "1"
    assert b["service_case"].p.model.calls == 1


async def test_service_terminal_stops_fresh_attempts_and_rejects_changed_selected_grant(
    service,
    monkeypatch,
):
    c, p = service, service.p
    owner, response, retirement, source, observation = await terminal_response(c)
    slot = service_grant_slot(c.grant.body)
    original = owner.journal.get
    window = fresh_window(p, c.grant.body.request, monkeypatch)
    case = c.assignment.catalog.catalog.work[0]
    alternate = signed_grant(
        c.grant.body.model_copy(
            update={
                "window": window,
                "request": window.request_with_ids(
                    case,
                    p.service_video,
                    service_wire_ids(c.assignment, p.validator.hotkey.ss58_address, 1),
                    p.transport_policy,
                ),
            }
        )
    )
    verify_service_grant(alternate, p.c.policy, p.transport_policy)

    def conflicting(kind, key, **kwargs):
        if kind == "service_grant" and key == slot:
            return alternate.model_dump(mode="json", by_alias=True)
        return original(kind, key, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(owner.journal, "get", conflicting)
        with pytest.raises(ValueError, match="selected request"):
            owner.prepare(slot, response, retirement, source, observation)
    intent = owner.prepare(slot, response, retirement, source, observation)
    assert owner.retain(intent, sign_object(intent, p.validator)).terminal == intent
    with pytest.raises(ValueError, match="terminal response selected"):
        owner.requests.prepare(
            c.claim, p.validator.hotkey.ss58_address, None, None, None, None, parent=c.grant
        )


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
def test_native_service_allocation_requires_the_complete_replayed_work(service_quality_inputs):
    b = service_quality_inputs
    result = service_quality(b, allocation=True)
    assert result.service_budget == 45874
    assert result.model_budget == 19661
    assert result.stratum_budgets == {"continuous": 35288, "fingerspelling": 10586}
    assert len(result.recipients) == 1
    assert result.recipients[0].raw_weight == 10586
    assert result.burn_weight == 35288
    assert not result.chain_submission_authorized
    key = b["service_terminal"].terminal.response_sha256
    raw = b["objects"].pop(key)
    with pytest.raises(KeyError):
        service_quality(b, allocation=True)
    b["objects"][key] = raw
    assert service_quality(b, allocation=True) == result
    assert b["service_case"].p.model.calls == 1


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
async def test_benchmark_quality_binds_combined_service_closure(service_quality_inputs, tmp_path):
    from umi.competition_cohort_quality import ClosedQualityReview
    from umi.competition_cohort_quality_signing import (
        PendingQualityCertificates,
        build_quality_manifest,
    )
    from umi.competition_cohort_request_closure import CohortRequestClosure
    from umi.competition_endpoint_execution import RetainedRevealPulse

    from .test_competition_cohort_consumers import tip
    from .test_drand import pulse_record

    b = service_quality_inputs
    args = dict(
        closure=b["closure"],
        roster=b["roster"],
        objects=b["objects"].__getitem__,
        suite=b["suite"],
        policy=b["policy"],
        history=b["history"],
        decision_source=b["decisions"].__getitem__,
        pulses=lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(b["history"]),
        current_block=2**53 - 1,
        transport=b["transport"],
        expected_catalogs=(b["service_case"].assignment.catalog,),
        expected_seals=(b["service_seal"],),
    )
    review = ClosedQualityReview(**args, intake_records=iter(b["records"]))
    outcome = review.outcome(review.closure.participants[0].submission_sha256)
    assert outcome.request_closure_sha256 == digest(b["closure"])
    assert outcome.request_closure_sha256 != digest(review.closure)
    assert outcome.candidate is not None
    assert not outcome.service_credit_authorized
    with pytest.raises(PendingQualityCertificates):
        build_quality_manifest(review, lambda _: None)
    from .test_competition_cohort_quality import certificates_for

    certificates = await certificates_for(b, review, tmp_path)
    manifest = build_quality_manifest(review, certificates.get)
    assert manifest.request_closure_sha256 == digest(b["closure"])
    subset = CohortRequestClosure.model_validate_json(
        b["objects"][b["closure"].benchmark_closure_sha256]
    )
    with pytest.raises(ValueError, match="exact closure"):
        ClosedQualityReview(**{**args, "closure": subset}, intake_records=iter(b["records"]))
    missing = b["objects"].pop(b["service_terminal"].terminal.response_sha256)
    with pytest.raises(KeyError):
        ClosedQualityReview(**args, intake_records=iter(b["records"]))
    b["objects"][b["service_terminal"].terminal.response_sha256] = missing


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
async def test_service_allocation_votes_recover_partial_quorum_and_lost_reply(
    service_quality_inputs, tmp_path, monkeypatch
):
    from umi.competition_cohort_service_certification import (
        collect_service_allocation,
        retained_service_allocation_vote,
        sign_service_allocation,
        verify_service_allocation_certificate,
    )
    from umi.competition_round_journal import RoundJournal

    b = service_quality_inputs
    review = service_quality(b, review=True)
    calls = []

    def journal(name):
        return RoundJournal(tmp_path / name, {"scope": "service-allocation-test", "owner": name})

    async def sign(body):
        calls.append("Charlie")
        return sign_object(body, wallet("Charlie"))

    charlie = wallet("Charlie").hotkey.ss58_address
    owner = journal("charlie-credit")
    original = owner.put

    def lost(kind, key, value):
        original(kind, key, value)
        if kind == "service_allocation_vote":
            raise OSError("fixture lost reply after durable commit")

    with monkeypatch.context() as patch:
        patch.setattr(owner, "put", lost)
        with pytest.raises(OSError, match="lost reply"):
            await sign_service_allocation(owner, review, charlie, sign)
    retained = retained_service_allocation_vote(journal("charlie-credit"), review.slot, charlie)
    assert retained is not None and len(calls) == 1
    assert (
        await sign_service_allocation(journal("charlie-credit"), review, charlie, sign) == retained
    )
    assert len(calls) == 1
    assert collect_service_allocation(journal("credit-collector"), review, [retained]) is None

    async def dave_sign(body):
        return sign_object(body, wallet("Dave"))

    dave = await sign_service_allocation(
        journal("dave-credit"), review, wallet("Dave").hotkey.ss58_address, dave_sign
    )
    certified = collect_service_allocation(journal("credit-collector"), review, [dave])
    assert certified is not None
    assert collect_service_allocation(journal("credit-collector"), review, []) == certified
    assert (
        collect_service_allocation(journal("credit-collector"), review, [dave, retained])
        == certified
    )
    assert (
        verify_service_allocation_certificate(certified, service_quality(b, review=True))
        == review.statement.allocation
    )
    changed = certified.model_copy(
        update={"statement": certified.statement.model_copy(update={"round_sha256": "ff" * 32})}
    )
    with pytest.raises(ValueError, match="replayed allocation"):
        verify_service_allocation_certificate(changed, review)
    assert b["service_case"].p.model.calls == 1


@pytest.mark.parametrize("service_catalog_inputs", ["miner_failure"], indirect=True)
async def test_service_allocation_signing_failure_capacity_and_self_review(
    service_quality_inputs, tmp_path
):
    from umi.competition_cohort_service_certification import sign_service_allocation
    from umi.competition_round_journal import RoundJournal

    b = service_quality_inputs
    review = service_quality(b, review=True)
    calls = []

    async def unavailable(body):
        calls.append(1)
        raise OSError("fixture key unavailable")

    charlie = wallet("Charlie").hotkey.ss58_address
    owner = RoundJournal(tmp_path / "retry-credit", {"scope": "retry-credit"})
    with pytest.raises(OSError, match="key unavailable"):
        await sign_service_allocation(owner, review, charlie, unavailable)

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    recovered = await sign_service_allocation(owner, review, charlie, sign)
    assert recovered.statement.allocation.recipients == ()
    saved = review.statement
    review.statement = saved.model_copy(
        update={"allocation": saved.allocation.model_copy(update={"model_budget": 1})}
    )
    with pytest.raises(ValueError):
        await sign_service_allocation(owner, review, charlie, sign)
    review.statement = saved
    full = RoundJournal(tmp_path / "full-credit", {"scope": "full-credit"}, maximum_bytes=1024)
    with pytest.raises(ValueError, match="capacity"):
        await sign_service_allocation(full, review, charlie, unavailable)
    assert len(calls) == 1
    miner = b["service_case"].p.miner.wallet.hotkey.ss58_address
    assert identity(miner) in review.recipients  # Even a scored zero must not certify itself.
    with pytest.raises(ValueError, match="ineligible"):
        await sign_service_allocation(owner, review, miner, unavailable)
    assert len(calls) == 1


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
async def test_native_reward_allocation_replays_lost_commit_without_new_head(
    service_quality_inputs, tmp_path, monkeypatch
):
    from umi.competition_artifacts import preserve_bundle
    from umi.competition_cohort_quality import ClosedQualityReview
    from umi.competition_cohort_quality_signing import build_quality_manifest
    from umi.competition_cohort_reward_allocation import retain_reward_allocation
    from umi.competition_cohort_service_certification import (
        collect_service_allocation,
        sign_service_allocation,
    )
    from umi.competition_endpoint_execution import RetainedRevealPulse
    from umi.competition_round_journal import RoundJournal
    from umi.competition_store import CompetitionStore

    from .test_competition_cohort_consumers import tip
    from .test_competition_cohort_quality import certificates_for
    from .test_drand import pulse_record
    from .test_open_competition import bundle_at

    b = service_quality_inputs
    sr = service_quality(b, review=True)
    br = ClosedQualityReview(
        closure=b["closure"],
        roster=b["roster"],
        objects=b["objects"].__getitem__,
        suite=b["suite"],
        policy=b["policy"],
        history=b["history"],
        decision_source=b["decisions"].__getitem__,
        intake_records=iter(b["records"]),
        pulses=lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(b["history"]),
        current_block=2**53 - 1,
        transport=b["transport"],
        expected_catalogs=(b["service_case"].assignment.catalog,),
        expected_seals=(b["service_seal"],),
    )
    certificates = await certificates_for(b, br, tmp_path)
    benchmark = build_quality_manifest(br, certificates.get)

    def journal(name):
        return RoundJournal(
            tmp_path / ("reward-" + name), {"scope": "allocation-integration", "owner": name}
        )

    votes = []
    for name in ("Charlie", "Dave"):

        async def sign(body, name=name):
            return sign_object(body, wallet(name))

        votes.append(
            await sign_service_allocation(journal(name), sr, wallet(name).hotkey.ss58_address, sign)
        )
    service = collect_service_allocation(journal("collector"), sr, votes)
    assert service is not None
    store = CompetitionStore(tmp_path / "promotion-state", b["policy"])
    owner = journal("combined-allocation")

    def retain(store=store, owner=owner, benchmark=benchmark):
        return retain_reward_allocation(
            owner, store, service, sr, benchmark, br, maximum_promotion_bytes=1_000_000
        )

    with pytest.raises(ValueError, match="missing"):
        retain()
    assert owner.get("cohort_reward_allocation", sr.slot) is None
    bundle = bundle_at(tmp_path / "model")
    preserve_bundle(bundle, tmp_path / "model", tmp_path / "archive", b["policy"])
    store.initialize_baseline(bundle, tmp_path / "archive")
    original = owner.put

    def lost(kind, key, value):
        original(kind, key, value)
        if kind == "cohort_reward_allocation":
            raise OSError("lost allocation reply")

    with monkeypatch.context() as patch:
        patch.setattr(owner, "put", lost)
        with pytest.raises(OSError, match="lost allocation reply"):
            retain()
    saved = owner.get("cohort_reward_allocation", sr.slot)
    assert saved is not None
    reopened = CompetitionStore(store.directory, b["policy"])

    def unavailable(*args, **kwargs):
        raise AssertionError("recovery tried selecting a new promotion head")

    with monkeypatch.context() as patch:
        patch.setattr(reopened, "reviewed_promotion_head", unavailable)
        result = retain(store=reopened, owner=journal("combined-allocation"))
    assert canonical_json_bytes(result) == canonical_json_bytes(saved)
    assert (
        result.burn_weight
        == sr.statement.allocation.burn_weight + sr.statement.allocation.model_budget
    )
    assert result.recipients == sr.statement.allocation.recipients
    assert not result.chain_submission_authorized
    with pytest.raises(ValueError):
        retain(benchmark=benchmark.model_copy(update={"request_closure_sha256": "ff" * 32}))
    assert b["service_case"].p.model.calls == 1

    # Reuse native phase certification; late consumption does not need renewal.
    from umi.competition_cohort_reward_certification import (
        reward_certification_progress,
        verify_certified_reward_allocation,
    )

    from .test_competition_cohort_consumers import transition
    from .test_competition_cohort_roster import close

    def verify(h, *, value=result, block=2**53 - 1):
        return verify_certified_reward_allocation(
            value,
            reopened,
            service,
            sr,
            benchmark,
            br,
            h,
            b["decisions"].__getitem__,
            expected_tip_sha256=tip(h),
            current_block=block,
            maximum_promotion_bytes=1_000_000,
        )

    with pytest.raises(ValueError, match="no certified closure"):
        verify(b["history"])
    start = b["history"].transitions[-1].transition.observed_at_block + 100
    h = close(b["history"], b["policy"], b["decisions"], start, digest(benchmark))
    h = close(h, b["policy"], b["decisions"], start + 10, digest(service))
    progress = reward_certification_progress(
        journal("combined-allocation"),
        reopened,
        service,
        sr,
        benchmark,
        br,
        h,
        b["decisions"].__getitem__,
        expected_tip_sha256=tip(h),
        current_block=start + 20,
        maximum_promotion_bytes=1_000_000,
    )
    certified = close(h, b["policy"], b["decisions"], start + 20, digest(result))
    actual = b["decisions"][certified.transitions[-1].transition.evidence_sha256].progress.progress
    assert actual == progress
    assert verify(certified) == result
    assert verify(certified, block=start + 20) == result
    wrong = close(h, b["policy"], b["decisions"], start + 20, "cc" * 32)
    with pytest.raises(ValueError, match="exact replayed reward allocation"):
        verify(wrong)
    with pytest.raises(ValueError, match="revoked"):
        verify(transition(certified, b["policy"], "revoke", start + 30))
    changed = result.model_copy(
        update={
            "promotion_head": result.promotion_head.model_copy(
                update={"contributor_hotkey": wallet("Alice").hotkey.ss58_address}
            )
        }
    )
    with pytest.raises(ValueError, match="independently replayed evidence"):
        verify(certified, value=changed)
    with pytest.raises(ValueError, match="current cohort phase"):
        reward_certification_progress(
            journal("combined-allocation"),
            reopened,
            service,
            sr,
            benchmark,
            br,
            certified,
            b["decisions"].__getitem__,
            expected_tip_sha256=tip(certified),
            current_block=start + 21,
            maximum_promotion_bytes=1_000_000,
        )
    assert b["service_case"].p.model.calls == 1

    # A validator reconstructs the native reviews from a copied private package,
    # long after the original target, without the evaluator's object callbacks.
    from umi.competition_cohort_reward_package import (
        RewardPackageObject,
        RewardPulseRef,
        RewardReplayInputs,
        load_reward_package,
        prepare_reward_package,
        publish_reward_package,
        replay_reward_package,
    )

    c = b["service_case"]
    inputs = RewardReplayInputs(
        closure=b["closure"],
        roster=b["roster"],
        suite=b["suite"],
        transport=b["transport"],
        terms=c.terms,
        reveal=b["reveal"],
        catalogs=(c.assignment.catalog,),
        seals=(b["service_seal"],),
        history=certified,
    )
    selection = dict(
        expected_tip_sha256=tip(certified),
        current_block=2**53 - 1,
        expected_terms_sha256=digest(c.terms),
        expected_catalog_sha256s=(digest(c.assignment.catalog.catalog),),
        maximum_promotion_bytes=1_000_000,
    )
    package = prepare_reward_package(
        inputs,
        result,
        service,
        benchmark,
        b["policy"],
        reopened,
        b["objects"].__getitem__,
        b["decisions"].__getitem__,
        iter(b["records"]),
        lambda _: RetainedRevealPulse(**pulse_record()),
        **selection,
    )
    selection.update(
        expected_package_sha256=digest(package), expected_cohort_sha256=digest(certified.plan)
    )
    path = tmp_path / "private-replica" / "rewards.json"
    publish_reward_package(path, package)
    original_bytes = path.read_bytes()
    publish_reward_package(path, package)  # Lost acknowledgement, same immutable bytes.
    assert path.read_bytes() == original_bytes
    assert load_reward_package(path, b["policy"], reopened, certified, **selection) == result
    assert not package.chain_submission_authorized

    # A portable package cannot replace independently retained model provenance.
    missing_promotion = CompetitionStore(tmp_path / "missing-promotion", b["policy"])
    with pytest.raises(ValueError, match="missing"):
        load_reward_package(path, b["policy"], missing_promotion, certified, **selection)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private regular file"):
        load_reward_package(path, b["policy"], reopened, certified, **selection)
    path.chmod(0o600)

    for field, value in (
        ("expected_cohort_sha256", "aa" * 32),
        ("expected_terms_sha256", "bb" * 32),
        ("expected_catalog_sha256s", ("cc" * 32,)),
        ("expected_package_sha256", "dd" * 32),
    ):
        with pytest.raises(ValueError):
            load_reward_package(
                path, b["policy"], reopened, certified, **{**selection, field: value}
            )

    with pytest.raises(ValueError, match="byte bound"):
        load_reward_package(path, b["policy"], reopened, certified, maximum_bytes=1024, **selection)
    for limit in (True, 0, 2**31):
        with pytest.raises(ValueError, match="byte bound"):
            replay_reward_package(
                package, b["policy"], reopened, certified, maximum_bytes=limit, **selection
            )

    # Original decision inputs must travel with the archive; the callback only
    # supplies transitions made after this package was prepared.
    original_decision = certified.transitions[0].transition.evidence_sha256
    changed = package.model_copy(
        update={"objects": tuple(o for o in package.objects if o.sha256 != original_decision)}
    )
    with pytest.raises(ValueError, match="lacks original cohort decisions"):
        replay_reward_package(
            changed,
            b["policy"],
            reopened,
            certified,
            **{**selection, "expected_package_sha256": digest(changed)},
            current_decision_source=b["decisions"].__getitem__,
        )
    unrelated = RewardPackageObject(sha256=digest({"unrelated": 1}), value={"unrelated": 1})
    changed = package.model_copy(
        update={"objects": tuple(sorted((*package.objects, unrelated), key=lambda o: o.sha256))}
    )
    with pytest.raises(ValueError, match="unreferenced evidence"):
        replay_reward_package(
            changed,
            b["policy"],
            reopened,
            certified,
            **{**selection, "expected_package_sha256": digest(changed)},
        )
    unused_round = package.pulses[-1].round + 1
    changed = package.model_copy(
        update={
            "pulses": (
                *package.pulses,
                RewardPulseRef(round=unused_round, pulse_sha256=package.pulses[-1].pulse_sha256),
            )
        }
    )
    with pytest.raises(ValueError, match="unreferenced evidence"):
        replay_reward_package(
            changed,
            b["policy"],
            reopened,
            certified,
            **{**selection, "expected_package_sha256": digest(changed)},
        )
    changed = package.model_copy(update={"objects": package.objects[:-1]})
    with pytest.raises((KeyError, ValueError, FileNotFoundError)):
        replay_reward_package(
            changed,
            b["policy"],
            reopened,
            certified,
            **{**selection, "expected_package_sha256": digest(changed)},
        )
    obj = package.objects[0].model_copy(update={"value": {"tampered": True}})
    changed = package.model_copy(update={"objects": (obj, *package.objects[1:])})
    with pytest.raises(ValueError, match="bounded identity"):
        replay_reward_package(
            changed,
            b["policy"],
            reopened,
            certified,
            **{**selection, "expected_package_sha256": digest(changed)},
        )
    with pytest.raises(ValueError, match="different bytes"):
        publish_reward_package(path, changed)
    revoked = transition(certified, b["policy"], "revoke", start + 30)
    with pytest.raises(ValueError, match="revoked"):
        load_reward_package(
            path,
            b["policy"],
            reopened,
            revoked,
            **{**selection, "expected_tip_sha256": tip(revoked)},
        )
    # Later certified history is supplied independently. It never edits the
    # package or changes its original scoring/promotion selection.
    completed = close(certified, b["policy"], b["decisions"], start + 30, "ef" * 32)
    advanced_selection = {**selection, "expected_tip_sha256": tip(completed)}
    with pytest.raises(FileNotFoundError, match="current cohort decision"):
        load_reward_package(path, b["policy"], reopened, completed, **advanced_selection)
    with pytest.raises(ValueError, match="current cohort decision evidence changed"):
        load_reward_package(
            path,
            b["policy"],
            reopened,
            completed,
            **advanced_selection,
            current_decision_source=lambda _: b["decisions"][original_decision],
        )
    assert (
        load_reward_package(
            path,
            b["policy"],
            reopened,
            completed,
            **{**selection, "expected_tip_sha256": tip(completed)},
            current_decision_source=b["decisions"].__getitem__,
        )
        == result
    )
    assert path.read_bytes() == original_bytes
    assert b["service_case"].p.model.calls == 1
