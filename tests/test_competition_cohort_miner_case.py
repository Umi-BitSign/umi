"""Versioned retry grants through native miner routes and durable review.

Finality, proof/DNS/video/model ports are fixtures. New request signatures use
fixture reviewer keys; installed replacement scheduling/signing is not claimed.
"""

import time
from dataclasses import replace

import bittensor as bt
import pytest

from umi.competition_cohort_endpoint import endpoint_attempt_wire_ids
from umi.competition_cohort_endpoint_decision import (
    CohortEndpointReplacementCaseReview,
    CohortEndpointReplacementSelection,
    case_decision_slot,
    validate_case_review,
)
from umi.competition_cohort_endpoint_recovery import CohortRecoveredEndpointCase
from umi.competition_cohort_endpoint_retirement import CohortRetiredEndpointCase
from umi.competition_cohort_miner_case import (
    CohortCaseMinerGrant,
    RecoverableEndpointCaseOrder,
    SignedRecoverableEndpointCaseOrder,
    grant_slot,
)
from umi.endpoint_protocol import (
    COHORT_GRANT_PATH,
    COHORT_RETIRE_PATH,
    RESPONSE_RECOVERY_PATH,
    TRANSLATE_PATH,
)
from umi.endpoint_response_recovery import RecoveredEndpointResponse
from umi.endpoint_retirement import SignedEndpointRetirementReceipt
from umi.open_competition import digest
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_cohort_endpoint_decision import (
    base_policy as base_policy,
)
from .test_competition_cohort_endpoint_decision import (
    chain as chain,
)
from .test_competition_cohort_endpoint_decision import (
    chain_config as chain_config,
)
from .test_competition_cohort_endpoint_decision import (
    decisions as decisions,
)
from .test_competition_cohort_endpoint_decision import (
    delivery as delivery,
)
from .test_competition_cohort_endpoint_decision import (
    endpoint as endpoint,
)
from .test_competition_cohort_endpoint_decision import (
    execution as execution,
)
from .test_competition_cohort_endpoint_decision import (
    granted as granted,
)
from .test_competition_cohort_endpoint_decision import (
    harness as harness,
)
from .test_competition_cohort_endpoint_decision import (
    known_video_bytes as known_video_bytes,
)
from .test_competition_cohort_endpoint_decision import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_endpoint_decision import (
    policy as policy,
)
from .test_competition_cohort_endpoint_decision import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_endpoint_decision import (
    recovery as recovery,
)
from .test_competition_cohort_endpoint_decision import (
    recovery_case as recovery_case,
)
from .test_competition_cohort_endpoint_decision import (
    relay as relay,
)
from .test_competition_cohort_endpoint_decision import (
    retiring as retiring,
)
from .test_competition_cohort_endpoint_decision import (
    runtime as runtime,
)
from .test_competition_cohort_endpoint_decision import (
    scenario as scenario,
)
from .test_competition_cohort_miner import request
from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_recovery import signatures
from .test_validator_plans import _block, _clock


async def certify(d, review):
    a, b = d.worker(), d.worker("Dave")
    await a.attest(review)
    body = validate_case_review(review, d.p.c.policy)[1]
    slot = case_decision_slot(body)
    await a.collect(slot, await b.attest(review))
    return await a.certify(slot)


def next_grant(d, parent, review, certificate, monkeypatch):
    p = d.p
    transport, job = p.transport_policy, parent.attempt.order.job
    number = parent.attempt.order.attempt_number + 1
    parent_body = parent.attempt.order
    index = (
        0
        if isinstance(parent, CohortCaseMinerGrant)
        else next(i for i, c in enumerate(job.cases) if c.case_id == review.retirement.case_id)
    )
    old = parent_body.requests[index]
    index = (
        max(p.finality.head, old.deadline_block) - transport.activation_block
    ) // transport.clock.window_stride_blocks + 2
    height = transport.activation_block + index * transport.clock.window_stride_blocks
    now_ms = max(
        time.time_ns() // 1_000_000 + number * 60_000,
        QUICKNET_GENESIS_MS
        + (max(bt.timelock.current_round(), old.response_close_round) + 1) * QUICKNET_PERIOD_MS,
    )
    announcement = _block(
        transport,
        0,
        height=height,
        block_byte="31",
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
        block_byte="41",
        timestamp_ms=QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS,
    )
    p.finality.blocks.update({announcement.height: announcement, issuance.height: issuance})
    p.finality.head = issuance.height
    p.c.finality.ref = replace(
        p.c.finality.ref, block_number=issuance.height, block_hash=f"0x{issuance.height:064x}"
    )
    monkeypatch.setattr(bt.timelock, "current_round", lambda: schedule.selection_round)
    case = review.retirement.case_id
    batch_id, challenge_id = endpoint_attempt_wire_ids(job, number, case)
    req = old.model_copy(
        update={
            "batch_id": batch_id,
            "challenge_id": challenge_id,
            "window_id": schedule.window_id,
            "issued_block": issuance.height,
            "issued_block_hash": issuance.block_hash,
            "deadline_block": issuance.height + schedule.response_deadline_blocks,
            "response_close_round": schedule.response_close_round,
            "reveal_round": schedule.reveal_round,
        }
    )
    body = RecoverableEndpointCaseOrder(
        schema="umi-recoverable-endpoint-case-order/1",
        job=job,
        transport_policy_sha256=scoring_policy_hash(transport),
        case_id=case,
        attempt_number=number,
        requests=(req,),
        parent_grant_slot=grant_slot(parent),
        parent_grant_sha256=digest(parent),
        prior_decision=certificate,
        prior_retirement=review.retirement.retirement,
    )
    return CohortCaseMinerGrant(
        schema="umi-cohort-miner-grant/2",
        assignment=parent.assignment,
        attempt=SignedRecoverableEndpointCaseOrder(order=body, signatures=signatures(body)),
    )


async def replacement_review(d, grant, monkeypatch, response=None):
    p = d.p
    req = grant.attempt.order.requests[0]
    if response is None:
        p.finality.head = req.deadline_block + 1
        p.c.finality.ref = replace(
            p.c.finality.ref, block_number=p.finality.head, block_hash=f"0x{p.finality.head:064x}"
        )
        monkeypatch.setattr(bt.timelock, "current_round", lambda: req.response_close_round + 1)
    reply = await request(p, COHORT_RETIRE_PATH, req)
    assert reply.status_code == 200, reply.text
    selection = CohortEndpointReplacementSelection(
        schema="umi-cohort-endpoint-replacement-selection/1",
        grant=grant,
        transport_policy=p.transport_policy,
    )
    retired = CohortRetiredEndpointCase(
        schema="umi-cohort-retired-endpoint-case/1",
        selection_sha256=digest(selection),
        case_id=grant.attempt.order.case_id,
        origin_evidence_sha256="ab" * 32,
        observed_block=p.finality.head,
        observed_round=bt.timelock.current_round(),
        retirement=SignedEndpointRetirementReceipt.model_validate_json(reply.content),
    )
    recovered = None
    if response is not None:
        recovered = CohortRecoveredEndpointCase(
            schema="umi-cohort-recovered-endpoint-case/1",
            selection_sha256=digest(selection),
            case_id=retired.case_id,
            origin_evidence_sha256="ab" * 32,
            response=RecoveredEndpointResponse(
                schema="umi-recovered-endpoint-response/1",
                envelope_hex=response.content.hex(),
                signature=response.headers["x-umi-signature"],
                retrieval_started_at_unix_ns="1",
                retrieved_at_unix_ns="2",
            ),
        )
    return CohortEndpointReplacementCaseReview(
        schema="umi-cohort-endpoint-case-review/2",
        selection=selection,
        retirement=retired,
        recovered=recovered,
    )


async def prepared(d, monkeypatch):
    review = await d.evidence()
    return next_grant(d, d.p.grant, review, await certify(d, review), monkeypatch)


@pytest.mark.parametrize("failed", [False, True])
async def test_retry_inference_and_signed_response_survive_restart(decisions, monkeypatch, failed):
    d = decisions
    p = d.p
    original = p.grant
    child = await prepared(d, monkeypatch)
    ack = await request(p, COHORT_GRANT_PATH, child)
    assert ack.status_code == 200, ack.text
    p.miner = p.rebuild()
    assert (await request(p, COHORT_GRANT_PATH, child)).content == ack.content
    req = child.attempt.order.requests[0]
    p.model.fail = failed
    result = await request(p, TRANSLATE_PATH, req)
    assert result.status_code == 200, result.text
    assert p.model.calls == 1
    assert (await request(p, TRANSLATE_PATH, req)).content == result.content
    review = await replacement_review(d, child, monkeypatch, result)
    cert = await certify(d, review)
    assert cert.decision.disposition == "retain_response"
    p.c.finality.fail = True
    p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
    p.miner = p.rebuild()
    assert (await request(p, COHORT_GRANT_PATH, child)).content == ack.content
    recovered = await request(p, RESPONSE_RECOVERY_PATH, req)
    assert recovered.content == result.content
    assert p.model.calls == 1
    authority = p.miner.competition_authority
    assert canonical_json_bytes(
        authority.journal.get("miner_grant", grant_slot(original))
    ) == canonical_json_bytes(original)
    assert canonical_json_bytes(
        authority.journal.get("miner_grant", grant_slot(child))
    ) == canonical_json_bytes(child)


async def test_repeated_expired_retries_preserve_all_parent_records(decisions, monkeypatch):
    d = decisions
    p = d.p
    review = await d.evidence()
    parent = p.grant
    grants = [parent]
    sizes = []
    for _number in range(2, 5):
        cert = await certify(d, review)
        child = next_grant(d, parent, review, cert, monkeypatch)
        ack = await request(p, COHORT_GRANT_PATH, child)
        assert ack.status_code == 200, ack.text
        p.miner = p.rebuild()
        assert (await request(p, COHORT_GRANT_PATH, child)).content == ack.content
        sizes.append(len(canonical_json_bytes(child)))
        grants.append(child)
        review = await replacement_review(d, child, monkeypatch)
        parent = child
    assert max(sizes) - min(sizes) < 200
    assert p.model.calls == p.fetcher.calls == 0
    authority = p.miner.competition_authority
    for g in grants:
        assert canonical_json_bytes(
            authority.journal.get("miner_grant", grant_slot(g))
        ) == canonical_json_bytes(g)


@pytest.mark.parametrize(
    "damage",
    [
        "parent_hash",
        "parent_slot",
        "decision",
        "retirement",
        "case",
        "attempt",
        "video",
        "batch",
        "overlap",
        "signature",
        "empty_requests",
        "extra_requests",
    ],
)
async def test_replacement_rejects_changed_parent_or_scope(decisions, monkeypatch, damage):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    body = child.attempt.order
    if damage in {"parent_hash", "parent_slot"}:
        field = "parent_grant_sha256" if damage == "parent_hash" else "parent_grant_slot"
        body = body.model_copy(update={field: "cd" * 32})
    elif damage == "decision":
        prior = body.prior_decision.decision.model_copy(update={"disposition": "retain_response"})
        body = body.model_copy(
            update={
                "prior_decision": body.prior_decision.model_copy(
                    update={"decision": prior, "signatures": signatures(prior)}
                )
            }
        )
    elif damage == "retirement":
        old = body.prior_retirement.receipt.model_copy(update={"request_digest": "cd" * 32})
        body = body.model_copy(
            update={"prior_retirement": body.prior_retirement.model_copy(update={"receipt": old})}
        )
    elif damage == "case":
        body = body.model_copy(update={"case_id": p.e.job.cases[1].case_id})
    elif damage == "attempt":
        body = body.model_copy(update={"attempt_number": 3})
    elif damage == "empty_requests":
        body = body.model_copy(update={"requests": ()})
    elif damage == "extra_requests":
        body = body.model_copy(update={"requests": (*body.requests, p.requests[1])})
    elif damage == "signature":
        child = child.model_copy(
            update={
                "attempt": child.attempt.model_copy(
                    update={"signatures": body.prior_decision.signatures}
                )
            }
        )
    else:
        req = body.requests[0]
        if damage == "video":
            req = req.model_copy(
                update={"video": req.video.model_copy(update={"sha256": "cd" * 32})}
            )
        elif damage == "batch":
            req = req.model_copy(update={"batch_id": p.requests[0].batch_id})
        else:
            req = req.model_copy(update={"issued_block": p.requests[0].deadline_block})
        body = body.model_copy(update={"requests": (req,)})
    if damage != "signature":
        child = child.model_copy(
            update={
                "attempt": SignedRecoverableEndpointCaseOrder(
                    order=body, signatures=signatures(body)
                )
            }
        )
    answer = await request(p, COHORT_GRANT_PATH, child)
    assert answer.status_code == 422, answer.text
    assert p.model.calls == p.fetcher.calls == 0


@pytest.mark.parametrize("kind", ["ok", "failed"])
async def test_completed_parent_cannot_be_retried(decisions, monkeypatch, kind):
    d = decisions
    p = d.p
    review = await d.evidence(kind)
    cert = await certify(d, review)
    # Even a quorum-signed malformed retry request cannot discard the miner's
    # signed retained response or failure.
    changed = cert.decision.model_copy(
        update={"disposition": "retry_required", "response_sha256": None}
    )
    cert = cert.model_copy(update={"decision": changed, "signatures": signatures(changed)})
    child = next_grant(d, p.grant, review, cert, monkeypatch)
    assert (await request(p, COHORT_GRANT_PATH, child)).status_code == 422
    assert p.model.calls == 1


async def test_competing_window_cannot_replace_retained_child(decisions, monkeypatch):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    ack = await request(p, COHORT_GRANT_PATH, child)
    assert ack.status_code == 200, ack.text
    body = child.attempt.order
    req = body.requests[0]
    req = req.model_copy(
        update={"video": req.video.model_copy(update={"url": req.video.url + "?v=2"})}
    )
    body = body.model_copy(update={"requests": (req,)})
    changed = child.model_copy(
        update={
            "attempt": SignedRecoverableEndpointCaseOrder(order=body, signatures=signatures(body))
        }
    )
    assert (await request(p, COHORT_GRANT_PATH, changed)).status_code == 422
    p.miner = p.rebuild()
    assert (await request(p, COHORT_GRANT_PATH, child)).content == ack.content
    assert p.model.calls == 0


@pytest.mark.parametrize("after", [False, True])
async def test_retry_receipt_commit_recovers_identical_ack(decisions, monkeypatch, after):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    journal = p.miner.competition_authority.journal
    real = journal.put

    def broken(kind, key, value):
        if kind == "miner_grant_receipt":
            if after:
                real(kind, key, value)
            raise OSError("acknowledgement lost")
        return real(kind, key, value)

    with monkeypatch.context() as patch:
        patch.setattr(journal, "put", broken)
        assert (await request(p, COHORT_GRANT_PATH, child)).status_code == 503
    p.miner = p.rebuild()
    ack = await request(p, COHORT_GRANT_PATH, child)
    assert ack.status_code == 200, ack.text
    assert (await request(p, COHORT_GRANT_PATH, child)).content == ack.content
    assert p.model.calls == 0


async def test_expired_child_can_be_retained_but_cannot_run(decisions, monkeypatch):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    req = child.attempt.order.requests[0]
    p.finality.head = req.deadline_block + 3000
    p.c.finality.ref = replace(
        p.c.finality.ref, block_number=p.finality.head, block_hash=f"0x{p.finality.head:064x}"
    )
    monkeypatch.setattr(bt.timelock, "current_round", lambda: req.reveal_round + 100)
    assert (await request(p, COHORT_GRANT_PATH, child)).status_code == 200
    assert (await request(p, TRANSLATE_PATH, req)).status_code == 422
    review = await replacement_review(d, child, monkeypatch)
    assert (await certify(d, review)).decision.disposition == "retry_required"
    assert p.model.calls == 0


async def test_missing_parent_is_recoverable_without_new_request(decisions, monkeypatch, tmp_path):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    original_cfg = p.miner_cfg
    p.miner_cfg = p.miner_cfg.model_copy(update={"directory": str(tmp_path / "restored-miner")})
    p.miner = p.rebuild()
    assert (await request(p, COHORT_GRANT_PATH, child)).status_code == 422
    # Restore the exact parent through normal admission, even though its
    # individual request window expired, then retry the unchanged child.
    assert (await request(p, COHORT_GRANT_PATH, p.grant)).status_code == 200
    assert (await request(p, COHORT_GRANT_PATH, child)).status_code == 200
    assert p.model.calls == 0
    p.miner_cfg = original_cfg


async def test_corrupt_parent_archive_blocks_inference(decisions, monkeypatch):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    assert (await request(p, COHORT_GRANT_PATH, child)).status_code == 200
    authority = p.miner.competition_authority
    real = authority.journal.get

    def corrupted(kind, key, **kwargs):
        value = real(kind, key, **kwargs)
        if kind == "miner_grant" and key == grant_slot(p.grant):
            value = dict(value)
            value["attempt"] = dict(value["attempt"])
            value["attempt"]["signatures"] = []
        return value

    with monkeypatch.context() as patch:
        patch.setattr(authority.journal, "get", corrupted)
        assert (
            await request(p, TRANSLATE_PATH, child.attempt.order.requests[0])
        ).status_code == 422
    assert p.model.calls == 0


@pytest.mark.parametrize("retained", [False, True])
async def test_closed_phase_rejects_new_retry_but_recovers_existing_ack(
    decisions, monkeypatch, retained
):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    if retained:
        ack = await request(p, COHORT_GRANT_PATH, child)
        assert ack.status_code == 200
    p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
    p.miner = p.rebuild()
    reply = await request(p, COHORT_GRANT_PATH, child)
    if retained:
        assert reply.content == ack.content
    else:
        assert reply.status_code == 422
    assert (await request(p, TRANSLATE_PATH, child.attempt.order.requests[0])).status_code == 422
    assert p.model.calls == 0


async def test_retry_capacity_growth_preserves_original_and_child(decisions, monkeypatch):
    d = decisions
    p = d.p
    child = await prepared(d, monkeypatch)
    p.miner = p.rebuild(maximum_grants=1)
    assert (await request(p, COHORT_GRANT_PATH, child)).status_code == 503
    assert (await request(p, COHORT_GRANT_PATH, p.grant)).status_code == 200
    p.miner = p.rebuild(maximum_grants=2)
    ack = await request(p, COHORT_GRANT_PATH, child)
    assert ack.status_code == 200, ack.text
    assert (await request(p, COHORT_GRANT_PATH, child)).content == ack.content
    assert p.model.calls == 0
