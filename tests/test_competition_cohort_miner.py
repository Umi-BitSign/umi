"""Actual miner ASGI admission with signed cohort history and owned-window ports.

RPC/finality inputs, DNS, videos and model inference are fixtures. No installed
service or native reward effect is claimed by these checks.
"""

import asyncio
import time
from dataclasses import replace

import bittensor as bt
import httpx
import pytest

from umi.auth import HotkeyAuth
from umi.competition_cohort_miner import (
    CohortMinerAuthorizationAuthority,
    CohortMinerConfig,
    CohortMinerGrant,
    SignedCohortMinerGrantReceipt,
)
from umi.endpoint_protocol import COHORT_GRANT_PATH, RESPONSE_RECOVERY_PATH, TRANSLATE_PATH
from umi.miner import create_app
from umi.open_competition import digest, identity, verify_signature
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_cohort_endpoint_recovery import (
    base_policy as base_policy,
)
from .test_competition_cohort_endpoint_recovery import (
    chain as chain,
)
from .test_competition_cohort_endpoint_recovery import (
    chain_config as chain_config,
)
from .test_competition_cohort_endpoint_recovery import (
    endpoint as endpoint,
)
from .test_competition_cohort_endpoint_recovery import (
    execution as execution,
)
from .test_competition_cohort_endpoint_recovery import (
    harness as harness,
)
from .test_competition_cohort_endpoint_recovery import (
    known_video_bytes as known_video_bytes,
)
from .test_competition_cohort_endpoint_recovery import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_endpoint_recovery import (
    policy as policy,
)
from .test_competition_cohort_endpoint_recovery import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_endpoint_recovery import (
    recovery as recovery,
)
from .test_competition_cohort_endpoint_recovery import (
    recovery_case as recovery_case,
)
from .test_competition_cohort_endpoint_recovery import (
    relay as relay,
)
from .test_competition_cohort_endpoint_recovery import (
    runtime as runtime,
)
from .test_competition_cohort_endpoint_recovery import (
    scenario as scenario,
)
from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_recovery import signatures
from .test_open_competition import wallet
from .test_validator_plans import FinalizedPort, _block, _clock


@pytest.fixture
def granted(recovery_case, tmp_path):
    p = recovery_case
    transport = p.transport_policy
    # Schedule a fresh transport window long after the cohort's original targets.
    index = (
        p.c.finality.ref.block_number - transport.activation_block
    ) // transport.clock.window_stride_blocks + 2
    announce_height = transport.activation_block + index * transport.clock.window_stride_blocks
    now_ms = time.time_ns() // 1_000_000
    announcement = _block(
        transport,
        0,
        height=announce_height,
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
    p.finality = FinalizedPort(
        head=issuance.height,
        blocks={
            announcement.height: announcement,
            issuance.height: issuance,
        },
    )
    p.requests = [
        r.model_copy(
            update={
                "window_id": schedule.window_id,
                "issued_block": issuance.height,
                "issued_block_hash": issuance.block_hash,
                "deadline_block": issuance.height + schedule.response_deadline_blocks,
                "response_close_round": schedule.response_close_round,
                "reveal_round": schedule.reveal_round,
            }
        )
        for r in p.requests
    ]
    body = p.signed.order.model_copy(update={"requests": tuple(p.requests)})
    p.signed = p.signed.model_copy(update={"order": body, "signatures": signatures(body)})
    p.grant = CohortMinerGrant(
        schema="umi-cohort-miner-grant/1", assignment=p.e.assignment, attempt=p.signed
    )
    p.miner_cfg = CohortMinerConfig(
        schema="umi-cohort-miner-config/1",
        directory=str(tmp_path / "cohort-miner"),
        cohorts=p.e.cfg.cohorts,
        policy_sha256=digest(p.c.policy),
        transport_policy_sha256=scoring_policy_hash(transport),
        miner_hotkey=p.miner.hotkey_ss58,
        model_revision=p.miner.model_revision,
        serving_origin=p.e.job.submission.submission.endpoint_url,
    )
    p.authority = lambda **kw: CohortMinerAuthorizationAuthority(
        p.miner_cfg.model_copy(update=kw),
        p.c.policy,
        transport,
        p.finality,
        p.e.box.history,
    )
    p.rebuild = lambda **kw: replace(
        p.miner,
        runtime_mode="competition_no_weight",
        response_deadline_blocks=schedule.response_deadline_blocks,
        limits=replace(
            p.miner.limits,
            inference_timeout_seconds=p.c.policy.maximum_inference_ms / 1000,
            maximum_hypothesis_utf8_bytes=p.c.policy.maximum_output_bytes,
            maximum_inference_concurrency=len(p.c.policy.evaluators),
        ),
        allowed_validator_hotkeys=frozenset(e.hotkey for e in p.c.policy.evaluators),
        competition_authority=p.authority(**kw),
    )
    p.miner = p.rebuild()
    return p


async def request(p, path, value, *, caller=None, raw=None):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(p.miner)), base_url="https://example.com"
    ) as client:
        return await client.post(
            path,
            content=canonical_json_bytes(value) if raw is None else raw,
            auth=HotkeyAuth(caller or p.validator, p.miner.hotkey_ss58),
        )


async def grant(p):
    return await request(p, COHORT_GRANT_PATH, p.grant)


async def translate(p, index=0):
    return await request(p, TRANSLATE_PATH, p.requests[index])


async def test_native_late_grant_inference_restart_and_original_response_recovery(
    granted, monkeypatch
):
    p = granted
    assert p.requests[0].issued_block > p.c.policy.valid_through_block
    assert (await translate(p)).status_code == 422
    ack = await grant(p)
    assert ack.status_code == 200, ack.text
    receipt = SignedCohortMinerGrantReceipt.model_validate_json(ack.content)
    verify_signature(receipt.receipt, receipt.signature)
    assert receipt.receipt.grant_sha256 == digest(p.grant)
    assert receipt.receipt.miner_hotkey == p.miner.hotkey_ss58
    assert not receipt.receipt.chain_submission_authorized
    assert p.fetcher.calls == p.model.calls == 0
    p.miner = p.rebuild()
    assert (await grant(p)).content == ack.content
    result = await translate(p)
    assert result.status_code == 200, result.text
    assert p.fetcher.calls == p.model.calls == 1
    duplicate = await translate(p)
    assert duplicate.content == result.content
    assert p.model.calls == 1
    p.finality.head = p.requests[0].deadline_block + 3000
    monkeypatch.setattr(bt.timelock, "current_round", lambda: p.requests[0].reveal_round + 100)
    assert (await translate(p)).status_code == 422
    recovered = await request(p, RESPONSE_RECOVERY_PATH, p.requests[0])
    assert recovered.status_code == 200, recovered.text
    assert recovered.content == result.content and p.model.calls == 1
    assert (await grant(p)).content == ack.content


@pytest.mark.parametrize(
    "damage",
    [
        "caller",
        "signature",
        "delivery",
        "participant",
        "model",
        "origin",
        "authority",
        "request",
        "replacement",
    ],
)
async def test_grant_rejects_changed_or_unauthorized_scope(granted, damage):
    p = granted
    caller = None
    if damage == "caller":
        caller = next(
            wallet(n)
            for n in ("Charlie", "Dave", "Eve", "Ferdie")
            if identity(wallet(n).hotkey.ss58_address) != identity(p.validator.hotkey.ss58_address)
        )
    elif damage == "signature":
        p.grant = p.grant.model_copy(
            update={"attempt": p.signed.model_copy(update={"signatures": p.signed.signatures[:1]})}
        )
    elif damage == "delivery":
        d = p.grant.assignment.delivery
        p.grant = p.grant.model_copy(
            update={
                "assignment": p.grant.assignment.model_copy(
                    update={
                        "delivery": d.model_copy(
                            update={
                                "signature": d.signature.model_copy(
                                    update={"signature": "0x" + "00" * 64}
                                )
                            }
                        )
                    }
                )
            }
        )
    elif damage == "participant":
        part = p.grant.assignment.participant
        part = part.model_copy(
            update={"admission_snapshot": part.admission_snapshot.model_copy(update={"block": 211})}
        )
        p.grant = p.grant.model_copy(
            update={"assignment": p.grant.assignment.model_copy(update={"participant": part})}
        )
    elif damage in {"model", "origin", "authority"}:
        updates = {
            "model": {"model_revision": "aa" * 32},
            "origin": {"serving_origin": "https://1.1.1.1:443"},
            "authority": {
                "cohorts": (
                    p.miner_cfg.cohorts[0].model_copy(update={"authority_sha256": "dd" * 32}),
                )
            },
        }[damage]
        # A separate configuration namespace avoids mistaking a binding rejection for authorization.
        updates["directory"] = p.miner_cfg.directory + "-" + damage
        authority = p.authority(**updates)
        if damage == "model":
            p.miner = replace(p.miner, model_revision="aa" * 32, competition_authority=authority)
        else:
            p.miner = replace(p.miner, competition_authority=authority)
    else:
        body = p.signed.order.model_copy(
            update={"attempt_number": 2}
            if damage == "replacement"
            else {
                "requests": (
                    p.requests[0].model_copy(
                        update={
                            "video": p.requests[0].video.model_copy(update={"sha256": "99" * 32})
                        }
                    ),
                    *p.requests[1:],
                )
            }
        )
        p.grant = p.grant.model_copy(
            update={
                "attempt": p.signed.model_copy(
                    update={"order": body, "signatures": signatures(body)}
                )
            }
        )
    result = await request(p, COHORT_GRANT_PATH, p.grant, caller=caller)
    assert result.status_code == 422, result.text
    assert p.fetcher.calls == p.model.calls == 0


async def test_closure_and_rollback_survive_miner_restart(granted):
    p = granted
    ack = await grant(p)
    assert ack.status_code == 200
    old = p.e.r.h.source
    p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
    assert (await translate(p)).status_code == 422
    # Storage acknowledgement stays available; it never grants execution.
    assert (await grant(p)).content == ack.content
    p.miner = p.rebuild()
    p.e.r.h.source = old
    assert (await translate(p)).status_code == 422
    assert p.model.calls == 0


async def test_lost_receipt_commit_resumes_without_current_history(granted, monkeypatch):
    p = granted
    authority = p.miner.competition_authority
    real = authority.journal.put

    def lose(kind, *args, **kwargs):
        if kind == "miner_grant_receipt":
            raise OSError("lost storage")
        return real(kind, *args, **kwargs)

    monkeypatch.setattr(authority.journal, "put", lose)
    result = await grant(p)
    assert result.status_code == 503
    p.miner = p.rebuild()

    async def unavailable(*args):
        raise OSError("history offline")

    p.miner.competition_authority.history = unavailable
    ack = await grant(p)
    assert ack.status_code == 200, ack.text
    assert (await grant(p)).content == ack.content
    assert (await translate(p)).status_code == 503
    assert p.model.calls == 0


async def test_nonce_and_route_authentication_are_required(granted):
    p = granted
    raw = canonical_json_bytes(p.grant)
    headers = bt.http_auth.sign(
        p.validator,
        method="POST",
        path=COHORT_GRANT_PATH,
        body=raw,
        receiver_ss58=p.miner.hotkey_ss58,
    )
    import hashlib

    from umi.auth import REQUEST_BODY_SHA256_HEADER

    headers[REQUEST_BODY_SHA256_HEADER] = hashlib.sha256(raw).hexdigest()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(p.miner)), base_url="https://example.com"
    ) as c:
        assert (await c.post(COHORT_GRANT_PATH, content=raw)).status_code == 401
        assert (await c.post(COHORT_GRANT_PATH, content=raw, headers=headers)).status_code == 200
        assert (await c.post(COHORT_GRANT_PATH, content=raw, headers=headers)).status_code == 401
        wrong = bt.http_auth.sign(
            p.validator,
            method="POST",
            path=TRANSLATE_PATH,
            body=raw,
            receiver_ss58=p.miner.hotkey_ss58,
        )
        wrong[REQUEST_BODY_SHA256_HEADER] = hashlib.sha256(raw).hexdigest()
        assert (await c.post(COHORT_GRANT_PATH, content=raw, headers=wrong)).status_code == 401


async def test_capacity_growth_preserves_grant_and_legacy_routes(granted):
    p = granted
    p.miner = p.rebuild(maximum_bytes=1024)
    assert (await grant(p)).status_code == 503
    p.miner = p.rebuild(maximum_bytes=1024**3)
    assert (await grant(p)).status_code == 200
    p.miner = p.rebuild(maximum_bytes=2 * 1024**3)
    assert (await translate(p)).status_code == 200
    assert p.model.calls == 1


def resign_requests(p, requests):
    p.requests = list(requests)
    body = p.signed.order.model_copy(update={"requests": tuple(requests)})
    p.signed = p.signed.model_copy(update={"order": body, "signatures": signatures(body)})
    p.grant = p.grant.model_copy(update={"attempt": p.signed})


@pytest.mark.parametrize(
    "damage", ["window", "hash", "reveal", "early", "expired", "missing_header", "bad_finality"]
)
async def test_owned_transport_window_cannot_be_overridden_by_cohort_signers(granted, damage):
    p = granted
    original = p.requests[0]
    if damage in {"window", "hash", "reveal"}:
        update = {
            "window": {"window_id": "99" * 32},
            "hash": {"issued_block_hash": "0x" + "99" * 32},
            "reveal": {"reveal_round": original.reveal_round + 10},
        }[damage]
        resign_requests(p, [original.model_copy(update=update), *p.requests[1:]])
    assert (await grant(p)).status_code == 200
    if damage == "early":
        p.finality.head = original.issued_block - 1
    elif damage == "expired":
        p.finality.head = original.deadline_block + 1
    elif damage == "missing_header":
        del p.finality.blocks[original.issued_block]
    elif damage == "bad_finality":
        p.finality.blocks[original.issued_block] = replace(
            p.finality.blocks[original.issued_block], finality_verifier_sha256="99" * 32
        )
    result = await translate(p)
    assert result.status_code in {422, 503}, result.text
    assert p.model.calls == p.fetcher.calls == 0


async def test_retained_grant_cannot_be_retimed_by_same_signers(granted):
    p = granted
    first = await grant(p)
    assert first.status_code == 200
    request = p.requests[0].model_copy(update={"window_id": "99" * 32})
    resign_requests(p, [request, *p.requests[1:]])
    assert (await grant(p)).status_code == 422
    assert p.model.calls == 0


async def test_closure_arriving_inside_transport_check_is_retained(granted, monkeypatch):
    p = granted
    assert (await grant(p)).status_code == 200
    authority = p.miner.competition_authority
    original = authority.legacy.authorize
    prior = p.e.r.h.source

    async def close_after_check(request):
        result = await original(request)
        p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
        return result

    monkeypatch.setattr(authority.legacy, "authorize", close_after_check)
    assert (await translate(p)).status_code == 422
    p.miner = p.rebuild()
    p.e.r.h.source = prior
    assert (await translate(p)).status_code == 422
    assert p.model.calls == 0


async def test_lost_acknowledgement_after_commit_returns_same_receipt(granted, monkeypatch):
    p = granted
    authority = p.miner.competition_authority
    original = authority.journal.put
    saved = []

    def commit_then_lose(kind, key, value, **kwargs):
        result = original(kind, key, value, **kwargs)
        if kind == "miner_grant_receipt":
            saved.append(canonical_json_bytes(value))
            raise OSError("connection lost after commit")
        return result

    monkeypatch.setattr(authority.journal, "put", commit_then_lose)
    assert (await grant(p)).status_code == 503
    assert len(saved) == 1
    p.miner = p.rebuild()
    assert (await grant(p)).content == saved[0]
    assert p.model.calls == 0


async def test_concurrent_duplicate_grants_share_one_receipt(granted):
    p = granted
    a, b = await asyncio.gather(grant(p), grant(p))
    assert a.status_code == b.status_code == 200
    assert a.content == b.content
    with p.miner.competition_authority.journal.transaction() as db:
        assert (
            db.execute("SELECT COUNT(*) FROM records WHERE kind='miner_grant'").fetchone()[0] == 1
        )


async def test_cancelled_receipt_write_drains_before_releasing_writer(granted, monkeypatch):
    import threading

    p = granted
    authority = p.miner.competition_authority
    original = authority.journal.put
    entered, release = threading.Event(), threading.Event()

    def delayed(kind, *args, **kw):
        if kind == "miner_grant_receipt":
            entered.set()
            assert release.wait(5)
        return original(kind, *args, **kw)

    monkeypatch.setattr(authority.journal, "put", delayed)
    task = asyncio.create_task(grant(p))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0.03)
        assert not task.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    p.miner = p.rebuild()
    assert (await grant(p)).status_code == 200
    assert (await translate(p)).status_code == 200
    assert p.model.calls == 1


@pytest.mark.parametrize("damage", ["noncanonical", "malformed", "over_limit"])
async def test_grant_ingress_is_bounded_and_canonical(granted, damage):
    p = granted
    raw = canonical_json_bytes(p.grant)
    if damage == "noncanonical":
        raw = b" " + raw
    elif damage == "malformed":
        raw = b"{}"
    else:
        from umi.competition_cohort_miner import MAX_COHORT_GRANT_BYTES

        raw = b"x" * (MAX_COHORT_GRANT_BYTES + 1)
    result = await request(p, COHORT_GRANT_PATH, p.grant, raw=raw)
    assert result.status_code == (413 if damage == "over_limit" else 422)
    assert p.model.calls == 0


async def test_grant_does_not_require_new_signature_after_phase_closure(granted, monkeypatch):
    from umi import competition_cohort_miner as module

    p = granted
    ack = await grant(p)
    assert ack.status_code == 200
    p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
    p.miner = p.rebuild()

    def forbidden(*args):
        raise AssertionError("already acknowledged grant must not be signed again")

    monkeypatch.setattr(module, "sign_object", forbidden)
    assert (await grant(p)).content == ack.content
    assert p.model.calls == 0


async def test_two_assigned_evaluators_retain_distinct_grants(granted):
    from umi.competition_cohort_endpoint import endpoint_attempt_wire_ids
    from umi.competition_cohort_orders import recoverable_order_job

    p = granted
    assert (await grant(p)).status_code == 200
    other = next(
        h
        for h in p.grant.assignment.certificate.order.evaluators
        if identity(h) != identity(p.validator.hotkey.ss58_address)
    )
    assignment = p.e.r.inbox(other).assignment(p.e.r.slot)
    job = recoverable_order_job(assignment.certificate.order, other)
    requests = []
    for old, case in zip(p.requests, job.cases, strict=True):
        batch, challenge = endpoint_attempt_wire_ids(job, 1, case.case_id)
        requests.append(old.model_copy(update={"batch_id": batch, "challenge_id": challenge}))
    body = p.signed.order.model_copy(update={"job": job, "requests": tuple(requests)})
    second = p.grant.model_copy(
        update={
            "assignment": assignment,
            "attempt": p.signed.model_copy(update={"order": body, "signatures": signatures(body)}),
        }
    )
    caller = next(
        wallet(n)
        for n in ("Charlie", "Dave", "Eve", "Ferdie")
        if identity(wallet(n).hotkey.ss58_address) == identity(other)
    )
    result = await request(p, COHORT_GRANT_PATH, second, caller=caller)
    assert result.status_code == 200, result.text
    result = await request(p, TRANSLATE_PATH, requests[0], caller=caller)
    assert result.status_code == 200, result.text
    assert (await translate(p)).status_code == 200
    assert p.model.calls == 2


@pytest.fixture
async def delivery(granted, tmp_path):
    from umi.competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
    from umi.competition_cohort_grant_delivery import CohortEndpointGrantDelivery

    p = granted
    existing = p.e.journal
    p.e.journal = lambda **kw: existing(directory=str(tmp_path / "delivery-journal"), **kw)
    p.transmissions = []
    inner = httpx.ASGITransport(app=create_app(p.miner))

    class Trace(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            p.transmissions.append(
                (request.url.path, request.headers["host"], request.extensions.get("sni_hostname"))
            )
            return await inner.handle_async_request(request)

    p.delivery_recovery = CohortEndpointResponseRecovery(
        p.service(), p.validator, transport=Trace()
    )
    p.delivery_selection = await p.delivery_recovery.prepare(
        p.e.assignment, p.signed, p.transport_policy
    )
    p.driver = CohortEndpointGrantDelivery(p.delivery_recovery)
    p.deliver = lambda: p.driver.deliver(p.delivery_selection.assignment_slot)
    return p


async def test_evaluator_delivers_grant_then_miner_serves_and_recovers(delivery, monkeypatch):
    p = delivery
    result = await p.deliver()
    assert result.status == "retained", result
    assert result.receipt.receipt.grant_sha256 == digest(p.grant)
    assert p.model.calls == 0
    assert p.transmissions == [(COHORT_GRANT_PATH, "example.com", "example.com")]
    response = await translate(p)
    assert response.status_code == 200, response.text
    assert p.model.calls == 1
    # The receiving ledger retains it; evaluator recovery consumes the same bytes.
    recovered = await p.delivery_recovery.recover(p.delivery_selection.assignment_slot, p.case_id)
    assert recovered.status == "recovered"
    assert bytes.fromhex(recovered.response.envelope_hex) == response.content
    count = len(p.transmissions)
    p.c.finality.fail = True
    assert (await p.deliver()).receipt == result.receipt
    assert len(p.transmissions) == count


async def test_lost_grant_http_ack_recovers_without_reselection(delivery):
    p = delivery
    inner = p.delivery_recovery.transport

    class Lose(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await inner.handle_async_request(request)
            raise httpx.ReadTimeout("lost acknowledgement")

    p.delivery_recovery.transport = Lose()
    assert (await p.deliver()).status == "pending"
    p.delivery_recovery.transport = inner
    first = await p.deliver()
    assert first.status == "retained"
    assert (await p.deliver()).receipt == first.receipt
    assert p.model.calls == 0
    with p.miner.competition_authority.journal.transaction() as db:
        assert (
            db.execute("SELECT COUNT(*) FROM records WHERE kind='miner_grant'").fetchone()[0] == 1
        )


@pytest.mark.parametrize(
    "damage", ["signature", "grant", "noncanonical", "oversize", "redirect", "encoded"]
)
async def test_evaluator_rejects_invalid_grant_receipt_and_keeps_selection(delivery, damage):
    import json

    p = delivery
    inner = p.delivery_recovery.transport

    class Damage(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            result = await inner.handle_async_request(request)
            body = json.loads(await result.aread())
            if damage == "signature":
                body["signature"]["signature"] = "0x" + "00" * 64
            elif damage == "grant":
                body["receipt"]["grant_sha256"] = "99" * 32
            raw = canonical_json_bytes(body)
            if damage == "noncanonical":
                raw = b" " + raw
            if damage == "oversize":
                raw = b"x" * (64 * 1024 + 1)
            return httpx.Response(
                302 if damage == "redirect" else 200,
                stream=httpx.ByteStream(raw),
                headers={"Content-Encoding": "gzip"} if damage == "encoded" else {},
            )

    p.delivery_recovery.transport = Damage()
    result = await p.deliver()
    assert result.status == "pending"
    assert p.model.calls == 0
    p.delivery_recovery.transport = inner
    assert (await p.deliver()).status == "retained"


async def test_grant_sender_resumes_after_local_receipt_storage_failure(delivery, monkeypatch):
    p = delivery
    journal = p.delivery_recovery.journal.journal
    original = journal.put

    def fail(kind, *args, **kw):
        if kind == "miner_grant_delivery":
            raise OSError("storage unavailable")
        return original(kind, *args, **kw)

    monkeypatch.setattr(journal, "put", fail)
    with pytest.raises(OSError):
        await p.deliver()
    monkeypatch.setattr(journal, "put", original)
    assert (await p.deliver()).status == "retained"
    assert p.model.calls == 0


@pytest.mark.parametrize("source", ["history", "finality"])
async def test_unavailable_authority_source_remains_retryable(granted, monkeypatch, source):
    p = granted
    authority = p.miner.competition_authority

    async def unavailable(*args):
        raise RuntimeError("owned source temporarily unavailable")

    owner, name = (
        (authority, "history") if source == "history" else (p.finality, "finalized_head_height")
    )
    original = getattr(owner, name)
    monkeypatch.setattr(owner, name, unavailable)
    assert (await grant(p)).status_code == 503
    monkeypatch.setattr(owner, name, original)
    ack = await grant(p)
    assert ack.status_code == 200
    monkeypatch.setattr(owner, name, unavailable)
    assert (await grant(p)).content == ack.content
    assert (await translate(p)).status_code == 503
    assert p.model.calls == 0
    monkeypatch.setattr(owner, name, original)
    assert (await translate(p)).status_code == 200
    assert p.model.calls == 1


async def test_local_grant_review_can_outlast_network_timeout(granted, monkeypatch):
    from umi import competition_cohort_miner as module

    p = granted
    p.miner = p.rebuild(read_timeout_seconds=1)
    original = module.review_order

    def slow_review(*args):
        time.sleep(1.05)
        return original(*args)

    monkeypatch.setattr(module, "review_order", slow_review)
    result = await grant(p)
    assert result.status_code == 200, result.text
    assert (await grant(p)).content == result.content
    assert p.model.calls == 0
