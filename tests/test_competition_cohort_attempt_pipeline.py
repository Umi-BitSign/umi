"""Existing evaluator workers drive versioned grants through native miner HTTP.

Finality, DNS and model inference use fixture ports; replacement request
signatures still use fixture keys. Persistent selections, authenticated grant
and response delivery, retirement, reviewer journals and quorum are native.
"""

from dataclasses import replace

import bittensor as bt
import httpx
import pytest

from umi.competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
from umi.competition_cohort_endpoint_recovery_worker import CohortEndpointRecoveryWorker
from umi.competition_cohort_endpoint_retirement import CohortEndpointRetirement
from umi.competition_cohort_endpoint_selection import (
    case_record_key,
    selection_slot,
)
from umi.competition_cohort_grant_delivery import CohortEndpointGrantDelivery
from umi.competition_cohort_miner_case import grant_slot
from umi.endpoint_protocol import TRANSLATE_PATH
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_endpoint_decision import (
    base_policy as base_policy,
)
from .test_competition_cohort_endpoint_decision import (
    chain as chain,
)
from .test_competition_cohort_endpoint_decision import (
    chain_config as chain_config,
)
from .test_competition_cohort_endpoint_decision import coordinator
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
from .test_competition_cohort_endpoint_retirement import translate
from .test_competition_cohort_miner import request
from .test_competition_cohort_miner_case import next_grant
from .test_competition_cohort_recovery import signatures


def reopen(p):
    p.delivery_recovery = CohortEndpointResponseRecovery(
        p.service(), p.validator, transport=p.delivery_recovery.transport
    )
    p.retirement = CohortEndpointRetirement(p.delivery_recovery)
    p.driver = CohortEndpointGrantDelivery(p.delivery_recovery)


async def child(d, monkeypatch, index=1):
    p = d.p
    review = await d.evidence(index=index)
    result = await coordinator(d).advance(p.retire_slot, review.retirement.case_id)
    grant = next_grant(d, p.grant, review, result.certificate, monkeypatch)
    return grant


def expire_child(p, grant, monkeypatch):
    r = grant.attempt.order.requests[0]
    p.finality.head = r.deadline_block + 1
    p.c.finality.ref = replace(
        p.c.finality.ref, block_number=p.finality.head, block_hash=f"0x{p.finality.head:064x}"
    )
    monkeypatch.setattr(bt.timelock, "current_round", lambda: r.response_close_round + 1)


@pytest.mark.parametrize("failed", [False, True])
async def test_nonfirst_replacement_preserves_mixed_completed_cases(decisions, monkeypatch, failed):
    d, p = decisions, decisions.p
    completed = []
    for index in (0, 2):
        p.model.fail = index == 2
        result = await translate(p, index=index)
        assert result.status_code == 200
        decision = await coordinator(d).advance(p.retire_slot, p.e.job.cases[index].case_id)
        assert decision.certificate.decision.disposition == "retain_response"
        completed.append(decision.certificate)
    grant = await child(d, monkeypatch)
    p.model.fail = failed
    selected = await p.delivery_recovery.prepare_case(grant, p.transport_policy)
    slot, case = selection_slot(selected), grant.attempt.order.case_id
    assert slot == grant_slot(grant) and slot != p.retire_slot
    assert case_record_key(selected, case) != case_record_key(p.delivery_selection, case)
    assert (await p.driver.deliver(slot)).status == "retained"
    response = await request(p, TRANSLATE_PATH, grant.attempt.order.requests[0])
    assert response.status_code == 200, response.text
    assert p.model.calls == 3
    reopen(p)
    result = await CohortEndpointRecoveryWorker(p.delivery_recovery).poll_once()
    assert result["responses_recovered"] >= 1
    recovered = p.delivery_recovery.retained(slot, case)
    assert bytes.fromhex(recovered.response.envelope_hex) == response.content
    result = await coordinator(d).advance(slot, case)
    assert result.certificate.decision.disposition == "retain_response"
    assert result.certificate.decision.attempt_number == 2
    assert p.delivery_recovery.retained(p.retire_slot, case) is None
    before = list(p.transmissions)
    p.c.finality.fail = True
    d.fail_sign = True
    reopen(p)
    assert (await p.driver.deliver(slot)).status == "retained"
    assert (
        await coordinator(d, offline=True).advance(slot, case)
    ).certificate == result.certificate
    for index, certificate in zip((0, 2), completed, strict=True):
        assert (
            await coordinator(d, offline=True).advance(p.retire_slot, p.e.job.cases[index].case_id)
        ).certificate == certificate
    assert before == p.transmissions and p.model.calls == 3


async def test_repeated_expired_replacements_archive_and_recover_independently(
    decisions, monkeypatch
):
    d, p = decisions, decisions.p
    grant = await child(d, monkeypatch)
    selections, certificates = [], []
    for number in (2, 3, 4):
        assert grant.attempt.order.attempt_number == number
        selected = await p.delivery_recovery.prepare_case(grant, p.transport_policy)
        slot, case = selection_slot(selected), grant.attempt.order.case_id
        assert (await p.driver.deliver(slot)).status == "retained"
        expire_child(p, grant, monkeypatch)
        assert (
            await request(p, TRANSLATE_PATH, grant.attempt.order.requests[0])
        ).status_code == 422
        result = await coordinator(d).advance(slot, case)
        assert result.certificate.decision.disposition == "retry_required"
        selections.append(selected)
        certificates.append(result.certificate)
        if number < 4:
            review = coordinator(d)._review(slot, case)
            grant = next_grant(d, grant, review, result.certificate, monkeypatch)
        reopen(p)
    assert p.model.calls == 0
    p.c.finality.fail = True
    for selected, certificate in zip(selections, certificates, strict=True):
        slot = selection_slot(selected)
        assert p.delivery_recovery.selection(slot)[0] == selected
        assert (await coordinator(d, offline=True).advance(slot, case)).certificate == certificate
    assert p.delivery_recovery.selection(p.retire_slot)[0] == p.delivery_selection


async def test_child_grant_lost_ack_does_not_select_another_window(decisions, monkeypatch):
    d, p = decisions, decisions.p
    grant = await child(d, monkeypatch)
    selected = await p.delivery_recovery.prepare_case(grant, p.transport_policy)
    slot = selection_slot(selected)
    original = p.delivery_recovery.transport

    class Lose(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            result = await original.handle_async_request(request)
            assert result.status_code == 200
            raise httpx.ReadTimeout("lost miner acknowledgement")

    p.delivery_recovery.transport = Lose()
    assert (await p.driver.deliver(slot)).status == "pending"
    body = grant.attempt.order
    changed = body.model_copy(
        update={
            "requests": (
                body.requests[0].model_copy(update={"issued_block_hash": "0x" + "ab" * 32}),
            )
        }
    )
    other = grant.model_copy(
        update={
            "attempt": grant.attempt.model_copy(
                update={"order": changed, "signatures": signatures(changed)}
            )
        }
    )
    with pytest.raises(ValueError, match="already retained"):
        await p.delivery_recovery.prepare_case(other, p.transport_policy)
    p.delivery_recovery.transport = original
    reopen(p)
    result = await p.driver.deliver(slot)
    assert result.status == "retained"
    assert result.receipt.receipt.grant_sha256 == digest(grant)
    assert p.model.calls == 0


@pytest.mark.parametrize("where", ["reservation", "before_commit", "after_commit"])
async def test_child_intent_queue_recovers_interrupted_preparation(decisions, monkeypatch, where):
    d, p = decisions, decisions.p
    grant = await child(d, monkeypatch)
    db = p.delivery_recovery.journal.journal
    put = db.put

    def fail_reservation(*a, **kw):
        raise OSError("interrupted reservation")

    def fail_commit(kind, key, value):
        if kind == "endpoint_recovery_selection":
            if where == "after_commit":
                put(kind, key, value)
            raise OSError("interrupted selection")
        return put(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(
            db,
            "reserve_records" if where == "reservation" else "put",
            fail_reservation if where == "reservation" else fail_commit,
        )
        with pytest.raises(OSError, match="interrupted"):
            await p.delivery_recovery.prepare_case(grant, p.transport_policy)
    slot, case = grant_slot(grant), grant.attempt.order.case_id
    before = db.get("endpoint_recovery_intent", slot)
    assert before is not None
    reopen(p)
    # Queue recovery must resume full intent, with no caller rebuilding a grant.
    await CohortEndpointRecoveryWorker(p.delivery_recovery).poll_once()
    selected = p.delivery_recovery.selection(slot)[0]
    assert canonical_json_bytes(selected) == canonical_json_bytes(before)
    assert (await p.driver.deliver(slot)).status == "retained"
    assert p.delivery_recovery.retained(slot, case) is None


async def test_missing_parent_is_pending_and_recovery_resumes_exact_archive(decisions, monkeypatch):
    d, p = decisions, decisions.p
    grant = await child(d, monkeypatch)
    selected = await p.delivery_recovery.prepare_case(grant, p.transport_policy)
    slot = selection_slot(selected)
    db = p.delivery_recovery.journal.journal
    get = db.get

    def missing(kind, key, **kw):
        if kind == "endpoint_recovery_selection" and key == p.retire_slot:
            return None
        return get(kind, key, **kw)

    before = len(p.transmissions)
    with monkeypatch.context() as m:
        m.setattr(db, "get", missing)
        with pytest.raises(FileNotFoundError, match="parent"):
            await p.driver.deliver(slot)
    assert len(p.transmissions) == before
    assert (await p.driver.deliver(slot)).status == "retained"
    assert p.delivery_recovery.selection(slot)[0] == selected
