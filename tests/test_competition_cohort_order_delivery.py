"""Actual order signers, coordinator outbox and evaluator inboxes across restart.

Only chain captures, history retrieval and transport are synthetic. No test
claims to authorize live inference or prove an installed production service.
"""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_cohort_order_inbox import CohortOrderInbox, CohortOrderInboxConfig
from umi.competition_cohort_order_queue import (
    CohortOrderQueue,
    CohortOrderQueueConfig,
    check_delivery_receipt,
)
from umi.competition_cohort_order_signer import CohortOrderParticipant, order_slot
from umi.competition_cohort_order_worker import CohortOrderWorker
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_disposition import order as signed_order
from .test_competition_cohort_order_signer import base_policy as base_policy
from .test_competition_cohort_order_signer import harness as harness
from .test_competition_cohort_order_signer import legacy_scenario as legacy_scenario
from .test_competition_cohort_order_signer import policy as policy
from .test_competition_cohort_order_signer import receipt_scenario as receipt_scenario
from .test_competition_cohort_order_signer import recovery as recovery
from .test_competition_cohort_order_signer import runtime as runtime
from .test_competition_cohort_order_signer import scenario as scenario
from .test_competition_cohort_order_signer import source_for
from .test_open_competition import wallet


@pytest.fixture
async def relay(harness, tmp_path):
    h = harness
    signer = h.worker()
    keys = tuple(sorted((wallet(n).hotkey.ss58_address for n in ("Charlie", "Dave")), key=identity))
    cfg = CohortOrderQueueConfig(
        schema="umi-cohort-order-queue-config/1",
        directory=str(tmp_path / "outbox"),
        policy_sha256=digest(h.batch["policy"]),
        cohorts=signer.journal.config.cohorts,
        reviewers=keys,
    )
    r = SimpleNamespace(
        h=h,
        cfg=cfg,
        blocked_reviewers=set(),
        blocked_recipients=set(),
        lost_vote_ack=False,
        lost_delivery_ack=False,
        fail_receipt=False,
        receipt_calls=[],
        delivery_calls=[],
    )
    r.names = {identity(wallet(n).hotkey.ss58_address): n for n in ("Charlie", "Dave")}

    def queue(**overrides):
        return CohortOrderQueue(cfg.model_copy(update=overrides), h.batch["policy"])

    def inbox(who):
        name = r.names[identity(who)]
        config = CohortOrderInboxConfig.model_validate(
            {
                **h.worker(name).journal.config.model_dump(by_alias=True),
                "schema": "umi-cohort-order-inbox-config/1",
                "directory": str(tmp_path / ("inbox-" + name)),
            }
        )
        box = None

        async def sign(body):
            assert box.journal.get("intent", body.slot) is not None
            assert box.journal.get("certificate", body.slot) is not None
            r.receipt_calls.append((name, canonical_json_bytes(body)))
            if r.fail_receipt:
                raise OSError("receipt signer unavailable")
            return sign_object(body, wallet(name))

        box = CohortOrderInbox(config, h.batch["policy"], signer.provider, signer.history, sign)
        return box

    async def lookup_vote(who, slot):
        if identity(who) in r.blocked_reviewers:
            raise OSError("reviewer unavailable")
        return await h.worker(r.names[identity(who)]).lookup(slot)

    async def attest(who, order, participant):
        if identity(who) in r.blocked_reviewers:
            raise OSError("reviewer unavailable")
        assert queue().intent(order_slot(order)).order == order
        vote = await h.worker(r.names[identity(who)]).attest(order, participant)
        if r.lost_vote_ack:
            raise OSError("vote acknowledgement lost")
        return vote

    async def lookup(who, slot):
        if identity(who) in r.blocked_recipients:
            raise OSError("evaluator unavailable")
        return await inbox(who).lookup(slot)

    async def accept(who, certificate, participant):
        if identity(who) in r.blocked_recipients:
            raise OSError("evaluator unavailable")
        assert queue().certificate(order_slot(certificate.order)) == certificate
        r.delivery_calls.append((identity(who), canonical_json_bytes(certificate)))
        receipt = await inbox(who).accept(certificate, participant)
        if r.lost_delivery_ack:
            raise OSError("delivery acknowledgement lost")
        return receipt

    r.reviewers = SimpleNamespace(lookup=lookup_vote, attest=attest)
    r.delivery = SimpleNamespace(lookup=lookup, accept=accept)
    r.queue, r.inbox = queue, inbox
    r.worker = lambda **kw: CohortOrderWorker(
        queue(), signer.provider, signer.history, r.reviewers, r.delivery, **kw
    )
    r.capture = signer.provider.collect
    r.slot = queue().select(h.order, h.participant, h.source, await r.capture())
    r.cohort = h.order.round.cohort_sha256
    return r


async def test_native_queue_to_each_native_inbox_and_quiet_restart(relay):
    r = relay
    result = await r.worker().poll_once()
    assert result["votes_retained"] == 2 and result["deliveries_acknowledged"] == 2
    assert result["retry_count"] == 0 and result["chain_submission_authorized"] is False
    certificate = r.queue().certificate(r.slot)
    for who in r.h.order.evaluators:
        receipt = await r.inbox(who).lookup(r.slot)
        assert check_delivery_receipt(certificate, receipt) == receipt
    assert not r.queue().pending(r.cohort)
    r.h.fail_collect = True
    assert (await r.worker().poll_once())["retry_count"] == 0
    assert len(r.h.calls) == 2 and len(r.receipt_calls) == 2 and len(r.delivery_calls) == 2


async def test_partial_quorum_survives_repeated_ten_hour_outages_without_new_selection(relay):
    r = relay
    r.blocked_reviewers.add(identity(wallet("Dave").hotkey.ss58_address))
    original = r.queue().intent(r.slot)
    for block in (400, 3400, 6400, 10**6):
        r.h.block = block
        assert (await r.worker().poll_once())["retry_count"] > 0
        assert r.queue().intent(r.slot) == original
        assert r.queue().certificate(r.slot) is None
    assert len(r.h.calls) == 1
    r.blocked_reviewers.clear()
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2
    assert len(r.h.calls) == 2


async def test_lost_vote_ack_uses_retained_votes_after_closure_without_signing_again(relay):
    r = relay
    r.lost_vote_ack = True
    assert (await r.worker().poll_once())["retry_count"] == 2
    assert len(r.h.calls) == 2 and r.queue().certificate(r.slot) is None
    r.h.source = source_for(r.h.batch, r.h.batch["history"])
    r.h.block = 5000
    r.h.fail_collect = True
    result = await r.worker().poll_once()
    assert result["votes_retained"] == 2 and result["deliveries_acknowledged"] == 0
    assert len(r.h.calls) == 2 and r.queue().certificate(r.slot) is not None
    assert not r.delivery_calls and r.queue().pending(r.cohort) == (r.slot,)


@pytest.mark.parametrize("interrupt", ["reply", "receipt_signing"])
async def test_retained_deliveries_recover_after_closure_with_no_provider(relay, interrupt):
    r = relay
    r.lost_delivery_ack = interrupt == "reply"
    r.fail_receipt = interrupt == "receipt_signing"
    result = await r.worker().poll_once()
    assert result["deliveries_acknowledged"] == 0 and result["retry_count"] == 2
    calls = tuple(r.delivery_calls)
    r.h.source = source_for(r.h.batch, r.h.batch["history"])
    r.h.fail_collect = True
    r.fail_receipt = False
    result = await r.worker().poll_once()
    assert result["deliveries_acknowledged"] == 2 and result["retry_count"] == 0
    assert tuple(r.delivery_calls) == calls and not r.queue().pending(r.cohort)
    assert len(r.h.calls) == 2


async def test_new_delivery_cannot_use_closed_history_or_roll_it_back(relay):
    r = relay
    r.blocked_recipients.update(r.names)
    await r.worker().poll_once()
    original = r.h.source
    r.h.source = source_for(r.h.batch, r.h.batch["history"])
    r.h.block = 5000
    r.blocked_recipients.clear()
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 0
    certificate = r.queue().certificate(r.slot)
    box = r.inbox(r.h.order.evaluators[0])
    with pytest.raises(ValueError, match="open request"):
        await box.accept(certificate, r.h.participant)
    r.h.source = original
    with pytest.raises(ValueError, match="rolled back"):
        await box.accept(certificate, r.h.participant)
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 0
    assert not r.delivery_calls


async def test_slow_recipient_does_not_erase_or_repeat_successful_delivery(relay):
    r = relay
    blocked = r.h.order.evaluators[0]
    r.blocked_recipients.add(identity(blocked))
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 1
    r.h.block = 100000
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 0
    r.blocked_recipients.clear()
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 1
    assert len(r.delivery_calls) == 2 and len(r.h.calls) == 2


@pytest.mark.parametrize("damage", ["selection", "participant"])
async def test_coordinator_restart_cannot_replace_original_inputs(relay, damage):
    r = relay
    order, participant = r.h.order, r.h.participant
    if damage == "selection":
        order = order.model_copy(update={"evaluators": tuple(reversed(order.evaluators))})
    else:
        participant = participant.model_copy(
            update={
                "admission_snapshot": participant.admission_snapshot.model_copy(
                    update={"block": 211}
                )
            }
        )
    with pytest.raises(ValueError, match="reserved"):
        r.queue().select(order, participant, r.h.source, await r.capture())
    assert r.queue().intent(r.slot).order == r.h.order
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2


async def test_durable_scan_prevents_stalled_first_entry_starving_later_after_restart(relay):
    r = relay
    b = r.h.batch
    second = signed_order(b["scenarios"][1]).order
    p = b["roster"].participants[1]
    participant = CohortOrderParticipant(
        consent=p.record.request.consent,
        admission=p.admission,
        admission_snapshot=p.record.snapshot,
    )
    second_slot = r.queue().select(second, participant, r.h.source, await r.capture())
    slots = sorted((r.slot, second_slot))
    native = r.reviewers.lookup

    async def unavailable_first(who, slot):
        if slot == slots[0]:
            raise OSError("first participant temporarily unavailable")
        return await native(who, slot)

    r.reviewers.lookup = unavailable_first
    assert (await r.worker(batch_size=1).poll_once())["retry_count"] == 2
    assert (await r.worker(batch_size=1).poll_once())["deliveries_acknowledged"] == 2
    assert r.queue().pending(r.cohort) == (slots[0],)
    r.reviewers.lookup = native
    assert (await r.worker(batch_size=1).poll_once())["deliveries_acknowledged"] == 2
    assert not r.queue().pending(r.cohort)


async def test_capacity_can_increase_without_replacing_selection_or_completed_votes(relay):
    r = relay
    r.blocked_reviewers.add(identity(wallet("Dave").hotkey.ss58_address))
    await r.worker().poll_once()
    retained = r.queue().intent(r.slot)
    cfg = r.cfg.model_copy(update={"maximum_bytes": 1024})
    small = CohortOrderQueue(cfg, r.h.batch["policy"])
    capture = await r.capture()
    with pytest.raises(ValueError, match="capacity"):
        small.check_current(r.slot, r.h.source, capture)
    r.cfg = r.cfg.model_copy(update={"maximum_bytes": 2 * 1024**3})
    # Existing queue factory pins semantic config, independent of enlarged limits.
    larger = r.queue(maximum_bytes=2 * 1024**3)
    assert larger.intent(r.slot) == retained
    r.blocked_reviewers.clear()
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2
    assert len(r.h.calls) == 2


async def test_queue_mutex_contention_is_retryable_and_has_no_remote_effect(relay):
    r = relay
    with r.queue().journal.locked():
        result = await r.worker().poll_once()
    assert result["retry_count"] == 1 and not r.h.calls and not r.delivery_calls
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2


@pytest.mark.parametrize("stage", ["vote", "delivery"])
async def test_queue_commit_ack_loss_recovers_same_immutable_records(relay, monkeypatch, stage):
    r = relay
    q = r.queue()
    original = q.journal.put_many
    lost = False

    def dropping(records, **kw):
        nonlocal lost
        records = tuple(records)
        original(records, **kw)
        kind = "queue_vote" if stage == "vote" else "delivery"
        if not lost and any(k == kind for k, _, _ in records):
            lost = True
            raise OSError("commit acknowledgement lost")

    monkeypatch.setattr(q.journal, "put_many", dropping)
    worker = r.worker()
    worker.queue = q
    await worker.poll_once()
    assert lost
    await r.worker().poll_once()
    assert not r.queue().pending(r.cohort)
    assert len(r.h.calls) == len(r.delivery_calls) == len(r.receipt_calls) == 2


async def test_inbox_partial_storage_failure_does_not_acknowledge(relay, monkeypatch):
    r = relay
    r.blocked_recipients.update(r.names)
    await r.worker().poll_once()
    certificate = r.queue().certificate(r.slot)
    box = r.inbox(r.h.order.evaluators[0])
    original = box.journal.put_many

    def unavailable(records, **kw):
        records = tuple(records)
        if any(k == "intent" for k, _, _ in records):
            raise OSError("disk unavailable")
        return original(records, **kw)

    monkeypatch.setattr(box.journal, "put_many", unavailable)
    with pytest.raises(OSError, match="disk"):
        await box.accept(certificate, r.h.participant)
    assert box.journal.get("intent", r.slot) is None
    assert box.journal.get("certificate", r.slot) is None and not r.receipt_calls
    monkeypatch.setattr(box.journal, "put_many", original)
    receipt = await box.accept(certificate, r.h.participant)
    assert check_delivery_receipt(certificate, receipt) == receipt


@pytest.mark.parametrize("damage", ["certificate", "signature", "recipient"])
async def test_forged_delivery_never_removes_pending_work(relay, damage):
    r = relay
    r.lost_delivery_ack = True
    await r.worker().poll_once()
    who = r.h.order.evaluators[0]
    receipt = await r.inbox(who).lookup(r.slot)
    if damage == "certificate":
        body = receipt.receipt.model_copy(update={"certificate_sha256": "ff" * 32})
        bad = receipt.model_copy(
            update={"receipt": body, "signature": sign_object(body, wallet(r.names[identity(who)]))}
        )
    elif damage == "signature":
        bad = receipt.model_copy(
            update={"signature": sign_object(receipt.receipt, wallet("Alice"))}
        )
    else:
        body = receipt.receipt.model_copy(
            update={"evaluator_hotkey": wallet("Alice").hotkey.ss58_address}
        )
        bad = receipt.model_copy(
            update={"receipt": body, "signature": sign_object(body, wallet("Alice"))}
        )
    with pytest.raises(ValueError):
        r.queue().acknowledge(r.slot, bad)
    assert r.queue().pending(r.cohort) == (r.slot,)
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2


async def test_receiving_host_rechecks_history_even_if_publisher_saw_open_requests(relay):
    r = relay
    r.blocked_recipients.update(r.names)
    await r.worker().poll_once()
    original = r.h.source
    certificate = r.queue().certificate(r.slot)
    box = r.inbox(r.h.order.evaluators[0])
    calls = 0

    async def changing(cohort):
        nonlocal calls
        calls += 1
        if calls == 2:
            r.h.block = 5000
            return source_for(r.h.batch, r.h.batch["history"])
        return original

    box.history = changing
    with pytest.raises(OSError, match="history changed"):
        await box.accept(certificate, r.h.participant)
    assert box.journal.get("intent", r.slot) is None and not r.receipt_calls
    with pytest.raises(ValueError, match="rolled back"):
        await r.inbox(r.h.order.evaluators[0]).accept(certificate, r.h.participant)


async def test_cancelled_service_leaves_recoverable_work_and_drains_owned_signer(relay):
    r = relay
    entered = asyncio.Event()
    original = r.reviewers.attest

    async def delayed(who, order, participant):
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return await original(who, order, participant)

    r.reviewers.attest = delayed
    stop = asyncio.Event()
    task = asyncio.create_task(r.worker().run(stop, poll_seconds=0.01))
    await asyncio.wait_for(entered.wait(), timeout=10)
    stop.set()
    await asyncio.wait_for(task, timeout=20)
    assert r.queue().pending(r.cohort) == (r.slot,)
    r.reviewers.attest = original
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2
    assert len(r.h.calls) == 2


async def test_operation_timeout_rotates_to_other_reviewers_without_discarding_work(relay):
    r = relay
    original = r.reviewers.lookup
    slow = identity(r.cfg.reviewers[0])

    async def delayed(who, slot):
        if identity(who) == slow:
            await asyncio.Event().wait()
        return await original(who, slot)

    r.reviewers.lookup = delayed
    result = await r.worker(operation_timeout_seconds=1).poll_once()
    assert result["retry_count"] == 1 and result["votes_retained"] == 1
    assert r.queue().pending(r.cohort) == (r.slot,)
    r.reviewers.lookup = original
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2
    assert len(r.h.calls) == 2


async def test_retry_report_is_bounded_and_does_not_echo_transport_credentials(relay):
    r = relay

    async def failed(who, slot):
        raise OSError("https://private.invalid/v1/clips/secret-capability")

    r.reviewers.lookup = failed
    result = await r.worker().poll_once()
    assert result["last_retry_stage"] == "vote"
    assert result["last_retry_slot"] == r.slot and result["last_retry_type"] == "OSError"
    assert "secret-capability" not in str(result) and len(canonical_json_bytes(result)) < 512
    assert r.queue().pending(r.cohort) == (r.slot,)


async def test_inbox_rejects_an_alternate_certificate_for_the_same_selection(relay):
    r = relay
    await r.worker().poll_once()
    certificate = r.queue().certificate(r.slot)
    altered = certificate.model_copy(update={"signatures": tuple(reversed(certificate.signatures))})
    with pytest.raises(ValueError, match="reserved"):
        await r.inbox(r.h.order.evaluators[0]).accept(altered, r.h.participant)
    assert len(r.receipt_calls) == 2


async def test_vote_with_changed_order_digest_remains_pending(relay):
    r = relay
    vote = await r.h.worker().attest(r.h.order, r.h.participant)
    with pytest.raises(ValueError, match="differs"):
        r.queue().publish_vote(r.slot, vote.model_copy(update={"order_sha256": "ff" * 32}))
    assert r.queue().certificate(r.slot) is None
    assert len(r.queue().missing_reviewers(r.slot)) == 2
    assert (await r.worker().poll_once())["deliveries_acknowledged"] == 2
    assert len(r.h.calls) == 2
