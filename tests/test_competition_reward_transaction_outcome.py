"""Standing restart/expiry and atomic successors with real signatures/storage.

The original fixture supplies synthetic finality and trie proofs bound to exact
bytes. Receipt-branch cases substitute only the already separately tested native
receipt reader. No installed writer or current reward authority is qualified.
"""

import asyncio
import hashlib
import json
import threading
from dataclasses import replace

import pytest

from umi.bootstrap_weight_operator import BootstrapExtrinsicReference
from umi.competition_reward_transaction_outcome import resolve_standing_transaction
from umi.competition_reward_transactions import StandingTransactionEnd, StandingWeightJournal
from umi.mortal_receipts import MortalReceiptReader, VerifiedMortalReceipt
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_historical_registration import change_block
from .test_competition_reward_transaction_recovery import chain_config as chain_config
from .test_competition_reward_transaction_recovery import native_encoding as native_encoding
from .test_competition_reward_transaction_recovery import original as original
from .test_competition_reward_transaction_recovery import policy as policy


def at(t, offset):
    header = change_block(t, t.old.height + offset)
    raw = canonical_json_bytes(
        {**json.loads(t.old.finality_evidence), "block": {"scale_header": header}}
    )
    t.blocks[t.finality.ref.block_number] = replace(
        t.old,
        height=t.finality.ref.block_number,
        block_hash=t.finality.ref.block_hash,
        state_root=t.finality.ref.state_root,
        timestamp_ms=t.finality.timestamp,
        finality_evidence=raw,
        finality_evidence_sha256=hashlib.sha256(raw).hexdigest(),
    )


def reopen(t):
    return StandingWeightJournal(
        t.journal.journal.root,
        series_sha256=t.intent.series_sha256,
        validator_hotkey=t.hotkey,
        chain_config_sha256=t.intent.chain_config_sha256,
        maximum_bytes=8 * 1024**2,
    )


def successor(t, end, **changes):
    # Reservation storage accepts data, not current proof authority. The native
    # preparation consumer is tested separately and must supply fresh evidence.
    intent = t.intent.model_copy(
        update={
            "block": end.snapshot.block_number,
            "block_hash": end.snapshot.block_hash,
            "nonce": t.intent.nonce + 1,
            **changes,
        }
    )
    return t.journal.reserve(
        intent,
        chain=t.chain.evidence,
        control=t.control.evidence,
        metadata=t.chain.runtime.metadata_bytes,
        previous=end,
    )


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("offset", [128, 3000])
async def test_expiry_keeps_unknown_outcome_and_allows_atomic_successor(original, signed, offset):
    t = original
    if not signed:
        t.journal = t.make_journal(
            t.intent, t.chain.evidence, t.control.evidence, signed=False, path="unsigned"
        )
    at(t, offset)
    before = t.journal.recovery_inputs()
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert end.reason == "expired_outcome_unknown"
    assert end.receipt_sha256 is None and end.chain_submission_authorized is False
    assert t.journal.recovery_inputs() == before
    assert not any(m in {"chain_getBlock", "state_getStorageAt"} for m, _ in t.calls)
    pending = successor(t, end, nonce=t.intent.nonce)
    assert pending.intent.block == t.intent.block + offset
    assert pending.signed is None
    t.journal = reopen(t)
    assert t.journal.pending() == pending == successor(t, end, nonce=t.intent.nonce)
    assert t.journal.journal.get("standing_weight_intent", digest(t.intent)) == t.intent.model_dump(
        mode="json", by_alias=True
    )
    assert t.journal._object(t.intent.chain_evidence_sha256) == before.chain
    if signed:
        assert t.journal.journal.get(
            "standing_weight_signed", digest(t.intent)
        ) == before.pending.signed.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValueError, match="reserved original intent"):
        t.journal.retain_signed(t.intent, t.encoded)


async def test_unsigned_live_attempt_cannot_be_replaced(original):
    t = original
    t.journal = t.make_journal(
        t.intent, t.chain.evidence, t.control.evidence, signed=False, path="unsigned"
    )
    at(t, 127)
    assert (
        await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey) is None
    )
    assert t.journal.pending().intent == t.intent


@pytest.mark.parametrize("successful", [None, False, True])
async def test_live_receipt_branch_and_consumed_nonce(original, monkeypatch, successful):
    t = original
    at(t, 127)
    seen = []

    async def find(reader, query):
        seen.append(query)
        if successful is None:
            return None
        return VerifiedMortalReceipt(
            BootstrapExtrinsicReference(
                extrinsic_id=f"{t.old.height + 3}-0001",
                block_number=t.old.height + 3,
                block_hash="0x" + "55" * 32,
                extrinsic_index=1,
            ),
            successful,
            query.signed_extrinsic_hash,
            t.finality.ref,
        )

    monkeypatch.setattr(MortalReceiptReader, "find", find)
    monkeypatch.setattr(t.provider, "_bridge_reader", lambda: object())
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert len(seen) == 1 and bytes.fromhex(seen[0].signed_extrinsic) == t.encoded
    if successful is None:
        assert end is None and t.journal.pending().intent == t.intent
        return
    assert end.reason == ("dispatch_succeeded" if successful else "dispatch_failed")
    assert end.receipt_sha256 and not end.chain_submission_authorized
    with pytest.raises(ValueError, match="native reconciliation"):
        successor(t, end, nonce=t.intent.nonce)
    assert successor(t, end).signed is None


@pytest.mark.parametrize("fault", ["missing", "wrong_root", "wrong_config"])
async def test_expiry_requires_owned_finality(original, fault):
    t = original
    head = t.finality.ref.block_number
    if fault == "missing":
        t.blocks.pop(head)
    elif fault == "wrong_root":
        t.blocks[head] = replace(t.blocks[head], state_root="0x" + "cc" * 32)
    else:
        t.blocks[head] = replace(t.blocks[head], finality_verifier_sha256="cc" * 32)
    with pytest.raises(ValueError):
        await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert t.journal.pending().intent == t.intent


@pytest.mark.parametrize(
    "fault", ["copy", "snapshot", "reason", "signed", "intent", "earlier", "other_hash"]
)
async def test_copied_or_rebound_result_cannot_replace_attempt(original, fault):
    t = original
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    changes = {}
    if fault == "copy":
        end = StandingTransactionEnd(end.pending, end.snapshot, end.reason)
    elif fault == "snapshot":
        end = replace(
            end, snapshot=replace(end.snapshot, block_number=end.snapshot.block_number - 1)
        )
    elif fault == "reason":
        end = replace(end, reason="dispatch_succeeded")
    elif fault == "signed":
        end = replace(end, pending=replace(end.pending, signed=None))
    elif fault == "intent":
        end = replace(
            end, pending=replace(end.pending, intent=t.intent.model_copy(update={"nonce": 5}))
        )
    elif fault == "earlier":
        changes["block"] = end.snapshot.block_number - 1
    else:
        changes["block_hash"] = "0x" + "ff" * 32
    with pytest.raises(ValueError, match="native reconciliation"):
        successor(t, end, **changes)
    assert t.journal.pending().intent == t.intent


@pytest.mark.parametrize("ack_lost", [False, True])
async def test_interrupted_successor_commit_recovers_without_deleting_old_attempt(
    original, monkeypatch, ack_lost
):
    t = original
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    put = t.journal.journal.put_many

    def interrupted(*args, **kwargs):
        if ack_lost:
            put(*args, **kwargs)
        raise OSError("lost successor commit reply")

    monkeypatch.setattr(t.journal.journal, "put_many", interrupted)
    with pytest.raises(OSError):
        successor(t, end)
    t.journal = reopen(t)
    assert (t.journal.pending().intent != t.intent) is ack_lost
    assert successor(t, end) == t.journal.pending()
    assert len(t.journal.journal.keys("standing_weight_intent")) == 2
    assert len(t.journal.journal.keys("standing_weight_successor")) == 1


async def test_late_signature_invalidates_earlier_unsigned_resolution(original):
    t = original
    t.journal = t.make_journal(
        t.intent, t.chain.evidence, t.control.evidence, signed=False, path="unsigned"
    )
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    t.journal.retain_signed(t.intent, t.encoded)
    with pytest.raises(ValueError, match="native reconciliation"):
        successor(t, end)
    checked = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert successor(t, checked).signed is None


async def test_cancelled_successor_write_drains_and_recovers(original, monkeypatch):
    from umi.concurrency import run_owned_thread

    t = original
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    put = t.journal.journal.put_many
    entered, release = threading.Event(), threading.Event()

    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        put(*args, **kwargs)

    monkeypatch.setattr(t.journal.journal, "put_many", slow)
    task = asyncio.create_task(run_owned_thread(successor, t, end))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    t.journal = reopen(t)
    assert t.journal.pending().intent.block == end.snapshot.block_number
    assert successor(t, end) == t.journal.pending()


async def test_reservation_failure_rolls_back_successor_and_allows_new_preflight(
    original, monkeypatch
):
    t = original
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    reserve = t.journal.journal.reserve_records
    before = t.journal.recovery_inputs()

    def interrupted(*args, **kwargs):
        assert kwargs["db"].in_transaction
        reserve(*args, **kwargs)
        raise OSError("interrupted before combined commit")

    monkeypatch.setattr(t.journal.journal, "reserve_records", interrupted)
    with pytest.raises(OSError):
        successor(t, end)
    t.journal = reopen(t)
    assert t.journal.recovery_inputs() == before
    assert t.journal.journal.keys("standing_weight_successor") == []
    # Another current preflight is allowed: the failed reservation did not pin
    # the predecessor to an intent whose original inputs were never committed.
    assert successor(t, end, block=end.snapshot.block_number + 1).signed is None


async def test_concurrent_signature_during_resolution_requires_another_review(
    original, monkeypatch
):
    t = original
    t.journal = t.make_journal(
        t.intent, t.chain.evidence, t.control.evidence, signed=False, path="unsigned"
    )
    snapshot = t.provider._proofs.finalized_snapshot
    calls = 0

    async def changed():
        nonlocal calls
        ref = await snapshot()
        calls += 1
        if calls == 2:
            t.journal.retain_signed(t.intent, t.encoded)
        return ref

    monkeypatch.setattr(t.provider._proofs, "finalized_snapshot", changed)
    with pytest.raises(ValueError, match="attempt changed"):
        await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert t.journal.pending().signed is not None
    assert t.journal.journal.keys("standing_weight_successor") == []


async def test_an_old_resolution_cannot_fork_the_current_attempt(original):
    t = original
    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    child = successor(t, end)
    with pytest.raises(ValueError, match="native reconciliation"):
        successor(t, end, block=child.intent.block + 1)
    assert t.journal.pending() == child
    assert len(t.journal.journal.keys("standing_weight_intent")) == 2


@pytest.mark.parametrize("fault", ["orphan", "wrong_child", "self", "signature"])
async def test_invalid_stored_lineage_is_rejected(original, fault):
    from umi.competition_reward_transactions import StandingWeightSuccessor

    t = original
    parent = digest(t.intent)
    link = StandingWeightSuccessor(
        schema="umi-standing-weight-successor/1",
        prior_intent_sha256=parent,
        next_intent_sha256=parent if fault == "self" else "bb" * 32,
        prior_signed_extrinsic_hash="0x" + "bb" * 32,
    )
    if fault == "signature":
        end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
        child = successor(t, end)
        # An imported descendant with no signed bytes cannot claim a signature.
        parent = digest(child.intent)
        grandchild = child.intent.model_copy(update={"block": child.intent.block + 1})
        t.journal.journal.put("standing_weight_intent", digest(grandchild), grandchild)
        link = link.model_copy(
            update={"prior_intent_sha256": parent, "next_intent_sha256": digest(grandchild)}
        )
    t.journal.journal.put(
        "standing_weight_successor", "aa" * 32 if fault == "orphan" else parent, link
    )
    with pytest.raises(ValueError, match=r"lineage|signature"):
        reopen(t).pending()
