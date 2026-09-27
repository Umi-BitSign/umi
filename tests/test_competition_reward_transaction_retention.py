"""Native codec/signatures and durable storage; projection is a substituted port.

No signing/submission permission or historical proof replay is established here.
"""

import asyncio
import hashlib
import json
import subprocess
import sys
import threading

import pytest

from umi.competition_reward_transactions import StandingWeightJournal, standing_weight_call
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.signed_extrinsic import encode_verified_mortal_call

from .test_competition_reward_transaction import transaction as transaction
from .test_signed_extrinsic_native import native_encoding as native_encoding


@pytest.fixture
def retained(transaction, tmp_path):
    t = transaction

    def reopen(**changes):
        options = dict(
            series_sha256=t.owner.series_sha256,
            validator_hotkey=t.chain.validator_hotkey,
            chain_config_sha256=t.chain.chain_config_sha256,
            maximum_bytes=8 * 1024**2,
        )
        options.update(changes)
        return StandingWeightJournal(tmp_path / "transactions", **options)

    t.reopen = reopen
    t.journal = reopen()
    return t


async def reserve(t):
    return await t.owner.reserve_transaction(t.prepared, t.journal, **t.options)


async def retain(t, encoded=None):
    return await t.owner.retain_signed_transaction(
        t.prepared, t.journal, t.encoded if encoded is None else encoded, **t.options
    )


async def test_original_context_and_signed_bytes_survive_restart(retained):
    t = retained
    unsigned = await reserve(t)
    assert unsigned.signed is None and unsigned.chain_submission_authorized is False
    assert unsigned.intent.destinations == (0, 1, 2)
    assert unsigned.intent.weights == (0, 20000, 45535)
    t.journal = t.reopen()
    assert t.journal.pending() == unsigned
    signed = await retain(t)
    assert bytes.fromhex(signed.signed.signed_extrinsic) == t.encoded
    t.journal = t.reopen(maximum_bytes=16 * 1024**2)
    assert t.journal.pending() == signed == await reserve(t) == await retain(t)
    assert signed.chain_submission_authorized is False
    for original in (
        t.chain.evidence,
        t.options["control"].evidence,
        t.chain.runtime.metadata_bytes,
    ):
        assert t.journal._object(hashlib.sha256(original).hexdigest()) == original


async def test_cold_process_recovers_exact_signed_attempt(retained):
    t = retained
    await reserve(t)
    pending = await retain(t)
    script = """
import json,sys
from pathlib import Path
from umi.competition_reward_transactions import StandingWeightJournal
from umi.open_competition import digest
args=json.loads(sys.stdin.read())
root=Path(args.pop('root'))
p=StandingWeightJournal(root,**args).pending()
print(json.dumps({'intent':digest(p.intent),'extrinsic':p.signed.extrinsic_hash,
                  'authorized':p.chain_submission_authorized}))
"""
    args = dict(
        root=str(t.journal.journal.root),
        series_sha256=t.owner.series_sha256,
        validator_hotkey=t.chain.validator_hotkey,
        chain_config_sha256=t.chain.chain_config_sha256,
        maximum_bytes=8 * 1024**2,
    )
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-B", "-c", script],
        input=json.dumps(args),
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert json.loads(result.stdout) == {
        "intent": digest(pending.intent),
        "extrinsic": pending.signed.extrinsic_hash,
        "authorized": False,
    }


async def test_signature_cannot_be_retained_without_original_intent(retained):
    t = retained
    with pytest.raises(ValueError, match="reserved original intent"):
        await retain(t)
    assert t.journal.pending() is None


@pytest.mark.parametrize("stage", ["intent", "signed"])
@pytest.mark.parametrize("ack_lost", [False, True])
async def test_failed_write_and_lost_ack_resume_same_attempt(
    retained, monkeypatch, stage, ack_lost
):
    t = retained
    if stage == "signed":
        await reserve(t)
    original = t.journal.journal.put_many

    def interrupted(*args, **kwargs):
        if ack_lost:
            original(*args, **kwargs)
        raise OSError("lost commit reply")

    monkeypatch.setattr(t.journal.journal, "put_many", interrupted)
    with pytest.raises(OSError):
        await (reserve(t) if stage == "intent" else retain(t))
    t.journal = t.reopen()
    old = t.journal.pending()
    if stage == "intent":
        assert (old is not None) == ack_lost
        recovered = await reserve(t)
    else:
        assert (old.signed is not None) == ack_lost
        recovered = await retain(t)
    if ack_lost:
        assert recovered == old
    assert t.journal.pending() == recovered


@pytest.mark.parametrize("change", ["nonce", "block", "selection", "row", "period"])
async def test_unresolved_attempt_cannot_be_replaced(retained, change):
    t = retained
    old = await reserve(t)
    await retain(t)
    t.journal = t.reopen()
    if change == "nonce":
        t.chain.validator_nonce += 1
    elif change == "block":
        t.chain.block += 1
    elif change == "selection":
        t.current.current.selection.decision_sha256 = "ba" * 32
    elif change == "row":
        t.current.projection = t.current.projection.model_copy(update={"weights": (20001, 45534)})
    else:
        t.options["mortality_period"] = 64
    with pytest.raises(ValueError, match="requires native reconciliation"):
        await reserve(t)
    assert t.journal.pending().intent == old.intent
    assert bytes.fromhex(t.journal.pending().signed.signed_extrinsic) == t.encoded


@pytest.mark.parametrize("change", ["series_sha256", "chain_config_sha256", "validator_hotkey"])
async def test_reopen_cannot_change_writer_or_authority(retained, change):
    t = retained
    await reserve(t)
    value = "bf" * 32 if change != "validator_hotkey" else "0x" + "00" * 32
    with pytest.raises(ValueError):
        t.reopen(**{change: value})


async def test_actual_signed_call_is_checked_before_retention(retained):
    t = retained
    await reserve(t)
    encoded = encode_verified_mortal_call(
        t.native.call, signer=t.native.signer, **{**t.native.context, "nonce": 5}
    )
    with pytest.raises(ValueError, match="signed transaction"):
        await retain(t, encoded)
    assert t.journal.pending().signed is None
    assert (await retain(t)).signed is not None


async def test_signed_intent_does_not_allow_alternate_signature(retained):
    t = retained
    await reserve(t)
    await retain(t)
    # Sr25519 permits another valid signature for the identical payload.
    second = encode_verified_mortal_call(t.native.call, signer=t.native.signer, **t.native.context)
    assert second != t.encoded
    with pytest.raises(ValueError, match="cannot replace retained bytes"):
        await retain(t, second)
    assert bytes.fromhex(t.journal.pending().signed.signed_extrinsic) == t.encoded


async def test_capacity_failure_is_retryable_before_signed_effect(retained):
    t = retained
    t.journal = t.reopen(maximum_bytes=1024)
    with pytest.raises(ValueError, match="capacity"):
        await reserve(t)
    assert t.journal.pending() is None
    t.journal = t.reopen()
    assert (await reserve(t)).signed is None


async def test_expired_proof_after_commit_preserves_unsigned_intent(retained, monkeypatch):
    t = retained
    original = t.journal.reserve

    def retain_then_expire(*args, **kwargs):
        result = original(*args, **kwargs)

        def expired(*args):
            raise ValueError("proof expired during durable commit")

        monkeypatch.setattr(t.owner, "_project", expired)
        return result

    monkeypatch.setattr(t.journal, "reserve", retain_then_expire)
    with pytest.raises(ValueError, match="proof expired"):
        await reserve(t)
    assert t.reopen().pending().signed is None
    assert not t.owner._lock.locked()


async def test_cancellation_drains_durable_signature_commit(retained, monkeypatch):
    t = retained
    await reserve(t)
    entered, release = threading.Event(), threading.Event()
    original = t.journal.retain_signed

    def slow(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(t.journal, "retain_signed", slow)
    task = asyncio.create_task(retain(t))
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    assert t.owner._lock.locked() and not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert t.reopen().pending().signed is not None
    assert not t.owner._lock.locked()


async def test_second_journal_owner_is_excluded(retained):
    t = retained
    other = t.reopen()
    with other.journal.locked(), pytest.raises((ValueError, BlockingIOError)):
        await reserve(t)
    assert (await reserve(t)).signed is None


@pytest.mark.parametrize(
    "corruption", ["missing_context", "changed_context", "changed_intent", "missing_intent"]
)
async def test_corrupt_or_missing_recovery_material_holds(retained, corruption):
    t = retained
    pending = await reserve(t)
    await retain(t)
    with t.journal.journal.transaction() as db:
        if corruption == "missing_context":
            db.execute(
                "DELETE FROM records WHERE kind='standing_weight_object' AND id=?",
                (pending.intent.metadata_sha256,),
            )
        elif corruption == "changed_context":
            db.execute(
                "UPDATE records SET body=? WHERE kind='standing_weight_object' AND id=?",
                (b'{"hex":"00"}', pending.intent.metadata_sha256),
            )
        elif corruption == "changed_intent":
            raw = t.journal.journal.get("standing_weight_intent", digest(pending.intent), db=db)
            raw["nonce"] += 1
            db.execute(
                "UPDATE records SET body=? WHERE kind='standing_weight_intent'",
                (canonical_json_bytes(raw),),
            )
        else:
            db.execute("DELETE FROM records WHERE kind='standing_weight_intent'")
    with pytest.raises(ValueError):
        t.reopen().pending()


@pytest.mark.parametrize(
    "field,value",
    [
        ("validator_permit", False),
        ("mechanism_count", 2),
        ("commit_reveal_enabled", True),
        ("weights_rate_limit", 24),
        ("max_allowed_uids", 2),
        ("registered_uid_count", 0),
        ("max_weights_limit", 40000),
    ],
)
async def test_chain_constraints_hold_before_intent_is_created(retained, field, value):
    t = retained
    setattr(t.chain, field, value)
    with pytest.raises(ValueError):
        await reserve(t)
    assert t.journal.pending() is None


def test_full_registered_domain_counts_zero_entries_and_rate_boundary(transaction):
    t = transaction
    t.chain.min_allowed_weights = 256
    t.chain.weights_rate_limit = 23
    call = standing_weight_call(t.current.projection, t.chain)
    assert call.params["dests"] == [0, 1, 2] and call.params["weights"] == [0, 20000, 45535]
