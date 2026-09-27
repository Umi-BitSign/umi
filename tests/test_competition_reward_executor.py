"""Recurring execution with real journal, locks, codec and signatures.

Current chain/control proofs, completed package replay, migration qualification
and outcome proofs are explicit substituted ports. Their native verification
has separate tests. These tests do not qualify an installed/live validator.
"""

import asyncio
import copy
import os
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_executor as execution
from umi.competition_reward_decisions import RewardActivation
from umi.competition_reward_executor import StandingRewardExecutor
from umi.competition_reward_transactions import _issue_standing_end
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError
from umi.signed_extrinsic import verify_mortal_call

from .test_competition_reward_transaction import transaction as transaction
from .test_competition_reward_transaction_retention import retained as retained
from .test_signed_extrinsic_native import native_encoding as native_encoding


@pytest.fixture
def executing(retained, monkeypatch):
    t = retained
    e = object.__new__(StandingRewardExecutor)
    e.preparation, e.journal = t.owner, t.journal
    e.first = t.current.prepared
    t.prepared = e.first
    e.handoff = SimpleNamespace(through_block=120)
    e.hotkey = t.chain.validator_hotkey
    e.period, e.maximum_history_blocks, e.timeout = 128, 64, 0.2
    e._prepared = {digest(e.first.activation): e.first}
    e._lock, e._descriptor = asyncio.Lock(), None
    e._writer_path = t.journal.journal.root / "standing-writer.lock"
    e.decisions = t.options["source"]
    t.signed, t.sent, t.captures, t.recoveries = [], [], [], []
    t.end, t.fenced, t.mutate = None, True, lambda _: None
    t.owner._authority = lambda: None
    t.owner._check_prepared = lambda _: None

    def fence(*args, **kwargs):
        if not t.fenced:
            raise ValueError("original writer ownership ended")

    monkeypatch.setattr(execution, "validate_legacy_handoff", fence)

    async def control(_):
        return SimpleNamespace(
            evidence=t.options["control"].evidence,
            snapshot=t.chain.runtime.snapshot,
        )

    async def weights(hotkey, *, at):
        assert hotkey == e.hotkey and at == t.chain.runtime.snapshot
        chain = copy.copy(t.chain)
        t.captures.append(chain)
        if len(t.captures) % 2 == 0:
            t.mutate(chain)
        return chain

    async def prefix(_):
        return t.options["history"]

    async def outcome(*args, **kwargs):
        t.recoveries.append(t.journal.pending())
        return t.end

    monkeypatch.setattr(execution, "resolve_standing_transaction", outcome)
    e.provider = SimpleNamespace(
        config=t.options["chain_config"],
        collect_control=control,
        collect_registered_weights=weights,
    )
    e.history = SimpleNamespace(hotkey=e.hotkey, verified_prefix=prefix)
    t.current.selection = SimpleNamespace(state="selected", activation=e.first.activation)
    t.owner._selected = lambda *args: t.current

    def sign(payload):
        pending = t.journal.pending()
        assert pending is not None and pending.signed is None
        t.signed.append(payload)
        return t.native.signer.sign(payload)

    e.signer = SimpleNamespace(
        ss58_address=e.hotkey, crypto_type=t.native.signer.crypto_type, sign=sign
    )

    async def submit(encoded, signer):
        assert signer is e.signer
        pending = t.journal.pending()
        assert bytes.fromhex(pending.signed.signed_extrinsic) == encoded
        verify_mortal_call(encoded, pending.intent.call(), **t.native.context)
        t.sent.append(encoded)

    e.transport = SimpleNamespace(submit=submit)
    t.executor = e
    return t


async def test_send_once_then_recover_even_after_restart(executing):
    t, e = executing, executing.executor
    with e.hold_writer():
        result = await e.step()
        assert result.status == "submitted_unconfirmed"
        pending = t.journal.pending()
        assert result.extrinsic_hash == pending.signed.extrinsic_hash
        assert (await e.step()).status == "transaction_pending"
    e.journal = t.journal = t.reopen()
    with e.hold_writer():
        assert (await e.step()).status == "transaction_pending"
    assert len(t.signed) == len(t.sent) == 1
    assert t.recoveries == [pending, pending]
    assert t.journal.pending() == pending


@pytest.mark.parametrize("when", ["before_send", "after_send"])
async def test_lost_submission_reply_never_replays_bytes(executing, when):
    t, e = executing, executing.executor
    submit = e.transport.submit

    async def lose_reply(*args):
        if when == "after_send":
            await submit(*args)
        raise ConnectionError("sensitive RPC credential")

    e.transport.submit = lose_reply
    with e.hold_writer(), pytest.raises(ConnectionError):
        await e.step()
    e.journal = t.journal = t.reopen()
    with e.hold_writer():
        assert (await e.step()).status == "transaction_pending"
    assert len(t.signed) == 1 and len(t.sent) == (when == "after_send")


@pytest.mark.parametrize("write", ["reservation", "signature"])
async def test_lost_storage_ack_preserves_one_attempt(executing, monkeypatch, write):
    t, e = executing, executing.executor
    name = "reserve" if write == "reservation" else "retain_signed"
    save = getattr(e.journal, name)

    def lost(*args, **kwargs):
        save(*args, **kwargs)
        raise OSError("lost commit acknowledgement")

    monkeypatch.setattr(e.journal, name, lost)
    with e.hold_writer(), pytest.raises(OSError):
        await e.step()
    e.journal = t.journal = t.reopen()
    with e.hold_writer():
        assert (await e.step()).status == "transaction_pending"
    assert len(t.signed) == (write == "signature") and not t.sent


@pytest.mark.parametrize(
    "change",
    ["nonce", "last_update", "version", "row", "registration", "expiry", "runtime", "permit"],
)
async def test_changed_current_chain_keeps_signed_bytes_without_send(executing, change):
    t, e = executing, executing.executor

    def mutate(c):
        if change == "nonce":
            c.validator_nonce += 1
        elif change == "last_update":
            c.validator_last_update += 1
        elif change == "version":
            c.weights_version_key += 1
        elif change == "row":
            t.current.projection = t.current.projection.model_copy(
                update={"weights": (30000, 35535)}
            )
        elif change == "registration":
            c.registered_uid_count += 1
        elif change == "expiry":
            c.block += e.period
        elif change == "runtime":
            c.runtime = replace(c.runtime, runtime_version_bytes=b'{"specVersion":99999}')
        else:
            c.validator_permit = False

    t.mutate = mutate
    with e.hold_writer():
        with pytest.raises(ValueError):
            await e.step()
        assert (await e.step()).status == "transaction_pending"
    assert t.journal.pending().signed is not None and not t.sent
    assert len(t.signed) == 1


async def test_newer_root_may_submit_same_original_bytes(executing):
    t, e = executing, executing.executor
    t.mutate = lambda c: setattr(c, "block", c.block + 1)
    with e.hold_writer():
        assert (await e.step()).status == "submitted_unconfirmed"
    assert len(t.signed) == len(t.sent) == 1
    assert t.journal.pending().intent.block == 123


async def test_durable_signed_attempt_survives_handoff_loss(executing):
    t, e = executing, executing.executor
    t.mutate = lambda _: setattr(t, "fenced", False)
    with e.hold_writer(), pytest.raises(ValueError, match="ownership ended"):
        await e.step()
    assert t.journal.pending().signed is not None and not t.sent


async def test_expiry_after_long_outage_reserves_successor_and_preserves_old(executing):
    t, e = executing, executing.executor
    with e.hold_writer():
        await e.step()
    old = t.journal.pending()
    t.chain.block += 10000
    t.chain.runtime = replace(
        t.chain.runtime, snapshot=replace(t.chain.runtime.snapshot, block_number=t.chain.block)
    )
    t.native.context["runtime"] = t.chain.runtime
    t.end = _issue_standing_end(old, t.chain.runtime.snapshot, "expired_outcome_unknown")
    e.journal = t.journal = t.reopen()
    with e.hold_writer():
        assert (await e.step()).status == "submitted_unconfirmed"
    assert len(t.signed) == len(t.sent) == 2
    assert t.journal.pending().intent.nonce == old.intent.nonce
    assert t.journal.pending().intent.block == 10123
    assert t.journal.journal.get("standing_weight_signed", digest(old.intent)) is not None


async def test_drain_does_not_sign_and_later_selection_resumes(executing):
    t, e = executing, executing.executor
    t.current.selection.state = "draining"
    with e.hold_writer():
        assert (await e.step()).status == "selection_pending"
        assert t.journal.pending() is None and not t.signed
        t.current.selection.state = "selected"
        assert (await e.step()).status == "submitted_unconfirmed"


async def test_writes_require_lock_and_cannot_compete(executing):
    t, e = executing, executing.executor
    with pytest.raises(ValueError, match="does not own"):
        await e.step()
    other = copy.copy(e)
    with e.hold_writer():
        with pytest.raises(PrivateStateBusyError), other.hold_writer():
            pass
        os.rename(e._writer_path, e._writer_path.with_suffix(".preserved"))
        e._writer_path.touch(mode=0o600)
        with pytest.raises(ValueError, match="lock changed"):
            await e.step()
    assert not t.signed


async def test_slow_signing_cancellation_drains_before_releasing_writer(executing):
    t, e = executing, executing.executor
    entered, finish = threading.Event(), threading.Event()
    sign = e.signer.sign

    def slow(payload):
        entered.set()
        assert finish.wait(5)
        return sign(payload)

    e.signer.sign = slow

    async def run():
        with e.hold_writer():
            await e.step()

    task = asyncio.create_task(run())
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0.01)
    assert not task.done() and e._descriptor is not None
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert e._descriptor is None and not t.sent
    assert t.journal.pending().signed is None
    with e.hold_writer():
        assert (await e.step()).status == "transaction_pending"


@pytest.mark.parametrize("cancel", [False, True], ids=["timeout", "cancellation"])
async def test_network_cleanup_finishes_before_writer_is_released(executing, cancel):
    e = executing.executor
    entered, cleanup, cleaned = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def hang(*args):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleanup.set()
            await asyncio.sleep(0.03)
            cleaned.set()

    e.transport.submit = hang

    async def run():
        with e.hold_writer():
            await e.step()

    task = asyncio.create_task(run())
    await asyncio.wait_for(entered.wait(), timeout=5)
    if cancel:
        task.cancel()
    await asyncio.wait_for(cleanup.wait(), timeout=5)
    assert e._descriptor is not None
    with pytest.raises(asyncio.CancelledError if cancel else asyncio.TimeoutError):
        await task
    assert cleaned.is_set() and e._descriptor is None
    with e.hold_writer():
        assert (await e.step()).status == "transaction_pending"


async def test_loop_retries_without_leaking_exception_details(executing, caplog):
    e = executing.executor
    stop = asyncio.Event()
    calls = []

    async def step():
        calls.append(1)
        if len(calls) == 3:
            stop.set()
        raise ConnectionError("secret-url-do-not-log")

    e.step = step
    await e.run(stop, poll_seconds=0.001)
    assert len(calls) == 3 and e._descriptor is None
    assert "secret-url-do-not-log" not in caplog.text
    assert "standing_retry reason=ConnectionError" in caplog.text


async def test_concurrent_steps_do_not_duplicate_signing(executing):
    t, e = executing, executing.executor
    with e.hold_writer():
        results = await asyncio.gather(e.step(), e.step(), e.step())
    assert [r.status for r in results] == [
        "submitted_unconfirmed",
        "transaction_pending",
        "transaction_pending",
    ]
    assert len(t.signed) == len(t.sent) == 1


async def test_history_catchup_is_bounded_and_resumable(executing):
    t, e = executing, executing.executor
    calls = []

    async def missing(_):
        raise ValueError("prefix pending")

    async def advance(provider, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(history=None if len(calls) == 1 else t.options["history"])

    e.history.verified_prefix, e.history.advance = missing, advance
    with e.hold_writer():
        with pytest.raises(execution.StandingHistoryPending):
            await e.step()
        assert t.journal.pending() is None and not t.signed
        assert (await e.step()).status == "submitted_unconfirmed"
    assert all(k == {"through_block": 123, "maximum_blocks": 64} for k in calls)


async def test_completed_package_replay_survives_freshness_retry(executing):
    t, e = executing, executing.executor
    e._prepared.clear()
    package, replayed = object(), []
    e.packages = lambda _: package
    activation = RewardActivation(
        cohort_sha256="aa" * 32,
        allocation_sha256="ab" * 32,
        package_sha256="ac" * 32,
        recovery_tip_sha256="ad" * 32,
        prior_opportunity_sha256="ae" * 32,
    )
    t.current.selection.activation = t.current.prepared.activation = activation

    async def prepare(value, **kwargs):
        assert value is package
        replayed.append(value)
        return t.current.prepared

    e.preparation.prepare = prepare
    context = e._context
    fresh_calls = []

    async def fresh(*args):
        fresh_calls.append(1)
        if len(fresh_calls) == 1:
            raise ValueError("initial control expired during replay")
        return await context(*args)

    e._context = fresh
    with e.hold_writer():
        with pytest.raises(ValueError, match="expired during"):
            await e.step()
        assert (await e.step()).status == "submitted_unconfirmed"
    assert len(replayed) == len(t.signed) == len(t.sent) == 1


async def test_original_signer_must_match_designated_validator(executing):
    t, e = executing, executing.executor
    e.signer.ss58_address = "wrong-hotkey"
    with e.hold_writer(), pytest.raises(ValueError):
        await e.step()
    assert t.journal.pending().signed is None and not t.sent


async def test_changed_decision_after_signing_cannot_submit(executing):
    t, e = executing, executing.executor
    t.mutate = lambda _: setattr(t.current.current.selection, "decision_sha256", "ff" * 32)
    with e.hold_writer(), pytest.raises(ValueError, match="current selection"):
        await e.step()
    assert t.journal.pending().signed is not None and not t.sent
