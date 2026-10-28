"""Recurring execution with real journal, locks, codec and signatures.

Current chain/control proofs, completed package replay, migration qualification
and outcome proofs are explicit substituted ports. Their native verification
has separate tests. These tests do not qualify an installed/live validator.
"""

import asyncio
import copy
import json
import os
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_executor as execution
from umi.competition_reward_decisions import RewardActivation
from umi.competition_reward_executor import StandingRewardExecutor
from umi.competition_reward_transactions import _issue_standing_end
from umi.competition_weight_timing import WeightRateLimitWait
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError
from umi.r2_evidence import R2EvidenceHTTPError
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
    e._lock, e._descriptor, e._series_descriptor = asyncio.Lock(), None, None
    e._writer_path = t.journal.journal.root.parent.parent / "standing-writer.lock"
    e._series_writer_path = t.journal.journal.root / "standing-writer.lock"
    e.decisions = t.options["source"]
    t.signed, t.sent, t.captures, t.recoveries = [], [], [], []
    t.end, t.fenced, t.mutate = None, True, lambda _: None
    t.owner._authority = lambda: None
    t.owner._check_prepared = lambda _: None
    t.owner.reader.reward_adoptions = None
    t.owner.reader.refresh_reward_adoptions = lambda: t.owner.reader.reward_adoptions

    def fence(*args, **kwargs):
        if not t.fenced:
            raise ValueError("original writer ownership ended")

    monkeypatch.setattr(execution, "validate_legacy_handoff", fence)
    e.host = SimpleNamespace(recheck=fence, writer_path=e._writer_path)

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
        ensure_observer_running=lambda: None,
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


async def test_invalid_feed_blocks_new_weight_work_before_signing(executing):
    t, e = executing, executing.executor

    def damaged():
        raise ValueError("signed reward feed needs repair")

    t.owner.reader.refresh_reward_adoptions = damaged
    with e.hold_writer(), pytest.raises(ValueError, match="feed needs repair"):
        await e.step()
    assert not t.captures and not t.signed and not t.sent
    assert t.journal.pending() is None


async def test_terminal_observer_exits_loop_for_service_restart(executing):
    t, e = executing, executing.executor

    def stopped():
        raise RuntimeError("owned_finality_observer_stopped")

    e.provider.ensure_observer_running = stopped
    with pytest.raises(RuntimeError, match="observer_stopped"):
        await e.run(asyncio.Event(), poll_seconds=0.001)
    assert e._descriptor is None and not t.signed and not t.sent


async def test_send_once_then_recover_even_after_restart(executing, caplog):
    t, e = executing, executing.executor
    caplog.set_level("INFO", logger=execution.__name__)
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
    observations = [
        json.loads(r.message)
        for r in caplog.records
        if r.name == execution.__name__ and r.message.startswith('{"block_number"')
    ]
    assert observations
    assert all(
        v
        == {
            "schema": "umi-standing-chain-observation/1",
            "block_number": t.chain.block,
            "weight_update_block": t.chain.validator_last_update,
        }
        for v in observations
    )
    # Transport success and pending recovery cannot claim a new finalized update.
    assert observations[-1]["weight_update_block"] == pending.intent.prior_last_update


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
    assert e._writer_path.parent == e.journal.journal.root.parent.parent
    assert e._series_writer_path.parent == e.journal.journal.root
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

    descriptor = execution.lock_private_file(e._series_writer_path)
    try:
        with pytest.raises(PrivateStateBusyError), e.hold_writer():
            pass
        assert e._descriptor is e._series_descriptor is None
        replacement = execution.lock_private_file(e._writer_path)
        os.close(replacement)
    finally:
        os.close(descriptor)


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
    assert not task.done() and e._descriptor is not None and e._series_descriptor is not None
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert e._descriptor is e._series_descriptor is None and not t.sent
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


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (ConnectionError("secret-url-do-not-log"), "standing_retry reason=ConnectionError"),
        (
            R2EvidenceHTTPError(429),
            "standing_retry reason=R2EvidenceHTTPError r2_http_status=429",
        ),
    ],
)
async def test_loop_retries_without_leaking_exception_details(executing, caplog, failure, expected):
    e = executing.executor
    stop = asyncio.Event()
    calls = []

    async def step():
        calls.append(1)
        if len(calls) == 3:
            stop.set()
        raise failure

    e.step = step
    await e.run(stop, poll_seconds=0.001)
    assert len(calls) == 3 and e._descriptor is None
    assert "secret-url-do-not-log" not in caplog.text
    assert expected in caplog.text


async def test_rate_wait_never_reserves_or_signs_and_retry_collects_new_state(executing):
    t, e = executing, executing.executor
    original = t.chain.weights_rate_limit
    t.chain.weights_rate_limit = t.chain.block - t.chain.validator_last_update + 1
    with e.hold_writer():
        with pytest.raises(WeightRateLimitWait) as held:
            await e.step()
        assert held.value.next_eligible_block == t.chain.block + 1
        assert t.journal.pending() is None and not t.signed and not t.sent
        captured_before = len(t.captures)
        # A later native snapshot may change the rate. No old wait is authority
        # or an execution clock; the full ordinary path must run again.
        t.chain.weights_rate_limit = original
        assert (await e.step()).status == "submitted_unconfirmed"
    assert len(t.captures) > captured_before
    assert len(t.signed) == len(t.sent) == 1


async def test_loop_bounds_rate_wait_backoff_and_keeps_stop_responsive(
    executing, monkeypatch, caplog
):
    e = executing.executor
    stop, calls, delays = asyncio.Event(), [], []
    original_wait = asyncio.wait_for

    async def step():
        assert e._descriptor is not None
        calls.append(1)
        if len(calls) == 1:
            raise WeightRateLimitWait(100, 200)
        stop.set()
        return execution.StandingExecutionProgress("selection_pending")

    async def wait(awaitable, *, timeout):
        frame = getattr(awaitable, "cr_frame", None)
        if frame is not None and frame.f_locals.get("self") is stop:
            delays.append(timeout)
            awaitable.close()
            if stop.is_set():
                return True
            raise asyncio.TimeoutError
        return await original_wait(awaitable, timeout=timeout)

    e.step = step
    monkeypatch.setattr(execution.asyncio, "wait_for", wait)
    with caplog.at_level("INFO", logger="umi.competition_reward_executor"):
        await e.run(stop, poll_seconds=12)
    assert delays == [60, 12] and len(calls) == 2
    assert e._descriptor is None and not executing.signed and not executing.sent
    messages = [json.loads(r.message) for r in caplog.records if r.message.startswith('{"')]
    report = next(m for m in messages if m.get("schema") == "umi-standing-weight-rate-wait/1")
    assert report["remaining_blocks"] == 100
    assert report["eta_scope"] == "current_rate_limit_only_not_rewards_or_opportunity"
    assert report["planning_eta_seconds"] == [600, 2400]


async def test_rate_wait_withdraws_eta_when_native_height_stalls(executing, monkeypatch, caplog):
    e = executing.executor
    stop, calls, times = asyncio.Event(), [], iter((0.0, 61.0))

    async def step():
        calls.append(1)
        if len(calls) == 2:
            stop.set()
        raise WeightRateLimitWait(100, 200)

    e.step = step
    monkeypatch.setattr(execution, "time", SimpleNamespace(monotonic=lambda: next(times)))
    with caplog.at_level("INFO", logger="umi.competition_reward_executor"):
        await e.run(stop, poll_seconds=0.001)
    reports = [json.loads(r.message) for r in caplog.records if r.message.startswith('{"')]
    assert reports[0]["status"] == "waiting" and reports[1]["status"] == "stalled"
    assert reports[1]["planning_eta_seconds"] is None
    assert reports[1]["percent"] == 0 and reports[1]["elapsed_seconds"] == 61
    assert e._descriptor is None and not executing.sent


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


def _revision_activations():
    original = RewardActivation(
        cohort_sha256="10" * 32,
        allocation_sha256="11" * 32,
        package_sha256="12" * 32,
        recovery_tip_sha256="13" * 32,
        prior_opportunity_sha256="14" * 32,
    )
    revised = original.model_copy(
        update={"reward_adoption_sha256": "15" * 32, "effective_allocation_sha256": "16" * 32}
    )
    return original, revised


async def test_revision_after_signing_preserves_original_bytes_without_transmission(executing):
    t, e = executing, executing.executor
    original, revised = _revision_activations()
    e.first = t.current.prepared = SimpleNamespace(activation=original)
    t.current.selection.activation = original
    e._prepared = {digest(original): e.first}
    t.mutate = lambda _: setattr(t.current, "prepared", SimpleNamespace(activation=revised))
    with e.hold_writer(), pytest.raises(ValueError, match="current selection"):
        await e.step()
    pending = t.journal.pending()
    assert pending.intent.activation_sha256 == digest(original)
    assert pending.signed is not None and not t.sent
    assert t.reopen().pending() == pending


async def test_revised_first_cohort_uses_original_held_handoff(executing):
    t, e = executing, executing.executor
    original, revised = _revision_activations()
    e.first = SimpleNamespace(activation=original)
    adopted = SimpleNamespace(activation=revised)
    t.current.prepared = adopted
    t.current.selection.activation = revised
    e._prepared = {digest(revised): adopted}
    with e.hold_writer():
        assert (await e.step()).status == "submitted_unconfirmed"
    assert t.journal.pending().intent.activation_sha256 == digest(revised)
    assert t.checks and all(args[-1] == e.handoff for args in t.checks)


async def test_suspended_cohort_cannot_sign_or_submit(executing):
    t, e = executing, executing.executor
    t.current.selection.state = "suspended"
    with e.hold_writer():
        assert (await e.step()).status == "selection_pending"
    assert not t.signed and not t.sent and t.journal.pending() is None


@pytest.mark.parametrize("when", ["before_reserve", "before_sign", "before_send"])
async def test_new_host_adoption_fences_each_transaction_boundary(executing, monkeypatch, when):
    t, e = executing, executing.executor
    requested = when == "before_reserve"
    # Current host-adoption selection is an explicit substituted port here;
    # its signed-prefix validation is covered by adoption/preparation tests.
    monkeypatch.setattr(execution, "activation_requires_revision", lambda *args: requested)
    if when == "before_sign":
        reserve = e.preparation.reserve_transaction

        async def update_after_reservation(*args, **kwargs):
            nonlocal requested
            value = await reserve(*args, **kwargs)
            requested = True
            return value

        monkeypatch.setattr(e.preparation, "reserve_transaction", update_after_reservation)
    elif when == "before_send":

        def update_after_signature(_):
            nonlocal requested
            requested = True

        t.mutate = update_after_signature
    with e.hold_writer():
        if when == "before_reserve":
            assert (await e.step()).status == "reward_revision_pending"
            assert t.journal.pending() is None and not t.signed
        else:
            with pytest.raises(ValueError, match="require a native activation revision"):
                await e.step()
            pending = t.journal.pending()
            assert pending is not None and (pending.signed is not None) == (when == "before_send")
            assert len(t.signed) == (when == "before_send")
            e.journal = t.journal = t.reopen()
            assert e.journal.pending() == pending
            assert (await e.step()).status == "transaction_pending"
    assert not t.sent


async def test_final_freshness_check_follows_host_and_journal_io(executing):
    t, e = executing, executing.executor
    events = []
    recheck, project, submit = e.host.recheck, t.owner.project, e.transport.submit

    def inspect(**kwargs):
        recheck(**kwargs)
        events.append("host-io")

    async def fresh(*args, **kwargs):
        result = await project(*args, **kwargs)
        events.append("proof-freshness")
        return result

    async def send(*args):
        assert events[-1] == "proof-freshness"
        return await submit(*args)

    e.host.recheck, t.owner.project, e.transport.submit = inspect, fresh, send
    with e.hold_writer():
        assert (await e.step()).status == "submitted_unconfirmed"
    assert len(t.sent) == 1


async def test_lost_host_approval_cannot_sign_or_submit(executing):
    t, e = executing, executing.executor

    def unavailable(**kwargs):
        raise ValueError("host approval missing")

    e.host.recheck = unavailable
    with pytest.raises(ValueError, match="approval missing"), e.hold_writer():
        await e.step()
    assert not t.signed and not t.sent and t.journal.pending() is None
