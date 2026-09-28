"""Publisher fault tests and real SCALE signing against synthetic owned state.

Only the proof/history boundary is substituted here. Native capture/replay is
covered separately; these cases do not establish installed host qualification.
"""

import asyncio
import hashlib
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_control as control_module
from umi import competition_reward_control_signing as nonce_module
from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.competition_reward_control_journal import (
    RewardControlTransactionJournal,
    verify_control_transaction_bytes,
)
from umi.competition_reward_control_publisher import StandingControlPublisher
from umi.competition_reward_decisions import StandingRewardControlReader
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_reward_history import RewardControlHistoryReader
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.signed_extrinsic import encode_mortal_call

from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_open_competition import wallet
from .test_signed_extrinsic_native import native_encoding as native_encoding


@pytest.fixture
async def publisher_case(native_encoding, series_case, tmp_path, monkeypatch):
    c = series_case
    item = c.control
    item.config = item.config.model_copy(
        update={
            "proof_rpc_fallback_urls": ("wss://backup1.example.org", "wss://backup2.example.org"),
        }
    )
    await item.provider.aclose()
    item.provider = HistoricalRewardControlProvider(
        item.config,
        item.policy,
        historical_header_directory=tmp_path / "headers",
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    config = digest(item.config)
    base = native_encoding.context["runtime"]

    def state(*, block=250, nonce=4, current=None):
        ref = replace(
            base.snapshot,
            block_number=block,
            block_hash="0x" + hashlib.sha256(str(block).encode()).hexdigest(),
        )
        runtime = replace(base, snapshot=ref)
        control = control_module.OwnedRewardControlObservation(
            ref,
            item.clock.now,
            item.hotkey,
            current,
            None if current is None else block - 1,
            config,
            time.monotonic_ns(),
            time.monotonic_ns() + 3600 * 10**9,
            runtime,
            canonical_json_bytes({"synthetic_control": block, "current": current}),
            _issuer=control_module._ISSUER,
        )
        object.__setattr__(control, "_binding", control_module._binding(control))
        observed = nonce_module.RewardControlSigningState(
            control,
            nonce,
            runtime,
            canonical_json_bytes({"synthetic_nonce": nonce, "block": block}),
            _issuer=nonce_module._ISSUER,
        )
        object.__setattr__(observed, "_binding", nonce_module._binding(observed))
        return observed

    files = StandingRewardFiles(
        tmp_path / "files", maximum_package_bytes=1_000_000, maximum_witness_bytes=1_000_000
    )
    files.retain_decision(c.genesis)
    real_signer = wallet("Ferdie").hotkey
    h = SimpleNamespace(
        c=c,
        item=item,
        state=state,
        current=state(),
        files=files,
        signs=[],
        sends=[],
        replays=[],
        selected=-1,
        lost_reply=False,
        sign_started=None,
        sign_release=None,
    )

    def sign(payload):
        h.signs.append(payload)
        if h.sign_started is not None:
            h.sign_started.set()
            assert h.sign_release.wait(5)
        return real_signer.sign(payload)

    signer = SimpleNamespace(
        ss58_address=real_signer.ss58_address, crypto_type=real_signer.crypto_type, sign=sign
    )

    def reopen():
        reader = StandingRewardControlReader(
            tmp_path / "reader",
            c.series,
            item.policy,
            expected_series_sha256=digest(c.series),
            expected_chain_config_sha256=config,
            maximum_bytes=8 * 1024**2,
        )
        journal = RewardControlTransactionJournal(
            tmp_path / "transactions", c.series, config_sha256=config, maximum_bytes=8 * 1024**2
        )
        history = RewardControlHistoryReader(
            tmp_path / "history",
            control_hotkey=item.hotkey,
            chain_config_sha256=config,
            first_block=c.series.recovery.authority.issued_at_block,
            maximum_bytes=8 * 1024**2,
        )
        publisher = StandingControlPublisher(
            reader=reader,
            provider=item.provider,
            history=history,
            journal=journal,
            files=files,
            signer=signer,
            mortality_period=128,
        )

        async def observed(prefix):
            return h.current, h.selected

        async def recover(pending, prefix):
            h.replays.append(pending)

        async def submit(raw, signer):
            # Persistence must precede even the first attempted transmission.
            pending = journal.pending()
            assert pending.signed.encoded == raw.hex()
            h.sends.append(raw)
            if h.lost_reply:
                raise TimeoutError("lost response after acceptance")
            return SimpleNamespace(is_success=True)  # Never sufficient evidence of finalization.

        monkeypatch.setattr(publisher, "_observed", observed)
        monkeypatch.setattr(publisher, "_recover", recover)
        monkeypatch.setattr(publisher.transport, "submit", submit)
        return publisher

    h.reopen, h.publisher = reopen, reopen()
    yield h
    await item.provider.aclose()


async def test_lost_reply_restart_waits_for_fence_then_recognizes_control(publisher_case):
    h, prefix = publisher_case, (publisher_case.c.genesis,)
    h.lost_reply = True
    with h.publisher.hold_writer(), pytest.raises(TimeoutError):
        await h.publisher.step(prefix)
    original = h.publisher.journal.pending()
    h.publisher = h.reopen()
    with h.publisher.hold_writer():
        held = await h.publisher.step(prefix)
        assert held.status == "transaction_pending"
        assert h.publisher.journal.pending() == original
        assert len(h.signs) == len(h.sends) == 1
        h.current = h.state(block=251, nonce=5, current=digest(prefix[0].decision))
        h.selected = 0
        done = await h.publisher.step(prefix)
        assert done.status == "control_finalized"
        assert len(h.signs) == len(h.sends) == 1


@pytest.mark.parametrize("fence", ["mortality", "nonce"])
async def test_fenced_unknown_attempt_retains_original_and_retries_fresh(publisher_case, fence):
    h, prefix = publisher_case, (publisher_case.c.genesis,)
    with h.publisher.hold_writer():
        assert (await h.publisher.step(prefix)).status == "submitted_unconfirmed"
        original = h.publisher.journal.pending()
        h.current = h.state(
            block=378 if fence == "mortality" else 251, nonce=4 if fence == "mortality" else 5
        )
        assert (await h.publisher.step(prefix)).status == "submitted_unconfirmed"
        fresh = h.publisher.journal.pending()
        assert fresh.intent.previous_attempt_sha256 == digest(original.intent)
        assert len(h.signs) == len(h.sends) == 2
        assert h.sends[0] != h.sends[1]
        assert len(h.publisher.journal.journal.keys("control_signed")) == 2
        assert (await h.publisher.step(prefix)).status == "transaction_pending"
        assert len(h.sends) == 2


async def test_reservation_lost_acknowledgment_is_exact_and_unsigned_recovery_waits(publisher_case):
    h = publisher_case
    journal = h.publisher.journal
    first = journal.reserve(h.c.genesis, h.current, mortality_period=128)
    assert journal.reserve(h.c.genesis, h.current, mortality_period=128) == first
    h.publisher = h.reopen()
    with h.publisher.hold_writer():
        assert (await h.publisher.step((h.c.genesis,))).status == "transaction_pending"
    assert h.signs == h.sends == []


async def test_real_signed_commitment_cannot_change_nonce_call_or_signature(publisher_case):
    h = publisher_case
    j = h.publisher.journal
    attempt = j.reserve(h.c.genesis, h.current, mortality_period=128)
    intent, state = attempt.intent, h.current
    options = dict(
        runtime=state.runtime,
        signer=h.publisher.signer,
        validator_hotkey=h.item.hotkey,
        nonce=intent.nonce,
        mortality_period=128,
        genesis_hash="0x" + h.c.series.genesis_hash,
    )
    encoded = encode_mortal_call(intent.call(), **options)
    saved = j.retain_signed(intent, encoded, state)
    assert j.retain_signed(intent, encoded, state) == saved
    assert verify_control_transaction_bytes(intent, encoded, state, h.c.series).data == encoded
    # Substrate permits nondeterministic signatures, but the journal retains one.
    altered = encode_mortal_call(intent.call(), **(options | {"nonce": intent.nonce + 1}))
    with pytest.raises(ValueError):
        j.retain_signed(intent, altered, state)
    assert j.pending() == saved
    with pytest.raises(ValueError):
        j.reserve(h.c.genesis, h.state(block=379, nonce=3), mortality_period=128)
    with pytest.raises(ValueError, match="signing context"):
        j.reserve(h.c.genesis, h.state(block=379, current="ff" * 32), mortality_period=128)


@pytest.mark.parametrize("change", ["predecessor", "nonce", "era"])
async def test_changed_preflight_after_signing_prevents_broadcast(
    publisher_case, monkeypatch, change
):
    h = publisher_case
    calls = 0

    async def observed(prefix):
        nonlocal calls
        calls += 1
        fresh = h.state(
            block=378 if change == "era" else 251,
            nonce=5 if change == "nonce" else 4,
            current="ff" * 32 if change == "predecessor" else None,
        )
        return (h.current if calls == 1 else fresh), -1

    monkeypatch.setattr(h.publisher, "_observed", observed)
    with h.publisher.hold_writer(), pytest.raises(ValueError, match="current predecessor"):
        await h.publisher.step((h.c.genesis,))
    assert len(h.signs) == 1 and not h.sends
    assert h.publisher.journal.pending().signed is not None


async def test_recurring_owner_recovers_lost_ack_without_manual_reset(publisher_case, monkeypatch):
    h = publisher_case
    stop, calls = asyncio.Event(), []
    monkeypatch.setattr(h.item.provider, "ensure_observer_running", lambda: None)

    def decisions():
        calls.append(1)
        if len(calls) == 1:
            h.lost_reply = True
        elif len(calls) == 2:
            h.lost_reply = False
            h.current = h.state(block=378)
        else:
            h.current = h.state(block=379, nonce=5, current=digest(h.c.genesis.decision))
            h.selected = 0
            stop.set()
        return (h.c.genesis,)

    await asyncio.wait_for(h.publisher.run(stop, decisions, poll_seconds=0.001), timeout=5)
    assert len(calls) == 3 and len(h.signs) == len(h.sends) == 2
    assert h.publisher._descriptor is None


async def test_initial_admission_validity_cannot_be_bypassed(publisher_case):
    h = publisher_case
    h.current = h.state(block=h.item.policy.valid_through_block - 10)
    with h.publisher.hold_writer(), pytest.raises(ValueError, match="admission validity"):
        await h.publisher.step((h.c.genesis,))
    assert h.publisher.journal.pending() is None
    assert not h.signs and not h.sends


async def test_cancellation_waits_for_signing_and_durable_effect_boundary(publisher_case):
    h = publisher_case
    h.sign_started, h.sign_release = threading.Event(), threading.Event()
    with h.publisher.hold_writer():
        task = asyncio.create_task(h.publisher.step((h.c.genesis,)))
        assert await asyncio.to_thread(h.sign_started.wait, 3)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        h.sign_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert h.publisher.journal.pending().signed is not None
        assert len(h.signs) == len(h.sends) == 1
        assert (await h.publisher.step((h.c.genesis,))).status == "transaction_pending"


async def test_missing_delivery_and_unowned_writer_cannot_submit(publisher_case):
    h = publisher_case
    with pytest.raises(ValueError, match="writer lock"):
        await h.publisher.step((h.c.genesis,))
    (h.files.root / "decisions" / (digest(h.c.genesis.decision) + ".json")).unlink()
    with h.publisher.hold_writer(), pytest.raises((ValueError, OSError)):
        await h.publisher.step((h.c.genesis,))
    assert h.signs == h.sends == []
