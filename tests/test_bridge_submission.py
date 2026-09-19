"""Isolated loop fault tests with synthetic chain proofs and in-memory hotkeys."""

import asyncio
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

import umi.registration_bridge as bridge
from tests.bridge_execution_fixtures import signing_state
from tests.test_registration_bridge_runtime import (
    BLOCK,
    REVISION,
    Chain,
    applied_observation,
    healthy,
    run,
    writer_observation,
)
from tests.test_registration_bridge_runtime import signed_policy as signed_policy
from tests.test_registration_bridge_runtime import wallet as wallet
from umi.bridge.receipts import VerifiedBridgeReceipt
from umi.chain_evidence import FinalizedSnapshotRef


def proven_receipt(journal, *, success=True):
    block = journal.attempt.preflight_block + 1
    receipt = bridge.BootstrapExtrinsicReference(
        extrinsic_id=f"{block}-0002",
        block_number=block,
        extrinsic_index=2,
        block_hash="0x" + "22" * 32,
    )
    return VerifiedBridgeReceipt(
        receipt,
        success,
        journal.signed_extrinsic_hash,
        FinalizedSnapshotRef(
            block, receipt.block_hash, journal.attempt.preflight_block_hash, "0x" + "55" * 32
        ),
    )


def test_call_builder_cannot_mutate_the_expected_parameter_snapshot(signed_policy, wallet):
    from tests.test_registration_bridge import decision
    from umi.bridge.submission import build_registration_bridge_call

    choice = decision(signed_policy, writer_observation(wallet))

    def mutate(**params):
        params["weights"][6] = 0
        return SimpleNamespace(
            module="SubtensorModule", function="set_mechanism_weights", params=params
        )

    with pytest.raises(bridge.RegistrationBridgeError, match="weight_call_shape_changed"):
        build_registration_bridge_call(choice, call_builder=mutate)
    assert choice.expected_row[6][1] > 0


def test_legacy_freshness_alias_is_preserved():
    from umi.bridge.submission import submission_freshness

    assert bridge._submission_freshness is submission_freshness


def test_idle_poll_does_not_execute_signing_proofs(tmp_path, signed_policy, wallet):
    with bridge.RegistrationBridgeState(tmp_path / "state") as state:
        before = writer_observation(wallet)
        after = applied_observation(wallet, signed_policy)
        run(signed_policy, wallet, Chain(state, [before, before, after]), state)
        chain = Chain(state, [after, after])
        assert run(signed_policy, wallet, chain, state)["status"] == "wait"
        assert chain.signing_reads == 0 and not chain.client.calls


@pytest.mark.parametrize(
    "change", ["new_head", "permit", "chain_settings", "stale", "mismatched_proof"]
)
def test_signing_head_is_rechecked_before_intent(tmp_path, signed_policy, wallet, change):
    before = writer_observation(wallet)
    fresh = before.model_copy(update={"block_number": BLOCK + 1, "block_hash": "0x" + "33" * 32})
    if change == "permit":
        from tests.test_registration_bridge import replace_participant

        fresh = replace_participant(fresh, 54, validator_permit=False)
    elif change == "chain_settings":
        fresh = fresh.model_copy(update={"commit_reveal_enabled": True})
    elif change == "stale":
        fresh = fresh.model_copy(update={"block_timestamp_ms": fresh.block_timestamp_ms - 121000})
    with bridge.RegistrationBridgeState(tmp_path / "state") as state:
        chain = Chain(
            state, [before, before, applied_observation(wallet, signed_policy, block=BLOCK + 2)]
        )

        async def new_head(client, *, validator_hotkey):
            assert validator_hotkey == wallet.hotkey.ss58_address
            proof = signing_state(before if change == "mismatched_proof" else fresh, state)
            return fresh, proof

        chain.signing_observation_with_client = new_head
        if change == "new_head":
            assert run(signed_policy, wallet, chain, state)["status"] == "submitted"
            assert state.load().attempt.preflight_block_hash == fresh.block_hash
            assert state.load().attempt.signing.block_number == fresh.block_number
        else:
            with pytest.raises(bridge.RegistrationBridgeError):
                run(signed_policy, wallet, chain, state)
            assert state.load().phase == "idle" and not chain.client.calls


@pytest.mark.parametrize("hint_success", [True, False])
def test_sdk_receipt_without_owned_proof_never_becomes_applied(
    tmp_path, signed_policy, wallet, hint_success
):
    with bridge.RegistrationBridgeState(tmp_path / "state") as state:
        before = writer_observation(wallet)
        chain = Chain(state, [before, before])
        submit = chain.client.submit_signed

        async def hint(*args, **kwargs):
            await submit(*args, **kwargs)
            return SimpleNamespace(
                success=hint_success, extrinsic_id=f"{BLOCK + 1}-0002", block_hash="0x" + "22" * 32
            )

        async def no_proof(client, journal):
            return None

        chain.client.submit_signed = hint
        chain.exact_receipt_with_client = no_proof
        with pytest.raises(
            bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"
        ):
            run(signed_policy, wallet, chain, state)
        assert state.load().phase == "outcome_unknown"
        assert state.load().weight_call is None and len(chain.client.calls) == 1


def test_failed_sdk_hint_does_not_override_proven_success(tmp_path, signed_policy, wallet):
    with bridge.RegistrationBridgeState(tmp_path / "state") as state:
        before = writer_observation(wallet)
        chain = Chain(state, [before, before, applied_observation(wallet, signed_policy)])
        submit = chain.client.submit_signed

        async def failed_hint(*args, **kwargs):
            await submit(*args, **kwargs)
            return SimpleNamespace(success=False)

        chain.client.submit_signed = failed_hint
        assert run(signed_policy, wallet, chain, state)["status"] == "submitted"
        assert state.load().phase == "applied"


@pytest.mark.parametrize("failure", [None, TimeoutError("proof unavailable"), "wrong_transaction"])
def test_receipt_collection_failure_retains_bytes_without_rebroadcast(
    tmp_path, signed_policy, wallet, failure
):
    root = tmp_path / "state"
    before = writer_observation(wallet)
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before])

        async def bad_proof(client, journal):
            if isinstance(failure, BaseException):
                raise failure
            return (
                None
                if failure is None
                else replace(proven_receipt(journal), signed_extrinsic_hash="0x" + "ff" * 32)
            )

        chain.exact_receipt_with_client = bad_proof
        with pytest.raises((bridge.RegistrationBridgeError, TimeoutError)):
            run(signed_policy, wallet, chain, state)
        old = state.load()
        assert old.phase == "outcome_unknown" and len(chain.client.calls) == 1
    with bridge.RegistrationBridgeState(root) as state:
        after = applied_observation(wallet, signed_policy)
        chain = Chain(state, [after, after, after])
        chain.nonce = 8
        chain.proven_receipt = proven_receipt(old)
        assert run(signed_policy, wallet, chain, state)["status"] == "wait"
        assert state.load().phase == "applied"
        assert state.load().signed_extrinsic == old.signed_extrinsic
        assert not chain.client.calls


@pytest.mark.parametrize("nonce", [7, 8])
def test_expired_attempt_requires_proven_original_nonce_before_a_new_attempt(
    tmp_path, signed_policy, wallet, nonce
):
    root = tmp_path / "state"
    before = writer_observation(wallet)
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before], error=TimeoutError())
        with pytest.raises(TimeoutError):
            run(signed_policy, wallet, chain, state)
        old = state.load()
    later = before.model_copy(update={"block_number": BLOCK + 8, "block_hash": "0x" + "33" * 32})
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(
            state, [later, later, applied_observation(wallet, signed_policy, block=BLOCK + 9)]
        )
        chain.nonce = nonce
        if nonce == 7:
            assert run(signed_policy, wallet, chain, state)["status"] == "submitted"
            assert len(chain.client.calls) == 1
            assert state.load().attempt.attempt_id != old.attempt.attempt_id
            expired = (
                state.root
                / "registration-bridge-history"
                / f"{old.attempt.attempt_id}-expired_nonce_available.json"
            )
            assert expired.is_file()
        else:
            with pytest.raises(
                bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"
            ):
                run(signed_policy, wallet, chain, state)
            assert state.load() == old and not chain.client.calls


def test_proven_dispatch_failure_is_terminal_and_next_attempt_is_distinct(
    tmp_path, signed_policy, wallet
):
    root = tmp_path / "state"
    before = writer_observation(wallet)
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before])

        async def failure(client, journal):
            return proven_receipt(journal, success=False)

        chain.exact_receipt_with_client = failure
        with pytest.raises(bridge.RegistrationBridgeError, match="bridge_weight_submission_failed"):
            run(signed_policy, wallet, chain, state)
        old = state.load()
        assert old.phase == "failed" and old.failed_call is not None and old.weight_call is None
    later = before.model_copy(update={"block_number": BLOCK + 2, "block_hash": "0x" + "33" * 32})
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(
            state, [later, later, applied_observation(wallet, signed_policy, block=BLOCK + 3)]
        )
        chain.nonce = 8
        assert run(signed_policy, wallet, chain, state)["status"] == "submitted"
        assert len(chain.client.calls) == 1 and state.load().attempt != old.attempt


@pytest.mark.parametrize("phase", ["preparing", "signed"])
def test_interrupted_prebroadcast_attempt_resumes_only_after_proven_expiry(
    tmp_path, signed_policy, wallet, monkeypatch, phase
):
    root = tmp_path / "state"
    before = writer_observation(wallet)
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before])
        store = state.store

        def interrupted(journal, *, archive=False):
            store(journal, archive=archive)
            if archive and journal.phase == phase:
                raise RuntimeError("interrupted before broadcast")

        with monkeypatch.context() as patch:
            patch.setattr(state, "store", interrupted)
            with pytest.raises(RuntimeError, match="interrupted before broadcast"):
                run(signed_policy, wallet, chain, state)
        old = state.load()
        assert old.phase == phase and not chain.client.calls
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before])
        with pytest.raises(
            bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"
        ):
            run(signed_policy, wallet, chain, state)
        assert state.load() == old and not chain.client.calls
    later = before.model_copy(update={"block_number": BLOCK + 8, "block_hash": "0x" + "33" * 32})
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(
            state, [later, later, applied_observation(wallet, signed_policy, block=BLOCK + 9)]
        )
        assert run(signed_policy, wallet, chain, state)["status"] == "submitted"
        assert len(chain.client.calls) == 1 and state.load().attempt != old.attempt


@pytest.mark.parametrize(
    "phase", ["preparing", "signed", "submitting", "receipt_returned", "applied"]
)
@pytest.mark.asyncio
async def test_cancellation_drains_every_transition_before_unlock(
    tmp_path, signed_policy, wallet, monkeypatch, phase
):
    root = tmp_path / "state"
    state = bridge.RegistrationBridgeState(root)
    before = writer_observation(wallet)
    chain = Chain(state, [before, before, applied_observation(wallet, signed_policy)])
    loop = asyncio.get_running_loop()
    started, release = asyncio.Event(), threading.Event()
    store = state.store

    def pause_after_publication(journal, *, archive=False):
        store(journal, archive=archive)
        if journal.phase == phase and archive:
            loop.call_soon_threadsafe(started.set)
            assert release.wait(5), "test did not release persistence"

    monkeypatch.setattr(state, "store", pause_after_publication)

    async def service():
        with state:
            await bridge.run_registration_bridge_iteration(
                signed_policy,
                wallet=wallet,
                chain=chain,
                state=state,
                expected_revision=REVISION,
                directive_valid_from=signed_policy.body.valid_from_block,
                directive_valid_through=signed_policy.body.hard_sunset_block - 1,
                request=healthy,
            )

    task = asyncio.create_task(service())
    try:
        await asyncio.wait_for(started.wait(), 4)
        for _ in range(2):
            task.cancel()
            await asyncio.sleep(0.01)
        assert not task.done()
        with pytest.raises(BlockingIOError), bridge.RegistrationBridgeState(root):
            pass
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    with bridge.RegistrationBridgeState(root) as reopened:
        assert reopened.load().phase == phase
    assert len(chain.client.calls) == (1 if phase in {"receipt_returned", "applied"} else 0)
