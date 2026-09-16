# ruff: noqa: F811
from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

import umi.registration_bridge as bridge
from tests.test_registration_bridge import (
    BLOCK,
    NOW,
    NOW_MS,
    REVISION,
    decision,
    health,
    hotkey,
    observation,
    replace_participant,
)
from tests.test_registration_bridge import signed_policy as signed_policy
from tests.test_registration_bridge_freeze import frozen
from tests.test_registration_bridge_funding import setup as funding_setup  # noqa: F401
from tests.test_registration_bridge_runtime import Chain, run, writer_observation
from tests.test_registration_bridge_runtime import wallet as wallet
from umi.protocol import canonical_json_bytes


def advance(obs, **changes):
    return obs.model_copy(
        update={
            "block_number": obs.block_number + 1,
            "block_hash": "0x" + "44" * 32,
            **changes,
        }
    )


def reconcile(policy, before, fresh, receipts=None, now=NOW):
    return bridge.validate_registration_bridge_observation(
        policy,
        fresh,
        health(before) if receipts is None else receipts,
        expected_revision=REVISION,
        now=now,
        health_observation=before,
    )


@pytest.mark.parametrize("uid", [6, 71])
def test_new_registration_does_not_inherit_probe_or_block_unchanged_miners(signed_policy, uid):
    before = observation()
    fresh = advance(
        replace_participant(
            before,
            uid,
            hotkey=hotkey(4000),
            registered_at_block=BLOCK,
            origin="https://1.1.1.1:443",
        )
    )
    result = reconcile(signed_policy, before, fresh)
    assert result.expected_row[uid][1] == 0
    assert result.expected_row[10][1] > 0
    # A complete probe of the new registration admits it on the next pass.
    assert reconcile(signed_policy, fresh, advance(fresh)).expected_row[uid][1] > 0


@pytest.mark.parametrize("change", ["new_endpoint", "lost_permit", "no_longer_owner"])
def test_newly_eligible_registration_waits_for_its_own_probe(signed_policy, change):
    before = observation()
    uid = 71
    if change == "lost_permit":
        before = replace_participant(
            before, uid, validator_permit=True, origin="https://1.1.1.1:443"
        )
        fresh = replace_participant(before, uid, validator_permit=False)
    elif change == "no_longer_owner":
        before = replace_participant(before, uid, origin="https://1.1.1.1:443")
        before = before.model_copy(
            update={
                "owner_associated_hotkeys": sorted(
                    [hotkey(0), hotkey(uid)],
                    key=bridge.account_id32,
                )
            }
        )
        fresh = before.model_copy(update={"owner_associated_hotkeys": [hotkey(0)]})
    else:
        fresh = replace_participant(before, uid, origin="https://1.1.1.1:443")
    result = reconcile(signed_policy, before, advance(fresh))
    assert result.expected_row[uid][1] == 0 and result.expected_row[6][1] > 0


def test_unrelated_churn_and_lastupdate_changes_do_not_interrupt_refresh(signed_policy):
    before = observation()
    fresh = advance(replace_participant(before, 71, hotkey=hotkey(4000)))
    fresh = replace_participant(fresh, 247, last_update=BLOCK)
    assert (
        reconcile(signed_policy, before, fresh).expected_row
        == decision(signed_policy, before).expected_row
    )


def test_funding_ip_and_coldkey_caps_survive_churn(funding_setup):
    before, _, _, policy, _ = funding_setup
    # Two IP-linked UIDs join the three already-linked funding entries.
    before = replace_participant(before, 74, origin=before.participants[71].origin)
    before = replace_participant(
        before, 75, origin="https://1.0.0.1:443", coldkey=before.participants[74].coldkey
    )
    fresh = advance(replace_participant(before, 73, hotkey=hotkey(4000), registered_at_block=BLOCK))
    row = reconcile(policy, before, fresh).expected_row
    assert row[73][1] == 0
    assert sum(row[uid][1] for uid in (71, 72, 74, 75)) == row[6][1] == 65535


def test_frozen_policy_still_rejects_replacements_after_new_probe(funding_setup):
    before = funding_setup[0]
    policy = frozen(funding_setup)
    fresh = advance(replace_participant(before, 71, hotkey=hotkey(4000), registered_at_block=BLOCK))
    assert reconcile(policy, before, fresh).expected_row[71][1] == 0
    row = reconcile(policy, fresh, advance(fresh)).expected_row
    assert row[71][1] == 0 and row[6][1] > 0


@pytest.mark.parametrize(
    "fault",
    ["missing", "duplicate", "wrong_hotkey", "wrong_origin", "expired", "future", "false_success"],
)
def test_churn_never_hides_bad_or_incomplete_probe_evidence(signed_policy, fault):
    before = observation()
    fresh = advance(replace_participant(before, 6, hotkey=hotkey(4000)))
    receipts = health(before)
    if fault == "missing":
        receipts = receipts[1:]
    elif fault == "duplicate":
        receipts = [receipts[0], *receipts]
    else:
        changes = {
            "wrong_hotkey": {"hotkey": hotkey(4000)},
            "wrong_origin": {"origin": "https://1.1.1.1:443"},
            "expired": {"checked_at_unix_ms": NOW_MS - 120001},
            "future": {"checked_at_unix_ms": NOW_MS + 1},
            "false_success": {"body_sha256": None},
        }
        receipts[0] = receipts[0].model_copy(update=changes[fault])
    with pytest.raises(bridge.RegistrationBridgeError, match="health_"):
        reconcile(signed_policy, before, fresh, receipts)


def test_all_changed_or_failed_holds_without_burn(signed_policy):
    before = observation()
    fresh = advance(before)
    for uid in (6, 10):
        fresh = replace_participant(fresh, uid, hotkey=hotkey(4000 + uid))
    receipts = health(before, failed={p.uid for p in before.participants if p.uid not in {6, 10}})
    with pytest.raises(bridge.RegistrationBridgeError, match="no_live_eligible_miners"):
        reconcile(signed_policy, before, fresh, receipts)


@pytest.mark.parametrize("fault", ["rollback", "hash", "roster"])
def test_fallback_does_not_accept_finality_inconsistency(signed_policy, fault):
    before = observation()
    fresh = before
    if fault == "rollback":
        fresh = fresh.model_copy(update={"block_number": BLOCK - 1})
    elif fault == "hash":
        fresh = fresh.model_copy(update={"block_hash": "0x" + "44" * 32})
    else:
        fresh = replace_participant(fresh, 6, hotkey=hotkey(4000))
    with pytest.raises(bridge.RegistrationBridgeError, match=r"health_(finality|roster)_"):
        reconcile(signed_policy, before, fresh)


@pytest.mark.parametrize(
    "fault", ["permit", "writer_registration", "settings", "stale", "health_headroom"]
)
def test_unsafe_global_conditions_still_prevent_any_send(tmp_path, signed_policy, wallet, fault):
    before = writer_observation(wallet)
    fresh = advance(replace_participant(before, 6, hotkey=hotkey(4000)))
    if fault == "permit":
        fresh = replace_participant(fresh, 54, validator_permit=False)
    elif fault == "writer_registration":
        fresh = replace_participant(fresh, 54, registered_at_block=BLOCK)
    elif fault == "settings":
        fresh = fresh.model_copy(update={"commit_reveal_enabled": True})
    elif fault == "stale":
        fresh = fresh.model_copy(update={"block_timestamp_ms": NOW_MS - 120001})
    elif fault == "health_headroom":
        fresh = fresh.model_copy(update={"block_timestamp_ms": NOW_MS + 61000})
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        chain = Chain(state, [before, fresh])
        if fault == "health_headroom":
            chain.hook = lambda count: (
                setattr(chain, "now", NOW + timedelta(seconds=61)) if count == 2 else None
            )
        with pytest.raises(bridge.RegistrationBridgeError):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls and state.load().phase == "idle"


def test_original_probe_snapshot_is_hashed_without_changing_old_attempts(signed_policy):
    before = observation()
    fresh = advance(replace_participant(before, 6, hotkey=hotkey(4000)))
    attempt = bridge._new_attempt(
        signed_policy,
        fresh,
        reconcile(signed_policy, before, fresh),
        health(before),
        health_observation=before,
    )
    assert isinstance(attempt, bridge.RegistrationBridgeChurnAttempt)
    raw = canonical_json_bytes(attempt)
    assert (
        canonical_json_bytes(bridge.RegistrationBridgeChurnAttempt.model_validate_json(raw)) == raw
    )
    changed = attempt.model_copy(update={"health_observation": fresh}).model_dump(
        mode="python",
        by_alias=True,
    )
    with pytest.raises(ValidationError, match="attempt identity mismatch"):
        bridge.RegistrationBridgeChurnAttempt.model_validate(changed)
    unchanged = advance(before)
    old = bridge._new_attempt(
        signed_policy, unchanged, decision(signed_policy, unchanged), health(before)
    )
    new = bridge._new_attempt(
        signed_policy,
        unchanged,
        decision(signed_policy, unchanged),
        health(before),
        health_observation=before,
    )
    assert type(new) is bridge.RegistrationBridgeAttempt
    assert canonical_json_bytes(new) == canonical_json_bytes(old)


@pytest.mark.parametrize("receipt_returned", [False, True])
def test_churn_attempt_restart_keeps_exact_receipt_and_no_duplicate_send(
    tmp_path,
    signed_policy,
    wallet,
    receipt_returned,
):
    before = writer_observation(wallet, block_number=BLOCK - 1, block_hash="0x" + "33" * 32)
    fresh = advance(replace_participant(before, 6, hotkey=hotkey(4000)))
    expected = reconcile(signed_policy, before, fresh).expected_row
    applied = replace_participant(
        advance(fresh, block_hash="0x" + "22" * 32, validator_row=expected),
        54,
        last_update=BLOCK + 1,
    )
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(
            state,
            [before, fresh, TimeoutError("post-submit RPC")],
            error=None if receipt_returned else TimeoutError("submission interrupted"),
        )
        with pytest.raises(TimeoutError):
            run(signed_policy, wallet, chain, state)
        journal = state.load()
        assert journal.phase == ("receipt_returned" if receipt_returned else "outcome_unknown")
        assert isinstance(journal.attempt, bridge.RegistrationBridgeChurnAttempt)
        assert journal.attempt.health_observation == before
    with bridge.RegistrationBridgeState(root) as state:
        # UID6 remains unavailable, so the next complete probe has the same row.
        async def probe(origin):
            if origin == applied.participants[6].origin:
                raise OSError("endpoint unavailable")
            return b"ok"

        chain = Chain(state, [applied, applied, applied])
        if receipt_returned:
            assert run(signed_policy, wallet, chain, state, request=probe)["status"] == "wait"
            assert state.load().phase == "applied" and len(chain.receipts) == 1
        else:
            with pytest.raises(
                bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"
            ):
                run(signed_policy, wallet, chain, state, request=probe)
        assert not chain.client.calls
