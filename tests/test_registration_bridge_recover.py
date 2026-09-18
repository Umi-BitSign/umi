import asyncio
from types import SimpleNamespace

import pytest

import umi.registration_bridge as bridge
from tests.factories import dev_wallet
from tests.test_registration_bridge import (
    BLOCK,
    NOW,
    decision,
    health,
    observation,
    policy_body,
    replace_participant,
)
from umi.registration_bridge_recover import prove_applied_attempt, recover_applied_attempt


@pytest.fixture
def signed_policy(monkeypatch):
    wallet = dev_wallet("//RegistrationBridgeAuthority")
    monkeypatch.setattr(
        "umi.bridge.policy.REGISTRATION_BRIDGE_COORDINATOR", wallet.hotkey.ss58_address
    )
    return bridge.sign_registration_bridge_policy(
        policy_body(coordinator_hotkey=wallet.hotkey.ss58_address), wallet=wallet
    )


def recovery_case(signed_policy):
    before = observation()
    expected = decision(signed_policy, before)
    attempt = bridge._new_attempt(signed_policy, before, expected, health(before))
    journal = bridge.RegistrationBridgeJournal(
        schema=bridge.REGISTRATION_BRIDGE_JOURNAL_SCHEMA,
        validator_hotkey=before.validator_hotkey,
        legacy_journal_sha256=None,
        phase="submitting",
        attempt=attempt,
        weight_call=None,
        last_observed_block=before.block_number,
        last_observed_block_hash=before.block_hash,
        updated_at_unix_ms=int(NOW.timestamp() * 1000),
    )
    included = BLOCK + 3
    after = before.model_copy(
        update={
            "block_number": BLOCK + 10,
            "block_hash": "0x" + "33" * 32,
            "validator_row": expected.expected_row,
        }
    )
    after = replace_participant(after, 54, last_update=included)
    call = {
        "call_module": "SubtensorModule",
        "call_function": "set_mechanism_weights",
        "call_args": [
            {"name": "netuid", "value": 78},
            {"name": "mecid", "value": 0},
            {"name": "dests", "value": list(range(256))},
            {"name": "weights", "value": [pair[1] for pair in expected.expected_row]},
            {"name": "version_key", "value": 4_294_967_296},
        ],
    }
    block = SimpleNamespace(
        number=included,
        hash="0x" + "44" * 32,
        extrinsics=[{"address": before.validator_hotkey, "call": call}],
    )
    events = [
        {
            "extrinsic_idx": 0,
            "module_id": "SubtensorModule",
            "event_id": "WeightsSet",
            "attributes": (78, 54),
        },
        {
            "extrinsic_idx": 0,
            "module_id": "System",
            "event_id": "ExtrinsicSuccess",
            "attributes": {},
        },
    ]
    return journal, after, block, events


def test_exact_successful_finalized_call_recovers_receipt(signed_policy):
    journal, observation, block, events = recovery_case(signed_policy)
    receipt = prove_applied_attempt(journal, observation, block, events)
    assert receipt.extrinsic_id == f"{BLOCK + 3}-0000"
    assert receipt.block_hash == block.hash


@pytest.mark.parametrize(
    "change,reason",
    [
        ("failed", "recovery_exact_successful_call_not_unique"),
        ("wrong_signer", "recovery_exact_successful_call_not_unique"),
        ("wrong_row", "recovery_expected_row_not_visible"),
        ("late", "recovery_last_update_outside_attempt_era"),
    ],
)
def test_recovery_refuses_unproven_effects(signed_policy, change, reason):
    journal, observation, block, events = recovery_case(signed_policy)
    if change == "failed":
        events[1]["event_id"] = "ExtrinsicFailed"
    elif change == "wrong_signer":
        block.extrinsics[0]["address"] = observation.participants[1].hotkey
    elif change == "wrong_row":
        observation = observation.model_copy(
            update={"validator_row": [[uid, 0] for uid in range(256)]}
        )
    else:
        included = BLOCK + journal.attempt.signed_policy.body.submission_era_period + 1
        observation = replace_participant(observation, 54, last_update=included)
        block.number = included
    with pytest.raises(bridge.RegistrationBridgeError, match=reason):
        prove_applied_attempt(journal, observation, block, events)


def test_recovery_dry_run_then_archives_supported_transition(tmp_path, signed_policy):
    journal, observation, block, events = recovery_case(signed_policy)
    state_dir = tmp_path / "state"
    with bridge.RegistrationBridgeState(state_dir) as state:
        state.store(journal, archive=True)

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def block_info(self, *, block):
            assert block == BLOCK + 3
            return globals_block

        async def query(self, item, *, block):
            assert item == ("System", "Events") and block == BLOCK + 3
            return globals_events

    class Chain:
        def __init__(self):
            self.client = Client()
            self.closed = False

        def client_factory(self, network):
            assert network == "finney"
            return self.client

        async def observation_with_client(self, client, *, validator_hotkey):
            assert client is self.client and validator_hotkey == journal.validator_hotkey
            return observation

        async def verify_finalized_receipt_with_client(self, client, receipt, *, observation):
            assert client is self.client
            assert receipt.extrinsic_id == f"{BLOCK + 3}-0000"

        def clock(self):
            return NOW

        async def aclose(self):
            self.closed = True

    globals_block, globals_events = block, events
    dry = asyncio.run(
        recover_applied_attempt(
            state_dir,
            execute=False,
            confirm_attempt_id=None,
            confirm_extrinsic_id=None,
            chain=Chain(),
        )
    )
    assert dry["status"] == "recoverable"
    with bridge.RegistrationBridgeState(state_dir) as state:
        assert state.load().phase == "submitting"

    result = asyncio.run(
        recover_applied_attempt(
            state_dir,
            execute=True,
            confirm_attempt_id=dry["attempt_id"],
            confirm_extrinsic_id=dry["extrinsic_id"],
            chain=Chain(),
        )
    )
    assert result["status"] == "applied"
    with bridge.RegistrationBridgeState(state_dir) as state:
        current = state.load()
        assert current.phase == "applied"
        history = state_dir / "registration-bridge-history"
        assert (history / f"{dry['attempt_id']}-receipt_returned.json").is_file()
        assert (history / f"{dry['attempt_id']}-applied.json").is_file()
