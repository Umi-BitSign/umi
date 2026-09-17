from __future__ import annotations

import random
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import umi.registration_bridge as bridge
from tests.factories import dev_wallet
from tests.test_registration_bridge import (
    BLOCK,
    decision,
    health,
    hotkey,
    observation,
    policy_body,
    replace_participant,
)
from tests.test_registration_bridge_runtime import (
    Chain,
    run,
    writer_observation,
)
from tests.test_registration_bridge_runtime import (
    wallet as wallet,
)
from umi.protocol import canonical_json_bytes


@pytest.fixture
def policies(monkeypatch):
    signer = dev_wallet("//RegistrationBridgeAuthority")
    monkeypatch.setattr(
        "umi.bridge.policy.REGISTRATION_BRIDGE_COORDINATOR", signer.hotkey.ss58_address
    )
    old = policy_body(coordinator_hotkey=signer.hotkey.ss58_address)
    new = bridge.RegistrationBridgePolicyBody.model_validate(
        {
            **old.model_dump(by_alias=True),
            "reward_rule": "equal_live_coldkey_ip_groups/1",
            "grouping_rule": "registered_owner_or_https_ip_connected_components/1",
        }
    )
    return tuple(bridge.sign_registration_bridge_policy(p, wallet=signer) for p in (old, new))


def roster(entries):
    obs = observation()
    participants = [p.model_copy(update={"origin": None}) for p in obs.participants]
    for uid, coldkey, origin in entries:
        participants[uid] = participants[uid].model_copy(
            update={"coldkey": hotkey(coldkey), "origin": origin}
        )
    return bridge.RegistrationBridgeObservation.model_validate(
        {**obs.model_dump(), "participants": participants}
    )


def test_nineteen_keys_on_one_endpoint_receive_one_group_budget(policies):
    obs = roster(
        [(uid, 1000 + uid, "https://178.156.250.12:443") for uid in range(71, 90)]
        + [(6, 2000, "https://1.1.1.1:8443")]
    )
    old, new = (decision(policy, obs) for policy in policies)
    assert old.expected_row[6][1] == 65535
    assert sum(old.expected_row[uid][1] for uid in range(71, 90)) == 19 * 65535
    assert new.eligible_count == new.eligible_coldkey_count == 20
    assert new.expected_row[6][1] == 65535
    assert sum(new.expected_row[uid][1] for uid in range(71, 90)) == 65535
    assert all(new.expected_row[uid][1] > 0 for uid in range(71, 90))
    assert max(weight for _, weight in new.expected_row) == 65535


def test_ports_do_not_create_groups_and_owner_cap_is_transitive(policies):
    # 6--IP--10--owner--11--IP--13 are one connected group.
    obs = roster(
        [
            (6, 1001, "https://8.8.8.8:443"),
            (10, 1002, "https://8.8.8.8:8443"),
            (11, 1002, "https://1.1.1.1:443"),
            (13, 1003, "https://1.1.1.1:9443"),
            (14, 1004, "https://9.9.9.9:443"),
        ]
    )
    live = [p for p in obs.participants if p.origin]
    assert bridge._coldkey_ip_groups(live) == [[6, 10, 11, 13], [14]]
    result = decision(policies[1], obs)
    assert sum(result.expected_row[uid][1] for uid in (6, 10, 11, 13)) == 65535
    assert result.expected_row[14][1] == 65535
    for seed in range(10):
        random.Random(seed).shuffle(live)
        assert bridge._coldkey_ip_groups(live) == [[6, 10, 11, 13], [14]]


@pytest.mark.parametrize("bridge_uid", [10, 11])
def test_failed_endpoint_cannot_connect_otherwise_separate_groups(policies, bridge_uid):
    obs = roster(
        [
            (6, 1001, "https://8.8.8.8:443"),
            (10, 1002, "https://8.8.8.8:8443"),
            (11, 1002, "https://1.1.1.1:443"),
            (13, 1003, "https://1.1.1.1:9443"),
        ]
    )
    result = decision(policies[1], obs, health(obs, failed={bridge_uid}))
    assert result.expected_row[bridge_uid][1] == 0
    assert sum(result.expected_row[uid][1] for uid in (6, 10)) == 65535
    assert sum(result.expected_row[uid][1] for uid in (11, 13)) == 65535


@pytest.mark.parametrize("excluded", ["permit", "owner"])
def test_excluded_registrations_do_not_connect_groups(policies, excluded):
    obs = roster(
        [
            (6, 1001, "https://8.8.8.8:443"),
            (10, 1002, "https://8.8.8.8:8443"),
            (11, 1002, "https://1.1.1.1:443"),
        ]
    )
    if excluded == "permit":
        obs = replace_participant(obs, 10, validator_permit=True)
    else:
        obs = obs.model_copy(update={"owner_associated_hotkeys": [hotkey(0), hotkey(10)]})
    result = decision(policies[1], obs)
    assert result.expected_row[10][1] == 0
    assert result.expected_row[6][1] == result.expected_row[11][1] == 65535


def test_ipv4_mapped_ipv6_is_the_same_ip_not_an_extra_share(policies):
    obs = roster(
        [
            (6, 1001, "https://8.8.8.8:443"),
            (10, 1002, "https://[::ffff:808:808]:8443"),
            (11, 1003, "https://[2606:4700:4700::1111]:443"),
            (13, 1004, "https://[2606:4700:4700::1111]:8443"),
            (14, 1005, "https://1.1.1.1:443"),
        ]
    )
    result = decision(policies[1], obs)
    assert bridge._coldkey_ip_groups([p for p in obs.participants if p.origin]) == [
        [6, 10],
        [11, 13],
        [14],
    ]
    assert sum(result.expected_row[uid][1] for uid in (6, 10)) == 65535
    assert sum(result.expected_row[uid][1] for uid in (11, 13)) == 65535
    assert result.expected_row[14][1] == 65535


def test_old_signed_policy_bytes_and_attempt_identity_are_not_reinterpreted(policies):
    obs = observation()
    old, new = policies
    raw = canonical_json_bytes(old)
    assert canonical_json_bytes(bridge.parse_registration_bridge_policy(raw)) == raw
    assert bridge.parse_registration_bridge_policy(canonical_json_bytes(new)) == new
    assert bridge.registration_bridge_policy_sha256(
        old
    ) != bridge.registration_bridge_policy_sha256(new)
    before = decision(old, obs)
    attempt = bridge._new_attempt(old, obs, before, health(obs))
    encoded = canonical_json_bytes(attempt)
    assert (
        canonical_json_bytes(bridge.RegistrationBridgeAttempt.model_validate_json(encoded))
        == encoded
    )
    assert decision(old, obs) == before


@pytest.mark.parametrize("field", ["reward_rule", "grouping_rule"])
def test_mixed_old_new_policy_rule_is_rejected(policies, field):
    old, new = policies
    with pytest.raises(ValidationError, match="rules disagree"):
        bridge.RegistrationBridgePolicyBody.model_validate(
            {**old.body.model_dump(by_alias=True), field: getattr(new.body, field)}
        )


def test_unsigned_policy_change_does_not_authorize_ip_grouping(policies):
    old, new = policies
    changed = old.model_copy(update={"body": new.body})
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_signature_invalid"):
        decision(changed, observation())


def test_ip_change_rebinds_roster_and_recomputes_groups(policies):
    obs = roster([(6, 1001, "https://8.8.8.8:443"), (10, 1002, "https://8.8.8.8:8443")])
    before = decision(policies[1], obs)
    moved = replace_participant(obs, 10, origin="https://1.1.1.1:443")
    after = decision(policies[1], moved)
    assert before.roster_sha256 != after.roster_sha256
    assert bridge._coldkey_ip_groups([p for p in moved.participants if p.origin]) == [[6], [10]]


def test_live_policy_upgrade_preserves_old_history_and_submits_rebalanced_row(
    tmp_path, policies, wallet
):
    old, new = policies
    before = replace_participant(writer_observation(wallet), 6, origin="https://1.1.1.1:443")
    old_row = decision(old, before).expected_row
    after_old = replace_participant(
        before.model_copy(
            update={
                "block_number": BLOCK + 1,
                "block_hash": "0x" + "22" * 32,
                "validator_row": old_row,
            }
        ),
        54,
        last_update=BLOCK + 1,
    )
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        assert (
            run(old, wallet, Chain(state, [before, before, after_old]), state)["status"]
            == "submitted"
        )
    history = {p.name: p.read_bytes() for p in (root / "registration-bridge-history").iterdir()}
    before_new = after_old.model_copy(
        update={
            "block_number": BLOCK + 120,
            "block_hash": "0x" + "33" * 32,
        }
    )
    new_row = decision(new, before_new).expected_row
    assert new_row != old_row
    after_new = replace_participant(
        before_new.model_copy(
            update={
                "block_number": BLOCK + 121,
                "block_hash": "0x" + "44" * 32,
                "validator_row": new_row,
            }
        ),
        54,
        last_update=BLOCK + 121,
    )
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before_new, before_new, after_new])
        submit = chain.client.submit_call

        async def new_receipt(*args, **kwargs):
            await submit(*args, **kwargs)
            return SimpleNamespace(
                success=True, extrinsic_id=f"{BLOCK + 121}-0002", block_hash="0x" + "44" * 32
            )

        chain.client.submit_call = new_receipt
        assert run(new, wallet, chain, state)["status"] == "submitted"
        assert len(chain.client.calls) == 1
        current = state.load()
        assert current.phase == "applied"
        assert current.attempt.signed_policy == new
        assert current.attempt.prior_last_update == BLOCK + 1
    for name, original in history.items():
        assert (root / "registration-bridge-history" / name).read_bytes() == original
    with bridge.RegistrationBridgeState(root) as state:
        assert state.load().attempt.expected_row == new_row


def test_new_policy_cannot_clear_an_uncertain_old_policy_submission(tmp_path, policies, wallet):
    root = tmp_path.resolve() / "state"
    before = writer_observation(wallet)
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before], error=TimeoutError())
        with pytest.raises((TimeoutError, bridge.RegistrationBridgeError)):
            run(policies[0], wallet, chain, state)
        assert state.load().phase == "outcome_unknown"
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before])
        with pytest.raises(
            bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"
        ):
            run(policies[1], wallet, chain, state)
        assert chain.client.calls == []
        assert state.load().attempt.signed_policy == policies[0]
