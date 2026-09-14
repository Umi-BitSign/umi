from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal, get_args, get_origin

import bittensor as bt
import pytest
from pydantic import ValidationError

import umi.registration_bridge as bridge
from tests.factories import dev_wallet
from umi.protocol import canonical_json_bytes

NOW = datetime(2026, 9, 12, 18, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
BLOCK = 9_055_000
REVISION = "ab" * 20
PERMITS = {0, 54, 198, 200, 210, 211, 247, 249}
LIVE = {6, 10, 11, 13, 14, 15, 16, 18, 19, 20, 21, 33, 223, 232, 251, 255}


def hotkey(uid):
    return bt.sp_core.Keypair(
        public_key=hashlib.sha256(f"bridge-{uid}".encode()).digest()
    ).ss58_address


def policy_body(*, coordinator_hotkey, revision=REVISION, valid_from_block=BLOCK - 1000):
    # All protocol constants are Literals; no policy choices receive defaults.
    values = {}
    for name, field in bridge.RegistrationBridgePolicyBody.model_fields.items():
        if get_origin(field.annotation) is Literal:
            values[field.alias or name] = get_args(field.annotation)[0]
    values.update(
        coordinator_hotkey=coordinator_hotkey,
        umi_git_revision=revision,
        valid_from_block=valid_from_block,
        required_runtime_spec_version=455,
    )
    return bridge.RegistrationBridgePolicyBody.model_validate(values)


@pytest.fixture
def signed_policy(monkeypatch):
    wallet = dev_wallet("//RegistrationBridgeAuthority")
    monkeypatch.setattr(bridge, "REGISTRATION_BRIDGE_COORDINATOR", wallet.hotkey.ss58_address)
    return bridge.sign_registration_bridge_policy(
        policy_body(coordinator_hotkey=wallet.hotkey.ss58_address), wallet=wallet
    )


def observation(**changes):
    participants = [
        bridge.RegistrationBridgeParticipant(
            uid=uid,
            hotkey=hotkey(uid),
            coldkey=hotkey(256 + uid),
            validator_permit=uid in PERMITS,
            last_update=BLOCK - 500,
            registered_at_block=BLOCK - 100,
            origin=f"https://8.8.8.8:{8000 + uid}" if uid in LIVE else None,
        )
        for uid in range(256)
    ]
    values = dict(
        network="finney",
        genesis_hash=f"0x{bridge.FINNEY_GENESIS_HASH}",
        block_number=BLOCK,
        block_hash="0x" + "11" * 32,
        block_timestamp_ms=NOW_MS,
        runtime_spec_version=455,
        mechanism_count=1,
        commit_reveal_enabled=False,
        commit_reveal_version=4,
        reveal_period_epochs=1,
        weights_version_key=4_294_967_296,
        min_allowed_weights=256,
        max_weights_limit=65535,
        max_allowed_uids=256,
        weights_set_rate_limit=100,
        activity_cutoff_factor_milli=1000,
        tempo=360,
        block_time_seconds=12.0,
        total_pending_commit_count=0,
        subnet_owner_hotkey=hotkey(0),
        owner_associated_hotkeys=[hotkey(0)],
        participants=participants,
        validator_hotkey=hotkey(54),
        validator_row=[],
    )
    values.update(changes)
    return bridge.RegistrationBridgeObservation.model_validate(values)


def health(obs, *, failed=frozenset(), checked_at=NOW_MS):
    return [
        bridge.RegistrationBridgeHealth(
            uid=p.uid,
            hotkey=p.hotkey,
            origin=p.origin,
            checked_at_unix_ms=checked_at,
            available=p.uid not in failed,
            reason_code="endpoint_unavailable" if p.uid in failed else "http_200",
            body_sha256=None if p.uid in failed else hashlib.sha256(b"ok").hexdigest(),
        )
        for p in bridge._registered_candidates(obs)
        if p.origin is not None
    ]


def decision(policy, obs, receipts=None):
    return bridge.validate_registration_bridge_observation(
        policy,
        obs,
        health(obs) if receipts is None else receipts,
        expected_revision=REVISION,
        now=NOW,
    )


def replace_participant(obs, uid, **changes):
    participants = list(obs.participants)
    participants[uid] = participants[uid].model_copy(update=changes)
    return bridge.RegistrationBridgeObservation.model_validate(
        obs.model_copy(update={"participants": participants}).model_dump(mode="python")
    )


def grouped_observation(sizes):
    obs = observation()
    candidates = [uid for uid in range(256) if uid not in PERMITS]
    assigned = {}
    groups = []
    offset = 0
    for index, size in enumerate(sizes):
        uids = candidates[offset : offset + size]
        assert len(uids) == size
        offset += size
        groups.append(uids)
        for uid in uids:
            assigned[uid] = hotkey(512 + index)
    participants = [
        participant.model_copy(
            update={
                "coldkey": assigned.get(participant.uid, participant.coldkey),
                "origin": f"https://8.8.8.8:{8000 + participant.uid}"
                if participant.uid in assigned
                else None,
            }
        )
        for participant in obs.participants
    ]
    return bridge.RegistrationBridgeObservation.model_validate(
        obs.model_copy(update={"participants": participants}).model_dump(mode="python")
    ), groups


@pytest.mark.parametrize("sizes", [(6, 4, 1), (2, 4, 6), (3, 5, 7), (3, 3), (11,), (1, 247)])
def test_coldkey_groups_receive_exact_equal_integer_totals(signed_policy, sizes):
    obs, groups = grouped_observation(sizes)
    result = decision(signed_policy, obs)
    budget = 65535 * min(sizes)
    assert result.eligible_count == sum(sizes)
    assert result.eligible_coldkey_count == len(sizes)
    assert [pair[0] for pair in result.expected_row] == list(range(256))
    assert max(pair[1] for pair in result.expected_row) == 65535
    for uids in groups:
        weights = [result.expected_row[uid][1] for uid in uids]
        quotient, remainder = divmod(budget, len(uids))
        assert sum(weights) == budget
        assert weights == [quotient + (index < remainder) for index in range(len(uids))]
        assert all(0 < weight <= 65535 for weight in weights)
    positive = {uid for uids in groups for uid in uids}
    assert all(weight == 0 for uid, weight in result.expected_row if uid not in positive)
    # The on-chain maximum-scaling transform has an exact fixed point here.
    assert [
        weight * 65535 // max(pair[1] for pair in result.expected_row)
        for _, weight in result.expected_row
    ] == [weight for _, weight in result.expected_row]


def test_health_loss_changes_only_live_membership_then_rebalances_coldkey_groups(signed_policy):
    obs, groups = grouped_observation((6, 4, 1))
    failed = {groups[0][0]}
    result = decision(signed_policy, obs, health(obs, failed=failed))
    assert result.eligible_count == 10 and result.eligible_coldkey_count == 3
    assert result.expected_row[groups[0][0]][1] == 0
    assert [sum(result.expected_row[uid][1] for uid in group) for group in groups] == [65535] * 3
    # If the singleton goes offline, only two groups remain and the minimum
    # live group size becomes four. Their exact budgets increase together.
    result = decision(signed_policy, obs, health(obs, failed={groups[2][0]}))
    assert result.eligible_coldkey_count == 2
    assert [sum(result.expected_row[uid][1] for uid in group) for group in groups] == [
        4 * 65535
    ] * 2 + [0]


def test_nondefault_chain_max_weight_limit_checks_grouped_row_not_uid_count(signed_policy):
    obs, _ = grouped_observation((6, 1))
    with pytest.raises(bridge.RegistrationBridgeError, match="row_exceeds_max_weight_ratio"):
        decision(signed_policy, obs.model_copy(update={"max_weights_limit": 10000}))
    assert (
        decision(signed_policy, obs.model_copy(update={"max_weights_limit": 32768})).eligible_count
        == 7
    )


def test_coldkey_ownership_is_validated_and_bound_into_roster_and_attempt(signed_policy):
    obs, groups = grouped_observation((6, 4, 1))
    receipts = health(obs)
    result = decision(signed_policy, obs, receipts)
    attempt = bridge._new_attempt(signed_policy, obs, result, receipts)
    uid = groups[0][0]
    changed = replace_participant(obs, uid, coldkey=hotkey(900))
    assert bridge.registration_bridge_roster_sha256(changed) != result.roster_sha256
    with pytest.raises(ValidationError, match="attempt identity mismatch"):
        bridge.RegistrationBridgeAttempt.model_validate(
            attempt.model_copy(
                update={
                    "roster": changed.participants,
                }
            ).model_dump(mode="python", by_alias=True)
        )
    with pytest.raises(ValidationError):
        replace_participant(obs, uid, coldkey="not-an-account")


def test_policy_real_signature_canonical_envelope_and_domain(signed_policy):
    raw = canonical_json_bytes(signed_policy)
    assert bridge.parse_registration_bridge_policy(raw) == signed_policy
    assert (
        bridge.registration_bridge_policy_sha256(signed_policy) == hashlib.sha256(raw).hexdigest()
    )
    assert (
        bridge.registration_bridge_policy_digest(signed_policy.body)
        != hashlib.sha256(canonical_json_bytes(signed_policy.body)).digest()
    )
    assert signed_policy.body.stop_submitting_block == 9073731
    assert signed_policy.body.hard_sunset_block == 9075171


@pytest.mark.parametrize(
    "change",
    [
        {"maximum_raw_weight": 1},
        {"reward_rule": "equal_registered_live_nonvalidators/1"},
        {"grouping_rule": "hotkey/1"},
        {"allocation_rule": "float_rounding/1"},
        {"exclude_uid_zero": False},
        {"exclude_validator_permits": False},
        {"exclude_subnet_owner_hotkeys": False},
        {"require_fresh_endpoint_health": False},
        {"require_public_pilot_replay": True},
        {"hard_sunset_block": 9075172},
        {"health_concurrency": 256},
        {"allow_redirects": True},
        {"health_status_code": 302},
    ],
)
def test_policy_hard_limits_cannot_be_relaxed(signed_policy, change):
    with pytest.raises(ValidationError):
        bridge.RegistrationBridgePolicyBody.model_validate(
            {**signed_policy.body.model_dump(by_alias=True), **change}
        )


def test_signature_authority_revision_and_time_rejected(signed_policy):
    tampered = signed_policy.model_copy(update={"signature": "0x" + "00" * 64})
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_signature_invalid"):
        bridge.verify_registration_bridge_policy(
            tampered, expected_revision=REVISION, current_block=BLOCK
        )
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_revision_mismatch"):
        bridge.verify_registration_bridge_policy(
            signed_policy, expected_revision="cd" * 20, current_block=BLOCK
        )
    for block in (0, 9075171, True):
        with pytest.raises(bridge.RegistrationBridgeError):
            bridge.verify_registration_bridge_policy(
                signed_policy, expected_revision=REVISION, current_block=block
            )
    with pytest.raises(ValidationError):
        bridge.RegistrationBridgePolicyBody.model_validate(
            {**signed_policy.body.model_dump(by_alias=True), "coordinator_hotkey": hotkey(12)}
        )


@pytest.mark.parametrize(
    "modifier",
    [
        lambda raw: raw + b"\n",
        lambda raw: b" " + raw,
        lambda raw: raw.replace(b'"body":', b'"body":{},"body":', 1),
    ],
)
def test_noncanonical_duplicate_policy_rejected(signed_policy, modifier):
    with pytest.raises(bridge.RegistrationBridgeError):
        bridge.parse_registration_bridge_policy(modifier(canonical_json_bytes(signed_policy)))


def test_only_live_registered_nonpermit_nonowner_get_equal_full_row(signed_policy):
    result = decision(signed_policy, observation())
    assert result.action == "submit"
    assert result.eligible_count == 16
    assert result.expected_row == [[uid, 65535 if uid in LIVE else 0] for uid in range(256)]
    assert all(result.expected_row[uid][1] == 0 for uid in PERMITS)


def test_owner_associated_nonzero_uid_is_excluded(signed_policy):
    obs = observation(
        owner_associated_hotkeys=sorted([hotkey(0), hotkey(6)], key=bridge.account_id32)
    )
    result = decision(signed_policy, obs)
    assert result.eligible_count == 15 and result.expected_row[6] == [6, 0]


def test_health_failure_excludes_only_one_uid_and_zero_success_holds(signed_policy):
    obs = observation()
    result = decision(signed_policy, obs, health(obs, failed={6}))
    assert result.eligible_count == 15 and result.expected_row[6][1] == 0
    with pytest.raises(bridge.RegistrationBridgeError, match="no_live_eligible_miners"):
        decision(signed_policy, obs, health(obs, failed=LIVE))


@pytest.mark.parametrize(
    "changes",
    [
        {"mechanism_count": 2},
        {"commit_reveal_enabled": True},
        {"commit_reveal_version": 5},
        {"reveal_period_epochs": 2},
        {"weights_version_key": 1},
        {"min_allowed_weights": 255},
        {"max_allowed_uids": 257},
        {"activity_cutoff_factor_milli": 999},
        {"tempo": 359},
        {"weights_set_rate_limit": 101},
        {"total_pending_commit_count": 1},
        {"block_time_seconds": 6.0},
        {"block_timestamp_ms": NOW_MS - 120001},
        {"block_timestamp_ms": NOW_MS + 30001},
    ],
)
def test_chain_settings_and_freshness_fail_closed(signed_policy, changes):
    with pytest.raises(bridge.RegistrationBridgeError):
        decision(signed_policy, observation(**changes))


def test_missing_writer_permit_and_insufficient_ratio_hold(signed_policy):
    with pytest.raises(bridge.RegistrationBridgeError, match="validator_permit_missing"):
        decision(signed_policy, replace_participant(observation(), 54, validator_permit=False))
    with pytest.raises(bridge.RegistrationBridgeError, match="row_exceeds_max_weight_ratio"):
        decision(signed_policy, observation(max_weights_limit=1))


def test_registration_requires_later_weight_even_when_row_is_equal(signed_policy):
    obs = replace_participant(observation(), 6, registered_at_block=BLOCK)
    assert decision(signed_policy, obs).reason_code == "registration_must_precede_weight"
    equal = decision(signed_policy, observation()).expected_row
    obs = observation(validator_row=equal)
    obs = replace_participant(obs, 54, last_update=BLOCK - 110)
    assert decision(signed_policy, obs).action == "submit"  # registration is newer than the old row


def test_rate_refresh_and_stop_submitting_gates(signed_policy):
    obs = replace_participant(observation(), 54, last_update=BLOCK - 1)
    assert decision(signed_policy, obs).reason_code == "weights_rate_limit_not_elapsed"
    row = decision(signed_policy, observation()).expected_row
    obs = replace_participant(observation(validator_row=row), 54, last_update=BLOCK - 50)
    assert decision(signed_policy, obs).reason_code == "exact_row_active"
    retiring = observation(block_number=9073731 - 64)
    assert decision(signed_policy, retiring).action == "retiring"


def test_health_freshness_identity_and_coverage_are_exact(signed_policy):
    obs = observation()
    for receipts in (
        health(obs, checked_at=NOW_MS - 120001),
        health(obs)[:-1],
        [health(obs)[0].model_copy(update={"hotkey": hotkey(99)}), *health(obs)[1:]],
    ):
        with pytest.raises(bridge.RegistrationBridgeError):
            decision(signed_policy, obs, receipts)


def test_exact_real_sdk_weight_call_is_full_256(signed_policy):
    result = decision(signed_policy, observation())
    call = bridge.build_registration_bridge_call(result)
    assert call.module == "SubtensorModule" and call.function == "set_mechanism_weights"
    assert call.params["dests"] == list(range(256))
    assert call.params["weights"] == [p[1] for p in result.expected_row]
    assert call.params["version_key"] == 4294967296


@pytest.mark.parametrize(
    "origin",
    [
        "https://224.0.0.1:443",
        "https://239.255.255.250:443",
        "https://[ff02::1]:443",
        "https://[ff0e::1]:443",
        "https://127.0.0.1:443",
        "https://169.254.169.254:443",
        "https://10.0.0.1:443",
        "https://[fe80::1%25eth0]:443",
        "https://example.com:443",
    ],
)
def test_nonpublic_nonunicast_origins_rejected(origin):
    with pytest.raises((ValueError, bridge.RegistrationBridgeError)):
        bridge._bridge_public_origin(origin)


def test_cli_help_is_wallet_free(capsys):
    with pytest.raises(SystemExit) as result:
        bridge.run_cli(["--help"])
    assert result.value.code == 0
    assert "run" in capsys.readouterr().out
