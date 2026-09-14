from __future__ import annotations

import copy
import hashlib
import random

import pytest

import umi.registration_bridge as bridge
from tests.factories import dev_wallet
from tests.test_registration_bridge import (
    BLOCK,
    decision,
    health,
    hotkey,
    policy_body,
    replace_participant,
)
from tests.test_registration_bridge_ip_groups import roster
from umi.protocol import canonical_json_bytes
from umi.registration_funding_audit import TRANSFER_URL
from umi.registration_funding_snapshot import snapshot_from_report
from umi.validator_supervisor_adapters import (
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
    _parse_bootstrap_input_bundle,
)


def funding_report(obs, funders):
    histories = []
    for uid, funder in funders.items():
        p = obs.participants[uid]
        histories.append(
            dict(
                coldkey=p.coldkey,
                uids=[uid],
                before_registration_block=p.registered_at_block,
                status="single_recorded_sender",
                candidate_funder=hotkey(funder),
                recorded_senders=[hotkey(funder)],
                transfers=[
                    dict(
                        id=f"finney-100-{uid}",
                        **{"from": hotkey(funder), "to": p.coldkey},
                        block_number=100,
                        amount_rao="50000000",
                        extrinsic_id="100-0001",
                        transaction_hash="0x" + "ab" * 32,
                    )
                ],
                page_sha256=["ab" * 32],
            )
        )
    return dict(
        schema="umi-registration-funding-audit/1",
        source=TRANSFER_URL,
        shared_funders_excluded=[],
        roster=dict(
            finalized_block=BLOCK - 1,
            finalized_block_hash="0x" + "ac" * 32,
            participants=[
                p.model_dump(
                    include={"uid", "hotkey", "coldkey", "registered_at_block", "validator_permit"}
                )
                for p in obs.participants
            ],
        ),
        histories=histories,
    )


@pytest.fixture
def setup(monkeypatch):
    signer = dev_wallet("//RegistrationBridgeAuthority")
    monkeypatch.setattr(bridge, "REGISTRATION_BRIDGE_COORDINATOR", signer.hotkey.ss58_address)
    obs = roster(
        [
            (6, 1006, "https://1.1.1.1:443"),
            (71, 1071, "https://8.8.8.8:443"),
            (72, 1072, "https://9.9.9.9:443"),
            (73, 1073, "https://8.8.4.4:443"),
        ]
    )
    report = funding_report(obs, {71: 2000, 72: 2000, 73: 2000})
    old = policy_body(coordinator_hotkey=signer.hotkey.ss58_address, valid_from_block=BLOCK - 1)
    new = bridge.RegistrationBridgeFundingPolicyBody.model_validate(
        {
            **old.model_dump(by_alias=True),
            "schema": "umi-registration-bridge-policy-body/2",
            "reward_rule": "equal_live_coldkey_ip_funder_groups/1",
            "grouping_rule": (
                "registered_owner_or_https_ip_or_recorded_funder_connected_components/1"
            ),
            "funding_snapshot": snapshot_from_report(report),
        }
    )
    return (
        obs,
        report,
        signer,
        bridge.sign_registration_bridge_policy(new, wallet=signer),
        bridge.sign_registration_bridge_policy(old, wallet=signer),
    )


def test_different_keys_and_ips_same_funder_share_one_budget(setup):
    obs, _, _, policy, old = setup
    result = decision(policy, obs)
    assert result.expected_row[6][1] == 65535
    assert sum(result.expected_row[u][1] for u in (71, 72, 73)) == 65535
    assert all(result.expected_row[u][1] > 0 for u in (71, 72, 73))
    assert sum(decision(old, obs).expected_row[u][1] for u in (71, 72, 73)) == 3 * 65535


@pytest.mark.parametrize("runtime", [0, 454, 456, 458, 459, 1000, 2**32 - 1])
def test_runtime_annotation_accepts_uint32_and_preserves_allocation(setup, runtime):
    obs, _, signer, policy, _ = setup
    expected = decision(policy, obs)
    values = policy.body.model_dump(by_alias=True)
    values["required_runtime_spec_version"] = runtime
    updated = bridge.sign_registration_bridge_policy(
        bridge.RegistrationBridgeFundingPolicyBody.model_validate(values), wallet=signer
    )
    parsed = bridge.parse_registration_bridge_policy(canonical_json_bytes(updated))
    bundle_raw = canonical_json_bytes(
        {
            "schema": SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
            "profile": SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
            "signed_policy": updated.model_dump(mode="json", by_alias=True),
        }
    )
    assert _parse_bootstrap_input_bundle(bundle_raw).signed_policy == parsed
    result = decision(parsed, obs.model_copy(update={"runtime_spec_version": runtime}))
    assert result.action == "submit"
    assert result.expected_row == expected.expected_row
    assert parsed.body.funding_snapshot == policy.body.funding_snapshot
    assert parsed.body.stop_submitting_block == 9073731
    assert parsed.body.hard_sunset_block == 9075171
    assert bridge.registration_bridge_policy_sha256(parsed) != (
        bridge.registration_bridge_policy_sha256(policy)
    )
    assert decision(parsed, obs).expected_row == expected.expected_row


@pytest.mark.parametrize("runtime", [456, 458, 459, 1000, 2**32 - 1])
def test_runtime_only_upgrade_keeps_old_policies_valid_without_resigning(setup, runtime):
    obs, _, _, policy, old = setup
    for signed in (policy, old):
        raw = canonical_json_bytes(signed)
        parsed = bridge.parse_registration_bridge_policy(raw)
        expected = decision(parsed, obs)
        upgraded = decision(parsed, obs.model_copy(update={"runtime_spec_version": runtime}))
        assert upgraded.action == "submit"
        assert upgraded.expected_row == expected.expected_row
        assert canonical_json_bytes(parsed) == raw


def test_runtime_annotation_is_still_authenticated(setup):
    policy = setup[3]
    tampered = policy.model_dump(by_alias=True)
    tampered["body"]["required_runtime_spec_version"] = 458
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_signature_invalid"):
        bridge.parse_registration_bridge_policy(canonical_json_bytes(tampered))


@pytest.mark.parametrize("runtime", [-1, 2**32, True, "458", 458.0, None])
def test_malformed_runtime_annotation_is_rejected(setup, runtime):
    for signed in (setup[3], setup[4]):
        values = signed.body.model_dump(by_alias=True)
        values["required_runtime_spec_version"] = runtime
        with pytest.raises(ValueError):
            type(signed.body).model_validate(values)


@pytest.mark.parametrize(
    "field,value",
    [("hotkey", hotkey(3000)), ("coldkey", hotkey(4000)), ("registered_at_block", BLOCK - 2)],
)
def test_stale_registration_binding_never_groups_replacement(setup, field, value):
    obs, _, _, policy, _ = setup
    changed = replace_participant(obs, 71, **{field: value})
    result = decision(policy, changed)
    assert result.expected_row[71][1] == 65535
    assert sum(result.expected_row[u][1] for u in (72, 73)) == 65535


def test_only_live_candidates_form_funding_edges(setup):
    obs, _, _, policy, _ = setup
    result = decision(policy, obs, health(obs, failed={72, 73}))
    assert result.expected_row[71][1] == 65535
    assert result.expected_row[72][1] == result.expected_row[73][1] == 0


def test_owner_ip_and_funding_edges_compose_deterministically(setup):
    obs, _, _, policy, _ = setup
    obs = replace_participant(obs, 6, origin=obs.participants[71].origin)
    live = [p for p in obs.participants if p.origin]
    for seed in range(20):
        random.Random(seed).shuffle(live)
        assert bridge._coldkey_ip_groups(live, funding_snapshot=policy.body.funding_snapshot) == [
            [6, 71, 72, 73]
        ]


def test_policy_and_old_journals_roundtrip_without_changing_old_bytes(setup):
    _, _, _, policy, old = setup
    for signed in (old, policy):
        raw = canonical_json_bytes(signed)
        assert canonical_json_bytes(bridge.parse_registration_bridge_policy(raw)) == raw
    assert b"funding_snapshot" not in canonical_json_bytes(old)
    assert (
        policy.body.funding_snapshot.report_sha256
        == hashlib.sha256(canonical_json_bytes(setup[1])).hexdigest()
    )
    tampered = policy.model_dump(by_alias=True)
    tampered["body"]["funding_snapshot"]["bindings"][0]["funder"] = hotkey(5000)
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_signature_invalid"):
        bridge.parse_registration_bridge_policy(canonical_json_bytes(tampered))


@pytest.mark.parametrize(
    "status",
    [
        "unverified_history",
        "queued",
        "page_bound_reached",
        "multiple_recorded_senders",
        "no_recorded_sender",
        "shared_service_funder_excluded",
    ],
)
def test_unknown_or_excluded_history_adds_no_funding_edge(setup, status):
    report = copy.deepcopy(setup[1])
    report["histories"][0]["status"] = status
    assert 71 not in [b.uid for b in snapshot_from_report(report).bindings]


def test_known_shared_service_exclusion(setup):
    report = copy.deepcopy(setup[1])
    report["shared_funders_excluded"] = [hotkey(2000)]
    assert not snapshot_from_report(report).bindings


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["histories"].append(copy.deepcopy(r["histories"][0])),
        lambda r: r["histories"][0].update(before_registration_block=1),
        lambda r: r["histories"][0].update(uids=[0]),
        lambda r: r["histories"][0].update(page_sha256=[]),
        lambda r: r["histories"][0].update(candidate_funder=hotkey(9999)),
        lambda r: r["histories"][0]["transfers"][0].update(block_number=BLOCK),
        lambda r: r["histories"][0]["transfers"].append(
            copy.deepcopy(r["histories"][0]["transfers"][0])
        ),
        lambda r: r["histories"][0]["transfers"][0].update(amount_rao="0"),
    ],
)
def test_report_inconsistency_cannot_be_signed_as_funding_snapshot(setup, mutation):
    report = copy.deepcopy(setup[1])
    mutation(report)
    with pytest.raises(ValueError):
        snapshot_from_report(report)


def test_future_snapshot_rejected(setup):
    values = setup[3].body.model_dump(by_alias=True)
    values["funding_snapshot"]["finalized_block"] = BLOCK + 1
    with pytest.raises(ValueError, match="newer than policy"):
        bridge.RegistrationBridgeFundingPolicyBody.model_validate(values)


def test_new_funding_policy_preserves_uncertain_old_submission(setup, tmp_path):
    from tests.test_registration_bridge_ip_groups import (
        test_new_policy_cannot_clear_an_uncertain_old_policy_submission as check,
    )

    check(tmp_path, (setup[4], setup[3]), dev_wallet("//RegistrationBridgeValidator"))
